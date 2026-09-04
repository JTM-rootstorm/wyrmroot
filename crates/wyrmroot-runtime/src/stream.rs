//! Bounded typed wrappers for WYR1-D WRST byte streams.

use deepwyrm_syscall::{
    DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_INSPECT, DW_RIGHT_READ, DW_RIGHT_WAIT, DW_RIGHT_WRITE,
    DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DW_SIGNAL_WRITABLE, DW_STATUS_WOULD_BLOCK, DwHandle,
    DwReceivedHandleInfoV1, DwRights, DwSignals,
};
use wyrmroot_loader::launch::{CHILD_CHANNEL_RIGHTS, LaunchError, LaunchProfile, parse_init};
use wyrmroot_stream_proto::{MAX_PAYLOAD_BYTES, MAX_RECORD_BYTES, decode_data, encode_data};

use crate::{NativeError, ReceiveCounts};

const MAX_RECEIVED_HANDLES: usize = 16;

/// Native Channel operations required by a stream wrapper.
///
/// This deliberately leaves the platform's Channel ABI in the runtime; the
/// protocol crate remains syscall-free and host tests can inject this facade.
pub trait StreamSystem {
    fn receive(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError>;
    fn send(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError>;
    fn close(&mut self, handle: DwHandle) -> Result<(), NativeError>;
    /// Waits through the reached native wait primitive for one stream endpoint.
    /// Returns the full Channel signal snapshot, not only the requested bits.
    fn wait(&mut self, channel: DwHandle, signals: DwSignals) -> Result<DwSignals, NativeError>;
}

/// Native-stream failure classes. Empty data records are never EOF.
#[derive(Debug, Eq, PartialEq)]
pub enum StreamError {
    Native(NativeError),
    WouldBlock,
    Eof,
    Broken,
    Protocol,
    ReceivedHandles,
    Failed,
    Launch(LaunchError),
}

/// One typed child stream endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamEndpoint(DwHandle);
impl StreamEndpoint {
    /// Wraps a nonzero Channel handle after the caller has validated or
    /// constructed it with [`JOB_V2_STREAM_RIGHTS`]. This does not manufacture
    /// authority and deliberately cannot widen rights.
    pub const fn from_validated_handle(handle: DwHandle) -> Result<Self, StreamError> {
        if handle.0 == 0 {
            Err(StreamError::Protocol)
        } else {
            Ok(Self(handle))
        }
    }

    pub const fn handle(self) -> DwHandle {
        self.0
    }
}

/// The exact stdin, stdout, stderr tuple transferred by JobV2Streams.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobV2Streams {
    pub stdin: StreamEndpoint,
    pub stdout: StreamEndpoint,
    pub stderr: StreamEndpoint,
}

/// Validates the reached JobV2 stream-role record before exposing handles.
pub fn extract_job_v2_streams(
    bytes: &[u8],
    handles: &[DwReceivedHandleInfoV1],
) -> Result<JobV2Streams, LaunchError> {
    parse_init(LaunchProfile::JobV2Streams, bytes, handles)?;
    Ok(JobV2Streams {
        stdin: StreamEndpoint(handles[0].handle),
        stdout: StreamEndpoint(handles[1].handle),
        stderr: StreamEndpoint(handles[2].handle),
    })
}

/// Wait interest for an input endpoint. READABLE is always drained before EOF.
pub const INPUT_WAIT_SIGNALS: DwSignals = DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0);
/// Wait interest for an output endpoint; WRITABLE is only a hint and must be retried.
pub const OUTPUT_WAIT_SIGNALS: DwSignals =
    DwSignals(DW_SIGNAL_WRITABLE.0 | DW_SIGNAL_PEER_CLOSED.0);

// DwWaitResultV1.observed is the full selected-object signal state. A stream's
// opposite direction can therefore be ready even when it was not requested.
// Keep the accepted object vocabulary separate from the directional interest.
const CHANNEL_OBSERVED_SIGNALS: DwSignals =
    DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_WRITABLE.0 | DW_SIGNAL_PEER_CLOSED.0);

/// One bounded byte reader retaining at most one decoded 1024-byte record.
pub struct NativeInput {
    endpoint: StreamEndpoint,
    record: [u8; MAX_PAYLOAD_BYTES],
    offset: usize,
    used: usize,
    eof: bool,
    failed: bool,
}
impl NativeInput {
    pub const fn new(endpoint: StreamEndpoint) -> Self {
        Self {
            endpoint,
            record: [0; MAX_PAYLOAD_BYTES],
            offset: 0,
            used: 0,
            eof: false,
            failed: false,
        }
    }
    pub const fn endpoint(&self) -> StreamEndpoint {
        self.endpoint
    }
    /// Consumes a full Channel snapshot. WRITABLE does not affect input;
    /// READABLE takes precedence over peer close because queued bytes drain first.
    pub fn observe_wait(&mut self, observed: DwSignals) -> Result<(), StreamError> {
        if observed.0 & !CHANNEL_OBSERVED_SIGNALS.0 != 0 {
            return Err(StreamError::Protocol);
        }
        if observed.0 & DW_SIGNAL_READABLE.0 == 0 && observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
            self.eof = true;
        }
        Ok(())
    }
    /// Waits for fresh input state. READABLE remains dominant over peer close;
    /// callers must drain any record before interpreting EOF.
    pub fn wait_readable<S: StreamSystem>(&mut self, system: &mut S) -> Result<(), StreamError> {
        if self.failed {
            return Err(StreamError::Failed);
        }
        let observed = system
            .wait(self.endpoint.0, INPUT_WAIT_SIGNALS)
            .map_err(classify)?;
        self.observe_wait(observed)
    }
    pub fn read<S: StreamSystem>(
        &mut self,
        system: &mut S,
        output: &mut [u8],
    ) -> Result<usize, StreamError> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.failed {
            return Err(StreamError::Failed);
        }
        let mut copied = 0;
        loop {
            if self.offset != self.used {
                copied += self.drain(&mut output[copied..]);
                if copied == output.len() {
                    return Ok(copied);
                }
                continue;
            }
            if self.eof {
                return if copied == 0 {
                    Err(StreamError::Eof)
                } else {
                    Ok(copied)
                };
            }
            let mut wire = [0u8; MAX_RECORD_BYTES];
            let mut handles = [DwReceivedHandleInfoV1::default(); MAX_RECEIVED_HANDLES];
            let counts = match system.receive(self.endpoint.0, &mut wire, &mut handles) {
                Ok(counts) => counts,
                Err(error) => match classify(error) {
                    StreamError::WouldBlock if copied != 0 => return Ok(copied),
                    error => return Err(error),
                },
            };
            if counts.bytes > wire.len() || counts.handles > handles.len() {
                self.fail(system, &handles);
                return Err(StreamError::Protocol);
            }
            if counts.handles != 0 {
                self.fail(system, &handles[..counts.handles]);
                return Err(StreamError::ReceivedHandles);
            }
            let data = match decode_data(&wire[..counts.bytes]) {
                Ok(data) => data,
                Err(_) => {
                    self.failed = true;
                    return Err(StreamError::Protocol);
                }
            };
            self.used = data.payload().len();
            self.offset = 0;
            self.record[..self.used].copy_from_slice(data.payload());
        }
    }
    fn fail<S: StreamSystem>(&mut self, system: &mut S, handles: &[DwReceivedHandleInfoV1]) {
        self.failed = true;
        for received in handles {
            if received.handle.0 != 0 {
                let _ = system.close(received.handle);
            }
        }
    }
    fn drain(&mut self, output: &mut [u8]) -> usize {
        let count = core::cmp::min(output.len(), self.used - self.offset);
        output[..count].copy_from_slice(&self.record[self.offset..self.offset + count]);
        self.offset += count;
        if self.offset == self.used {
            self.offset = 0;
            self.used = 0;
        }
        count
    }
}

/// One bounded DATA packetizer. A failed send commits no bytes.
pub struct NativeOutput {
    endpoint: StreamEndpoint,
}
impl NativeOutput {
    pub const fn new(endpoint: StreamEndpoint) -> Self {
        Self { endpoint }
    }
    pub const fn endpoint(&self) -> StreamEndpoint {
        self.endpoint
    }
    /// Consumes a full Channel snapshot. READABLE does not affect output;
    /// peer close is broken output even if other signals are also present.
    pub fn observe_wait(&self, observed: DwSignals) -> Result<(), StreamError> {
        if observed.0 & !CHANNEL_OBSERVED_SIGNALS.0 != 0 {
            return Err(StreamError::Protocol);
        }
        if observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
            return Err(StreamError::Broken);
        }
        Ok(())
    }
    /// Waits through the reached native wait primitive. A peer close is broken
    /// output, never a writable reservation.
    pub fn wait_writable<S: StreamSystem>(&self, system: &mut S) -> Result<(), StreamError> {
        let observed = system
            .wait(self.endpoint.0, OUTPUT_WAIT_SIGNALS)
            .map_err(classify)?;
        self.observe_wait(observed)
    }
    pub fn write<S: StreamSystem>(
        &mut self,
        system: &mut S,
        bytes: &[u8],
    ) -> Result<usize, StreamError> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let mut committed = 0;
        while committed != bytes.len() {
            let packet = core::cmp::min(bytes.len() - committed, MAX_PAYLOAD_BYTES);
            let mut wire = [0u8; MAX_RECORD_BYTES];
            let size = encode_data(&bytes[committed..committed + packet], &mut wire)
                .map_err(|_| StreamError::Protocol)?;
            match system
                .send(self.endpoint.0, &wire[..size])
                .map_err(classify)
            {
                Ok(()) => committed += packet,
                Err(StreamError::WouldBlock) if committed != 0 => return Ok(committed),
                Err(error) => return Err(error),
            }
        }
        Ok(committed)
    }
    /// Writes the complete caller buffer without spinning: it waits only after
    /// a no-progress or partial-progress capacity race, then retries the
    /// caller-owned suffix. A peer close remains [`StreamError::Broken`].
    pub fn write_wait<S: StreamSystem>(
        &mut self,
        system: &mut S,
        bytes: &[u8],
    ) -> Result<usize, StreamError> {
        let mut committed = 0;
        while committed != bytes.len() {
            match self.write(system, &bytes[committed..]) {
                Ok(written) => {
                    committed += written;
                    if committed == bytes.len() {
                        return Ok(committed);
                    }
                    self.wait_writable(system)?;
                }
                Err(StreamError::WouldBlock) => self.wait_writable(system)?,
                Err(error) => return Err(error),
            }
        }
        Ok(committed)
    }
}

fn classify(error: NativeError) -> StreamError {
    if matches!(error, NativeError::Status(status) if status == DW_STATUS_WOULD_BLOCK) {
        StreamError::WouldBlock
    } else {
        StreamError::Native(error)
    }
}

/// Exact full-duplex rights required for every JobV2 stream role.
pub const JOB_V2_STREAM_RIGHTS: DwRights =
    DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0);
const _: () = assert!(JOB_V2_STREAM_RIGHTS.0 == CHILD_CHANNEL_RIGHTS.0);
const _: () = assert!(DW_OBJECT_TYPE_CHANNEL.0 != 0);

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use deepwyrm_syscall::DW_STATUS_WOULD_BLOCK;
    use std::vec;
    use std::vec::Vec;

    #[derive(Default)]
    struct Fixture {
        incoming: Vec<Vec<u8>>,
        sends: Vec<Vec<u8>>,
        send_attempts: usize,
        block_send_at: Option<usize>,
        received_handles: usize,
        closed: Vec<DwHandle>,
        waits: Vec<DwSignals>,
        receive_calls: usize,
    }
    impl StreamSystem for Fixture {
        fn receive(
            &mut self,
            _: DwHandle,
            bytes: &mut [u8],
            handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, NativeError> {
            self.receive_calls += 1;
            let Some(record) = self.incoming.first().cloned() else {
                return Err(NativeError::Status(DW_STATUS_WOULD_BLOCK));
            };
            self.incoming.remove(0);
            bytes[..record.len()].copy_from_slice(&record);
            for handle in handles.iter_mut().take(self.received_handles) {
                handle.handle = DwHandle(77);
            }
            Ok(ReceiveCounts {
                bytes: record.len(),
                handles: self.received_handles,
            })
        }
        fn send(&mut self, _: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
            self.send_attempts += 1;
            if self.block_send_at == Some(self.send_attempts) {
                return Err(NativeError::Status(DW_STATUS_WOULD_BLOCK));
            }
            self.sends.push(bytes.to_vec());
            Ok(())
        }
        fn close(&mut self, handle: DwHandle) -> Result<(), NativeError> {
            self.closed.push(handle);
            Ok(())
        }
        fn wait(&mut self, _: DwHandle, _: DwSignals) -> Result<DwSignals, NativeError> {
            Ok(self.waits.remove(0))
        }
    }
    fn endpoint() -> StreamEndpoint {
        StreamEndpoint::from_validated_handle(DwHandle(9)).unwrap()
    }

    #[test]
    fn validated_stream_endpoint_rejects_the_zero_sentinel() {
        assert_eq!(
            StreamEndpoint::from_validated_handle(DwHandle(0)),
            Err(StreamError::Protocol)
        );
        assert_eq!(
            StreamEndpoint::from_validated_handle(DwHandle(9))
                .unwrap()
                .handle(),
            DwHandle(9)
        );
    }
    fn record(payload: &[u8]) -> Vec<u8> {
        let mut bytes = [0u8; MAX_RECORD_BYTES];
        let size = encode_data(payload, &mut bytes).unwrap();
        bytes[..size].to_vec()
    }
    #[test]
    fn input_retains_one_record_for_partial_and_zero_sized_reads() {
        let mut system = Fixture {
            incoming: vec![record(b"abcdef")],
            sends: vec![],
            send_attempts: 0,
            block_send_at: None,
            received_handles: 0,
            closed: vec![],
            waits: vec![],
            receive_calls: 0,
        };
        let mut input = NativeInput::new(endpoint());
        assert_eq!(input.read(&mut system, &mut []), Ok(0));
        let mut first = [0; 2];
        assert_eq!(input.read(&mut system, &mut first), Ok(2));
        assert_eq!(&first, b"ab");
        let mut rest = [0; 8];
        assert_eq!(input.read(&mut system, &mut rest), Ok(4));
        assert_eq!(&rest[..4], b"cdef");
    }
    #[test]
    fn output_packets_all_input_and_returns_progress_before_would_block() {
        let mut system = Fixture {
            incoming: vec![],
            sends: vec![],
            send_attempts: 0,
            block_send_at: Some(1),
            received_handles: 0,
            closed: vec![],
            waits: vec![],
            receive_calls: 0,
        };
        let mut output = NativeOutput::new(endpoint());
        assert_eq!(
            output.write(&mut system, b"x"),
            Err(StreamError::WouldBlock)
        );
        system.block_send_at = None;
        assert_eq!(
            output.write(&mut system, &[7; MAX_PAYLOAD_BYTES + 1]),
            Ok(MAX_PAYLOAD_BYTES + 1)
        );
        assert_eq!(
            system
                .sends
                .iter()
                .map(|record| decode_data(record).unwrap().payload().len())
                .collect::<Vec<_>>(),
            vec![1024, 1]
        );
        assert_eq!(output.write(&mut system, &[7; 2049]), Ok(2049));
        assert_eq!(
            system
                .sends
                .iter()
                .skip(2)
                .map(|record| decode_data(record).unwrap().payload().len())
                .collect::<Vec<_>>(),
            vec![1024, 1024, 1]
        );
        system.block_send_at = Some(system.send_attempts + 2);
        assert_eq!(output.write(&mut system, &[7; 2049]), Ok(1024));
    }
    #[test]
    fn peer_close_is_explicit_and_readable_precedes_eof() {
        let mut input = NativeInput::new(endpoint());
        assert_eq!(
            input.observe_wait(DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0)),
            Ok(())
        );
        let mut closed = NativeInput::new(endpoint());
        assert_eq!(closed.observe_wait(DW_SIGNAL_PEER_CLOSED), Ok(()));
        let mut fixture = Fixture {
            incoming: vec![],
            sends: vec![],
            send_attempts: 0,
            block_send_at: None,
            received_handles: 0,
            closed: vec![],
            waits: vec![],
            receive_calls: 0,
        };
        assert_eq!(closed.read(&mut fixture, &mut [0]), Err(StreamError::Eof));
    }
    #[test]
    fn unexpected_transferred_handles_are_closed_then_rejected() {
        let mut fixture = Fixture {
            incoming: vec![record(b"x")],
            sends: vec![],
            send_attempts: 0,
            block_send_at: None,
            received_handles: 1,
            closed: vec![],
            waits: vec![],
            receive_calls: 0,
        };
        let mut input = NativeInput::new(endpoint());
        assert_eq!(
            input.read(&mut fixture, &mut [0]),
            Err(StreamError::ReceivedHandles)
        );
        assert_eq!(fixture.closed, [DwHandle(77)]);
        assert_eq!(
            input.read(&mut fixture, &mut [0; 1]),
            Err(StreamError::Failed)
        );
        assert_eq!(fixture.receive_calls, 1);
    }

    #[test]
    fn malformed_and_count_invalid_input_are_terminal() {
        let mut malformed = Fixture {
            incoming: vec![vec![0; 3]],
            sends: vec![],
            send_attempts: 0,
            block_send_at: None,
            received_handles: 0,
            closed: vec![],
            waits: vec![],
            receive_calls: 0,
        };
        let mut input = NativeInput::new(endpoint());
        assert_eq!(
            input.read(&mut malformed, &mut [0; 1]),
            Err(StreamError::Protocol)
        );
        assert_eq!(
            input.read(&mut malformed, &mut [0; 1]),
            Err(StreamError::Failed)
        );
        assert_eq!(malformed.receive_calls, 1);

        let mut invalid = Fixture {
            incoming: vec![record(b"x")],
            sends: vec![],
            send_attempts: 0,
            block_send_at: None,
            received_handles: MAX_RECEIVED_HANDLES + 1,
            closed: vec![],
            waits: vec![],
            receive_calls: 0,
        };
        let mut input = NativeInput::new(endpoint());
        assert_eq!(
            input.read(&mut invalid, &mut [0; 1]),
            Err(StreamError::Protocol)
        );
        assert_eq!(invalid.closed.len(), MAX_RECEIVED_HANDLES);
        assert_eq!(
            input.read(&mut invalid, &mut [0; 1]),
            Err(StreamError::Failed)
        );
        assert_eq!(invalid.receive_calls, 1);
    }

    #[test]
    fn input_concatenates_records_retains_final_partial_and_returns_progress_before_would_block() {
        let mut fixture = Fixture {
            incoming: vec![record(b"ab"), record(b"cdef")],
            sends: vec![],
            send_attempts: 0,
            block_send_at: None,
            received_handles: 0,
            closed: vec![],
            waits: vec![],
            receive_calls: 0,
        };
        let mut input = NativeInput::new(endpoint());
        let mut first = [0; 4];
        assert_eq!(input.read(&mut fixture, &mut first), Ok(4));
        assert_eq!(&first, b"abcd");
        let mut last = [0; 8];
        assert_eq!(input.read(&mut fixture, &mut last), Ok(2));
        assert_eq!(&last[..2], b"ef");
        assert_eq!(
            input.read(&mut fixture, &mut last),
            Err(StreamError::WouldBlock)
        );
    }
    #[test]
    fn wait_helpers_use_fresh_wait_and_honor_peer_close() {
        let mut fixture = Fixture {
            incoming: vec![],
            sends: vec![],
            send_attempts: 0,
            block_send_at: None,
            received_handles: 0,
            closed: vec![],
            waits: vec![DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_WRITABLE],
            receive_calls: 0,
        };
        let mut input = NativeInput::new(endpoint());
        assert_eq!(input.wait_readable(&mut fixture), Ok(()));
        assert_eq!(input.read(&mut fixture, &mut [0]), Err(StreamError::Eof));
        let output = NativeOutput::new(endpoint());
        assert_eq!(output.wait_writable(&mut fixture), Ok(()));
        let mut broken = Fixture {
            incoming: vec![],
            sends: vec![],
            send_attempts: 0,
            block_send_at: None,
            received_handles: 0,
            closed: vec![],
            waits: vec![DW_SIGNAL_PEER_CLOSED],
            receive_calls: 0,
        };
        assert_eq!(output.wait_writable(&mut broken), Err(StreamError::Broken));
    }
    #[test]
    fn blocking_output_waits_after_a_racing_would_block_then_retries() {
        let mut fixture = Fixture {
            incoming: vec![],
            sends: vec![],
            send_attempts: 0,
            block_send_at: Some(1),
            received_handles: 0,
            closed: vec![],
            waits: vec![DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_WRITABLE.0)],
            receive_calls: 0,
        };
        let mut output = NativeOutput::new(endpoint());
        assert_eq!(output.write_wait(&mut fixture, b"abc"), Ok(3));
        assert_eq!(fixture.sends.len(), 1);
        assert_eq!(decode_data(&fixture.sends[0]).unwrap().payload(), b"abc");
        assert!(fixture.waits.is_empty());
    }

    #[test]
    fn input_wait_accepts_full_snapshot_and_drains_readable_before_eof() {
        for writable in [0, DW_SIGNAL_WRITABLE.0] {
            for peer_closed in [0, DW_SIGNAL_PEER_CLOSED.0] {
                let mut fixture = Fixture {
                    incoming: vec![record(b"abc")],
                    waits: vec![
                        DwSignals(DW_SIGNAL_READABLE.0 | writable | peer_closed),
                        DW_SIGNAL_PEER_CLOSED,
                    ],
                    ..Fixture::default()
                };
                let mut input = NativeInput::new(endpoint());
                input.wait_readable(&mut fixture).unwrap();
                let mut bytes = [0; 3];
                assert_eq!(input.read(&mut fixture, &mut bytes), Ok(3));
                assert_eq!(&bytes, b"abc");
                input.wait_readable(&mut fixture).unwrap();
                assert_eq!(input.read(&mut fixture, &mut bytes), Err(StreamError::Eof));
                assert_eq!(fixture.receive_calls, 1);
                assert!(fixture.waits.is_empty());
            }
        }
    }

    #[test]
    fn channel_snapshot_combinations_preserve_directional_semantics() {
        assert_eq!(
            INPUT_WAIT_SIGNALS.0,
            DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0
        );
        assert_eq!(
            OUTPUT_WAIT_SIGNALS.0,
            DW_SIGNAL_WRITABLE.0 | DW_SIGNAL_PEER_CLOSED.0
        );
        for readable in [0, DW_SIGNAL_READABLE.0] {
            for writable in [0, DW_SIGNAL_WRITABLE.0] {
                for peer_closed in [0, DW_SIGNAL_PEER_CLOSED.0] {
                    let observed = DwSignals(readable | writable | peer_closed);
                    let mut input = NativeInput::new(endpoint());
                    assert_eq!(input.observe_wait(observed), Ok(()));
                    let expected = if readable == 0 && peer_closed != 0 {
                        StreamError::Eof
                    } else {
                        StreamError::WouldBlock
                    };
                    assert_eq!(input.read(&mut Fixture::default(), &mut [0]), Err(expected));
                    let output = NativeOutput::new(endpoint());
                    assert_eq!(
                        output.observe_wait(observed),
                        if peer_closed != 0 {
                            Err(StreamError::Broken)
                        } else {
                            Ok(())
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn output_wait_peer_close_prevents_retry_for_every_other_channel_bit() {
        for readable in [0, DW_SIGNAL_READABLE.0] {
            for writable in [0, DW_SIGNAL_WRITABLE.0] {
                let mut fixture = Fixture {
                    block_send_at: Some(1),
                    waits: vec![DwSignals(DW_SIGNAL_PEER_CLOSED.0 | readable | writable)],
                    ..Fixture::default()
                };
                let mut output = NativeOutput::new(endpoint());
                assert_eq!(
                    output.write_wait(&mut fixture, b"abc"),
                    Err(StreamError::Broken)
                );
                assert_eq!(fixture.send_attempts, 1);
                assert!(fixture.sends.is_empty());
                assert!(fixture.waits.is_empty());
            }
        }
    }

    #[test]
    fn wait_helpers_reject_every_non_channel_bit_even_with_ready_and_closed() {
        for shift in 0..64 {
            let invalid = 1u64 << shift;
            if invalid & CHANNEL_OBSERVED_SIGNALS.0 != 0 {
                continue;
            }
            for valid in [0, CHANNEL_OBSERVED_SIGNALS.0] {
                let observed = DwSignals(invalid | valid);
                let mut fixture = Fixture {
                    incoming: vec![record(b"x")],
                    block_send_at: Some(1),
                    waits: vec![observed, observed],
                    ..Fixture::default()
                };
                let mut input = NativeInput::new(endpoint());
                assert_eq!(
                    input.wait_readable(&mut fixture),
                    Err(StreamError::Protocol)
                );
                // A rejected snapshot must not set EOF or consume queued data.
                assert_eq!(fixture.receive_calls, 0);
                let mut bytes = [0];
                assert_eq!(input.read(&mut fixture, &mut bytes), Ok(1));
                assert_eq!(&bytes, b"x");
                let mut output = NativeOutput::new(endpoint());
                assert_eq!(
                    output.write_wait(&mut fixture, b"abc"),
                    Err(StreamError::Protocol)
                );
                assert_eq!(fixture.send_attempts, 1);
                assert!(fixture.sends.is_empty());
                assert!(fixture.waits.is_empty());
            }
        }
    }
}
