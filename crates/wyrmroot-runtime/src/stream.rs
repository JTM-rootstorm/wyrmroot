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
    Launch(LaunchError),
}

/// One typed child stream endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamEndpoint(DwHandle);
impl StreamEndpoint {
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

/// One bounded byte reader retaining at most one decoded 1024-byte record.
pub struct NativeInput {
    endpoint: StreamEndpoint,
    record: [u8; MAX_PAYLOAD_BYTES],
    offset: usize,
    used: usize,
    eof: bool,
}
impl NativeInput {
    pub const fn new(endpoint: StreamEndpoint) -> Self {
        Self {
            endpoint,
            record: [0; MAX_PAYLOAD_BYTES],
            offset: 0,
            used: 0,
            eof: false,
        }
    }
    pub const fn endpoint(&self) -> StreamEndpoint {
        self.endpoint
    }
    /// Consumes a fresh wait result. A READABLE bit takes precedence because queued bytes must drain first.
    pub fn observe_wait(&mut self, observed: DwSignals) -> Result<(), StreamError> {
        if observed.0 & !INPUT_WAIT_SIGNALS.0 != 0 {
            return Err(StreamError::Protocol);
        }
        if observed.0 & DW_SIGNAL_READABLE.0 == 0 && observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
            self.eof = true;
        }
        Ok(())
    }
    pub fn read<S: StreamSystem>(
        &mut self,
        system: &mut S,
        output: &mut [u8],
    ) -> Result<usize, StreamError> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.offset != self.used {
            return Ok(self.drain(output));
        }
        if self.eof {
            return Err(StreamError::Eof);
        }
        let mut wire = [0u8; MAX_RECORD_BYTES];
        let mut handles = [DwReceivedHandleInfoV1::default(); MAX_RECEIVED_HANDLES];
        let counts = match system.receive(self.endpoint.0, &mut wire, &mut handles) {
            Ok(counts) => counts,
            Err(error) => return Err(classify(error)),
        };
        if counts.bytes > wire.len() || counts.handles > handles.len() {
            return Err(StreamError::Protocol);
        }
        if counts.handles != 0 {
            for received in handles[..counts.handles].iter() {
                let _ = system.close(received.handle);
            }
            return Err(StreamError::ReceivedHandles);
        }
        let data = decode_data(&wire[..counts.bytes]).map_err(|_| StreamError::Protocol)?;
        self.used = data.payload().len();
        self.offset = 0;
        self.record[..self.used].copy_from_slice(data.payload());
        Ok(self.drain(output))
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
    pub fn observe_wait(&self, observed: DwSignals) -> Result<(), StreamError> {
        if observed.0 & !OUTPUT_WAIT_SIGNALS.0 != 0 {
            return Err(StreamError::Protocol);
        }
        if observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
            return Err(StreamError::Broken);
        }
        Ok(())
    }
    pub fn write<S: StreamSystem>(
        &mut self,
        system: &mut S,
        bytes: &[u8],
    ) -> Result<usize, StreamError> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let committed = core::cmp::min(bytes.len(), MAX_PAYLOAD_BYTES);
        let mut wire = [0u8; MAX_RECORD_BYTES];
        let size =
            encode_data(&bytes[..committed], &mut wire).map_err(|_| StreamError::Protocol)?;
        system
            .send(self.endpoint.0, &wire[..size])
            .map_err(classify)?;
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

    struct Fixture {
        incoming: Vec<Vec<u8>>,
        sends: Vec<Vec<u8>>,
        block_send: bool,
        received_handles: usize,
        closed: Vec<DwHandle>,
    }
    impl StreamSystem for Fixture {
        fn receive(
            &mut self,
            _: DwHandle,
            bytes: &mut [u8],
            handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, NativeError> {
            let record = self.incoming.remove(0);
            bytes[..record.len()].copy_from_slice(&record);
            for handle in handles[..self.received_handles].iter_mut() {
                handle.handle = DwHandle(77);
            }
            Ok(ReceiveCounts {
                bytes: record.len(),
                handles: self.received_handles,
            })
        }
        fn send(&mut self, _: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
            if self.block_send {
                return Err(NativeError::Status(DW_STATUS_WOULD_BLOCK));
            }
            self.sends.push(bytes.to_vec());
            Ok(())
        }
        fn close(&mut self, handle: DwHandle) -> Result<(), NativeError> {
            self.closed.push(handle);
            Ok(())
        }
    }
    fn endpoint() -> StreamEndpoint {
        StreamEndpoint(DwHandle(9))
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
            block_send: false,
            received_handles: 0,
            closed: vec![],
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
    fn output_bounds_packets_and_preserves_would_block() {
        let mut system = Fixture {
            incoming: vec![],
            sends: vec![],
            block_send: true,
            received_handles: 0,
            closed: vec![],
        };
        let mut output = NativeOutput::new(endpoint());
        assert_eq!(
            output.write(&mut system, b"x"),
            Err(StreamError::WouldBlock)
        );
        system.block_send = false;
        assert_eq!(
            output.write(&mut system, &[7; MAX_PAYLOAD_BYTES + 1]),
            Ok(MAX_PAYLOAD_BYTES)
        );
        assert_eq!(
            decode_data(&system.sends[0]).unwrap().payload().len(),
            MAX_PAYLOAD_BYTES
        );
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
            block_send: false,
            received_handles: 0,
            closed: vec![],
        };
        assert_eq!(closed.read(&mut fixture, &mut [0]), Err(StreamError::Eof));
    }
    #[test]
    fn unexpected_transferred_handles_are_closed_then_rejected() {
        let mut fixture = Fixture {
            incoming: vec![record(b"x")],
            sends: vec![],
            block_send: false,
            received_handles: 1,
            closed: vec![],
        };
        let mut input = NativeInput::new(endpoint());
        assert_eq!(
            input.read(&mut fixture, &mut [0]),
            Err(StreamError::ReceivedHandles)
        );
        assert_eq!(fixture.closed, [DwHandle(77)]);
    }
}
