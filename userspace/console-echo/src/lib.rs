#![no_std]
#![forbid(unsafe_code)]

//! Bounded WYR1-D selector-32 console acceptance client.
//!
//! This is deliberately not a shell. It receives only the validated JobV2
//! stdin/stdout/stderr stream tuple, acknowledges startup, and recognizes the
//! three fixed test commands required by the native console proof.

use deepwyrm_syscall::{DwHandle, DwObjectType, DwReceivedHandleInfoV1, DwRights};
use wyrmroot_loader::launch::{
    HEADER_BYTES, LaunchError, LaunchProfile, encode_ready_for_profile, parse_init,
};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, CapabilityValidationError, NativeError,
    NativeInput, NativeOutput, ReceiveCounts, StreamError, StreamSystem, extract_job_v2_streams,
    native_error_code, validate_bootstrap_channel,
};

/// Sufficient for the 22-byte `ping <16 uppercase hex>\n` command, with a
/// modest fixed allowance for malformed-input detection. It is not a shell
/// input budget.
pub const LINE_CAPACITY: usize = 64;
const INIT_CAPACITY: usize = 64;

/// Bootstrap operations owned by the acceptance client.
pub trait ConsoleEchoSystem: StreamSystem {
    fn query_capability_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError>;
    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError>;
    fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError>;
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError>;
}

/// A bounded console-client failure.
#[derive(Debug, Eq, PartialEq)]
pub enum ConsoleEchoError {
    Native {
        operation: ConsoleEchoNativeOperation,
        cause: NativeError,
    },
    BootstrapChannel(CapabilityValidationError),
    ReceiveCounts(ReceiveCounts),
    Launch(LaunchError),
    Stream(StreamError),
    MalformedLine,
    LineTooLong,
}

/// Native operation associated with an application failure code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ConsoleEchoNativeOperation {
    QueryBootstrapChannel = 1,
    ReceiveInit = 2,
    SendReady = 3,
    CloseBootstrapChannel = 4,
}

impl ConsoleEchoError {
    /// Returns a bounded native application exit code for live diagnostics.
    #[must_use]
    pub const fn exit_code(&self) -> u32 {
        const PREFIX: u32 = 0xCE00_0000;
        match self {
            Self::Native { operation, cause } => {
                PREFIX | ((*operation as u32) << 16) | native_error_code(*cause)
            }
            Self::BootstrapChannel(_) => PREFIX | 0x02,
            Self::ReceiveCounts(_) => PREFIX | 0x03,
            Self::Launch(_) => PREFIX | 0x04,
            Self::Stream(_) => PREFIX | 0x05,
            Self::MalformedLine => PREFIX | 0x06,
            Self::LineTooLong => PREFIX | 0x07,
        }
    }
}

/// Validates the exact JobV2 stream launch, sends its correlation-exact READY
/// only after retaining the three roles, and serves the fixed command grammar.
pub fn run_console_echo<System: ConsoleEchoSystem>(
    system: &mut System,
    bootstrap_channel: DwHandle,
) -> Result<(), ConsoleEchoError> {
    let channel = system
        .query_capability_info(bootstrap_channel)
        .map_err(|cause| ConsoleEchoError::Native {
            operation: ConsoleEchoNativeOperation::QueryBootstrapChannel,
            cause,
        })?;
    validate_bootstrap_channel(channel, BOOTSTRAP_CHANNEL_EXPECTATION)
        .map_err(ConsoleEchoError::BootstrapChannel)?;

    let mut init = [0_u8; INIT_CAPACITY];
    let mut handles = [DwReceivedHandleInfoV1::default(); 3];
    let counts = system
        .receive_channel(bootstrap_channel, &mut init, &mut handles)
        .map_err(|cause| ConsoleEchoError::Native {
            operation: ConsoleEchoNativeOperation::ReceiveInit,
            cause,
        })?;
    if counts.bytes > init.len() || counts.handles != handles.len() {
        return Err(ConsoleEchoError::ReceiveCounts(counts));
    }
    let parsed = parse_init(LaunchProfile::JobV2Streams, &init[..counts.bytes], &handles)
        .map_err(ConsoleEchoError::Launch)?;
    let streams = extract_job_v2_streams(&init[..counts.bytes], &handles)
        .map_err(ConsoleEchoError::Launch)?;
    let mut stdin = NativeInput::new(streams.stdin);
    let mut stdout = NativeOutput::new(streams.stdout);
    let mut stderr = NativeOutput::new(streams.stderr);

    let mut ready = [0_u8; HEADER_BYTES];
    let ready_size = encode_ready_for_profile(
        LaunchProfile::JobV2Streams,
        parsed.transaction_id,
        &mut ready,
    )
    .map_err(ConsoleEchoError::Launch)?;
    system
        .send_channel(bootstrap_channel, &ready[..ready_size])
        .map_err(|cause| ConsoleEchoError::Native {
            operation: ConsoleEchoNativeOperation::SendReady,
            cause,
        })?;
    system
        .close_handle(bootstrap_channel)
        .map_err(|cause| ConsoleEchoError::Native {
            operation: ConsoleEchoNativeOperation::CloseBootstrapChannel,
            cause,
        })?;

    serve_commands(system, &mut stdin, &mut stdout, &mut stderr)
}

fn serve_commands<System: StreamSystem>(
    system: &mut System,
    stdin: &mut NativeInput,
    stdout: &mut NativeOutput,
    stderr: &mut NativeOutput,
) -> Result<(), ConsoleEchoError> {
    let mut line = LineBuffer::new();
    let mut bytes = [0_u8; LINE_CAPACITY];
    loop {
        match stdin.read(system, &mut bytes) {
            Ok(count) => {
                for byte in &bytes[..count] {
                    match line.push(*byte)? {
                        Some(Command::Ping(nonce)) => {
                            write_exact(system, stdout, b"pong ", &nonce)?;
                        }
                        Some(Command::Err(nonce)) => {
                            write_exact(system, stderr, b"err ", &nonce)?;
                        }
                        Some(Command::Exit) => return Ok(()),
                        None => {}
                    }
                }
            }
            Err(StreamError::WouldBlock) => stdin
                .wait_readable(system)
                .map_err(ConsoleEchoError::Stream)?,
            Err(StreamError::Eof) => return Ok(()),
            Err(error) => return Err(ConsoleEchoError::Stream(error)),
        }
    }
}

fn write_exact<System: StreamSystem>(
    system: &mut System,
    output: &mut NativeOutput,
    prefix: &[u8],
    nonce: &[u8; 16],
) -> Result<(), ConsoleEchoError> {
    let mut response = [0_u8; 22];
    let size = prefix.len() + nonce.len() + 1;
    response[..prefix.len()].copy_from_slice(prefix);
    response[prefix.len()..prefix.len() + nonce.len()].copy_from_slice(nonce);
    response[size - 1] = b'\n';
    if output
        .write_wait(system, &response[..size])
        .map_err(ConsoleEchoError::Stream)?
        != size
    {
        return Err(ConsoleEchoError::Stream(StreamError::Protocol));
    }
    Ok(())
}

enum Command {
    Ping([u8; 16]),
    Err([u8; 16]),
    Exit,
}

struct LineBuffer {
    bytes: [u8; LINE_CAPACITY],
    used: usize,
}

impl LineBuffer {
    const fn new() -> Self {
        Self {
            bytes: [0; LINE_CAPACITY],
            used: 0,
        }
    }

    fn push(&mut self, byte: u8) -> Result<Option<Command>, ConsoleEchoError> {
        if self.used == self.bytes.len() || (self.used + 1 == self.bytes.len() && byte != b'\n') {
            return Err(ConsoleEchoError::LineTooLong);
        }
        self.bytes[self.used] = byte;
        self.used += 1;
        if byte != b'\n' {
            return Ok(None);
        }
        let command = parse_command(&self.bytes[..self.used])?;
        self.used = 0;
        Ok(Some(command))
    }
}

fn parse_command(line: &[u8]) -> Result<Command, ConsoleEchoError> {
    if line == b"exit\n" {
        return Ok(Command::Exit);
    }
    let (prefix, is_ping) = if line.len() == 22 && line.starts_with(b"ping ") {
        (&b"ping "[..], true)
    } else if line.len() == 21 && line.starts_with(b"err ") {
        (&b"err "[..], false)
    } else {
        return Err(ConsoleEchoError::MalformedLine);
    };
    let nonce_start = prefix.len();
    let nonce_slice = &line[nonce_start..nonce_start + 16];
    if line[line.len() - 1] != b'\n' || !nonce_slice.iter().all(|byte| is_upper_hex(*byte)) {
        return Err(ConsoleEchoError::MalformedLine);
    }
    let nonce = nonce_slice
        .try_into()
        .map_err(|_| ConsoleEchoError::MalformedLine)?;
    Ok(if is_ping {
        Command::Ping(nonce)
    } else {
        Command::Err(nonce)
    })
}

const fn is_upper_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (byte >= b'A' && byte <= b'F')
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use deepwyrm_syscall::{
        DW_OBJECT_TYPE_CHANNEL, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_WRITABLE, DW_STATUS_WOULD_BLOCK,
        DwSignals,
    };
    use std::collections::VecDeque;
    use std::vec;
    use std::vec::Vec;
    use wyrmroot_loader::launch::{CHILD_CHANNEL_RIGHTS, encode_init, parse_ready_for_profile};
    use wyrmroot_stream_proto::{MAX_RECORD_BYTES, decode_data, encode_data};

    const BOOTSTRAP: DwHandle = DwHandle(11);
    const STDIN: DwHandle = DwHandle(21);
    const STDOUT: DwHandle = DwHandle(22);
    const STDERR: DwHandle = DwHandle(23);

    struct Fixture {
        init: [u8; INIT_CAPACITY],
        handles: [DwReceivedHandleInfoV1; 3],
        incoming: VecDeque<Vec<u8>>,
        outputs: Vec<(DwHandle, Vec<u8>)>,
        bootstrap_output: Vec<u8>,
        closed: Vec<DwHandle>,
        waits: VecDeque<DwSignals>,
        block_output_once: bool,
        send_attempts: usize,
    }

    impl Fixture {
        fn with_records(records: &[&[u8]]) -> Self {
            let mut init = [0; INIT_CAPACITY];
            encode_init(LaunchProfile::JobV2Streams, 0x92, &mut init).unwrap();
            let channel = |raw| DwReceivedHandleInfoV1 {
                handle: DwHandle(raw),
                object_type: DW_OBJECT_TYPE_CHANNEL,
                rights: CHILD_CHANNEL_RIGHTS,
                ..DwReceivedHandleInfoV1::default()
            };
            Self {
                init,
                handles: [channel(STDIN.0), channel(STDOUT.0), channel(STDERR.0)],
                incoming: records.iter().map(|record| wire(record)).collect(),
                outputs: vec![],
                bootstrap_output: vec![],
                closed: vec![],
                waits: VecDeque::from([DW_SIGNAL_PEER_CLOSED]),
                block_output_once: false,
                send_attempts: 0,
            }
        }
    }

    impl ConsoleEchoSystem for Fixture {
        fn query_capability_info(
            &mut self,
            handle: DwHandle,
        ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
            assert_eq!(handle, BOOTSTRAP);
            Ok(CapabilityInfo {
                object_type: DW_OBJECT_TYPE_CHANNEL,
                rights: BOOTSTRAP_CHANNEL_EXPECTATION.rights,
            })
        }
        fn receive_channel(
            &mut self,
            channel: DwHandle,
            bytes: &mut [u8],
            handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, NativeError> {
            assert_eq!(channel, BOOTSTRAP);
            bytes.copy_from_slice(&self.init);
            handles.copy_from_slice(&self.handles);
            Ok(ReceiveCounts {
                bytes: self.init.len(),
                handles: self.handles.len(),
            })
        }
        fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
            assert_eq!(channel, BOOTSTRAP);
            self.bootstrap_output.extend_from_slice(bytes);
            Ok(())
        }
        fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
            self.closed.push(handle);
            Ok(())
        }
    }

    impl StreamSystem for Fixture {
        fn receive(
            &mut self,
            channel: DwHandle,
            bytes: &mut [u8],
            _: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, NativeError> {
            assert_eq!(channel, STDIN);
            let Some(record) = self.incoming.pop_front() else {
                return Err(NativeError::Status(DW_STATUS_WOULD_BLOCK));
            };
            bytes[..record.len()].copy_from_slice(&record);
            Ok(ReceiveCounts {
                bytes: record.len(),
                handles: 0,
            })
        }
        fn send(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
            assert!(channel == STDOUT || channel == STDERR);
            self.send_attempts += 1;
            if self.block_output_once {
                self.block_output_once = false;
                return Err(NativeError::Status(DW_STATUS_WOULD_BLOCK));
            }
            self.outputs.push((channel, bytes.to_vec()));
            Ok(())
        }
        fn close(&mut self, handle: DwHandle) -> Result<(), NativeError> {
            self.closed.push(handle);
            Ok(())
        }
        fn wait(
            &mut self,
            _: DwHandle,
            _: deepwyrm_syscall::DwSignals,
        ) -> Result<deepwyrm_syscall::DwSignals, NativeError> {
            Ok(self.waits.pop_front().unwrap_or(DW_SIGNAL_PEER_CLOSED))
        }
    }

    fn wire(payload: &[u8]) -> Vec<u8> {
        let mut bytes = [0; MAX_RECORD_BYTES];
        let size = encode_data(payload, &mut bytes).unwrap();
        bytes[..size].to_vec()
    }

    fn decoded_outputs(fixture: &Fixture) -> Vec<(DwHandle, Vec<u8>)> {
        fixture
            .outputs
            .iter()
            .map(|(handle, wire)| (*handle, decode_data(wire).unwrap().payload().to_vec()))
            .collect()
    }

    #[test]
    fn split_records_drive_the_exact_stdout_and_stderr_roles() {
        let mut fixture =
            Fixture::with_records(&[b"ping 01234567", b"89ABCDEF\nerr FEDCBA9876543210\nexit\n"]);
        assert_eq!(run_console_echo(&mut fixture, BOOTSTRAP), Ok(()));
        assert_eq!(
            decoded_outputs(&fixture),
            vec![
                (STDOUT, b"pong 0123456789ABCDEF\n".to_vec()),
                (STDERR, b"err FEDCBA9876543210\n".to_vec()),
            ]
        );
        assert_eq!(fixture.closed, vec![BOOTSTRAP]);
        assert_eq!(
            parse_ready_for_profile(LaunchProfile::JobV2Streams, &fixture.bootstrap_output, 0x92),
            Ok(())
        );
    }

    #[test]
    fn unnormalized_crlf_is_not_accepted_by_the_child_grammar() {
        let mut fixture = Fixture::with_records(&[b"ping 0123456789ABCDEF\r\n"]);
        assert_eq!(
            run_console_echo(&mut fixture, BOOTSTRAP),
            Err(ConsoleEchoError::MalformedLine)
        );
        assert!(fixture.outputs.is_empty());
    }

    #[test]
    fn malformed_utf8_and_wrong_grammar_fail_closed() {
        for record in [
            &b"ping 0123456789ABCDE\xff\n"[..],
            &b"Ping 0123456789ABCDEF\n"[..],
        ] {
            let mut fixture = Fixture::with_records(&[record]);
            assert_eq!(
                run_console_echo(&mut fixture, BOOTSTRAP),
                Err(ConsoleEchoError::MalformedLine)
            );
            assert!(fixture.outputs.is_empty());
        }
    }

    #[test]
    fn oversized_line_fails_closed_before_a_newline() {
        let oversized = [b'X'; LINE_CAPACITY];
        let mut fixture = Fixture::with_records(&[&oversized]);
        assert_eq!(
            run_console_echo(&mut fixture, BOOTSTRAP),
            Err(ConsoleEchoError::LineTooLong)
        );
        assert!(fixture.outputs.is_empty());
    }

    #[test]
    fn would_block_retries_the_caller_owned_response_after_a_writable_hint() {
        let mut fixture = Fixture::with_records(&[b"ping 0123456789ABCDEF\nexit\n"]);
        fixture.block_output_once = true;
        fixture.waits = VecDeque::from([DW_SIGNAL_WRITABLE]);
        assert_eq!(run_console_echo(&mut fixture, BOOTSTRAP), Ok(()));
        assert_eq!(fixture.send_attempts, 2);
        assert_eq!(
            decoded_outputs(&fixture),
            vec![(STDOUT, b"pong 0123456789ABCDEF\n".to_vec())]
        );
    }

    #[test]
    fn peer_close_is_a_clean_session_exit() {
        let mut fixture = Fixture::with_records(&[]);
        assert_eq!(run_console_echo(&mut fixture, BOOTSTRAP), Ok(()));
        assert!(fixture.outputs.is_empty());
    }

    #[test]
    fn exact_public_line_bound_covers_the_longest_command() {
        assert_eq!(b"ping 0123456789ABCDEF\n".len(), 22);
        assert!(LINE_CAPACITY > b"ping 0123456789ABCDEF\n".len());
    }
}
