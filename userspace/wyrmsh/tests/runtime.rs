// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::VecDeque;
use std::vec::Vec;

use deepwyrm_syscall::{
    DW_OBJECT_TYPE_CHANNEL, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DW_SIGNAL_WRITABLE,
    DW_STATUS_PEER_CLOSED, DW_STATUS_TIMED_OUT, DW_STATUS_WOULD_BLOCK, DwDeadline, DwHandle,
    DwObjectType, DwReceivedHandleInfoV1, DwRights, DwSignals, DwWaitItemV1, DwWaitResultV1,
};
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, LaunchProfile, WYRMSH_BYTES, encode_wyrmsh_init, parse_ready_for_profile,
};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, NativeError, ReceiveCounts, STARTUP_ABI_V1,
    STARTUP_ABI_V2, STARTUP_BLOCK_SIZE, STARTUP_BLOCK_V2_SIZE, StartupBlock, StartupRegisters,
    StreamSystem,
};
use wyrmroot_stream_proto::{MAX_PAYLOAD_BYTES, MAX_RECORD_BYTES, decode_data, encode_data};
use wyrmroot_wyrmsh::{EndpointRole, ShellError, WyrmshSystem, run_wyrmsh};
use wyrmroot_wyrmsh_core::COMMANDS;

const BASE: u64 = 0x40_0000;
const BOOTSTRAP: DwHandle = DwHandle(11);
const STDIN: DwHandle = DwHandle(80);
const STDOUT: DwHandle = DwHandle(90);
const STDERR: DwHandle = DwHandle(30);
const STATUS: DwHandle = DwHandle(43);
const REGISTRY: DwHandle = DwHandle(44);
const SHELL_JOBS: DwHandle = DwHandle(45);
const TRANSACTION: u64 = 0x91;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Trace {
    Ready,
    ReleaseWait,
    StreamSend(DwHandle),
    ControlWait,
}

struct Fixture {
    init: [u8; WYRMSH_BYTES],
    handles: [DwReceivedHandleInfoV1; 6],
    receive_counts: ReceiveCounts,
    bad_fresh_index: Option<usize>,
    incoming: VecDeque<Vec<u8>>,
    outputs: Vec<(DwHandle, Vec<u8>)>,
    ready: Vec<u8>,
    closed: Vec<DwHandle>,
    trace: Vec<Trace>,
    release_signals: DwSignals,
    block_send_once: bool,
    physical_eof: bool,
    control_loss_after_receives: Option<(usize, usize)>,
    receive_calls: usize,
}

impl Fixture {
    fn new(input_fragments: &[&[u8]]) -> Self {
        let mut init = [0; WYRMSH_BYTES];
        encode_wyrmsh_init(TRANSACTION, 2, 3, 4, 5, 6, 7, 8, 9, 10, &mut init).unwrap();
        let channel = |handle| DwReceivedHandleInfoV1 {
            handle,
            object_type: DW_OBJECT_TYPE_CHANNEL,
            rights: CHILD_CHANNEL_RIGHTS,
            ..DwReceivedHandleInfoV1::default()
        };
        Self {
            init,
            handles: [
                channel(STDIN),
                channel(STDOUT),
                channel(STDERR),
                channel(STATUS),
                channel(REGISTRY),
                channel(SHELL_JOBS),
            ],
            receive_counts: ReceiveCounts {
                bytes: WYRMSH_BYTES,
                handles: 6,
            },
            bad_fresh_index: None,
            incoming: input_fragments.iter().map(|bytes| wire(bytes)).collect(),
            outputs: vec![],
            ready: vec![],
            closed: vec![],
            trace: vec![],
            release_signals: DW_SIGNAL_PEER_CLOSED,
            block_send_once: false,
            physical_eof: false,
            control_loss_after_receives: None,
            receive_calls: 0,
        }
    }

    fn metadata(&self, handle: DwHandle) -> CapabilityInfo<DwObjectType, DwRights> {
        if handle == BOOTSTRAP {
            return CapabilityInfo {
                object_type: BOOTSTRAP_CHANNEL_EXPECTATION.object_type,
                rights: BOOTSTRAP_CHANNEL_EXPECTATION.rights,
            };
        }
        let index = self
            .handles
            .iter()
            .position(|received| received.handle == handle)
            .unwrap();
        CapabilityInfo {
            object_type: self.handles[index].object_type,
            rights: if self.bad_fresh_index == Some(index) {
                DwRights(CHILD_CHANNEL_RIGHTS.0 ^ 1)
            } else {
                self.handles[index].rights
            },
        }
    }

    fn output(&self, handle: DwHandle) -> Vec<u8> {
        let mut result = vec![];
        for (actual, record) in &self.outputs {
            if *actual == handle {
                result.extend_from_slice(decode_data(record).unwrap().payload());
            }
        }
        result
    }
}

impl WyrmshSystem for Fixture {
    fn query_capability_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
        Ok(self.metadata(handle))
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
        Ok(self.receive_counts)
    }

    fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
        assert_eq!(channel, BOOTSTRAP);
        self.trace.push(Trace::Ready);
        self.ready.extend_from_slice(bytes);
        Ok(())
    }

    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        self.closed.push(handle);
        Ok(())
    }

    fn wait_many(
        &mut self,
        items: &[DwWaitItemV1],
        deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, NativeError> {
        if items.len() == 1 && items[0].handle == BOOTSTRAP {
            self.trace.push(Trace::ReleaseWait);
            return Ok(wait_result(0, self.release_signals));
        }
        if let Some((after, index)) = self.control_loss_after_receives
            && self.receive_calls >= after
        {
            self.trace.push(Trace::ControlWait);
            return Ok(wait_result(index, DW_SIGNAL_PEER_CLOSED));
        }
        if deadline == deepwyrm_syscall::DW_DEADLINE_NOW {
            return Err(NativeError::Status(DW_STATUS_TIMED_OUT));
        }
        self.trace.push(Trace::ControlWait);
        if let Some((index, _)) = items
            .iter()
            .enumerate()
            .find(|(_, item)| item.handle == STDOUT && item.signals.0 & DW_SIGNAL_WRITABLE.0 != 0)
        {
            return Ok(wait_result(index, DW_SIGNAL_WRITABLE));
        }
        if let Some((index, _)) = items
            .iter()
            .enumerate()
            .find(|(_, item)| item.handle == STDERR && item.signals.0 & DW_SIGNAL_WRITABLE.0 != 0)
        {
            return Ok(wait_result(index, DW_SIGNAL_WRITABLE));
        }
        let index = items
            .iter()
            .position(|item| item.handle == STDIN)
            .expect("stdin wait item");
        Ok(wait_result(
            index,
            if self.incoming.is_empty() && self.physical_eof {
                DW_SIGNAL_PEER_CLOSED
            } else {
                DW_SIGNAL_READABLE
            },
        ))
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
        self.receive_calls += 1;
        let Some(record) = self.incoming.pop_front() else {
            return Err(NativeError::Status(if self.physical_eof {
                DW_STATUS_PEER_CLOSED
            } else {
                DW_STATUS_WOULD_BLOCK
            }));
        };
        bytes[..record.len()].copy_from_slice(&record);
        Ok(ReceiveCounts {
            bytes: record.len(),
            handles: 0,
        })
    }

    fn send(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
        assert!(channel == STDOUT || channel == STDERR);
        self.trace.push(Trace::StreamSend(channel));
        if self.block_send_once {
            self.block_send_once = false;
            return Err(NativeError::Status(DW_STATUS_WOULD_BLOCK));
        }
        self.outputs.push((channel, bytes.to_vec()));
        Ok(())
    }

    fn close(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        self.closed.push(handle);
        Ok(())
    }

    fn wait(&mut self, _: DwHandle, _: DwSignals) -> Result<DwSignals, NativeError> {
        panic!("the shell runtime must use the combined wait facade")
    }
}

fn wait_result(index: usize, observed: DwSignals) -> DwWaitResultV1 {
    DwWaitResultV1 {
        size: deepwyrm_syscall::DW_WAIT_RESULT_V1_SIZE,
        version: 1,
        index: index as u32,
        observed,
        ..DwWaitResultV1::default()
    }
}

fn wire(payload: &[u8]) -> Vec<u8> {
    let mut wire = [0; MAX_RECORD_BYTES];
    let size = encode_data(payload, &mut wire).unwrap();
    wire[..size].to_vec()
}

fn put_word(block: &mut [u8], offset: usize, value: u64) {
    block[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn run_v2(fixture: &mut Fixture, path: &str, environment: &[&str]) -> Result<(), ShellError> {
    let mut block = [0_u8; STARTUP_BLOCK_V2_SIZE];
    let argc = 1usize;
    put_word(&mut block, 0, argc as u64);
    let argv_end = 8 + argc * 8;
    let env_start = argv_end + 8;
    let aux_start = env_start + environment.len() * 8 + 8;
    let mut string_offset = aux_start + 16;
    put_word(&mut block, 8, BASE + string_offset as u64);
    block[string_offset..string_offset + path.len()].copy_from_slice(path.as_bytes());
    string_offset += path.len() + 1;
    for (index, value) in environment.iter().enumerate() {
        put_word(
            &mut block,
            env_start + index * 8,
            BASE + string_offset as u64,
        );
        block[string_offset..string_offset + value.len()].copy_from_slice(value.as_bytes());
        string_offset += value.len() + 1;
    }
    let startup = StartupBlock::parse(
        StartupRegisters {
            startup_argument0: BOOTSTRAP.0,
            startup_argument1: STARTUP_ABI_V2,
        },
        BASE,
        &block,
    )
    .unwrap();
    run_wyrmsh(fixture, startup)
}

fn run_v1(fixture: &mut Fixture) -> Result<(), ShellError> {
    let mut block = [0_u8; STARTUP_BLOCK_SIZE];
    put_word(&mut block, 0, 1);
    put_word(&mut block, 8, BASE + 40);
    put_word(&mut block, 8, BASE + 48);
    block[48..62].copy_from_slice(b"system/wyrmsh\0");
    let startup = StartupBlock::parse(
        StartupRegisters {
            startup_argument0: BOOTSTRAP.0,
            startup_argument1: STARTUP_ABI_V1,
        },
        BASE,
        &block,
    )
    .unwrap();
    run_wyrmsh(fixture, startup)
}

#[test]
fn startup_ready_release_and_local_builtins_use_the_real_stream_runtime() {
    let mut fixture =
        Fixture::new(&[b"\nhelp\necho a \"\" \xf0\x9f\x90\x89\necho\nclear\nservices\nexit\n"]);
    assert_eq!(run_v2(&mut fixture, "system/wyrmsh", &[]), Ok(()));
    assert_eq!(
        parse_ready_for_profile(LaunchProfile::Wyrmsh, &fixture.ready, TRANSACTION),
        Ok(())
    );
    let release = fixture
        .trace
        .iter()
        .position(|event| *event == Trace::ReleaseWait)
        .unwrap();
    let ready = fixture
        .trace
        .iter()
        .position(|event| *event == Trace::Ready)
        .unwrap();
    let first_output = fixture
        .trace
        .iter()
        .position(|event| matches!(event, Trace::StreamSend(_)))
        .unwrap();
    assert!(ready < release && release < first_output);

    let stdout = fixture.output(STDOUT);
    assert!(stdout.starts_with(b"\r\x1b[2Kwyrmsh> \n\r\x1b[2Kwyrmsh> "));
    let mut help = vec![];
    for spec in COMMANDS {
        help.extend_from_slice(spec.usage.as_bytes());
        help.push(b'\n');
    }
    assert!(stdout.windows(help.len()).any(|window| window == help));
    assert!(
        stdout
            .windows(8)
            .any(|window| window == b"a  \xf0\x9f\x90\x89\n")
    );
    assert!(
        stdout
            .windows(b"\x1b[2J\x1b[H\r\x1b[2Kwyrmsh> ".len())
            .any(|window| window == b"\x1b[2J\x1b[H\r\x1b[2Kwyrmsh> ")
    );
    assert!(
        stdout
            .windows(b"unavailable: services\n".len())
            .any(|window| window == b"unavailable: services\n")
    );
    assert!(fixture.output(STDERR).is_empty());
    assert_eq!(fixture.closed[0], BOOTSTRAP);
    assert_eq!(fixture.closed.len(), 7);
}

#[test]
fn utf8_csi_and_multiple_submissions_survive_record_fragmentation() {
    let bytes = b"echo ax\x1b[D\x7f\xf0\x9f\x90\x89\necho second\n\x04";
    let fragments: Vec<&[u8]> = bytes.chunks(1).collect();
    let mut fixture = Fixture::new(&fragments);
    assert_eq!(run_v2(&mut fixture, "system/wyrmsh", &[]), Ok(()));
    let stdout = fixture.output(STDOUT);
    assert!(
        stdout
            .windows(b"\xf0\x9f\x90\x89x\n".len())
            .any(|window| window == b"\xf0\x9f\x90\x89x\n")
    );
    assert!(
        stdout
            .windows(b"second\n".len())
            .any(|window| window == b"second\n")
    );
}

#[test]
fn output_backpressure_retries_only_the_uncommitted_suffix() {
    let mut baseline = Fixture::new(&[b"echo one two\nexit\n"]);
    assert_eq!(run_v2(&mut baseline, "system/wyrmsh", &[]), Ok(()));
    let expected = baseline.output(STDOUT);

    let mut blocked = Fixture::new(&[b"echo one two\nexit\n"]);
    blocked.block_send_once = true;
    assert_eq!(run_v2(&mut blocked, "system/wyrmsh", &[]), Ok(()));
    assert_eq!(blocked.output(STDOUT), expected);
    assert!(blocked.trace.contains(&Trace::ControlWait));
}

#[test]
fn ctrl_d_is_clean_but_physical_stdin_eof_is_a_generation_failure() {
    let mut ctrl_d = Fixture::new(&[b"\x04"]);
    assert_eq!(run_v2(&mut ctrl_d, "system/wyrmsh", &[]), Ok(()));

    let mut eof = Fixture::new(&[]);
    eof.physical_eof = true;
    assert_eq!(
        run_v2(&mut eof, "system/wyrmsh", &[]),
        Err(ShellError::RequiredEndpointLost(EndpointRole::Stdin))
    );
}

#[test]
fn empty_record_flood_is_bounded_before_a_control_peer_loss_wins() {
    let empty = wire(b"");
    let mut fixture = Fixture::new(&[]);
    fixture.incoming = VecDeque::from(vec![empty; 32]);
    fixture.control_loss_after_receives = Some((8, 0));
    assert_eq!(
        run_v2(&mut fixture, "system/wyrmsh", &[]),
        Err(ShellError::RequiredEndpointLost(
            EndpointRole::ConsoleStatus
        ))
    );
    assert_eq!(fixture.receive_calls, 8);
}

#[test]
fn every_required_control_and_output_peer_loss_is_fatal_before_prompt() {
    for (index, role) in [
        EndpointRole::ConsoleStatus,
        EndpointRole::Registry,
        EndpointRole::ShellJobs,
        EndpointRole::Stdout,
        EndpointRole::Stderr,
    ]
    .into_iter()
    .enumerate()
    {
        let mut fixture = Fixture::new(&[b"\x04"]);
        fixture.control_loss_after_receives = Some((0, index));
        assert_eq!(
            run_v2(&mut fixture, "system/wyrmsh", &[]),
            Err(ShellError::RequiredEndpointLost(role))
        );
        assert!(fixture.outputs.is_empty());
    }
}

#[test]
fn startup_rejects_abi1_wrong_path_and_environment_before_ready() {
    let mut abi1 = Fixture::new(&[b"\x04"]);
    assert_eq!(run_v1(&mut abi1), Err(ShellError::Startup));
    assert!(abi1.ready.is_empty());

    for (path, env) in [("bin/wyrmsh", &[][..]), ("system/wyrmsh", &["MODE=1"][..])] {
        let mut fixture = Fixture::new(&[b"\x04"]);
        assert_eq!(run_v2(&mut fixture, path, env), Err(ShellError::Startup));
        assert!(fixture.ready.is_empty());
    }
}

#[test]
fn malformed_init_and_fresh_metadata_fail_closed_and_release_roles() {
    let mut count = Fixture::new(&[b"\x04"]);
    count.receive_counts.handles = 5;
    assert!(matches!(
        run_v2(&mut count, "system/wyrmsh", &[]),
        Err(ShellError::ReceiveCounts(_))
    ));
    assert!(count.ready.is_empty());
    assert_eq!(count.closed.len(), 5);

    let mut received = Fixture::new(&[b"\x04"]);
    received.handles[4].rights = DwRights(CHILD_CHANNEL_RIGHTS.0 ^ 1);
    assert!(matches!(
        run_v2(&mut received, "system/wyrmsh", &[]),
        Err(ShellError::Launch(_))
    ));
    assert!(received.ready.is_empty());
    assert_eq!(received.closed.len(), 6);

    let mut fresh = Fixture::new(&[b"\x04"]);
    fresh.bad_fresh_index = Some(2);
    assert_eq!(
        run_v2(&mut fresh, "system/wyrmsh", &[]),
        Err(ShellError::FreshCapability { index: 2 })
    );
    assert!(fresh.ready.is_empty());
    assert_eq!(fresh.closed.len(), 6);

    for offset in (88..160).step_by(8) {
        let mut correlation = Fixture::new(&[b"\x04"]);
        correlation.init[offset..offset + 8].fill(0);
        assert!(matches!(
            run_v2(&mut correlation, "system/wyrmsh", &[]),
            Err(ShellError::Launch(_))
        ));
        assert!(correlation.ready.is_empty());
    }
}

#[test]
fn unexpected_bootstrap_data_never_reaches_the_prompt() {
    for signals in [
        DW_SIGNAL_READABLE,
        DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
    ] {
        let mut fixture = Fixture::new(&[b"\x04"]);
        fixture.release_signals = signals;
        assert_eq!(
            run_v2(&mut fixture, "system/wyrmsh", &[]),
            Err(ShellError::UnexpectedBootstrapRelease(signals))
        );
        assert!(fixture.outputs.is_empty());
    }
}

#[test]
fn editing_parser_and_usage_errors_redraw_without_control_requests() {
    let mut fixture = Fixture::new(&[
        b"bad\xff\x03echo \"unterminated\nclear too many operands\nunknown\nexit\n",
    ]);
    assert_eq!(run_v2(&mut fixture, "system/wyrmsh", &[]), Ok(()));
    let stderr = fixture.output(STDERR);
    for message in [
        &b"\nerror: invalid input\n"[..],
        &b"error: parse\n"[..],
        &b"error: usage\n"[..],
        &b"error: unknown command\n"[..],
    ] {
        assert!(
            stderr
                .windows(message.len())
                .any(|window| window == message)
        );
    }
}

#[test]
fn maximum_line_echo_streams_without_a_second_large_output_buffer() {
    let mut input = vec![];
    input.extend_from_slice(b"echo ");
    input.extend(std::iter::repeat_n(b'x', 4091));
    input.extend_from_slice(b"\nexit\n");
    let fragments: Vec<&[u8]> = input.chunks(MAX_PAYLOAD_BYTES).collect();
    let mut fixture = Fixture::new(&fragments);
    assert_eq!(run_v2(&mut fixture, "system/wyrmsh", &[]), Ok(()));
    let stdout = fixture.output(STDOUT);
    assert!(
        stdout
            .windows(4092)
            .any(|window| window[..4091].iter().all(|byte| *byte == b'x') && window[4091] == b'\n')
    );
}
