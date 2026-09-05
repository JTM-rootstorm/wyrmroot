// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::VecDeque;
use std::vec::Vec;

use deepwyrm_syscall::{
    DW_OBJECT_TYPE_CHANNEL, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DW_SIGNAL_WRITABLE,
    DW_STATUS_PEER_CLOSED, DW_STATUS_TIMED_OUT, DW_STATUS_WOULD_BLOCK, DwDeadline, DwHandle,
    DwObjectType, DwReceivedHandleInfoV1, DwRights, DwSignals, DwWaitItemV1, DwWaitResultV1,
};
use wyrmroot_console_proto::{
    ErrorCode as StatusErrorCode, Header as StatusHeader, LastFailure, Snapshot,
    State as StatusState, encode_error as encode_status_error, encode_snapshot,
};
use wyrmroot_launch_proto::{
    ErrorCode as LaunchErrorCode, Message as LaunchMessage, Reservation,
    encode_error as encode_launch_error, encode_job_list, parse_message as parse_launch_message,
};
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, LaunchProfile, WYRMSH_BYTES, encode_wyrmsh_init, parse_ready_for_profile,
};
use wyrmroot_registry_proto::{
    ErrorCode as RegistryErrorCode, Header as RegistryHeader, Message as RegistryMessage,
    MessageType as RegistryMessageType, ProtocolVersion, ServiceListRecord,
    encode_error as encode_registry_error, encode_service_list, parse as parse_registry_message,
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

#[derive(Clone)]
struct ControlDatagram {
    channel: DwHandle,
    bytes: Vec<u8>,
    handles: Vec<DwReceivedHandleInfoV1>,
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
    block_second_long_packet: bool,
    long_packet_attempts: usize,
    control_loss_on_output_wait: Option<usize>,
    physical_eof: bool,
    control_loss_after_receives: Option<(usize, usize)>,
    receive_calls: usize,
    control_incoming: VecDeque<ControlDatagram>,
    control_requests: Vec<(DwHandle, Vec<u8>)>,
    scripted_controls: bool,
    control_send_would_block: VecDeque<DwHandle>,
    now: u64,
    clock_values: VecDeque<u64>,
    timeout_control: Option<DwHandle>,
    control_loss_on_transaction_wait: Option<usize>,
    waited_deadlines: Vec<DwDeadline>,
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
            block_second_long_packet: false,
            long_packet_attempts: 0,
            control_loss_on_output_wait: None,
            physical_eof: false,
            control_loss_after_receives: None,
            receive_calls: 0,
            control_incoming: VecDeque::new(),
            control_requests: vec![],
            scripted_controls: false,
            control_send_would_block: VecDeque::new(),
            now: 5_000_000_000,
            clock_values: VecDeque::new(),
            timeout_control: None,
            control_loss_on_transaction_wait: None,
            waited_deadlines: vec![],
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

    fn queue_control(&mut self, channel: DwHandle, bytes: &[u8]) {
        self.scripted_controls = true;
        self.control_incoming.push_back(ControlDatagram {
            channel,
            bytes: bytes.to_vec(),
            handles: vec![],
        });
    }

    fn queue_control_with_handle(&mut self, channel: DwHandle, bytes: &[u8], handle: DwHandle) {
        self.scripted_controls = true;
        self.control_incoming.push_back(ControlDatagram {
            channel,
            bytes: bytes.to_vec(),
            handles: vec![DwReceivedHandleInfoV1 {
                handle,
                object_type: DW_OBJECT_TYPE_CHANNEL,
                rights: CHILD_CHANNEL_RIGHTS,
                ..DwReceivedHandleInfoV1::default()
            }],
        });
    }

    fn default_control_reply(&mut self, channel: DwHandle, request: &[u8]) {
        let mut bytes = [0_u8; 416];
        let used = if channel == REGISTRY {
            let parsed = parse_registry_message(request, 0).unwrap();
            assert!(matches!(parsed.message, RegistryMessage::Enumerate));
            encode_service_list(
                RegistryHeader {
                    message_type: RegistryMessageType::ServiceList,
                    ..parsed.header
                },
                0,
                1,
                0,
                &[],
                &mut bytes,
            )
            .unwrap()
        } else if channel == SHELL_JOBS {
            let parsed = parse_launch_message(request, 0).unwrap();
            assert!(matches!(parsed.message, LaunchMessage::ListJobs));
            encode_job_list(parsed.reservation, &[], &mut bytes).unwrap()
        } else {
            let wyrmroot_console_proto::Message::Query(header) =
                wyrmroot_console_proto::decode(request, 0).unwrap()
            else {
                panic!("status query")
            };
            encode_snapshot(header, status_snapshot(), &mut bytes).unwrap()
        };
        self.control_incoming.push_back(ControlDatagram {
            channel,
            bytes: bytes[..used].to_vec(),
            handles: vec![],
        });
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
        if channel == BOOTSTRAP {
            bytes.copy_from_slice(&self.init);
            handles.copy_from_slice(&self.handles);
            return Ok(self.receive_counts);
        }
        let message = self.control_incoming.pop_front().expect("control reply");
        assert_eq!(message.channel, channel);
        bytes[..message.bytes.len()].copy_from_slice(&message.bytes);
        for (target, source) in handles.iter_mut().zip(&message.handles) {
            *target = *source;
        }
        Ok(ReceiveCounts {
            bytes: message.bytes.len(),
            handles: message.handles.len(),
        })
    }

    fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
        if channel == BOOTSTRAP {
            self.trace.push(Trace::Ready);
            self.ready.extend_from_slice(bytes);
            return Ok(());
        }
        if self.control_send_would_block.front() == Some(&channel) {
            self.control_send_would_block.pop_front();
            return Err(NativeError::Status(DW_STATUS_WOULD_BLOCK));
        }
        self.control_requests.push((channel, bytes.to_vec()));
        if !self.scripted_controls {
            self.default_control_reply(channel, bytes);
        }
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
        self.waited_deadlines.push(deadline);
        if let Some(index) = self.control_loss_on_transaction_wait {
            return Ok(wait_result(index, DW_SIGNAL_PEER_CLOSED));
        }
        if let Some(handle) = self.timeout_control
            && items.iter().any(|item| {
                item.handle == handle
                    && item.signals.0 & (DW_SIGNAL_READABLE.0 | DW_SIGNAL_WRITABLE.0) != 0
            })
        {
            return Err(NativeError::Status(DW_STATUS_TIMED_OUT));
        }
        if let Some(message) = self.control_incoming.front()
            && let Some(index) = items.iter().position(|item| {
                item.handle == message.channel && item.signals.0 & DW_SIGNAL_READABLE.0 != 0
            })
        {
            return Ok(wait_result(index, DW_SIGNAL_READABLE));
        }
        if let Some(index) = items.iter().position(|item| {
            (item.handle == STATUS || item.handle == REGISTRY || item.handle == SHELL_JOBS)
                && item.signals.0 & DW_SIGNAL_WRITABLE.0 != 0
        }) {
            return Ok(wait_result(index, DW_SIGNAL_WRITABLE));
        }
        if let Some((index, _)) = items
            .iter()
            .enumerate()
            .find(|(_, item)| item.handle == STDOUT && item.signals.0 & DW_SIGNAL_WRITABLE.0 != 0)
        {
            if let Some(loss) = self.control_loss_on_output_wait {
                return Ok(wait_result(loss, DW_SIGNAL_PEER_CLOSED));
            }
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

    fn monotonic_active_now(&mut self) -> Result<u64, NativeError> {
        Ok(self.clock_values.pop_front().unwrap_or(self.now))
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
        let payload = decode_data(bytes).unwrap().payload();
        if channel == STDOUT
            && payload.len() == MAX_PAYLOAD_BYTES
            && payload.iter().all(|byte| *byte == b'x')
        {
            self.long_packet_attempts += 1;
            if self.block_second_long_packet && self.long_packet_attempts == 2 {
                return Err(NativeError::Status(DW_STATUS_WOULD_BLOCK));
            }
        }
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

fn status_snapshot() -> Snapshot {
    Snapshot {
        state: StatusState::Active,
        flags: wyrmroot_console_proto::FLAG_SERIAL_PRESENT
            | wyrmroot_console_proto::FLAG_CHILD_PRESENT,
        serial_registry_generation: 12,
        publication_generation: 13,
        device_bundle: 14,
        driver_attempt: 15,
        raw_stream_generation: 16,
        child_generation: 9,
        outer_job: 17,
        outer_launch_transaction: 10,
        live_peer_mask: 7,
        input_queue_bytes: 1,
        stdout_queue_bytes: 2,
        stderr_queue_bytes: 3,
        child_failures: 0,
        serial_failures: 0,
        last_failure: LastFailure::None,
    }
}

fn registry_reply(
    transaction: u64,
    page_index: u16,
    page_count: u16,
    total_count: u16,
    records: &[ServiceListRecord<'_>],
) -> Vec<u8> {
    let mut bytes = [0_u8; 416];
    let size = encode_service_list(
        RegistryHeader {
            message_type: RegistryMessageType::ServiceList,
            registry_generation: 2,
            endpoint_id: 3,
            endpoint_generation: 4,
            transaction_id: transaction,
        },
        page_index,
        page_count,
        total_count,
        records,
        &mut bytes,
    )
    .unwrap();
    bytes[..size].to_vec()
}

fn service<'a>(
    name: &'a [u8],
    protocol_id: u64,
    generation: u64,
    versions: &[ProtocolVersion],
) -> ServiceListRecord<'a> {
    let mut values = [ProtocolVersion::default(); 4];
    values[..versions.len()].copy_from_slice(versions);
    ServiceListRecord {
        protocol_id,
        service_generation: generation,
        versions: values,
        version_count: versions.len() as u8,
        service_name: name,
    }
}

fn jobs_reply(transaction: u64, ids: &[u64]) -> Vec<u8> {
    let mut bytes = [0_u8; 312];
    let size = encode_job_list(
        Reservation {
            connection_id: 5,
            generation: 6,
            transaction_id: transaction,
        },
        ids,
        &mut bytes,
    )
    .unwrap();
    bytes[..size].to_vec()
}

fn status_reply(transaction: u64, snapshot: Snapshot) -> Vec<u8> {
    let mut bytes = [0_u8; wyrmroot_console_proto::MAX_MESSAGE_BYTES];
    let size = encode_snapshot(
        StatusHeader {
            transaction_id: transaction,
            console_generation: 7,
            status_generation: 8,
        },
        snapshot,
        &mut bytes,
    )
    .unwrap();
    bytes[..size].to_vec()
}

fn registry_error(transaction: u64, code: RegistryErrorCode) -> Vec<u8> {
    let mut bytes = [0_u8; 72];
    let size = encode_registry_error(
        RegistryHeader {
            message_type: RegistryMessageType::Error,
            registry_generation: 2,
            endpoint_id: 3,
            endpoint_generation: 4,
            transaction_id: transaction,
        },
        code,
        &mut bytes,
    )
    .unwrap();
    bytes[..size].to_vec()
}

fn launch_error(transaction: u64, code: LaunchErrorCode) -> Vec<u8> {
    let mut bytes = [0_u8; 56];
    let size = encode_launch_error(
        Reservation {
            connection_id: 5,
            generation: 6,
            transaction_id: transaction,
        },
        code,
        &mut bytes,
    )
    .unwrap();
    bytes[..size].to_vec()
}

fn status_error(transaction: u64, code: StatusErrorCode) -> Vec<u8> {
    let mut bytes = [0_u8; wyrmroot_console_proto::ERROR_BYTES];
    let size = encode_status_error(
        StatusHeader {
            transaction_id: transaction,
            console_generation: 7,
            status_generation: 8,
        },
        code,
        &mut bytes,
    )
    .unwrap();
    bytes[..size].to_vec()
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
            .windows(b"services: empty\n".len())
            .any(|window| window == b"services: empty\n")
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
fn partial_long_echo_waits_then_retries_only_the_uncommitted_suffix() {
    let mut input = vec![];
    input.extend_from_slice(b"echo ");
    input.extend(std::iter::repeat_n(b'x', 4091));
    input.extend_from_slice(b"\nexit\n");
    let fragments: Vec<&[u8]> = input.chunks(MAX_PAYLOAD_BYTES).collect();

    let mut fixture = Fixture::new(&fragments);
    fixture.block_second_long_packet = true;
    assert_eq!(run_v2(&mut fixture, "system/wyrmsh", &[]), Ok(()));
    let stdout = fixture.output(STDOUT);
    assert!(
        stdout
            .windows(4092)
            .any(|window| window[..4091].iter().all(|byte| *byte == b'x') && window[4091] == b'\n')
    );
    assert_eq!(fixture.long_packet_attempts, 4);
    assert!(fixture.trace.contains(&Trace::ControlWait));
}

#[test]
fn required_control_loss_wins_while_partial_output_is_blocked() {
    let mut input = vec![];
    input.extend_from_slice(b"echo ");
    input.extend(std::iter::repeat_n(b'x', 2048));
    input.push(b'\n');
    let fragments: Vec<&[u8]> = input.chunks(MAX_PAYLOAD_BYTES).collect();

    let mut fixture = Fixture::new(&fragments);
    fixture.block_second_long_packet = true;
    fixture.control_loss_on_output_wait = Some(1);
    assert_eq!(
        run_v2(&mut fixture, "system/wyrmsh", &[]),
        Err(ShellError::RequiredEndpointLost(EndpointRole::Registry))
    );
    assert_eq!(fixture.long_packet_attempts, 2);
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

#[test]
fn inspection_commands_use_exact_transactions_and_format_complete_results() {
    let mut fixture = Fixture::new(&[b"services\ntasks\nstatus\nexit\n"]);
    let v10 = ProtocolVersion { major: 1, minor: 0 };
    let v11 = ProtocolVersion { major: 1, minor: 1 };
    let page0 = registry_reply(
        2,
        0,
        2,
        3,
        &[
            service(b"console", 30, 101, &[v10]),
            service(b"registry", 10, 102, &[v10, v11]),
        ],
    );
    let page1 = registry_reply(2, 1, 2, 3, &[service(b"serial", 20, 103, &[v11])]);
    fixture.queue_control(REGISTRY, &page0);
    fixture.queue_control(REGISTRY, &page1);
    fixture.queue_control(SHELL_JOBS, &jobs_reply(1, &[91, 7, 44]));
    fixture.queue_control(STATUS, &status_reply(1, status_snapshot()));

    assert_eq!(run_v2(&mut fixture, "system/wyrmsh", &[]), Ok(()));
    let stdout = fixture.output(STDOUT);
    for expected in [
        &b"service name=console protocol=30 versions=1.0 generation=101\n"[..],
        &b"service name=registry protocol=10 versions=1.0,1.1 generation=102\n"[..],
        &b"service name=serial protocol=20 versions=1.1 generation=103\n"[..],
        &b"task job=91 state=active\n"[..],
        &b"task job=7 state=active\n"[..],
        &b"task job=44 state=active\n"[..],
        &b"status state=active shell-generation=9 endpoints=healthy"[..],
    ] {
        assert!(
            stdout
                .windows(expected.len())
                .any(|window| window == expected)
        );
    }
    assert_eq!(fixture.control_requests.len(), 3);
    let registry = parse_registry_message(&fixture.control_requests[0].1, 0).unwrap();
    assert_eq!(registry.header.transaction_id, 2);
    let launch = parse_launch_message(&fixture.control_requests[1].1, 0).unwrap();
    assert_eq!(launch.reservation.transaction_id, 1);
    let wyrmroot_console_proto::Message::Query(status) =
        wyrmroot_console_proto::decode(&fixture.control_requests[2].1, 0).unwrap()
    else {
        panic!("status query")
    };
    assert_eq!(status.transaction_id, 1);
    assert!(
        fixture
            .waited_deadlines
            .iter()
            .all(|deadline| *deadline == DwDeadline(fixture.now + 1_000_000_000))
    );
}

#[test]
fn maximum_services_and_tasks_remain_bounded_and_preserve_wire_order() {
    let mut fixture = Fixture::new(&[b"services\ntasks\nexit\n"]);
    let version = ProtocolVersion { major: 1, minor: 0 };
    let names: Vec<Vec<u8>> = (0..32)
        .map(|index| format!("service{index:02}").into_bytes())
        .collect();
    for page in 0..16 {
        let first = service(
            &names[page * 2],
            100 + page as u64 * 2,
            200 + page as u64 * 2,
            &[version],
        );
        let second = service(
            &names[page * 2 + 1],
            101 + page as u64 * 2,
            201 + page as u64 * 2,
            &[version],
        );
        fixture.queue_control(
            REGISTRY,
            &registry_reply(2, page as u16, 16, 32, &[first, second]),
        );
    }
    let ids: Vec<u64> = (0..32).map(|index| 1_000 - index).collect();
    fixture.queue_control(SHELL_JOBS, &jobs_reply(1, &ids));

    assert_eq!(run_v2(&mut fixture, "system/wyrmsh", &[]), Ok(()));
    let stdout = fixture.output(STDOUT);
    assert_eq!(
        stdout
            .windows(b"service name=".len())
            .filter(|window| *window == b"service name=")
            .count(),
        32
    );
    assert_eq!(
        stdout
            .windows(b" state=active\n".len())
            .filter(|window| *window == b" state=active\n")
            .count(),
        32
    );
    let first = stdout
        .windows(b"task job=1000".len())
        .position(|window| window == b"task job=1000")
        .unwrap();
    let second = stdout
        .windows(b"task job=999".len())
        .position(|window| window == b"task job=999")
        .unwrap();
    assert!(first < second);
}

#[test]
fn status_reports_every_state_and_valid_no_child_snapshots_without_authority_values() {
    let mut fixture = Fixture::new(&[b"status\nstatus\nstatus\nstatus\nstatus\nstatus\nexit\n"]);
    for (index, state) in [
        StatusState::Active,
        StatusState::RetiringChild,
        StatusState::AwaitingReap,
        StatusState::Reconnecting,
        StatusState::Exhausted,
        StatusState::FailClosed,
    ]
    .into_iter()
    .enumerate()
    {
        let snapshot = if matches!(
            state,
            StatusState::Reconnecting | StatusState::Exhausted | StatusState::FailClosed
        ) {
            Snapshot {
                state,
                flags: 0,
                serial_registry_generation: 0,
                publication_generation: 0,
                device_bundle: 0,
                driver_attempt: 0,
                raw_stream_generation: 0,
                child_generation: 0,
                outer_job: 0,
                outer_launch_transaction: 0,
                live_peer_mask: 0,
                input_queue_bytes: 0,
                stdout_queue_bytes: 0,
                stderr_queue_bytes: 0,
                child_failures: 4,
                serial_failures: 4,
                last_failure: LastFailure::NoChild,
            }
        } else {
            Snapshot {
                state,
                ..status_snapshot()
            }
        };
        fixture.queue_control(STATUS, &status_reply(index as u64 + 1, snapshot));
    }
    assert_eq!(run_v2(&mut fixture, "system/wyrmsh", &[]), Ok(()));
    let stdout = fixture.output(STDOUT);
    for state in [
        b"state=active".as_slice(),
        b"state=retiring-child",
        b"state=awaiting-reap",
        b"state=reconnecting",
        b"state=exhausted",
        b"state=fail-closed",
    ] {
        assert!(stdout.windows(state.len()).any(|window| window == state));
    }
    assert!(
        !stdout
            .windows(b"device-bundle".len())
            .any(|window| window == b"device-bundle")
    );
    assert!(
        !stdout
            .windows(b"endpoint-id".len())
            .any(|window| window == b"endpoint-id")
    );
}

#[test]
fn malformed_or_stale_control_replies_fail_without_partial_or_guessed_data() {
    let version = ProtocolVersion { major: 1, minor: 0 };
    let mut services = Fixture::new(&[b"services\n"]);
    services.queue_control(
        REGISTRY,
        &registry_reply(
            2,
            0,
            2,
            3,
            &[
                service(b"middle", 1, 1, &[version]),
                service(b"zulu", 2, 2, &[version]),
            ],
        ),
    );
    services.queue_control(
        REGISTRY,
        &registry_reply(2, 1, 2, 3, &[service(b"alpha", 3, 3, &[version])]),
    );
    assert_eq!(
        run_v2(&mut services, "system/wyrmsh", &[]),
        Err(ShellError::InspectionProtocol)
    );
    assert!(
        !services
            .output(STDOUT)
            .windows(b"service name=".len())
            .any(|window| window == b"service name=")
    );

    let mut tasks = Fixture::new(&[b"tasks\n"]);
    tasks.queue_control(SHELL_JOBS, &jobs_reply(2, &[4]));
    assert_eq!(
        run_v2(&mut tasks, "system/wyrmsh", &[]),
        Err(ShellError::InspectionProtocol)
    );

    let mut status = status_snapshot();
    status.child_generation = 99;
    let mut shell = Fixture::new(&[b"status\n"]);
    shell.queue_control(STATUS, &status_reply(1, status));
    assert_eq!(
        run_v2(&mut shell, "system/wyrmsh", &[]),
        Err(ShellError::InspectionProtocol)
    );
}

#[test]
fn typed_control_errors_are_reported_and_fail_closed() {
    let cases = [
        (
            REGISTRY,
            registry_error(2, RegistryErrorCode::EnumerationDenied),
            b"unavailable: services\n".as_slice(),
            b"services\n".as_slice(),
        ),
        (
            SHELL_JOBS,
            launch_error(1, LaunchErrorCode::ForeignOrUnknownJob),
            b"unavailable: tasks\n".as_slice(),
            b"tasks\n".as_slice(),
        ),
    ];
    for (channel, response, diagnostic, input) in cases {
        let mut fixture = Fixture::new(&[input]);
        fixture.queue_control(channel, &response);
        assert_eq!(
            run_v2(&mut fixture, "system/wyrmsh", &[]),
            Err(ShellError::InspectionProtocol)
        );
        assert!(
            fixture
                .output(STDERR)
                .windows(diagnostic.len())
                .any(|window| window == diagnostic)
        );
    }

    for code in [
        StatusErrorCode::Malformed,
        StatusErrorCode::StaleGeneration,
        StatusErrorCode::Replay,
        StatusErrorCode::Unavailable,
    ] {
        let mut fixture = Fixture::new(&[b"status\n"]);
        fixture.queue_control(STATUS, &status_error(1, code));
        assert_eq!(
            run_v2(&mut fixture, "system/wyrmsh", &[]),
            Err(ShellError::InspectionProtocol)
        );
        assert!(
            fixture
                .output(STDERR)
                .windows(b"unavailable: status\n".len())
                .any(|window| window == b"unavailable: status\n")
        );
    }
}

#[test]
fn control_backpressure_timeout_peer_loss_and_unexpected_handles_are_bounded() {
    let mut retried = Fixture::new(&[b"tasks\nexit\n"]);
    retried.control_send_would_block.push_back(SHELL_JOBS);
    assert_eq!(run_v2(&mut retried, "system/wyrmsh", &[]), Ok(()));
    assert_eq!(
        retried
            .control_requests
            .iter()
            .filter(|(channel, _)| *channel == SHELL_JOBS)
            .count(),
        1
    );
    assert!(
        retried
            .output(STDOUT)
            .windows(b"tasks: empty\n".len())
            .any(|window| window == b"tasks: empty\n")
    );

    let mut timeout = Fixture::new(&[b"status\n"]);
    timeout.scripted_controls = true;
    timeout.timeout_control = Some(STATUS);
    assert_eq!(
        run_v2(&mut timeout, "system/wyrmsh", &[]),
        Err(ShellError::InspectionTimeout)
    );
    assert_eq!(timeout.control_requests.len(), 1);
    assert!(
        timeout
            .output(STDERR)
            .windows(b"unavailable: status\n".len())
            .any(|window| window == b"unavailable: status\n")
    );
    assert!(
        timeout
            .waited_deadlines
            .contains(&DwDeadline(timeout.now + 1_000_000_000))
    );

    let mut lost = Fixture::new(&[b"services\n"]);
    lost.scripted_controls = true;
    lost.control_loss_on_transaction_wait = Some(1);
    assert_eq!(
        run_v2(&mut lost, "system/wyrmsh", &[]),
        Err(ShellError::RequiredEndpointLost(EndpointRole::Registry))
    );

    let mut handled = Fixture::new(&[b"tasks\n"]);
    handled.queue_control_with_handle(SHELL_JOBS, &jobs_reply(1, &[]), DwHandle(700));
    assert_eq!(
        run_v2(&mut handled, "system/wyrmsh", &[]),
        Err(ShellError::InspectionProtocol)
    );
    assert!(handled.closed.contains(&DwHandle(700)));
}

#[test]
fn each_target_control_peer_loss_is_generation_fatal_while_awaiting_its_reply() {
    for (input, index, role) in [
        (b"services\n".as_slice(), 1, EndpointRole::Registry),
        (b"tasks\n".as_slice(), 2, EndpointRole::ShellJobs),
        (b"status\n".as_slice(), 0, EndpointRole::ConsoleStatus),
    ] {
        let mut fixture = Fixture::new(&[input]);
        fixture.scripted_controls = true;
        fixture.control_loss_on_transaction_wait = Some(index);
        assert_eq!(
            run_v2(&mut fixture, "system/wyrmsh", &[]),
            Err(ShellError::RequiredEndpointLost(role))
        );
    }
}

#[test]
fn wrong_registry_correlation_and_malformed_job_lists_are_fatal() {
    let mut registry = Fixture::new(&[b"services\n"]);
    registry.queue_control(REGISTRY, &registry_reply(3, 0, 1, 0, &[]));
    assert_eq!(
        run_v2(&mut registry, "system/wyrmsh", &[]),
        Err(ShellError::InspectionProtocol)
    );

    let mut zero = jobs_reply(1, &[4]);
    zero[56..64].fill(0);
    let mut job = Fixture::new(&[b"tasks\n"]);
    job.queue_control(SHELL_JOBS, &zero);
    assert_eq!(
        run_v2(&mut job, "system/wyrmsh", &[]),
        Err(ShellError::InspectionProtocol)
    );

    let mut short = jobs_reply(1, &[4]);
    short.pop();
    let mut job = Fixture::new(&[b"tasks\n"]);
    job.queue_control(SHELL_JOBS, &short);
    assert_eq!(
        run_v2(&mut job, "system/wyrmsh", &[]),
        Err(ShellError::InspectionProtocol)
    );
}

#[test]
fn mixed_inspections_advance_only_their_independent_transaction_namespaces() {
    let mut fixture = Fixture::new(&[b"services\ntasks\nstatus\nservices\ntasks\nstatus\nexit\n"]);
    fixture.queue_control(REGISTRY, &registry_reply(2, 0, 1, 0, &[]));
    fixture.queue_control(SHELL_JOBS, &jobs_reply(1, &[]));
    fixture.queue_control(STATUS, &status_reply(1, status_snapshot()));
    fixture.queue_control(REGISTRY, &registry_reply(3, 0, 1, 0, &[]));
    fixture.queue_control(SHELL_JOBS, &jobs_reply(2, &[]));
    fixture.queue_control(STATUS, &status_reply(2, status_snapshot()));
    assert_eq!(run_v2(&mut fixture, "system/wyrmsh", &[]), Ok(()));

    let transactions: Vec<u64> = fixture
        .control_requests
        .iter()
        .map(|(channel, bytes)| {
            if *channel == REGISTRY {
                parse_registry_message(bytes, 0)
                    .unwrap()
                    .header
                    .transaction_id
            } else if *channel == SHELL_JOBS {
                parse_launch_message(bytes, 0)
                    .unwrap()
                    .reservation
                    .transaction_id
            } else {
                let wyrmroot_console_proto::Message::Query(header) =
                    wyrmroot_console_proto::decode(bytes, 0).unwrap()
                else {
                    panic!("status query")
                };
                header.transaction_id
            }
        })
        .collect();
    assert_eq!(transactions, [2, 1, 1, 3, 2, 2]);

    let mut exit = Fixture::new(&[b"exit\n"]);
    assert_eq!(run_v2(&mut exit, "system/wyrmsh", &[]), Ok(()));
    assert!(exit.control_requests.is_empty());
}

#[test]
fn every_inspection_timeout_uses_one_committed_request_and_the_same_absolute_deadline() {
    for (channel, command, diagnostic) in [
        (
            REGISTRY,
            b"services\n".as_slice(),
            b"unavailable: services\n".as_slice(),
        ),
        (
            SHELL_JOBS,
            b"tasks\n".as_slice(),
            b"unavailable: tasks\n".as_slice(),
        ),
        (
            STATUS,
            b"status\n".as_slice(),
            b"unavailable: status\n".as_slice(),
        ),
    ] {
        let mut fixture = Fixture::new(&[command]);
        fixture.scripted_controls = true;
        fixture.timeout_control = Some(channel);
        assert_eq!(
            run_v2(&mut fixture, "system/wyrmsh", &[]),
            Err(ShellError::InspectionTimeout)
        );
        assert_eq!(fixture.control_requests.len(), 1);
        assert!(
            fixture
                .output(STDERR)
                .windows(diagnostic.len())
                .any(|window| window == diagnostic)
        );
        assert_eq!(
            fixture.waited_deadlines,
            [DwDeadline(fixture.now + 1_000_000_000)]
        );
    }
}

#[test]
fn exact_infinite_sentinel_is_never_used_as_a_control_deadline() {
    let mut fixture = Fixture::new(&[b"tasks\nexit\n"]);
    fixture.now = u64::MAX - 1_000_000_000;
    assert_eq!(
        run_v2(&mut fixture, "system/wyrmsh", &[]),
        Err(ShellError::InspectionProtocol)
    );
    assert!(fixture.control_requests.is_empty());
}

#[test]
fn later_registry_page_ready_at_the_absolute_deadline_is_rejected() {
    let mut fixture = Fixture::new(&[b"services\nexit\n"]);
    let version = ProtocolVersion { major: 1, minor: 0 };
    fixture.queue_control(
        REGISTRY,
        &registry_reply(
            2,
            0,
            2,
            3,
            &[
                service(b"alpha", 1, 1, &[version]),
                service(b"beta", 2, 2, &[version]),
            ],
        ),
    );
    fixture.queue_control(
        REGISTRY,
        &registry_reply(2, 1, 2, 3, &[service(b"gamma", 3, 3, &[version])]),
    );
    fixture.clock_values = VecDeque::from([
        5_000_000_000,
        5_000_000_000,
        5_000_000_000,
        5_000_000_000,
        6_000_000_000,
    ]);
    assert_eq!(
        run_v2(&mut fixture, "system/wyrmsh", &[]),
        Err(ShellError::InspectionTimeout)
    );
    assert!(
        !fixture
            .output(STDOUT)
            .windows(b"service name=".len())
            .any(|window| window == b"service name=")
    );
    assert_eq!(fixture.control_requests.len(), 1);
    assert!(fixture.clock_values.is_empty());
    assert_eq!(fixture.control_incoming.len(), 1);
}

#[test]
fn send_retry_writable_at_the_absolute_deadline_is_rejected_without_commit() {
    let mut fixture = Fixture::new(&[b"tasks\nexit\n"]);
    fixture.control_send_would_block.push_back(SHELL_JOBS);
    fixture.clock_values = VecDeque::from([5_000_000_000, 5_000_000_000, 6_000_000_000]);
    assert_eq!(
        run_v2(&mut fixture, "system/wyrmsh", &[]),
        Err(ShellError::InspectionTimeout)
    );
    assert!(fixture.control_requests.is_empty());
    assert!(fixture.control_send_would_block.is_empty());
    assert!(fixture.clock_values.is_empty());
}

#[test]
fn response_validation_must_complete_before_the_absolute_deadline() {
    let version = ProtocolVersion { major: 1, minor: 0 };
    let registry = registry_reply(2, 0, 1, 1, &[service(b"alpha", 1, 1, &[version])]);
    let cases = [
        (
            REGISTRY,
            b"services\n".as_slice(),
            registry,
            b"unavailable: services\n".as_slice(),
        ),
        (
            SHELL_JOBS,
            b"tasks\n".as_slice(),
            jobs_reply(1, &[4]),
            b"unavailable: tasks\n".as_slice(),
        ),
        (
            STATUS,
            b"status\n".as_slice(),
            status_reply(1, status_snapshot()),
            b"unavailable: status\n".as_slice(),
        ),
    ];
    for (channel, command, response, diagnostic) in cases {
        let mut fixture = Fixture::new(&[command]);
        fixture.queue_control(channel, &response);
        fixture.clock_values =
            VecDeque::from([5_000_000_000, 5_000_000_000, 5_000_000_000, 6_000_000_000]);
        assert_eq!(
            run_v2(&mut fixture, "system/wyrmsh", &[]),
            Err(ShellError::InspectionTimeout)
        );
        assert!(
            fixture
                .output(STDERR)
                .windows(diagnostic.len())
                .any(|window| window == diagnostic)
        );
        assert!(fixture.clock_values.is_empty());
        assert!(fixture.control_incoming.is_empty());
    }
}
