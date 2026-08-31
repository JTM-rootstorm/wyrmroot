//! Executable WYR1-D0 contract model.
//!
//! This is intentionally test-only. D1 owns the production WRST codec and
//! runtime wrappers; D2 owns the production UART core.

use std::collections::VecDeque;
use wyrmroot_device_proto as _;

const WRST_HEADER_BYTES: usize = 24;
const WRST_MAX_PAYLOAD: usize = 1024;
const UART_RING_BYTES: usize = 4096;
const CONSOLE_INPUT_STAGE_BYTES: usize = 4096;
const CONSOLE_STDOUT_STAGE_BYTES: usize = 4096;
const CONSOLE_STDERR_STAGE_BYTES: usize = 4096;
const MAX_ACTIVE_STREAMS: usize = 1;
const MAX_PENDING_ATTACHES: usize = 1;
const MAX_CHILD_FAILURES: usize = 4;
const MAX_RECONNECT_FAILURES: usize = 4;
const RESTART_WINDOW_SECONDS: u64 = 60;
const IIR_DRAIN_LIMIT: usize = 256;
const STALE_INIT_DRAIN_LIMIT: usize = 256;

#[derive(Debug, Eq, PartialEq)]
enum WrstError {
    WrongSize,
    WrongMagic,
    WrongVersion,
    WrongHeaderSize,
    UnknownType,
    NonzeroFlags,
    OversizedPayload,
    NonzeroReserved,
    UnexpectedHandles,
}

fn wrst_data(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= WRST_MAX_PAYLOAD);
    let mut bytes = vec![0; WRST_HEADER_BYTES + payload.len()];
    bytes[..4].copy_from_slice(b"WRST");
    bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&0u16.to_le_bytes());
    bytes[8..10].copy_from_slice(&(WRST_HEADER_BYTES as u16).to_le_bytes());
    bytes[10..12].copy_from_slice(&1u16.to_le_bytes());
    bytes[16..20].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes[WRST_HEADER_BYTES..].copy_from_slice(payload);
    bytes
}

fn parse_wrst(bytes: &[u8], handles: usize) -> Result<&[u8], WrstError> {
    if handles != 0 {
        return Err(WrstError::UnexpectedHandles);
    }
    if bytes.len() < WRST_HEADER_BYTES {
        return Err(WrstError::WrongSize);
    }
    if &bytes[..4] != b"WRST" {
        return Err(WrstError::WrongMagic);
    }
    if u16::from_le_bytes(bytes[4..6].try_into().unwrap()) != 1
        || u16::from_le_bytes(bytes[6..8].try_into().unwrap()) != 0
    {
        return Err(WrstError::WrongVersion);
    }
    if usize::from(u16::from_le_bytes(bytes[8..10].try_into().unwrap())) != WRST_HEADER_BYTES {
        return Err(WrstError::WrongHeaderSize);
    }
    if u16::from_le_bytes(bytes[10..12].try_into().unwrap()) != 1 {
        return Err(WrstError::UnknownType);
    }
    if u32::from_le_bytes(bytes[12..16].try_into().unwrap()) != 0 {
        return Err(WrstError::NonzeroFlags);
    }
    let payload = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
    if payload > WRST_MAX_PAYLOAD {
        return Err(WrstError::OversizedPayload);
    }
    if u32::from_le_bytes(bytes[20..24].try_into().unwrap()) != 0 {
        return Err(WrstError::NonzeroReserved);
    }
    if WRST_HEADER_BYTES.checked_add(payload) != Some(bytes.len()) {
        return Err(WrstError::WrongSize);
    }
    Ok(&bytes[WRST_HEADER_BYTES..])
}

#[derive(Default)]
struct PartialInput {
    queued: VecDeque<Vec<u8>>,
    retained: Option<(Vec<u8>, usize)>,
    peer_closed: bool,
}

#[derive(Debug, Eq, PartialEq)]
enum ReadResult {
    Count(usize),
    WouldBlock,
    Eof,
}

impl PartialInput {
    fn push_record(&mut self, payload: &[u8]) {
        self.queued.push_back(wrst_data(payload));
    }

    fn read(&mut self, output: &mut [u8]) -> ReadResult {
        if output.is_empty() {
            return ReadResult::Count(0);
        }
        let mut written = 0;
        while written < output.len() {
            if self.retained.is_none() {
                let Some(record) = self.queued.pop_front() else {
                    break;
                };
                let payload = parse_wrst(&record, 0).unwrap().to_vec();
                self.retained = Some((payload, 0));
            }
            let (payload, cursor) = self.retained.as_mut().unwrap();
            let count = (output.len() - written).min(payload.len() - *cursor);
            output[written..written + count].copy_from_slice(&payload[*cursor..*cursor + count]);
            written += count;
            *cursor += count;
            if *cursor == payload.len() {
                self.retained = None;
            }
        }
        if written != 0 {
            ReadResult::Count(written)
        } else if self.peer_closed && self.queued.is_empty() && self.retained.is_none() {
            ReadResult::Eof
        } else {
            ReadResult::WouldBlock
        }
    }
}

#[derive(Default)]
struct PartialOutput {
    datagram_capacity: usize,
    queued: Vec<Vec<u8>>,
    writable_hint: bool,
    force_racing_would_block: bool,
}

#[derive(Debug, Eq, PartialEq)]
enum WriteResult {
    Count(usize),
    WouldBlock,
}

impl PartialOutput {
    fn write(&mut self, input: &[u8]) -> WriteResult {
        if input.is_empty() {
            return WriteResult::Count(0);
        }
        let mut committed = 0;
        while committed < input.len() {
            if self.force_racing_would_block || self.queued.len() == self.datagram_capacity {
                break;
            }
            let count = WRST_MAX_PAYLOAD.min(input.len() - committed);
            self.queued
                .push(wrst_data(&input[committed..committed + count]));
            committed += count;
        }
        if committed == 0 {
            WriteResult::WouldBlock
        } else {
            WriteResult::Count(committed)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DriverIdentity {
    publication: u64,
    role: u64,
    bundle: u64,
    attempt: u64,
    endpoint_id: u64,
    endpoint_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConnectRequest {
    publication: u64,
    transaction: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Attach {
    driver: DriverIdentity,
    client_transaction: u64,
    attach_transaction: u64,
    stream_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectError {
    Busy,
    NotReady,
    Stale,
    InternalFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EndpointOwner {
    Devmgr,
    Driver,
    Client,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EndpointPair {
    client: EndpointOwner,
    driver: EndpointOwner,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Slot {
    Empty,
    Pending { attach: Attach, pair: EndpointPair },
    ReadyToConnect { attach: Attach, pair: EndpointPair },
    Active { attach: Attach, pair: EndpointPair },
}

struct Connector {
    current: Option<DriverIdentity>,
    next_attach_transaction: u64,
    next_stream_generation: u64,
    slot: Slot,
    closed_endpoints: usize,
}

impl Connector {
    fn new(current: Option<DriverIdentity>) -> Self {
        Self {
            current,
            next_attach_transaction: 1,
            next_stream_generation: 1,
            slot: Slot::Empty,
            closed_endpoints: 0,
        }
    }

    fn connect(&mut self, request: ConnectRequest) -> Result<Attach, ConnectError> {
        let Some(current) = self.current else {
            return Err(ConnectError::NotReady);
        };
        if request.publication != current.publication {
            return Err(ConnectError::Stale);
        }
        if !matches!(self.slot, Slot::Empty) {
            return Err(ConnectError::Busy);
        }
        let Some(next_attach_transaction) = self.next_attach_transaction.checked_add(1) else {
            return Err(ConnectError::InternalFailure);
        };
        let Some(next_stream_generation) = self.next_stream_generation.checked_add(1) else {
            return Err(ConnectError::InternalFailure);
        };
        let attach = Attach {
            driver: current,
            client_transaction: request.transaction,
            attach_transaction: self.next_attach_transaction,
            stream_generation: self.next_stream_generation,
        };
        self.next_attach_transaction = next_attach_transaction;
        self.next_stream_generation = next_stream_generation;
        self.slot = Slot::Pending {
            attach,
            pair: EndpointPair {
                client: EndpointOwner::Devmgr,
                driver: EndpointOwner::Driver,
            },
        };
        Ok(attach)
    }

    fn ready(&mut self, observed: Attach) -> Result<(), ConnectError> {
        let Slot::Pending { attach, pair } = self.slot else {
            return Err(ConnectError::Stale);
        };
        if attach != observed {
            self.cleanup_uncommitted();
            return Err(ConnectError::Stale);
        }
        self.slot = Slot::ReadyToConnect { attach, pair };
        Ok(())
    }

    fn connected(&mut self) -> Result<(), ConnectError> {
        let Slot::ReadyToConnect { attach, mut pair } = self.slot else {
            return Err(ConnectError::Stale);
        };
        pair.client = EndpointOwner::Client;
        self.slot = Slot::Active { attach, pair };
        Ok(())
    }

    fn connected_send_failed(&mut self) -> ConnectError {
        self.cleanup_uncommitted();
        ConnectError::InternalFailure
    }

    fn cleanup_uncommitted(&mut self) {
        if let Slot::Pending { pair, .. } | Slot::ReadyToConnect { pair, .. } = self.slot {
            // The driver owns the moved endpoint. Closing the retained peer
            // makes PEER_CLOSED observable; driver cleanup then closes it.
            self.closed_endpoints = self.closed_endpoints.saturating_add(
                usize::from(pair.client != EndpointOwner::Closed)
                    + usize::from(pair.driver != EndpointOwner::Closed),
            );
            self.slot = Slot::Empty;
        }
    }

    fn peer_closed(&mut self) {
        if let Slot::Active { pair, .. } = self.slot {
            self.closed_endpoints = self.closed_endpoints.saturating_add(
                usize::from(pair.client != EndpointOwner::Closed)
                    + usize::from(pair.driver != EndpointOwner::Closed),
            );
            self.slot = Slot::Empty;
        }
    }

    fn retire_generation(&mut self) {
        match self.slot {
            Slot::Pending { .. } | Slot::ReadyToConnect { .. } => self.cleanup_uncommitted(),
            Slot::Active { .. } => self.peer_closed(),
            Slot::Empty => {}
        }
        self.current = None;
    }

    fn live_handles(&self) -> usize {
        let pair = match self.slot {
            Slot::Pending { pair, .. }
            | Slot::ReadyToConnect { pair, .. }
            | Slot::Active { pair, .. } => pair,
            Slot::Empty => return 0,
        };
        usize::from(pair.client != EndpointOwner::Closed)
            + usize::from(pair.driver != EndpointOwner::Closed)
    }
}

struct FixedRing<const N: usize> {
    bytes: [u8; N],
    head: usize,
    len: usize,
}

impl<const N: usize> FixedRing<N> {
    fn new() -> Self {
        Self {
            bytes: [0; N],
            head: 0,
            len: 0,
        }
    }

    fn push(&mut self, byte: u8) -> bool {
        if self.len == N {
            return false;
        }
        self.bytes[(self.head + self.len) % N] = byte;
        self.len += 1;
        true
    }

    fn pop(&mut self) -> Option<u8> {
        if self.len == 0 {
            return None;
        }
        let byte = self.bytes[self.head];
        self.head = (self.head + 1) % N;
        self.len -= 1;
        Some(byte)
    }
}

struct RxModel {
    ring: FixedRing<UART_RING_BYTES>,
    software_overrun_bytes: u64,
}

impl RxModel {
    fn receive_hardware(&mut self, byte: u8) {
        if !self.ring.push(byte) {
            self.software_overrun_bytes = self.software_overrun_bytes.saturating_add(1);
        }
    }
}

#[derive(Default)]
struct InputNewlines {
    suppress_lf: bool,
}

impl InputNewlines {
    fn transform(&mut self, input: &[u8], output: &mut Vec<u8>) {
        for byte in input.iter().copied() {
            if self.suppress_lf {
                self.suppress_lf = false;
                if byte == b'\n' {
                    continue;
                }
            }
            if byte == b'\r' {
                output.push(b'\n');
                self.suppress_lf = true;
            } else {
                output.push(byte);
            }
        }
    }
}

#[derive(Default)]
struct OutputNewlines {
    previous_was_cr: bool,
}

impl OutputNewlines {
    fn transform(&mut self, input: &[u8], output: &mut Vec<u8>) {
        for byte in input.iter().copied() {
            if byte == b'\n' && !self.previous_was_cr {
                output.extend_from_slice(b"\r\n");
            } else {
                output.push(byte);
            }
            self.previous_was_cr = byte == b'\r';
        }
    }
}

#[test]
fn wrst_v1_accepts_only_exact_data_grammar() {
    for payload in [
        &b""[..],
        &b"abc\0\r\n\x7f"[..],
        &vec![0x5a; WRST_MAX_PAYLOAD][..],
    ] {
        let bytes = wrst_data(payload);
        assert_eq!(parse_wrst(&bytes, 0), Ok(payload));
    }

    let canonical = wrst_data(b"x");
    let mut cases = Vec::new();
    for (index, value, error) in [
        (0, b'X', WrstError::WrongMagic),
        (4, 2, WrstError::WrongVersion),
        (6, 1, WrstError::WrongVersion),
        (8, 23, WrstError::WrongHeaderSize),
        (10, 2, WrstError::UnknownType),
        (12, 1, WrstError::NonzeroFlags),
        (20, 1, WrstError::NonzeroReserved),
    ] {
        let mut bytes = canonical.clone();
        bytes[index] = value;
        cases.push((bytes, error));
    }
    for (bytes, error) in cases {
        assert_eq!(parse_wrst(&bytes, 0), Err(error));
    }

    let mut oversized = wrst_data(b"");
    oversized[16..20].copy_from_slice(&1025u32.to_le_bytes());
    assert_eq!(parse_wrst(&oversized, 0), Err(WrstError::OversizedPayload));
    let mut short = canonical.clone();
    short.pop();
    assert_eq!(parse_wrst(&short, 0), Err(WrstError::WrongSize));
    let mut trailing = canonical.clone();
    trailing.push(0);
    assert_eq!(parse_wrst(&trailing, 0), Err(WrstError::WrongSize));
    assert_eq!(parse_wrst(&canonical, 1), Err(WrstError::UnexpectedHandles));
}

#[test]
fn partial_io_retains_one_record_and_rechecks_racing_would_block() {
    let mut input = PartialInput::default();
    input.push_record(b"abc");
    input.push_record(b"def");
    let mut two = [0; 2];
    assert_eq!(input.read(&mut two), ReadResult::Count(2));
    assert_eq!(&two, b"ab");
    assert!(input.retained.is_some());
    let mut four = [0; 4];
    assert_eq!(input.read(&mut four), ReadResult::Count(4));
    assert_eq!(&four, b"cdef");
    assert!(input.retained.is_none());
    input.peer_closed = true;
    assert_eq!(input.read(&mut [0; 1]), ReadResult::Eof);

    let mut output = PartialOutput {
        datagram_capacity: 1,
        writable_hint: true,
        force_racing_would_block: true,
        ..Default::default()
    };
    assert_eq!(output.write(b"x"), WriteResult::WouldBlock);
    assert!(output.writable_hint, "WRITABLE is only a wake hint");
    output.force_racing_would_block = false;
    assert_eq!(
        output.write(&vec![0x5a; WRST_MAX_PAYLOAD + 1]),
        WriteResult::Count(WRST_MAX_PAYLOAD)
    );
    assert_eq!(output.queued.len(), 1);
}

#[test]
fn connector_correlates_ready_busy_stale_and_cleanup_without_handle_leaks() {
    let driver = DriverIdentity {
        publication: 11,
        role: 1,
        bundle: 21,
        attempt: 31,
        endpoint_id: 41,
        endpoint_generation: 51,
    };
    let mut connector = Connector::new(Some(driver));
    assert_eq!(
        connector.connect(ConnectRequest {
            publication: 10,
            transaction: 1,
        }),
        Err(ConnectError::Stale)
    );
    assert_eq!(connector.live_handles(), 0);

    let attach = connector
        .connect(ConnectRequest {
            publication: 11,
            transaction: 2,
        })
        .unwrap();
    assert_eq!(connector.live_handles(), 2);
    assert_eq!(
        connector.connect(ConnectRequest {
            publication: 11,
            transaction: 3,
        }),
        Err(ConnectError::Busy)
    );
    let mut stale = attach;
    stale.stream_generation += 1;
    assert_eq!(connector.ready(stale), Err(ConnectError::Stale));
    assert_eq!(connector.live_handles(), 0);
    assert_eq!(connector.closed_endpoints, 2);

    let attach = connector
        .connect(ConnectRequest {
            publication: 11,
            transaction: 4,
        })
        .unwrap();
    assert_eq!(connector.ready(attach), Ok(()));
    assert_eq!(connector.live_handles(), 2);
    assert_eq!(
        connector.connected_send_failed(),
        ConnectError::InternalFailure
    );
    assert_eq!(connector.live_handles(), 0);
    assert_eq!(connector.closed_endpoints, 4);

    let attach = connector
        .connect(ConnectRequest {
            publication: 11,
            transaction: 5,
        })
        .unwrap();
    assert_eq!(connector.ready(attach), Ok(()));
    assert_eq!(connector.connected(), Ok(()));
    assert_eq!(connector.live_handles(), 2);
    connector.peer_closed();
    assert_eq!(connector.live_handles(), 0);
    assert_eq!(connector.closed_endpoints, 6);

    let attach = connector
        .connect(ConnectRequest {
            publication: 11,
            transaction: 6,
        })
        .unwrap();
    assert_eq!(attach.stream_generation, 4);
    assert_eq!(connector.ready(attach), Ok(()));
    assert_eq!(connector.connected(), Ok(()));
    connector.retire_generation();
    assert_eq!(connector.live_handles(), 0);
    assert_eq!(connector.closed_endpoints, 8);
    assert_eq!(
        connector.connect(ConnectRequest {
            publication: 11,
            transaction: 7,
        }),
        Err(ConnectError::NotReady)
    );
}

#[test]
fn fixed_bounds_drop_only_rx_overflow_and_backpressure_tx() {
    assert_eq!(WRST_MAX_PAYLOAD, 1024);
    assert_eq!(UART_RING_BYTES, 4096);
    assert_eq!(CONSOLE_INPUT_STAGE_BYTES, 4096);
    assert_eq!(CONSOLE_STDOUT_STAGE_BYTES, 4096);
    assert_eq!(CONSOLE_STDERR_STAGE_BYTES, 4096);
    assert_eq!(MAX_ACTIVE_STREAMS, 1);
    assert_eq!(MAX_PENDING_ATTACHES, 1);
    assert_eq!(MAX_CHILD_FAILURES, 4);
    assert_eq!(MAX_RECONNECT_FAILURES, 4);
    assert_eq!(RESTART_WINDOW_SECONDS, 60);
    assert_eq!(IIR_DRAIN_LIMIT, 256);
    assert_eq!(STALE_INIT_DRAIN_LIMIT, 256);

    let mut rx = RxModel {
        ring: FixedRing::new(),
        software_overrun_bytes: u64::MAX - 1,
    };
    for byte in 0..UART_RING_BYTES {
        rx.receive_hardware(byte as u8);
    }
    rx.receive_hardware(0xaa);
    rx.receive_hardware(0xbb);
    assert_eq!(rx.ring.len, UART_RING_BYTES);
    assert_eq!(rx.software_overrun_bytes, u64::MAX);

    let mut tx = FixedRing::<UART_RING_BYTES>::new();
    for byte in 0..UART_RING_BYTES {
        assert!(tx.push(byte as u8));
    }
    assert!(!tx.push(0xcc), "TX must backpressure instead of dropping");
    assert_eq!(tx.len, UART_RING_BYTES);
    for byte in 0..UART_RING_BYTES {
        assert_eq!(tx.pop(), Some(byte as u8));
    }
}

#[test]
fn connector_generation_exhaustion_fails_closed_before_creating_handles() {
    let driver = DriverIdentity {
        publication: 1,
        role: 1,
        bundle: 1,
        attempt: 1,
        endpoint_id: 1,
        endpoint_generation: 1,
    };
    let request = ConnectRequest {
        publication: 1,
        transaction: 1,
    };
    let mut exhausted_attach = Connector::new(Some(driver));
    exhausted_attach.next_attach_transaction = u64::MAX;
    assert_eq!(
        exhausted_attach.connect(request),
        Err(ConnectError::InternalFailure)
    );
    assert_eq!(exhausted_attach.live_handles(), 0);

    let mut exhausted_stream = Connector::new(Some(driver));
    exhausted_stream.next_stream_generation = u64::MAX;
    assert_eq!(
        exhausted_stream.connect(request),
        Err(ConnectError::InternalFailure)
    );
    assert_eq!(exhausted_stream.live_handles(), 0);
}

#[test]
fn newline_transforms_preserve_cross_record_state() {
    let mut input = InputNewlines::default();
    let mut normalized = Vec::new();
    input.transform(b"a\r", &mut normalized);
    input.transform(b"\nb\n\rc", &mut normalized);
    assert_eq!(normalized, b"a\nb\n\nc");

    let mut output = OutputNewlines::default();
    let mut normalized = Vec::new();
    output.transform(b"a\r", &mut normalized);
    output.transform(b"\nb\nc", &mut normalized);
    assert_eq!(normalized, b"a\r\nb\r\nc");
}
