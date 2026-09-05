//! Byte-defined, allocation-free WRCN console status protocol and relationship model.
//!
//! The crate has no syscall dependency. Callers provide complete Channel datagrams,
//! account for handles, and close a relationship after an uncorrelatable message.

#![no_std]
#![forbid(unsafe_code)]

pub const HEADER_BYTES: usize = 48;
pub const ERROR_BYTES: usize = 56;
pub const SNAPSHOT_BYTES: usize = 160;
pub const MAX_MESSAGE_BYTES: usize = SNAPSHOT_BYTES;
pub const MAX_QUEUE_BYTES: u32 = 4096;
pub const MAX_FAILURES: u32 = 4;
pub const SHELL_PATH: &str = "system/wyrmsh";
pub const LIVE_PEER_MASK: u32 = 0b111;
pub const FLAG_SERIAL_PRESENT: u32 = 1 << 0;
pub const FLAG_CHILD_PRESENT: u32 = 1 << 1;
pub const FLAG_SERIAL_INVALIDATED: u32 = 1 << 2;
pub const FLAG_PENDING_LAUNCH: u32 = 1 << 3;
pub const FLAG_PENDING_LAUNCH_CLEANUP: u32 = 1 << 4;
pub const FLAG_CHILD_RESTART_EXHAUSTED: u32 = 1 << 5;
pub const FLAG_SERIAL_RESTART_EXHAUSTED: u32 = 1 << 6;
pub const FLAGS_MASK: u32 = (1 << 7) - 1;

const MAGIC: [u8; 4] = *b"WRCN";
const MAJOR: u16 = 1;
const MINOR: u16 = 0;
const QUERY_STATUS: u32 = 1;
const STATUS_SNAPSHOT: u32 = 2;
const ERROR: u32 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub transaction_id: u64,
    pub console_generation: u64,
    pub status_generation: u64,
}

impl Header {
    pub const fn valid(self) -> bool {
        self.transaction_id != 0 && self.console_generation != 0 && self.status_generation != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum State {
    Active = 1,
    RetiringChild = 2,
    AwaitingReap = 3,
    Reconnecting = 4,
    Exhausted = 5,
    FailClosed = 6,
}

impl State {
    fn parse(value: u32) -> Result<Self, DecodeError> {
        match value {
            1 => Ok(Self::Active),
            2 => Ok(Self::RetiringChild),
            3 => Ok(Self::AwaitingReap),
            4 => Ok(Self::Reconnecting),
            5 => Ok(Self::Exhausted),
            6 => Ok(Self::FailClosed),
            _ => Err(DecodeError::State),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum LastFailure {
    None = 0,
    ZeroCorrelation = 1,
    StaleCorrelation = 2,
    WrongConnectionState = 3,
    NoChild = 4,
    IncompleteCleanup = 5,
    AlreadyReserved = 6,
    UnknownReservation = 7,
    Backpressure = 8,
    TooLarge = 9,
    MonotonicRegression = 10,
    ArithmeticOverflow = 11,
    RestartExhausted = 12,
    SerialDisconnected = 13,
    ChildDisconnected = 14,
    WrongDirection = 15,
}

impl LastFailure {
    fn parse(value: u32) -> Result<Self, DecodeError> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::ZeroCorrelation),
            2 => Ok(Self::StaleCorrelation),
            3 => Ok(Self::WrongConnectionState),
            4 => Ok(Self::NoChild),
            5 => Ok(Self::IncompleteCleanup),
            6 => Ok(Self::AlreadyReserved),
            7 => Ok(Self::UnknownReservation),
            8 => Ok(Self::Backpressure),
            9 => Ok(Self::TooLarge),
            10 => Ok(Self::MonotonicRegression),
            11 => Ok(Self::ArithmeticOverflow),
            12 => Ok(Self::RestartExhausted),
            13 => Ok(Self::SerialDisconnected),
            14 => Ok(Self::ChildDisconnected),
            15 => Ok(Self::WrongDirection),
            _ => Err(DecodeError::LastFailure),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub state: State,
    pub flags: u32,
    pub serial_registry_generation: u64,
    pub publication_generation: u64,
    pub device_bundle: u64,
    pub driver_attempt: u64,
    pub raw_stream_generation: u64,
    pub child_generation: u64,
    pub outer_job: u64,
    pub outer_launch_transaction: u64,
    pub live_peer_mask: u32,
    pub input_queue_bytes: u32,
    pub stdout_queue_bytes: u32,
    pub stderr_queue_bytes: u32,
    pub child_failures: u32,
    pub serial_failures: u32,
    pub last_failure: LastFailure,
}

impl Snapshot {
    pub fn validate(self) -> Result<(), EncodeError> {
        if self.flags & !FLAGS_MASK != 0
            || self.live_peer_mask & !LIVE_PEER_MASK != 0
            || self.input_queue_bytes > MAX_QUEUE_BYTES
            || self.stdout_queue_bytes > MAX_QUEUE_BYTES
            || self.stderr_queue_bytes > MAX_QUEUE_BYTES
            || self.child_failures > MAX_FAILURES
            || self.serial_failures > MAX_FAILURES
        {
            return Err(EncodeError::Bounds);
        }
        let serial = [
            self.serial_registry_generation,
            self.publication_generation,
            self.device_bundle,
            self.driver_attempt,
            self.raw_stream_generation,
        ];
        if (self.flags & FLAG_SERIAL_PRESENT != 0) != serial.iter().all(|value| *value != 0)
            || (self.flags & FLAG_SERIAL_PRESENT == 0) && serial.iter().any(|value| *value != 0)
        {
            return Err(EncodeError::Invariant);
        }
        let child = [
            self.child_generation,
            self.outer_job,
            self.outer_launch_transaction,
        ];
        if (self.flags & FLAG_CHILD_PRESENT != 0) != child.iter().all(|value| *value != 0)
            || (self.flags & FLAG_CHILD_PRESENT == 0)
                && (child.iter().any(|value| *value != 0) || self.live_peer_mask != 0)
        {
            return Err(EncodeError::Invariant);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ErrorCode {
    Malformed = 1,
    StaleGeneration = 2,
    Replay = 3,
    Unavailable = 4,
}

impl ErrorCode {
    fn parse(value: u32) -> Result<Self, DecodeError> {
        match value {
            1 => Ok(Self::Malformed),
            2 => Ok(Self::StaleGeneration),
            3 => Ok(Self::Replay),
            4 => Ok(Self::Unavailable),
            _ => Err(DecodeError::ErrorCode),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Message {
    Query(Header),
    Snapshot(Header, Snapshot),
    Error(Header, ErrorCode),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    Buffer,
    Identity,
    Bounds,
    Invariant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    Size,
    Handles,
    Magic,
    Version,
    Flags,
    Identity,
    MessageType,
    State,
    LastFailure,
    ErrorCode,
    Bounds,
    Invariant,
    Reserved,
}

pub fn encode_query(header: Header, output: &mut [u8]) -> Result<usize, EncodeError> {
    encode_header(header, QUERY_STATUS, HEADER_BYTES, output)?;
    Ok(HEADER_BYTES)
}

pub fn encode_snapshot(
    header: Header,
    snapshot: Snapshot,
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    snapshot.validate()?;
    encode_header(header, STATUS_SNAPSHOT, SNAPSHOT_BYTES, output)?;
    put_u32(output, 48, snapshot.state as u32);
    put_u32(output, 52, snapshot.flags);
    for (index, value) in [
        snapshot.serial_registry_generation,
        snapshot.publication_generation,
        snapshot.device_bundle,
        snapshot.driver_attempt,
        snapshot.raw_stream_generation,
        snapshot.child_generation,
        snapshot.outer_job,
        snapshot.outer_launch_transaction,
    ]
    .into_iter()
    .enumerate()
    {
        put_u64(output, 56 + index * 8, value);
    }
    put_u32(output, 120, snapshot.live_peer_mask);
    put_u32(output, 124, snapshot.input_queue_bytes);
    put_u32(output, 128, snapshot.stdout_queue_bytes);
    put_u32(output, 132, snapshot.stderr_queue_bytes);
    put_u32(output, 136, snapshot.child_failures);
    put_u32(output, 140, snapshot.serial_failures);
    put_u32(output, 144, snapshot.last_failure as u32);
    Ok(SNAPSHOT_BYTES)
}

pub fn encode_error(
    header: Header,
    code: ErrorCode,
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    encode_header(header, ERROR, ERROR_BYTES, output)?;
    put_u32(output, 48, code as u32);
    Ok(ERROR_BYTES)
}

/// Parses a trustworthy common header. It intentionally does not accept a
/// short record, unknown version, nonzero flags, handles, or zero correlation.
pub fn parse_header(bytes: &[u8], handles: usize) -> Result<Header, DecodeError> {
    if bytes.len() < HEADER_BYTES {
        return Err(DecodeError::Size);
    }
    if handles != 0 || get_u32(bytes, 20) != 0 {
        return Err(DecodeError::Handles);
    }
    if bytes[..4] != MAGIC {
        return Err(DecodeError::Magic);
    }
    if get_u16(bytes, 4) != MAJOR || get_u16(bytes, 6) != MINOR {
        return Err(DecodeError::Version);
    }
    if get_u32(bytes, 12) != 0 {
        return Err(DecodeError::Flags);
    }
    let header = Header {
        transaction_id: get_u64(bytes, 24),
        console_generation: get_u64(bytes, 32),
        status_generation: get_u64(bytes, 40),
    };
    if !header.valid() {
        return Err(DecodeError::Identity);
    }
    Ok(header)
}

pub fn decode(bytes: &[u8], handles: usize) -> Result<Message, DecodeError> {
    let header = parse_header(bytes, handles)?;
    let message_type = get_u32(bytes, 8);
    let expected = match message_type {
        QUERY_STATUS => HEADER_BYTES,
        STATUS_SNAPSHOT => SNAPSHOT_BYTES,
        ERROR => ERROR_BYTES,
        _ => return Err(DecodeError::MessageType),
    };
    if bytes.len() != expected || get_u32(bytes, 16) as usize != expected {
        return Err(DecodeError::Size);
    }
    match message_type {
        QUERY_STATUS => Ok(Message::Query(header)),
        STATUS_SNAPSHOT => {
            if get_u32(bytes, 148) != 0 || get_u64(bytes, 152) != 0 {
                return Err(DecodeError::Reserved);
            }
            let snapshot = Snapshot {
                state: State::parse(get_u32(bytes, 48))?,
                flags: get_u32(bytes, 52),
                serial_registry_generation: get_u64(bytes, 56),
                publication_generation: get_u64(bytes, 64),
                device_bundle: get_u64(bytes, 72),
                driver_attempt: get_u64(bytes, 80),
                raw_stream_generation: get_u64(bytes, 88),
                child_generation: get_u64(bytes, 96),
                outer_job: get_u64(bytes, 104),
                outer_launch_transaction: get_u64(bytes, 112),
                live_peer_mask: get_u32(bytes, 120),
                input_queue_bytes: get_u32(bytes, 124),
                stdout_queue_bytes: get_u32(bytes, 128),
                stderr_queue_bytes: get_u32(bytes, 132),
                child_failures: get_u32(bytes, 136),
                serial_failures: get_u32(bytes, 140),
                last_failure: LastFailure::parse(get_u32(bytes, 144))?,
            };
            snapshot.validate().map_err(|error| match error {
                EncodeError::Bounds => DecodeError::Bounds,
                _ => DecodeError::Invariant,
            })?;
            Ok(Message::Snapshot(header, snapshot))
        }
        ERROR => {
            if get_u32(bytes, 52) != 0 {
                return Err(DecodeError::Reserved);
            }
            Ok(Message::Error(
                header,
                ErrorCode::parse(get_u32(bytes, 48))?,
            ))
        }
        _ => Err(DecodeError::MessageType),
    }
}

fn encode_header(
    header: Header,
    message_type: u32,
    size: usize,
    output: &mut [u8],
) -> Result<(), EncodeError> {
    if !header.valid() {
        return Err(EncodeError::Identity);
    }
    if output.len() < size {
        return Err(EncodeError::Buffer);
    }
    output[..size].fill(0);
    output[..4].copy_from_slice(&MAGIC);
    put_u16(output, 4, MAJOR);
    put_u16(output, 6, MINOR);
    put_u32(output, 8, message_type);
    put_u32(output, 16, size as u32);
    put_u64(output, 24, header.transaction_id);
    put_u64(output, 32, header.console_generation);
    put_u64(output, 40, header.status_generation);
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Relationship {
    pub console_generation: u64,
    pub status_generation: u64,
    pub child_generation: u64,
    pub outer_launch_transaction: u64,
}

impl Relationship {
    pub const fn valid(self) -> bool {
        self.console_generation != 0
            && self.status_generation != 0
            && self.child_generation != 0
            && self.outer_launch_transaction != 0
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct QueryTicket {
    header: Header,
}

impl QueryTicket {
    pub const fn header(&self) -> Header {
        self.header
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct StatusSession {
    relationship: Relationship,
    high_water: u64,
    outstanding: Option<u64>,
    open: bool,
}

impl StatusSession {
    pub fn new(relationship: Relationship) -> Result<Self, ErrorCode> {
        if !relationship.valid() {
            return Err(ErrorCode::StaleGeneration);
        }
        Ok(Self {
            relationship,
            high_water: 0,
            outstanding: None,
            open: true,
        })
    }

    pub const fn relationship(&self) -> Relationship {
        self.relationship
    }

    pub const fn high_water(&self) -> u64 {
        self.high_water
    }

    pub const fn is_open(&self) -> bool {
        self.open
    }

    /// Consumes every fresh transaction before semantic generation or busy
    /// rejection. Replayed/nonmonotonic transactions never produce a snapshot.
    pub fn admit(&mut self, header: Header) -> Result<QueryTicket, ErrorCode> {
        if !self.open {
            return Err(ErrorCode::Unavailable);
        }
        if header.transaction_id <= self.high_water {
            return Err(ErrorCode::Replay);
        }
        self.high_water = header.transaction_id;
        if header.console_generation != self.relationship.console_generation
            || header.status_generation != self.relationship.status_generation
        {
            return Err(ErrorCode::StaleGeneration);
        }
        if self.outstanding.is_some() {
            return Err(ErrorCode::Unavailable);
        }
        self.outstanding = Some(header.transaction_id);
        Ok(QueryTicket { header })
    }

    pub fn complete(&mut self, ticket: QueryTicket) -> Result<(), ErrorCode> {
        if !self.open || self.outstanding != Some(ticket.header.transaction_id) {
            return Err(ErrorCode::Unavailable);
        }
        self.outstanding = None;
        Ok(())
    }

    pub fn close(&mut self) {
        self.open = false;
        self.outstanding = None;
    }
}

fn get_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    const H: Header = Header {
        transaction_id: 7,
        console_generation: 11,
        status_generation: 13,
    };

    fn full_snapshot() -> Snapshot {
        Snapshot {
            state: State::Active,
            flags: FLAGS_MASK,
            serial_registry_generation: 1,
            publication_generation: 2,
            device_bundle: 3,
            driver_attempt: 4,
            raw_stream_generation: 5,
            child_generation: 6,
            outer_job: 7,
            outer_launch_transaction: 8,
            live_peer_mask: 0b111,
            input_queue_bytes: 4096,
            stdout_queue_bytes: 4096,
            stderr_queue_bytes: 4096,
            child_failures: 4,
            serial_failures: 4,
            last_failure: LastFailure::WrongDirection,
        }
    }

    #[test]
    fn golden_query_snapshot_and_error_are_exact() {
        let mut bytes = [0xaa; SNAPSHOT_BYTES];
        assert_eq!(encode_query(H, &mut bytes), Ok(48));
        assert_eq!(&bytes[..4], b"WRCN");
        assert_eq!(get_u32(&bytes, 8), 1);
        assert_eq!(get_u32(&bytes, 16), 48);
        assert_eq!(decode(&bytes[..48], 0), Ok(Message::Query(H)));

        let snapshot = full_snapshot();
        assert_eq!(encode_snapshot(H, snapshot, &mut bytes), Ok(160));
        assert_eq!(get_u32(&bytes, 8), 2);
        assert_eq!(get_u32(&bytes, 16), 160);
        assert_eq!(get_u32(&bytes, 144), 15);
        assert_eq!(decode(&bytes, 0), Ok(Message::Snapshot(H, snapshot)));

        assert_eq!(encode_error(H, ErrorCode::Replay, &mut bytes), Ok(56));
        assert_eq!(get_u32(&bytes, 8), 3);
        assert_eq!(get_u32(&bytes, 48), 3);
        assert_eq!(
            decode(&bytes[..56], 0),
            Ok(Message::Error(H, ErrorCode::Replay))
        );
    }

    #[test]
    fn malformed_corpus_and_snapshot_invariants_fail_closed() {
        let mut bytes = [0; SNAPSHOT_BYTES];
        encode_snapshot(H, full_snapshot(), &mut bytes).unwrap();
        for offset in [0, 4, 6, 8, 12, 16, 20, 24, 32, 40, 48, 52, 120, 148, 152] {
            let mut bad = bytes;
            if matches!(offset, 24 | 32 | 40) {
                bad[offset..offset + 8].fill(0);
            } else {
                bad[offset] ^= 0xff;
            }
            assert!(decode(&bad, 0).is_err(), "accepted mutation at {offset}");
        }
        assert_eq!(decode(&bytes, 1), Err(DecodeError::Handles));
        assert_eq!(decode(&bytes[..159], 0), Err(DecodeError::Size));

        let mut invalid = full_snapshot();
        invalid.input_queue_bytes = 4097;
        assert_eq!(
            encode_snapshot(H, invalid, &mut bytes),
            Err(EncodeError::Bounds)
        );
        invalid = full_snapshot();
        invalid.flags &= !FLAG_CHILD_PRESENT;
        assert_eq!(
            encode_snapshot(H, invalid, &mut bytes),
            Err(EncodeError::Invariant)
        );

        for update in [
            |snapshot: &mut Snapshot| snapshot.flags |= 1 << 7,
            |snapshot: &mut Snapshot| snapshot.live_peer_mask |= 1 << 3,
            |snapshot: &mut Snapshot| snapshot.stdout_queue_bytes = 4097,
            |snapshot: &mut Snapshot| snapshot.stderr_queue_bytes = 4097,
            |snapshot: &mut Snapshot| snapshot.child_failures = 5,
            |snapshot: &mut Snapshot| snapshot.serial_failures = 5,
        ] {
            let mut invalid = full_snapshot();
            update(&mut invalid);
            assert_eq!(invalid.validate(), Err(EncodeError::Bounds));
        }
    }

    #[test]
    fn correlatable_malformed_header_is_distinct_from_untrusted_input() {
        let mut bytes = [0; HEADER_BYTES];
        encode_query(H, &mut bytes).unwrap();
        put_u32(&mut bytes, 8, 99);
        assert_eq!(parse_header(&bytes, 0), Ok(H));
        assert_eq!(decode(&bytes, 0), Err(DecodeError::MessageType));

        for offset in [0, 4, 6, 12, 20, 24, 32, 40] {
            let mut bad = bytes;
            if matches!(offset, 24 | 32 | 40) {
                bad[offset..offset + 8].fill(0);
            } else {
                bad[offset] ^= 0xff;
            }
            assert!(parse_header(&bad, 0).is_err());
        }
        assert_eq!(parse_header(&bytes, 1), Err(DecodeError::Handles));
    }

    #[test]
    fn every_explicit_state_failure_and_error_id_round_trips() {
        let mut bytes = [0; SNAPSHOT_BYTES];
        for state in [
            State::Active,
            State::RetiringChild,
            State::AwaitingReap,
            State::Reconnecting,
            State::Exhausted,
            State::FailClosed,
        ] {
            for failure in [
                LastFailure::None,
                LastFailure::ZeroCorrelation,
                LastFailure::StaleCorrelation,
                LastFailure::WrongConnectionState,
                LastFailure::NoChild,
                LastFailure::IncompleteCleanup,
                LastFailure::AlreadyReserved,
                LastFailure::UnknownReservation,
                LastFailure::Backpressure,
                LastFailure::TooLarge,
                LastFailure::MonotonicRegression,
                LastFailure::ArithmeticOverflow,
                LastFailure::RestartExhausted,
                LastFailure::SerialDisconnected,
                LastFailure::ChildDisconnected,
                LastFailure::WrongDirection,
            ] {
                let snapshot = Snapshot {
                    state,
                    last_failure: failure,
                    ..full_snapshot()
                };
                encode_snapshot(H, snapshot, &mut bytes).unwrap();
                assert_eq!(decode(&bytes, 0), Ok(Message::Snapshot(H, snapshot)));
            }
        }
        for code in [
            ErrorCode::Malformed,
            ErrorCode::StaleGeneration,
            ErrorCode::Replay,
            ErrorCode::Unavailable,
        ] {
            let size = encode_error(H, code, &mut bytes).unwrap();
            assert_eq!(decode(&bytes[..size], 0), Ok(Message::Error(H, code)));
        }
    }

    #[test]
    fn pending_launch_without_child_is_valid() {
        let snapshot = Snapshot {
            state: State::Active,
            flags: FLAG_SERIAL_PRESENT | FLAG_PENDING_LAUNCH,
            serial_registry_generation: 1,
            publication_generation: 2,
            device_bundle: 3,
            driver_attempt: 4,
            raw_stream_generation: 5,
            child_generation: 0,
            outer_job: 0,
            outer_launch_transaction: 0,
            live_peer_mask: 0,
            input_queue_bytes: 0,
            stdout_queue_bytes: 0,
            stderr_queue_bytes: 0,
            child_failures: 0,
            serial_failures: 0,
            last_failure: LastFailure::None,
        };
        let mut bytes = [0; SNAPSHOT_BYTES];
        assert_eq!(encode_snapshot(H, snapshot, &mut bytes), Ok(160));
        assert_eq!(decode(&bytes, 0), Ok(Message::Snapshot(H, snapshot)));
    }

    #[test]
    fn status_session_is_monotonic_replay_exact_and_generation_bound() {
        let relationship = Relationship {
            console_generation: 11,
            status_generation: 13,
            child_generation: 17,
            outer_launch_transaction: 19,
        };
        let mut session = StatusSession::new(relationship).unwrap();
        let first = session.admit(H).unwrap();
        assert_eq!(
            session.admit(Header {
                transaction_id: 8,
                ..H
            }),
            Err(ErrorCode::Unavailable)
        );
        assert_eq!(session.high_water(), 8);
        session.complete(first).unwrap();
        assert_eq!(session.admit(H), Err(ErrorCode::Replay));
        assert_eq!(
            session.admit(Header {
                transaction_id: 9,
                status_generation: 99,
                ..H
            }),
            Err(ErrorCode::StaleGeneration)
        );
        let max = session
            .admit(Header {
                transaction_id: u64::MAX,
                ..H
            })
            .unwrap();
        session.complete(max).unwrap();
        assert_eq!(
            session.admit(Header {
                transaction_id: 1,
                ..H
            }),
            Err(ErrorCode::Replay)
        );
        session.close();
        assert_eq!(
            session.admit(Header {
                transaction_id: u64::MAX,
                ..H
            }),
            Err(ErrorCode::Unavailable)
        );

        let replacement = Relationship {
            status_generation: relationship.status_generation + 1,
            child_generation: relationship.child_generation + 1,
            outer_launch_transaction: relationship.outer_launch_transaction + 1,
            ..relationship
        };
        let mut replacement_session = StatusSession::new(replacement).unwrap();
        assert_eq!(
            replacement_session.admit(H),
            Err(ErrorCode::StaleGeneration)
        );
        assert_eq!(replacement_session.high_water(), H.transaction_id);
    }
}
