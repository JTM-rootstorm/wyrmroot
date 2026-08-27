//! Allocation-free WRLJ version 1 launch/job protocol.
//!
//! Jobs are opaque identities scoped to one exact connection generation. The
//! wire protocol exposes no PID, signal, descriptor, VFS, or ambient namespace.

#![no_std]
#![forbid(unsafe_code)]

pub const ENVELOPE_BYTES: usize = 40;
pub const PREFIX_BYTES: usize = 8;
pub const HEADER_BYTES: usize = ENVELOPE_BYTES + PREFIX_BYTES;
pub const MAX_LIVE_JOBS: usize = 32;
pub const MAX_COMPLETED_JOBS: usize = 32;
pub const MAX_ARGV: usize = 64;
pub const MAX_ENVIRONMENT: usize = 64;
pub const MAX_STRING_BYTES: usize = 16 * 1024;
pub const MAX_PATH_BYTES: usize = 256;
pub const STREAM_COUNT: usize = 3;

const MAGIC: [u8; 4] = *b"WRLJ";
const MAJOR: u16 = 1;
const MINOR: u16 = 0;
const RECORD_BYTES: usize = 8;
const LAUNCH_FIXED_BYTES: usize = 72;
/// Exact largest admitted LAUNCH message without reducing any argv,
/// environment, stream, path, or aggregate-string limit.
pub const MAX_LAUNCH_MESSAGE_BYTES: usize = LAUNCH_FIXED_BYTES
    + (MAX_ARGV + MAX_ENVIRONMENT) * RECORD_BYTES
    + STREAM_COUNT * RECORD_BYTES
    + MAX_PATH_BYTES
    + MAX_STRING_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reservation {
    pub connection_id: u64,
    pub generation: u64,
    pub transaction_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum MessageType {
    Launch = 1,
    LaunchAccepted = 2,
    Query = 3,
    JobState = 4,
    Wait = 5,
    JobResult = 6,
    Terminate = 7,
    TerminationAccepted = 8,
    ListJobs = 9,
    JobList = 10,
    Cancel = 11,
    Cancelled = 12,
    CloseJob = 13,
    Closed = 14,
    Error = 15,
}

impl MessageType {
    fn parse(value: u32) -> Result<Self, Error> {
        Ok(match value {
            1 => Self::Launch,
            2 => Self::LaunchAccepted,
            3 => Self::Query,
            4 => Self::JobState,
            5 => Self::Wait,
            6 => Self::JobResult,
            7 => Self::Terminate,
            8 => Self::TerminationAccepted,
            9 => Self::ListJobs,
            10 => Self::JobList,
            11 => Self::Cancel,
            12 => Self::Cancelled,
            13 => Self::CloseJob,
            14 => Self::Closed,
            15 => Self::Error,
            _ => return Err(Error::UnknownMessageType),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum StreamRole {
    Stdin = 1,
    Stdout = 2,
    Stderr = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobPhase {
    Running,
    Terminating,
    Exited,
    Reaped,
}

/// Stable controller failure classes for WRLJ `ERROR` responses.
///
/// These codes deliberately describe controller/protocol outcomes rather than
/// Deepwyrm statuses, which remain available only in a terminal `JOB_RESULT`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ErrorCode {
    MalformedRequest = 1,
    StaleOrUnknownSession = 2,
    TransactionReplay = 3,
    ForeignOrUnknownJob = 4,
    InvalidState = 5,
    Capacity = 6,
    PolicyRejected = 7,
    LoaderFailure = 8,
    CleanupFailure = 9,
    CancellationUnavailable = 10,
}

impl ErrorCode {
    const fn parse(value: u32) -> Result<Self, Error> {
        Ok(match value {
            1 => Self::MalformedRequest,
            2 => Self::StaleOrUnknownSession,
            3 => Self::TransactionReplay,
            4 => Self::ForeignOrUnknownJob,
            5 => Self::InvalidState,
            6 => Self::Capacity,
            7 => Self::PolicyRejected,
            8 => Self::LoaderFailure,
            9 => Self::CleanupFailure,
            10 => Self::CancellationUnavailable,
            _ => return Err(Error::InvalidErrorCode),
        })
    }

    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

/// Deepwyrm's exact public task-termination reasons accepted on the WRLJ
/// result wire. Values are frozen to the generated ABI and are not POSIX
/// status aliases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum TerminationClassification {
    NormalExit = 1,
    Authorized = 2,
    UnhandledException = 3,
    ResourcePolicy = 4,
    TaskGroupTeardown = 5,
}

impl TerminationClassification {
    const fn parse(value: u32) -> Result<Self, Error> {
        Ok(match value {
            1 => Self::NormalExit,
            2 => Self::Authorized,
            3 => Self::UnhandledException,
            4 => Self::ResourcePolicy,
            5 => Self::TaskGroupTeardown,
            _ => return Err(Error::InvalidTerminationClassification),
        })
    }

    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

/// All controller-owned cleanup bits currently admitted by WRLJ v1.
pub const CLEANUP_RESULT_MASK: u32 = 0x1f;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminationResult {
    pub classification: TerminationClassification,
    pub application_code: u32,
    pub exception_class: u32,
    pub exception_detail: u32,
    pub exception_address: u64,
    pub cleanup_result: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StringRecords<'a> {
    records: &'a [u8],
    strings: &'a [u8],
    count: usize,
}

impl<'a> StringRecords<'a> {
    fn get(self, index: usize) -> Option<&'a str> {
        if index >= self.count {
            return None;
        }
        let record = &self.records[index * RECORD_BYTES..(index + 1) * RECORD_BYTES];
        let offset = usize::try_from(get_u32(record, 0)?).ok()?;
        let length = usize::from(get_u16(record, 4)?);
        core::str::from_utf8(self.strings.get(offset..offset.checked_add(length)?)?).ok()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaunchRequest<'a> {
    pub path: &'a str,
    argv: StringRecords<'a>,
    environment: StringRecords<'a>,
    pub stream_count: usize,
}

impl<'a> LaunchRequest<'a> {
    pub const fn argc(self) -> usize {
        self.argv.count
    }
    pub const fn environment_count(self) -> usize {
        self.environment.count
    }
    pub fn arg(self, index: usize) -> Option<&'a str> {
        self.argv.get(index)
    }
    pub fn environment(self, index: usize) -> Option<&'a str> {
        self.environment.get(index)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobIds<'a>(&'a [u8]);

impl JobIds<'_> {
    pub const fn len(self) -> usize {
        self.0.len() / 8
    }
    pub const fn is_empty(self) -> bool {
        self.0.is_empty()
    }
    pub fn get(self, index: usize) -> Option<u64> {
        get_u64(self.0, index.checked_mul(8)?)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Message<'a> {
    Launch(LaunchRequest<'a>),
    LaunchAccepted {
        job_id: u64,
    },
    Query {
        job_id: u64,
    },
    JobState {
        job_id: u64,
        phase: JobPhase,
    },
    Wait {
        job_id: u64,
    },
    JobResult {
        job_id: u64,
        result: TerminationResult,
    },
    Terminate {
        job_id: u64,
    },
    TerminationAccepted {
        job_id: u64,
    },
    ListJobs,
    JobList(JobIds<'a>),
    Cancel {
        target_transaction_id: u64,
    },
    Cancelled {
        target_transaction_id: u64,
    },
    CloseJob {
        job_id: u64,
    },
    Closed {
        job_id: u64,
    },
    Error {
        code: ErrorCode,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedMessage<'a> {
    pub reservation: Reservation,
    pub message: Message<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    WrongSize,
    WrongMagic,
    UnsupportedVersion,
    UnknownMessageType,
    NonzeroFlags,
    NonzeroReserved,
    ZeroIdentity,
    WrongHandleCount,
    InvalidPath,
    InvalidArgumentCount,
    InvalidEnvironmentCount,
    InvalidStreamRoles,
    StringBytesExceeded,
    NoncanonicalStringRecords,
    InvalidUtf8,
    InvalidEnvironment,
    DuplicateEnvironmentName,
    Argv0Mismatch,
    InvalidJobState,
    InvalidErrorCode,
    InvalidTerminationClassification,
    InvalidCleanupResult,
    ArithmeticOverflow,
}

/// Compatibility envelope encoder retained for WYR1-A callers.
pub fn encode(value: Reservation, output: &mut [u8]) -> Result<usize, Error> {
    encode_envelope(value, output)?;
    Ok(ENVELOPE_BYTES)
}

/// Compatibility envelope parser retained for WYR1-A callers.
pub fn parse(bytes: &[u8]) -> Result<Reservation, Error> {
    if bytes.len() != ENVELOPE_BYTES {
        return Err(Error::WrongSize);
    }
    parse_envelope(bytes)
}

/// Parses only the fixed correlatable envelope from a complete or partial
/// message. Dispatchers use this before semantic body validation so a fresh
/// transaction is replay-protected even when the body is rejected.
pub fn parse_reservation_prefix(bytes: &[u8]) -> Result<Reservation, Error> {
    if bytes.len() < ENVELOPE_BYTES {
        return Err(Error::WrongSize);
    }
    parse_envelope(bytes)
}

pub fn parse_message(bytes: &[u8], received_handles: usize) -> Result<ParsedMessage<'_>, Error> {
    if bytes.len() < HEADER_BYTES {
        return Err(Error::WrongSize);
    }
    let reservation = parse_envelope(bytes)?;
    let message_type = MessageType::parse(read_u32(bytes, 40)?)?;
    if read_u32(bytes, 44)? != 0 {
        return Err(Error::NonzeroFlags);
    }
    let message = match message_type {
        MessageType::Launch => Message::Launch(parse_launch(bytes, received_handles)?),
        MessageType::LaunchAccepted => Message::LaunchAccepted {
            job_id: parse_job_id(bytes, received_handles)?,
        },
        MessageType::Query => Message::Query {
            job_id: parse_job_id(bytes, received_handles)?,
        },
        MessageType::JobState => {
            require_handles(received_handles, 0)?;
            require_size(bytes, 64)?;
            let job_id = nonzero(read_u64(bytes, 48)?)?;
            let phase = match read_u32(bytes, 56)? {
                1 => JobPhase::Running,
                2 => JobPhase::Terminating,
                3 => JobPhase::Exited,
                4 => JobPhase::Reaped,
                _ => return Err(Error::InvalidJobState),
            };
            if read_u32(bytes, 60)? != 0 {
                return Err(Error::NonzeroReserved);
            }
            Message::JobState { job_id, phase }
        }
        MessageType::Wait => Message::Wait {
            job_id: parse_job_id(bytes, received_handles)?,
        },
        MessageType::JobResult => {
            require_handles(received_handles, 0)?;
            require_size(bytes, 88)?;
            if read_u32(bytes, 84)? != 0 {
                return Err(Error::NonzeroReserved);
            }
            Message::JobResult {
                job_id: nonzero(read_u64(bytes, 48)?)?,
                result: TerminationResult {
                    classification: TerminationClassification::parse(read_u32(bytes, 56)?)?,
                    application_code: read_u32(bytes, 60)?,
                    exception_class: read_u32(bytes, 64)?,
                    exception_detail: read_u32(bytes, 68)?,
                    exception_address: read_u64(bytes, 72)?,
                    cleanup_result: parse_cleanup_result(read_u32(bytes, 80)?)?,
                },
            }
        }
        MessageType::Terminate => Message::Terminate {
            job_id: parse_job_id(bytes, received_handles)?,
        },
        MessageType::TerminationAccepted => Message::TerminationAccepted {
            job_id: parse_job_id(bytes, received_handles)?,
        },
        MessageType::ListJobs => {
            require_handles(received_handles, 0)?;
            require_size(bytes, HEADER_BYTES)?;
            Message::ListJobs
        }
        MessageType::JobList => Message::JobList(parse_job_list(bytes, received_handles)?),
        MessageType::Cancel => Message::Cancel {
            target_transaction_id: parse_job_id(bytes, received_handles)?,
        },
        MessageType::Cancelled => Message::Cancelled {
            target_transaction_id: parse_job_id(bytes, received_handles)?,
        },
        MessageType::CloseJob => Message::CloseJob {
            job_id: parse_job_id(bytes, received_handles)?,
        },
        MessageType::Closed => Message::Closed {
            job_id: parse_job_id(bytes, received_handles)?,
        },
        MessageType::Error => {
            require_handles(received_handles, 0)?;
            require_size(bytes, 56)?;
            if read_u32(bytes, 52)? != 0 {
                return Err(Error::NonzeroReserved);
            }
            Message::Error {
                code: ErrorCode::parse(read_u32(bytes, 48)?)?,
            }
        }
    };
    Ok(ParsedMessage {
        reservation,
        message,
    })
}

pub fn encode_launch(
    reservation: Reservation,
    path: &str,
    argv: &[&str],
    environment: &[&str],
    streams: bool,
    out: &mut [u8],
) -> Result<usize, Error> {
    validate_path(path)?;
    if argv.is_empty() || argv.len() > MAX_ARGV {
        return Err(Error::InvalidArgumentCount);
    }
    if environment.len() > MAX_ENVIRONMENT {
        return Err(Error::InvalidEnvironmentCount);
    }
    if argv[0] != path {
        return Err(Error::Argv0Mismatch);
    }
    validate_environment(environment)?;
    let string_bytes = argv
        .iter()
        .chain(environment.iter())
        .try_fold(0usize, |sum, value| {
            sum.checked_add(value.len())
                .ok_or(Error::ArithmeticOverflow)
        })?;
    if string_bytes > MAX_STRING_BYTES {
        return Err(Error::StringBytesExceeded);
    }
    let records = argv
        .len()
        .checked_add(environment.len())
        .and_then(|value| value.checked_mul(RECORD_BYTES))
        .ok_or(Error::ArithmeticOverflow)?;
    let stream_bytes = if streams {
        STREAM_COUNT * RECORD_BYTES
    } else {
        0
    };
    let total = LAUNCH_FIXED_BYTES
        .checked_add(records)
        .and_then(|value| value.checked_add(stream_bytes))
        .and_then(|value| value.checked_add(path.len()))
        .and_then(|value| value.checked_add(string_bytes))
        .ok_or(Error::ArithmeticOverflow)?;
    if out.len() < total {
        return Err(Error::WrongSize);
    }
    out[..total].fill(0);
    encode_prefix(reservation, MessageType::Launch, out)?;
    put_u32(out, 48, u32::try_from(total).map_err(|_| Error::WrongSize)?)?;
    put_u32(out, 52, if streams { 3 } else { 0 })?;
    put_u16(out, 56, path.len() as u16)?;
    put_u16(out, 58, argv.len() as u16)?;
    put_u16(out, 60, environment.len() as u16)?;
    put_u16(out, 62, if streams { 3 } else { 0 })?;
    put_u32(out, 64, string_bytes as u32)?;
    let mut record_offset = LAUNCH_FIXED_BYTES;
    let mut string_offset = 0usize;
    for value in argv.iter().chain(environment.iter()) {
        put_u32(out, record_offset, string_offset as u32)?;
        put_u16(out, record_offset + 4, value.len() as u16)?;
        record_offset += RECORD_BYTES;
        string_offset += value.len();
    }
    if streams {
        for role in [StreamRole::Stdin, StreamRole::Stdout, StreamRole::Stderr] {
            put_u32(out, record_offset, role as u32)?;
            record_offset += RECORD_BYTES;
        }
    }
    out[record_offset..record_offset + path.len()].copy_from_slice(path.as_bytes());
    let mut cursor = record_offset + path.len();
    for value in argv.iter().chain(environment.iter()) {
        out[cursor..cursor + value.len()].copy_from_slice(value.as_bytes());
        cursor += value.len();
    }
    Ok(total)
}

pub fn encode_job_message(
    reservation: Reservation,
    kind: MessageType,
    job_id: u64,
    out: &mut [u8],
) -> Result<usize, Error> {
    if !matches!(
        kind,
        MessageType::LaunchAccepted
            | MessageType::Query
            | MessageType::Wait
            | MessageType::Terminate
            | MessageType::TerminationAccepted
            | MessageType::Cancel
            | MessageType::Cancelled
            | MessageType::CloseJob
            | MessageType::Closed
    ) {
        return Err(Error::UnknownMessageType);
    }
    nonzero(job_id)?;
    if out.len() < 56 {
        return Err(Error::WrongSize);
    }
    out[..56].fill(0);
    encode_prefix(reservation, kind, out)?;
    put_u64(out, 48, job_id)?;
    Ok(56)
}

/// Encodes a terminal or current job phase response.
pub fn encode_job_state(
    reservation: Reservation,
    job_id: u64,
    phase: JobPhase,
    out: &mut [u8],
) -> Result<usize, Error> {
    nonzero(job_id)?;
    if out.len() < 64 {
        return Err(Error::WrongSize);
    }
    out[..64].fill(0);
    encode_prefix(reservation, MessageType::JobState, out)?;
    put_u64(out, 48, job_id)?;
    put_u32(
        out,
        56,
        match phase {
            JobPhase::Running => 1,
            JobPhase::Terminating => 2,
            JobPhase::Exited => 3,
            JobPhase::Reaped => 4,
        },
    )?;
    Ok(64)
}

/// Encodes the exact structured Deepwyrm termination and controller cleanup
/// outcome. No POSIX status is synthesized here.
pub fn encode_job_result(
    reservation: Reservation,
    job_id: u64,
    result: TerminationResult,
    out: &mut [u8],
) -> Result<usize, Error> {
    nonzero(job_id)?;
    if out.len() < 88 {
        return Err(Error::WrongSize);
    }
    out[..88].fill(0);
    encode_prefix(reservation, MessageType::JobResult, out)?;
    put_u64(out, 48, job_id)?;
    put_u32(out, 56, result.classification.as_u32())?;
    put_u32(out, 60, result.application_code)?;
    put_u32(out, 64, result.exception_class)?;
    put_u32(out, 68, result.exception_detail)?;
    put_u64(out, 72, result.exception_address)?;
    put_u32(out, 80, parse_cleanup_result(result.cleanup_result)?)?;
    Ok(88)
}

/// Encodes a typed protocol/controller failure response.
pub fn encode_error(
    reservation: Reservation,
    code: ErrorCode,
    out: &mut [u8],
) -> Result<usize, Error> {
    if out.len() < 56 {
        return Err(Error::WrongSize);
    }
    out[..56].fill(0);
    encode_prefix(reservation, MessageType::Error, out)?;
    put_u32(out, 48, code.as_u32())?;
    Ok(56)
}

/// Encodes a canonical owner-visible job list.
pub fn encode_job_list(
    reservation: Reservation,
    job_ids: &[u64],
    out: &mut [u8],
) -> Result<usize, Error> {
    if job_ids.len() > MAX_LIVE_JOBS {
        return Err(Error::WrongSize);
    }
    let size = 56usize
        .checked_add(
            job_ids
                .len()
                .checked_mul(8)
                .ok_or(Error::ArithmeticOverflow)?,
        )
        .ok_or(Error::ArithmeticOverflow)?;
    if out.len() < size {
        return Err(Error::WrongSize);
    }
    out[..size].fill(0);
    encode_prefix(reservation, MessageType::JobList, out)?;
    put_u32(
        out,
        48,
        u32::try_from(job_ids.len()).map_err(|_| Error::WrongSize)?,
    )?;
    for (index, job_id) in job_ids.iter().copied().enumerate() {
        nonzero(job_id)?;
        put_u64(out, 56 + index * 8, job_id)?;
    }
    Ok(size)
}

fn parse_launch(bytes: &[u8], received_handles: usize) -> Result<LaunchRequest<'_>, Error> {
    if bytes.len() < LAUNCH_FIXED_BYTES {
        return Err(Error::WrongSize);
    }
    if usize::try_from(read_u32(bytes, 48)?).map_err(|_| Error::WrongSize)? != bytes.len() {
        return Err(Error::WrongSize);
    }
    let declared_handles =
        usize::try_from(read_u32(bytes, 52)?).map_err(|_| Error::WrongHandleCount)?;
    require_handles(received_handles, declared_handles)?;
    let path_len = usize::from(read_u16(bytes, 56)?);
    let argc = usize::from(read_u16(bytes, 58)?);
    let envc = usize::from(read_u16(bytes, 60)?);
    let stream_count = usize::from(read_u16(bytes, 62)?);
    let string_bytes =
        usize::try_from(read_u32(bytes, 64)?).map_err(|_| Error::StringBytesExceeded)?;
    if read_u32(bytes, 68)? != 0 {
        return Err(Error::NonzeroReserved);
    }
    if !(1..=MAX_ARGV).contains(&argc) {
        return Err(Error::InvalidArgumentCount);
    }
    if envc > MAX_ENVIRONMENT {
        return Err(Error::InvalidEnvironmentCount);
    }
    if !matches!(stream_count, 0 | STREAM_COUNT) || stream_count != declared_handles {
        return Err(Error::InvalidStreamRoles);
    }
    if string_bytes > MAX_STRING_BYTES {
        return Err(Error::StringBytesExceeded);
    }
    let record_count = argc.checked_add(envc).ok_or(Error::ArithmeticOverflow)?;
    let records_end = LAUNCH_FIXED_BYTES
        .checked_add(
            record_count
                .checked_mul(RECORD_BYTES)
                .ok_or(Error::ArithmeticOverflow)?,
        )
        .ok_or(Error::ArithmeticOverflow)?;
    let stream_end = records_end
        .checked_add(
            stream_count
                .checked_mul(RECORD_BYTES)
                .ok_or(Error::ArithmeticOverflow)?,
        )
        .ok_or(Error::ArithmeticOverflow)?;
    let path_end = stream_end
        .checked_add(path_len)
        .ok_or(Error::ArithmeticOverflow)?;
    let strings_end = path_end
        .checked_add(string_bytes)
        .ok_or(Error::ArithmeticOverflow)?;
    if strings_end != bytes.len() {
        return Err(Error::WrongSize);
    }
    if stream_count == STREAM_COUNT {
        for (index, expected) in [StreamRole::Stdin, StreamRole::Stdout, StreamRole::Stderr]
            .into_iter()
            .enumerate()
        {
            let offset = records_end + index * RECORD_BYTES;
            if read_u32(bytes, offset)? != expected as u32 {
                return Err(Error::InvalidStreamRoles);
            }
            if read_u32(bytes, offset + 4)? != 0 {
                return Err(Error::NonzeroReserved);
            }
        }
    }
    let path =
        core::str::from_utf8(&bytes[stream_end..path_end]).map_err(|_| Error::InvalidUtf8)?;
    validate_path(path)?;
    let all_records = &bytes[LAUNCH_FIXED_BYTES..records_end];
    let strings = &bytes[path_end..];
    validate_records(all_records, strings, record_count)?;
    let argv = StringRecords {
        records: &all_records[..argc * RECORD_BYTES],
        strings,
        count: argc,
    };
    let environment = StringRecords {
        records: &all_records[argc * RECORD_BYTES..],
        strings,
        count: envc,
    };
    if argv.get(0) != Some(path) {
        return Err(Error::Argv0Mismatch);
    }
    validate_environment_records(environment)?;
    Ok(LaunchRequest {
        path,
        argv,
        environment,
        stream_count,
    })
}

fn parse_job_list(bytes: &[u8], received_handles: usize) -> Result<JobIds<'_>, Error> {
    require_handles(received_handles, 0)?;
    if bytes.len() < 56 {
        return Err(Error::WrongSize);
    }
    let count = usize::try_from(read_u32(bytes, 48)?).map_err(|_| Error::WrongSize)?;
    if count > MAX_LIVE_JOBS || read_u32(bytes, 52)? != 0 || bytes.len() != 56 + count * 8 {
        return Err(Error::WrongSize);
    }
    let ids = JobIds(&bytes[56..]);
    for index in 0..ids.len() {
        nonzero(ids.get(index).ok_or(Error::WrongSize)?)?;
    }
    Ok(ids)
}

fn validate_records(records: &[u8], strings: &[u8], count: usize) -> Result<(), Error> {
    let mut expected_offset = 0usize;
    for index in 0..count {
        let record = &records[index * RECORD_BYTES..(index + 1) * RECORD_BYTES];
        if get_u32(record, 0) != Some(expected_offset as u32) || get_u16(record, 6) != Some(0) {
            return Err(Error::NoncanonicalStringRecords);
        }
        let length = usize::from(get_u16(record, 4).ok_or(Error::WrongSize)?);
        let end = expected_offset
            .checked_add(length)
            .ok_or(Error::ArithmeticOverflow)?;
        core::str::from_utf8(strings.get(expected_offset..end).ok_or(Error::WrongSize)?)
            .map_err(|_| Error::InvalidUtf8)?;
        expected_offset = end;
    }
    if expected_offset != strings.len() {
        return Err(Error::NoncanonicalStringRecords);
    }
    Ok(())
}

pub fn validate_path(path: &str) -> Result<(), Error> {
    let bytes = path.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_PATH_BYTES
        || !bytes.is_ascii()
        || bytes[0] == b'/'
        || bytes.contains(&0)
    {
        return Err(Error::InvalidPath);
    }
    if path
        .split('/')
        .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(Error::InvalidPath);
    }
    Ok(())
}

fn validate_environment(values: &[&str]) -> Result<(), Error> {
    for (index, value) in values.iter().enumerate() {
        let name = environment_name(value)?;
        if values[..index]
            .iter()
            .any(|other| environment_name(other).ok() == Some(name))
        {
            return Err(Error::DuplicateEnvironmentName);
        }
    }
    Ok(())
}

fn validate_environment_records(values: StringRecords<'_>) -> Result<(), Error> {
    for index in 0..values.count {
        let value = values.get(index).ok_or(Error::InvalidUtf8)?;
        let name = environment_name(value)?;
        for previous in 0..index {
            if environment_name(values.get(previous).ok_or(Error::InvalidUtf8)?)? == name {
                return Err(Error::DuplicateEnvironmentName);
            }
        }
    }
    Ok(())
}

fn environment_name(value: &str) -> Result<&str, Error> {
    let (name, _) = value.split_once('=').ok_or(Error::InvalidEnvironment)?;
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 64
        || !(bytes[0].is_ascii_uppercase() || bytes[0] == b'_')
        || !bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        return Err(Error::InvalidEnvironment);
    }
    Ok(name)
}

fn parse_job_id(bytes: &[u8], handles: usize) -> Result<u64, Error> {
    require_handles(handles, 0)?;
    require_size(bytes, 56)?;
    nonzero(read_u64(bytes, 48)?)
}

fn encode_envelope(value: Reservation, output: &mut [u8]) -> Result<(), Error> {
    if output.len() < ENVELOPE_BYTES {
        return Err(Error::WrongSize);
    }
    if value.connection_id == 0 || value.generation == 0 || value.transaction_id == 0 {
        return Err(Error::ZeroIdentity);
    }
    output[..ENVELOPE_BYTES].fill(0);
    output[..4].copy_from_slice(&MAGIC);
    put_u16(output, 4, MAJOR)?;
    put_u16(output, 6, MINOR)?;
    put_u64(output, 8, value.connection_id)?;
    put_u64(output, 16, value.generation)?;
    put_u64(output, 24, value.transaction_id)?;
    Ok(())
}

fn encode_prefix(
    value: Reservation,
    message_type: MessageType,
    output: &mut [u8],
) -> Result<(), Error> {
    if output.len() < HEADER_BYTES {
        return Err(Error::WrongSize);
    }
    encode_envelope(value, output)?;
    put_u32(output, 40, message_type as u32)?;
    Ok(())
}

fn parse_envelope(bytes: &[u8]) -> Result<Reservation, Error> {
    if bytes.len() < ENVELOPE_BYTES {
        return Err(Error::WrongSize);
    }
    if bytes[..4] != MAGIC {
        return Err(Error::WrongMagic);
    }
    if read_u16(bytes, 4)? != MAJOR || read_u16(bytes, 6)? != MINOR {
        return Err(Error::UnsupportedVersion);
    }
    if read_u64(bytes, 32)? != 0 {
        return Err(Error::NonzeroReserved);
    }
    let value = Reservation {
        connection_id: read_u64(bytes, 8)?,
        generation: read_u64(bytes, 16)?,
        transaction_id: read_u64(bytes, 24)?,
    };
    if value.connection_id == 0 || value.generation == 0 || value.transaction_id == 0 {
        return Err(Error::ZeroIdentity);
    }
    Ok(value)
}

fn nonzero(value: u64) -> Result<u64, Error> {
    if value == 0 {
        Err(Error::ZeroIdentity)
    } else {
        Ok(value)
    }
}

fn parse_cleanup_result(value: u32) -> Result<u32, Error> {
    if value & !CLEANUP_RESULT_MASK != 0 {
        Err(Error::InvalidCleanupResult)
    } else {
        Ok(value)
    }
}
fn require_size(bytes: &[u8], expected: usize) -> Result<(), Error> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(Error::WrongSize)
    }
}
fn require_handles(actual: usize, expected: usize) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::WrongHandleCount)
    }
}
fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    get_u16(bytes, offset).ok_or(Error::WrongSize)
}
fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    get_u32(bytes, offset).ok_or(Error::WrongSize)
}
fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    get_u64(bytes, offset).ok_or(Error::WrongSize)
}
fn get_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn get_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn get_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}
fn put_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), Error> {
    bytes
        .get_mut(offset..offset.checked_add(2).ok_or(Error::ArithmeticOverflow)?)
        .ok_or(Error::WrongSize)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}
fn put_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), Error> {
    bytes
        .get_mut(offset..offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?)
        .ok_or(Error::WrongSize)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}
fn put_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<(), Error> {
    bytes
        .get_mut(offset..offset.checked_add(8).ok_or(Error::ArithmeticOverflow)?)
        .ok_or(Error::WrongSize)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::{string::String, vec, vec::Vec};
    const R: Reservation = Reservation {
        connection_id: 7,
        generation: 9,
        transaction_id: 11,
    };

    #[test]
    fn legacy_envelope_remains_exact() {
        let mut bytes = [0xaa; ENVELOPE_BYTES];
        assert_eq!(encode(R, &mut bytes), Ok(ENVELOPE_BYTES));
        assert_eq!(parse(&bytes), Ok(R));
        for offset in [0, 4, 6, 32] {
            let mut malformed = bytes;
            malformed[offset] ^= 1;
            assert!(parse(&malformed).is_err());
        }
        let mut complete = [0_u8; HEADER_BYTES];
        complete[..ENVELOPE_BYTES].copy_from_slice(&bytes);
        assert_eq!(parse_reservation_prefix(&complete), Ok(R));
        assert_eq!(
            parse_reservation_prefix(&complete[..ENVELOPE_BYTES - 1]),
            Err(Error::WrongSize)
        );
    }

    #[test]
    fn launch_round_trip_binds_arguments_environment_and_streams() {
        let argv = ["bin/hello", "kobold"];
        let environment = ["MODE=gate", "WYRMROOT_TEST=1"];
        let mut bytes = [0u8; 512];
        let size = encode_launch(R, "bin/hello", &argv, &environment, true, &mut bytes).unwrap();
        let parsed = parse_message(&bytes[..size], 3).unwrap();
        let Message::Launch(request) = parsed.message else {
            panic!("wrong message")
        };
        assert_eq!(request.path, "bin/hello");
        assert_eq!(request.arg(1), Some("kobold"));
        assert_eq!(request.environment(1), Some("WYRMROOT_TEST=1"));
        assert_eq!(request.stream_count, 3);
    }

    #[test]
    fn maximum_launch_message_size_is_exact_for_encode_and_parse() {
        let path = "p".repeat(MAX_PATH_BYTES);
        let environment: Vec<String> = (0..MAX_ENVIRONMENT)
            .map(|index| std::format!("E{index:02}="))
            .collect();
        let environment: Vec<&str> = environment.iter().map(String::as_str).collect();
        let environment_bytes = environment.iter().map(|value| value.len()).sum::<usize>();
        let mut argv = vec![String::new(); MAX_ARGV];
        argv[0] = path.clone();
        argv[1] = "a".repeat(MAX_STRING_BYTES - path.len() - environment_bytes);
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        assert_eq!(
            argv.iter()
                .chain(environment.iter())
                .map(|value| value.len())
                .sum::<usize>(),
            MAX_STRING_BYTES
        );

        let mut bytes = vec![0; MAX_LAUNCH_MESSAGE_BYTES];
        assert_eq!(
            encode_launch(R, &path, &argv, &environment, true, &mut bytes),
            Ok(MAX_LAUNCH_MESSAGE_BYTES)
        );
        assert!(matches!(
            parse_message(&bytes, STREAM_COUNT),
            Ok(ParsedMessage {
                message: Message::Launch(_),
                ..
            })
        ));
        assert_eq!(
            encode_launch(
                R,
                &path,
                &argv,
                &environment,
                true,
                &mut bytes[..MAX_LAUNCH_MESSAGE_BYTES - 1],
            ),
            Err(Error::WrongSize)
        );
        bytes.push(0);
        assert_eq!(parse_message(&bytes, STREAM_COUNT), Err(Error::WrongSize));
    }

    #[test]
    fn malformed_launch_fails_before_construction() {
        let mut bytes = [0u8; 256];
        assert_eq!(
            encode_launch(R, "../hello", &["../hello"], &[], false, &mut bytes),
            Err(Error::InvalidPath)
        );
        assert_eq!(
            encode_launch(R, "bin/hello", &["other"], &[], false, &mut bytes),
            Err(Error::Argv0Mismatch)
        );
        assert_eq!(
            encode_launch(
                R,
                "bin/hello",
                &["bin/hello"],
                &["bad=value"],
                false,
                &mut bytes
            ),
            Err(Error::InvalidEnvironment)
        );
        let size =
            encode_launch(R, "bin/hello", &["bin/hello"], &["A=1"], false, &mut bytes).unwrap();
        assert_eq!(
            parse_message(&bytes[..size], 1),
            Err(Error::WrongHandleCount)
        );
        bytes[68] = 1;
        assert_eq!(
            parse_message(&bytes[..size], 0),
            Err(Error::NonzeroReserved)
        );
    }

    #[test]
    fn job_operations_remain_connection_scoped() {
        let mut bytes = [0u8; 56];
        let size = encode_job_message(R, MessageType::Query, 17, &mut bytes).unwrap();
        assert_eq!(
            parse_message(&bytes[..size], 0).unwrap().message,
            Message::Query { job_id: 17 }
        );
        assert_eq!(
            encode_job_message(R, MessageType::ListJobs, 17, &mut bytes),
            Err(Error::UnknownMessageType)
        );
    }

    #[test]
    fn typed_responses_round_trip_without_posix_translation() {
        let mut bytes = [0u8; 88];
        let result = TerminationResult {
            classification: TerminationClassification::UnhandledException,
            application_code: 0,
            exception_class: 7,
            exception_detail: 9,
            exception_address: 0xfeed_beef,
            cleanup_result: 0b1_0100,
        };
        let size = encode_job_result(R, 17, result, &mut bytes).unwrap();
        assert_eq!(
            parse_message(&bytes[..size], 0).unwrap().message,
            Message::JobResult { job_id: 17, result }
        );
        let size = encode_error(R, ErrorCode::ForeignOrUnknownJob, &mut bytes).unwrap();
        assert_eq!(
            parse_message(&bytes[..size], 0).unwrap().message,
            Message::Error {
                code: ErrorCode::ForeignOrUnknownJob
            }
        );
    }

    #[test]
    fn resource_policy_termination_has_the_exact_deepwyrm_wire_value() {
        let mut bytes = [0u8; 88];
        let result = TerminationResult {
            classification: TerminationClassification::ResourcePolicy,
            application_code: 0,
            exception_class: 0,
            exception_detail: 0,
            exception_address: 0,
            cleanup_result: 0,
        };
        let size = encode_job_result(R, 17, result, &mut bytes).unwrap();
        assert_eq!(&bytes[56..60], &4_u32.to_le_bytes());
        assert_eq!(
            parse_message(&bytes[..size], 0).unwrap().message,
            Message::JobResult { job_id: 17, result }
        );
    }

    #[test]
    fn error_and_result_enums_reject_unknown_or_unowned_values() {
        let mut bytes = [0u8; 88];
        let size = encode_error(R, ErrorCode::Capacity, &mut bytes).unwrap();
        bytes[48..52].copy_from_slice(&0_u32.to_le_bytes());
        assert_eq!(
            parse_message(&bytes[..size], 0),
            Err(Error::InvalidErrorCode)
        );

        let result = TerminationResult {
            classification: TerminationClassification::NormalExit,
            application_code: 0,
            exception_class: 0,
            exception_detail: 0,
            exception_address: 0,
            cleanup_result: CLEANUP_RESULT_MASK + 1,
        };
        assert_eq!(
            encode_job_result(R, 17, result, &mut bytes),
            Err(Error::InvalidCleanupResult)
        );
        let valid = TerminationResult {
            cleanup_result: 0,
            ..result
        };
        let size = encode_job_result(R, 17, valid, &mut bytes).unwrap();
        bytes[56..60].copy_from_slice(&6_u32.to_le_bytes());
        assert_eq!(
            parse_message(&bytes[..size], 0),
            Err(Error::InvalidTerminationClassification)
        );
        bytes[56..60]
            .copy_from_slice(&(TerminationClassification::NormalExit as u32).to_le_bytes());
        bytes[80..84].copy_from_slice(&(CLEANUP_RESULT_MASK + 1).to_le_bytes());
        assert_eq!(
            parse_message(&bytes[..size], 0),
            Err(Error::InvalidCleanupResult)
        );
    }

    #[test]
    fn canonical_job_state_and_list_encoders_reject_bad_identities() {
        let mut bytes = [0u8; 320];
        let size = encode_job_state(R, 17, JobPhase::Terminating, &mut bytes).unwrap();
        assert_eq!(
            parse_message(&bytes[..size], 0).unwrap().message,
            Message::JobState {
                job_id: 17,
                phase: JobPhase::Terminating,
            }
        );
        let size = encode_job_list(R, &[17, 18], &mut bytes).unwrap();
        let Message::JobList(ids) = parse_message(&bytes[..size], 0).unwrap().message else {
            panic!("wrong message");
        };
        assert_eq!([ids.get(0), ids.get(1)], [Some(17), Some(18)]);
        assert_eq!(
            encode_job_list(R, &[0], &mut bytes),
            Err(Error::ZeroIdentity)
        );
    }
}
