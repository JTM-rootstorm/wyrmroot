//! WRBD 1.1: the BlockDevice protocol (root `STORAGE_PLAN.md` W3).
//!
//! A client reaches a block driver through the registry and then speaks WRBD
//! on its own direct Channel. Data never crosses the Channel: the client
//! attaches one MemoryObject, which the driver maps into its device's IOMMU
//! domain, and every READ or WRITE names a block range and an offset into
//! that buffer. The device moves the bytes itself.
//!
//! ```text
//! client -> driver   GET_INFO                      -> INFO
//! client -> driver   ATTACH (+ one MemoryObject)   -> COMPLETE
//! client -> driver   READ | WRITE | FLUSH          -> COMPLETE
//! client -> driver   QUERY_VERSION                 -> VERSION (1.1)
//! ```
//!
//! Every message is one datagram: a 32-byte header and a fixed body per
//! type, little-endian. The client picks a nonzero transaction for each
//! request and the reply echoes it. One request is outstanding at a time.
//! Every field this minor knows is checked; unknown types, flags, nonzero
//! reserved fields, short messages and wrong handle counts are refused.
//!
//! # Versions (root `OS_STACK_ARCHITECTURE_PLAN.md` X1)
//!
//! Minors are additive. A decoder accepts major 1 with any minor from
//! [`MIN_MINOR`] up, including minors newer than its own [`MINOR`]. A later
//! minor may add message types (each accepted only in a header whose minor
//! has it) and may append fields to the end of a message; the decoder
//! ignores every byte past the body it knows, while the header's size still
//! equals the datagram's. [`MAX_BYTES`] keeps [`EXTENSION_BYTES`] of room
//! for such fields, and a later minor appends no more than that. Reserved
//! fields, flags, statuses and handle counts stay exact.
//!
//! A responder answers in the request's minor, or its own if that is older
//! ([`ReplyTo`], [`encode_reply`]), in that minor's layout, so a peer whose
//! decoder requires its exact minor is answered as it expects; `blockmgr`
//! passes a request on in the minor it arrived in. QUERY_VERSION (1.1) asks
//! for the responder's [`Version`]. WRBD defines no feature bits yet; a
//! later minor may (device capabilities stay in INFO's flags).

#![no_std]
#![forbid(unsafe_code)]

pub const MAGIC: [u8; 4] = *b"WRBD";
pub const MAJOR: u16 = 1;
/// The minor this crate speaks.
pub const MINOR: u16 = 1;
/// The oldest minor whose layouts this crate reads.
pub const MIN_MINOR: u16 = 0;
/// The minor that added QUERY_VERSION and VERSION.
pub const VERSION_QUERY_MINOR: u16 = 1;
pub const HEADER_BYTES: usize = 32;
/// Room every receive buffer keeps past the largest body this minor
/// defines, for fields a later minor appends.
pub const EXTENSION_BYTES: usize = 64;
/// The largest WRBD message of any 1.x minor, for receive buffers.
pub const MAX_BYTES: usize = HEADER_BYTES + 24 + EXTENSION_BYTES;
/// The most handles any WRBD message carries.
pub const MAX_HANDLES: usize = 1;

const TYPE_GET_INFO: u32 = 1;
const TYPE_INFO: u32 = 2;
const TYPE_ATTACH: u32 = 3;
const TYPE_READ: u32 = 4;
const TYPE_WRITE: u32 = 5;
const TYPE_FLUSH: u32 = 6;
const TYPE_COMPLETE: u32 = 7;
const TYPE_QUERY_VERSION: u32 = 8;
const TYPE_VERSION: u32 = 9;

/// INFO flag: the device refuses writes.
pub const INFO_READ_ONLY: u32 = 1 << 0;
/// INFO flag: FLUSH reaches stable storage; without it FLUSH is UNSUPPORTED.
pub const INFO_FLUSH: u32 = 1 << 1;
const INFO_FLAGS: u32 = INFO_READ_ONLY | INFO_FLUSH;

/// Smallest and largest logical block sizes WRBD 1.0 describes.
pub const MIN_BLOCK_BYTES: u32 = 512;
pub const MAX_BLOCK_BYTES: u32 = 4096;

/// What the device reports about itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Info {
    /// A power of two from 512 to 4096.
    pub block_size: u32,
    pub flags: u32,
    /// Nonzero.
    pub block_count: u64,
    /// The most blocks one READ or WRITE may name; nonzero.
    pub max_transfer_blocks: u32,
}

/// One READ or WRITE: `block_count` blocks from `lba`, to or from the
/// attached buffer at `buffer_offset`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transfer {
    pub lba: u64,
    /// Nonzero.
    pub block_count: u32,
    pub buffer_offset: u64,
}

/// A responder's answer to QUERY_VERSION (1.1): the version it speaks,
/// which may be newer than the minor its answer travels in, and its feature
/// bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Version {
    /// Always [`MAJOR`].
    pub major: u16,
    /// At least [`VERSION_QUERY_MINOR`] and at least the answer's own minor.
    pub minor: u16,
    /// An open set of feature bits, none defined yet: a client ignores bits
    /// it does not know.
    pub features: u64,
}

impl Version {
    /// This crate's version with `features`.
    pub const fn current(features: u64) -> Self {
        Self {
            major: MAJOR,
            minor: MINOR,
            features,
        }
    }
}

/// What a reply answers: the request's transaction, and the minor to answer
/// in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplyTo {
    pub transaction_id: u64,
    pub minor: u16,
}

impl ReplyTo {
    /// For the request in `request`, which parsed with `transaction_id`.
    pub fn new(request: &[u8], transaction_id: u64) -> Self {
        Self {
            transaction_id,
            minor: reply_minor(request),
        }
    }
}

/// The minor to answer `request` in: its own, or [`MINOR`] if it is newer.
/// Meant for a request that parsed; anything shorter than a header gets
/// [`MINOR`].
pub fn reply_minor(request: &[u8]) -> u16 {
    if request.len() < HEADER_BYTES {
        return MINOR;
    }
    get16(request, 6).clamp(MIN_MINOR, MINOR)
}

/// A request's outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Status {
    Ok = 0,
    /// The device reported an error, or did not answer in time.
    IoError = 1,
    /// The device does not support the request (FLUSH without INFO_FLUSH).
    Unsupported = 2,
    /// The block range lies outside the device, or the byte range outside
    /// the attached buffer.
    OutOfRange = 3,
    /// READ or WRITE before a successful ATTACH.
    NoBuffer = 4,
    /// The request is well formed but unacceptable: a transfer above
    /// `max_transfer_blocks`, a misaligned offset, or a buffer the driver
    /// will not map.
    Invalid = 5,
    ReadOnly = 6,
    /// The driver or the kernel has no room for another mapping.
    NoResources = 7,
    /// ATTACH on a connection that already has a buffer.
    AlreadyAttached = 8,
}

impl Status {
    fn parse(value: u32) -> Result<Self, Error> {
        Ok(match value {
            0 => Self::Ok,
            1 => Self::IoError,
            2 => Self::Unsupported,
            3 => Self::OutOfRange,
            4 => Self::NoBuffer,
            5 => Self::Invalid,
            6 => Self::ReadOnly,
            7 => Self::NoResources,
            8 => Self::AlreadyAttached,
            _ => return Err(Error::UnknownStatus),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Body {
    GetInfo,
    Info(Info),
    /// Carries exactly one MemoryObject handle; the driver maps its first
    /// `byte_len` bytes, a nonzero multiple of 4096.
    Attach {
        byte_len: u64,
    },
    Read(Transfer),
    Write(Transfer),
    Flush,
    Complete(Status),
    /// Asks for the responder's version (1.1).
    QueryVersion,
    /// QUERY_VERSION's answer (1.1).
    Version(Version),
}

impl Body {
    /// Whether a client sends this message (as opposed to the driver).
    pub const fn is_request(self) -> bool {
        matches!(
            self,
            Self::GetInfo
                | Self::Attach { .. }
                | Self::Read(_)
                | Self::Write(_)
                | Self::Flush
                | Self::QueryVersion
        )
    }

    /// The minor that introduced this message.
    pub const fn since(self) -> u16 {
        match self {
            Self::QueryVersion | Self::Version(_) => VERSION_QUERY_MINOR,
            _ => MIN_MINOR,
        }
    }

    pub const fn wire_size(self) -> usize {
        HEADER_BYTES
            + match self {
                Self::GetInfo | Self::Flush | Self::QueryVersion => 0,
                Self::Attach { .. } | Self::Complete(_) => 8,
                Self::Version(_) => 16,
                Self::Info(_) | Self::Read(_) | Self::Write(_) => 24,
            }
    }

    pub const fn handle_count(self) -> usize {
        match self {
            Self::Attach { .. } => 1,
            _ => 0,
        }
    }

    const fn message_type(self) -> u32 {
        match self {
            Self::GetInfo => TYPE_GET_INFO,
            Self::Info(_) => TYPE_INFO,
            Self::Attach { .. } => TYPE_ATTACH,
            Self::Read(_) => TYPE_READ,
            Self::Write(_) => TYPE_WRITE,
            Self::Flush => TYPE_FLUSH,
            Self::Complete(_) => TYPE_COMPLETE,
            Self::QueryVersion => TYPE_QUERY_VERSION,
            Self::Version(_) => TYPE_VERSION,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Message {
    /// Nonzero.
    pub transaction_id: u64,
    pub body: Body,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    WrongSize,
    WrongMagic,
    WrongVersion,
    UnknownMessage,
    WrongHandleCount,
    ZeroTransaction,
    NonzeroReserved,
    UnknownFlags,
    UnknownStatus,
    InvalidField,
}

/// Encodes `message` in [`MINOR`] into exactly `output[..wire_size]`,
/// returning that size.
pub fn encode(message: Message, output: &mut [u8]) -> Result<usize, Error> {
    encode_at(message, MINOR, output)
}

/// Encodes the reply `body` to `to` in its minor.
pub fn encode_reply(to: ReplyTo, body: Body, output: &mut [u8]) -> Result<usize, Error> {
    encode_at(
        Message {
            transaction_id: to.transaction_id,
            body,
        },
        to.minor,
        output,
    )
}

/// Encodes `message` in `minor`'s layout, which must be one this crate
/// speaks and have the message.
pub fn encode_at(message: Message, minor: u16, output: &mut [u8]) -> Result<usize, Error> {
    if !(MIN_MINOR..=MINOR).contains(&minor) || minor < message.body.since() {
        return Err(Error::WrongVersion);
    }
    let size = message.body.wire_size();
    let output = output.get_mut(..size).ok_or(Error::WrongSize)?;
    if message.transaction_id == 0 {
        return Err(Error::ZeroTransaction);
    }
    validate_body(message.body)?;
    output.fill(0);
    output[..4].copy_from_slice(&MAGIC);
    output[4..6].copy_from_slice(&MAJOR.to_le_bytes());
    output[6..8].copy_from_slice(&minor.to_le_bytes());
    put32(output, 8, message.body.message_type());
    put32(output, 12, size as u32);
    put32(output, 16, message.body.handle_count() as u32);
    put64(output, 24, message.transaction_id);
    match message.body {
        Body::GetInfo | Body::Flush => {}
        Body::Info(info) => {
            put32(output, 32, info.block_size);
            put32(output, 36, info.flags);
            put64(output, 40, info.block_count);
            put32(output, 48, info.max_transfer_blocks);
        }
        Body::Attach { byte_len } => put64(output, 32, byte_len),
        Body::Read(transfer) | Body::Write(transfer) => {
            put64(output, 32, transfer.lba);
            put32(output, 40, transfer.block_count);
            put64(output, 48, transfer.buffer_offset);
        }
        Body::Complete(status) => put32(output, 32, status as u32),
        Body::QueryVersion => {}
        Body::Version(version) => {
            output[32..34].copy_from_slice(&version.major.to_le_bytes());
            output[34..36].copy_from_slice(&version.minor.to_le_bytes());
            put64(output, 40, version.features);
        }
    }
    Ok(size)
}

/// Parses one datagram of `bytes` that arrived with `handle_count` handles.
pub fn parse(bytes: &[u8], handle_count: usize) -> Result<Message, Error> {
    if bytes.len() < HEADER_BYTES || get32(bytes, 12) as usize != bytes.len() {
        return Err(Error::WrongSize);
    }
    if bytes[..4] != MAGIC {
        return Err(Error::WrongMagic);
    }
    // Every minor of major 1 is read: [`MIN_MINOR`] is 1.0 itself.
    let minor = get16(bytes, 6);
    if get16(bytes, 4) != MAJOR {
        return Err(Error::WrongVersion);
    }
    if get32(bytes, 20) != 0 {
        return Err(Error::NonzeroReserved);
    }
    let transaction_id = get64(bytes, 24);
    if transaction_id == 0 {
        return Err(Error::ZeroTransaction);
    }
    let message_type = get32(bytes, 8);
    let versioned = minor >= VERSION_QUERY_MINOR;
    let body_bytes = match message_type {
        TYPE_GET_INFO | TYPE_FLUSH => 0,
        TYPE_QUERY_VERSION if versioned => 0,
        TYPE_ATTACH | TYPE_COMPLETE => 8,
        TYPE_VERSION if versioned => 16,
        TYPE_INFO | TYPE_READ | TYPE_WRITE => 24,
        _ => return Err(Error::UnknownMessage),
    };
    // The size is checked before any body field is read. Bytes past the
    // body are a later minor's and ignored.
    if bytes.len() < HEADER_BYTES + body_bytes {
        return Err(Error::WrongSize);
    }
    let transfer = || Transfer {
        lba: get64(bytes, 32),
        block_count: get32(bytes, 40),
        buffer_offset: get64(bytes, 48),
    };
    let body = match message_type {
        TYPE_GET_INFO => Body::GetInfo,
        TYPE_INFO => Body::Info(Info {
            block_size: get32(bytes, 32),
            flags: get32(bytes, 36),
            block_count: get64(bytes, 40),
            max_transfer_blocks: get32(bytes, 48),
        }),
        TYPE_ATTACH => Body::Attach {
            byte_len: get64(bytes, 32),
        },
        TYPE_READ => Body::Read(transfer()),
        TYPE_WRITE => Body::Write(transfer()),
        TYPE_FLUSH => Body::Flush,
        TYPE_COMPLETE => Body::Complete(Status::parse(get32(bytes, 32))?),
        TYPE_QUERY_VERSION => Body::QueryVersion,
        TYPE_VERSION => {
            let version = Version {
                major: get16(bytes, 32),
                minor: get16(bytes, 34),
                features: get64(bytes, 40),
            };
            // A responder's own minor is never older than its answer's.
            if version.minor < minor {
                return Err(Error::InvalidField);
            }
            Body::Version(version)
        }
        _ => return Err(Error::UnknownMessage),
    };
    let declared = get32(bytes, 16) as usize;
    if declared != body.handle_count() || handle_count != declared {
        return Err(Error::WrongHandleCount);
    }
    let reserved_zero = match body {
        Body::Info(_) => get32(bytes, 52) == 0,
        Body::Read(_) | Body::Write(_) => get32(bytes, 44) == 0,
        Body::Complete(_) | Body::Version(_) => get32(bytes, 36) == 0,
        _ => true,
    };
    if !reserved_zero {
        return Err(Error::NonzeroReserved);
    }
    validate_body(body)?;
    Ok(Message {
        transaction_id,
        body,
    })
}

fn validate_body(body: Body) -> Result<(), Error> {
    match body {
        Body::Info(info) => {
            if info.flags & !INFO_FLAGS != 0 {
                return Err(Error::UnknownFlags);
            }
            if !info.block_size.is_power_of_two()
                || !(MIN_BLOCK_BYTES..=MAX_BLOCK_BYTES).contains(&info.block_size)
                || info.block_count == 0
                || info.max_transfer_blocks == 0
            {
                return Err(Error::InvalidField);
            }
        }
        Body::Attach { byte_len } => {
            if byte_len == 0 || !byte_len.is_multiple_of(4096) {
                return Err(Error::InvalidField);
            }
        }
        Body::Read(transfer) | Body::Write(transfer) => {
            if transfer.block_count == 0 {
                return Err(Error::InvalidField);
            }
        }
        Body::Version(version) => {
            if version.major != MAJOR || version.minor < VERSION_QUERY_MINOR {
                return Err(Error::InvalidField);
            }
        }
        Body::GetInfo | Body::Flush | Body::Complete(_) | Body::QueryVersion => {}
    }
    Ok(())
}

fn get16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn get32(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

fn get64(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests;
