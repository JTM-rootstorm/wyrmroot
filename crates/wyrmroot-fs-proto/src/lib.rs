//! The VFS protocols (root `STORAGE_PLAN.md` W5).
//!
//! Two protocols share one header layout, one status set and one path
//! grammar:
//!
//! - [`node`] (`WRFS` 1.4) is spoken on a Channel to one opened directory or
//!   file. A filesystem service serves it, and so does `vfsd` for the
//!   synthetic directories above its mount points.
//! - [`namespace`] (`WRNS` 1.4) is spoken to `vfsd`: OPEN of an absolute
//!   path through the mount table, and MOUNT/UNMOUNT on the administrative
//!   connection.
//!
//! The two share one version: `vfsd` passes a WRNS OPEN on to a filesystem
//! as a WRFS OPEN in the same minor, so they bump together.
//!
//! An open is pipelined and one-way: the client creates a Channel pair, keeps
//! one end, and sends the other with OPEN. Whoever finally serves the node
//! (a filesystem, or `vfsd` itself) sends one ON_OPEN event on that Channel
//! first, carrying the outcome and, on success, the node's attributes. A
//! failed open is ON_OPEN with an error status followed by the Channel's
//! closure. A forwarder such as `vfsd` therefore never waits on a
//! filesystem, and after the open the client talks to the filesystem
//! directly.
//!
//! Every message is one datagram: a 32-byte header (magic, major, minor,
//! type, total size, handle count, a reserved word, a nonzero transaction)
//! and a body, little-endian. Variable bodies (paths, names, data, directory
//! entries) carry an explicit length. Every field this minor knows is
//! checked; unknown types and flags, nonzero reserved fields, short
//! messages and wrong handle counts are refused. The size is checked before
//! any body field is read.
//!
//! # Versions (root `OS_STACK_ARCHITECTURE_PLAN.md` X1)
//!
//! Minors are additive. A decoder accepts its own major with any minor from
//! [`MIN_MINOR`] up, including minors newer than its own [`MINOR`]:
//!
//! - A later minor may add message types; a message type is accepted only
//!   in a header whose minor has it, so a type newer than the decoder is
//!   still refused as unknown.
//! - A later minor may append fields to the end of an existing message.
//!   The decoder ignores every byte past the body it knows: past the fixed
//!   body, or past the payload a variable body's own length selects. The
//!   header's total size still equals the datagram's. Receive buffers
//!   ([`node::MAX_BYTES`], [`namespace::MAX_BYTES`]) keep
//!   [`EXTENSION_BYTES`] of room past the largest body this minor defines,
//!   and a later minor appends no more than that.
//! - Nothing else changes in a minor: reserved fields stay zero, flags,
//!   statuses and handle counts stay exact.
//!
//! A responder answers in the request's minor, or its own if that is older
//! ([`reply_minor`], `encode_at`), and in that minor's layout, so a peer
//! built against an older minor (whose decoder may require its exact minor)
//! is answered as it expects. An event a server sends unasked (WRFS
//! ON_OPEN) uses the minor of the OPEN that asked for the Channel, and
//! `vfsd` passes an OPEN on in the minor it arrived in. QUERY_VERSION (1.4)
//! asks a server for its own version and feature bits ([`Version`]).
//!
//! Paths are byte strings, as on disk: components are separated by `/`,
//! nonempty, at most [`MAX_NAME_BYTES`] bytes, contain no NUL and are never
//! `.` or `..`. The protocols carry only canonical paths, so no server ever
//! resolves `..` and a filesystem cannot be escaped through its root;
//! clients normalize lexically before they send. Native text APIs above
//! this layer expect UTF-8 (platform conventions §5.1); this layer does not.

#![no_std]
#![forbid(unsafe_code)]

pub mod namespace;
pub mod node;

pub const MAJOR: u16 = 1;
/// The minor this crate speaks.
pub const MINOR: u16 = 4;
/// The oldest minor whose layouts this crate reads; older ones are refused.
pub const MIN_MINOR: u16 = 3;
/// The minor that added QUERY_VERSION and VERSION.
pub const VERSION_QUERY_MINOR: u16 = 4;
pub const HEADER_BYTES: usize = 32;
/// Room every receive buffer keeps past the largest body this minor
/// defines, for fields a later minor appends.
pub const EXTENSION_BYTES: usize = 64;
/// The longest path either protocol carries, in bytes.
pub const MAX_PATH_BYTES: usize = 1024;
/// The longest path component, in bytes.
pub const MAX_NAME_BYTES: usize = 255;
/// The most handles any message carries.
pub const MAX_HANDLES: usize = 1;

/// OPEN flag: the opened node may be read (files) or listed (directories).
pub const OPEN_READ: u32 = 1 << 0;
/// OPEN flag: the opened node may be written (files) or have entries created
/// and removed (directories).
pub const OPEN_WRITE: u32 = 1 << 1;
/// OPEN flag: the node must be a directory; with [`OPEN_CREATE`], create one.
pub const OPEN_DIRECTORY: u32 = 1 << 2;
/// OPEN flag: the node must be a file; with [`OPEN_CREATE`], create one.
pub const OPEN_FILE: u32 = 1 << 3;
/// OPEN flag: create the final component if it does not exist. Needs a
/// nonempty path and exactly one of [`OPEN_DIRECTORY`] or [`OPEN_FILE`].
pub const OPEN_CREATE: u32 = 1 << 4;
/// OPEN flag, only with [`OPEN_CREATE`]: fail with EXISTS if it exists.
pub const OPEN_EXCLUSIVE: u32 = 1 << 5;
/// OPEN flag: truncate a file to zero bytes. Needs [`OPEN_WRITE`] and is
/// refused with [`OPEN_DIRECTORY`].
pub const OPEN_TRUNCATE: u32 = 1 << 6;
const OPEN_FLAGS: u32 = OPEN_READ
    | OPEN_WRITE
    | OPEN_DIRECTORY
    | OPEN_FILE
    | OPEN_CREATE
    | OPEN_EXCLUSIVE
    | OPEN_TRUNCATE;
/// Flags that need write access to the node or its directory.
pub const OPEN_MUTATING: u32 = OPEN_WRITE | OPEN_CREATE | OPEN_TRUNCATE;

/// Checks one OPEN's flags against `path`.
///
/// Access never grows: a server refuses with ACCESS_DENIED any open that
/// asks for more access than the directory it arrived on carries.
pub fn check_open_flags(flags: u32, path: &[u8]) -> Result<(), Error> {
    let kind = flags & (OPEN_DIRECTORY | OPEN_FILE);
    let valid = flags & !OPEN_FLAGS == 0
        && flags & (OPEN_READ | OPEN_WRITE) != 0
        && kind != OPEN_DIRECTORY | OPEN_FILE
        && (flags & OPEN_CREATE == 0 || (kind != 0 && !path.is_empty()))
        && (flags & OPEN_EXCLUSIVE == 0 || flags & OPEN_CREATE != 0)
        && (flags & OPEN_TRUNCATE == 0 || (flags & OPEN_WRITE != 0 && flags & OPEN_DIRECTORY == 0));
    if valid {
        Ok(())
    } else {
        Err(Error::UnknownFlags)
    }
}

/// An operation's outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Status {
    Ok = 0,
    NotFound = 1,
    Exists = 2,
    NotDirectory = 3,
    IsDirectory = 4,
    /// The request asks for more access than the handle carries.
    AccessDenied = 5,
    /// The filesystem or mount is read-only.
    ReadOnly = 6,
    NoSpace = 7,
    /// A well-formed path that cannot be used here, such as one that grows
    /// past [`MAX_PATH_BYTES`] once joined to its directory.
    InvalidPath = 8,
    /// A well-formed request that is unacceptable, such as a stale cookie.
    Invalid = 9,
    NotSupported = 10,
    IoError = 11,
    NotEmpty = 12,
    /// The server has no room for another connection, mount or node.
    NoResources = 13,
    /// The request could not be passed on now; it may be retried.
    Busy = 14,
    /// Waiting for the lock would wait for ever (1.2).
    Deadlock = 15,
}

impl Status {
    fn parse(value: u32) -> Result<Self, Error> {
        Ok(match value {
            0 => Self::Ok,
            1 => Self::NotFound,
            2 => Self::Exists,
            3 => Self::NotDirectory,
            4 => Self::IsDirectory,
            5 => Self::AccessDenied,
            6 => Self::ReadOnly,
            7 => Self::NoSpace,
            8 => Self::InvalidPath,
            9 => Self::Invalid,
            10 => Self::NotSupported,
            11 => Self::IoError,
            12 => Self::NotEmpty,
            13 => Self::NoResources,
            14 => Self::Busy,
            15 => Self::Deadlock,
            _ => return Err(Error::UnknownStatus),
        })
    }
}

/// A server's answer to QUERY_VERSION (1.4): the version it speaks, which
/// may be newer than the minor its answer travels in, and its feature bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Version {
    /// Always [`MAJOR`].
    pub major: u16,
    /// At least [`VERSION_QUERY_MINOR`] and at least the answer's own minor.
    pub minor: u16,
    /// An open set of the protocol's `FEATURE_*` bits: a client ignores bits
    /// it does not know, and a later minor may define more.
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

/// The minor to answer `request` in: its own, or [`MINOR`] if it is newer.
/// Meant for a request that parsed; anything shorter than a header gets
/// [`MINOR`].
pub fn reply_minor(request: &[u8]) -> u16 {
    if request.len() < HEADER_BYTES {
        return MINOR;
    }
    get16(request, 6).clamp(MIN_MINOR, MINOR)
}

/// What a reply answers: the request's transaction, and the minor to answer
/// in. A server that answers later (ON_OPEN, a LOCK that waited) keeps it.
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
    InvalidPath,
}

/// Checks one path component.
pub fn check_name(name: &[u8]) -> Result<(), Error> {
    if name.is_empty()
        || name.len() > MAX_NAME_BYTES
        || name == b"."
        || name == b".."
        || name.iter().any(|&byte| byte == 0 || byte == b'/')
    {
        Err(Error::InvalidPath)
    } else {
        Ok(())
    }
}

/// Checks a canonical relative path: empty (the node itself), or components
/// joined by single slashes, with no leading or trailing slash.
pub fn check_relative(path: &[u8]) -> Result<(), Error> {
    if path.len() > MAX_PATH_BYTES {
        return Err(Error::InvalidPath);
    }
    if path.is_empty() {
        return Ok(());
    }
    path.split(|&byte| byte == b'/').try_for_each(check_name)
}

/// Checks a canonical absolute path: `/`, or `/` followed by a nonempty
/// canonical relative path.
pub fn check_absolute(path: &[u8]) -> Result<(), Error> {
    match path {
        [b'/'] => Ok(()),
        [b'/', rest @ ..] if !rest.is_empty() && path.len() <= MAX_PATH_BYTES => {
            check_relative(rest)
        }
        _ => Err(Error::InvalidPath),
    }
}

struct Header {
    minor: u16,
    message_type: u32,
    handle_count: usize,
    transaction_id: u64,
}

/// Checks that a message introduced in minor `since` may be encoded in
/// `minor`.
fn check_encode_minor(minor: u16, since: u16) -> Result<(), Error> {
    if (MIN_MINOR..=MINOR).contains(&minor) && minor >= since {
        Ok(())
    } else {
        Err(Error::WrongVersion)
    }
}

fn write_header(
    output: &mut [u8],
    magic: [u8; 4],
    minor: u16,
    message_type: u32,
    handle_count: usize,
    transaction_id: u64,
) {
    output.fill(0);
    output[..4].copy_from_slice(&magic);
    output[4..6].copy_from_slice(&MAJOR.to_le_bytes());
    output[6..8].copy_from_slice(&minor.to_le_bytes());
    put32(output, 8, message_type);
    put32(output, 12, output.len() as u32);
    put32(output, 16, handle_count as u32);
    put64(output, 24, transaction_id);
}

/// Checks everything in the header except that the type is known and that
/// the handle count suits it.
fn read_header(bytes: &[u8], magic: [u8; 4]) -> Result<Header, Error> {
    if bytes.len() < HEADER_BYTES || get32(bytes, 12) as usize != bytes.len() {
        return Err(Error::WrongSize);
    }
    if bytes[..4] != magic {
        return Err(Error::WrongMagic);
    }
    let minor = get16(bytes, 6);
    if get16(bytes, 4) != MAJOR || minor < MIN_MINOR {
        return Err(Error::WrongVersion);
    }
    if get32(bytes, 20) != 0 {
        return Err(Error::NonzeroReserved);
    }
    let transaction_id = get64(bytes, 24);
    if transaction_id == 0 {
        return Err(Error::ZeroTransaction);
    }
    Ok(Header {
        minor,
        message_type: get32(bytes, 8),
        handle_count: get32(bytes, 16) as usize,
        transaction_id,
    })
}

/// Checks the message holds a fixed body of `body` bytes; anything after
/// it is a later minor's and ignored.
fn fixed(bytes: &[u8], body: usize) -> Result<(), Error> {
    if bytes.len() >= HEADER_BYTES + body {
        Ok(())
    } else {
        Err(Error::WrongSize)
    }
}

/// A variable tail of `fixed` bytes of body followed by `length` bytes,
/// where `length` is the u32 at `length_at`: those bytes, which the message
/// must hold. Anything after them is a later minor's and ignored.
fn tail(bytes: &[u8], fixed: usize, length_at: usize, max: usize) -> Result<&[u8], Error> {
    let start = HEADER_BYTES + fixed;
    if bytes.len() < start {
        return Err(Error::WrongSize);
    }
    let length = get32(bytes, length_at) as usize;
    if length > max || bytes.len() - start < length {
        return Err(Error::WrongSize);
    }
    Ok(&bytes[start..start + length])
}

const VERSION_BODY_BYTES: usize = 16;

fn put_version(output: &mut [u8], offset: usize, version: Version) {
    output[offset..offset + 2].copy_from_slice(&version.major.to_le_bytes());
    output[offset + 2..offset + 4].copy_from_slice(&version.minor.to_le_bytes());
    put64(output, offset + 8, version.features);
}

/// Reads VERSION's body at `offset`, which arrived in a header of `minor`.
fn get_version(bytes: &[u8], offset: usize, minor: u16) -> Result<Version, Error> {
    if get32(bytes, offset + 4) != 0 {
        return Err(Error::NonzeroReserved);
    }
    let version = Version {
        major: get16(bytes, offset),
        minor: get16(bytes, offset + 2),
        features: get64(bytes, offset + 8),
    };
    if version.minor < minor {
        return Err(Error::InvalidField);
    }
    check_version(version)?;
    Ok(version)
}

fn check_version(version: Version) -> Result<(), Error> {
    if version.major != MAJOR || version.minor < VERSION_QUERY_MINOR {
        Err(Error::InvalidField)
    } else {
        Ok(())
    }
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
