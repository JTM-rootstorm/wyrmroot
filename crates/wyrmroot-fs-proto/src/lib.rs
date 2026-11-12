//! The VFS protocols (root `STORAGE_PLAN.md` W5).
//!
//! Two protocols share one header layout, one status set and one path
//! grammar:
//!
//! - [`node`] (`WRFS` 1.2) is spoken on a Channel to one opened directory or
//!   file. A filesystem service serves it, and so does `vfsd` for the
//!   synthetic directories above its mount points.
//! - [`namespace`] (`WRNS` 1.2, unchanged from 1.0 but for the shared header's version) is spoken to `vfsd`: OPEN of an absolute
//!   path through the mount table, and MOUNT/UNMOUNT on the administrative
//!   connection.
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
//! entries) carry an explicit length that must match the total size. Every
//! field is checked; unknown types and flags, nonzero reserved fields and
//! wrong sizes or handle counts are refused. The size is checked before any
//! body field is read.
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
pub const MINOR: u16 = 2;
pub const HEADER_BYTES: usize = 32;
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
    message_type: u32,
    handle_count: usize,
    transaction_id: u64,
}

fn write_header(
    output: &mut [u8],
    magic: [u8; 4],
    message_type: u32,
    handle_count: usize,
    transaction_id: u64,
) {
    output.fill(0);
    output[..4].copy_from_slice(&magic);
    output[4..6].copy_from_slice(&MAJOR.to_le_bytes());
    output[6..8].copy_from_slice(&MINOR.to_le_bytes());
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
    if get16(bytes, 4) != MAJOR || get16(bytes, 6) != MINOR {
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
        message_type: get32(bytes, 8),
        handle_count: get32(bytes, 16) as usize,
        transaction_id,
    })
}

/// A variable tail of `fixed` bytes of body followed by `length` bytes,
/// where `length` is the u32 at `length_at`; checks it fills the message.
fn tail(bytes: &[u8], fixed: usize, length_at: usize, max: usize) -> Result<&[u8], Error> {
    let start = HEADER_BYTES + fixed;
    if bytes.len() < start {
        return Err(Error::WrongSize);
    }
    let length = get32(bytes, length_at) as usize;
    if length > max || bytes.len() != start + length {
        return Err(Error::WrongSize);
    }
    Ok(&bytes[start..])
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
