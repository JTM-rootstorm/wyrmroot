//! WRNS 1.2: the namespace protocol, spoken to `vfsd`.
//!
//! ```text
//! client -> vfsd  OPEN (+ new node Channel)        (one-way; WRFS ON_OPEN on that Channel)
//! admin  -> vfsd  MOUNT (+ filesystem root Channel) -> STATUS
//! admin  -> vfsd  UNMOUNT                          -> STATUS
//! ```
//!
//! OPEN takes a canonical absolute path. `vfsd` picks the mount whose path
//! is the longest component-wise prefix of it and passes the open on to
//! that filesystem with the rest of the path, or serves a read-only
//! synthetic directory for a path above a mount point. MOUNT and UNMOUNT
//! are accepted only on the administrative connection; on any other they
//! are answered ACCESS_DENIED.

use crate::{
    Error, HEADER_BYTES, MAX_PATH_BYTES, Status, check_absolute, check_open_flags, get32, put32,
    read_header, tail, write_header,
};

pub const MAGIC: [u8; 4] = *b"WRNS";
/// The largest WRNS message, for receive buffers.
pub const MAX_BYTES: usize = HEADER_BYTES + 8 + MAX_PATH_BYTES;

const TYPE_OPEN: u32 = 1;
const TYPE_MOUNT: u32 = 2;
const TYPE_UNMOUNT: u32 = 3;
const TYPE_STATUS: u32 = 4;

/// MOUNT flag: `vfsd` refuses every write, create or truncate under the
/// mount with READ_ONLY, whatever the filesystem would allow.
pub const MOUNT_READ_ONLY: u32 = 1 << 0;
const MOUNT_FLAGS: u32 = MOUNT_READ_ONLY;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Body<'a> {
    /// Carries exactly one handle: the server end of the new node's Channel.
    Open {
        flags: u32,
        path: &'a [u8],
    },
    /// Carries exactly one handle: a WRFS Channel to the filesystem's root
    /// directory, on which `vfsd` only ever sends OPEN.
    Mount {
        flags: u32,
        path: &'a [u8],
    },
    Unmount {
        path: &'a [u8],
    },
    Status(Status),
}

impl Body<'_> {
    /// Whether a client sends this message (as opposed to `vfsd`).
    pub const fn is_request(&self) -> bool {
        !matches!(self, Self::Status(_))
    }

    pub const fn wire_size(&self) -> usize {
        HEADER_BYTES
            + 8
            + match self {
                Self::Open { path, .. } | Self::Mount { path, .. } | Self::Unmount { path } => {
                    path.len()
                }
                Self::Status(_) => 0,
            }
    }

    pub const fn handle_count(&self) -> usize {
        match self {
            Self::Open { .. } | Self::Mount { .. } => 1,
            _ => 0,
        }
    }

    const fn message_type(&self) -> u32 {
        match self {
            Self::Open { .. } => TYPE_OPEN,
            Self::Mount { .. } => TYPE_MOUNT,
            Self::Unmount { .. } => TYPE_UNMOUNT,
            Self::Status(_) => TYPE_STATUS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Message<'a> {
    /// Nonzero.
    pub transaction_id: u64,
    pub body: Body<'a>,
}

/// Encodes `message` into exactly `output[..wire_size]`, returning that size.
pub fn encode(message: &Message<'_>, output: &mut [u8]) -> Result<usize, Error> {
    let body = &message.body;
    let size = body.wire_size();
    let output = output.get_mut(..size).ok_or(Error::WrongSize)?;
    if message.transaction_id == 0 {
        return Err(Error::ZeroTransaction);
    }
    validate(body)?;
    write_header(
        output,
        MAGIC,
        body.message_type(),
        body.handle_count(),
        message.transaction_id,
    );
    match *body {
        Body::Open { flags, path } | Body::Mount { flags, path } => {
            put32(output, 32, flags);
            put32(output, 36, path.len() as u32);
            output[40..].copy_from_slice(path);
        }
        Body::Unmount { path } => {
            put32(output, 32, path.len() as u32);
            output[40..].copy_from_slice(path);
        }
        Body::Status(status) => put32(output, 32, status as u32),
    }
    Ok(size)
}

/// Parses one datagram of `bytes` that arrived with `handle_count` handles.
pub fn parse(bytes: &[u8], handle_count: usize) -> Result<Message<'_>, Error> {
    let header = read_header(bytes, MAGIC)?;
    let body = match header.message_type {
        TYPE_OPEN => Body::Open {
            path: tail(bytes, 8, 36, MAX_PATH_BYTES)?,
            flags: get32(bytes, 32),
        },
        TYPE_MOUNT => Body::Mount {
            path: tail(bytes, 8, 36, MAX_PATH_BYTES)?,
            flags: get32(bytes, 32),
        },
        TYPE_UNMOUNT => {
            let path = tail(bytes, 8, 32, MAX_PATH_BYTES)?;
            if get32(bytes, 36) != 0 {
                return Err(Error::NonzeroReserved);
            }
            Body::Unmount { path }
        }
        TYPE_STATUS => {
            if bytes.len() != HEADER_BYTES + 8 {
                return Err(Error::WrongSize);
            }
            if get32(bytes, 36) != 0 {
                return Err(Error::NonzeroReserved);
            }
            Body::Status(Status::parse(get32(bytes, 32))?)
        }
        _ => return Err(Error::UnknownMessage),
    };
    if header.handle_count != body.handle_count() || handle_count != header.handle_count {
        return Err(Error::WrongHandleCount);
    }
    validate(&body)?;
    Ok(Message {
        transaction_id: header.transaction_id,
        body,
    })
}

fn validate(body: &Body<'_>) -> Result<(), Error> {
    match *body {
        Body::Open { flags, path } => {
            check_absolute(path)?;
            check_open_flags(flags, path_below_root(path))
        }
        Body::Mount { flags, path } => {
            check_absolute(path)?;
            if flags & !MOUNT_FLAGS == 0 {
                Ok(())
            } else {
                Err(Error::UnknownFlags)
            }
        }
        Body::Unmount { path } => check_absolute(path),
        Body::Status(_) => Ok(()),
    }
}

/// The path without its leading slash, as the flag rules see it: CREATE of
/// `/` itself is refused like CREATE of an empty relative path.
fn path_below_root(path: &[u8]) -> &[u8] {
    &path[1..]
}
