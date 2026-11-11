//! WRFS 1.0: the node protocol, on a Channel to one directory or file.
//!
//! ```text
//! client -> server  OPEN (+ new node Channel)   (one-way; ON_OPEN on that Channel)
//! client -> server  GET_ATTR                    -> ATTR
//! client -> server  READ_DIR                    -> DIRENTS
//! client -> server  READ                        -> DATA
//! client -> server  WRITE                       -> STATUS (value: bytes written)
//! client -> server  TRUNCATE | UNLINK | SYNC    -> STATUS
//! client -> server  QUERY_FILESYSTEM            -> FS_INFO
//! server -> client  ON_OPEN                     (event, first on a new Channel)
//! ```
//!
//! A request that does not apply to the node (READ on a directory, UNLINK
//! on a file) is answered with STATUS and the matching error. Replies echo
//! the request's transaction; ON_OPEN echoes the OPEN's. A directory handle
//! names one filesystem: a relative OPEN on it never crosses into another
//! mount (only `vfsd`'s path opens see the mount table). Data travels inline,
//! at most [`MAX_IO_BYTES`] per message.

use crate::{
    Error, HEADER_BYTES, MAX_PATH_BYTES, Status, check_name, check_open_flags, check_relative,
    get32, get64, put32, put64, read_header, tail, write_header,
};

pub const MAGIC: [u8; 4] = *b"WRFS";
/// The most data one READ or WRITE moves.
pub const MAX_IO_BYTES: usize = 8192;
/// The most encoded directory entries one DIRENTS carries.
pub const MAX_DIRENT_BYTES: usize = 8192;
/// The largest WRFS message, for receive buffers.
pub const MAX_BYTES: usize = HEADER_BYTES + 16 + MAX_IO_BYTES;

const TYPE_OPEN: u32 = 1;
const TYPE_GET_ATTR: u32 = 2;
const TYPE_READ_DIR: u32 = 3;
const TYPE_READ: u32 = 4;
const TYPE_WRITE: u32 = 5;
const TYPE_TRUNCATE: u32 = 6;
const TYPE_UNLINK: u32 = 7;
const TYPE_SYNC: u32 = 8;
const TYPE_QUERY_FILESYSTEM: u32 = 9;
const TYPE_ON_OPEN: u32 = 16;
const TYPE_STATUS: u32 = 17;
const TYPE_ATTR: u32 = 18;
const TYPE_DIRENTS: u32 = 19;
const TYPE_DATA: u32 = 20;
const TYPE_FS_INFO: u32 = 21;

/// Attribute access bit: the handle may read or list.
pub const ACCESS_READ: u32 = 1 << 0;
/// Attribute access bit: the handle may write, or create and remove entries.
pub const ACCESS_WRITE: u32 = 1 << 1;
const ACCESS_BITS: u32 = ACCESS_READ | ACCESS_WRITE;

/// FS_INFO flag: nothing on this filesystem can be changed.
pub const FS_READ_ONLY: u32 = 1 << 0;
/// FS_INFO flag: SYNC reaches stable storage.
pub const FS_DURABLE_SYNC: u32 = 1 << 1;
/// FS_INFO flag: a file may have more than one name.
pub const FS_HARD_LINKS: u32 = 1 << 2;
/// FS_INFO flag: the filesystem stores symbolic links.
pub const FS_SYMLINKS: u32 = 1 << 3;
const FS_FLAGS: u32 = FS_READ_ONLY | FS_DURABLE_SYNC | FS_HARD_LINKS | FS_SYMLINKS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Kind {
    Directory = 1,
    File = 2,
}

impl Kind {
    fn parse(value: u32) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Directory),
            2 => Ok(Self::File),
            _ => Err(Error::InvalidField),
        }
    }
}

/// One node's attributes, as seen through one handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Attr {
    pub kind: Kind,
    /// The handle's access: a nonzero set of `ACCESS_*` bits.
    pub access: u32,
    /// Bytes, for a file; unspecified for a directory.
    pub size: u64,
    /// A filesystem-chosen identity, stable while the node is open; zero if
    /// the filesystem has none.
    pub id: u64,
}

/// What a filesystem reports about itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsInfo {
    pub flags: u32,
    /// The longest name it stores, from 1 to 255.
    pub name_max: u32,
    /// Its allocation unit: a power of two from 512 to 65536.
    pub block_size: u32,
    pub total_bytes: u64,
    /// At most `total_bytes`.
    pub free_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Body<'a> {
    /// Carries exactly one handle: the server end of the new node's Channel.
    Open {
        flags: u32,
        /// Canonical relative; empty opens this node again.
        path: &'a [u8],
    },
    GetAttr,
    /// `cookie` 0 starts a listing; later calls pass the last DIRENTS'
    /// `next_cookie`.
    ReadDir {
        cookie: u64,
    },
    /// `length` from 1 to [`MAX_IO_BYTES`].
    Read {
        offset: u64,
        length: u32,
    },
    /// 1 to [`MAX_IO_BYTES`] bytes.
    Write {
        offset: u64,
        data: &'a [u8],
    },
    Truncate {
        size: u64,
    },
    /// One name in this directory; a directory must be empty.
    Unlink {
        name: &'a [u8],
    },
    Sync,
    QueryFilesystem,
    /// `attr` is present exactly when `status` is OK.
    OnOpen {
        status: Status,
        attr: Option<Attr>,
    },
    Status {
        status: Status,
        value: u64,
    },
    Attr(Attr),
    /// Zero `next_cookie` ends the listing; an empty page always ends it.
    Dirents {
        next_cookie: u64,
        entries: Entries<'a>,
    },
    /// At most the requested length; empty at or past the end of the file.
    Data(&'a [u8]),
    FsInfo(FsInfo),
}

impl Body<'_> {
    /// Whether a client sends this message (as opposed to the server).
    pub const fn is_request(&self) -> bool {
        matches!(
            self,
            Self::Open { .. }
                | Self::GetAttr
                | Self::ReadDir { .. }
                | Self::Read { .. }
                | Self::Write { .. }
                | Self::Truncate { .. }
                | Self::Unlink { .. }
                | Self::Sync
                | Self::QueryFilesystem
        )
    }

    pub const fn wire_size(&self) -> usize {
        HEADER_BYTES
            + match self {
                Self::GetAttr | Self::Sync | Self::QueryFilesystem => 0,
                Self::ReadDir { .. } | Self::Truncate { .. } => 8,
                Self::Open { path, .. } => 8 + path.len(),
                Self::Unlink { name } => 8 + name.len(),
                Self::Data(data) => 8 + data.len(),
                Self::Read { .. } | Self::Status { .. } => 16,
                Self::Write { data, .. } => 16 + data.len(),
                Self::Dirents { entries, .. } => 16 + entries.bytes.len(),
                Self::Attr(_) => 24,
                Self::OnOpen { .. } | Self::FsInfo(_) => 32,
            }
    }

    pub const fn handle_count(&self) -> usize {
        match self {
            Self::Open { .. } => 1,
            _ => 0,
        }
    }

    const fn message_type(&self) -> u32 {
        match self {
            Self::Open { .. } => TYPE_OPEN,
            Self::GetAttr => TYPE_GET_ATTR,
            Self::ReadDir { .. } => TYPE_READ_DIR,
            Self::Read { .. } => TYPE_READ,
            Self::Write { .. } => TYPE_WRITE,
            Self::Truncate { .. } => TYPE_TRUNCATE,
            Self::Unlink { .. } => TYPE_UNLINK,
            Self::Sync => TYPE_SYNC,
            Self::QueryFilesystem => TYPE_QUERY_FILESYSTEM,
            Self::OnOpen { .. } => TYPE_ON_OPEN,
            Self::Status { .. } => TYPE_STATUS,
            Self::Attr(_) => TYPE_ATTR,
            Self::Dirents { .. } => TYPE_DIRENTS,
            Self::Data(_) => TYPE_DATA,
            Self::FsInfo(_) => TYPE_FS_INFO,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Message<'a> {
    /// Nonzero.
    pub transaction_id: u64,
    pub body: Body<'a>,
}

/// A checked run of encoded directory entries: each is a kind byte, a name
/// length byte and the name, a valid component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Entries<'a> {
    bytes: &'a [u8],
}

impl<'a> Entries<'a> {
    pub const EMPTY: Self = Self { bytes: &[] };

    /// Checks `bytes` as a run of entries.
    pub fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_DIRENT_BYTES {
            return Err(Error::WrongSize);
        }
        let mut rest = bytes;
        while let [kind, length, tail @ ..] = rest {
            Kind::parse(u32::from(*kind))?;
            let name = tail
                .get(..usize::from(*length))
                .ok_or(Error::InvalidField)?;
            check_name(name).map_err(|_| Error::InvalidField)?;
            rest = &tail[name.len()..];
        }
        if rest.is_empty() {
            Ok(Self { bytes })
        } else {
            Err(Error::InvalidField)
        }
    }

    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn iter(&self) -> impl Iterator<Item = (Kind, &'a [u8])> + 'a {
        let mut rest = self.bytes;
        core::iter::from_fn(move || {
            let [kind, length, tail @ ..] = rest else {
                return None;
            };
            let kind = if *kind == Kind::Directory as u8 {
                Kind::Directory
            } else {
                Kind::File
            };
            let (name, after) = tail.split_at(usize::from(*length));
            rest = after;
            Some((kind, name))
        })
    }
}

/// Builds a DIRENTS page in a caller buffer.
pub struct EntryWriter<'b> {
    buffer: &'b mut [u8],
    used: usize,
}

impl<'b> EntryWriter<'b> {
    /// Writes into at most [`MAX_DIRENT_BYTES`] of `buffer`.
    pub fn new(buffer: &'b mut [u8]) -> Self {
        let limit = buffer.len().min(MAX_DIRENT_BYTES);
        Self {
            buffer: &mut buffer[..limit],
            used: 0,
        }
    }

    /// Appends one entry; `false` if it does not fit or the name is invalid.
    pub fn push(&mut self, kind: Kind, name: &[u8]) -> bool {
        let end = self.used + 2 + name.len();
        if check_name(name).is_err() || end > self.buffer.len() {
            return false;
        }
        self.buffer[self.used] = kind as u8;
        self.buffer[self.used + 1] = name.len() as u8;
        self.buffer[self.used + 2..end].copy_from_slice(name);
        self.used = end;
        true
    }

    pub fn entries(&self) -> Entries<'_> {
        Entries {
            bytes: &self.buffer[..self.used],
        }
    }
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
        Body::GetAttr | Body::Sync | Body::QueryFilesystem => {}
        Body::Open { flags, path } => {
            put32(output, 32, flags);
            put32(output, 36, path.len() as u32);
            output[40..].copy_from_slice(path);
        }
        Body::ReadDir { cookie } => put64(output, 32, cookie),
        Body::Read { offset, length } => {
            put64(output, 32, offset);
            put32(output, 40, length);
        }
        Body::Write { offset, data } => {
            put64(output, 32, offset);
            put32(output, 40, data.len() as u32);
            output[48..].copy_from_slice(data);
        }
        Body::Truncate { size } => put64(output, 32, size),
        Body::Unlink { name } => {
            put32(output, 32, name.len() as u32);
            output[40..].copy_from_slice(name);
        }
        Body::OnOpen { status, attr } => {
            put32(output, 32, status as u32);
            if let Some(attr) = attr {
                put_attr(output, 40, attr);
            }
        }
        Body::Status { status, value } => {
            put32(output, 32, status as u32);
            put64(output, 40, value);
        }
        Body::Attr(attr) => put_attr(output, 32, attr),
        Body::Dirents {
            next_cookie,
            entries,
        } => {
            put64(output, 32, next_cookie);
            put32(output, 40, entries.bytes.len() as u32);
            output[48..].copy_from_slice(entries.bytes);
        }
        Body::Data(data) => {
            put32(output, 32, data.len() as u32);
            output[40..].copy_from_slice(data);
        }
        Body::FsInfo(info) => {
            put32(output, 32, info.flags);
            put32(output, 36, info.name_max);
            put32(output, 40, info.block_size);
            put64(output, 48, info.total_bytes);
            put64(output, 56, info.free_bytes);
        }
    }
    Ok(size)
}

/// Parses one datagram of `bytes` that arrived with `handle_count` handles.
pub fn parse(bytes: &[u8], handle_count: usize) -> Result<Message<'_>, Error> {
    let header = read_header(bytes, MAGIC)?;
    let fixed = |body: usize| {
        if bytes.len() == HEADER_BYTES + body {
            Ok(())
        } else {
            Err(Error::WrongSize)
        }
    };
    let zero32 = |offset: usize| {
        if get32(bytes, offset) == 0 {
            Ok(())
        } else {
            Err(Error::NonzeroReserved)
        }
    };
    let body = match header.message_type {
        TYPE_OPEN => Body::Open {
            path: tail(bytes, 8, 36, MAX_PATH_BYTES)?,
            flags: get32(bytes, 32),
        },
        TYPE_GET_ATTR => {
            fixed(0)?;
            Body::GetAttr
        }
        TYPE_READ_DIR => {
            fixed(8)?;
            Body::ReadDir {
                cookie: get64(bytes, 32),
            }
        }
        TYPE_READ => {
            fixed(16)?;
            zero32(44)?;
            Body::Read {
                offset: get64(bytes, 32),
                length: get32(bytes, 40),
            }
        }
        TYPE_WRITE => {
            let data = tail(bytes, 16, 40, MAX_IO_BYTES)?;
            zero32(44)?;
            Body::Write {
                offset: get64(bytes, 32),
                data,
            }
        }
        TYPE_TRUNCATE => {
            fixed(8)?;
            Body::Truncate {
                size: get64(bytes, 32),
            }
        }
        TYPE_UNLINK => {
            let name = tail(bytes, 8, 32, crate::MAX_NAME_BYTES)?;
            zero32(36)?;
            Body::Unlink { name }
        }
        TYPE_SYNC => {
            fixed(0)?;
            Body::Sync
        }
        TYPE_QUERY_FILESYSTEM => {
            fixed(0)?;
            Body::QueryFilesystem
        }
        TYPE_ON_OPEN => {
            fixed(32)?;
            zero32(36)?;
            let status = Status::parse(get32(bytes, 32))?;
            let attr = if status == Status::Ok {
                Some(get_attr(bytes, 40)?)
            } else if bytes[40..64].iter().all(|&byte| byte == 0) {
                None
            } else {
                return Err(Error::NonzeroReserved);
            };
            Body::OnOpen { status, attr }
        }
        TYPE_STATUS => {
            fixed(16)?;
            zero32(36)?;
            Body::Status {
                status: Status::parse(get32(bytes, 32))?,
                value: get64(bytes, 40),
            }
        }
        TYPE_ATTR => {
            fixed(24)?;
            Body::Attr(get_attr(bytes, 32)?)
        }
        TYPE_DIRENTS => {
            let entries = Entries::new(tail(bytes, 16, 40, MAX_DIRENT_BYTES)?)?;
            zero32(44)?;
            Body::Dirents {
                next_cookie: get64(bytes, 32),
                entries,
            }
        }
        TYPE_DATA => {
            let data = tail(bytes, 8, 32, MAX_IO_BYTES)?;
            zero32(36)?;
            Body::Data(data)
        }
        TYPE_FS_INFO => {
            fixed(32)?;
            zero32(44)?;
            Body::FsInfo(FsInfo {
                flags: get32(bytes, 32),
                name_max: get32(bytes, 36),
                block_size: get32(bytes, 40),
                total_bytes: get64(bytes, 48),
                free_bytes: get64(bytes, 56),
            })
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
            check_relative(path)?;
            check_open_flags(flags, path)?;
        }
        Body::Read { length, .. } => {
            if length == 0 || length as usize > MAX_IO_BYTES {
                return Err(Error::InvalidField);
            }
        }
        Body::Write { data, .. } => {
            if data.is_empty() || data.len() > MAX_IO_BYTES {
                return Err(Error::InvalidField);
            }
        }
        Body::Unlink { name } => check_name(name)?,
        Body::OnOpen { status, attr } => {
            if (status == Status::Ok) != attr.is_some() {
                return Err(Error::InvalidField);
            }
            if let Some(attr) = attr {
                check_attr(attr)?;
            }
        }
        Body::Attr(attr) => check_attr(attr)?,
        Body::Dirents {
            next_cookie,
            entries,
        } => {
            // Re-checked so that encode refuses a hand-built run too.
            Entries::new(entries.bytes)?;
            if entries.is_empty() && next_cookie != 0 {
                return Err(Error::InvalidField);
            }
        }
        Body::Data(data) => {
            if data.len() > MAX_IO_BYTES {
                return Err(Error::WrongSize);
            }
        }
        Body::FsInfo(info) => {
            if info.flags & !FS_FLAGS != 0 {
                return Err(Error::UnknownFlags);
            }
            if !(1..=crate::MAX_NAME_BYTES as u32).contains(&info.name_max)
                || !info.block_size.is_power_of_two()
                || !(512..=65536).contains(&info.block_size)
                || info.free_bytes > info.total_bytes
            {
                return Err(Error::InvalidField);
            }
        }
        Body::GetAttr
        | Body::ReadDir { .. }
        | Body::Truncate { .. }
        | Body::Sync
        | Body::QueryFilesystem
        | Body::Status { .. } => {}
    }
    Ok(())
}

fn check_attr(attr: Attr) -> Result<(), Error> {
    if attr.access == 0 || attr.access & !ACCESS_BITS != 0 {
        Err(Error::InvalidField)
    } else {
        Ok(())
    }
}

fn put_attr(output: &mut [u8], offset: usize, attr: Attr) {
    put32(output, offset, attr.kind as u32);
    put32(output, offset + 4, attr.access);
    put64(output, offset + 8, attr.size);
    put64(output, offset + 16, attr.id);
}

fn get_attr(bytes: &[u8], offset: usize) -> Result<Attr, Error> {
    Ok(Attr {
        kind: Kind::parse(get32(bytes, offset))?,
        access: get32(bytes, offset + 4),
        size: get64(bytes, offset + 8),
        id: get64(bytes, offset + 16),
    })
}
