//! Zero-copy parser for the WYR0 uncompressed `cpio newc` bootstrap archive.

use super::path::{ArchivePath, ArchivePathError};

const HEADER_SIZE: usize = 110;
const TRAILER_NAME: &[u8] = b"TRAILER!!!";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Archive<'a> {
    bytes: &'a [u8],
}

impl<'a> Archive<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self, ParseError> {
        check_archive_length(bytes.len())?;
        let mut cursor = 0;
        let mut previous_name = None;
        let mut record_count = 0usize;
        loop {
            let record = parse_record(bytes, cursor)?;
            cursor = record.next;
            record_count += 1;
            if !record.is_trailer && record_count > crate::limits::MAX_RECORDS {
                return Err(ParseError::TooManyRecords {
                    offset: record.start,
                });
            }
            if record.is_trailer {
                if cursor != bytes.len() {
                    return Err(ParseError::TrailingBytes { offset: cursor });
                }
                break;
            }
            if let Some(previous) = previous_name {
                match record.name.cmp(previous) {
                    core::cmp::Ordering::Equal => {
                        return Err(ParseError::DuplicateName {
                            offset: record.start,
                        });
                    }
                    core::cmp::Ordering::Less => {
                        return Err(ParseError::UnsortedName {
                            offset: record.start,
                        });
                    }
                    core::cmp::Ordering::Greater => {}
                }
            }
            previous_name = Some(record.name);
        }
        Ok(Self { bytes })
    }

    pub fn entries(self) -> Entries<'a> {
        Entries {
            bytes: self.bytes,
            cursor: 0,
        }
    }

    /// Find an entry by a canonical relative byte path.
    pub fn lookup(&self, query: &[u8]) -> Result<Entry<'a>, LookupError> {
        let canonical_query = ArchivePath::new(query).map_err(LookupError::InvalidPath)?;
        for entry in self.entries() {
            if entry.name == canonical_query.as_bytes() {
                return Ok(entry);
            }
        }
        Err(LookupError::NotFound)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Entry<'a> {
    name: &'a [u8],
    data: &'a [u8],
    path: ArchivePath<'a>,
    executable: bool,
}

impl<'a> Entry<'a> {
    pub const fn name(&self) -> &'a [u8] {
        self.name
    }

    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Return the entry name as native UTF-8 text when valid.
    pub fn name_utf8(&self) -> Result<&'a str, core::str::Utf8Error> {
        self.path.as_utf8()
    }

    /// Whether this immutable regular file has executable permission.
    pub const fn is_executable(&self) -> bool {
        self.executable
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Entries<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Iterator for Entries<'a> {
    type Item = Entry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let record = parse_record(self.bytes, self.cursor).ok()?;
        self.cursor = record.next;
        if record.is_trailer {
            None
        } else {
            Some(Entry {
                name: record.name,
                data: record.data,
                path: record.path?,
                executable: record.executable,
            })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Record<'a> {
    start: usize,
    next: usize,
    name: &'a [u8],
    data: &'a [u8],
    path: Option<ArchivePath<'a>>,
    executable: bool,
    is_trailer: bool,
}

fn parse_record(bytes: &[u8], start: usize) -> Result<Record<'_>, ParseError> {
    let header = bytes
        .get(start..)
        .ok_or(ParseError::TruncatedHeader { offset: start })?;
    if header.len() < HEADER_SIZE {
        return Err(ParseError::TruncatedHeader { offset: start });
    }
    if &header[..6] != crate::NEWC_MAGIC {
        return Err(ParseError::InvalidMagic { offset: start });
    }

    let ino = hex_field(&header[6..14], start + 6)?;
    let mode = hex_field(&header[14..22], start + 14)?;
    let uid = hex_field(&header[22..30], start + 22)?;
    let gid = hex_field(&header[30..38], start + 30)?;
    let nlink = hex_field(&header[38..46], start + 38)?;
    let mtime = hex_field(&header[46..54], start + 46)?;
    let filesize = hex_field(&header[54..62], start + 54)?;
    let devmajor = hex_field(&header[62..70], start + 62)?;
    let devminor = hex_field(&header[70..78], start + 70)?;
    let rdevmajor = hex_field(&header[78..86], start + 78)?;
    let rdevminor = hex_field(&header[86..94], start + 86)?;
    let namesize = hex_field(&header[94..102], start + 94)?;
    let check = hex_field(&header[102..110], start + 102)?;
    let namesize =
        usize::try_from(namesize).map_err(|_| ParseError::SizeOverflow { offset: start + 94 })?;
    if namesize > crate::limits::MAX_ENCODED_NAME_BYTES {
        return Err(ParseError::NameTooLarge { offset: start + 94 });
    }
    if namesize == 0 {
        return Err(ParseError::InvalidNameSize { offset: start + 94 });
    }
    let name_start = start
        .checked_add(HEADER_SIZE)
        .ok_or(ParseError::SizeOverflow { offset: start })?;
    let name_end = name_start
        .checked_add(namesize)
        .ok_or(ParseError::SizeOverflow { offset: start + 94 })?;
    let name_with_nul = bytes
        .get(name_start..name_end)
        .ok_or(ParseError::TruncatedName { offset: name_start })?;
    if name_with_nul.last() != Some(&0) || name_with_nul[..name_with_nul.len() - 1].contains(&0) {
        return Err(ParseError::InvalidName { offset: name_start });
    }
    let name = &name_with_nul[..name_with_nul.len() - 1];
    let data_start = align4(name_end).ok_or(ParseError::SizeOverflow { offset: name_end })?;
    if bytes
        .get(name_end..data_start)
        .ok_or(ParseError::TruncatedPadding { offset: name_end })?
        .iter()
        .any(|&byte| byte != 0)
    {
        return Err(ParseError::InvalidPadding { offset: name_end });
    }
    let filesize =
        usize::try_from(filesize).map_err(|_| ParseError::SizeOverflow { offset: start + 54 })?;
    let data_end = data_start
        .checked_add(filesize)
        .ok_or(ParseError::SizeOverflow { offset: data_start })?;
    let data = bytes
        .get(data_start..data_end)
        .ok_or(ParseError::TruncatedData { offset: data_start })?;
    let next = align4(data_end).ok_or(ParseError::SizeOverflow { offset: data_end })?;
    if next > bytes.len() {
        return Err(ParseError::TruncatedPadding { offset: data_end });
    }
    if bytes[data_end..next].iter().any(|&byte| byte != 0) {
        return Err(ParseError::InvalidPadding { offset: data_end });
    }

    let is_trailer = name == TRAILER_NAME;
    if is_trailer {
        if ino != 0
            || mode != 0
            || uid != 0
            || gid != 0
            || nlink != 0
            || mtime != 0
            || filesize != 0
            || devmajor != 0
            || devminor != 0
            || rdevmajor != 0
            || rdevminor != 0
            || check != 0
        {
            return Err(ParseError::InvalidTrailer { offset: start });
        }
        return Ok(Record {
            start,
            next,
            name,
            data,
            path: None,
            executable: false,
            is_trailer: true,
        });
    }

    if ino != 0
        || uid != 0
        || gid != 0
        || mtime != 0
        || devmajor != 0
        || devminor != 0
        || rdevmajor != 0
        || rdevminor != 0
        || check != 0
        || nlink != 1
    {
        return Err(ParseError::InvalidMetadata { offset: start });
    }
    if mode & 0o170000 != 0o100000 {
        return Err(ParseError::UnsupportedFileType { offset: start });
    }
    let executable = match mode {
        0o100444 => false,
        0o100555 => true,
        _ => {
            return Err(ParseError::UnsupportedPermissions { offset: start });
        }
    };
    let path = ArchivePath::new(name).map_err(|_| ParseError::InvalidPath { offset: start })?;
    Ok(Record {
        start,
        next,
        name,
        data,
        path: Some(path),
        executable,
        is_trailer: false,
    })
}

fn check_archive_length(byte_len: usize) -> Result<(), ParseError> {
    if byte_len > crate::limits::MAX_ARCHIVE_BYTES {
        Err(ParseError::ArchiveTooLarge {
            offset: crate::limits::MAX_ARCHIVE_BYTES,
        })
    } else {
        Ok(())
    }
}

fn align4(value: usize) -> Option<usize> {
    value.checked_add(3).map(|aligned| aligned & !3)
}

fn hex_field(field: &[u8], offset: usize) -> Result<u64, ParseError> {
    let mut value = 0u64;
    for &byte in field {
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'a'..=b'f' => u64::from(byte - b'a' + 10),
            b'A'..=b'F' => u64::from(byte - b'A' + 10),
            _ => return Err(ParseError::InvalidNumeric { offset }),
        };
        value = value
            .checked_mul(16)
            .and_then(|current| current.checked_add(digit))
            .ok_or(ParseError::SizeOverflow { offset })?;
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    TruncatedHeader { offset: usize },
    InvalidMagic { offset: usize },
    InvalidNumeric { offset: usize },
    SizeOverflow { offset: usize },
    InvalidNameSize { offset: usize },
    TruncatedName { offset: usize },
    InvalidName { offset: usize },
    TruncatedData { offset: usize },
    TruncatedPadding { offset: usize },
    InvalidPadding { offset: usize },
    InvalidTrailer { offset: usize },
    DuplicateName { offset: usize },
    UnsortedName { offset: usize },
    InvalidMetadata { offset: usize },
    UnsupportedFileType { offset: usize },
    UnsupportedPermissions { offset: usize },
    InvalidPath { offset: usize },
    ArchiveTooLarge { offset: usize },
    TooManyRecords { offset: usize },
    NameTooLarge { offset: usize },
    TrailingBytes { offset: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LookupError {
    InvalidPath(ArchivePathError),
    NotFound,
}

#[cfg(test)]
mod tests {
    use super::{ParseError, check_archive_length};
    use crate::WYR0_LIMITS;

    #[test]
    fn archive_length_cap_accepts_exactly_the_limit_and_rejects_one_more() {
        assert_eq!(check_archive_length(WYR0_LIMITS.max_archive_bytes), Ok(()));
        assert_eq!(
            check_archive_length(WYR0_LIMITS.max_archive_bytes + 1),
            Err(ParseError::ArchiveTooLarge {
                offset: WYR0_LIMITS.max_archive_bytes,
            })
        );
    }
}
