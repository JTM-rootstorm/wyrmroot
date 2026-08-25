//! Deterministic host-side construction of the WYR0 `cpio newc` boot archive.
//!
//! This module accepts only caller-provided byte slices.  In particular, it does not traverse the
//! host filesystem or derive metadata from it.  Every record is a normalized regular file and the
//! caller's insertion order is discarded in favour of bytewise canonical-path ordering.

#![cfg(feature = "builder")]

extern crate alloc;

use alloc::vec::Vec;

use crate::limits::{MAX_ARCHIVE_BYTES, MAX_ENCODED_NAME_BYTES, MAX_RECORDS};
use crate::path::ArchivePath;

const HEADER_SIZE: usize = 110;
const TRAILER_NAME: &[u8] = b"TRAILER!!!";

/// Builds a deterministic, uncompressed `cpio newc` archive from explicit file contents.
///
/// Paths are canonical archive-relative byte paths.  The builder does not accept host paths or
/// metadata; all output records use fixed metadata and have a zero modification timestamp.
#[derive(Debug, Default)]
pub struct Builder<'a> {
    entries: Vec<BuilderEntry<'a>>,
}

#[derive(Clone, Copy, Debug)]
struct BuilderEntry<'a> {
    path: ArchivePath<'a>,
    data: &'a [u8],
    mode: FileMode,
}

impl<'a> Builder<'a> {
    /// Creates an empty archive builder.
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Adds one regular file.
    ///
    /// The path is validated immediately but no filesystem access occurs.  Duplicate paths are
    /// rejected by [`Self::build`] after canonical bytewise ordering has been established.
    pub fn add(
        &mut self,
        path: &'a [u8],
        data: &'a [u8],
        mode: FileMode,
    ) -> Result<(), BuildError> {
        if self.entries.len() == MAX_RECORDS {
            return Err(BuildError::RecordLimit);
        }
        let encoded_name_size = path.len().checked_add(1).ok_or(BuildError::NameTooLong)?;
        if encoded_name_size > MAX_ENCODED_NAME_BYTES {
            return Err(BuildError::NameTooLong);
        }
        let path = ArchivePath::new(path).map_err(|_| BuildError::InvalidPath)?;
        fallibly_reserve(&mut self.entries, 1)?;
        self.entries.push(BuilderEntry { path, data, mode });
        Ok(())
    }

    /// Encodes the complete archive, including the required `TRAILER!!!` record.
    pub fn build(&self) -> Result<Vec<u8>, BuildError> {
        let mut entries = Vec::new();
        fallibly_reserve_exact(&mut entries, self.entries.len())?;
        entries.extend_from_slice(&self.entries);
        entries.sort_unstable_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));

        let mut total = record_size(TRAILER_NAME, &[])?;
        let mut previous = None;
        for entry in &entries {
            if previous == Some(entry.path.as_bytes()) {
                return Err(BuildError::DuplicatePath);
            }
            previous = Some(entry.path.as_bytes());
            total = total
                .checked_add(record_size(entry.path.as_bytes(), entry.data)?)
                .ok_or(BuildError::ArchiveTooLarge)?;
            ensure_archive_size(total)?;
        }

        let mut output = Vec::new();
        fallibly_reserve_exact(&mut output, total)?;
        for entry in &entries {
            write_record(
                &mut output,
                entry.path.as_bytes(),
                entry.data,
                entry.mode.newc_mode(),
                0,
                1,
            )?;
        }
        write_record(&mut output, TRAILER_NAME, &[], 0, 0, 0)?;
        debug_assert_eq!(output.len(), total);
        Ok(output)
    }
}

/// Why a boot archive could not be constructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildError {
    /// A fixed WYR1 product entry had no immutable payload.
    EmptyArtifact,
    /// The supplied path was not a canonical archive-relative path.
    InvalidPath,
    /// The encoded `newc` name, including its required NUL terminator, exceeds the cap.
    NameTooLong,
    /// The archive has more regular-file records than the locked WYR0 cap permits.
    RecordLimit,
    /// Two entries have the same canonical byte path.
    DuplicatePath,
    /// A `newc` 32-bit size field or the host output buffer cannot represent the input.
    ArchiveTooLarge,
    /// A host allocation failed before encoding could start.
    AllocationFailure,
}

/// The only regular-file metadata forms permitted in a WYR0 bootfs archive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileMode {
    /// An immutable regular file with no execute bits (`0100444`).
    ReadOnly,
    /// An immutable executable regular file (`0100555`).
    Executable,
}

impl FileMode {
    const fn newc_mode(self) -> u32 {
        match self {
            Self::ReadOnly => 0o100444,
            Self::Executable => 0o100555,
        }
    }
}

fn record_size(name: &[u8], data: &[u8]) -> Result<usize, BuildError> {
    checked_u32(
        name.len()
            .checked_add(1)
            .ok_or(BuildError::ArchiveTooLarge)?,
    )?;
    checked_u32(data.len())?;
    let name_end = HEADER_SIZE
        .checked_add(name.len())
        .and_then(|value| value.checked_add(1))
        .ok_or(BuildError::ArchiveTooLarge)?;
    let data_start = align4(name_end)?;
    let data_end = data_start
        .checked_add(data.len())
        .ok_or(BuildError::ArchiveTooLarge)?;
    align4(data_end)
}

fn write_record(
    output: &mut Vec<u8>,
    name: &[u8],
    data: &[u8],
    mode: u32,
    inode: u32,
    nlink: u32,
) -> Result<(), BuildError> {
    let namesize = checked_u32(
        name.len()
            .checked_add(1)
            .ok_or(BuildError::ArchiveTooLarge)?,
    )?;
    let filesize = checked_u32(data.len())?;

    let mut header = [b'0'; HEADER_SIZE];
    header[..6].copy_from_slice(crate::NEWC_MAGIC);
    write_hex(&mut header[6..14], inode);
    write_hex(&mut header[14..22], mode);
    write_hex(&mut header[22..30], 0); // uid
    write_hex(&mut header[30..38], 0); // gid
    write_hex(&mut header[38..46], nlink);
    write_hex(&mut header[46..54], 0); // mtime
    write_hex(&mut header[54..62], filesize);
    write_hex(&mut header[62..70], 0); // device major
    write_hex(&mut header[70..78], 0); // device minor
    write_hex(&mut header[78..86], 0); // rdevice major
    write_hex(&mut header[86..94], 0); // rdevice minor
    write_hex(&mut header[94..102], namesize);
    write_hex(&mut header[102..110], 0); // `newc` check field

    output.extend_from_slice(&header);
    output.extend_from_slice(name);
    output.push(0);
    pad4(output);
    output.extend_from_slice(data);
    pad4(output);
    Ok(())
}

fn checked_u32(value: usize) -> Result<u32, BuildError> {
    u32::try_from(value).map_err(|_| BuildError::ArchiveTooLarge)
}

fn ensure_archive_size(total: usize) -> Result<(), BuildError> {
    if total > MAX_ARCHIVE_BYTES {
        return Err(BuildError::ArchiveTooLarge);
    }
    Ok(())
}

fn fallibly_reserve<T>(output: &mut Vec<T>, additional: usize) -> Result<(), BuildError> {
    output
        .try_reserve(additional)
        .map_err(|_| BuildError::AllocationFailure)
}

fn fallibly_reserve_exact<T>(output: &mut Vec<T>, additional: usize) -> Result<(), BuildError> {
    output
        .try_reserve_exact(additional)
        .map_err(|_| BuildError::AllocationFailure)
}

fn align4(value: usize) -> Result<usize, BuildError> {
    value
        .checked_add(3)
        .map(|aligned| aligned & !3)
        .ok_or(BuildError::ArchiveTooLarge)
}

fn pad4(output: &mut Vec<u8>) {
    let padding = (4 - (output.len() & 3)) & 3;
    output.extend(core::iter::repeat_n(0, padding));
}

fn write_hex(field: &mut [u8], value: u32) {
    debug_assert_eq!(field.len(), 8);
    for (index, slot) in field.iter_mut().enumerate() {
        let shift = 4 * (7 - index);
        *slot = b"0123456789abcdef"[((value >> shift) & 0x0f) as usize];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_cap_accepts_its_exact_limit_and_rejects_one_byte_more() {
        assert_eq!(ensure_archive_size(MAX_ARCHIVE_BYTES), Ok(()));
        assert_eq!(
            ensure_archive_size(MAX_ARCHIVE_BYTES + 1),
            Err(BuildError::ArchiveTooLarge)
        );
    }

    #[test]
    fn unrepresentable_allocation_requests_return_an_error() {
        let mut output = Vec::<u8>::new();
        assert_eq!(
            fallibly_reserve_exact(&mut output, usize::MAX),
            Err(BuildError::AllocationFailure)
        );
    }
}
