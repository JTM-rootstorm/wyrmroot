//! Canonical byte paths for the read-only WYR0 boot archive.
//!
//! A canonical archive path is a non-empty, relative sequence of non-empty
//! byte components separated by `/`. It has no allocation or normalization
//! step: any spelling that would need normalization is rejected. Archive
//! parsing remains byte-safe; callers that need native text semantics can
//! request a checked UTF-8 view.

use crate::limits::MAX_ENCODED_NAME_BYTES;

/// A validated canonical archive path.
///
/// The representation is relative, has no leading or trailing separator, and
/// stores no `.` or `..` components. It borrows the archive or caller input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchivePath<'a>(&'a [u8]);

/// Why a byte path cannot be used as a canonical archive path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchivePathError {
    EmptyPath,
    AbsolutePath,
    EmptyComponent,
    CurrentDirectoryComponent,
    ParentDirectoryComponent,
    NulByte,
    Backslash,
    PathTooLong,
    ReservedTrailerName,
}

impl<'a> ArchivePath<'a> {
    /// Validates one canonical archive path without allocating or rewriting it.
    pub fn new(bytes: &'a [u8]) -> Result<Self, ArchivePathError> {
        validate_archive_path(bytes)?;
        Ok(Self(bytes))
    }

    /// Returns the canonical archive bytes exactly as validated.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.0
    }

    /// Returns the native text view when the archive name is valid UTF-8.
    ///
    /// Invalid UTF-8 remains a valid byte-safe archive name; text callers must
    /// choose whether to reject it through this explicit conversion.
    pub fn as_utf8(self) -> Result<&'a str, core::str::Utf8Error> {
        core::str::from_utf8(self.0)
    }

    /// Compares with another path only after validating its canonical spelling.
    ///
    /// This is the tiny byte-lookup primitive for parser users that retain
    /// archive entry names as byte slices rather than `ArchivePath` values.
    pub fn matches(self, candidate: &[u8]) -> Result<bool, ArchivePathError> {
        validate_archive_path(candidate)?;
        Ok(self.0 == candidate)
    }
}

fn validate_archive_path(bytes: &[u8]) -> Result<(), ArchivePathError> {
    if bytes.is_empty() {
        return Err(ArchivePathError::EmptyPath);
    }
    if bytes.len() >= MAX_ENCODED_NAME_BYTES {
        return Err(ArchivePathError::PathTooLong);
    }
    if bytes == b"TRAILER!!!" {
        return Err(ArchivePathError::ReservedTrailerName);
    }
    if bytes[0] == b'/' {
        return Err(ArchivePathError::AbsolutePath);
    }

    let mut component_start = 0;
    for (index, byte) in bytes.iter().copied().enumerate() {
        match byte {
            0 => return Err(ArchivePathError::NulByte),
            b'\\' => return Err(ArchivePathError::Backslash),
            b'/' => {
                validate_component(&bytes[component_start..index])?;
                component_start = index + 1;
            }
            _ => {}
        }
    }
    validate_component(&bytes[component_start..])?;
    Ok(())
}

fn validate_component(component: &[u8]) -> Result<(), ArchivePathError> {
    match component {
        [] => Err(ArchivePathError::EmptyComponent),
        b"." => Err(ArchivePathError::CurrentDirectoryComponent),
        b".." => Err(ArchivePathError::ParentDirectoryComponent),
        _ => Ok(()),
    }
}
