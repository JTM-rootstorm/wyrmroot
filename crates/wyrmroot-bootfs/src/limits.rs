//! Central WYR0 boot archive resource policy.

/// Bounded resource policy for one encoded WYR0 boot archive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootfsLimits {
    /// Maximum bytes in the entire encoded archive, including the trailer.
    pub max_archive_bytes: usize,
    /// Maximum number of non-trailer file records.
    pub max_records: usize,
    /// Maximum encoded pathname bytes, including the required NUL terminator.
    pub max_encoded_name_bytes: usize,
}

/// Locked WYR0-C archive resource limits.
pub const WYR0_LIMITS: BootfsLimits = BootfsLimits {
    max_archive_bytes: 32 * 1024 * 1024,
    max_records: 4096,
    max_encoded_name_bytes: 4096,
};

pub(crate) const MAX_ARCHIVE_BYTES: usize = WYR0_LIMITS.max_archive_bytes;
pub(crate) const MAX_RECORDS: usize = WYR0_LIMITS.max_records;
pub(crate) const MAX_ENCODED_NAME_BYTES: usize = WYR0_LIMITS.max_encoded_name_bytes;
