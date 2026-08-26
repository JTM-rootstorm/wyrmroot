//! Checked segment and initial-stack materialization plans.

use crate::elf::{LoadSegment, PAGE_SIZE, STACK_BYTES, STACK_TOP, SegmentProtection};

pub const STARTUP_ABI_VERSION: u64 = 1;
pub const STARTUP_ABI_V2: u64 = 2;
pub const STARTUP_PAGE_ADDRESS: u64 = STACK_TOP - PAGE_SIZE;
pub const INITIAL_STACK_POINTER: u64 = STARTUP_PAGE_ADDRESS;
pub const STARTUP_V2_BLOCK_BYTES: usize = 5 * PAGE_SIZE as usize;
pub const STARTUP_V2_BLOCK_ADDRESS: u64 = STACK_TOP - STARTUP_V2_BLOCK_BYTES as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaterializationPlan {
    pub object_size: u64,
    pub source_offset: u64,
    pub source_size: u64,
    pub destination_offset: u64,
    pub child_address: u64,
    pub protection: SegmentProtection,
}

impl From<LoadSegment> for MaterializationPlan {
    fn from(segment: LoadSegment) -> Self {
        Self {
            object_size: segment.mapping_size,
            source_offset: segment.file_offset,
            source_size: segment.file_size,
            destination_offset: segment.leading_bytes,
            child_address: segment.mapping_start,
            protection: segment.protection,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StackPlan {
    pub object_size: u64,
    pub child_address: u64,
    pub startup_page_offset: u64,
    pub stack_pointer: u64,
}

pub const INITIAL_STACK: StackPlan = StackPlan {
    object_size: STACK_BYTES,
    child_address: STACK_TOP - STACK_BYTES,
    startup_page_offset: STACK_BYTES - PAGE_SIZE,
    stack_pointer: INITIAL_STACK_POINTER,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupBlockError {
    PageSize,
    EmptyDisplayPath,
    DisplayPathContainsNul,
    DisplayPathTooLong,
    PointerOverflow,
    TooManyArguments,
    TooManyEnvironmentEntries,
    StringBytesExceeded,
    InvalidEnvironment,
    DuplicateEnvironment,
    Argv0Mismatch,
    StringContainsNul,
}

/// Writes the exact WYR0-D0 `argc`/`argv`/`envp`/auxv startup block.
///
/// The entire page is cleared so all unused bytes and terminators are deterministic.
pub fn write_startup_block(
    page: &mut [u8],
    page_address: u64,
    display_path: &str,
) -> Result<(), StartupBlockError> {
    const WORD_BYTES: usize = 8;
    const FIXED_WORDS: usize = 6;
    const STRING_OFFSET: usize = FIXED_WORDS * WORD_BYTES;

    if page.len() != PAGE_SIZE as usize {
        return Err(StartupBlockError::PageSize);
    }
    if display_path.is_empty() {
        return Err(StartupBlockError::EmptyDisplayPath);
    }
    if display_path.as_bytes().contains(&0) {
        return Err(StartupBlockError::DisplayPathContainsNul);
    }
    let string_end = STRING_OFFSET
        .checked_add(display_path.len())
        .and_then(|end| end.checked_add(1))
        .ok_or(StartupBlockError::DisplayPathTooLong)?;
    if string_end > page.len() {
        return Err(StartupBlockError::DisplayPathTooLong);
    }
    let argv0 = page_address
        .checked_add(STRING_OFFSET as u64)
        .ok_or(StartupBlockError::PointerOverflow)?;

    page.fill(0);
    put_u64(page, 0, 1);
    put_u64(page, 8, argv0);
    // argv[1], envp[0], and the terminal auxv (0, 0) remain zero.
    page[STRING_OFFSET..STRING_OFFSET + display_path.len()]
        .copy_from_slice(display_path.as_bytes());
    Ok(())
}

/// Writes the canonical startup ABI v2 vector/string block for a launched job.
pub fn write_startup_block_v2(
    block: &mut [u8],
    block_address: u64,
    path: &str,
    argv: &[&str],
    environment: &[&str],
) -> Result<(), StartupBlockError> {
    const MAX_ARGV: usize = 64;
    const MAX_ENVIRONMENT: usize = 64;
    const MAX_STRING_BYTES: usize = 16 * 1024;
    if block.len() != STARTUP_V2_BLOCK_BYTES {
        return Err(StartupBlockError::PageSize);
    }
    if argv.is_empty() || argv.len() > MAX_ARGV {
        return Err(StartupBlockError::TooManyArguments);
    }
    if environment.len() > MAX_ENVIRONMENT {
        return Err(StartupBlockError::TooManyEnvironmentEntries);
    }
    if argv[0] != path {
        return Err(StartupBlockError::Argv0Mismatch);
    }
    if path.is_empty() || path.as_bytes().contains(&0) {
        return Err(if path.is_empty() {
            StartupBlockError::EmptyDisplayPath
        } else {
            StartupBlockError::DisplayPathContainsNul
        });
    }
    if argv
        .iter()
        .skip(1)
        .chain(environment.iter())
        .any(|value| value.as_bytes().contains(&0))
    {
        return Err(StartupBlockError::StringContainsNul);
    }
    let aggregate_string_bytes = argv
        .iter()
        .chain(environment.iter())
        .try_fold(0usize, |sum, value| sum.checked_add(value.len()))
        .ok_or(StartupBlockError::StringBytesExceeded)?;
    if aggregate_string_bytes > MAX_STRING_BYTES {
        return Err(StartupBlockError::StringBytesExceeded);
    }
    let encoded_string_bytes = aggregate_string_bytes
        .checked_add(argv.len())
        .and_then(|value| value.checked_add(environment.len()))
        .ok_or(StartupBlockError::StringBytesExceeded)?;
    for (index, value) in environment.iter().enumerate() {
        let name = environment_name(value)?;
        if environment[..index]
            .iter()
            .any(|other| environment_name(other).ok() == Some(name))
        {
            return Err(StartupBlockError::DuplicateEnvironment);
        }
    }

    let vector_words = 1usize
        .checked_add(argv.len())
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(environment.len()))
        .and_then(|value| value.checked_add(1 + 2))
        .ok_or(StartupBlockError::StringBytesExceeded)?;
    let string_start = vector_words
        .checked_mul(8)
        .ok_or(StartupBlockError::StringBytesExceeded)?;
    if string_start + encoded_string_bytes > block.len() {
        return Err(StartupBlockError::StringBytesExceeded);
    }
    block.fill(0);
    put_u64(block, 0, argv.len() as u64);
    let mut word_offset = 8usize;
    let mut string_offset = string_start;
    for value in argv {
        put_u64(
            block,
            word_offset,
            block_address
                .checked_add(string_offset as u64)
                .ok_or(StartupBlockError::PointerOverflow)?,
        );
        word_offset += 8;
        block[string_offset..string_offset + value.len()].copy_from_slice(value.as_bytes());
        string_offset += value.len() + 1;
    }
    word_offset += 8;
    for value in environment {
        put_u64(
            block,
            word_offset,
            block_address
                .checked_add(string_offset as u64)
                .ok_or(StartupBlockError::PointerOverflow)?,
        );
        word_offset += 8;
        block[string_offset..string_offset + value.len()].copy_from_slice(value.as_bytes());
        string_offset += value.len() + 1;
    }
    // envp NULL and terminal auxv pair remain zero.
    Ok(())
}

fn environment_name(value: &str) -> Result<&str, StartupBlockError> {
    let (name, _) = value
        .split_once('=')
        .ok_or(StartupBlockError::InvalidEnvironment)?;
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 64
        || !(bytes[0].is_ascii_uppercase() || bytes[0] == b'_')
        || !bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        return Err(StartupBlockError::InvalidEnvironment);
    }
    Ok(name)
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
