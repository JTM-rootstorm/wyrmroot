//! Checked segment and initial-stack materialization plans.

use crate::elf::{LoadSegment, PAGE_SIZE, STACK_BYTES, STACK_TOP, SegmentProtection};

pub const STARTUP_ABI_VERSION: u64 = 1;
pub const STARTUP_PAGE_ADDRESS: u64 = STACK_TOP - PAGE_SIZE;
pub const INITIAL_STACK_POINTER: u64 = STARTUP_PAGE_ADDRESS;

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

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
