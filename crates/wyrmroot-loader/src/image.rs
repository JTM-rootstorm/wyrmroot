//! Checked segment and initial-stack materialization plans.

use crate::elf::{
    ElfLoadPlan, LoadSegment, PAGE_SIZE, PROGRAM_HEADER_ENTRY_BYTES, STACK_BYTES, STACK_TOP,
    SegmentProtection,
};

/// Auxiliary-vector types the loader fills (System V ABI, as Linux numbers
/// them, which is what musl reads).
pub const AT_PHDR: u64 = 3;
pub const AT_PHENT: u64 = 4;
pub const AT_PHNUM: u64 = 5;
pub const AT_PAGESZ: u64 = 6;
pub const AT_ENTRY: u64 = 9;
/// At most this many auxv entries before the terminal pair.
pub const MAX_AUXV_ENTRIES: usize = 5;

/// What a startup ABI v2 block's auxv says about the image (root
/// `TOOLCHAIN_POSIX_LAYER_DESIGN.md` request W2). `AT_RANDOM` is absent:
/// Deepwyrm offers userspace no entropy source yet, and musl copes without it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageAuxv {
    pub entry: u64,
    pub program_headers: Option<crate::elf::ProgramHeaderTable>,
}

impl ImageAuxv {
    pub fn from_plan(plan: &ElfLoadPlan<'_>) -> Self {
        Self {
            entry: plan.entry,
            program_headers: plan.program_headers,
        }
    }

    /// The entries in order: `AT_PHDR`, `AT_PHENT` and `AT_PHNUM` when the
    /// table is mapped, then `AT_PAGESZ` and `AT_ENTRY`.
    pub fn entries(&self) -> ([(u64, u64); MAX_AUXV_ENTRIES], usize) {
        let mut entries = [(0, 0); MAX_AUXV_ENTRIES];
        let mut count = 0;
        let mut push = |kind, value| {
            entries[count] = (kind, value);
            count += 1;
        };
        if let Some(table) = self.program_headers {
            push(AT_PHDR, table.address);
            push(AT_PHENT, PROGRAM_HEADER_ENTRY_BYTES);
            push(AT_PHNUM, u64::from(table.count));
        }
        push(AT_PAGESZ, PAGE_SIZE);
        push(AT_ENTRY, self.entry);
        (entries, count)
    }
}

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
    auxv: &ImageAuxv,
) -> Result<(), StartupBlockError> {
    let plan = StartupBlockV2Plan::new(block.len(), block_address, path, argv, environment, auxv)?;
    plan.write(block);
    Ok(())
}

pub(crate) struct StartupBlockV2Plan<'a> {
    block_address: u64,
    argv: &'a [&'a str],
    environment: &'a [&'a str],
    auxv: [(u64, u64); MAX_AUXV_ENTRIES],
    auxv_count: usize,
    string_start: usize,
}

impl<'a> StartupBlockV2Plan<'a> {
    pub(crate) fn new(
        block_len: usize,
        block_address: u64,
        path: &str,
        argv: &'a [&'a str],
        environment: &'a [&'a str],
        auxv: &ImageAuxv,
    ) -> Result<Self, StartupBlockError> {
        let (auxv, auxv_count) = auxv.entries();
        const MAX_ARGV: usize = 64;
        const MAX_ENVIRONMENT: usize = 64;
        const MAX_STRING_BYTES: usize = 16 * 1024;
        if block_len != STARTUP_V2_BLOCK_BYTES {
            return Err(StartupBlockError::PageSize);
        }
        if argv.is_empty() || argv.len() > MAX_ARGV {
            return Err(StartupBlockError::TooManyArguments);
        }
        if environment.len() > MAX_ENVIRONMENT {
            return Err(StartupBlockError::TooManyEnvironmentEntries);
        }
        // argv[0] is the launcher's choice (root
        // `TOOLCHAIN_POSIX_LAYER_DESIGN.md` W3); `path` names the image.
        if path.is_empty() || path.as_bytes().contains(&0) {
            return Err(if path.is_empty() {
                StartupBlockError::EmptyDisplayPath
            } else {
                StartupBlockError::DisplayPathContainsNul
            });
        }
        if argv
            .iter()
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
            .and_then(|value| value.checked_add(1 + 2 * (auxv_count + 1)))
            .ok_or(StartupBlockError::StringBytesExceeded)?;
        let string_start = vector_words
            .checked_mul(8)
            .ok_or(StartupBlockError::StringBytesExceeded)?;
        if string_start + encoded_string_bytes > block_len {
            return Err(StartupBlockError::StringBytesExceeded);
        }
        block_address
            .checked_add((string_start + encoded_string_bytes) as u64)
            .ok_or(StartupBlockError::PointerOverflow)?;
        Ok(Self {
            block_address,
            argv,
            environment,
            auxv,
            auxv_count,
            string_start,
        })
    }

    pub(crate) fn write(self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), STARTUP_V2_BLOCK_BYTES);
        block.fill(0);
        put_u64(block, 0, self.argv.len() as u64);
        let mut word_offset = 8usize;
        let mut string_offset = self.string_start;
        for value in self.argv {
            put_u64(
                block,
                word_offset,
                self.block_address + string_offset as u64,
            );
            word_offset += 8;
            block[string_offset..string_offset + value.len()].copy_from_slice(value.as_bytes());
            string_offset += value.len() + 1;
        }
        word_offset += 8;
        for value in self.environment {
            put_u64(
                block,
                word_offset,
                self.block_address + string_offset as u64,
            );
            word_offset += 8;
            block[string_offset..string_offset + value.len()].copy_from_slice(value.as_bytes());
            string_offset += value.len() + 1;
        }
        // The envp NULL stays zero, then the auxv entries; the terminal
        // pair stays zero.
        word_offset += 8;
        for &(kind, value) in &self.auxv[..self.auxv_count] {
            put_u64(block, word_offset, kind);
            put_u64(block, word_offset + 8, value);
            word_offset += 16;
        }
        debug_assert_eq!(word_offset + 16, self.string_start);
    }
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
