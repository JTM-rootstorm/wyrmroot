//! Bounded hostile-input parser for the WYR0 static native ELF subset.

pub const PAGE_SIZE: u64 = 4096;
pub const MAX_ELF_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PROGRAM_HEADERS: usize = 16;
pub const MAX_LOAD_SEGMENTS: usize = 8;
/// PT_LOAD segments any image loaded with JobV2 startup may have: shell jobs
/// and the JobV2 services (bootstrap service, registry and launch clients,
/// wyrmsh). Deepwyrm's production geometry budgets each such image this many
/// MemoryObjects plus its stack (`JOB_IMAGE_OBJECTS`, `RESIDENT_IMAGE_OBJECTS`),
/// and init creates those objects, so the loader enforces the bound rather
/// than the job's TaskGroup limits. Raising it means raising both there.
pub const MAX_JOB_LOAD_SEGMENTS: usize = 2;
pub const MAX_MAPPED_IMAGE_BYTES: u64 = 32 * 1024 * 1024;
pub const USER_END_EXCLUSIVE: u64 = 0x0000_8000_0000_0000;
pub const STACK_TOP: u64 = 0x0000_7fff_ffff_0000;
pub const STACK_BYTES: u64 = 128 * 1024;
pub const STACK_GUARD_BYTES: u64 = PAGE_SIZE;
pub const STACK_BOTTOM: u64 = STACK_TOP - STACK_BYTES;
pub const STACK_GUARD_START: u64 = STACK_BOTTOM - STACK_GUARD_BYTES;

const ELF_HEADER_BYTES: usize = 64;
const PROGRAM_HEADER_BYTES: usize = 56;
const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;
const EV_CURRENT: u32 = 1;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_NOTE: u32 = 4;
const PT_PHDR: u32 = 6;
const PT_TLS: u32 = 7;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const PF_RW: u32 = PF_R | PF_W;
const PF_RX: u32 = PF_R | PF_X;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SegmentProtection {
    Read,
    ReadWrite,
    ReadExecute,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadSegment {
    pub header_index: u16,
    pub file_offset: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub virtual_address: u64,
    pub mapping_start: u64,
    pub mapping_size: u64,
    pub leading_bytes: u64,
    pub protection: SegmentProtection,
}

impl LoadSegment {
    pub const fn memory_end(self) -> u64 {
        self.virtual_address + self.memory_size
    }

    pub const fn mapping_end(self) -> u64 {
        self.mapping_start + self.mapping_size
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ElfLoadPlan<'segments> {
    pub entry: u64,
    pub segments: &'segments [LoadSegment],
    pub mapped_bytes: u64,
    /// The program-header table's child address, when a `PT_LOAD` maps it
    /// from the file (`AT_PHDR`), and its entry count (`AT_PHNUM`).
    pub program_headers: Option<ProgramHeaderTable>,
    /// The static TLS template, when the image has one. The loader only
    /// checks it; the program's own startup builds the TLS block from it.
    pub tls: Option<TlsTemplate>,
}

/// Where the child finds its own program headers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgramHeaderTable {
    pub address: u64,
    pub count: u16,
}

/// A checked `PT_TLS` record: the initialization image lies wholly inside a
/// `PT_LOAD`'s file-backed bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsTemplate {
    pub address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub alignment: u64,
}

/// The ELF64 program-header entry size (`AT_PHENT`).
pub const PROGRAM_HEADER_ENTRY_BYTES: u64 = PROGRAM_HEADER_BYTES as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfError {
    ImageSize,
    HeaderTruncated,
    BadMagic,
    UnsupportedClass(u8),
    UnsupportedDataEncoding(u8),
    UnsupportedIdentVersion(u8),
    UnsupportedOsAbi(u8),
    UnsupportedAbiVersion(u8),
    UnsupportedElfType(u16),
    UnsupportedMachine(u16),
    UnsupportedElfVersion(u32),
    UnsupportedElfFlags(u32),
    InvalidElfHeaderSize(u16),
    InvalidProgramHeaderSize(u16),
    MissingProgramHeaders,
    TooManyProgramHeaders(usize),
    ProgramHeaderTableOverflow,
    ProgramHeaderTableTruncated,
    ProgramHeaderTableOverlapsElfHeader,
    ProgramHeaderTableMisaligned,
    UnsupportedProgramHeaderType {
        index: u16,
        header_type: u32,
    },
    DuplicateProgramHeaderType(u32),
    UnknownSegmentFlags {
        index: u16,
        flags: u32,
    },
    InvalidStackHeader {
        index: u16,
    },
    InvalidPhdrHeader {
        index: u16,
    },
    /// A `PT_TLS` record with wrong flags, sizes or alignment, or whose
    /// initialization image no `PT_LOAD` maps from the file.
    InvalidTlsHeader {
        index: u16,
    },
    TooManyLoadSegments(usize),
    OutputTooSmall {
        required: usize,
        supplied: usize,
    },
    EmptyLoadSegment {
        index: u16,
    },
    FileSizeExceedsMemorySize {
        index: u16,
    },
    SegmentFileRangeOverflow {
        index: u16,
    },
    SegmentFileRangeTruncated {
        index: u16,
    },
    SegmentVirtualRangeOverflow {
        index: u16,
    },
    SegmentMappingRangeOverflow {
        index: u16,
    },
    InvalidSegmentAlignment {
        index: u16,
        alignment: u64,
    },
    SegmentAlignmentBelowPolicy {
        index: u16,
        alignment: u64,
    },
    SegmentAddressAlignmentMismatch {
        index: u16,
    },
    SegmentVirtualRangeOutsidePolicy {
        index: u16,
    },
    SegmentOverlapsInitialStack {
        index: u16,
    },
    WritableExecutableSegment {
        index: u16,
    },
    UnsupportedSegmentProtection {
        index: u16,
        flags: u32,
    },
    OverlappingVirtualSegments {
        first: u16,
        second: u16,
    },
    OverlappingVirtualMappingRanges {
        first: u16,
        second: u16,
    },
    MappedImageLimit,
    ZeroEntryPoint,
    EntryPointOutsideExecutableSegment,
}

#[derive(Clone, Copy)]
struct Header {
    entry: u64,
    program_offset: usize,
    program_count: usize,
}

pub fn required_segment_count(image: &[u8]) -> Result<usize, ElfError> {
    let header = parse_header(image)?;
    let mut count = 0_usize;
    let mut saw_phdr = false;
    let mut saw_stack = false;
    let mut saw_tls = false;
    for index in 0..header.program_count {
        let ph = program_header(image, header, index)?;
        let header_type = get_u32(ph, 0);
        match header_type {
            PT_LOAD => {
                count += 1;
                if count > MAX_LOAD_SEGMENTS {
                    return Err(ElfError::TooManyLoadSegments(count));
                }
            }
            PT_PHDR => {
                if saw_phdr {
                    return Err(ElfError::DuplicateProgramHeaderType(PT_PHDR));
                }
                validate_phdr_header(ph, header, index as u16, image.len())?;
                saw_phdr = true;
            }
            PT_GNU_STACK => {
                if saw_stack {
                    return Err(ElfError::DuplicateProgramHeaderType(PT_GNU_STACK));
                }
                validate_stack_header(ph, index as u16)?;
                saw_stack = true;
            }
            PT_TLS => {
                if saw_tls {
                    return Err(ElfError::DuplicateProgramHeaderType(PT_TLS));
                }
                validate_tls_header(ph, index as u16)?;
                saw_tls = true;
            }
            PT_INTERP | PT_DYNAMIC | PT_NOTE | PT_GNU_RELRO => {
                return Err(ElfError::UnsupportedProgramHeaderType {
                    index: index as u16,
                    header_type,
                });
            }
            _ => {
                return Err(ElfError::UnsupportedProgramHeaderType {
                    index: index as u16,
                    header_type,
                });
            }
        }
    }
    if count == 0 {
        return Err(ElfError::MissingProgramHeaders);
    }
    Ok(count)
}

pub fn plan<'segments>(
    image: &[u8],
    output: &'segments mut [LoadSegment],
) -> Result<ElfLoadPlan<'segments>, ElfError> {
    let required = required_segment_count(image)?;
    if output.len() < required {
        return Err(ElfError::OutputTooSmall {
            required,
            supplied: output.len(),
        });
    }
    let header = parse_header(image)?;
    let mut len = 0_usize;
    let mut mapped_bytes = 0_u64;
    for index in 0..header.program_count {
        let ph = program_header(image, header, index)?;
        if get_u32(ph, 0) != PT_LOAD {
            continue;
        }
        let segment = parse_load_segment(image, ph, index as u16)?;
        mapped_bytes = mapped_bytes
            .checked_add(segment.mapping_size)
            .ok_or(ElfError::MappedImageLimit)?;
        if mapped_bytes > MAX_MAPPED_IMAGE_BYTES {
            return Err(ElfError::MappedImageLimit);
        }
        output[len] = segment;
        len += 1;
    }
    output[..len].sort_unstable_by_key(|segment| (segment.mapping_start, segment.header_index));
    validate_nonoverlap(&output[..len])?;
    if header.entry == 0 {
        return Err(ElfError::ZeroEntryPoint);
    }
    if !output[..len].iter().any(|segment| {
        segment.protection == SegmentProtection::ReadExecute
            && header.entry >= segment.virtual_address
            && header.entry < segment.memory_end()
    }) {
        return Err(ElfError::EntryPointOutsideExecutableSegment);
    }
    let segments = &output[..len];
    let mut program_headers = None;
    let mut tls = None;
    let table_offset = header.program_offset as u64;
    let table_bytes = (header.program_count * PROGRAM_HEADER_BYTES) as u64;
    for index in 0..header.program_count {
        let ph = program_header(image, header, index)?;
        match get_u32(ph, 0) {
            PT_PHDR => {
                // The record must name exactly where a PT_LOAD maps the table.
                let address = get_u64(ph, 16);
                if file_backed_address(segments, table_offset, table_bytes) != Some(address) {
                    return Err(ElfError::InvalidPhdrHeader {
                        index: index as u16,
                    });
                }
            }
            PT_TLS => {
                let template = TlsTemplate {
                    address: get_u64(ph, 16),
                    file_size: get_u64(ph, 32),
                    memory_size: get_u64(ph, 40),
                    alignment: get_u64(ph, 48),
                };
                if template.file_size != 0
                    && file_backed_address(segments, get_u64(ph, 8), template.file_size)
                        != Some(template.address)
                {
                    return Err(ElfError::InvalidTlsHeader {
                        index: index as u16,
                    });
                }
                tls = Some(template);
            }
            _ => {}
        }
    }
    if let Some(address) = file_backed_address(segments, table_offset, table_bytes) {
        program_headers = Some(ProgramHeaderTable {
            address,
            count: header.program_count as u16,
        });
    }
    Ok(ElfLoadPlan {
        entry: header.entry,
        segments,
        mapped_bytes,
        program_headers,
        tls,
    })
}

/// The child address of file bytes `[offset, offset + length)` when one
/// `PT_LOAD` maps all of them from the file (not from its zero-filled tail).
fn file_backed_address(segments: &[LoadSegment], offset: u64, length: u64) -> Option<u64> {
    let end = offset.checked_add(length)?;
    segments.iter().find_map(|segment| {
        let segment_end = segment.file_offset.checked_add(segment.file_size)?;
        (offset >= segment.file_offset && end <= segment_end)
            .then(|| segment.virtual_address + (offset - segment.file_offset))
    })
}

fn parse_header(image: &[u8]) -> Result<Header, ElfError> {
    if image.is_empty() || image.len() > MAX_ELF_BYTES {
        return Err(ElfError::ImageSize);
    }
    let bytes = image
        .get(..ELF_HEADER_BYTES)
        .ok_or(ElfError::HeaderTruncated)?;
    if &bytes[..4] != b"\x7fELF" {
        return Err(ElfError::BadMagic);
    }
    if bytes[4] != 2 {
        return Err(ElfError::UnsupportedClass(bytes[4]));
    }
    if bytes[5] != 1 {
        return Err(ElfError::UnsupportedDataEncoding(bytes[5]));
    }
    if bytes[6] != 1 {
        return Err(ElfError::UnsupportedIdentVersion(bytes[6]));
    }
    if bytes[7] != 0 {
        return Err(ElfError::UnsupportedOsAbi(bytes[7]));
    }
    if bytes[8] != 0 {
        return Err(ElfError::UnsupportedAbiVersion(bytes[8]));
    }
    let elf_type = get_u16(bytes, 16);
    if elf_type != ET_EXEC {
        return Err(ElfError::UnsupportedElfType(elf_type));
    }
    let machine = get_u16(bytes, 18);
    if machine != EM_X86_64 {
        return Err(ElfError::UnsupportedMachine(machine));
    }
    let version = get_u32(bytes, 20);
    if version != EV_CURRENT {
        return Err(ElfError::UnsupportedElfVersion(version));
    }
    let flags = get_u32(bytes, 48);
    if flags != 0 {
        return Err(ElfError::UnsupportedElfFlags(flags));
    }
    let header_size = get_u16(bytes, 52);
    if usize::from(header_size) != ELF_HEADER_BYTES {
        return Err(ElfError::InvalidElfHeaderSize(header_size));
    }
    let program_size = get_u16(bytes, 54);
    if usize::from(program_size) != PROGRAM_HEADER_BYTES {
        return Err(ElfError::InvalidProgramHeaderSize(program_size));
    }
    let program_count = usize::from(get_u16(bytes, 56));
    if program_count == 0 {
        return Err(ElfError::MissingProgramHeaders);
    }
    if program_count > MAX_PROGRAM_HEADERS {
        return Err(ElfError::TooManyProgramHeaders(program_count));
    }
    let program_offset =
        usize::try_from(get_u64(bytes, 32)).map_err(|_| ElfError::ProgramHeaderTableOverflow)?;
    if program_offset < ELF_HEADER_BYTES {
        return Err(ElfError::ProgramHeaderTableOverlapsElfHeader);
    }
    if program_offset & 7 != 0 {
        return Err(ElfError::ProgramHeaderTableMisaligned);
    }
    let table_bytes = program_count
        .checked_mul(PROGRAM_HEADER_BYTES)
        .ok_or(ElfError::ProgramHeaderTableOverflow)?;
    let table_end = program_offset
        .checked_add(table_bytes)
        .ok_or(ElfError::ProgramHeaderTableOverflow)?;
    if table_end > image.len() {
        return Err(ElfError::ProgramHeaderTableTruncated);
    }
    Ok(Header {
        entry: get_u64(bytes, 24),
        program_offset,
        program_count,
    })
}

fn program_header(image: &[u8], header: Header, index: usize) -> Result<&[u8], ElfError> {
    let start = header
        .program_offset
        .checked_add(
            index
                .checked_mul(PROGRAM_HEADER_BYTES)
                .ok_or(ElfError::ProgramHeaderTableOverflow)?,
        )
        .ok_or(ElfError::ProgramHeaderTableOverflow)?;
    image
        .get(start..start + PROGRAM_HEADER_BYTES)
        .ok_or(ElfError::ProgramHeaderTableTruncated)
}

fn parse_load_segment(image: &[u8], ph: &[u8], index: u16) -> Result<LoadSegment, ElfError> {
    let flags = get_u32(ph, 4);
    if flags & !(PF_R | PF_W | PF_X) != 0 {
        return Err(ElfError::UnknownSegmentFlags { index, flags });
    }
    if flags & PF_W != 0 && flags & PF_X != 0 {
        return Err(ElfError::WritableExecutableSegment { index });
    }
    let protection = match flags {
        PF_R => SegmentProtection::Read,
        PF_RW => SegmentProtection::ReadWrite,
        PF_RX => SegmentProtection::ReadExecute,
        _ => return Err(ElfError::UnsupportedSegmentProtection { index, flags }),
    };
    let file_offset = get_u64(ph, 8);
    let virtual_address = get_u64(ph, 16);
    let file_size = get_u64(ph, 32);
    let memory_size = get_u64(ph, 40);
    let alignment = get_u64(ph, 48);
    if memory_size == 0 {
        return Err(ElfError::EmptyLoadSegment { index });
    }
    if file_size > memory_size {
        return Err(ElfError::FileSizeExceedsMemorySize { index });
    }
    let file_end = file_offset
        .checked_add(file_size)
        .ok_or(ElfError::SegmentFileRangeOverflow { index })?;
    if file_end > image.len() as u64 {
        return Err(ElfError::SegmentFileRangeTruncated { index });
    }
    let memory_end = virtual_address
        .checked_add(memory_size)
        .ok_or(ElfError::SegmentVirtualRangeOverflow { index })?;
    if !alignment.is_power_of_two() {
        return Err(ElfError::InvalidSegmentAlignment { index, alignment });
    }
    if alignment < PAGE_SIZE {
        return Err(ElfError::SegmentAlignmentBelowPolicy { index, alignment });
    }
    if file_offset & (alignment - 1) != virtual_address & (alignment - 1) {
        return Err(ElfError::SegmentAddressAlignmentMismatch { index });
    }
    let mapping_start = virtual_address & !(PAGE_SIZE - 1);
    let mapping_end =
        align_up(memory_end, PAGE_SIZE).ok_or(ElfError::SegmentMappingRangeOverflow { index })?;
    let mapping_size = mapping_end
        .checked_sub(mapping_start)
        .ok_or(ElfError::SegmentMappingRangeOverflow { index })?;
    if mapping_start < PAGE_SIZE || mapping_end > USER_END_EXCLUSIVE {
        return Err(ElfError::SegmentVirtualRangeOutsidePolicy { index });
    }
    if mapping_start < STACK_TOP && STACK_GUARD_START < mapping_end {
        return Err(ElfError::SegmentOverlapsInitialStack { index });
    }
    Ok(LoadSegment {
        header_index: index,
        file_offset,
        file_size,
        memory_size,
        virtual_address,
        mapping_start,
        mapping_size,
        leading_bytes: virtual_address - mapping_start,
        protection,
    })
}

fn validate_nonoverlap(segments: &[LoadSegment]) -> Result<(), ElfError> {
    for pair in segments.windows(2) {
        let first = pair[0];
        let second = pair[1];
        if second.virtual_address < first.memory_end() {
            return Err(ElfError::OverlappingVirtualSegments {
                first: first.header_index,
                second: second.header_index,
            });
        }
        if second.mapping_start < first.mapping_end() {
            return Err(ElfError::OverlappingVirtualMappingRanges {
                first: first.header_index,
                second: second.header_index,
            });
        }
    }
    Ok(())
}

fn validate_stack_header(ph: &[u8], index: u16) -> Result<(), ElfError> {
    if get_u32(ph, 4) != PF_R | PF_W
        || get_u64(ph, 8) != 0
        || get_u64(ph, 16) != 0
        || get_u64(ph, 24) != 0
        || get_u64(ph, 32) != 0
        || get_u64(ph, 40) != 0
    {
        return Err(ElfError::InvalidStackHeader { index });
    }
    Ok(())
}

/// A `PT_TLS` record on its own: read-only, `filesz <= memsz`, a power-of-two
/// alignment no larger than a page (0 means 1), and no address overflow.
/// Whether a `PT_LOAD` maps its image is checked once the segments are known.
fn validate_tls_header(ph: &[u8], index: u16) -> Result<(), ElfError> {
    let address = get_u64(ph, 16);
    let file_size = get_u64(ph, 32);
    let memory_size = get_u64(ph, 40);
    let alignment = get_u64(ph, 48);
    if get_u32(ph, 4) != PF_R
        || file_size > memory_size
        || memory_size > MAX_MAPPED_IMAGE_BYTES
        || (alignment != 0 && !alignment.is_power_of_two())
        || alignment > PAGE_SIZE
        || address
            .checked_add(memory_size)
            .is_none_or(|end| end > USER_END_EXCLUSIVE)
    {
        return Err(ElfError::InvalidTlsHeader { index });
    }
    Ok(())
}

fn validate_phdr_header(
    ph: &[u8],
    header: Header,
    index: u16,
    image_len: usize,
) -> Result<(), ElfError> {
    let table_bytes = header.program_count * PROGRAM_HEADER_BYTES;
    let expected_offset = header.program_offset as u64;
    let expected_size = table_bytes as u64;
    let file_end = expected_offset
        .checked_add(expected_size)
        .ok_or(ElfError::InvalidPhdrHeader { index })?;
    if get_u32(ph, 4) != PF_R
        || get_u64(ph, 8) != expected_offset
        || get_u64(ph, 32) != expected_size
        || get_u64(ph, 40) != expected_size
        || file_end > image_len as u64
    {
        return Err(ElfError::InvalidPhdrHeader { index });
    }
    Ok(())
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    let mask = alignment - 1;
    value.checked_add(mask).map(|sum| sum & !mask)
}

fn get_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
