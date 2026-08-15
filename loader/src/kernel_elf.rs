//! Hostile-input validation and deterministic load planning for `deepwyrm.elf`.
//!
//! This module deliberately stops before firmware allocation, page-table construction, copying,
//! or kernel entry. Callers supply the permitted virtual range and mapping granule from the
//! exact pinned Deepwyrm layout manifest rather than duplicating kernel build constants here.
//!
//! ELF `p_paddr` is non-authoritative metadata for this boot contract. It is intentionally ignored:
//! firmware allocation chooses suitable physical pages later, and a separate mapping stage maps
//! those pages at the validated `p_vaddr` addresses.

const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;

const ELF_CLASS_64: u8 = 2;
const ELF_DATA_LITTLE_ENDIAN: u8 = 1;
const ELF_IDENT_VERSION_CURRENT: u8 = 1;
const ELF_OS_ABI_SYSTEM_V: u8 = 0;
const ELF_ABI_VERSION_SYSTEM_V: u8 = 0;
const ELF_VERSION_CURRENT: u32 = 1;
const ELF_TYPE_EXECUTABLE: u16 = 2;
const ELF_MACHINE_X86_64: u16 = 62;
const PROGRAM_TYPE_LOAD: u32 = 1;

const FLAG_EXECUTE: u32 = 1;
const FLAG_WRITE: u32 = 2;
const FLAG_READ: u32 = 4;
const KNOWN_FLAGS: u32 = FLAG_EXECUTE | FLAG_WRITE | FLAG_READ;

/// A half-open address range allowed by the reviewed kernel handoff policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressRange {
    /// First permitted address.
    pub start: u64,
    /// Address immediately after the permitted range.
    pub end: u64,
}

impl AddressRange {
    /// Construct a half-open address range. Validation occurs when a policy is used.
    pub const fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    fn contains(self, start: u64, end: u64) -> bool {
        self.start <= start && start < end && end <= self.end
    }
}

/// Policy inputs generated from Deepwyrm's pinned linker/handoff contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelElfPolicy {
    /// Deep-generated upper-half window. Its start must equal `link_base` and its conservative
    /// half-open end must be `u64::MAX`, excluding the final byte.
    pub virtual_addresses: AddressRange,
    /// Exact page-rounded address at which the first `PT_LOAD` mapping must begin.
    pub link_base: u64,
    /// Power-of-two virtual mapping granule and smallest accepted segment `p_align`.
    pub mapping_granule: u64,
}

/// Read/write/execute permissions requested by one validated loadable segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentPermissions {
    /// Segment contents may be read after handoff.
    pub read: bool,
    /// Segment contents may be written after handoff.
    pub write: bool,
    /// Segment contents may be executed after handoff.
    pub execute: bool,
}

/// One validated `PT_LOAD` operation, independent of firmware allocation and mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelLoadSegment {
    /// Original program-header index, retained for diagnostics.
    pub program_header_index: u16,
    /// Byte offset of initialized data in the ELF image.
    pub file_offset: u64,
    /// Number of initialized bytes copied from the ELF image.
    pub file_size: u64,
    /// Requested runtime virtual address.
    pub virtual_address: u64,
    /// Page-rounded virtual mapping start derived from `p_vaddr` and the policy granule.
    pub mapping_virtual_address: u64,
    /// Page-rounded mapping length required for this segment.
    pub mapping_byte_len: u64,
    /// Offset of the segment's first byte within its first mapped page.
    pub segment_page_offset: u64,
    /// Total in-memory size, including a zero-filled tail after `file_size`.
    pub memory_size: u64,
    /// Required ELF segment alignment.
    pub alignment: u64,
    /// Final segment permissions. Writable and executable is always rejected.
    pub permissions: SegmentPermissions,
}

/// A validated deterministic kernel load plan.
#[derive(Debug, Eq, PartialEq)]
pub struct KernelLoadPlan<'a> {
    /// Validated kernel entry point.
    pub entry_point: u64,
    /// Loadable segments sorted by virtual address, then header index.
    pub segments: &'a [KernelLoadSegment],
    /// Smallest half-open virtual range containing every segment.
    pub virtual_span: AddressRange,
}

/// Fail-closed errors returned while validating an untrusted kernel ELF image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelElfError {
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
    ExtendedProgramHeaderCountUnsupported,
    ProgramHeaderTableOverlapsElfHeader,
    ProgramHeaderTableMisaligned,
    ProgramHeaderTableOverflow,
    ProgramHeaderTableTruncated,
    InvalidPolicy,
    OutputTooSmall { required: usize, available: usize },
    UnsupportedProgramHeaderType { index: u16, program_type: u32 },
    UnknownSegmentFlags { index: u16, flags: u32 },
    WritableExecutableSegment { index: u16 },
    EmptyLoadSegment { index: u16 },
    FileSizeExceedsMemorySize { index: u16 },
    SegmentFileRangeOverflow { index: u16 },
    SegmentFileRangeTruncated { index: u16 },
    SegmentVirtualRangeOverflow { index: u16 },
    SegmentMappingRangeOverflow { index: u16 },
    InvalidSegmentAlignment { index: u16, alignment: u64 },
    SegmentAlignmentBelowPolicy { index: u16, alignment: u64 },
    SegmentAddressAlignmentMismatch { index: u16 },
    SegmentVirtualRangeOutsidePolicy { index: u16 },
    OverlappingVirtualSegments { first: u16, second: u16 },
    OverlappingVirtualMappingRanges { first: u16, second: u16 },
    KernelLinkBaseMismatch { expected: u64, observed: u64 },
    ZeroEntryPoint,
    EntryPointNotInExecutableFileData,
}

/// Validate the ELF header and complete program-header table before allocating plan storage.
///
/// This performs no allocation and returns the exact number of `KernelLoadSegment` slots required.
/// The caller must preserve the image bytes unchanged, allocate fallibly, and then call
/// [`plan_kernel_elf`], which deliberately reparses and authoritatively validates every field.
pub fn kernel_load_segment_capacity(
    image: &[u8],
    policy: KernelElfPolicy,
) -> Result<usize, KernelElfError> {
    validated_header_and_capacity(image, policy).map(|(_, capacity)| capacity)
}

/// Validate an ELF image and write its deterministic load plan into caller-owned storage.
///
/// The output buffer bounds hostile program-header counts without requiring allocation. On
/// failure, its contents are unspecified and must not be used. The returned plan performs no
/// firmware I/O and grants no authority to enter the kernel.
pub fn plan_kernel_elf<'plan>(
    image: &[u8],
    policy: KernelElfPolicy,
    output: &'plan mut [KernelLoadSegment],
) -> Result<KernelLoadPlan<'plan>, KernelElfError> {
    let (header, segment_count) = validated_header_and_capacity(image, policy)?;
    if segment_count > output.len() {
        return Err(KernelElfError::OutputTooSmall {
            required: segment_count,
            available: output.len(),
        });
    }

    for index in 0..header.program_header_count {
        let bytes = program_header_bytes(image, header, index)?;
        output[usize::from(index)] = parse_segment(image, bytes, index, policy)?;
    }

    let segments = &mut output[..segment_count];
    segments.sort_unstable_by(|left, right| {
        left.virtual_address
            .cmp(&right.virtual_address)
            .then(left.program_header_index.cmp(&right.program_header_index))
    });

    validate_non_overlapping(segments, policy.mapping_granule)?;
    if header.entry_point == 0 {
        return Err(KernelElfError::ZeroEntryPoint);
    }
    if !segments.iter().any(|segment| {
        segment.permissions.execute
            && segment.file_size != 0
            && header.entry_point >= segment.virtual_address
            && header.entry_point - segment.virtual_address < segment.file_size
    }) {
        return Err(KernelElfError::EntryPointNotInExecutableFileData);
    }

    let first = segments
        .first()
        .ok_or(KernelElfError::MissingProgramHeaders)?;
    if first.mapping_virtual_address != policy.link_base {
        return Err(KernelElfError::KernelLinkBaseMismatch {
            expected: policy.link_base,
            observed: first.mapping_virtual_address,
        });
    }
    let virtual_start = first.virtual_address;
    let mut virtual_end = first.virtual_address + first.memory_size;
    for segment in &segments[1..] {
        virtual_end = virtual_end.max(segment.virtual_address + segment.memory_size);
    }

    Ok(KernelLoadPlan {
        entry_point: header.entry_point,
        segments,
        virtual_span: AddressRange::new(virtual_start, virtual_end),
    })
}

fn validated_header_and_capacity(
    image: &[u8],
    policy: KernelElfPolicy,
) -> Result<(ElfHeader, usize), KernelElfError> {
    validate_policy(policy)?;
    let header = parse_header(image)?;
    let table_size = u64::from(header.program_header_count)
        .checked_mul(u64::from(header.program_header_size))
        .ok_or(KernelElfError::ProgramHeaderTableOverflow)?;
    let table_end = header
        .program_header_offset
        .checked_add(table_size)
        .ok_or(KernelElfError::ProgramHeaderTableOverflow)?;
    if table_end > image_len_u64(image)? {
        return Err(KernelElfError::ProgramHeaderTableTruncated);
    }
    for index in 0..header.program_header_count {
        let bytes = program_header_bytes(image, header, index)?;
        let program_type = read_u32(bytes, 0);
        if program_type != PROGRAM_TYPE_LOAD {
            return Err(KernelElfError::UnsupportedProgramHeaderType {
                index,
                program_type,
            });
        }
    }
    Ok((header, usize::from(header.program_header_count)))
}

fn program_header_bytes(
    image: &[u8],
    header: ElfHeader,
    index: u16,
) -> Result<&[u8], KernelElfError> {
    let relative_offset = u64::from(index)
        .checked_mul(u64::from(header.program_header_size))
        .ok_or(KernelElfError::ProgramHeaderTableOverflow)?;
    let offset = header
        .program_header_offset
        .checked_add(relative_offset)
        .ok_or(KernelElfError::ProgramHeaderTableOverflow)?;
    byte_range(image, offset, PROGRAM_HEADER_SIZE as u64)
        .ok_or(KernelElfError::ProgramHeaderTableTruncated)
}

#[derive(Clone, Copy)]
struct ElfHeader {
    entry_point: u64,
    program_header_offset: u64,
    program_header_size: u16,
    program_header_count: u16,
}

fn parse_header(image: &[u8]) -> Result<ElfHeader, KernelElfError> {
    let header = image
        .get(..ELF_HEADER_SIZE)
        .ok_or(KernelElfError::HeaderTruncated)?;
    if header[..4] != *b"\x7fELF" {
        return Err(KernelElfError::BadMagic);
    }
    if header[4] != ELF_CLASS_64 {
        return Err(KernelElfError::UnsupportedClass(header[4]));
    }
    if header[5] != ELF_DATA_LITTLE_ENDIAN {
        return Err(KernelElfError::UnsupportedDataEncoding(header[5]));
    }
    if header[6] != ELF_IDENT_VERSION_CURRENT {
        return Err(KernelElfError::UnsupportedIdentVersion(header[6]));
    }
    if header[7] != ELF_OS_ABI_SYSTEM_V {
        return Err(KernelElfError::UnsupportedOsAbi(header[7]));
    }
    if header[8] != ELF_ABI_VERSION_SYSTEM_V {
        return Err(KernelElfError::UnsupportedAbiVersion(header[8]));
    }

    let elf_type = read_u16(header, 16);
    if elf_type != ELF_TYPE_EXECUTABLE {
        return Err(KernelElfError::UnsupportedElfType(elf_type));
    }
    let machine = read_u16(header, 18);
    if machine != ELF_MACHINE_X86_64 {
        return Err(KernelElfError::UnsupportedMachine(machine));
    }
    let version = read_u32(header, 20);
    if version != ELF_VERSION_CURRENT {
        return Err(KernelElfError::UnsupportedElfVersion(version));
    }
    let flags = read_u32(header, 48);
    if flags != 0 {
        return Err(KernelElfError::UnsupportedElfFlags(flags));
    }
    let header_size = read_u16(header, 52);
    if usize::from(header_size) != ELF_HEADER_SIZE {
        return Err(KernelElfError::InvalidElfHeaderSize(header_size));
    }
    let program_header_size = read_u16(header, 54);
    if usize::from(program_header_size) != PROGRAM_HEADER_SIZE {
        return Err(KernelElfError::InvalidProgramHeaderSize(
            program_header_size,
        ));
    }
    let program_header_count = read_u16(header, 56);
    if program_header_count == 0 {
        return Err(KernelElfError::MissingProgramHeaders);
    }
    if program_header_count == u16::MAX {
        return Err(KernelElfError::ExtendedProgramHeaderCountUnsupported);
    }
    let program_header_offset = read_u64(header, 32);
    if program_header_offset < ELF_HEADER_SIZE as u64 {
        return Err(KernelElfError::ProgramHeaderTableOverlapsElfHeader);
    }
    if !program_header_offset.is_multiple_of(8) {
        return Err(KernelElfError::ProgramHeaderTableMisaligned);
    }

    Ok(ElfHeader {
        entry_point: read_u64(header, 24),
        program_header_offset,
        program_header_size,
        program_header_count,
    })
}

fn validate_policy(policy: KernelElfPolicy) -> Result<(), KernelElfError> {
    if policy.virtual_addresses.start != policy.link_base
        || policy.virtual_addresses.end != u64::MAX
        || !policy.mapping_granule.is_power_of_two()
        || !policy.link_base.is_multiple_of(policy.mapping_granule)
    {
        return Err(KernelElfError::InvalidPolicy);
    }
    Ok(())
}

fn parse_segment(
    image: &[u8],
    header: &[u8],
    index: u16,
    policy: KernelElfPolicy,
) -> Result<KernelLoadSegment, KernelElfError> {
    let program_type = read_u32(header, 0);
    if program_type != PROGRAM_TYPE_LOAD {
        return Err(KernelElfError::UnsupportedProgramHeaderType {
            index,
            program_type,
        });
    }
    let flags = read_u32(header, 4);
    if flags & !KNOWN_FLAGS != 0 {
        return Err(KernelElfError::UnknownSegmentFlags { index, flags });
    }
    if flags & FLAG_WRITE != 0 && flags & FLAG_EXECUTE != 0 {
        return Err(KernelElfError::WritableExecutableSegment { index });
    }

    let file_offset = read_u64(header, 8);
    let virtual_address = read_u64(header, 16);
    // `p_paddr` at bytes 24..32 is intentionally ignored. It is not part of Deepwyrm's physical
    // placement contract and must never steer firmware allocation.
    let file_size = read_u64(header, 32);
    let memory_size = read_u64(header, 40);
    let alignment = read_u64(header, 48);

    if memory_size == 0 {
        return Err(KernelElfError::EmptyLoadSegment { index });
    }
    if file_size > memory_size {
        return Err(KernelElfError::FileSizeExceedsMemorySize { index });
    }
    let file_end = file_offset
        .checked_add(file_size)
        .ok_or(KernelElfError::SegmentFileRangeOverflow { index })?;
    if file_end > image_len_u64(image)? {
        return Err(KernelElfError::SegmentFileRangeTruncated { index });
    }
    let virtual_end = virtual_address
        .checked_add(memory_size)
        .ok_or(KernelElfError::SegmentVirtualRangeOverflow { index })?;
    let mapping_start = align_down(virtual_address, policy.mapping_granule);
    let mapping_end = align_up(virtual_end, policy.mapping_granule)
        .ok_or(KernelElfError::SegmentMappingRangeOverflow { index })?;
    if !alignment.is_power_of_two() {
        return Err(KernelElfError::InvalidSegmentAlignment { index, alignment });
    }
    if alignment < policy.mapping_granule {
        return Err(KernelElfError::SegmentAlignmentBelowPolicy { index, alignment });
    }
    let alignment_mask = alignment - 1;
    let expected_remainder = file_offset & alignment_mask;
    if virtual_address & alignment_mask != expected_remainder {
        return Err(KernelElfError::SegmentAddressAlignmentMismatch { index });
    }
    if !policy
        .virtual_addresses
        .contains(mapping_start, mapping_end)
    {
        return Err(KernelElfError::SegmentVirtualRangeOutsidePolicy { index });
    }
    Ok(KernelLoadSegment {
        program_header_index: index,
        file_offset,
        file_size,
        virtual_address,
        mapping_virtual_address: mapping_start,
        mapping_byte_len: mapping_end - mapping_start,
        segment_page_offset: virtual_address - mapping_start,
        memory_size,
        alignment,
        permissions: SegmentPermissions {
            read: flags & FLAG_READ != 0,
            write: flags & FLAG_WRITE != 0,
            execute: flags & FLAG_EXECUTE != 0,
        },
    })
}

fn validate_non_overlapping(
    segments: &[KernelLoadSegment],
    mapping_granule: u64,
) -> Result<(), KernelElfError> {
    for pair in segments.windows(2) {
        let left = pair[0];
        let right = pair[1];
        if left.virtual_address + left.memory_size > right.virtual_address {
            return Err(KernelElfError::OverlappingVirtualSegments {
                first: left.program_header_index,
                second: right.program_header_index,
            });
        }
    }

    for pair in segments.windows(2) {
        let left = pair[0];
        let right = pair[1];
        let left_end = left.virtual_address + left.memory_size;
        let left_mapping_end = align_up(left_end, mapping_granule).ok_or(
            KernelElfError::SegmentMappingRangeOverflow {
                index: left.program_header_index,
            },
        )?;
        let right_mapping_start = align_down(right.virtual_address, mapping_granule);
        if left_mapping_end > right_mapping_start {
            return Err(KernelElfError::OverlappingVirtualMappingRanges {
                first: left.program_header_index,
                second: right.program_header_index,
            });
        }
    }

    Ok(())
}

fn align_down(value: u64, alignment: u64) -> u64 {
    value & !(alignment - 1)
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value
        .checked_add(alignment - 1)
        .map(|end| align_down(end, alignment))
}

fn image_len_u64(image: &[u8]) -> Result<u64, KernelElfError> {
    u64::try_from(image.len()).map_err(|_| KernelElfError::ProgramHeaderTableTruncated)
}

fn byte_range(image: &[u8], offset: u64, size: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let size = usize::try_from(size).ok()?;
    let end = start.checked_add(size)?;
    image.get(start..end)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}
