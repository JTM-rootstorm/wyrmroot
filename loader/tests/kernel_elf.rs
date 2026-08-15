#[path = "../src/kernel_elf.rs"]
mod kernel_elf;

use kernel_elf::{
    AddressRange, KernelElfError, KernelElfPolicy, KernelLoadSegment, SegmentPermissions,
    plan_kernel_elf,
};

const CODE_VIRTUAL: u64 = 0xffff_8000_0010_0000;
const CODE_PHYSICAL: u64 = 0x0010_0000;
const DATA_VIRTUAL: u64 = CODE_VIRTUAL + 0x2000;
const DATA_PHYSICAL: u64 = CODE_PHYSICAL + 0x2000;

const EMPTY_SEGMENT: KernelLoadSegment = KernelLoadSegment {
    program_header_index: 0,
    file_offset: 0,
    file_size: 0,
    virtual_address: 0,
    mapping_virtual_address: 0,
    mapping_byte_len: 0,
    segment_page_offset: 0,
    memory_size: 0,
    alignment: 1,
    permissions: SegmentPermissions {
        read: false,
        write: false,
        execute: false,
    },
};

#[derive(Clone, Copy)]
struct SegmentSpec {
    program_type: u32,
    flags: u32,
    file_offset: u64,
    virtual_address: u64,
    physical_address: u64,
    file_size: u64,
    memory_size: u64,
    alignment: u64,
}

fn code_segment() -> SegmentSpec {
    SegmentSpec {
        program_type: 1,
        flags: 5,
        file_offset: 0x1000,
        virtual_address: CODE_VIRTUAL,
        physical_address: CODE_PHYSICAL,
        file_size: 0x200,
        memory_size: 0x1000,
        alignment: 0x1000,
    }
}

fn data_segment() -> SegmentSpec {
    SegmentSpec {
        program_type: 1,
        flags: 6,
        file_offset: 0x2000,
        virtual_address: DATA_VIRTUAL,
        physical_address: DATA_PHYSICAL,
        file_size: 0x100,
        memory_size: 0x1000,
        alignment: 0x1000,
    }
}

fn policy() -> KernelElfPolicy {
    KernelElfPolicy {
        virtual_addresses: AddressRange::new(CODE_VIRTUAL, u64::MAX),
        link_base: CODE_VIRTUAL,
        mapping_granule: 0x1000,
    }
}

fn elf(entry: u64, segments: &[SegmentSpec]) -> Vec<u8> {
    let table_end = 64 + segments.len() * 56;
    let file_end = segments
        .iter()
        .filter_map(|segment| segment.file_offset.checked_add(segment.file_size))
        .filter_map(|end| usize::try_from(end).ok())
        .max()
        .unwrap_or(table_end);
    let mut bytes = vec![0_u8; table_end.max(file_end)];

    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put_u16(&mut bytes, 16, 2);
    put_u16(&mut bytes, 18, 62);
    put_u32(&mut bytes, 20, 1);
    put_u64(&mut bytes, 24, entry);
    put_u64(&mut bytes, 32, 64);
    put_u16(&mut bytes, 52, 64);
    put_u16(&mut bytes, 54, 56);
    put_u16(&mut bytes, 56, u16::try_from(segments.len()).unwrap());

    for (index, segment) in segments.iter().enumerate() {
        let offset = 64 + index * 56;
        put_u32(&mut bytes, offset, segment.program_type);
        put_u32(&mut bytes, offset + 4, segment.flags);
        put_u64(&mut bytes, offset + 8, segment.file_offset);
        put_u64(&mut bytes, offset + 16, segment.virtual_address);
        put_u64(&mut bytes, offset + 24, segment.physical_address);
        put_u64(&mut bytes, offset + 32, segment.file_size);
        put_u64(&mut bytes, offset + 40, segment.memory_size);
        put_u64(&mut bytes, offset + 48, segment.alignment);
    }

    bytes
}

fn error_for(image: &[u8]) -> KernelElfError {
    let mut output = [EMPTY_SEGMENT; 4];
    plan_kernel_elf(image, policy(), &mut output).unwrap_err()
}

#[test]
fn produces_a_deterministic_virtual_address_ordered_plan() {
    let image = elf(CODE_VIRTUAL + 0x10, &[data_segment(), code_segment()]);
    let mut output = [EMPTY_SEGMENT; 2];

    let plan = plan_kernel_elf(&image, policy(), &mut output).unwrap();

    assert_eq!(plan.entry_point, CODE_VIRTUAL + 0x10);
    assert_eq!(plan.segments.len(), 2);
    assert_eq!(plan.segments[0].program_header_index, 1);
    assert_eq!(plan.segments[0].virtual_address, CODE_VIRTUAL);
    assert_eq!(plan.segments[0].mapping_virtual_address, CODE_VIRTUAL);
    assert_eq!(plan.segments[0].mapping_byte_len, 0x1000);
    assert_eq!(plan.segments[0].segment_page_offset, 0);
    assert_eq!(plan.segments[1].program_header_index, 0);
    assert_eq!(plan.segments[1].virtual_address, DATA_VIRTUAL);
    assert_eq!(
        plan.virtual_span,
        AddressRange::new(CODE_VIRTUAL, DATA_VIRTUAL + 0x1000)
    );
}

#[test]
fn et_exec_lowest_mapping_must_equal_the_manifest_link_base() {
    let shift = 0x1000;
    let mut code = code_segment();
    code.virtual_address += shift;
    let mut data = data_segment();
    data.virtual_address += shift;
    let image = elf(code.virtual_address, &[code, data]);
    let mut output = [EMPTY_SEGMENT; 2];

    assert_eq!(
        plan_kernel_elf(&image, policy(), &mut output),
        Err(KernelElfError::KernelLinkBaseMismatch {
            expected: CODE_VIRTUAL,
            observed: CODE_VIRTUAL + shift,
        })
    );
}

#[test]
fn exposes_page_offset_and_rounded_mapping_for_congruent_unaligned_segment() {
    let mut segment = code_segment();
    segment.file_offset = 0x1800;
    segment.virtual_address = CODE_VIRTUAL + 0x800;
    segment.file_size = 0x100;
    segment.memory_size = 0x700;
    let image = elf(segment.virtual_address, &[segment]);
    let mut output = [EMPTY_SEGMENT; 1];

    let plan = plan_kernel_elf(&image, policy(), &mut output).unwrap();

    assert_eq!(plan.segments[0].mapping_virtual_address, CODE_VIRTUAL);
    assert_eq!(plan.segments[0].mapping_byte_len, 0x1000);
    assert_eq!(plan.segments[0].segment_page_offset, 0x800);
}

#[test]
fn rejects_truncated_and_malformed_identification() {
    assert_eq!(error_for(&[]), KernelElfError::HeaderTruncated);

    let base = elf(CODE_VIRTUAL, &[code_segment()]);
    let cases = [
        (0, 0, KernelElfError::BadMagic),
        (4, 1, KernelElfError::UnsupportedClass(1)),
        (5, 2, KernelElfError::UnsupportedDataEncoding(2)),
        (6, 0, KernelElfError::UnsupportedIdentVersion(0)),
        (7, 3, KernelElfError::UnsupportedOsAbi(3)),
        (8, 1, KernelElfError::UnsupportedAbiVersion(1)),
    ];
    for (offset, value, expected) in cases {
        let mut image = base.clone();
        image[offset] = value;
        assert_eq!(error_for(&image), expected);
    }
}

#[test]
fn rejects_unsupported_type_machine_and_version() {
    let base = elf(CODE_VIRTUAL, &[code_segment()]);

    let mut dynamic = base.clone();
    put_u16(&mut dynamic, 16, 3);
    assert_eq!(error_for(&dynamic), KernelElfError::UnsupportedElfType(3));

    let mut wrong_machine = base.clone();
    put_u16(&mut wrong_machine, 18, 3);
    assert_eq!(
        error_for(&wrong_machine),
        KernelElfError::UnsupportedMachine(3)
    );

    let mut wrong_version = base;
    put_u32(&mut wrong_version, 20, 2);
    assert_eq!(
        error_for(&wrong_version),
        KernelElfError::UnsupportedElfVersion(2)
    );

    let mut wrong_flags = elf(CODE_VIRTUAL, &[code_segment()]);
    put_u32(&mut wrong_flags, 48, 1);
    assert_eq!(
        error_for(&wrong_flags),
        KernelElfError::UnsupportedElfFlags(1)
    );
}

#[test]
fn rejects_malformed_program_header_tables() {
    let base = elf(CODE_VIRTUAL, &[code_segment()]);

    let mut bad_elf_header_size = base.clone();
    put_u16(&mut bad_elf_header_size, 52, 63);
    assert_eq!(
        error_for(&bad_elf_header_size),
        KernelElfError::InvalidElfHeaderSize(63)
    );

    let mut bad_entry_size = base.clone();
    put_u16(&mut bad_entry_size, 54, 55);
    assert_eq!(
        error_for(&bad_entry_size),
        KernelElfError::InvalidProgramHeaderSize(55)
    );

    let mut missing = base.clone();
    put_u16(&mut missing, 56, 0);
    assert_eq!(error_for(&missing), KernelElfError::MissingProgramHeaders);

    let mut extended = base.clone();
    put_u16(&mut extended, 56, u16::MAX);
    assert_eq!(
        error_for(&extended),
        KernelElfError::ExtendedProgramHeaderCountUnsupported
    );

    let mut overlap = base.clone();
    put_u64(&mut overlap, 32, 32);
    assert_eq!(
        error_for(&overlap),
        KernelElfError::ProgramHeaderTableOverlapsElfHeader
    );

    let mut misaligned = base.clone();
    put_u64(&mut misaligned, 32, 65);
    assert_eq!(
        error_for(&misaligned),
        KernelElfError::ProgramHeaderTableMisaligned
    );

    let mut wrapped = base.clone();
    put_u64(&mut wrapped, 32, u64::MAX - 15);
    assert_eq!(
        error_for(&wrapped),
        KernelElfError::ProgramHeaderTableOverflow
    );

    let mut truncated = base;
    truncated.truncate(100);
    assert_eq!(
        error_for(&truncated),
        KernelElfError::ProgramHeaderTableTruncated
    );
}

#[test]
fn accepts_only_pt_load_and_known_non_wx_permissions() {
    let mut unsupported = code_segment();
    unsupported.program_type = 3;
    assert_eq!(
        error_for(&elf(CODE_VIRTUAL, &[unsupported])),
        KernelElfError::UnsupportedProgramHeaderType {
            index: 0,
            program_type: 3
        }
    );

    let mut unknown_flags = code_segment();
    unknown_flags.flags = 0x80;
    assert_eq!(
        error_for(&elf(CODE_VIRTUAL, &[unknown_flags])),
        KernelElfError::UnknownSegmentFlags {
            index: 0,
            flags: 0x80
        }
    );

    let mut writable_executable = code_segment();
    writable_executable.flags = 7;
    assert_eq!(
        error_for(&elf(CODE_VIRTUAL, &[writable_executable])),
        KernelElfError::WritableExecutableSegment { index: 0 }
    );
}

#[test]
fn rejects_invalid_file_and_memory_sizes() {
    let mut empty = code_segment();
    empty.memory_size = 0;
    empty.file_size = 0;
    assert_eq!(
        error_for(&elf(CODE_VIRTUAL, &[empty])),
        KernelElfError::EmptyLoadSegment { index: 0 }
    );

    let mut too_large = code_segment();
    too_large.file_size = too_large.memory_size + 1;
    assert_eq!(
        error_for(&elf(CODE_VIRTUAL, &[too_large])),
        KernelElfError::FileSizeExceedsMemorySize { index: 0 }
    );

    let mut wrapped = code_segment();
    wrapped.file_offset = u64::MAX - 7;
    wrapped.file_size = 16;
    wrapped.memory_size = 16;
    let mut image = elf(CODE_VIRTUAL, &[code_segment()]);
    write_segment(&mut image, 0, wrapped);
    assert_eq!(
        error_for(&image),
        KernelElfError::SegmentFileRangeOverflow { index: 0 }
    );

    let mut truncated = code_segment();
    truncated.file_offset = 0x3000;
    let mut image = elf(CODE_VIRTUAL, &[code_segment()]);
    write_segment(&mut image, 0, truncated);
    assert_eq!(
        error_for(&image),
        KernelElfError::SegmentFileRangeTruncated { index: 0 }
    );
}

#[test]
fn rejects_virtual_address_arithmetic_wrap() {
    let mut virtual_wrap = code_segment();
    virtual_wrap.virtual_address = u64::MAX - 0x7ff;
    virtual_wrap.memory_size = 0x1000;
    virtual_wrap.alignment = 1;
    let mut permissive = policy();
    permissive.mapping_granule = 1;
    let image = elf(virtual_wrap.virtual_address, &[virtual_wrap]);
    let mut output = [EMPTY_SEGMENT; 1];
    assert_eq!(
        plan_kernel_elf(&image, permissive, &mut output),
        Err(KernelElfError::SegmentVirtualRangeOverflow { index: 0 })
    );
}

#[test]
fn rejects_mapping_granule_rounding_wrap() {
    let mut segment = code_segment();
    segment.file_offset = 0x1800;
    segment.virtual_address = u64::MAX - 0x7ff;
    segment.file_size = 0x10;
    segment.memory_size = 0x100;

    let image = elf(segment.virtual_address, &[segment]);
    let mut output = [EMPTY_SEGMENT; 1];

    assert_eq!(
        plan_kernel_elf(&image, policy(), &mut output),
        Err(KernelElfError::SegmentMappingRangeOverflow { index: 0 })
    );
}

#[test]
fn p_paddr_is_ignored_and_cannot_steer_physical_placement() {
    let mut segment = code_segment();
    segment.physical_address = u64::MAX;
    let image = elf(CODE_VIRTUAL, &[segment]);
    let mut output = [EMPTY_SEGMENT; 1];

    let plan = plan_kernel_elf(&image, policy(), &mut output).unwrap();

    assert_eq!(plan.segments[0].virtual_address, CODE_VIRTUAL);
}

#[test]
fn rejects_invalid_or_inconsistent_alignment() {
    let mut not_power_of_two = code_segment();
    not_power_of_two.alignment = 3;
    assert_eq!(
        error_for(&elf(CODE_VIRTUAL, &[not_power_of_two])),
        KernelElfError::InvalidSegmentAlignment {
            index: 0,
            alignment: 3
        }
    );

    let mut below_policy = code_segment();
    below_policy.alignment = 0x100;
    assert_eq!(
        error_for(&elf(CODE_VIRTUAL, &[below_policy])),
        KernelElfError::SegmentAlignmentBelowPolicy {
            index: 0,
            alignment: 0x100
        }
    );

    let mut mismatched = code_segment();
    mismatched.virtual_address += 1;
    assert_eq!(
        error_for(&elf(mismatched.virtual_address, &[mismatched])),
        KernelElfError::SegmentAddressAlignmentMismatch { index: 0 }
    );
}

#[test]
fn requires_all_segment_ranges_to_fit_explicit_policy() {
    let image = elf(CODE_VIRTUAL, &[code_segment()]);
    let mut output = [EMPTY_SEGMENT; 1];

    let mut invalid = policy();
    invalid.virtual_addresses.end = invalid.virtual_addresses.start;
    assert_eq!(
        plan_kernel_elf(&image, invalid, &mut output),
        Err(KernelElfError::InvalidPolicy)
    );

    let mut wrong_lower_bound = policy();
    wrong_lower_bound.virtual_addresses.start -= 0x1000;
    assert_eq!(
        plan_kernel_elf(&image, wrong_lower_bound, &mut output),
        Err(KernelElfError::InvalidPolicy)
    );

    let mut wrong_upper_bound = policy();
    wrong_upper_bound.virtual_addresses.end = u64::MAX - 1;
    assert_eq!(
        plan_kernel_elf(&image, wrong_upper_bound, &mut output),
        Err(KernelElfError::InvalidPolicy)
    );
}

#[test]
fn rejects_virtual_segment_overlap() {
    let code = code_segment();

    let mut virtual_overlap = data_segment();
    virtual_overlap.virtual_address = code.virtual_address;
    assert_eq!(
        error_for(&elf(CODE_VIRTUAL, &[code, virtual_overlap])),
        KernelElfError::OverlappingVirtualSegments {
            first: 0,
            second: 1
        }
    );
}

#[test]
fn rejects_nonoverlapping_segments_that_alias_one_mapping_granule() {
    let mut code = code_segment();
    code.file_size = 0x400;
    code.memory_size = 0x800;

    let mut data = data_segment();
    data.file_offset = 0x1800;
    data.virtual_address = CODE_VIRTUAL + 0x800;
    data.file_size = 0x100;
    data.memory_size = 0x800;

    assert_eq!(
        error_for(&elf(CODE_VIRTUAL, &[code, data])),
        KernelElfError::OverlappingVirtualMappingRanges {
            first: 0,
            second: 1
        }
    );
}

#[test]
fn entry_must_be_nonzero_and_inside_executable_file_data() {
    let code = code_segment();
    assert_eq!(error_for(&elf(0, &[code])), KernelElfError::ZeroEntryPoint);
    assert_eq!(
        error_for(&elf(DATA_VIRTUAL, &[code, data_segment()])),
        KernelElfError::EntryPointNotInExecutableFileData
    );
    assert_eq!(
        error_for(&elf(CODE_VIRTUAL + code.file_size, &[code])),
        KernelElfError::EntryPointNotInExecutableFileData
    );
}

#[test]
fn caller_storage_bounds_hostile_program_header_counts() {
    let image = elf(CODE_VIRTUAL, &[code_segment(), data_segment()]);
    let mut output = [EMPTY_SEGMENT; 1];
    assert_eq!(
        plan_kernel_elf(&image, policy(), &mut output),
        Err(KernelElfError::OutputTooSmall {
            required: 2,
            available: 1
        })
    );
}

fn write_segment(bytes: &mut [u8], index: usize, segment: SegmentSpec) {
    let offset = 64 + index * 56;
    put_u32(bytes, offset, segment.program_type);
    put_u32(bytes, offset + 4, segment.flags);
    put_u64(bytes, offset + 8, segment.file_offset);
    put_u64(bytes, offset + 16, segment.virtual_address);
    put_u64(bytes, offset + 24, segment.physical_address);
    put_u64(bytes, offset + 32, segment.file_size);
    put_u64(bytes, offset + 40, segment.memory_size);
    put_u64(bytes, offset + 48, segment.alignment);
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
