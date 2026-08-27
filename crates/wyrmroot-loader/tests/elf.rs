use wyrmroot_loader::elf::{
    self, ElfError, LoadSegment, MAX_LOAD_SEGMENTS, PAGE_SIZE, STACK_BOTTOM, STACK_GUARD_START,
    STACK_TOP, SegmentProtection,
};

const PH_OFFSET: usize = 64;
const PH_SIZE: usize = 56;

#[derive(Clone, Copy)]
struct Ph {
    kind: u32,
    flags: u32,
    offset: u64,
    address: u64,
    file_size: u64,
    memory_size: u64,
    alignment: u64,
}

fn image(headers: &[Ph], entry: u64, length: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; length];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put16(&mut bytes, 16, 2);
    put16(&mut bytes, 18, 62);
    put32(&mut bytes, 20, 1);
    put64(&mut bytes, 24, entry);
    put64(&mut bytes, 32, PH_OFFSET as u64);
    put16(&mut bytes, 52, 64);
    put16(&mut bytes, 54, PH_SIZE as u16);
    put16(&mut bytes, 56, headers.len() as u16);
    for (index, ph) in headers.iter().enumerate() {
        let at = PH_OFFSET + index * PH_SIZE;
        put32(&mut bytes, at, ph.kind);
        put32(&mut bytes, at + 4, ph.flags);
        put64(&mut bytes, at + 8, ph.offset);
        put64(&mut bytes, at + 16, ph.address);
        put64(&mut bytes, at + 24, ph.address);
        put64(&mut bytes, at + 32, ph.file_size);
        put64(&mut bytes, at + 40, ph.memory_size);
        put64(&mut bytes, at + 48, ph.alignment);
    }
    bytes
}

fn load(flags: u32, offset: u64, address: u64, file_size: u64, memory_size: u64) -> Ph {
    Ph {
        kind: 1,
        flags,
        offset,
        address,
        file_size,
        memory_size,
        alignment: PAGE_SIZE,
    }
}

fn stack() -> Ph {
    Ph {
        kind: 0x6474_e551,
        flags: 6,
        offset: 0,
        address: 0,
        file_size: 0,
        memory_size: 0,
        alignment: 16,
    }
}

fn valid() -> Vec<u8> {
    image(
        &[
            load(6, 0x2000, 0x402000, 0x80, 0x900),
            stack(),
            load(5, 0x1000, 0x400000, 0x180, 0x1200),
        ],
        0x400080,
        0x3000,
    )
}

#[test]
fn valid_static_image_produces_sorted_complete_plan() {
    let image = valid();
    let mut output = [empty_segment(); MAX_LOAD_SEGMENTS];
    let plan = elf::plan(&image, &mut output).unwrap();
    assert_eq!(plan.entry, 0x400080);
    assert_eq!(plan.mapped_bytes, 0x3000);
    assert_eq!(plan.segments.len(), 2);
    assert_eq!(plan.segments[0].header_index, 2);
    assert_eq!(plan.segments[0].mapping_size, 0x2000);
    assert_eq!(plan.segments[0].protection, SegmentProtection::ReadExecute);
    assert_eq!(plan.segments[1].header_index, 0);
    assert_eq!(plan.segments[1].protection, SegmentProtection::ReadWrite);
}

#[test]
fn malformed_ident_and_header_table_fail_closed() {
    let mut bytes = valid();
    bytes[0] = 0;
    assert_eq!(elf::required_segment_count(&bytes), Err(ElfError::BadMagic));

    let mut bytes = valid();
    bytes[4] = 1;
    assert_eq!(
        elf::required_segment_count(&bytes),
        Err(ElfError::UnsupportedClass(1))
    );

    let mut bytes = valid();
    put16(&mut bytes, 16, 3);
    assert_eq!(
        elf::required_segment_count(&bytes),
        Err(ElfError::UnsupportedElfType(3))
    );

    let mut bytes = valid();
    put16(&mut bytes, 18, 3);
    assert_eq!(
        elf::required_segment_count(&bytes),
        Err(ElfError::UnsupportedMachine(3))
    );

    let bytes = &valid()[..100];
    assert_eq!(
        elf::required_segment_count(bytes),
        Err(ElfError::ProgramHeaderTableTruncated)
    );
}

#[test]
fn unsupported_program_headers_and_executable_stack_are_rejected() {
    for kind in [2, 3, 4, 7, 0x6474_e552, 0x7000_0000] {
        let bytes = image(
            &[load(5, 0x1000, 0x400000, 1, 1), Ph { kind, ..stack() }],
            0x400000,
            0x2000,
        );
        assert!(
            matches!(elf::required_segment_count(&bytes), Err(ElfError::UnsupportedProgramHeaderType { header_type, .. }) if header_type == kind)
        );
    }
    let bytes = image(
        &[
            load(5, 0x1000, 0x400000, 1, 1),
            Ph {
                flags: 7,
                ..stack()
            },
        ],
        0x400000,
        0x2000,
    );
    assert!(matches!(
        elf::required_segment_count(&bytes),
        Err(ElfError::InvalidStackHeader { .. })
    ));
}

#[test]
fn segment_permissions_sizes_and_alignment_are_enforced() {
    for flags in [1, 2, 3, 7, 8] {
        let bytes = image(&[load(flags, 0x1000, 0x400000, 1, 1)], 0x400000, 0x2000);
        let mut output = [empty_segment(); 1];
        assert!(elf::plan(&bytes, &mut output).is_err(), "flags {flags}");
    }
    let cases = [
        load(5, 0x1000, 0x400000, 2, 1),
        load(5, 0x1fff, 0x400000, 2, 2),
        Ph {
            alignment: 0,
            ..load(5, 0x1000, 0x400000, 1, 1)
        },
        Ph {
            alignment: 512,
            ..load(5, 0x1000, 0x400000, 1, 1)
        },
        load(5, 0x1001, 0x400000, 1, 1),
        load(5, 0x1000, 0x400000, 0, 0),
    ];
    for ph in cases {
        let bytes = image(&[ph], 0x400000, 0x2000);
        let mut output = [empty_segment(); 1];
        assert!(elf::plan(&bytes, &mut output).is_err());
    }
}

#[test]
fn reserved_and_overlapping_virtual_ranges_are_rejected() {
    let cases = [
        vec![load(5, 0, 0, 1, 1)],
        vec![load(5, 0, STACK_GUARD_START, 1, PAGE_SIZE)],
        vec![
            load(5, 0x1000, 0x400000, 1, 0x1800),
            load(4, 0x2800, 0x401800, 1, 1),
        ],
        vec![
            load(5, 0x1000, 0x400000, 1, 0x801),
            load(4, 0x2801, 0x400801, 1, 1),
        ],
    ];
    for headers in cases {
        let bytes = image(&headers, headers[0].address, 0x4000);
        let mut output = [empty_segment(); MAX_LOAD_SEGMENTS];
        assert!(elf::plan(&bytes, &mut output).is_err());
    }
}

#[test]
fn expanded_stack_guard_boundaries_are_exact() {
    let adjacent_address = STACK_GUARD_START - PAGE_SIZE;
    let adjacent = image(
        &[load(5, 0, adjacent_address, 1, PAGE_SIZE)],
        adjacent_address,
        0x1000,
    );
    let mut output = [empty_segment(); MAX_LOAD_SEGMENTS];
    let plan = elf::plan(&adjacent, &mut output).unwrap();
    assert_eq!(plan.segments[0].mapping_end(), STACK_GUARD_START);

    for (address, memory_size) in [
        (adjacent_address, PAGE_SIZE + 1),
        (STACK_GUARD_START, PAGE_SIZE),
        (STACK_BOTTOM, PAGE_SIZE),
        (STACK_TOP - PAGE_SIZE, PAGE_SIZE),
    ] {
        let bytes = image(&[load(5, 0, address, 1, memory_size)], address, 0x1000);
        assert!(elf::plan(&bytes, &mut output).is_err());
    }
}

#[test]
fn entry_and_output_capacity_are_checked() {
    let image = valid();
    let mut short = [empty_segment(); 1];
    assert_eq!(
        elf::plan(&image, &mut short),
        Err(ElfError::OutputTooSmall {
            required: 2,
            supplied: 1
        })
    );

    let mut output = [empty_segment(); MAX_LOAD_SEGMENTS];
    let bytes = image_with_entry(0);
    assert_eq!(
        elf::plan(&bytes, &mut output),
        Err(ElfError::ZeroEntryPoint)
    );
    let bytes = image_with_entry(0x402000);
    assert_eq!(
        elf::plan(&bytes, &mut output),
        Err(ElfError::EntryPointOutsideExecutableSegment)
    );
}

fn image_with_entry(entry: u64) -> Vec<u8> {
    let mut bytes = valid();
    put64(&mut bytes, 24, entry);
    bytes
}

fn empty_segment() -> LoadSegment {
    LoadSegment {
        header_index: 0,
        file_offset: 0,
        file_size: 0,
        memory_size: 0,
        virtual_address: 0,
        mapping_start: 0,
        mapping_size: 0,
        leading_bytes: 0,
        protection: SegmentProtection::Read,
    }
}

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
