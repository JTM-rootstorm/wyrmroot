use wyrmroot_loader::{
    elf::{
        LoadSegment, PAGE_SIZE, ProgramHeaderTable, STACK_BOTTOM, STACK_BYTES, STACK_GUARD_BYTES,
        STACK_GUARD_START, STACK_TOP, SegmentProtection,
    },
    image::{
        AT_ENTRY, AT_PAGESZ, AT_PHDR, AT_PHENT, AT_PHNUM, INITIAL_STACK, INITIAL_STACK_POINTER,
        ImageAuxv, MaterializationPlan, STARTUP_V2_BLOCK_ADDRESS, STARTUP_V2_BLOCK_BYTES,
        StartupBlockError, write_startup_block, write_startup_block_v2,
    },
};

#[test]
fn materialization_preserves_checked_segment_layout() {
    let plan = MaterializationPlan::from(LoadSegment {
        header_index: 3,
        file_offset: 0x123,
        file_size: 0x456,
        memory_size: 0x789,
        virtual_address: 0x401123,
        mapping_start: 0x401000,
        mapping_size: 0x1000,
        leading_bytes: 0x123,
        protection: SegmentProtection::ReadExecute,
    });
    assert_eq!(plan.object_size, 0x1000);
    assert_eq!(plan.source_offset, 0x123);
    assert_eq!(plan.source_size, 0x456);
    assert_eq!(plan.destination_offset, 0x123);
    assert_eq!(plan.child_address, 0x401000);
    assert_eq!(plan.protection, SegmentProtection::ReadExecute);
}

#[test]
fn fixed_stack_and_startup_block_match_the_contract() {
    assert_eq!(STACK_BYTES, 128 * 1024);
    assert_eq!(INITIAL_STACK.object_size, STACK_BYTES);
    assert_eq!(INITIAL_STACK.child_address, STACK_BOTTOM);
    assert_eq!(STACK_GUARD_BYTES, PAGE_SIZE);
    assert_eq!(STACK_GUARD_START + STACK_GUARD_BYTES, STACK_BOTTOM);
    assert_eq!(INITIAL_STACK.startup_page_offset, STACK_BYTES - PAGE_SIZE);
    assert_eq!(INITIAL_STACK.stack_pointer, STACK_TOP - PAGE_SIZE);
    assert_eq!(INITIAL_STACK.stack_pointer - STACK_BOTTOM, 124 * 1024);
    assert_eq!(STARTUP_V2_BLOCK_ADDRESS - STACK_BOTTOM, 108 * 1024);

    let mut page = [0xaa; PAGE_SIZE as usize];
    write_startup_block(&mut page, INITIAL_STACK_POINTER, "/system/init0").unwrap();
    assert_eq!(get64(&page, 0), 1);
    assert_eq!(get64(&page, 8), INITIAL_STACK_POINTER + 48);
    assert_eq!(&page[48..61], b"/system/init0");
    assert_eq!(page[61], 0);
    assert!(page[16..48].iter().all(|byte| *byte == 0));
    assert!(page[62..].iter().all(|byte| *byte == 0));
}

#[test]
fn startup_block_rejects_invalid_inputs_without_partial_writes() {
    let mut wrong = [0xaa; 64];
    assert_eq!(
        write_startup_block(&mut wrong, 0, "x"),
        Err(StartupBlockError::PageSize)
    );
    assert!(wrong.iter().all(|byte| *byte == 0xaa));

    let mut page = [0xaa; PAGE_SIZE as usize];
    assert_eq!(
        write_startup_block(&mut page, 0, ""),
        Err(StartupBlockError::EmptyDisplayPath)
    );
    assert_eq!(
        write_startup_block(&mut page, 0, "a\0b"),
        Err(StartupBlockError::DisplayPathContainsNul)
    );
    let long = "x".repeat(PAGE_SIZE as usize);
    assert_eq!(
        write_startup_block(&mut page, 0, &long),
        Err(StartupBlockError::DisplayPathTooLong)
    );
    assert!(page.iter().all(|byte| *byte == 0xaa));
}

#[test]
fn startup_v2_uses_five_pages_and_canonical_vectors() {
    let mut block = [0xaa; STARTUP_V2_BLOCK_BYTES];
    write_startup_block_v2(
        &mut block,
        STARTUP_V2_BLOCK_ADDRESS,
        "bin/hello",
        &["bin/hello", "kobold"],
        &["MODE=gate"],
        &NO_TABLE,
    )
    .unwrap();
    assert_eq!(get64(&block, 0), 2);
    // argc, two argv words and NULL, one envp word and NULL, then AT_PAGESZ,
    // AT_ENTRY and the terminal pair: strings start at word 12.
    assert_eq!(get64(&block, 8), STARTUP_V2_BLOCK_ADDRESS + 96);
    let auxv: Vec<u64> = (6..12).map(|word| get64(&block, word * 8)).collect();
    assert_eq!(auxv, [AT_PAGESZ, 4096, AT_ENTRY, 0x40_0080, 0, 0]);
    assert_eq!(&block[96..106], b"bin/hello\0");
    assert_eq!(&block[106..113], b"kobold\0");
    assert_eq!(&block[113..123], b"MODE=gate\0");
    // argv[0] need not be the path, but it may not hold a NUL either.
    let mut other = vec![0_u8; block.len()];
    write_startup_block_v2(
        &mut other,
        STARTUP_V2_BLOCK_ADDRESS,
        "bin/hello",
        &["hello"],
        &[],
        &NO_TABLE,
    )
    .unwrap();
    assert_eq!(get64(&other, 0), 1);
    let argv0 = (get64(&other, 8) - STARTUP_V2_BLOCK_ADDRESS) as usize;
    assert_eq!(&other[argv0..argv0 + 6], b"hello\0");
    for (argv, environment) in [
        (["bad\0argv0"].as_slice(), [].as_slice()),
        (
            ["bin/hello", "bad\0arg"].as_slice(),
            ["MODE=gate"].as_slice(),
        ),
        (["bin/hello"].as_slice(), ["MODE=bad\0value"].as_slice()),
    ] {
        assert_eq!(
            write_startup_block_v2(
                &mut block,
                STARTUP_V2_BLOCK_ADDRESS,
                "bin/hello",
                argv,
                environment,
                &NO_TABLE,
            ),
            Err(StartupBlockError::StringContainsNul)
        );
    }
}

/// An image whose program headers no PT_LOAD maps.
const NO_TABLE: ImageAuxv = ImageAuxv {
    entry: 0x40_0080,
    program_headers: None,
};

/// W2: a mapped program-header table adds `AT_PHDR`, `AT_PHENT` and
/// `AT_PHNUM` ahead of `AT_PAGESZ` and `AT_ENTRY`.
#[test]
fn startup_v2_auxv_names_the_mapped_program_headers() {
    let auxv = ImageAuxv {
        entry: 0x40_1000,
        program_headers: Some(ProgramHeaderTable {
            address: 0x40_0040,
            count: 4,
        }),
    };
    let mut block = [0xaa; STARTUP_V2_BLOCK_BYTES];
    write_startup_block_v2(
        &mut block,
        STARTUP_V2_BLOCK_ADDRESS,
        "bin/c",
        &["bin/c"],
        &[],
        &auxv,
    )
    .unwrap();
    // argc, argv[0], NULL, envp NULL, five pairs and the terminal pair.
    let words: Vec<u64> = (4..16).map(|word| get64(&block, word * 8)).collect();
    assert_eq!(
        words,
        [
            AT_PHDR, 0x40_0040, AT_PHENT, 56, AT_PHNUM, 4, AT_PAGESZ, 4096, AT_ENTRY, 0x40_1000, 0,
            0
        ]
    );
    assert_eq!(get64(&block, 8), STARTUP_V2_BLOCK_ADDRESS + 16 * 8);
    assert_eq!(&block[128..134], b"bin/c\0");
}

fn get64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
