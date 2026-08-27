use wyrmroot_loader::{
    elf::{
        LoadSegment, PAGE_SIZE, STACK_BOTTOM, STACK_BYTES, STACK_GUARD_BYTES, STACK_GUARD_START,
        STACK_TOP, SegmentProtection,
    },
    image::{
        INITIAL_STACK, INITIAL_STACK_POINTER, MaterializationPlan, STARTUP_V2_BLOCK_ADDRESS,
        STARTUP_V2_BLOCK_BYTES, StartupBlockError, write_startup_block, write_startup_block_v2,
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
    )
    .unwrap();
    assert_eq!(get64(&block, 0), 2);
    assert_eq!(get64(&block, 8), STARTUP_V2_BLOCK_ADDRESS + 64);
    assert_eq!(&block[64..74], b"bin/hello\0");
    assert_eq!(&block[74..81], b"kobold\0");
    assert_eq!(&block[81..91], b"MODE=gate\0");
    assert_eq!(
        write_startup_block_v2(
            &mut block,
            STARTUP_V2_BLOCK_ADDRESS,
            "bin/hello",
            &["wrong"],
            &[],
        ),
        Err(StartupBlockError::Argv0Mismatch)
    );
    for (argv, environment) in [
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
            ),
            Err(StartupBlockError::StringContainsNul)
        );
    }
}

fn get64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
