use wyrmroot_loader::{
    elf::{LoadSegment, PAGE_SIZE, STACK_BYTES, STACK_TOP, SegmentProtection},
    image::{
        INITIAL_STACK, INITIAL_STACK_POINTER, MaterializationPlan, StartupBlockError,
        write_startup_block,
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
    assert_eq!(INITIAL_STACK.object_size, STACK_BYTES);
    assert_eq!(INITIAL_STACK.child_address, STACK_TOP - STACK_BYTES);
    assert_eq!(INITIAL_STACK.startup_page_offset, STACK_BYTES - PAGE_SIZE);
    assert_eq!(INITIAL_STACK.stack_pointer, STACK_TOP - PAGE_SIZE);

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

fn get64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
