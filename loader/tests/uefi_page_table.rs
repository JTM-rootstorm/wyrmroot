#[path = "../src/uefi_page_table.rs"]
mod uefi_page_table;

use deepwyrm_abi::{
    DW_BOOT_X86_64_PAGING_HANDOFF_LAYOUT_VERSION,
    DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT, DW_BOOT_X86_64_PAGING_HANDOFF_PD_INDEX,
    DW_BOOT_X86_64_PAGING_HANDOFF_PDPT_INDEX, DW_BOOT_X86_64_PAGING_HANDOFF_PML4_INDEX,
    DW_BOOT_X86_64_PAGING_HANDOFF_PT_INDEX, DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAME_STRIDE,
    DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAMES_OFFSET,
    DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS, DW_BOOT_X86_64_PAGING_HANDOFF_V1_SIZE,
    DW_BOOT_X86_64_PAGING_HANDOFF_V1_VERSION, DwBootX86_64PagingHandoffV1,
};
use uefi_page_table::{PAGE_BYTES, UefiPageTable, UefiPageTableError};
use wyrmroot_efi_loader::kernel_elf::{KernelLoadSegment, SegmentPermissions};
use wyrmroot_efi_loader::transition::{
    AllocationLifetime, IdentityMapInputs, KernelMaterialization, KernelSegmentPages, MappingKind,
    MappingPermissions, RetainedPhysicalRange, TemporaryMappingReservation, TransitionMapping,
    TransitionPageTable, TransitionPolicy, TransitionPreflightInput, confirm_exit_boot_services,
    finalize_transition, populate_page_table, preflight_transition,
};

const RETAINED: AllocationLifetime = AllocationLifetime::RetainedUntilKernelPageTableReplacement;
const PHYSICAL_ADDRESS_BITS: u8 = 48;

fn capacity_pages() -> Vec<[u64; 512]> {
    vec![[0_u64; 512]; DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT as usize]
}

fn temporary() -> TemporaryMappingReservation {
    TemporaryMappingReservation {
        virtual_address: DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS,
        indices: [
            DW_BOOT_X86_64_PAGING_HANDOFF_PML4_INDEX,
            DW_BOOT_X86_64_PAGING_HANDOFF_PDPT_INDEX,
            DW_BOOT_X86_64_PAGING_HANDOFF_PD_INDEX,
            DW_BOOT_X86_64_PAGING_HANDOFF_PT_INDEX,
        ],
    }
}

const EMPTY_MATERIALIZATION: KernelMaterialization = KernelMaterialization {
    program_header_index: 0,
    allocation: RetainedPhysicalRange {
        physical_start: 0,
        byte_len: 0,
        lifetime: RETAINED,
    },
    file_offset: 0,
    file_size: 0,
    copy_destination: 0,
};

fn retained(physical_start: u64, byte_len: u64) -> RetainedPhysicalRange {
    RetainedPhysicalRange {
        physical_start,
        byte_len,
        lifetime: RETAINED,
    }
}

fn planned_transition<'a>(
    mappings: &'a mut [TransitionMapping],
    materializations: &'a mut [KernelMaterialization],
) -> wyrmroot_efi_loader::transition::TransitionPlan<'a> {
    let kernel = [KernelSegmentPages {
        segment: KernelLoadSegment {
            program_header_index: 0,
            file_offset: 0,
            file_size: PAGE_BYTES,
            virtual_address: 0xffff_8000_0020_0000,
            mapping_virtual_address: 0xffff_8000_0020_0000,
            mapping_byte_len: PAGE_BYTES,
            segment_page_offset: 0,
            memory_size: PAGE_BYTES,
            alignment: PAGE_BYTES,
            permissions: SegmentPermissions {
                read: true,
                write: false,
                execute: true,
            },
        },
        pages: retained(0x100000, PAGE_BYTES),
    }];
    let modules = [retained(0x204000, PAGE_BYTES)];
    let input = TransitionPreflightInput {
        policy: TransitionPolicy {
            mapping_granule: PAGE_BYTES,
            rsdp_max_intersecting_pages: 2,
            transition_stack_size: PAGE_BYTES,
            transition_stack_alignment: PAGE_BYTES,
            stack_pointer_alignment: 16,
            boot_info_alignment: 8,
        },
        kernel_entry: 0xffff_8000_0020_0000,
        kernel_image_byte_len: PAGE_BYTES,
        kernel_segments: &kernel,
        identity: IdentityMapInputs {
            boot_info: retained(0x200000, PAGE_BYTES),
            memory_map_table: retained(0x201000, PAGE_BYTES),
            module_table: retained(0x202000, PAGE_BYTES),
            module_data: &modules,
            command_line: None,
            entropy: None,
            validated_rsdp: None,
            handoff_stub: retained(0x205000, PAGE_BYTES),
            handoff_stub_entry: 0x205000,
            transition_stack: retained(0x206000, PAGE_BYTES),
            framebuffer_pixels: None,
        },
    };
    let preflight = preflight_transition(&input, mappings, materializations).unwrap();
    finalize_transition(
        preflight,
        retained(
            0x400000,
            u64::from(DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT) * PAGE_BYTES,
        ),
    )
    .unwrap()
}

fn mapping(
    virtual_start: u64,
    physical_start: u64,
    byte_len: u64,
    writable: bool,
    executable: bool,
) -> TransitionMapping {
    TransitionMapping {
        kind: MappingKind::BootInfo,
        virtual_start,
        physical_start,
        byte_len,
        permissions: MappingPermissions {
            writable,
            executable,
        },
        lifetime: RETAINED,
    }
}

fn leaf_location(table: &UefiPageTable<'_>, virtual_address: u64) -> (usize, usize) {
    let indices = [
        ((virtual_address >> 39) & 0x1ff) as usize,
        ((virtual_address >> 30) & 0x1ff) as usize,
        ((virtual_address >> 21) & 0x1ff) as usize,
        ((virtual_address >> 12) & 0x1ff) as usize,
    ];
    let address_mask = ((1_u64 << PHYSICAL_ADDRESS_BITS) - 1) & !(PAGE_BYTES - 1);
    let mut page_index = 0usize;
    for index in &indices[..3] {
        let entry = table.raw_entry_for_test(page_index, *index).unwrap();
        page_index = usize::try_from((entry & address_mask) - 0x400000).unwrap()
            / usize::try_from(PAGE_BYTES).unwrap();
    }
    (page_index, indices[3])
}

#[test]
fn maps_identity_and_canonical_high_pages_with_exact_permissions() {
    let mut pages = capacity_pages();
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    table.leave_page_zero_unmapped(PAGE_BYTES).unwrap();
    table.reserve_temporary_mapping(temporary()).unwrap();
    table
        .map(mapping(0x2000, 0x2000, PAGE_BYTES, true, false))
        .unwrap();
    table
        .map(mapping(
            0xffff_8000_0040_0000,
            0x500000,
            PAGE_BYTES,
            false,
            true,
        ))
        .unwrap();

    assert_eq!(table.cr3_root_physical(), 0x400000);
    assert_eq!(table.used_page_count(), 10);
    assert_eq!(
        table.translate(0x2345),
        Some(uefi_page_table::Translation {
            physical_address: 0x2345,
            writable: true,
            executable: false,
        })
    );
    assert_eq!(
        table.translate(0xffff_8000_0040_0037),
        Some(uefi_page_table::Translation {
            physical_address: 0x500037,
            writable: false,
            executable: true,
        })
    );
}

#[test]
fn page_zero_stays_absent_and_cannot_be_mapped() {
    let mut pages = capacity_pages();
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    table.leave_page_zero_unmapped(PAGE_BYTES).unwrap();
    assert_eq!(table.translate(0), None);
    assert_eq!(
        table.map(mapping(0, 0x2000, PAGE_BYTES, false, false)),
        Err(UefiPageTableError::PageZeroMappingForbidden)
    );
    assert_eq!(table.translate(0), None);
}

#[test]
fn rejects_duplicate_conflicting_and_invalid_physical_mappings() {
    let mut pages = capacity_pages();
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    table.leave_page_zero_unmapped(PAGE_BYTES).unwrap();
    let original = mapping(0x2000, 0x600000, PAGE_BYTES, false, true);
    table.map(original).unwrap();
    assert_eq!(
        table.map(original),
        Err(UefiPageTableError::DuplicateMapping)
    );
    assert_eq!(
        table.map(mapping(0x2000, 0x700000, PAGE_BYTES, false, true)),
        Err(UefiPageTableError::MappingConflict)
    );
    assert_eq!(
        table.map(mapping(
            0x3000,
            1_u64 << PHYSICAL_ADDRESS_BITS,
            PAGE_BYTES,
            false,
            false
        )),
        Err(UefiPageTableError::PhysicalAddressInvalid)
    );
}

#[test]
fn rejects_nonzero_storage_and_accepts_bounded_growth() {
    let mut nonzero = capacity_pages();
    nonzero[0][0] = 1;
    assert!(matches!(
        UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut nonzero),
        Err(UefiPageTableError::StorageNotZeroed)
    ));

    let mut pages = capacity_pages();
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    table.leave_page_zero_unmapped(PAGE_BYTES).unwrap();
    assert_eq!(
        table.map(mapping(0x2000, 0x2000, PAGE_BYTES, false, false)),
        Ok(())
    );
}

#[test]
fn rejects_noncanonical_and_unaligned_requests() {
    let mut pages = capacity_pages();
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    table.leave_page_zero_unmapped(PAGE_BYTES).unwrap();
    assert_eq!(
        table.map(mapping(
            0x0000_8000_0000_0000,
            0x2000,
            PAGE_BYTES,
            false,
            false
        )),
        Err(UefiPageTableError::VirtualAddressNonCanonical)
    );
    assert_eq!(
        table.map(mapping(
            0x0001_0000_0000_0000,
            0x2000,
            PAGE_BYTES,
            false,
            false
        )),
        Err(UefiPageTableError::VirtualAddressNonCanonical)
    );
    assert_eq!(
        table.map(mapping(0x2001, 0x2000, PAGE_BYTES, false, false)),
        Err(UefiPageTableError::MappingUnaligned)
    );
    assert_eq!(
        table.map(mapping(
            0x0000_7fff_ffff_f000,
            0x3000,
            PAGE_BYTES * 2,
            false,
            false,
        )),
        Err(UefiPageTableError::MappingSpansCanonicalHole)
    );
}

#[test]
fn requires_valid_physical_address_width_and_exact_table_consumption() {
    let mut pages = capacity_pages();
    assert!(matches!(
        UefiPageTable::new(0x400000, 11, &mut pages),
        Err(UefiPageTableError::PhysicalAddressBitsInvalid)
    ));

    let mut pages = capacity_pages();
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    table.leave_page_zero_unmapped(PAGE_BYTES).unwrap();
    table.reserve_temporary_mapping(temporary()).unwrap();
    table
        .map(mapping(0x2000, 0x2000, PAGE_BYTES, false, false))
        .unwrap();
}

#[test]
fn requires_generated_capacity_and_rejects_the_reserved_temporary_leaf() {
    let mut undersized = [[0_u64; 512]; 1];
    assert!(matches!(
        UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut undersized),
        Err(UefiPageTableError::CapacityLengthMismatch)
    ));

    let mut pages = capacity_pages();
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    table.leave_page_zero_unmapped(PAGE_BYTES).unwrap();
    table.reserve_temporary_mapping(temporary()).unwrap();
    assert_eq!(table.translate(temporary().virtual_address), None);
    assert_eq!(
        table.map(mapping(
            temporary().virtual_address,
            0x900000,
            PAGE_BYTES,
            true,
            false,
        )),
        Err(UefiPageTableError::TemporaryMappingConflict)
    );
    assert_eq!(
        table.map(mapping(
            temporary().virtual_address + PAGE_BYTES,
            0x901000,
            PAGE_BYTES,
            true,
            false,
        )),
        Err(UefiPageTableError::TemporaryMappingConflict)
    );

    let mut pages = capacity_pages();
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    table.leave_page_zero_unmapped(PAGE_BYTES).unwrap();
    table
        .map(mapping(
            temporary().virtual_address + PAGE_BYTES,
            0x901000,
            PAGE_BYTES,
            true,
            false,
        ))
        .unwrap();
    assert_eq!(
        table.reserve_temporary_mapping(temporary()),
        Err(UefiPageTableError::TemporaryMappingConflict)
    );
}

#[test]
fn consuming_attestation_binds_graph_temp_path_and_plan() {
    let mut mappings = [mapping(0, 0, 0, false, false); 16];
    let mut materializations = [EMPTY_MATERIALIZATION; 1];
    let plan = planned_transition(&mut mappings, &mut materializations);
    let mut pages = capacity_pages();
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    let post_exit = confirm_exit_boot_services(true).unwrap();
    populate_page_table(&plan, post_exit, &mut table).unwrap();
    assert_eq!(
        u64::try_from(table.used_page_count()).unwrap(),
        plan.used_page_table_page_count()
    );
    assert_eq!(table.translate(temporary().virtual_address), None);
    let identity = plan.table_identity_mapping();
    assert_eq!(
        table.translate(identity.virtual_start),
        Some(uefi_page_table::Translation {
            physical_address: identity.physical_start,
            writable: true,
            executable: false,
        })
    );

    let attestation = table.attest(&plan).unwrap();
    assert_eq!(attestation.root_physical(), 0x400000);
    assert_eq!(attestation.physical_address_width(), 48);
    assert_eq!(
        u64::from(attestation.used_page_count()),
        plan.used_page_table_page_count()
    );
    let path = attestation.temporary_path_frames();
    assert_eq!(path[0], 0x400000);
    assert!(path.windows(2).all(|pair| pair[0] != pair[1]));
    let frames = (0..attestation.used_page_count())
        .map(|index| attestation.table_frame_physical(index).unwrap())
        .collect::<Vec<_>>();
    assert!(
        frames
            .windows(2)
            .all(|pair| pair[1] - pair[0] == PAGE_BYTES)
    );
    assert_eq!(
        attestation.table_frame_physical(attestation.used_page_count()),
        None
    );

    let mut header = DwBootX86_64PagingHandoffV1::default();
    let mut encoded_frames = vec![0_u64; attestation.used_page_count() as usize];
    let byte_len = attestation
        .write_carrier(&mut header, &mut encoded_frames)
        .unwrap();
    assert_eq!(header.size, DW_BOOT_X86_64_PAGING_HANDOFF_V1_SIZE);
    assert_eq!(header.version, DW_BOOT_X86_64_PAGING_HANDOFF_V1_VERSION);
    assert_eq!(header.flags.0, 0);
    assert_eq!(
        header.physical_address_width,
        u32::from(PHYSICAL_ADDRESS_BITS)
    );
    assert_eq!(header.cr3_root_physical, attestation.root_physical());
    assert_eq!(
        header.table_frames_offset,
        DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAMES_OFFSET
    );
    assert_eq!(header.table_frame_count, attestation.used_page_count());
    assert_eq!(
        header.table_frame_stride,
        DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAME_STRIDE
    );
    assert_eq!(header.total_byte_len, byte_len);
    assert_eq!(
        header.paging_layout_version,
        DW_BOOT_X86_64_PAGING_HANDOFF_LAYOUT_VERSION
    );
    assert_eq!(header.reserved0, 0);
    assert_eq!(
        header.temporary_virtual_address,
        temporary().virtual_address
    );
    assert_eq!(
        [
            header.pml4_index,
            header.pdpt_index,
            header.pd_index,
            header.pt_index
        ],
        temporary().indices
    );
    assert_eq!(
        [
            header.temporary_pdpt_frame_physical,
            header.temporary_pd_frame_physical,
            header.temporary_pt_frame_physical
        ],
        path[1..]
    );
    assert_eq!(header.reserved, [0; 3]);
    assert_eq!(encoded_frames, frames);
    assert_eq!(
        byte_len,
        DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAMES_OFFSET
            + attestation.used_page_count() * DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAME_STRIDE
    );
    assert_eq!(
        attestation.write_carrier(&mut header, &mut encoded_frames[..1]),
        Err(UefiPageTableError::CarrierFrameCountMismatch)
    );
}

#[test]
fn attestation_rejects_encoder_base_that_differs_from_the_plan() {
    let mut mappings = [mapping(0, 0, 0, false, false); 16];
    let mut materializations = [EMPTY_MATERIALIZATION; 1];
    let plan = planned_transition(&mut mappings, &mut materializations);
    let mut pages = capacity_pages();
    let mut table = UefiPageTable::new(0x800000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    populate_page_table(&plan, confirm_exit_boot_services(true).unwrap(), &mut table).unwrap();
    assert!(matches!(
        table.attest(&plan),
        Err(UefiPageTableError::StoragePhysicalAddressInvalid)
    ));
}

#[test]
fn attestation_rejects_unreachable_tables_and_forbidden_intermediate_flags() {
    let mut mappings = [mapping(0, 0, 0, false, false); 16];
    let mut materializations = [EMPTY_MATERIALIZATION; 1];
    let plan = planned_transition(&mut mappings, &mut materializations);
    let mut pages = capacity_pages();
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    populate_page_table(&plan, confirm_exit_boot_services(true).unwrap(), &mut table).unwrap();
    *table.raw_entry_mut_for_test(0, 0).unwrap() = 0;
    assert!(matches!(
        table.attest(&plan),
        Err(UefiPageTableError::UnreachableUsedTable)
    ));

    let mut mappings = [mapping(0, 0, 0, false, false); 16];
    let mut materializations = [EMPTY_MATERIALIZATION; 1];
    let plan = planned_transition(&mut mappings, &mut materializations);
    let mut pages = capacity_pages();
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    populate_page_table(&plan, confirm_exit_boot_services(true).unwrap(), &mut table).unwrap();
    *table
        .raw_entry_mut_for_test(0, usize::from(temporary().indices[0]))
        .unwrap() |= 1 << 2;
    assert!(matches!(
        table.attest(&plan),
        Err(UefiPageTableError::IntermediateEntryFlagsInvalid)
    ));
}

#[test]
fn attestation_rejects_temp_leaf_unused_tail_and_shared_graph() {
    let mut mappings = [mapping(0, 0, 0, false, false); 16];
    let mut materializations = [EMPTY_MATERIALIZATION; 1];
    let plan = planned_transition(&mut mappings, &mut materializations);
    let mut pages = capacity_pages();
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    populate_page_table(&plan, confirm_exit_boot_services(true).unwrap(), &mut table).unwrap();
    let temp_pages = table.temporary_page_indices_for_test().unwrap();
    *table
        .raw_entry_mut_for_test(temp_pages[3], usize::from(temporary().indices[3]))
        .unwrap() = 0x900000 | 1;
    assert!(matches!(
        table.attest(&plan),
        Err(UefiPageTableError::TemporaryLeafNotZero)
    ));

    let mut mappings = [mapping(0, 0, 0, false, false); 16];
    let mut materializations = [EMPTY_MATERIALIZATION; 1];
    let plan = planned_transition(&mut mappings, &mut materializations);
    let mut pages = capacity_pages();
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    populate_page_table(&plan, confirm_exit_boot_services(true).unwrap(), &mut table).unwrap();
    let unused = usize::try_from(plan.used_page_table_page_count()).unwrap();
    *table.raw_entry_mut_for_test(unused, 0).unwrap() = 1;
    assert!(matches!(
        table.attest(&plan),
        Err(UefiPageTableError::UnusedCapacityDirty)
    ));

    let mut mappings = [mapping(0, 0, 0, false, false); 16];
    let mut materializations = [EMPTY_MATERIALIZATION; 1];
    let plan = planned_transition(&mut mappings, &mut materializations);
    let mut pages = capacity_pages();
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    populate_page_table(&plan, confirm_exit_boot_services(true).unwrap(), &mut table).unwrap();
    let temp_child = table.temporary_page_indices_for_test().unwrap()[1];
    *table.raw_entry_mut_for_test(0, 509).unwrap() =
        (0x400000 + u64::try_from(temp_child).unwrap() * PAGE_BYTES) | 3;
    assert!(matches!(
        table.attest(&plan),
        Err(UefiPageTableError::SharedOrCyclicTable)
    ));

    let mut mappings = [mapping(0, 0, 0, false, false); 16];
    let mut materializations = [EMPTY_MATERIALIZATION; 1];
    let plan = planned_transition(&mut mappings, &mut materializations);
    let mut pages = capacity_pages();
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    populate_page_table(&plan, confirm_exit_boot_services(true).unwrap(), &mut table).unwrap();
    let identity = plan.table_identity_mapping();
    let (page_index, leaf_index) = leaf_location(&table, identity.virtual_start);
    *table
        .raw_entry_mut_for_test(page_index, leaf_index)
        .unwrap() |= 1 << 8;
    assert!(matches!(
        table.attest(&plan),
        Err(UefiPageTableError::LeafPlanMismatch)
    ));

    let mut mappings = [mapping(0, 0, 0, false, false); 16];
    let mut materializations = [EMPTY_MATERIALIZATION; 1];
    let plan = planned_transition(&mut mappings, &mut materializations);
    let mut pages = capacity_pages();
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    populate_page_table(&plan, confirm_exit_boot_services(true).unwrap(), &mut table).unwrap();
    let unused = plan.used_page_table_page_count();
    *table.raw_entry_mut_for_test(0, 0).unwrap() = (0x400000 + unused * PAGE_BYTES) | 3;
    assert!(matches!(
        table.attest(&plan),
        Err(UefiPageTableError::ReachableUnusedCapacity)
    ));
}

#[test]
fn attestation_rejects_cycles_missing_extra_nonpresent_and_cache_flag_bits() {
    for bit in [2_u8, 3, 4, 5, 6, 7, 8] {
        let mut mappings = [mapping(0, 0, 0, false, false); 16];
        let mut materializations = [EMPTY_MATERIALIZATION; 1];
        let plan = planned_transition(&mut mappings, &mut materializations);
        let mut pages = capacity_pages();
        let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
        populate_page_table(&plan, confirm_exit_boot_services(true).unwrap(), &mut table).unwrap();
        *table
            .raw_entry_mut_for_test(0, usize::from(temporary().indices[0]))
            .unwrap() |= 1 << bit;
        assert!(matches!(
            table.attest(&plan),
            Err(UefiPageTableError::IntermediateEntryFlagsInvalid)
        ));
    }

    for bit in [2_u8, 3, 4, 5, 6, 7, 8] {
        let mut mappings = [mapping(0, 0, 0, false, false); 16];
        let mut materializations = [EMPTY_MATERIALIZATION; 1];
        let plan = planned_transition(&mut mappings, &mut materializations);
        let mut pages = capacity_pages();
        let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
        populate_page_table(&plan, confirm_exit_boot_services(true).unwrap(), &mut table).unwrap();
        let identity = plan.table_identity_mapping();
        let (page_index, leaf_index) = leaf_location(&table, identity.virtual_start);
        *table
            .raw_entry_mut_for_test(page_index, leaf_index)
            .unwrap() |= 1 << bit;
        assert!(matches!(
            table.attest(&plan),
            Err(UefiPageTableError::LeafPlanMismatch)
        ));
    }

    let mut mappings = [mapping(0, 0, 0, false, false); 16];
    let mut materializations = [EMPTY_MATERIALIZATION; 1];
    let plan = planned_transition(&mut mappings, &mut materializations);
    let mut pages = capacity_pages();
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    populate_page_table(&plan, confirm_exit_boot_services(true).unwrap(), &mut table).unwrap();
    *table.raw_entry_mut_for_test(0, 509).unwrap() = 0x400000 | 3;
    assert!(matches!(
        table.attest(&plan),
        Err(UefiPageTableError::SharedOrCyclicTable)
    ));

    let mut mappings = [mapping(0, 0, 0, false, false); 16];
    let mut materializations = [EMPTY_MATERIALIZATION; 1];
    let plan = planned_transition(&mut mappings, &mut materializations);
    let mut pages = capacity_pages();
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    populate_page_table(&plan, confirm_exit_boot_services(true).unwrap(), &mut table).unwrap();
    *table.raw_entry_mut_for_test(0, 509).unwrap() = 1 << 9;
    assert!(matches!(
        table.attest(&plan),
        Err(UefiPageTableError::NonPresentEntryNotZero)
    ));

    let mut mappings = [mapping(0, 0, 0, false, false); 16];
    let mut materializations = [EMPTY_MATERIALIZATION; 1];
    let plan = planned_transition(&mut mappings, &mut materializations);
    let mut pages = capacity_pages();
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    populate_page_table(&plan, confirm_exit_boot_services(true).unwrap(), &mut table).unwrap();
    let temp_pt = table.temporary_page_indices_for_test().unwrap()[3];
    *table.raw_entry_mut_for_test(temp_pt, 1).unwrap() = 0x900000 | 1 | (1 << 63);
    assert!(matches!(
        table.attest(&plan),
        Err(UefiPageTableError::UnexpectedLeaf)
    ));

    let mut mappings = [mapping(0, 0, 0, false, false); 16];
    let mut materializations = [EMPTY_MATERIALIZATION; 1];
    let plan = planned_transition(&mut mappings, &mut materializations);
    let mut pages = capacity_pages();
    let mut table = UefiPageTable::new(0x400000, PHYSICAL_ADDRESS_BITS, &mut pages).unwrap();
    populate_page_table(&plan, confirm_exit_boot_services(true).unwrap(), &mut table).unwrap();
    let identity = plan.table_identity_mapping();
    let (page_index, leaf_index) = leaf_location(&table, identity.virtual_start);
    *table
        .raw_entry_mut_for_test(page_index, leaf_index)
        .unwrap() = 0;
    assert!(matches!(
        table.attest(&plan),
        Err(UefiPageTableError::MissingLeaf)
    ));
}
