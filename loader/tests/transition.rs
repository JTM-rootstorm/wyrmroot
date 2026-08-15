#[path = "../src/handoff_x86_64.rs"]
mod handoff_x86_64;
#[allow(dead_code)]
#[path = "../src/kernel_elf.rs"]
mod kernel_elf;
#[path = "../src/transition.rs"]
mod transition;

use deepwyrm_abi::{
    DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT, DW_BOOT_X86_64_PAGING_HANDOFF_PD_INDEX,
    DW_BOOT_X86_64_PAGING_HANDOFF_PDPT_INDEX, DW_BOOT_X86_64_PAGING_HANDOFF_PML4_INDEX,
    DW_BOOT_X86_64_PAGING_HANDOFF_PT_INDEX,
    DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS,
};
use handoff_x86_64::{
    Com1InitializationError, Com1RegisterIo, FINAL_HANDOFF_MARKER, FinalDiagnosticError,
    PostExitDiagnosticWriter, X86_64EntryStateEvidence, X86_64HandoffError, cr4_transition,
    initialize_com1_registers, prepare_x86_64_transfer, test_page_table_attestation, verify_pat0,
    verify_x86_64_entry_state, write_final_handoff_marker,
};
use kernel_elf::{KernelLoadSegment, SegmentPermissions};
use transition::{
    AllocationLifetime, IdentityMapInputs, KernelMaterialization, KernelSegmentPages, MappingKind,
    MappingPermissions, PageTablePopulationError, PhysicalRange, RetainedPhysicalRange,
    TemporaryMappingReservation, TransitionError, TransitionInput, TransitionMapping,
    TransitionPageTable, TransitionPolicy, TransitionPreflightInput, ValidatedRsdpMappingInput,
    confirm_exit_boot_services, finalize_transition, plan_transition, populate_page_table,
    preflight_transition,
};

const GRANULE: u64 = 0x1000;
const CODE_MAPPING: u64 = 0xffff_8000_0010_0000;
const RETAINED: AllocationLifetime = AllocationLifetime::RetainedUntilKernelPageTableReplacement;
const TABLE_CAPACITY_PAGES: u64 = DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT as u64;
const TABLE_STORAGE_START: u64 = 0x400000;

const EMPTY_MAPPING: TransitionMapping = TransitionMapping {
    kind: MappingKind::BootInfo,
    physical_start: 0,
    virtual_start: 0,
    byte_len: 0,
    permissions: MappingPermissions {
        writable: false,
        executable: false,
    },
    lifetime: RETAINED,
};

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

struct Fixture {
    kernel: [KernelSegmentPages; 2],
    modules: [RetainedPhysicalRange; 2],
    framebuffer: Option<PhysicalRange>,
}

impl Fixture {
    fn new() -> Self {
        let code = KernelLoadSegment {
            program_header_index: 0,
            file_offset: 0x1800,
            file_size: 0x100,
            virtual_address: CODE_MAPPING + 0x800,
            mapping_virtual_address: CODE_MAPPING,
            mapping_byte_len: GRANULE,
            segment_page_offset: 0x800,
            memory_size: 0x700,
            alignment: GRANULE,
            permissions: SegmentPermissions {
                read: true,
                write: false,
                execute: true,
            },
        };
        let data = KernelLoadSegment {
            program_header_index: 1,
            file_offset: 0x3000,
            file_size: 0x200,
            virtual_address: CODE_MAPPING + 0x2000,
            mapping_virtual_address: CODE_MAPPING + 0x2000,
            mapping_byte_len: GRANULE,
            segment_page_offset: 0,
            memory_size: GRANULE,
            alignment: GRANULE,
            permissions: SegmentPermissions {
                read: true,
                write: true,
                execute: false,
            },
        };
        Self {
            kernel: [
                KernelSegmentPages {
                    segment: code,
                    pages: retained(0x100000, GRANULE),
                },
                KernelSegmentPages {
                    segment: data,
                    pages: retained(0x102000, GRANULE),
                },
            ],
            modules: [retained(0x203000, 0x200), retained(0x204000, 0x300)],
            framebuffer: Some(PhysicalRange {
                physical_start: 0x300000,
                byte_len: 0x100000,
            }),
        }
    }

    fn input(&self) -> TransitionInput<'_> {
        TransitionInput {
            policy: TransitionPolicy {
                mapping_granule: GRANULE,
                rsdp_max_intersecting_pages: 2,
                transition_stack_size: 0x4000,
                transition_stack_alignment: GRANULE,
                stack_pointer_alignment: 16,
                boot_info_alignment: 8,
            },
            kernel_entry: self.kernel[0].segment.virtual_address,
            kernel_image_byte_len: 0x4000,
            kernel_segments: &self.kernel,
            page_table_storage: retained(TABLE_STORAGE_START, TABLE_CAPACITY_PAGES * GRANULE),
            identity: IdentityMapInputs {
                boot_info: retained(0x200000, 312),
                memory_map_table: retained(0x201000, 0x300),
                module_table: retained(0x202000, 0x100),
                module_data: &self.modules,
                command_line: Some(retained(0x205000, 0x80)),
                entropy: Some(retained(0x206000, 0x40)),
                validated_rsdp: Some(ValidatedRsdpMappingInput {
                    retained_allocation: retained(0x207000, GRANULE),
                    record_physical_start: 0x207000,
                    record_byte_len: 0x100,
                }),
                handoff_stub: retained(0x208000, 0x100),
                handoff_stub_entry: 0x208000,
                transition_stack: retained(0x210000, 0x4000),
                framebuffer_pixels: self.framebuffer,
            },
        }
    }

    fn preflight_input(&self) -> TransitionPreflightInput<'_> {
        let input = self.input();
        TransitionPreflightInput {
            policy: input.policy,
            kernel_entry: input.kernel_entry,
            kernel_image_byte_len: input.kernel_image_byte_len,
            kernel_segments: input.kernel_segments,
            identity: input.identity,
        }
    }
}

fn retained(physical_start: u64, byte_len: u64) -> RetainedPhysicalRange {
    RetainedPhysicalRange {
        physical_start,
        byte_len,
        lifetime: RETAINED,
    }
}

#[test]
fn plans_only_reviewed_mappings_with_wx_nx_and_pre_exit_materialization() {
    let fixture = Fixture::new();
    let input = fixture.input();
    let mut mappings = [EMPTY_MAPPING; 16];
    let mut copies = [EMPTY_MATERIALIZATION; 2];

    let plan = plan_transition(&input, &mut mappings, &mut copies).unwrap();

    assert_eq!(plan.mappings().len(), 12);
    assert!(
        plan.mappings()
            .windows(2)
            .all(|pair| { pair[0].virtual_start + pair[0].byte_len <= pair[1].virtual_start })
    );
    assert!(
        plan.mappings()
            .iter()
            .all(|mapping| mapping.virtual_start != 0)
    );
    assert!(
        plan.mappings()
            .iter()
            .all(|mapping| !(mapping.permissions.writable && mapping.permissions.executable))
    );
    assert!(!plan.mappings().iter().any(|mapping| {
        mapping.physical_start < 0x400000 && 0x300000 < mapping.physical_start + mapping.byte_len
    }));

    let code = plan
        .mappings()
        .iter()
        .find(|mapping| {
            mapping.kind
                == (MappingKind::KernelSegment {
                    program_header_index: 0,
                })
        })
        .unwrap();
    assert_eq!(code.virtual_start, CODE_MAPPING);
    assert_eq!(code.physical_start, 0x100000);
    assert_eq!(
        code.permissions,
        MappingPermissions {
            writable: false,
            executable: true
        }
    );

    let stack = plan
        .mappings()
        .iter()
        .find(|mapping| mapping.kind == MappingKind::TransitionStack)
        .unwrap();
    assert_eq!(stack.byte_len, 0x4000);
    assert_eq!(
        stack.permissions,
        MappingPermissions {
            writable: true,
            executable: false
        }
    );
    assert_eq!(plan.transition_stack_pointer(), 0x214000);
    assert_eq!(plan.boot_info_identity_pointer(), 0x200000);
    assert_eq!(plan.handoff_stub_entry(), 0x208000);
    assert_eq!(
        plan.temporary_mapping(),
        TemporaryMappingReservation {
            virtual_address: DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS,
            indices: [
                DW_BOOT_X86_64_PAGING_HANDOFF_PML4_INDEX,
                DW_BOOT_X86_64_PAGING_HANDOFF_PDPT_INDEX,
                DW_BOOT_X86_64_PAGING_HANDOFF_PD_INDEX,
                DW_BOOT_X86_64_PAGING_HANDOFF_PT_INDEX,
            ],
        }
    );

    assert_eq!(plan.pre_exit().kernel_materializations.len(), 2);
    assert_eq!(
        plan.pre_exit().kernel_materializations[0].file_offset,
        0x1800
    );
    assert_eq!(
        plan.pre_exit().kernel_materializations[0].copy_destination,
        0x100800
    );
    assert_eq!(
        plan.pre_exit().kernel_materializations[0]
            .allocation
            .byte_len,
        GRANULE
    );
    assert_eq!(plan.pre_exit().page_table_page_count, TABLE_CAPACITY_PAGES);
    assert_eq!(plan.used_page_table_page_count(), 11);
    assert_eq!(
        plan.pre_exit().page_table_storage,
        retained(TABLE_STORAGE_START, TABLE_CAPACITY_PAGES * GRANULE)
    );
}

#[test]
fn preflight_sizes_before_allocation_and_matches_final_plan() {
    let fixture = Fixture::new();
    let mut preflight_mappings = [EMPTY_MAPPING; 16];
    let mut preflight_copies = [EMPTY_MATERIALIZATION; 2];
    let preflight = preflight_transition(
        &fixture.preflight_input(),
        &mut preflight_mappings,
        &mut preflight_copies,
    )
    .unwrap();

    assert_eq!(preflight.page_table_page_count(), TABLE_CAPACITY_PAGES);
    assert_eq!(preflight.minimum_page_table_page_count(), 10);
    assert_eq!(preflight.mappings().len(), 12);
    assert_eq!(preflight.kernel_materializations().len(), 2);
    let plan = finalize_transition(
        preflight,
        retained(TABLE_STORAGE_START, TABLE_CAPACITY_PAGES * GRANULE),
    )
    .unwrap();
    assert_eq!(plan.pre_exit().page_table_page_count, TABLE_CAPACITY_PAGES);
    assert_eq!(plan.used_page_table_page_count(), 11);

    let mut wrapper_mappings = [EMPTY_MAPPING; 16];
    let mut wrapper_copies = [EMPTY_MATERIALIZATION; 2];
    let wrapper =
        plan_transition(&fixture.input(), &mut wrapper_mappings, &mut wrapper_copies).unwrap();
    assert_eq!(plan.mappings(), wrapper.mappings());
    assert_eq!(
        plan.pre_exit().kernel_materializations,
        wrapper.pre_exit().kernel_materializations
    );
    assert_eq!(
        plan.pre_exit().page_table_page_count,
        wrapper.pre_exit().page_table_page_count
    );
}

#[test]
fn preflight_and_final_planning_have_adversarial_parity() {
    let fixture = Fixture::new();
    let mut mappings = [EMPTY_MAPPING; 16];
    let mut copies = [EMPTY_MATERIALIZATION; 2];

    let mut separated_kernel = fixture.kernel;
    separated_kernel[1].segment.virtual_address = CODE_MAPPING + 0x4000_0000;
    separated_kernel[1].segment.mapping_virtual_address = CODE_MAPPING + 0x4000_0000;
    let mut preflight_input = fixture.preflight_input();
    preflight_input.kernel_segments = &separated_kernel;
    let preflight = preflight_transition(&preflight_input, &mut mappings, &mut copies).unwrap();
    let minimum_page_count = preflight.minimum_page_table_page_count();
    assert!(minimum_page_count > 10);
    let page_count = preflight.page_table_page_count();
    let plan = finalize_transition(
        preflight,
        retained(
            TABLE_STORAGE_START,
            page_count.checked_mul(GRANULE).unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(plan.pre_exit().page_table_page_count, page_count);
    assert!(plan.used_page_table_page_count() >= minimum_page_count);

    let mut wrapper_input = fixture.input();
    wrapper_input.kernel_segments = &separated_kernel;
    wrapper_input.page_table_storage.byte_len = page_count * GRANULE;
    let mut wrapper_mappings = [EMPTY_MAPPING; 16];
    let mut wrapper_copies = [EMPTY_MATERIALIZATION; 2];
    let wrapper =
        plan_transition(&wrapper_input, &mut wrapper_mappings, &mut wrapper_copies).unwrap();
    assert_eq!(wrapper.pre_exit().page_table_page_count, page_count);
    assert_eq!(wrapper.mappings(), plan.mappings());

    let mut wx_kernel = fixture.kernel;
    wx_kernel[0].segment.permissions.write = true;
    let mut preflight_input = fixture.preflight_input();
    preflight_input.kernel_segments = &wx_kernel;
    assert!(matches!(
        preflight_transition(&preflight_input, &mut mappings, &mut copies),
        Err(TransitionError::WritableExecutable { .. })
    ));
    let mut wrapper_input = fixture.input();
    wrapper_input.kernel_segments = &wx_kernel;
    assert!(matches!(
        plan_transition(&wrapper_input, &mut mappings, &mut copies),
        Err(TransitionError::WritableExecutable { .. })
    ));
}

#[test]
fn fixed_point_is_bounded_and_temporary_leaf_cannot_be_planned() {
    let fixture = Fixture::new();
    let mut mappings = [EMPTY_MAPPING; 16];
    let mut copies = [EMPTY_MATERIALIZATION; 2];
    let preflight =
        preflight_transition(&fixture.preflight_input(), &mut mappings, &mut copies).unwrap();
    assert_eq!(preflight.minimum_page_table_page_count(), 10);
    let plan = finalize_transition(
        preflight,
        retained(TABLE_STORAGE_START, TABLE_CAPACITY_PAGES * GRANULE),
    )
    .unwrap();
    assert_eq!(plan.used_page_table_page_count(), 11);
    assert_eq!(
        plan.table_identity_mapping().byte_len,
        plan.used_page_table_page_count() * GRANULE
    );

    let mut adjacent_kernel = fixture.kernel;
    adjacent_kernel[0].segment.virtual_address =
        DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS + GRANULE;
    adjacent_kernel[0].segment.mapping_virtual_address =
        DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS + GRANULE;
    adjacent_kernel[0].segment.file_offset = GRANULE;
    adjacent_kernel[0].segment.segment_page_offset = 0;
    let mut input = fixture.preflight_input();
    input.kernel_segments = &adjacent_kernel;
    input.kernel_entry = adjacent_kernel[0].segment.virtual_address;
    assert_eq!(
        preflight_transition(&input, &mut mappings, &mut copies),
        Err(TransitionError::TemporaryMappingConflict {
            with: MappingKind::KernelSegment {
                program_header_index: 0,
            },
        })
    );

    let mut kernel = fixture.kernel;
    kernel[0].segment.virtual_address = DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS;
    kernel[0].segment.mapping_virtual_address =
        DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS;
    kernel[0].segment.segment_page_offset = 0;
    let mut input = fixture.preflight_input();
    input.kernel_segments = &kernel;
    input.kernel_entry = DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS;
    assert_eq!(
        preflight_transition(&input, &mut mappings, &mut copies),
        Err(TransitionError::TemporaryMappingConflict {
            with: MappingKind::KernelSegment {
                program_header_index: 0,
            },
        })
    );

    let maximum = DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT as usize;
    let mut many_kernel_segments = Vec::with_capacity(maximum);
    for index in 0..maximum {
        let index_u64 = u64::try_from(index).unwrap();
        many_kernel_segments.push(KernelSegmentPages {
            segment: KernelLoadSegment {
                program_header_index: u16::try_from(index).unwrap(),
                file_offset: index_u64 * GRANULE,
                file_size: GRANULE,
                virtual_address: CODE_MAPPING + index_u64 * 0x20_0000,
                mapping_virtual_address: CODE_MAPPING + index_u64 * 0x20_0000,
                mapping_byte_len: GRANULE,
                segment_page_offset: 0,
                memory_size: GRANULE,
                alignment: GRANULE,
                permissions: SegmentPermissions {
                    read: true,
                    write: false,
                    execute: true,
                },
            },
            pages: retained(0x1000_0000 + index_u64 * GRANULE, GRANULE),
        });
    }
    let mut input = fixture.preflight_input();
    input.kernel_segments = &many_kernel_segments;
    input.kernel_entry = CODE_MAPPING;
    input.kernel_image_byte_len = u64::try_from(maximum).unwrap() * GRANULE;
    let mut many_mappings = vec![EMPTY_MAPPING; maximum + 16];
    let mut many_copies = vec![EMPTY_MATERIALIZATION; maximum];
    assert!(matches!(
        preflight_transition(&input, &mut many_mappings, &mut many_copies),
        Err(TransitionError::PageTableFixedPointCapacityExceeded {
            maximum_pages: TABLE_CAPACITY_PAGES,
            ..
        })
    ));
}

#[test]
fn fixed_point_converges_across_pt_pd_and_pdpt_boundaries() {
    let fixture = Fixture::new();
    for (boundary, expected_used) in [
        (0x80_0000_u64, 12_u64),
        (0x4000_0000, 13),
        (0x80_0000_0000, 15),
    ] {
        let storage_start = boundary - GRANULE;
        let mut mappings = [EMPTY_MAPPING; 16];
        let mut copies = [EMPTY_MATERIALIZATION; 2];
        let preflight =
            preflight_transition(&fixture.preflight_input(), &mut mappings, &mut copies).unwrap();
        let minimum = preflight.minimum_page_table_page_count();
        let plan = finalize_transition(
            preflight,
            retained(storage_start, TABLE_CAPACITY_PAGES * GRANULE),
        )
        .unwrap();
        let identity = plan.table_identity_mapping();
        assert_eq!(identity.virtual_start, storage_start);
        assert!(identity.virtual_start < boundary);
        assert!(identity.virtual_start + identity.byte_len > boundary);
        assert!(plan.used_page_table_page_count() >= minimum);
        assert_eq!(plan.used_page_table_page_count(), expected_used);
        assert!(plan.used_page_table_page_count() <= TABLE_CAPACITY_PAGES);
    }
}

#[test]
fn preflight_does_not_claim_page_table_storage_and_finalize_rejects_aliases() {
    let fixture = Fixture::new();
    let mut mappings = [EMPTY_MAPPING; 16];
    let mut copies = [EMPTY_MATERIALIZATION; 2];
    let preflight =
        preflight_transition(&fixture.preflight_input(), &mut mappings, &mut copies).unwrap();
    let page_count = preflight.page_table_page_count();

    assert_eq!(
        finalize_transition(
            preflight,
            retained(0x200000, page_count.checked_mul(GRANULE).unwrap())
        ),
        Err(TransitionError::PageTableStorageAlias {
            with: MappingKind::BootInfo,
        })
    );
}

#[test]
fn derives_only_the_validated_rsdp_intersecting_pages() {
    let fixture = Fixture::new();
    let mut mappings = [EMPTY_MAPPING; 16];
    let mut copies = [EMPTY_MATERIALIZATION; 2];

    let plan = plan_transition(&fixture.input(), &mut mappings, &mut copies).unwrap();
    let one_page = plan
        .mappings()
        .iter()
        .find(|mapping| mapping.kind == MappingKind::RequiredAcpiRsdp)
        .unwrap();
    assert_eq!(one_page.physical_start, 0x207000);
    assert_eq!(one_page.virtual_start, 0x207000);
    assert_eq!(one_page.byte_len, GRANULE);
    assert_eq!(
        one_page.permissions,
        MappingPermissions {
            writable: false,
            executable: false,
        }
    );

    let mut input = fixture.input();
    input.identity.validated_rsdp = Some(ValidatedRsdpMappingInput {
        retained_allocation: retained(0x230000, 2 * GRANULE),
        record_physical_start: 0x230ff0,
        record_byte_len: 36,
    });
    let plan = plan_transition(&input, &mut mappings, &mut copies).unwrap();
    let coalesced = plan
        .mappings()
        .iter()
        .find(|mapping| mapping.kind == MappingKind::RequiredAcpiRsdp)
        .unwrap();
    assert_eq!(coalesced.physical_start, 0x230000);
    assert_eq!(coalesced.byte_len, 2 * GRANULE);
    assert_eq!(
        plan.mappings()
            .iter()
            .filter(|mapping| mapping.kind == MappingKind::RequiredAcpiRsdp)
            .count(),
        1
    );

    let mut input = fixture.input();
    input.identity.validated_rsdp = None;
    let plan = plan_transition(&input, &mut mappings, &mut copies).unwrap();
    assert!(
        plan.mappings()
            .iter()
            .all(|mapping| mapping.kind != MappingKind::RequiredAcpiRsdp)
    );
}

#[test]
fn rejects_rsdp_mapping_mismatch_limits_and_overflow() {
    let fixture = Fixture::new();
    let mut mappings = [EMPTY_MAPPING; 16];
    let mut copies = [EMPTY_MATERIALIZATION; 2];

    let mut input = fixture.input();
    input.identity.validated_rsdp = Some(ValidatedRsdpMappingInput {
        retained_allocation: retained(0x207000, 2 * GRANULE),
        record_physical_start: 0x207000,
        record_byte_len: 36,
    });
    assert_eq!(
        plan_transition(&input, &mut mappings, &mut copies),
        Err(TransitionError::RsdpRetainedAllocationMismatch)
    );

    let mut input = fixture.input();
    input.identity.validated_rsdp = Some(ValidatedRsdpMappingInput {
        retained_allocation: retained(0x230000, 2 * GRANULE),
        record_physical_start: 0x230ff0,
        record_byte_len: 36,
    });
    input.policy.rsdp_max_intersecting_pages = 1;
    assert_eq!(
        plan_transition(&input, &mut mappings, &mut copies),
        Err(TransitionError::RsdpMappingPageLimitExceeded {
            required_pages: 2,
            maximum_pages: 1,
        })
    );

    let mut input = fixture.input();
    input.identity.validated_rsdp = Some(ValidatedRsdpMappingInput {
        retained_allocation: retained(0x230000, 3 * GRANULE),
        record_physical_start: 0x230001,
        record_byte_len: 2 * GRANULE,
    });
    assert_eq!(
        plan_transition(&input, &mut mappings, &mut copies),
        Err(TransitionError::RsdpMappingPageLimitExceeded {
            required_pages: 3,
            maximum_pages: 2,
        })
    );

    let mut input = fixture.input();
    input.identity.validated_rsdp = Some(ValidatedRsdpMappingInput {
        retained_allocation: retained(0x207000, GRANULE),
        record_physical_start: u64::MAX - 8,
        record_byte_len: 16,
    });
    assert_eq!(
        plan_transition(&input, &mut mappings, &mut copies),
        Err(TransitionError::RsdpRecordRangeOverflow)
    );

    let mut input = fixture.input();
    input.identity.validated_rsdp = Some(ValidatedRsdpMappingInput {
        retained_allocation: retained(0x207000, GRANULE),
        record_physical_start: 0x207000,
        record_byte_len: 0,
    });
    assert_eq!(
        plan_transition(&input, &mut mappings, &mut copies),
        Err(TransitionError::InvalidRsdpRecord)
    );
}

#[test]
fn rejects_framebuffer_page_identity_mapping_or_page_table_backing() {
    let mut fixture = Fixture::new();
    fixture.framebuffer = Some(PhysicalRange {
        physical_start: 0x200800,
        byte_len: 0x100,
    });
    let mut mappings = [EMPTY_MAPPING; 16];
    let mut copies = [EMPTY_MATERIALIZATION; 2];
    assert_eq!(
        plan_transition(&fixture.input(), &mut mappings, &mut copies),
        Err(TransitionError::FramebufferPixelsWouldBeMapped {
            kind: MappingKind::BootInfo
        })
    );

    fixture.framebuffer = Some(PhysicalRange {
        physical_start: TABLE_STORAGE_START + 0x800,
        byte_len: 0x100,
    });
    assert_eq!(
        plan_transition(&fixture.input(), &mut mappings, &mut copies),
        Err(TransitionError::FramebufferPixelsWouldBackPageTables)
    );
}

#[test]
fn rejects_page_zero_overlap_alias_wx_and_released_allocations() {
    let fixture = Fixture::new();
    let mut mappings = [EMPTY_MAPPING; 16];
    let mut copies = [EMPTY_MATERIALIZATION; 2];

    let mut input = fixture.input();
    input.identity.boot_info = retained(0x800, 0x100);
    assert_eq!(
        plan_transition(&input, &mut mappings, &mut copies),
        Err(TransitionError::PageZeroWouldBeMapped {
            kind: MappingKind::BootInfo
        })
    );

    let mut kernel = fixture.kernel;
    kernel[1].pages.physical_start = kernel[0].pages.physical_start;
    let mut input = fixture.input();
    input.kernel_segments = &kernel;
    assert!(matches!(
        plan_transition(&input, &mut mappings, &mut copies),
        Err(TransitionError::PhysicalAlias { .. })
    ));

    let mut kernel = fixture.kernel;
    kernel[1].segment.mapping_virtual_address = CODE_MAPPING;
    kernel[1].segment.virtual_address = CODE_MAPPING;
    let mut input = fixture.input();
    input.kernel_segments = &kernel;
    assert!(matches!(
        plan_transition(&input, &mut mappings, &mut copies),
        Err(TransitionError::VirtualOverlap { .. })
            | Err(TransitionError::InvalidKernelSegment { .. })
    ));

    let mut kernel = fixture.kernel;
    kernel[0].segment.permissions.write = true;
    let mut input = fixture.input();
    input.kernel_segments = &kernel;
    assert!(matches!(
        plan_transition(&input, &mut mappings, &mut copies),
        Err(TransitionError::WritableExecutable { .. })
    ));

    let mut input = fixture.input();
    input.identity.entropy.as_mut().unwrap().lifetime =
        AllocationLifetime::ReleasedBeforeKernelPageTableReplacement;
    assert_eq!(
        plan_transition(&input, &mut mappings, &mut copies),
        Err(TransitionError::AllocationNotRetained {
            kind: MappingKind::Entropy
        })
    );
}

#[test]
fn rejects_bad_ranges_stack_policy_entry_sources_and_capacity() {
    let fixture = Fixture::new();
    let mut mappings = [EMPTY_MAPPING; 16];
    let mut copies = [EMPTY_MATERIALIZATION; 2];

    let mut input = fixture.input();
    input.policy.mapping_granule = 0;
    assert_eq!(
        plan_transition(&input, &mut mappings, &mut copies),
        Err(TransitionError::InvalidPolicy)
    );

    let mut input = fixture.input();
    input.page_table_storage.byte_len -= GRANULE;
    assert_eq!(
        plan_transition(&input, &mut mappings, &mut copies),
        Err(TransitionError::PageTableStorageLengthMismatch {
            required_pages: TABLE_CAPACITY_PAGES,
            provided_pages: TABLE_CAPACITY_PAGES - 1,
        })
    );

    let mut input = fixture.input();
    input.identity.transition_stack.byte_len -= GRANULE;
    assert_eq!(
        plan_transition(&input, &mut mappings, &mut copies),
        Err(TransitionError::InvalidTransitionStack)
    );

    let mut input = fixture.input();
    input.kernel_entry = input.kernel_segments[1].segment.virtual_address;
    assert_eq!(
        plan_transition(&input, &mut mappings, &mut copies),
        Err(TransitionError::KernelEntryNotExecutable)
    );

    let mut input = fixture.input();
    input.kernel_image_byte_len = 0x1800;
    assert_eq!(
        plan_transition(&input, &mut mappings, &mut copies),
        Err(TransitionError::KernelSourceOutsideImage {
            program_header_index: 0
        })
    );

    let mut input = fixture.input();
    input.identity.command_line = Some(retained(u64::MAX - 7, 16));
    assert!(matches!(
        plan_transition(&input, &mut mappings, &mut copies),
        Err(TransitionError::RangeOverflow { .. })
    ));

    let mut too_few_mappings = [EMPTY_MAPPING; 1];
    assert!(matches!(
        plan_transition(&fixture.input(), &mut too_few_mappings, &mut copies),
        Err(TransitionError::OutputTooSmall { .. })
    ));

    let mut too_few_copies = [EMPTY_MATERIALIZATION; 1];
    assert_eq!(
        plan_transition(&fixture.input(), &mut mappings, &mut too_few_copies),
        Err(TransitionError::OutputTooSmall {
            required: 2,
            available: 1
        })
    );
}

#[test]
fn rejects_noncanonical_ranges_and_ranges_crossing_the_canonical_hole() {
    let fixture = Fixture::new();
    let mut mappings = [EMPTY_MAPPING; 16];
    let mut copies = [EMPTY_MATERIALIZATION; 2];

    let mut kernel = fixture.kernel;
    kernel[0].segment.virtual_address = 0x0000_8000_0000_0000;
    kernel[0].segment.mapping_virtual_address = 0x0000_8000_0000_0000;
    kernel[0].segment.segment_page_offset = 0;
    let mut input = fixture.input();
    input.kernel_segments = &kernel;
    input.kernel_entry = kernel[0].segment.virtual_address;
    assert_eq!(
        plan_transition(&input, &mut mappings, &mut copies),
        Err(TransitionError::NonCanonicalVirtualRange {
            kind: MappingKind::KernelSegment {
                program_header_index: 0,
            },
        })
    );

    let mut kernel = fixture.kernel;
    kernel[0].segment.virtual_address = GRANULE;
    kernel[0].segment.mapping_virtual_address = GRANULE;
    kernel[0].segment.segment_page_offset = 0;
    kernel[0].segment.memory_size = 0xffff_8000_0000_0000;
    kernel[0].segment.mapping_byte_len = 0xffff_8000_0000_0000;
    kernel[0].pages.byte_len = 0xffff_8000_0000_0000;
    let mut input = fixture.input();
    input.kernel_segments = &kernel[..1];
    input.kernel_entry = GRANULE;
    assert_eq!(
        plan_transition(&input, &mut mappings, &mut copies),
        Err(TransitionError::NonCanonicalVirtualRange {
            kind: MappingKind::KernelSegment {
                program_header_index: 0,
            },
        })
    );
}

#[derive(Default)]
struct RecordingTable {
    page_zero: Vec<u64>,
    temporary: Vec<TemporaryMappingReservation>,
    mappings: Vec<TransitionMapping>,
    fail_kind: Option<MappingKind>,
}

impl TransitionPageTable for RecordingTable {
    type Error = &'static str;

    fn leave_page_zero_unmapped(&mut self, byte_len: u64) -> Result<(), Self::Error> {
        self.page_zero.push(byte_len);
        Ok(())
    }

    fn reserve_temporary_mapping(
        &mut self,
        reservation: TemporaryMappingReservation,
    ) -> Result<(), Self::Error> {
        self.temporary.push(reservation);
        Ok(())
    }

    fn map(&mut self, mapping: TransitionMapping) -> Result<(), Self::Error> {
        if self.fail_kind == Some(mapping.kind) {
            return Err("map failed");
        }
        self.mappings.push(mapping);
        Ok(())
    }
}

#[test]
fn post_exit_population_explicitly_leaves_page_zero_unmapped_and_is_fail_closed() {
    assert!(confirm_exit_boot_services(false).is_none());
    let post_exit = confirm_exit_boot_services(true).unwrap();
    let fixture = Fixture::new();
    let mut mappings = [EMPTY_MAPPING; 16];
    let mut copies = [EMPTY_MATERIALIZATION; 2];
    let plan = plan_transition(&fixture.input(), &mut mappings, &mut copies).unwrap();

    let mut table = RecordingTable::default();
    populate_page_table(&plan, post_exit, &mut table).unwrap();
    assert_eq!(table.page_zero, vec![GRANULE]);
    assert_eq!(table.temporary, vec![plan.temporary_mapping()]);
    let mut expected_mappings = plan.mappings().to_vec();
    expected_mappings.push(plan.table_identity_mapping());
    assert_eq!(table.mappings, expected_mappings);

    let mut failing = RecordingTable {
        fail_kind: Some(MappingKind::TransitionStack),
        ..RecordingTable::default()
    };
    assert_eq!(
        populate_page_table(&plan, post_exit, &mut failing),
        Err(PageTablePopulationError::Mapping {
            kind: MappingKind::TransitionStack,
            error: "map failed"
        })
    );
}

fn valid_evidence() -> X86_64EntryStateEvidence {
    X86_64EntryStateEvidence {
        exit_boot_services_complete: true,
        interrupts_disabled: true,
        cr0_write_protect: true,
        execute_disable: true,
        four_level_paging: true,
        initial_processor_is_bsp: true,
        pat0_write_back: true,
        valid_code_and_stack_segments: true,
    }
}

#[test]
fn raw_transfer_requires_verified_machine_state_and_preallocated_cr3() {
    let cases = [
        (
            X86_64EntryStateEvidence {
                exit_boot_services_complete: false,
                ..valid_evidence()
            },
            X86_64HandoffError::BootServicesStillAvailable,
        ),
        (
            X86_64EntryStateEvidence {
                interrupts_disabled: false,
                ..valid_evidence()
            },
            X86_64HandoffError::InterruptsEnabled,
        ),
        (
            X86_64EntryStateEvidence {
                cr0_write_protect: false,
                ..valid_evidence()
            },
            X86_64HandoffError::WriteProtectDisabled,
        ),
        (
            X86_64EntryStateEvidence {
                execute_disable: false,
                ..valid_evidence()
            },
            X86_64HandoffError::ExecuteDisableUnavailable,
        ),
        (
            X86_64EntryStateEvidence {
                four_level_paging: false,
                ..valid_evidence()
            },
            X86_64HandoffError::WrongPagingMode,
        ),
        (
            X86_64EntryStateEvidence {
                initial_processor_is_bsp: false,
                ..valid_evidence()
            },
            X86_64HandoffError::NotBootstrapProcessor,
        ),
        (
            X86_64EntryStateEvidence {
                pat0_write_back: false,
                ..valid_evidence()
            },
            X86_64HandoffError::Pat0NotWriteBack,
        ),
        (
            X86_64EntryStateEvidence {
                valid_code_and_stack_segments: false,
                ..valid_evidence()
            },
            X86_64HandoffError::InvalidSegmentState,
        ),
    ];
    for (evidence, expected) in cases {
        assert_eq!(verify_x86_64_entry_state(evidence), Err(expected));
    }

    let state = verify_x86_64_entry_state(valid_evidence()).unwrap();
    let fixture = Fixture::new();
    let mut mappings = [EMPTY_MAPPING; 16];
    let mut copies = [EMPTY_MATERIALIZATION; 2];
    let plan = plan_transition(&fixture.input(), &mut mappings, &mut copies).unwrap();
    let attestation = test_page_table_attestation(
        &plan,
        TABLE_STORAGE_START,
        u32::try_from(plan.used_page_table_page_count()).unwrap(),
    );
    let transfer = prepare_x86_64_transfer(attestation, state).unwrap();
    assert_eq!(
        transfer.kernel_entry(),
        fixture.kernel[0].segment.virtual_address
    );
    assert_eq!(transfer.boot_info_identity_pointer(), 0x200000);
    assert_eq!(transfer.transition_stack_pointer(), 0x214000);
    assert_eq!(transfer.page_table_root_physical(), TABLE_STORAGE_START);
    assert_eq!(transfer.handoff_stub_range(), (0x208000, 0x208100));

    assert_eq!(verify_pat0(0x0007_0406_0007_0406), Ok(()));
    assert_eq!(
        verify_pat0(0x0007_0400_0007_0400),
        Err(X86_64HandoffError::Pat0NotWriteBack)
    );
    for initial in [0, 1 << 7, 1 << 17, (1 << 7) | (1 << 17)] {
        let transition = cr4_transition(initial | (1 << 5));
        assert_eq!(transition.before_cr3 & (1 << 7), 0);
        assert_eq!(transition.before_cr3 & (1 << 17), initial & (1 << 17));
        assert_eq!(transition.after_cr3 & ((1 << 7) | (1 << 17)), 0);
        assert_ne!(transition.after_cr3 & (1 << 5), 0);
    }

    assert!(matches!(
        prepare_x86_64_transfer(
            test_page_table_attestation(
                &plan,
                0x220001,
                u32::try_from(plan.used_page_table_page_count()).unwrap()
            ),
            state
        ),
        Err(X86_64HandoffError::InvalidPageTableRoot)
    ));
    assert!(matches!(
        prepare_x86_64_transfer(
            test_page_table_attestation(
                &plan,
                0x300000,
                u32::try_from(plan.used_page_table_page_count()).unwrap()
            ),
            state
        ),
        Err(X86_64HandoffError::PageTableRootOutsidePreExitStorage)
    ));
    assert!(matches!(
        prepare_x86_64_transfer(
            test_page_table_attestation(
                &plan,
                TABLE_STORAGE_START | (1 << 63),
                u32::try_from(plan.used_page_table_page_count()).unwrap()
            ),
            state
        ),
        Err(X86_64HandoffError::InvalidPageTableRoot)
    ));
    assert!(matches!(
        prepare_x86_64_transfer(
            test_page_table_attestation(
                &plan,
                TABLE_STORAGE_START,
                u32::try_from(plan.used_page_table_page_count() - 1).unwrap()
            ),
            state
        ),
        Err(X86_64HandoffError::InvalidPageTableRoot)
    ));

    let mut input = fixture.input();
    input.identity.handoff_stub_entry += 1;
    let plan = plan_transition(&input, &mut mappings, &mut copies).unwrap();
    assert!(matches!(
        prepare_x86_64_transfer(
            test_page_table_attestation(
                &plan,
                TABLE_STORAGE_START,
                u32::try_from(plan.used_page_table_page_count()).unwrap()
            ),
            state
        ),
        Err(X86_64HandoffError::InvalidHandoffStub)
    ));
}

#[derive(Default)]
struct RecordingWriter {
    bytes: Vec<u8>,
    polls: Vec<u32>,
    fail_after: Option<usize>,
}

struct RecordingCom1 {
    writes: Vec<(u16, u8)>,
    reads: Vec<Result<u8, &'static str>>,
    read_ports: Vec<u16>,
    next_read: usize,
}

impl Com1RegisterIo for RecordingCom1 {
    type Error = &'static str;

    fn read(&mut self, port: u16) -> Result<u8, Self::Error> {
        self.read_ports.push(port);
        let result = self.reads.get(self.next_read).copied().unwrap_or(Ok(0));
        self.next_read += 1;
        result
    }

    fn write(&mut self, port: u16, value: u8) -> Result<(), Self::Error> {
        self.writes.push((port, value));
        Ok(())
    }
}

fn recording_com1(reads: Vec<Result<u8, &'static str>>) -> RecordingCom1 {
    RecordingCom1 {
        writes: Vec::new(),
        reads,
        read_ports: Vec::new(),
        next_read: 0,
    }
}

#[test]
fn com1_initialization_is_explicit_bounded_and_fail_closed() {
    let mut io = recording_com1(vec![Ok(0x03), Ok(0x00), Ok(0x00), Ok(0x20)]);
    initialize_com1_registers(&mut io, 2).unwrap();
    assert_eq!(
        io.writes,
        vec![
            (0x03f9, 0x00),
            (0x03fb, 0x80),
            (0x03f8, 0x01),
            (0x03f9, 0x00),
            (0x03fb, 0x03),
            (0x03fa, 0xc7),
            (0x03fc, 0x03),
        ]
    );
    assert_eq!(io.read_ports, vec![0x03fb, 0x03f9, 0x03fd, 0x03fd]);

    let mut zero_limit = recording_com1(Vec::new());
    assert_eq!(
        initialize_com1_registers(&mut zero_limit, 0),
        Err(Com1InitializationError::ZeroPollLimit)
    );
    assert!(zero_limit.writes.is_empty());

    let mut mismatch = recording_com1(vec![Ok(0x83)]);
    assert_eq!(
        initialize_com1_registers(&mut mismatch, 1),
        Err(Com1InitializationError::ConfigurationMismatch {
            register: 0x03fb,
            expected: 0x03,
            observed: 0x83,
        })
    );

    let mut line_fault = recording_com1(vec![Ok(0x03), Ok(0x00), Ok(0x1e)]);
    assert_eq!(
        initialize_com1_registers(&mut line_fault, 1),
        Err(Com1InitializationError::LineStatusFault(0x1e))
    );

    let mut timeout = recording_com1(vec![Ok(0x03), Ok(0x00), Ok(0x00), Ok(0x00)]);
    assert_eq!(
        initialize_com1_registers(&mut timeout, 2),
        Err(Com1InitializationError::TransmitTimeout)
    );

    let mut read_error = recording_com1(vec![Err("port unavailable")]);
    assert_eq!(
        initialize_com1_registers(&mut read_error, 1),
        Err(Com1InitializationError::RegisterIo("port unavailable"))
    );
}

impl PostExitDiagnosticWriter for RecordingWriter {
    type Error = &'static str;

    fn write_byte_bounded(&mut self, byte: u8, poll_limit: u32) -> Result<(), Self::Error> {
        if self.fail_after == Some(self.bytes.len()) {
            return Err("timeout");
        }
        self.bytes.push(byte);
        self.polls.push(poll_limit);
        Ok(())
    }
}

#[test]
fn final_marker_is_bounded_complete_and_fails_closed_without_firmware_io() {
    let mut writer = RecordingWriter::default();
    write_final_handoff_marker(&mut writer, 17).unwrap();
    assert_eq!(writer.bytes, FINAL_HANDOFF_MARKER);
    assert!(writer.polls.iter().all(|limit| *limit == 17));

    assert_eq!(
        write_final_handoff_marker(&mut RecordingWriter::default(), 0),
        Err(FinalDiagnosticError::ZeroPollLimit)
    );
    let mut failing = RecordingWriter {
        fail_after: Some(3),
        ..RecordingWriter::default()
    };
    assert_eq!(
        write_final_handoff_marker(&mut failing, 1),
        Err(FinalDiagnosticError::Write("timeout"))
    );
}

#[test]
fn linked_raw_stub_orders_interrupt_pat_cr4_cr3_and_never_calls_kernel() {
    let source = include_str!("../src/handoff_x86_64.rs");
    let cli = source.find("asm!(\"cli\"").unwrap();
    let observation = source
        .find("let evidence = unsafe { observe_entry_state(exit_boot_services_complete) }")
        .unwrap();
    assert!(cli < observation);
    let stub = source
        .split("__wyrmroot_handoff_start:")
        .nth(1)
        .unwrap()
        .split("__wyrmroot_handoff_end:")
        .next()
        .unwrap();
    let cld = stub.find("cld").unwrap();
    let read_cr4_before = stub.find("mov rax, cr4").unwrap();
    let clear_pge = stub.find("btr rax, 7").unwrap();
    let write_cr4_before = stub.find("mov cr4, rax").unwrap();
    let cr3 = stub.find("mov cr3, rdi").unwrap();
    let after_cr3 = &stub[cr3..];
    let read_cr4_after = cr3 + after_cr3.find("mov rax, cr4").unwrap();
    let clear_pcide = cr3 + after_cr3.find("btr rax, 17").unwrap();
    let write_cr4_after = cr3 + after_cr3.find("mov cr4, rax").unwrap();
    let stack = stub.find("mov rsp, rsi").unwrap();
    let boot_info = stub.find("mov rdi, rcx").unwrap();
    let jump = stub.find("jmp rdx").unwrap();
    assert!(
        cld < read_cr4_before
            && read_cr4_before < clear_pge
            && clear_pge < write_cr4_before
            && write_cr4_before < cr3
            && cr3 < read_cr4_after
            && read_cr4_after < clear_pcide
            && clear_pcide < write_cr4_after
            && write_cr4_after < stack
            && stack < boot_info
            && boot_info < jump
    );
    assert!(!stub.contains("cli"));
    assert!(!stub.contains("call"));
    assert!(!stub.contains("ret"));
}
