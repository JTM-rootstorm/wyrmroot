#[path = "../src/modules.rs"]
mod modules;

use deepwyrm_abi::{
    DW_BOOT_MODULE_FLAG_READ_ONLY, DW_BOOT_MODULE_KIND_DEEPWYRM_X86_64_PAGING_HANDOFF_V1,
    DW_BOOT_MODULE_KIND_UNSPECIFIED, DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS,
    DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP, DW_BOOT_MODULE_V1_SIZE, DW_BOOT_MODULE_V1_VERSION,
    DwBootModuleFlags, DwBootModuleKind,
};
use modules::{ModuleInput, ModulePlanError, PAGE_SIZE, plan_modules};

fn input(kind: DwBootModuleKind, start: u64, len: u64) -> ModuleInput {
    ModuleInput {
        kind,
        physical_start: start,
        byte_len: len,
    }
}

fn paging_handoff(start: u64, len: u64) -> ModuleInput {
    input(
        DW_BOOT_MODULE_KIND_DEEPWYRM_X86_64_PAGING_HANDOFF_V1,
        start,
        len,
    )
}

#[test]
fn plans_required_modules_in_canonical_order_and_preserves_byte_lengths() {
    let plan = plan_modules(
        input(DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP, PAGE_SIZE, 1),
        input(
            DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS,
            PAGE_SIZE * 3,
            PAGE_SIZE + 1,
        ),
        paging_handoff(PAGE_SIZE * 6, 144),
    )
    .unwrap();
    let modules = plan.to_abi_modules();

    assert_eq!(modules[0].kind, DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP);
    assert_eq!(modules[1].kind, DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS);
    assert_eq!(modules[0].byte_len, 1);
    assert_eq!(modules[1].byte_len, PAGE_SIZE + 1);
    assert_eq!(modules[1].flags, DW_BOOT_MODULE_FLAG_READ_ONLY);
    assert_eq!(
        modules[2].kind,
        DW_BOOT_MODULE_KIND_DEEPWYRM_X86_64_PAGING_HANDOFF_V1
    );
    assert_eq!(modules[2].flags, DW_BOOT_MODULE_FLAG_READ_ONLY);
}

#[test]
fn rounds_each_payload_to_the_required_allocation_extent() {
    let plan = plan_modules(
        input(DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP, PAGE_SIZE, 1),
        input(
            DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS,
            PAGE_SIZE * 3,
            PAGE_SIZE + 1,
        ),
        paging_handoff(PAGE_SIZE * 6, 144),
    )
    .unwrap();

    assert_eq!(plan.bootstrap().allocated_len, PAGE_SIZE);
    assert_eq!(plan.bootfs().allocated_len, PAGE_SIZE * 2);
    assert_eq!(plan.paging_handoff().allocated_len, PAGE_SIZE);
}

#[test]
fn accepts_allocations_that_are_exactly_adjacent_after_rounding() {
    let plan = plan_modules(
        input(DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP, PAGE_SIZE, 1),
        input(DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS, PAGE_SIZE * 2, 1),
        paging_handoff(PAGE_SIZE * 3, 144),
    )
    .unwrap();

    assert_eq!(plan.bootstrap().allocated_len, PAGE_SIZE);
    assert_eq!(plan.bootfs().physical_start, PAGE_SIZE * 2);
}

#[test]
fn emits_complete_generated_module_records_with_zero_reserved_fields() {
    let bootstrap_start = PAGE_SIZE;
    let bootfs_start = PAGE_SIZE * 3;
    let bootstrap_len = 17;
    let bootfs_len = PAGE_SIZE + 3;
    let modules = plan_modules(
        input(
            DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP,
            bootstrap_start,
            bootstrap_len,
        ),
        input(
            DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS,
            bootfs_start,
            bootfs_len,
        ),
        paging_handoff(PAGE_SIZE * 6, 144),
    )
    .unwrap()
    .to_abi_modules();

    assert_eq!(modules[0].size, DW_BOOT_MODULE_V1_SIZE);
    assert_eq!(modules[0].version, DW_BOOT_MODULE_V1_VERSION);
    assert_eq!(modules[0].kind, DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP);
    assert_eq!(modules[0].flags, DwBootModuleFlags(0));
    assert_eq!(modules[0].physical_start, bootstrap_start);
    assert_eq!(modules[0].byte_len, bootstrap_len);
    assert_eq!(modules[0].reserved, [0; 4]);

    assert_eq!(modules[1].size, DW_BOOT_MODULE_V1_SIZE);
    assert_eq!(modules[1].version, DW_BOOT_MODULE_V1_VERSION);
    assert_eq!(modules[1].kind, DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS);
    assert_eq!(modules[1].flags, DW_BOOT_MODULE_FLAG_READ_ONLY);
    assert_eq!(modules[1].physical_start, bootfs_start);
    assert_eq!(modules[1].byte_len, bootfs_len);
    assert_eq!(modules[1].reserved, [0; 4]);

    assert_eq!(
        modules[2].kind,
        DW_BOOT_MODULE_KIND_DEEPWYRM_X86_64_PAGING_HANDOFF_V1
    );
    assert_eq!(modules[2].flags, DW_BOOT_MODULE_FLAG_READ_ONLY);
    assert_eq!(modules[2].reserved, [0; 4]);
}

#[test]
fn rejects_wrong_kind_zero_length_unaligned_and_overlapping_ranges() {
    let err = plan_modules(
        input(DW_BOOT_MODULE_KIND_UNSPECIFIED, PAGE_SIZE, 1),
        input(DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS, PAGE_SIZE * 3, 1),
        paging_handoff(PAGE_SIZE * 5, 144),
    )
    .unwrap_err();
    assert!(matches!(err, ModulePlanError::UnexpectedKind { .. }));

    let err = plan_modules(
        input(DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP, PAGE_SIZE, 0),
        input(DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS, PAGE_SIZE * 3, 1),
        paging_handoff(PAGE_SIZE * 5, 144),
    )
    .unwrap_err();
    assert!(matches!(err, ModulePlanError::ZeroLength { .. }));

    let err = plan_modules(
        input(DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP, 1, 1),
        input(DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS, PAGE_SIZE * 3, 1),
        paging_handoff(PAGE_SIZE * 5, 144),
    )
    .unwrap_err();
    assert!(matches!(err, ModulePlanError::UnalignedStart { .. }));

    let err = plan_modules(
        input(DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP, PAGE_SIZE, PAGE_SIZE),
        input(DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS, PAGE_SIZE, 1),
        paging_handoff(PAGE_SIZE * 5, 144),
    )
    .unwrap_err();
    assert_eq!(err, ModulePlanError::OverlappingAllocations);
}

#[test]
fn rejects_payload_and_page_rounding_overflow() {
    let err = plan_modules(
        input(
            DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP,
            PAGE_SIZE * 2,
            u64::MAX - PAGE_SIZE * 2 + 1,
        ),
        input(DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS, PAGE_SIZE * 3, 1),
        paging_handoff(PAGE_SIZE * 5, 144),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ModulePlanError::RangeOverflow { .. } | ModulePlanError::AllocationOverflow { .. }
    ));

    let err = plan_modules(
        input(
            DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP,
            PAGE_SIZE,
            u64::MAX - PAGE_SIZE,
        ),
        input(DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS, PAGE_SIZE * 3, 1),
        paging_handoff(PAGE_SIZE * 5, 144),
    )
    .unwrap_err();
    assert!(matches!(err, ModulePlanError::AllocationOverflow { .. }));
}

#[test]
fn paging_handoff_extent_is_exactly_header_plus_bounded_u64_frames() {
    for byte_len in [112_u64, 136, 145, 2161, 2168] {
        assert_eq!(
            plan_modules(
                input(DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP, PAGE_SIZE, 1),
                input(DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS, PAGE_SIZE * 2, 1),
                paging_handoff(PAGE_SIZE * 3, byte_len),
            ),
            Err(ModulePlanError::InvalidPagingHandoffExtent)
        );
    }
    for byte_len in [144_u64, 2160] {
        let plan = plan_modules(
            input(DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP, PAGE_SIZE, 1),
            input(DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS, PAGE_SIZE * 2, 1),
            paging_handoff(PAGE_SIZE * 3, byte_len),
        )
        .unwrap();
        assert_eq!(plan.paging_handoff().byte_len, byte_len);
    }
}
