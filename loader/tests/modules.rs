#[path = "../src/modules.rs"]
mod modules;

use deepwyrm_abi::{
    DW_BOOT_MODULE_FLAG_READ_ONLY, DW_BOOT_MODULE_KIND_UNSPECIFIED,
    DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS, DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP, DwBootModuleKind,
};
use modules::{ModuleInput, ModulePlanError, PAGE_SIZE, plan_modules};

fn input(kind: DwBootModuleKind, start: u64, len: u64) -> ModuleInput {
    ModuleInput {
        kind,
        physical_start: start,
        byte_len: len,
    }
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
    )
    .unwrap();
    let modules = plan.to_abi_modules();

    assert_eq!(modules[0].kind, DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP);
    assert_eq!(modules[1].kind, DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS);
    assert_eq!(modules[0].byte_len, 1);
    assert_eq!(modules[1].byte_len, PAGE_SIZE + 1);
    assert_eq!(modules[1].flags, DW_BOOT_MODULE_FLAG_READ_ONLY);
}

#[test]
fn rejects_wrong_kind_zero_length_unaligned_and_overlapping_ranges() {
    let err = plan_modules(
        input(DW_BOOT_MODULE_KIND_UNSPECIFIED, PAGE_SIZE, 1),
        input(DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS, PAGE_SIZE * 3, 1),
    )
    .unwrap_err();
    assert!(matches!(err, ModulePlanError::UnexpectedKind { .. }));

    let err = plan_modules(
        input(DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP, PAGE_SIZE, 0),
        input(DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS, PAGE_SIZE * 3, 1),
    )
    .unwrap_err();
    assert!(matches!(err, ModulePlanError::ZeroLength { .. }));

    let err = plan_modules(
        input(DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP, 1, 1),
        input(DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS, PAGE_SIZE * 3, 1),
    )
    .unwrap_err();
    assert!(matches!(err, ModulePlanError::UnalignedStart { .. }));

    let err = plan_modules(
        input(DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP, PAGE_SIZE, PAGE_SIZE),
        input(DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS, PAGE_SIZE, 1),
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
    )
    .unwrap_err();
    assert!(matches!(err, ModulePlanError::AllocationOverflow { .. }));
}
