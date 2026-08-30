#[path = "../src/boot_info.rs"]
mod boot_info;
#[path = "../src/modules.rs"]
mod modules;

use boot_info::{
    AcpiRsdpInput, AllocationLifetime, BootInfoError, BootInfoInput, BootInfoLimits,
    BootInfoOutput, CommandLineInput, EntropyInput, FirmwareEntropySource, FirmwarePhase,
    FramebufferInput, FramebufferPixelFormat, HandoffAllocation, UefiMemoryDescriptor,
    UefiMemoryKind, build, build_with_limits, validate_boot_info, validate_tables,
};
use deepwyrm_abi::{
    DW_BOOT_ENTROPY_SOURCE_FIRMWARE_PLATFORM, DW_BOOT_ENTROPY_SOURCE_MIXED_FIRMWARE,
    DW_BOOT_ENTROPY_SOURCE_UEFI_RNG_PROTOCOL, DW_BOOT_INFO_FLAG_FRAMEBUFFER_PRESENT,
    DW_BOOT_MEMORY_KIND_MMIO, DW_BOOT_MEMORY_KIND_RESERVED, DW_BOOT_MEMORY_KIND_USABLE,
    DW_BOOT_MEMORY_RANGE_V1_SIZE, DW_BOOT_MEMORY_RANGE_V1_VERSION,
    DW_BOOT_MODULE_KIND_DEEPWYRM_BOOT_DEVICE_TABLE_V1,
    DW_BOOT_MODULE_KIND_DEEPWYRM_X86_64_PAGING_HANDOFF_V1, DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS,
    DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP, DwBootInfoV1, DwBootMemoryKind, DwBootMemoryRangeV1,
    DwBootModuleV1,
};
use modules::{ModuleInput, plan_modules, plan_modules_with_boot_device_table};

fn retained(physical_start: u64, byte_len: u64) -> HandoffAllocation {
    HandoffAllocation {
        physical_start,
        byte_len,
        lifetime: AllocationLifetime::RetainedUntilDeepwyrmPageTableReplacement,
    }
}

fn map_entry(
    kind: DwBootMemoryKind,
    physical_start: u64,
    page_count: u64,
    firmware_attributes: u64,
) -> DwBootMemoryRangeV1 {
    DwBootMemoryRangeV1 {
        size: DW_BOOT_MEMORY_RANGE_V1_SIZE,
        version: DW_BOOT_MEMORY_RANGE_V1_VERSION,
        kind,
        reserved0: 0,
        physical_start,
        page_count,
        firmware_attributes,
        reserved: [0; 3],
    }
}

fn memory_map() -> [DwBootMemoryRangeV1; 2] {
    [
        map_entry(DW_BOOT_MEMORY_KIND_RESERVED, 0x1000, 16, 0x1234),
        map_entry(DW_BOOT_MEMORY_KIND_USABLE, 0x11000, 16, 0),
    ]
}

fn canonical_modules() -> [DwBootModuleV1; 3] {
    plan_modules(
        ModuleInput {
            kind: DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP,
            physical_start: 0x4000,
            byte_len: 0x1000,
        },
        ModuleInput {
            kind: DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS,
            physical_start: 0x5000,
            byte_len: 0x1000,
        },
        ModuleInput {
            kind: DW_BOOT_MODULE_KIND_DEEPWYRM_X86_64_PAGING_HANDOFF_V1,
            physical_start: 0xa000,
            byte_len: 144,
        },
    )
    .unwrap()
    .to_abi_modules()
}

fn d6_modules() -> [DwBootModuleV1; 4] {
    plan_modules_with_boot_device_table(
        ModuleInput {
            kind: DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP,
            physical_start: 0x4000,
            byte_len: 0x1000,
        },
        ModuleInput {
            kind: DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS,
            physical_start: 0x5000,
            byte_len: 0x1000,
        },
        ModuleInput {
            kind: DW_BOOT_MODULE_KIND_DEEPWYRM_X86_64_PAGING_HANDOFF_V1,
            physical_start: 0xa000,
            byte_len: 144,
        },
        ModuleInput {
            kind: DW_BOOT_MODULE_KIND_DEEPWYRM_BOOT_DEVICE_TABLE_V1,
            physical_start: 0xb000,
            byte_len: 80,
        },
    )
    .unwrap()
}

fn input<'a>(
    memory_map: &'a [DwBootMemoryRangeV1],
    modules: &'a [DwBootModuleV1],
) -> BootInfoInput<'a> {
    BootInfoInput {
        phase: FirmwarePhase::AfterExitBootServices,
        boot_info_storage: retained(0x1000, 0x1000),
        memory_map_storage: retained(0x2000, 0x1000),
        module_table_storage: retained(0x3000, 0x1000),
        memory_map,
        modules,
        acpi_rsdp: Some(AcpiRsdpInput {
            storage: retained(0x9000, 0x1000),
            byte_len: 20,
        }),
        framebuffer: Some(FramebufferInput {
            physical_start: 0x8000,
            byte_len: 64,
            width: 8,
            height: 2,
            pixels_per_scanline: 8,
            pixel_format: FramebufferPixelFormat::Rgbx8,
        }),
        command_line: Some(CommandLineInput {
            storage: retained(0x6000, 0x1000),
            byte_len: 32,
        }),
        entropy: Some(EntropyInput {
            storage: retained(0x7000, 0x1000),
            byte_len: 64,
            source: FirmwareEntropySource::UefiRngProtocol,
            conditioned: false,
        }),
    }
}

fn output<'a>(info: &'a mut DwBootInfoV1, modules: &'a mut [DwBootModuleV1]) -> BootInfoOutput<'a> {
    BootInfoOutput {
        boot_info: info,
        modules,
    }
}

#[test]
fn retains_source_neutral_uefi_memory_descriptor_categories() {
    let descriptors = [
        UefiMemoryKind::Conventional,
        UefiMemoryKind::BootServices,
        UefiMemoryKind::Loader,
        UefiMemoryKind::Reserved,
        UefiMemoryKind::AcpiReclaim,
        UefiMemoryKind::AcpiNvs,
        UefiMemoryKind::Mmio,
        UefiMemoryKind::RuntimeServices,
        UefiMemoryKind::Unusable,
    ]
    .map(|kind| UefiMemoryDescriptor {
        kind,
        physical_start: 0,
        page_count: 1,
        firmware_attributes: 0,
    });

    assert_eq!(descriptors.len(), 9);
}

#[test]
fn builds_canonical_boot_info_and_copies_the_retained_module_table() {
    let memory_map = memory_map();
    let modules = canonical_modules();
    let mut info = DwBootInfoV1::default();
    let mut copied_modules = [DwBootModuleV1::default(); 3];

    build(
        &input(&memory_map, &modules),
        &mut output(&mut info, &mut copied_modules),
    )
    .unwrap();

    assert_eq!(info.flags, DW_BOOT_INFO_FLAG_FRAMEBUFFER_PRESENT);
    assert_eq!(info.memory_map_physical_start, 0x2000);
    assert_eq!(info.modules_physical_start, 0x3000);
    assert_eq!(copied_modules, modules);
    validate_boot_info(&info).unwrap();
    validate_tables(&info, &memory_map, &copied_modules).unwrap();
}

#[test]
fn d6_builds_exact_four_module_table_and_rejects_reordered_or_writable_table() {
    let memory_map = memory_map();
    let modules = d6_modules();
    let mut info = DwBootInfoV1::default();
    let mut copied_modules = [DwBootModuleV1::default(); 4];
    build(
        &input(&memory_map, &modules),
        &mut output(&mut info, &mut copied_modules),
    )
    .unwrap();
    assert_eq!(info.module_count, 4);
    assert_eq!(
        copied_modules[3].kind,
        DW_BOOT_MODULE_KIND_DEEPWYRM_BOOT_DEVICE_TABLE_V1
    );
    validate_tables(&info, &memory_map, &copied_modules).unwrap();

    let mut reordered = modules;
    reordered.swap(2, 3);
    assert_eq!(
        validate_tables(&info, &memory_map, &reordered),
        Err(BootInfoError::InvalidModuleOrder)
    );

    let mut writable = modules;
    writable[3].flags = deepwyrm_abi::DwBootModuleFlags(0);
    assert_eq!(
        validate_tables(&info, &memory_map, &writable),
        Err(BootInfoError::ModuleMustBeReadOnly)
    );
}

#[test]
fn rejects_generated_policy_entry_limit_excesses_before_publication() {
    let memory_map = memory_map();
    let modules = canonical_modules();
    let mut info = DwBootInfoV1::default();
    let mut copied_modules = [DwBootModuleV1::default(); 3];
    assert_eq!(
        build_with_limits(
            &input(&memory_map, &modules),
            &mut output(&mut info, &mut copied_modules),
            BootInfoLimits {
                max_memory_map_entries: 1,
                max_module_entries: 2,
            }
        ),
        Err(BootInfoError::MemoryMapEntryLimitExceeded)
    );

    assert_eq!(
        build_with_limits(
            &input(&memory_map, &modules),
            &mut output(&mut info, &mut copied_modules),
            BootInfoLimits {
                max_memory_map_entries: 2,
                max_module_entries: 1,
            }
        ),
        Err(BootInfoError::ModuleEntryLimitExceeded)
    );
}

#[test]
fn maps_every_firmware_entropy_source() {
    let memory_map = memory_map();
    let modules = canonical_modules();
    for (source, expected) in [
        (
            FirmwareEntropySource::UefiRngProtocol,
            DW_BOOT_ENTROPY_SOURCE_UEFI_RNG_PROTOCOL,
        ),
        (
            FirmwareEntropySource::FirmwarePlatform,
            DW_BOOT_ENTROPY_SOURCE_FIRMWARE_PLATFORM,
        ),
        (
            FirmwareEntropySource::MixedFirmware,
            DW_BOOT_ENTROPY_SOURCE_MIXED_FIRMWARE,
        ),
    ] {
        let mut value = input(&memory_map, &modules);
        value.entropy.as_mut().unwrap().source = source;
        let mut info = DwBootInfoV1::default();
        let mut copied_modules = [DwBootModuleV1::default(); 3];

        build(&value, &mut output(&mut info, &mut copied_modules)).unwrap();
        assert_eq!(info.entropy.source, expected);
    }
}

#[test]
fn accepts_an_unaligned_gop_framebuffer_inside_mmio() {
    let memory_map = [
        memory_map()[0],
        memory_map()[1],
        map_entry(DW_BOOT_MEMORY_KIND_MMIO, 0x21000, 1, 0),
    ];
    let modules = canonical_modules();
    let mut value = input(&memory_map, &modules);
    value.framebuffer.as_mut().unwrap().physical_start = 0x21003;
    let mut info = DwBootInfoV1::default();
    let mut copied_modules = [DwBootModuleV1::default(); 3];

    build(&value, &mut output(&mut info, &mut copied_modules)).unwrap();
    assert_eq!(info.framebuffer.physical_start, 0x21003);
}

#[test]
fn rejects_pre_exit_released_and_misaligned_loader_owned_storage() {
    let memory_map = memory_map();
    let modules = canonical_modules();
    for (phase, lifetime, expected) in [
        (
            FirmwarePhase::BeforeExitBootServices,
            AllocationLifetime::RetainedUntilDeepwyrmPageTableReplacement,
            BootInfoError::ExitBootServicesIncomplete,
        ),
        (
            FirmwarePhase::AfterExitBootServices,
            AllocationLifetime::AllocationFailed,
            BootInfoError::AllocationUnavailable,
        ),
        (
            FirmwarePhase::AfterExitBootServices,
            AllocationLifetime::ReleasedBeforeDeepwyrmPageTableReplacement,
            BootInfoError::AllocationReleased,
        ),
    ] {
        let mut value = input(&memory_map, &modules);
        value.phase = phase;
        value.module_table_storage.lifetime = lifetime;
        let mut info = DwBootInfoV1::default();
        let mut copied_modules = [DwBootModuleV1::default(); 3];
        assert_eq!(
            build(&value, &mut output(&mut info, &mut copied_modules)),
            Err(expected)
        );
    }

    let mut value = input(&memory_map, &modules);
    value.command_line.as_mut().unwrap().storage = retained(0x6001, 0x1000);
    let mut info = DwBootInfoV1::default();
    let mut copied_modules = [DwBootModuleV1::default(); 3];
    assert_eq!(
        build(&value, &mut output(&mut info, &mut copied_modules)),
        Err(BootInfoError::PhysicalAddressUnaligned)
    );
}

#[test]
fn rejects_unknown_map_module_and_reserved_field_errors() {
    let mut invalid_memory_map = memory_map();
    let modules = canonical_modules();
    invalid_memory_map[0].kind = DwBootMemoryKind(u32::MAX);
    let mut info = DwBootInfoV1::default();
    let mut copied_modules = [DwBootModuleV1::default(); 3];
    assert_eq!(
        build(
            &input(&invalid_memory_map, &modules),
            &mut output(&mut info, &mut copied_modules)
        ),
        Err(BootInfoError::UnknownMemoryKind)
    );

    let baseline_memory_map = memory_map();
    let mut duplicate = canonical_modules();
    duplicate[1].kind = DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP;
    let mut info = DwBootInfoV1::default();
    let mut copied_modules = [DwBootModuleV1::default(); 3];
    assert_eq!(
        build(
            &input(&baseline_memory_map, &duplicate),
            &mut output(&mut info, &mut copied_modules)
        ),
        Err(BootInfoError::DuplicateModule)
    );

    let mut valid_map = memory_map();
    let mut info = DwBootInfoV1::default();
    let mut copied_modules = [DwBootModuleV1::default(); 3];
    build(
        &input(&valid_map, &modules),
        &mut output(&mut info, &mut copied_modules),
    )
    .unwrap();
    valid_map[0].reserved0 = 1;
    assert_eq!(
        validate_tables(&info, &valid_map, &copied_modules),
        Err(BootInfoError::InvalidReservedField)
    );
}

#[test]
fn requires_exactly_one_read_only_generated_paging_handoff_module() {
    let memory_map = memory_map();
    let modules = canonical_modules();

    let mut info = DwBootInfoV1::default();
    let mut copied_modules = [DwBootModuleV1::default(); 3];
    assert_eq!(
        build(
            &input(&memory_map, &modules[..2]),
            &mut output(&mut info, &mut copied_modules[..2]),
        ),
        Err(BootInfoError::MissingPagingHandoffModule)
    );

    let mut writable = modules;
    writable[2].flags = deepwyrm_abi::DwBootModuleFlags(0);
    let mut info = DwBootInfoV1::default();
    let mut copied_modules = [DwBootModuleV1::default(); 3];
    assert_eq!(
        build(
            &input(&memory_map, &writable),
            &mut output(&mut info, &mut copied_modules),
        ),
        Err(BootInfoError::ModuleMustBeReadOnly)
    );

    for byte_len in [112_u64, 136, 145, 2161] {
        let mut invalid_extent = modules;
        invalid_extent[2].byte_len = byte_len;
        let mut info = DwBootInfoV1::default();
        let mut copied_modules = [DwBootModuleV1::default(); 3];
        assert_eq!(
            build(
                &input(&memory_map, &invalid_extent),
                &mut output(&mut info, &mut copied_modules),
            ),
            Err(BootInfoError::InvalidHeader)
        );
    }

    let mut duplicate = [modules[0], modules[1], modules[2], modules[2]];
    duplicate[3].physical_start = 0xb000;
    let mut info = DwBootInfoV1::default();
    let mut copied_modules = [DwBootModuleV1::default(); 4];
    assert_eq!(
        build(
            &input(&memory_map, &duplicate),
            &mut output(&mut info, &mut copied_modules),
        ),
        Err(BootInfoError::DuplicateModule)
    );
}

#[test]
fn rejects_optional_storage_overlap_and_module_allocation_slack() {
    let memory_map = memory_map();
    let mut modules = canonical_modules();
    modules[0].byte_len = 1;

    for overlap in [0x1000, 0x2000, 0x3000, 0x4000, 0x6000, 0x7000] {
        let mut value = input(&memory_map, &modules);
        value.acpi_rsdp.as_mut().unwrap().storage = retained(overlap, 0x1000);
        let mut info = DwBootInfoV1::default();
        let mut copied_modules = [DwBootModuleV1::default(); 3];
        assert_eq!(
            build(&value, &mut output(&mut info, &mut copied_modules)),
            Err(BootInfoError::HandoffStorageOverlap)
        );
    }

    for overlap in [0x4000, 0x9000] {
        let mut value = input(&memory_map, &modules);
        value.command_line = Some(CommandLineInput {
            storage: retained(overlap, 0x1000),
            byte_len: 32,
        });
        let mut info = DwBootInfoV1::default();
        let mut copied_modules = [DwBootModuleV1::default(); 3];
        assert_eq!(
            build(&value, &mut output(&mut info, &mut copied_modules)),
            Err(BootInfoError::HandoffStorageOverlap)
        );
    }

    let mut value = input(&memory_map, &modules);
    value.entropy.as_mut().unwrap().storage = retained(0x4000, 0x1000);
    let mut info = DwBootInfoV1::default();
    let mut copied_modules = [DwBootModuleV1::default(); 3];
    assert_eq!(
        build(&value, &mut output(&mut info, &mut copied_modules)),
        Err(BootInfoError::HandoffStorageOverlap)
    );
}

#[test]
fn rejects_malformed_acpi_storage_and_module_output_length_mismatch() {
    let memory_map = memory_map();
    let modules = canonical_modules();
    let mut value = input(&memory_map, &modules);
    value.acpi_rsdp.as_mut().unwrap().byte_len = 0x1001;
    let mut info = DwBootInfoV1::default();
    let mut copied_modules = [DwBootModuleV1::default(); 3];
    assert_eq!(
        build(&value, &mut output(&mut info, &mut copied_modules)),
        Err(BootInfoError::InvalidAcpiRsdp)
    );

    let mut value = input(&memory_map, &modules);
    value.acpi_rsdp.as_mut().unwrap().storage = retained(0x11000, 0x1000);
    let mut info = DwBootInfoV1::default();
    let mut copied_modules = [DwBootModuleV1::default(); 3];
    assert_eq!(
        build(&value, &mut output(&mut info, &mut copied_modules)),
        Err(BootInfoError::HandoffStorageNotReserved)
    );

    let mut info = DwBootInfoV1::default();
    let mut copied_modules = [DwBootModuleV1::default(); 1];
    assert_eq!(
        build(
            &input(&memory_map, &modules),
            &mut output(&mut info, &mut copied_modules)
        ),
        Err(BootInfoError::OutputLengthMismatch)
    );
}
