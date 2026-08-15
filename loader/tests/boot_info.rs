#[path = "../src/boot_info.rs"]
mod boot_info;
#[path = "../src/modules.rs"]
mod modules;

use boot_info::{
    AcpiRsdpInput, AllocationLifetime, BootInfoError, BootInfoInput, BootInfoOutput,
    CommandLineInput, EntropyInput, FirmwareEntropySource, FirmwarePhase, FramebufferInput,
    FramebufferPixelFormat, HandoffAllocation, UefiMemoryDescriptor, UefiMemoryKind, build,
    validate_boot_info, validate_tables,
};
use deepwyrm_abi::{
    DW_BOOT_ENTROPY_SOURCE_FIRMWARE_PLATFORM, DW_BOOT_ENTROPY_SOURCE_MIXED_FIRMWARE,
    DW_BOOT_ENTROPY_SOURCE_UEFI_RNG_PROTOCOL, DW_BOOT_INFO_FLAG_FRAMEBUFFER_PRESENT,
    DW_BOOT_MEMORY_KIND_ACPI_NVS, DW_BOOT_MEMORY_KIND_ACPI_RECLAIM, DW_BOOT_MEMORY_KIND_MMIO,
    DW_BOOT_MEMORY_KIND_RESERVED, DW_BOOT_MEMORY_KIND_RUNTIME_SERVICES,
    DW_BOOT_MEMORY_KIND_UNUSABLE, DW_BOOT_MEMORY_KIND_USABLE, DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS,
    DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP, DwBootInfoV1, DwBootMemoryKind, DwBootMemoryRangeV1,
    DwBootModuleV1,
};
use modules::{ModuleInput, plan_modules};

fn retained(physical_start: u64, byte_len: u64) -> HandoffAllocation {
    HandoffAllocation {
        physical_start,
        byte_len,
        lifetime: AllocationLifetime::RetainedUntilKernelCopy,
    }
}

fn memory_map() -> [UefiMemoryDescriptor; 2] {
    [
        UefiMemoryDescriptor {
            kind: UefiMemoryKind::Loader,
            physical_start: 0x1000,
            page_count: 16,
            firmware_attributes: 0x1234,
        },
        UefiMemoryDescriptor {
            kind: UefiMemoryKind::Conventional,
            physical_start: 0x11000,
            page_count: 16,
            firmware_attributes: 0,
        },
    ]
}

fn canonical_modules() -> [DwBootModuleV1; 2] {
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
    )
    .unwrap()
    .to_abi_modules()
}

fn input<'a>(
    memory_map: &'a [UefiMemoryDescriptor],
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
            physical_start: 0x9000,
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
            conditioned: true,
        }),
    }
}

fn output<'a>(
    info: &'a mut DwBootInfoV1,
    memory_map: &'a mut [DwBootMemoryRangeV1],
) -> BootInfoOutput<'a> {
    BootInfoOutput {
        boot_info: info,
        memory_map,
    }
}

#[test]
fn builds_generated_boot_info_from_canonical_post_exit_tables() {
    let memory_input = memory_map();
    let modules = canonical_modules();
    let mut info = DwBootInfoV1::default();
    let mut memory_output = [DwBootMemoryRangeV1::default(); 2];
    build(
        &input(&memory_input, &modules),
        &mut output(&mut info, &mut memory_output),
    )
    .unwrap();

    assert_eq!(info.flags, DW_BOOT_INFO_FLAG_FRAMEBUFFER_PRESENT);
    assert_eq!(memory_output[0].kind, DW_BOOT_MEMORY_KIND_RESERVED);
    assert_eq!(memory_output[1].kind, DW_BOOT_MEMORY_KIND_USABLE);
    validate_boot_info(&info).unwrap();
    validate_tables(&info, &memory_output, &modules).unwrap();
}

#[test]
fn normalizes_every_uefi_memory_kind() {
    let descriptors = [
        UefiMemoryDescriptor {
            kind: UefiMemoryKind::Loader,
            physical_start: 0x1000,
            page_count: 16,
            firmware_attributes: 0,
        },
        UefiMemoryDescriptor {
            kind: UefiMemoryKind::Conventional,
            physical_start: 0x11000,
            page_count: 1,
            firmware_attributes: 0,
        },
        UefiMemoryDescriptor {
            kind: UefiMemoryKind::BootServices,
            physical_start: 0x12000,
            page_count: 1,
            firmware_attributes: 0,
        },
        UefiMemoryDescriptor {
            kind: UefiMemoryKind::Reserved,
            physical_start: 0x13000,
            page_count: 1,
            firmware_attributes: 0,
        },
        UefiMemoryDescriptor {
            kind: UefiMemoryKind::AcpiReclaim,
            physical_start: 0x14000,
            page_count: 1,
            firmware_attributes: 0,
        },
        UefiMemoryDescriptor {
            kind: UefiMemoryKind::AcpiNvs,
            physical_start: 0x15000,
            page_count: 1,
            firmware_attributes: 0,
        },
        UefiMemoryDescriptor {
            kind: UefiMemoryKind::Mmio,
            physical_start: 0x16000,
            page_count: 1,
            firmware_attributes: 0,
        },
        UefiMemoryDescriptor {
            kind: UefiMemoryKind::RuntimeServices,
            physical_start: 0x17000,
            page_count: 1,
            firmware_attributes: 0,
        },
        UefiMemoryDescriptor {
            kind: UefiMemoryKind::Unusable,
            physical_start: 0x18000,
            page_count: 1,
            firmware_attributes: 0,
        },
    ];
    let modules = canonical_modules();
    let mut info = DwBootInfoV1::default();
    let mut memory_output = [DwBootMemoryRangeV1::default(); 9];

    build(
        &input(&descriptors, &modules),
        &mut output(&mut info, &mut memory_output),
    )
    .unwrap();

    assert_eq!(
        memory_output.map(|entry| entry.kind),
        [
            DW_BOOT_MEMORY_KIND_RESERVED,
            DW_BOOT_MEMORY_KIND_USABLE,
            DW_BOOT_MEMORY_KIND_USABLE,
            DW_BOOT_MEMORY_KIND_RESERVED,
            DW_BOOT_MEMORY_KIND_ACPI_RECLAIM,
            DW_BOOT_MEMORY_KIND_ACPI_NVS,
            DW_BOOT_MEMORY_KIND_MMIO,
            DW_BOOT_MEMORY_KIND_RUNTIME_SERVICES,
            DW_BOOT_MEMORY_KIND_UNUSABLE,
        ]
    );
}

#[test]
fn maps_every_firmware_entropy_source() {
    let memory_input = memory_map();
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
        let mut value = input(&memory_input, &modules);
        value.entropy.as_mut().unwrap().source = source;
        let mut info = DwBootInfoV1::default();
        let mut memory_output = [DwBootMemoryRangeV1::default(); 2];

        build(&value, &mut output(&mut info, &mut memory_output)).unwrap();
        assert_eq!(info.entropy.source, expected);
    }
}

#[test]
fn accepts_an_unaligned_gop_framebuffer_inside_mmio() {
    let descriptors = [
        memory_map()[0],
        memory_map()[1],
        UefiMemoryDescriptor {
            kind: UefiMemoryKind::Mmio,
            physical_start: 0x21000,
            page_count: 1,
            firmware_attributes: 0,
        },
    ];
    let modules = canonical_modules();
    let mut value = input(&descriptors, &modules);
    value.framebuffer.as_mut().unwrap().physical_start = 0x21003;
    let mut info = DwBootInfoV1::default();
    let mut memory_output = [DwBootMemoryRangeV1::default(); 3];

    build(&value, &mut output(&mut info, &mut memory_output)).unwrap();
    assert_eq!(info.framebuffer.physical_start, 0x21003);
}

#[test]
fn rejects_pre_exit_or_lost_handoff_storage() {
    let memory_input = memory_map();
    let modules = canonical_modules();
    for (phase, lifetime, expected) in [
        (
            FirmwarePhase::BeforeExitBootServices,
            AllocationLifetime::RetainedUntilKernelCopy,
            BootInfoError::ExitBootServicesIncomplete,
        ),
        (
            FirmwarePhase::AfterExitBootServices,
            AllocationLifetime::AllocationFailed,
            BootInfoError::AllocationUnavailable,
        ),
        (
            FirmwarePhase::AfterExitBootServices,
            AllocationLifetime::ReleasedBeforeHandoff,
            BootInfoError::AllocationReleased,
        ),
    ] {
        let mut value = input(&memory_input, &modules);
        value.phase = phase;
        value.module_table_storage.lifetime = lifetime;
        let mut info = DwBootInfoV1::default();
        let mut memory_output = [DwBootMemoryRangeV1::default(); 2];
        assert_eq!(
            build(&value, &mut output(&mut info, &mut memory_output)),
            Err(expected)
        );
    }
}

#[test]
fn rejects_overflow_unknown_memory_kind_and_non_reserved_loader_storage() {
    let modules = canonical_modules();
    let mut overflowing = memory_map();
    overflowing[0].physical_start = u64::MAX - 0xfff;
    overflowing[0].page_count = 1;
    let mut info = DwBootInfoV1::default();
    let mut memory_output = [DwBootMemoryRangeV1::default(); 2];
    assert_eq!(
        build(
            &input(&overflowing, &modules),
            &mut output(&mut info, &mut memory_output)
        ),
        Err(BootInfoError::RangeOverflow)
    );

    let memory_input = memory_map();
    let mut info = DwBootInfoV1::default();
    let mut memory_output = [DwBootMemoryRangeV1::default(); 2];
    build(
        &input(&memory_input, &modules),
        &mut output(&mut info, &mut memory_output),
    )
    .unwrap();
    memory_output[0].kind = DwBootMemoryKind(u32::MAX);
    assert_eq!(
        validate_tables(&info, &memory_output, &modules),
        Err(BootInfoError::UnknownMemoryKind)
    );

    let mut only_usable = memory_map();
    only_usable[0].kind = UefiMemoryKind::BootServices;
    let mut info = DwBootInfoV1::default();
    let mut memory_output = [DwBootMemoryRangeV1::default(); 2];
    assert_eq!(
        build(
            &input(&only_usable, &modules),
            &mut output(&mut info, &mut memory_output)
        ),
        Err(BootInfoError::HandoffStorageNotReserved)
    );
}

#[test]
fn rejects_duplicate_missing_or_overlapping_module_table_entries() {
    let memory_input = memory_map();
    let mut duplicate = canonical_modules();
    duplicate[1].kind = DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP;
    let mut info = DwBootInfoV1::default();
    let mut memory_output = [DwBootMemoryRangeV1::default(); 2];
    assert_eq!(
        build(
            &input(&memory_input, &duplicate),
            &mut output(&mut info, &mut memory_output)
        ),
        Err(BootInfoError::DuplicateModule)
    );

    let one_module = [canonical_modules()[0]];
    let mut info = DwBootInfoV1::default();
    let mut memory_output = [DwBootMemoryRangeV1::default(); 2];
    assert_eq!(
        build(
            &input(&memory_input, &one_module),
            &mut output(&mut info, &mut memory_output)
        ),
        Err(BootInfoError::MissingBootfsModule)
    );

    let mut overlapping = canonical_modules();
    overlapping[1].physical_start = overlapping[0].physical_start;
    let mut info = DwBootInfoV1::default();
    let mut memory_output = [DwBootMemoryRangeV1::default(); 2];
    assert_eq!(
        build(
            &input(&memory_input, &overlapping),
            &mut output(&mut info, &mut memory_output)
        ),
        Err(BootInfoError::HandoffStorageOverlap)
    );
}

#[test]
fn rejects_reserved_field_acpi_and_framebuffer_errors() {
    let memory_input = memory_map();
    let modules = canonical_modules();
    let mut info = DwBootInfoV1::default();
    let mut memory_output = [DwBootMemoryRangeV1::default(); 2];
    build(
        &input(&memory_input, &modules),
        &mut output(&mut info, &mut memory_output),
    )
    .unwrap();
    info.reserved[0] = 1;
    assert_eq!(
        validate_boot_info(&info),
        Err(BootInfoError::InvalidReservedField)
    );

    let mut malformed_acpi = input(&memory_input, &modules);
    malformed_acpi.acpi_rsdp.as_mut().unwrap().physical_start = 0x9001;
    let mut info = DwBootInfoV1::default();
    let mut memory_output = [DwBootMemoryRangeV1::default(); 2];
    assert_eq!(
        build(&malformed_acpi, &mut output(&mut info, &mut memory_output)),
        Err(BootInfoError::InvalidAcpiRsdp)
    );

    let mut malformed_framebuffer = input(&memory_input, &modules);
    malformed_framebuffer
        .framebuffer
        .as_mut()
        .unwrap()
        .pixel_format = FramebufferPixelFormat::Bitmask {
        red_mask: 0xff,
        green_mask: 0xff,
        blue_mask: 0xff0000,
        reserved_mask: 0,
    };
    let mut info = DwBootInfoV1::default();
    let mut memory_output = [DwBootMemoryRangeV1::default(); 2];
    assert_eq!(
        build(
            &malformed_framebuffer,
            &mut output(&mut info, &mut memory_output)
        ),
        Err(BootInfoError::InvalidFramebuffer)
    );
}

#[test]
fn rejects_overlapping_loader_owned_handoff_regions() {
    let memory_input = memory_map();
    let modules = canonical_modules();
    let mut value = input(&memory_input, &modules);
    value.memory_map_storage.physical_start = value.boot_info_storage.physical_start;
    let mut info = DwBootInfoV1::default();
    let mut memory_output = [DwBootMemoryRangeV1::default(); 2];
    assert_eq!(
        build(&value, &mut output(&mut info, &mut memory_output)),
        Err(BootInfoError::HandoffStorageOverlap)
    );

    let mut value = input(&memory_input, &modules);
    value.module_table_storage.physical_start = value.boot_info_storage.physical_start;
    let mut info = DwBootInfoV1::default();
    let mut memory_output = [DwBootMemoryRangeV1::default(); 2];
    assert_eq!(
        build(&value, &mut output(&mut info, &mut memory_output)),
        Err(BootInfoError::HandoffStorageOverlap)
    );

    let mut value = input(&memory_input, &modules);
    value.module_table_storage.physical_start = value.memory_map_storage.physical_start;
    let mut info = DwBootInfoV1::default();
    let mut memory_output = [DwBootMemoryRangeV1::default(); 2];
    assert_eq!(
        build(&value, &mut output(&mut info, &mut memory_output)),
        Err(BootInfoError::HandoffStorageOverlap)
    );
}

#[test]
fn rejects_acpi_extent_or_usable_memory_and_table_reserved_fields() {
    let memory_input = memory_map();
    let modules = canonical_modules();
    let mut short = input(&memory_input, &modules);
    short.acpi_rsdp.as_mut().unwrap().byte_len = 19;
    let mut info = DwBootInfoV1::default();
    let mut memory_output = [DwBootMemoryRangeV1::default(); 2];
    assert_eq!(
        build(&short, &mut output(&mut info, &mut memory_output)),
        Err(BootInfoError::InvalidAcpiRsdp)
    );

    let mut usable = input(&memory_input, &modules);
    usable.acpi_rsdp.as_mut().unwrap().physical_start = 0x11000;
    let mut info = DwBootInfoV1::default();
    let mut memory_output = [DwBootMemoryRangeV1::default(); 2];
    assert_eq!(
        build(&usable, &mut output(&mut info, &mut memory_output)),
        Err(BootInfoError::InvalidAcpiRsdp)
    );

    let mut info = DwBootInfoV1::default();
    let mut memory_output = [DwBootMemoryRangeV1::default(); 2];
    build(
        &input(&memory_input, &modules),
        &mut output(&mut info, &mut memory_output),
    )
    .unwrap();
    memory_output[0].reserved0 = 1;
    assert_eq!(
        validate_tables(&info, &memory_output, &modules),
        Err(BootInfoError::InvalidReservedField)
    );
}

#[test]
fn rejects_handoff_command_entropy_and_module_overlap_classes() {
    let memory_input = memory_map();
    let modules = canonical_modules();
    for command_start in [0x1000, 0x2000, 0x3000, 0x4000, 0x7000] {
        let mut value = input(&memory_input, &modules);
        value.command_line = Some(CommandLineInput {
            storage: retained(command_start, 0x1000),
            byte_len: 32,
        });
        let mut info = DwBootInfoV1::default();
        let mut memory_output = [DwBootMemoryRangeV1::default(); 2];
        assert_eq!(
            build(&value, &mut output(&mut info, &mut memory_output)),
            Err(BootInfoError::HandoffStorageOverlap)
        );
    }
    for entropy_start in [0x1000, 0x2000, 0x3000, 0x4000, 0x6000] {
        let mut value = input(&memory_input, &modules);
        value.entropy.as_mut().unwrap().storage = retained(entropy_start, 0x1000);
        let mut info = DwBootInfoV1::default();
        let mut memory_output = [DwBootMemoryRangeV1::default(); 2];
        assert_eq!(
            build(&value, &mut output(&mut info, &mut memory_output)),
            Err(BootInfoError::HandoffStorageOverlap)
        );
    }
    let mut module_overlaps_boot_info = canonical_modules();
    module_overlaps_boot_info[0].physical_start = 0x1000;
    let mut info = DwBootInfoV1::default();
    let mut memory_output = [DwBootMemoryRangeV1::default(); 2];
    assert_eq!(
        build(
            &input(&memory_input, &module_overlaps_boot_info),
            &mut output(&mut info, &mut memory_output)
        ),
        Err(BootInfoError::HandoffStorageOverlap)
    );
}

#[test]
fn rejects_command_and_entropy_in_module_page_rounding_slack() {
    let memory_input = memory_map();
    let mut modules = canonical_modules();
    modules[0].byte_len = 1;

    let mut command_in_slack = input(&memory_input, &modules);
    command_in_slack.command_line = Some(CommandLineInput {
        storage: retained(0x4f00, 64),
        byte_len: 32,
    });
    let mut info = DwBootInfoV1::default();
    let mut memory_output = [DwBootMemoryRangeV1::default(); 2];
    assert_eq!(
        build(
            &command_in_slack,
            &mut output(&mut info, &mut memory_output)
        ),
        Err(BootInfoError::HandoffStorageOverlap)
    );

    let mut entropy_in_slack = input(&memory_input, &modules);
    entropy_in_slack.entropy.as_mut().unwrap().storage = retained(0x4f00, 64);
    let mut info = DwBootInfoV1::default();
    let mut memory_output = [DwBootMemoryRangeV1::default(); 2];
    assert_eq!(
        build(
            &entropy_in_slack,
            &mut output(&mut info, &mut memory_output)
        ),
        Err(BootInfoError::HandoffStorageOverlap)
    );
}
