#[path = "../src/uefi_app.rs"]
mod uefi_app;

use uefi_app::{
    ACPI_RSDP_V1_BYTES, ACPI_RSDP_V2_MIN_BYTES, AcpiRsdpConfigCandidate, AcpiRsdpConfigKind,
    CONFIG_PATH, MAX_KERNEL_ARTIFACT_BYTES, MAX_TOTAL_ARTIFACT_BYTES, PostExitGateError,
    PreparationError, RetainedAddressError, RetainedAddressFacts, UEFI_PAGE_BYTES,
    accept_boot_info, accept_final_memory_map, accept_page_table, accept_serial_diagnostic,
    accept_transfer, allocation_bytes_for_payload, authorize_jump, bounded_artifact_len,
    bounded_intake_count, dispatch_post_exit_failure, initialize_payload_allocation,
    normalize_optional_config, pages_for_payload, rsdp_intersecting_pages, select_rsdp_candidate,
    take_owned_resource_once, total_artifact_bytes, validate_acpi_rsdp, validate_acpi_rsdp_address,
    validate_retained_address_coherence,
};
use wyrmroot_efi_loader::config::{ConfigError, LoaderConfig, Profile};

#[test]
fn optional_config_is_defaulted_or_rejected_by_the_shared_parser() {
    assert_eq!(normalize_optional_config(None), Ok(LoaderConfig::DEFAULT));
    assert_eq!(
        normalize_optional_config(Some(b"profile=default\n")),
        Ok(LoaderConfig {
            profile: Profile::Default,
        })
    );
    assert_eq!(
        normalize_optional_config(Some(b"profile=developer\n")),
        Err(PreparationError::Config(ConfigError::UnsupportedProfile))
    );
    assert_eq!(CONFIG_PATH, "/EFI/Wyrmroot/loader.conf");
}

#[test]
fn page_accounting_rejects_empty_and_overflowing_payloads() {
    assert_eq!(pages_for_payload(1), Ok(1));
    assert_eq!(pages_for_payload(UEFI_PAGE_BYTES), Ok(1));
    assert_eq!(pages_for_payload(UEFI_PAGE_BYTES + 1), Ok(2));
    assert_eq!(pages_for_payload(0), Err(PreparationError::EmptyArtifact));
    assert_eq!(
        pages_for_payload(usize::MAX),
        Err(PreparationError::PageCountOverflow)
    );
}

#[test]
fn one_byte_payload_retains_a_zeroed_full_page() {
    assert_eq!(allocation_bytes_for_payload(1), Ok(UEFI_PAGE_BYTES));
    let mut retained = [0xa5_u8; UEFI_PAGE_BYTES];
    initialize_payload_allocation(&mut retained, &[0x42]).unwrap();
    assert_eq!(retained[0], 0x42);
    assert!(retained[1..].iter().all(|byte| *byte == 0));
}

#[test]
fn artifact_admission_is_bounded_before_buffer_allocation() {
    assert_eq!(bounded_artifact_len(1, 1), Ok(1));
    assert_eq!(
        bounded_artifact_len(
            (MAX_KERNEL_ARTIFACT_BYTES as u64) + 1,
            MAX_KERNEL_ARTIFACT_BYTES
        ),
        Err(PreparationError::ArtifactTooLarge)
    );
    assert_eq!(
        bounded_artifact_len(0, MAX_KERNEL_ARTIFACT_BYTES),
        Err(PreparationError::EmptyArtifact)
    );
    assert_eq!(
        total_artifact_bytes([MAX_TOTAL_ARTIFACT_BYTES, 1, 0]),
        Err(PreparationError::TotalArtifactLimitExceeded)
    );
}

#[test]
fn generated_intake_capacity_is_enforced_before_storage_use() {
    assert_eq!(bounded_intake_count(128, 128), Ok(128));
    assert_eq!(
        bounded_intake_count(129, 128),
        Err(PreparationError::IntakeCapacityExceeded)
    );
    assert_eq!(bounded_intake_count(16, 16), Ok(16));
    assert_eq!(
        bounded_intake_count(17, 16),
        Err(PreparationError::IntakeCapacityExceeded)
    );
}

#[test]
fn rsdp_validation_requires_checksums_and_bounded_v2_length() {
    assert_eq!(
        validate_acpi_rsdp_address(1),
        Err(PreparationError::InvalidAcpiRsdpAlignment)
    );
    let mut v1 = [0_u8; ACPI_RSDP_V1_BYTES];
    v1[..8].copy_from_slice(b"RSD PTR ");
    v1[15] = 0;
    v1[8] = 0_u8.wrapping_sub(v1.iter().copied().fold(0_u8, u8::wrapping_add));
    assert_eq!(
        validate_acpi_rsdp(&v1).unwrap().byte_len,
        ACPI_RSDP_V1_BYTES
    );

    let mut v2 = [0_u8; ACPI_RSDP_V2_MIN_BYTES];
    v2[..8].copy_from_slice(b"RSD PTR ");
    v2[15] = 2;
    v2[20..24].copy_from_slice(&(ACPI_RSDP_V2_MIN_BYTES as u32).to_le_bytes());
    v2[8] = 0_u8.wrapping_sub(
        v2[..ACPI_RSDP_V1_BYTES]
            .iter()
            .copied()
            .fold(0_u8, u8::wrapping_add),
    );
    v2[32] = 0_u8.wrapping_sub(v2.iter().copied().fold(0_u8, u8::wrapping_add));
    assert_eq!(
        validate_acpi_rsdp(&v2).unwrap().byte_len,
        ACPI_RSDP_V2_MIN_BYTES
    );

    v2[32] = v2[32].wrapping_add(1);
    assert_eq!(
        validate_acpi_rsdp(&v2),
        Err(PreparationError::InvalidAcpiRsdpChecksum)
    );
}

#[test]
fn rsdp_selection_prefers_acpi2_and_rejects_duplicates_without_downgrade() {
    let acpi1 = AcpiRsdpConfigCandidate {
        kind: AcpiRsdpConfigKind::Acpi1,
        physical_start: 0x1000,
    };
    let acpi2 = AcpiRsdpConfigCandidate {
        kind: AcpiRsdpConfigKind::Acpi2,
        physical_start: 0x2000,
    };
    assert_eq!(select_rsdp_candidate([acpi1, acpi2]), Ok(Some(acpi2)));
    assert_eq!(select_rsdp_candidate([acpi1]), Ok(Some(acpi1)));
    assert_eq!(
        select_rsdp_candidate([acpi2, acpi2]),
        Err(PreparationError::DuplicateSelectedAcpiGuid)
    );
    // ACPI2 is selected before validation, so later malformed-record handling
    // receives its address and cannot silently retry the ACPI1 candidate.
    assert_eq!(select_rsdp_candidate([acpi1, acpi2]), Ok(Some(acpi2)));
    assert_eq!(
        select_rsdp_candidate([acpi1, acpi1, acpi2]),
        Ok(Some(acpi2))
    );
}

#[test]
fn retained_rsdp_maps_only_its_intersecting_base_pages() {
    let one_page = rsdp_intersecting_pages(0x2010, 36, UEFI_PAGE_BYTES as u64).unwrap();
    assert_eq!(
        one_page,
        uefi_app::AcpiRsdpPageRange {
            physical_start: 0x2000,
            byte_len: 4096,
        }
    );
    assert_eq!(one_page.page_count(UEFI_PAGE_BYTES as u64), 1);
    assert_eq!(
        rsdp_intersecting_pages(0x2ff0, 36, UEFI_PAGE_BYTES as u64),
        Ok(uefi_app::AcpiRsdpPageRange {
            physical_start: 0x2000,
            byte_len: 8192,
        })
    );
    assert_eq!(
        rsdp_intersecting_pages(0x2000, 8193, UEFI_PAGE_BYTES as u64),
        Err(PreparationError::AcpiMappingExceedsTwoPages)
    );
}

#[test]
fn pre_exit_rollback_consumes_every_owned_slot_exactly_once() {
    let mut slots = [
        Some(0_u8),
        Some(1),
        Some(2),
        Some(3),
        Some(4),
        Some(5),
        Some(6),
    ];
    let mut releases = [0_u8; 7];
    for slot in &mut slots {
        assert!(take_owned_resource_once(slot, |index| {
            releases[usize::from(index)] += 1;
        }));
        assert!(!take_owned_resource_once(slot, |index| {
            releases[usize::from(index)] += 1;
        }));
    }
    assert_eq!(releases, [1; 7]);
    assert!(slots.iter().all(Option::is_none));
}

#[test]
fn post_exit_failures_cannot_authorize_the_raw_jump() {
    use wyrmroot_efi_loader::memory_map::MemoryMapError;

    for error in [
        MemoryMapError::RangeOverflow,
        MemoryMapError::OutputExhausted,
        MemoryMapError::UnknownMemoryKind,
    ] {
        assert_eq!(
            accept_final_memory_map::<(), _>(Err(error)),
            Err(PostExitGateError::FinalMemoryMap)
        );
    }
    assert_eq!(
        accept_boot_info::<(), _>(Err("invalid BootInfo")),
        Err(PostExitGateError::BootInfo)
    );
    assert_eq!(
        accept_page_table::<(), _>(Err("invalid CR3")),
        Err(PostExitGateError::PageTable)
    );
    assert_eq!(
        accept_serial_diagnostic::<(), _>(Err("COM1 timeout")),
        Err(PostExitGateError::SerialDiagnostic)
    );
    assert_eq!(
        accept_transfer::<(), _>(Err("invalid RDI/RSP/entry state")),
        Err(PostExitGateError::Transfer)
    );
}

#[test]
fn every_post_exit_gate_error_reaches_only_the_fatal_sink_once() {
    for error in [
        PostExitGateError::FinalMemoryMap,
        PostExitGateError::BootInfo,
        PostExitGateError::PageTable,
        PostExitGateError::SerialDiagnostic,
        PostExitGateError::Transfer,
    ] {
        let mut calls = 0;
        let delivered = dispatch_post_exit_failure(error, |observed| {
            calls += 1;
            observed
        });
        assert_eq!(delivered, error);
        assert_eq!(calls, 1);
    }
}

#[test]
fn post_exit_ownership_surface_has_no_firmware_release_authority() {
    let source = include_str!("../src/uefi_app.rs");
    assert_eq!(source.matches("boot::exit_boot_services(").count(), 1);
    assert!(!source.contains("PreparedPostExit"));
    let post_exit_pages = source
        .split("struct PostExitPages")
        .nth(1)
        .unwrap()
        .split("struct PostExitAcpiRsdp")
        .next()
        .unwrap();
    assert!(!post_exit_pages.contains("fn release"));
    assert!(!post_exit_pages.contains("boot::free_pages"));

    let completion = source
        .split("impl ExitedHandoff")
        .nth(1)
        .unwrap()
        .split("struct MaterializedInputs")
        .next()
        .unwrap();
    assert!(!completion.contains("boot::"));
    assert!(!completion.contains("uefi::println"));
    assert!(completion.contains("jump_to_kernel_authorized"));
    assert!(
        completion.find("Com1Writer::initialize").unwrap()
            < completion.find("enable_and_verify_entry_state").unwrap()
    );
}

#[test]
fn retained_records_and_transition_mappings_share_exact_addresses() {
    use wyrmroot_efi_loader::{
        boot_info::{AllocationLifetime as BootLifetime, HandoffAllocation},
        modules::{ModuleInput, plan_modules},
        transition::{
            AllocationLifetime, MappingKind, MappingPermissions, RetainedPhysicalRange,
            TransitionMapping, ValidatedRsdpMappingInput,
        },
    };

    let retained = |physical_start, byte_len| RetainedPhysicalRange {
        physical_start,
        byte_len,
        lifetime: AllocationLifetime::RetainedUntilKernelPageTableReplacement,
    };
    let boot_storage = |physical_start, byte_len| HandoffAllocation {
        physical_start,
        byte_len,
        lifetime: BootLifetime::RetainedUntilDeepwyrmPageTableReplacement,
    };
    let mapping = |kind, physical_start, byte_len| TransitionMapping {
        kind,
        physical_start,
        virtual_start: physical_start,
        byte_len,
        permissions: MappingPermissions {
            writable: false,
            executable: false,
        },
        lifetime: AllocationLifetime::RetainedUntilKernelPageTableReplacement,
    };
    let module_records = plan_modules(
        ModuleInput {
            kind: deepwyrm_abi::DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP,
            physical_start: 0x4000,
            byte_len: 7,
        },
        ModuleInput {
            kind: deepwyrm_abi::DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS,
            physical_start: 0x5000,
            byte_len: 9,
        },
    )
    .unwrap()
    .to_abi_modules();
    let module_allocations = [retained(0x4000, 0x1000), retained(0x5000, 0x1000)];
    let entropy = retained(0x6000, 0x1000);
    let rsdp = ValidatedRsdpMappingInput {
        retained_allocation: retained(0x7000, 0x1000),
        record_physical_start: 0x7000,
        record_byte_len: 36,
    };
    let mut mappings = [
        mapping(MappingKind::BootInfo, 0x1000, 0x1000),
        mapping(MappingKind::MemoryMapTable, 0x2000, 0x1000),
        mapping(MappingKind::ModuleTable, 0x3000, 0x1000),
        mapping(MappingKind::ModuleData { index: 0 }, 0x4000, 0x1000),
        mapping(MappingKind::ModuleData { index: 1 }, 0x5000, 0x1000),
        mapping(MappingKind::Entropy, 0x6000, 0x1000),
        mapping(MappingKind::RequiredAcpiRsdp, 0x7000, 0x1000),
    ];
    let facts = || RetainedAddressFacts {
        boot_info: boot_storage(0x1000, 0x1000),
        memory_map: boot_storage(0x2000, 0x1000),
        module_table: boot_storage(0x3000, 0x1000),
        module_records: &module_records,
        module_allocations: &module_allocations,
        entropy: Some((boot_storage(0x6000, 0x1000), entropy)),
        rsdp: Some((boot_storage(0x7000, 0x1000), rsdp)),
    };
    let retained_addresses = validate_retained_address_coherence(&mappings, facts()).unwrap();

    mappings[0].physical_start += 0x1000;
    assert_eq!(
        validate_retained_address_coherence(&mappings, facts()),
        Err(RetainedAddressError::StorageMappingMismatch)
    );
    mappings[0].physical_start -= 0x1000;
    let mut bad_module_records = module_records;
    bad_module_records[0].physical_start += 0x1000;
    assert_eq!(
        validate_retained_address_coherence(
            &mappings,
            RetainedAddressFacts {
                module_records: &bad_module_records,
                ..facts()
            }
        ),
        Err(RetainedAddressError::ModuleRecordMismatch)
    );
    mappings[5].byte_len += 0x1000;
    assert_eq!(
        validate_retained_address_coherence(&mappings, facts()),
        Err(RetainedAddressError::StorageMappingMismatch)
    );
    mappings[5].byte_len -= 0x1000;
    mappings[6].physical_start += 0x1000;
    assert_eq!(
        validate_retained_address_coherence(&mappings, facts()),
        Err(RetainedAddressError::StorageMappingMismatch)
    );

    let (_, final_map) = accept_final_memory_map::<_, &str>(Ok(())).unwrap();
    let (_, boot_info) = accept_boot_info::<_, &str>(Ok(())).unwrap();
    let (_, page_table) = accept_page_table::<_, &str>(Ok(())).unwrap();
    let (_, serial) = accept_serial_diagnostic::<_, &str>(Ok(())).unwrap();
    let (_, transfer) = accept_transfer::<_, &str>(Ok(())).unwrap();
    let _authorization = authorize_jump(
        final_map,
        boot_info,
        page_table,
        serial,
        transfer,
        retained_addresses,
    );
}
