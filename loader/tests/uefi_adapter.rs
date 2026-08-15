#[path = "../src/uefi_app.rs"]
mod uefi_app;

use uefi_app::{
    ACPI_RSDP_V1_BYTES, ACPI_RSDP_V2_MIN_BYTES, AcpiRsdpConfigCandidate, AcpiRsdpConfigKind,
    CONFIG_PATH, MAX_KERNEL_ARTIFACT_BYTES, MAX_TOTAL_ARTIFACT_BYTES, PreparationError,
    UEFI_PAGE_BYTES, allocation_bytes_for_payload, bounded_artifact_len,
    initialize_payload_allocation, normalize_optional_config, pages_for_payload,
    rsdp_intersecting_pages, select_rsdp_candidate, total_artifact_bytes, validate_acpi_rsdp,
    validate_acpi_rsdp_address,
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
