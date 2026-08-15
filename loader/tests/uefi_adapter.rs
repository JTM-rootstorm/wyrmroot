#[path = "../src/uefi_app.rs"]
mod uefi_app;

use uefi_app::{
    ACPI_RSDP_V1_BYTES, ACPI_RSDP_V2_MIN_BYTES, CONFIG_PATH, MAX_KERNEL_ARTIFACT_BYTES,
    MAX_TOTAL_ARTIFACT_BYTES, PreparationError, UEFI_PAGE_BYTES, bounded_artifact_len,
    normalize_optional_config, pages_for_payload, total_artifact_bytes, validate_acpi_rsdp,
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
