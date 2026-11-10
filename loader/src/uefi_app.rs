//! UEFI 0.39 firmware adapter for the WYR0 loader boundary.
//!
//! The host-testable normalization helpers in this file deliberately contain no
//! UEFI calls. Firmware work is feature-gated and keeps protocol guards and
//! allocator-backed values inside pre-exit scopes.

#[cfg(feature = "firmware")]
use wyrmroot_efi_loader::config::MAX_CONFIG_BYTES;
use wyrmroot_efi_loader::config::{ConfigError, LoaderConfig};

/// Optional, bounded loader configuration location.
///
/// Artifact locations remain fixed; this file can only select the currently
/// supported default profile.
pub const CONFIG_PATH: &str = "/EFI/Wyrmroot/loader.conf";

/// UEFI page size used solely for firmware page-allocation accounting.
pub const UEFI_PAGE_BYTES: usize = 4096;

// The loader's UEFI allocation granule must never drift from the generated
// Deepwyrm BootInfo base-page contract. This is a compile-time equality guard,
// not a locally duplicated ABI value.
const _: [(); UEFI_PAGE_BYTES] = [(); deepwyrm_abi::DW_BOOT_BASE_PAGE_SIZE as usize];

/// Loader-local admission limit for the kernel ELF.
///
/// The phase plan does not yet prescribe artifact limits. This deliberately
/// conservative limit is a loader policy, not a kernel ABI constant.
pub const MAX_KERNEL_ARTIFACT_BYTES: usize = 32 * 1024 * 1024;

/// Loader-local admission limit for the primordial bootstrap ELF.
pub const MAX_BOOTSTRAP_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;

/// Loader-local admission limit for the read-only bootfs image.
pub const MAX_BOOTFS_ARTIFACT_BYTES: usize = 32 * 1024 * 1024;

/// The optional D6 table is bounded entirely by generated ABI capacities.
#[allow(dead_code)]
pub const MAX_BOOT_DEVICE_TABLE_ARTIFACT_BYTES: usize = deepwyrm_abi::DW_BOOT_DEVICE_TABLE_V1_SIZE
    as usize
    + deepwyrm_abi::DW_BOOT_DEVICE_TABLE_MAX_RESOURCES as usize
        * deepwyrm_abi::DW_BOOT_DEVICE_TABLE_RECORD_STRIDE as usize;

/// Maximum combined required-artifact input held before the handoff builder
/// consumes it. It is the exact sum of the per-artifact caps, preventing an
/// accidental future cap increase from silently admitting an unbounded total.
pub const MAX_TOTAL_ARTIFACT_BYTES: usize = MAX_KERNEL_ARTIFACT_BYTES
    + MAX_BOOTSTRAP_ARTIFACT_BYTES
    + MAX_BOOTFS_ARTIFACT_BYTES
    + MAX_BOOT_DEVICE_TABLE_ARTIFACT_BYTES;

/// ACPI RSDP v1 is exactly this many bytes.
pub const ACPI_RSDP_V1_BYTES: usize = 20;
/// ACPI RSDP revision 2 and later require at least this many bytes.
pub const ACPI_RSDP_V2_MIN_BYTES: usize = 36;
/// Loader-local upper bound for an extended RSDP length field.
pub const MAX_ACPI_RSDP_BYTES: usize = UEFI_PAGE_BYTES;

/// Fail-closed errors that can be normalized without firmware access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparationError {
    Config(ConfigError),
    PageCountOverflow,
    AllocationExtentMismatch,
    EmptyArtifact,
    ArtifactTooLarge,
    ArtifactLengthNotRepresentable,
    TotalArtifactLimitExceeded,
    #[allow(dead_code)] // Target-only generated-policy validation consumes this.
    IntakeCapacityExceeded,
    InvalidAcpiRsdpAddress,
    InvalidAcpiRsdpSignature,
    InvalidAcpiRsdpLength,
    InvalidAcpiRsdpChecksum,
    DuplicateSelectedAcpiGuid,
    #[allow(dead_code)] // Returned by the pending generated-policy mapping bridge.
    InvalidMappingGranule,
    #[allow(dead_code)] // Returned by the pending generated-policy mapping bridge.
    AcpiRangeOverflow,
    #[allow(dead_code)] // Returned by the pending generated-policy mapping bridge.
    AcpiMappingExceedsTwoPages,
}

/// Parsed facts needed to retain a validated RSDP without inventing an ACPI
/// table ABI for later handoff code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcpiRsdpLayout {
    pub revision: u8,
    pub byte_len: usize,
}

/// Firmware configuration-table identity relevant to RSDP selection only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcpiRsdpConfigKind {
    Acpi1,
    Acpi2,
}

/// A configuration-table candidate normalized without retaining UEFI types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcpiRsdpConfigCandidate {
    pub kind: AcpiRsdpConfigKind,
    pub physical_start: u64,
}

/// The one contiguous identity range covering the one or two base pages that
/// intersect a retained, validated RSDP record.
#[allow(dead_code)] // Consumed by the pending generated-policy mapping bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcpiRsdpPageRange {
    pub physical_start: u64,
    pub byte_len: u64,
}

#[allow(dead_code)] // Consumed by the pending generated-policy mapping bridge.
impl AcpiRsdpPageRange {
    pub const fn page_count(self, page_granule: u64) -> u64 {
        self.byte_len / page_granule
    }
}

/// Selects ACPI 2.0 when present. A duplicate selected GUID is ambiguous and
/// rejected; a malformed selected ACPI2 record is later rejected in-place and
/// must never trigger a silent ACPI1 downgrade.
pub fn select_rsdp_candidate(
    candidates: impl IntoIterator<Item = AcpiRsdpConfigCandidate>,
) -> Result<Option<AcpiRsdpConfigCandidate>, PreparationError> {
    let mut acpi1 = None;
    let mut acpi2 = None;
    let mut duplicate_acpi1 = false;
    for candidate in candidates {
        match candidate.kind {
            AcpiRsdpConfigKind::Acpi1 => {
                duplicate_acpi1 |= acpi1.replace(candidate).is_some();
            }
            AcpiRsdpConfigKind::Acpi2 => {
                if acpi2.replace(candidate).is_some() {
                    return Err(PreparationError::DuplicateSelectedAcpiGuid);
                }
            }
        }
    }
    if let Some(acpi2) = acpi2 {
        return Ok(Some(acpi2));
    }
    if duplicate_acpi1 {
        return Err(PreparationError::DuplicateSelectedAcpiGuid);
    }
    Ok(acpi1)
}

/// Derives the exact base pages required for a retained validated RSDP. The
/// caller supplies the generated base-page granule; no local ACPI mapping cap
/// or traversal policy is introduced here.
#[allow(dead_code)] // Consumed by the pending generated-policy mapping bridge.
pub fn rsdp_intersecting_pages(
    physical_start: u64,
    record_byte_len: u64,
    page_granule: u64,
) -> Result<AcpiRsdpPageRange, PreparationError> {
    if page_granule == 0 || !page_granule.is_power_of_two() || record_byte_len == 0 {
        return Err(PreparationError::InvalidMappingGranule);
    }
    let record_end = physical_start
        .checked_add(record_byte_len - 1)
        .ok_or(PreparationError::AcpiRangeOverflow)?;
    let page_mask = page_granule - 1;
    let first_page = physical_start & !page_mask;
    let last_page = record_end & !page_mask;
    let byte_len = last_page
        .checked_sub(first_page)
        .and_then(|span| span.checked_add(page_granule))
        .ok_or(PreparationError::AcpiRangeOverflow)?;
    if byte_len > page_granule.saturating_mul(2) {
        return Err(PreparationError::AcpiMappingExceedsTwoPages);
    }
    Ok(AcpiRsdpPageRange {
        physical_start: first_page,
        byte_len,
    })
}

/// Validates the firmware-supplied UEFI configuration-table RSDP pointer before raw byte reads.
///
/// The ACPI 16-byte rule applies to the legacy IA-PC memory-search procedure,
/// not to the pointer supplied directly through the UEFI configuration table.
pub fn validate_acpi_rsdp_address(address: usize) -> Result<(), PreparationError> {
    if address == 0 || address.checked_add(MAX_ACPI_RSDP_BYTES).is_none() {
        return Err(PreparationError::InvalidAcpiRsdpAddress);
    }
    Ok(())
}

/// Parses an absent optional configuration as the canonical default.
pub fn normalize_optional_config(input: Option<&[u8]>) -> Result<LoaderConfig, PreparationError> {
    match input {
        Some(bytes) => LoaderConfig::parse(bytes).map_err(PreparationError::Config),
        None => Ok(LoaderConfig::DEFAULT),
    }
}

/// Admits a non-empty file length before allocating a payload buffer.
pub fn bounded_artifact_len(byte_len: u64, cap: usize) -> Result<usize, PreparationError> {
    let byte_len =
        usize::try_from(byte_len).map_err(|_| PreparationError::ArtifactLengthNotRepresentable)?;
    if byte_len == 0 {
        return Err(PreparationError::EmptyArtifact);
    }
    if byte_len > cap {
        return Err(PreparationError::ArtifactTooLarge);
    }
    Ok(byte_len)
}

/// Checks the aggregate input budget with overflow protection.
pub fn total_artifact_bytes(
    lengths: impl IntoIterator<Item = usize>,
) -> Result<usize, PreparationError> {
    let total = lengths.into_iter().try_fold(0_usize, |total, length| {
        total
            .checked_add(length)
            .ok_or(PreparationError::TotalArtifactLimitExceeded)
    })?;
    if total > MAX_TOTAL_ARTIFACT_BYTES {
        return Err(PreparationError::TotalArtifactLimitExceeded);
    }
    Ok(total)
}

/// Converts a generated intake capacity into a checked local slice length and
/// rejects an observed count before it can index caller-provided storage.
///
/// The caller supplies the generated capacity; this helper deliberately does
/// not carry a second local memory-map or module cap.
#[allow(dead_code)] // Used by target-only generated-policy validation and host tests.
pub fn bounded_intake_count(observed: usize, capacity: u64) -> Result<usize, PreparationError> {
    let capacity =
        usize::try_from(capacity).map_err(|_| PreparationError::IntakeCapacityExceeded)?;
    if observed > capacity {
        return Err(PreparationError::IntakeCapacityExceeded);
    }
    Ok(observed)
}

/// Computes the exact number of UEFI pages needed for a non-empty payload.
pub fn pages_for_payload(byte_len: usize) -> Result<usize, PreparationError> {
    if byte_len == 0 {
        return Err(PreparationError::EmptyArtifact);
    }
    byte_len
        .checked_add(UEFI_PAGE_BYTES - 1)
        .map(|rounded| rounded / UEFI_PAGE_BYTES)
        .ok_or(PreparationError::PageCountOverflow)
}

/// Full page-backed allocation extent for one payload. This is distinct from
/// the exact payload length exposed in module records.
pub fn allocation_bytes_for_payload(byte_len: usize) -> Result<usize, PreparationError> {
    pages_for_payload(byte_len)?
        .checked_mul(UEFI_PAGE_BYTES)
        .ok_or(PreparationError::PageCountOverflow)
}

/// Initializes the entire retained allocation before copying exact payload
/// bytes. This pure seam prevents page slack from retaining firmware data.
pub fn initialize_payload_allocation(
    allocation: &mut [u8],
    payload: &[u8],
) -> Result<(), PreparationError> {
    if allocation.len() != allocation_bytes_for_payload(payload.len())? {
        return Err(PreparationError::AllocationExtentMismatch);
    }
    allocation.fill(0);
    allocation[..payload.len()].copy_from_slice(payload);
    Ok(())
}

/// Validates an ACPI RSDP byte range before it becomes a handoff dependency.
pub fn validate_acpi_rsdp(bytes: &[u8]) -> Result<AcpiRsdpLayout, PreparationError> {
    if bytes.len() < ACPI_RSDP_V1_BYTES || bytes[..8] != *b"RSD PTR " {
        return Err(PreparationError::InvalidAcpiRsdpSignature);
    }
    if checksum(bytes, ACPI_RSDP_V1_BYTES) != 0 {
        return Err(PreparationError::InvalidAcpiRsdpChecksum);
    }

    let revision = bytes[15];
    if revision < 2 {
        return Ok(AcpiRsdpLayout {
            revision,
            byte_len: ACPI_RSDP_V1_BYTES,
        });
    }
    if bytes.len() < 24 {
        return Err(PreparationError::InvalidAcpiRsdpLength);
    }
    let byte_len = u32::from_le_bytes(bytes[20..24].try_into().expect("fixed slice length"));
    let byte_len =
        usize::try_from(byte_len).map_err(|_| PreparationError::InvalidAcpiRsdpLength)?;
    if !(ACPI_RSDP_V2_MIN_BYTES..=MAX_ACPI_RSDP_BYTES).contains(&byte_len) || bytes.len() < byte_len
    {
        return Err(PreparationError::InvalidAcpiRsdpLength);
    }
    if checksum(bytes, byte_len) != 0 {
        return Err(PreparationError::InvalidAcpiRsdpChecksum);
    }
    Ok(AcpiRsdpLayout { revision, byte_len })
}

fn checksum(bytes: &[u8], byte_len: usize) -> u8 {
    bytes[..byte_len]
        .iter()
        .fold(0_u8, |sum, byte| sum.wrapping_add(*byte))
}

/// Consume an owned pre-EBS resource at most once.
///
/// The firmware transaction uses this helper for every optional rollback slot;
/// a second cleanup pass observes `None` and therefore cannot free the same
/// pages twice.
pub fn take_owned_resource_once<T>(slot: &mut Option<T>, consume: impl FnOnce(T)) -> bool {
    match slot.take() {
        Some(value) => {
            consume(value);
            true
        }
        None => false,
    }
}

/// Post-EBS failure classes. Every one is fatal because firmware services are
/// no longer callable and a partially built handoff must not reach the kernel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostExitGateError {
    FinalMemoryMap,
    BootInfo,
    PageTable,
    SerialDiagnostic,
    Transfer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalMemoryMapAccepted {
    _private: (),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootInfoAccepted {
    _private: (),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageTableAccepted {
    _private: (),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SerialDiagnosticAccepted {
    _private: (),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferAccepted {
    _private: (),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedAddressesAccepted {
    _private: (),
}

pub struct RetainedAddressFacts<'a> {
    pub boot_info: wyrmroot_efi_loader::boot_info::HandoffAllocation,
    pub memory_map: wyrmroot_efi_loader::boot_info::HandoffAllocation,
    pub module_table: wyrmroot_efi_loader::boot_info::HandoffAllocation,
    pub module_records: &'a [deepwyrm_abi::DwBootModuleV1],
    pub module_allocations: &'a [wyrmroot_efi_loader::transition::RetainedPhysicalRange],
    pub entropy: Option<(
        wyrmroot_efi_loader::boot_info::HandoffAllocation,
        wyrmroot_efi_loader::transition::RetainedPhysicalRange,
    )>,
    pub rsdp: Option<(
        wyrmroot_efi_loader::boot_info::HandoffAllocation,
        wyrmroot_efi_loader::transition::ValidatedRsdpMappingInput,
    )>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedAddressError {
    MissingOrDuplicateMapping,
    StorageMappingMismatch,
    ModuleCountMismatch,
    ModuleRecordMismatch,
    OptionalMappingMismatch,
}

/// Unforgeable authorization consumed by the target-only raw jump wrapper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JumpAuthorization {
    _private: (),
}

pub fn accept_final_memory_map<T, E>(
    result: Result<T, E>,
) -> Result<(T, FinalMemoryMapAccepted), PostExitGateError> {
    result
        .map(|value| (value, FinalMemoryMapAccepted { _private: () }))
        .map_err(|_| PostExitGateError::FinalMemoryMap)
}

pub fn accept_boot_info<T, E>(
    result: Result<T, E>,
) -> Result<(T, BootInfoAccepted), PostExitGateError> {
    result
        .map(|value| (value, BootInfoAccepted { _private: () }))
        .map_err(|_| PostExitGateError::BootInfo)
}

pub fn accept_page_table<T, E>(
    result: Result<T, E>,
) -> Result<(T, PageTableAccepted), PostExitGateError> {
    result
        .map(|value| (value, PageTableAccepted { _private: () }))
        .map_err(|_| PostExitGateError::PageTable)
}

pub fn accept_serial_diagnostic<T, E>(
    result: Result<T, E>,
) -> Result<(T, SerialDiagnosticAccepted), PostExitGateError> {
    result
        .map(|value| (value, SerialDiagnosticAccepted { _private: () }))
        .map_err(|_| PostExitGateError::SerialDiagnostic)
}

pub fn accept_transfer<T, E>(
    result: Result<T, E>,
) -> Result<(T, TransferAccepted), PostExitGateError> {
    result
        .map(|value| (value, TransferAccepted { _private: () }))
        .map_err(|_| PostExitGateError::Transfer)
}

pub fn authorize_jump(
    _memory_map: FinalMemoryMapAccepted,
    _boot_info: BootInfoAccepted,
    _page_table: PageTableAccepted,
    _serial: SerialDiagnosticAccepted,
    _transfer: TransferAccepted,
    _retained_addresses: RetainedAddressesAccepted,
) -> JumpAuthorization {
    JumpAuthorization { _private: () }
}

pub fn validate_retained_address_coherence(
    mappings: &[wyrmroot_efi_loader::transition::TransitionMapping],
    facts: RetainedAddressFacts<'_>,
) -> Result<RetainedAddressesAccepted, RetainedAddressError> {
    use wyrmroot_efi_loader::transition::{MappingKind, RetainedPhysicalRange};

    fn exact_mapping(
        mappings: &[wyrmroot_efi_loader::transition::TransitionMapping],
        kind: MappingKind,
        expected: RetainedPhysicalRange,
    ) -> Result<(), RetainedAddressError> {
        let mut matches = mappings.iter().filter(|mapping| mapping.kind == kind);
        let mapping = matches
            .next()
            .ok_or(RetainedAddressError::MissingOrDuplicateMapping)?;
        if matches.next().is_some() {
            return Err(RetainedAddressError::MissingOrDuplicateMapping);
        }
        if mapping.physical_start != expected.physical_start
            || mapping.virtual_start != expected.physical_start
            || mapping.byte_len != expected.byte_len
        {
            return Err(RetainedAddressError::StorageMappingMismatch);
        }
        Ok(())
    }

    fn allocation(
        value: wyrmroot_efi_loader::boot_info::HandoffAllocation,
    ) -> RetainedPhysicalRange {
        RetainedPhysicalRange {
            physical_start: value.physical_start,
            byte_len: value.byte_len,
            lifetime: wyrmroot_efi_loader::transition::AllocationLifetime::RetainedUntilKernelPageTableReplacement,
        }
    }

    exact_mapping(mappings, MappingKind::BootInfo, allocation(facts.boot_info))?;
    exact_mapping(
        mappings,
        MappingKind::MemoryMapTable,
        allocation(facts.memory_map),
    )?;
    exact_mapping(
        mappings,
        MappingKind::ModuleTable,
        allocation(facts.module_table),
    )?;
    if facts.module_records.len() != facts.module_allocations.len() {
        return Err(RetainedAddressError::ModuleCountMismatch);
    }
    for (index, (record, allocation)) in facts
        .module_records
        .iter()
        .zip(facts.module_allocations)
        .enumerate()
    {
        if record.physical_start != allocation.physical_start
            || record.byte_len == 0
            || record.byte_len > allocation.byte_len
        {
            return Err(RetainedAddressError::ModuleRecordMismatch);
        }
        exact_mapping(mappings, MappingKind::ModuleData { index }, *allocation)?;
    }
    match facts.entropy {
        Some((storage, expected)) => {
            if allocation(storage) != expected {
                return Err(RetainedAddressError::OptionalMappingMismatch);
            }
            exact_mapping(mappings, MappingKind::Entropy, expected)?;
        }
        None if mappings
            .iter()
            .any(|mapping| mapping.kind == MappingKind::Entropy) =>
        {
            return Err(RetainedAddressError::OptionalMappingMismatch);
        }
        None => {}
    }
    match facts.rsdp {
        Some((storage, expected)) => {
            if allocation(storage) != expected.retained_allocation {
                return Err(RetainedAddressError::OptionalMappingMismatch);
            }
            exact_mapping(
                mappings,
                MappingKind::RequiredAcpiRsdp,
                expected.retained_allocation,
            )?;
        }
        None if mappings
            .iter()
            .any(|mapping| mapping.kind == MappingKind::RequiredAcpiRsdp) =>
        {
            return Err(RetainedAddressError::OptionalMappingMismatch);
        }
        None => {}
    }
    Ok(RetainedAddressesAccepted { _private: () })
}

/// Dispatch one post-EBS gate failure to its sole fatal sink. The target sink
/// is the local `cli; hlt` loop; host tests inject a recorder to prove the
/// failure is delivered exactly once without a firmware call.
pub fn dispatch_post_exit_failure<R>(
    error: PostExitGateError,
    fatal: impl FnOnce(PostExitGateError) -> R,
) -> R {
    fatal(error)
}

#[cfg(feature = "firmware")]
mod firmware;

#[cfg(all(feature = "firmware", target_arch = "x86_64", target_os = "uefi"))]
pub use firmware::{GeneratedHandoffPolicy, run_handoff};
