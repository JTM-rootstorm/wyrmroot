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

/// Maximum combined required-artifact input held before the handoff builder
/// consumes it. It is the exact sum of the per-artifact caps, preventing an
/// accidental future cap increase from silently admitting an unbounded total.
pub const MAX_TOTAL_ARTIFACT_BYTES: usize =
    MAX_KERNEL_ARTIFACT_BYTES + MAX_BOOTSTRAP_ARTIFACT_BYTES + MAX_BOOTFS_ARTIFACT_BYTES;

/// ACPI RSDP v1 is exactly this many bytes.
pub const ACPI_RSDP_V1_BYTES: usize = 20;
/// ACPI RSDP revision 2 and later require at least this many bytes.
pub const ACPI_RSDP_V2_MIN_BYTES: usize = 36;
/// A configuration-table RSDP must have this alignment.
pub const ACPI_RSDP_ALIGNMENT: usize = 16;
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
    InvalidAcpiRsdpAlignment,
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

/// Validates the firmware-supplied RSDP address before any raw dereference.
pub fn validate_acpi_rsdp_address(address: usize) -> Result<(), PreparationError> {
    if address == 0 || !address.is_multiple_of(ACPI_RSDP_ALIGNMENT) {
        return Err(PreparationError::InvalidAcpiRsdpAlignment);
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
pub fn total_artifact_bytes(lengths: [usize; 3]) -> Result<usize, PreparationError> {
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
mod firmware {
    extern crate alloc;

    use alloc::vec::Vec;
    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    use core::arch::x86_64::__cpuid;
    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    use core::mem::{align_of, size_of};
    use core::ptr::{self, NonNull};

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    use deepwyrm_abi::{
        DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS, DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP, DwBootInfoV1,
        DwBootMemoryRangeV1, DwBootModuleV1,
    };
    use uefi::boot::{
        self, AllocateType, MemoryType, MemoryType as UefiMemoryType, ScopedProtocol,
    };
    use uefi::mem::memory_map::{MemoryMap, MemoryMapMut};
    use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
    use uefi::proto::media::file::{Directory, File, FileAttribute, FileInfo, FileMode};
    use uefi::proto::rng::Rng;
    use uefi::table::cfg::ConfigTableEntry;
    use uefi::{CString16, Status, system};
    use wyrmroot_efi_loader::artifacts::{
        ArtifactInputs, BOOTFS_PATH, BOOTSTRAP_PATH, KERNEL_PATH,
    };
    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    use wyrmroot_efi_loader::boot_info::{
        AllocationLifetime as BootInfoAllocationLifetime, HandoffAllocation,
    };
    use wyrmroot_efi_loader::transition::{AllocationLifetime, RetainedPhysicalRange};

    use super::{
        ACPI_RSDP_V1_BYTES, ACPI_RSDP_V2_MIN_BYTES, AcpiRsdpLayout, CONFIG_PATH,
        MAX_ACPI_RSDP_BYTES, MAX_BOOTFS_ARTIFACT_BYTES, MAX_BOOTSTRAP_ARTIFACT_BYTES,
        MAX_CONFIG_BYTES, MAX_KERNEL_ARTIFACT_BYTES, PreparationError, bounded_artifact_len,
        pages_for_payload, total_artifact_bytes, validate_acpi_rsdp, validate_acpi_rsdp_address,
    };

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    use wyrmroot_efi_loader::{
        boot_info::{
            self, AcpiRsdpInput, BootInfoInput, BootInfoLimits, BootInfoOutput, EntropyInput,
            FirmwareEntropySource as BootInfoEntropySource, FirmwarePhase,
            FramebufferInput as BootInfoFramebufferInput,
            FramebufferPixelFormat as BootInfoPixelFormat, UefiMemoryKind,
        },
        kernel_elf::{self, AddressRange, KernelElfPolicy, KernelLoadSegment, SegmentPermissions},
        memory_map::{self, FirmwareMemoryDescriptor},
        modules::{self, ModuleInput},
        transition::{
            self, IdentityMapInputs, KernelMaterialization, KernelSegmentPages, PhysicalRange,
            TransitionMapping, TransitionPolicy, TransitionPreflightInput,
            ValidatedRsdpMappingInput,
        },
    };

    /// The exact purpose of a pre-EBS allocation. Byte and page counts remain
    /// caller inputs until the pinned Deepwyrm layout manifest is available.
    #[allow(dead_code)] // Final transaction inputs are supplied after ABI policy generation.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum PreExitAllocationPurpose {
        KernelSegment { program_header_index: u16 },
        PageTableStorage,
        TransitionStack,
        BootInfo,
        MemoryMapTable,
        ModuleTable,
        HandoffScratch,
    }

    /// One caller-sized request for an exact zeroed LoaderData allocation.
    #[allow(dead_code)] // Final transaction inputs are supplied after ABI policy generation.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct PreExitAllocationRequest {
        pub purpose: PreExitAllocationPurpose,
        pub page_count: usize,
    }

    /// Firmware-specific failure before boot services have exited.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum FirmwarePreparationError {
        FileSystem,
        Artifact(PreparationError),
        PageAllocation,
        Config(PreparationError),
        Allocation,
        ShortRead,
        Acpi(PreparationError),
        InvalidPreExitAllocation,
        DuplicatePreExitAllocation,
        PreExitAllocationSlotsExhausted,
        CopyRangeInvalid,
        #[allow(dead_code)] // Constructed by the pending kernel materialization bridge.
        KernelSourceReleased,
        #[allow(dead_code)] // Constructed by target-only CPUID probing.
        CpuMaxPhysicalAddressUnavailable,
        #[allow(dead_code)] // Constructed by target-only named typed-view methods.
        TypedViewInvalid,
        #[allow(dead_code)] // Constructed by target-only generated-granule guard.
        GeneratedPageGranuleMismatch,
        #[allow(dead_code)] // Constructed only in the x86_64 UEFI target discovery path.
        LinkedHandoffStub,
        #[allow(dead_code)] // Constructed only by the target-only policy boundary.
        InvalidGeneratedPolicy,
    }

    /// Generated Deepwyrm values consumed by the target-only adapter. Keeping
    /// these in one typed object prevents later transaction stages from
    /// reaching back to environment-generated constants ad hoc.
    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct GeneratedHandoffPolicy {
        pub link_base: u64,
        pub base_page_size: u64,
        pub elf_window_start: u64,
        pub elf_window_end_exclusive: u64,
        pub transition_stack_size: u64,
        pub transition_stack_alignment: u64,
        pub stack_pointer_mod_16: u64,
        pub boot_info_alignment: u64,
        pub max_normalized_memory_map_entries: u64,
        pub max_module_entries: u64,
        pub max_acpi_rsdp_intersecting_pages: u64,
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    impl GeneratedHandoffPolicy {
        pub fn validate(self) -> Result<(), FirmwarePreparationError> {
            if self.base_page_size != super::UEFI_PAGE_BYTES as u64
                || self.link_base != self.elf_window_start
                || self.elf_window_end_exclusive <= self.elf_window_start
                || self.transition_stack_size == 0
                || !self
                    .transition_stack_size
                    .is_multiple_of(self.base_page_size)
                || !self.transition_stack_alignment.is_power_of_two()
                || self.transition_stack_alignment < self.base_page_size
                || self.stack_pointer_mod_16 != 0
                || !self.boot_info_alignment.is_power_of_two()
                || self.max_normalized_memory_map_entries == 0
                || self.max_module_entries == 0
                || !(1..=2).contains(&self.max_acpi_rsdp_intersecting_pages)
            {
                return Err(FirmwarePreparationError::InvalidGeneratedPolicy);
            }
            super::bounded_intake_count(0, self.max_normalized_memory_map_entries)
                .map_err(|_| FirmwarePreparationError::InvalidGeneratedPolicy)?;
            super::bounded_intake_count(0, self.max_module_entries)
                .map_err(|_| FirmwarePreparationError::InvalidGeneratedPolicy)?;
            Ok(())
        }
    }

    /// Explicit firmware-entropy outcome; neither absence nor failure receives
    /// a synthetic replacement value. Successful bytes are retained in pages.
    #[derive(Debug)]
    pub enum FirmwareEntropy {
        Available {
            storage: RetainedPages,
            #[allow(dead_code)] // Forwarded unchanged to canonical BootInfo construction.
            source: FirmwareEntropySource,
            #[allow(dead_code)] // Forwarded unchanged to canonical BootInfo construction.
            conditioned: bool,
        },
        Unavailable,
        Failed,
    }

    /// The loader records firmware entropy provenance explicitly instead of
    /// inferring a property from the storage location.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum FirmwareEntropySource {
        UefiRngProtocol,
    }

    /// GOP pixel layout copied from firmware. RGB and BGR formats have their
    /// implied UEFI 8-bit layouts; bitmask mode carries all four raw masks.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum FramebufferPixelFormat {
        Rgb,
        Bgr,
        Bitmask {
            red_mask: u32,
            green_mask: u32,
            blue_mask: u32,
            reserved_mask: u32,
        },
    }

    /// Copied optional GOP metadata. No framebuffer access is attempted here.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct FramebufferMetadata {
        pub physical_base: u64,
        pub byte_len: u64,
        pub width: u32,
        pub height: u32,
        pub pixels_per_scan_line: u32,
        pub pixel_format: FramebufferPixelFormat,
    }

    /// A validated and copied ACPI RSDP. The retained range, rather than the
    /// firmware configuration-table pointer, is what later mapping owns.
    #[allow(dead_code)] // Consumed by the pending canonical BootInfo adapter.
    #[derive(Debug)]
    pub struct AcpiRsdp {
        pub storage: RetainedPages,
        pub revision: u8,
        pub byte_len: usize,
    }

    /// Page-backed storage retained through the handoff boundary.
    #[allow(dead_code)] // Physical/length facts are consumed by transition mapping.
    #[derive(Debug)]
    pub struct RetainedPages {
        ptr: NonNull<u8>,
        page_count: usize,
        allocation_byte_len: usize,
        payload_byte_len: usize,
    }

    #[allow(dead_code)] // Includes the pending pre-EBS segment/table allocation API.
    impl RetainedPages {
        pub fn physical_start(&self) -> u64 {
            self.ptr.as_ptr() as u64
        }

        /// Full page-rounded retained extent. Collision, mapping, and lifetime
        /// checks must use this value, never the smaller payload byte length.
        pub const fn allocation_byte_len(&self) -> usize {
            self.allocation_byte_len
        }

        /// Exact initialized payload length used for module/entropy/RSDP data.
        pub const fn payload_byte_len(&self) -> usize {
            self.payload_byte_len
        }

        pub const fn page_count(&self) -> usize {
            self.page_count
        }

        /// Full retained physical allocation for overlap and transition
        /// planning. Payload consumers must use `payload_byte_len` instead.
        pub fn retained_physical_range(
            &self,
        ) -> Result<RetainedPhysicalRange, FirmwarePreparationError> {
            Ok(RetainedPhysicalRange {
                physical_start: self.physical_start(),
                byte_len: u64::try_from(self.allocation_byte_len)
                    .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?,
                lifetime: AllocationLifetime::RetainedUntilKernelPageTableReplacement,
            })
        }

        /// Converts only this owned allocation into the BootInfo lifetime
        /// model. The full page-rounded extent is intentionally published so
        /// storage-reservation and alias checks include zeroed slack.
        #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
        pub fn boot_info_allocation(&self) -> Result<HandoffAllocation, FirmwarePreparationError> {
            Ok(HandoffAllocation {
                physical_start: self.physical_start(),
                byte_len: u64::try_from(self.allocation_byte_len)
                    .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?,
                lifetime: BootInfoAllocationLifetime::RetainedUntilDeepwyrmPageTableReplacement,
            })
        }

        unsafe fn release(self) {
            // SAFETY: this helper is called only before ExitBootServices, with
            // the exact pointer/count returned by `allocate_pages`, and no
            // references into the allocation escape its caller on that path.
            unsafe { boot::free_pages(self.ptr, self.page_count) }
                .expect("retained pre-exit pages must be releasable");
        }

        /// Allocates exactly `page_count` fresh LoaderData pages and clears the
        /// full allocation before any kernel segment or handoff table copy.
        fn allocate_zeroed_pages(page_count: usize) -> Result<Self, FirmwarePreparationError> {
            if page_count == 0 {
                return Err(FirmwarePreparationError::InvalidPreExitAllocation);
            }
            let allocation_byte_len = page_count
                .checked_mul(super::UEFI_PAGE_BYTES)
                .ok_or(FirmwarePreparationError::InvalidPreExitAllocation)?;
            let ptr = boot::allocate_pages(
                AllocateType::AnyPages,
                UefiMemoryType::LOADER_DATA,
                page_count,
            )
            .map_err(|_| FirmwarePreparationError::PageAllocation)?;
            // SAFETY: UEFI returned exactly `page_count` writable base pages;
            // `allocation_byte_len` is their checked extent and no alias to this fresh
            // allocation exists while it is being initialized.
            unsafe { ptr::write_bytes(ptr.as_ptr(), 0, allocation_byte_len) };
            Ok(Self {
                ptr,
                page_count,
                allocation_byte_len,
                payload_byte_len: allocation_byte_len,
            })
        }

        /// Copies a bounded source slice into already-zeroed retained pages.
        /// The caller supplies the ELF file range after hostile-input planning;
        /// omitted bytes remain zero for BSS and page padding.
        pub fn copy_zeroed_from(
            &mut self,
            destination_offset: usize,
            source: &[u8],
        ) -> Result<(), FirmwarePreparationError> {
            let destination_end = destination_offset
                .checked_add(source.len())
                .ok_or(FirmwarePreparationError::CopyRangeInvalid)?;
            if destination_end > self.allocation_byte_len {
                return Err(FirmwarePreparationError::CopyRangeInvalid);
            }
            // SAFETY: `destination_end` was checked against this allocation's
            // exact extent; source is a valid slice and retained pages do not
            // alias its firmware-pool backing storage.
            unsafe {
                ptr::copy_nonoverlapping(
                    source.as_ptr(),
                    self.ptr.as_ptr().add(destination_offset),
                    source.len(),
                )
            };
            Ok(())
        }

        /// Borrows the whole zeroed allocation as exact x86_64 page-table
        /// pages. The allocation remains owned by `self` throughout the
        /// callback and therefore cannot be freed or outlive the handoff.
        #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
        pub fn with_page_table_pages<R>(
            &mut self,
            callback: impl FnOnce(&mut [crate::uefi_page_table::PageTablePage]) -> R,
        ) -> Result<R, FirmwarePreparationError> {
            verify_generated_base_page_size()?;
            let page_bytes = size_of::<crate::uefi_page_table::PageTablePage>();
            if self.allocation_byte_len == 0 || self.allocation_byte_len % page_bytes != 0 {
                return Err(FirmwarePreparationError::TypedViewInvalid);
            }
            let count = self.allocation_byte_len / page_bytes;
            // SAFETY: the named page-table view validates alignment, checked
            // extent, and unique ownership below; it cannot escape this borrow.
            let pages =
                unsafe { self.typed_slice_mut::<crate::uefi_page_table::PageTablePage>(count)? };
            Ok(callback(pages))
        }

        /// Borrows one generated BootInfo object from preallocated storage.
        #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
        pub fn with_boot_info<R>(
            &mut self,
            callback: impl FnOnce(&mut DwBootInfoV1) -> R,
        ) -> Result<R, FirmwarePreparationError> {
            verify_generated_base_page_size()?;
            // SAFETY: this named view retains unique ownership and checks the
            // generated type's alignment and exact one-element extent.
            let values = unsafe { self.typed_slice_mut::<DwBootInfoV1>(1)? };
            Ok(callback(&mut values[0]))
        }

        /// Borrows exactly `count` generated memory-map records from retained
        /// storage; count comes from final post-EBS map normalization.
        #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
        pub fn with_memory_map_records<R>(
            &mut self,
            count: usize,
            callback: impl FnOnce(&mut [DwBootMemoryRangeV1]) -> R,
        ) -> Result<R, FirmwarePreparationError> {
            verify_generated_base_page_size()?;
            // SAFETY: this named view retains unique ownership and validates
            // count/extent before exposing generated ABI records.
            let values = unsafe { self.typed_slice_mut::<DwBootMemoryRangeV1>(count)? };
            Ok(callback(values))
        }

        /// Borrows exactly `count` generated module records from retained
        /// storage; canonical module ordering remains owned by `modules`.
        #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
        pub fn with_module_records<R>(
            &mut self,
            count: usize,
            callback: impl FnOnce(&mut [DwBootModuleV1]) -> R,
        ) -> Result<R, FirmwarePreparationError> {
            verify_generated_base_page_size()?;
            // SAFETY: this named view retains unique ownership and validates
            // count/extent before exposing generated ABI records.
            let values = unsafe { self.typed_slice_mut::<DwBootModuleV1>(count)? };
            Ok(callback(values))
        }

        /// The only raw conversion point. It is private so no caller can cast
        /// retained pages into an arbitrary public type.
        #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
        unsafe fn typed_slice_mut<T>(
            &mut self,
            count: usize,
        ) -> Result<&mut [T], FirmwarePreparationError> {
            let element_size = size_of::<T>();
            if element_size == 0 || (self.ptr.as_ptr() as usize) % align_of::<T>() != 0 {
                return Err(FirmwarePreparationError::TypedViewInvalid);
            }
            let byte_len = count
                .checked_mul(element_size)
                .ok_or(FirmwarePreparationError::TypedViewInvalid)?;
            if byte_len > self.allocation_byte_len {
                return Err(FirmwarePreparationError::TypedViewInvalid);
            }
            // SAFETY: caller selected one of the named ABI/page-table types;
            // this unique `&mut self` owns at least `byte_len` aligned bytes.
            Ok(unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr().cast::<T>(), count) })
        }
    }

    /// One fixed caller-owned slot. Avoiding a growable vector ensures that no
    /// hidden allocator-backed metadata survives into the final EBS boundary.
    #[allow(dead_code)] // Fixed slots avoid allocator-backed metadata at the EBS boundary.
    #[derive(Debug)]
    pub struct PreExitAllocationSlot {
        purpose: Option<PreExitAllocationPurpose>,
        storage: Option<RetainedPages>,
    }

    #[allow(dead_code)] // Called by the final command-scoped handoff builder.
    impl PreExitAllocationSlot {
        pub const fn empty() -> Self {
            Self {
                purpose: None,
                storage: None,
            }
        }
    }

    /// Ownership-complete pre-EBS allocation transaction. The future
    /// transition/BootInfo adapter must use this for every extra allocation,
    /// then consume the transaction only after it has built one full plan.
    #[allow(dead_code)] // Activated once transition and BootInfo inputs share ownership.
    #[derive(Debug)]
    pub struct PreExitTransaction<'slots> {
        prepared: PreparedPreExit,
        slots: &'slots mut [PreExitAllocationSlot],
    }

    #[allow(dead_code)] // Activated once transition and BootInfo inputs share ownership.
    impl<'slots> PreExitTransaction<'slots> {
        pub fn begin(
            prepared: PreparedPreExit,
            slots: &'slots mut [PreExitAllocationSlot],
        ) -> Result<Self, FirmwarePreparationError> {
            if slots
                .iter()
                .any(|slot| slot.purpose.is_some() || slot.storage.is_some())
            {
                return Err(FirmwarePreparationError::InvalidPreExitAllocation);
            }
            Ok(Self { prepared, slots })
        }

        /// Allocates and zeroes one exact, caller-specified handoff object.
        pub fn allocate(
            &mut self,
            request: PreExitAllocationRequest,
        ) -> Result<&mut RetainedPages, FirmwarePreparationError> {
            if request.page_count == 0 {
                return Err(FirmwarePreparationError::InvalidPreExitAllocation);
            }
            if self
                .slots
                .iter()
                .any(|slot| slot.purpose == Some(request.purpose))
            {
                return Err(FirmwarePreparationError::DuplicatePreExitAllocation);
            }
            let slot = self
                .slots
                .iter_mut()
                .find(|slot| slot.storage.is_none())
                .ok_or(FirmwarePreparationError::PreExitAllocationSlotsExhausted)?;
            let storage = RetainedPages::allocate_zeroed_pages(request.page_count)?;
            slot.purpose = Some(request.purpose);
            slot.storage = Some(storage);
            // The slot was populated immediately above and stays uniquely
            // borrowed through `self`, so its retained-page metadata is valid.
            Ok(slot.storage.as_mut().expect("just populated pre-exit slot"))
        }

        /// Releases every page on a failure path before boot services exit.
        pub fn abort_before_exit(self) {
            for slot in &mut *self.slots {
                if let Some(storage) = slot.storage.take() {
                    // SAFETY: transaction abort is exclusively pre-EBS and no
                    // reference into a failed transaction may escape.
                    unsafe { storage.release() };
                }
                slot.purpose = None;
            }
            self.prepared.release_before_exit();
        }

        /// Exposes the original retained artifact state only to the final
        /// ownership-complete builder. It must not call EBS until it has also
        /// converted all slots into the transition and BootInfo inputs.
        pub fn prepared(&self) -> &PreparedPreExit {
            &self.prepared
        }
    }

    /// Pre-exit loader state containing only copied metadata and retained pages.
    #[derive(Debug)]
    pub struct PreparedPreExit {
        kernel: Option<RetainedPages>,
        pub bootstrap: RetainedPages,
        pub bootfs: RetainedPages,
        pub acpi_rsdp: Option<AcpiRsdp>,
        #[allow(dead_code)] // Canonical BootInfo consumes GOP metadata after integration.
        pub framebuffer: Option<FramebufferMetadata>,
        pub entropy: FirmwareEntropy,
    }

    #[allow(dead_code)] // Consumed by the pending pre-EBS kernel materialization bridge.
    impl PreparedPreExit {
        /// Exact immutable kernel ELF payload for hostile-input planning. The
        /// source remains page-backed until successful PT_LOAD materialization.
        pub fn kernel_elf_bytes(&self) -> Result<&[u8], FirmwarePreparationError> {
            let kernel = self
                .kernel
                .as_ref()
                .ok_or(FirmwarePreparationError::KernelSourceReleased)?;
            // SAFETY: `kernel` retains the allocation for the returned borrow;
            // only the exact initialized payload length is exposed.
            Ok(
                unsafe {
                    core::slice::from_raw_parts(kernel.ptr.as_ptr(), kernel.payload_byte_len)
                },
            )
        }

        /// Runs all validated PT_LOAD copies over the immutable source and
        /// releases only the original kernel source pages after success. A
        /// failed closure preserves the source for diagnostics/retry; bootstrap,
        /// bootfs, RSDP, and entropy are never affected by this operation.
        pub fn materialize_kernel_and_release<R>(
            &mut self,
            materialize: impl FnOnce(&[u8]) -> Result<R, FirmwarePreparationError>,
        ) -> Result<R, FirmwarePreparationError> {
            let materialized = {
                let bytes = self.kernel_elf_bytes()?;
                materialize(bytes)?
            };
            let kernel = self
                .kernel
                .take()
                .ok_or(FirmwarePreparationError::KernelSourceReleased)?;
            // SAFETY: successful caller materialization is the only path to
            // this consume point, and no immutable source borrow remains.
            unsafe { kernel.release() };
            Ok(materialized)
        }

        /// Frees retained pages while boot services are still live. The current
        /// entry uses this fail-closed path until transition and BootInfo inputs
        /// are integrated into the same pre-exit allocation transaction.
        pub fn release_before_exit(self) {
            // SAFETY: this consumes every allocation before ExitBootServices;
            // no reference into these pages escapes the current fail-closed path.
            if let Some(kernel) = self.kernel {
                // SAFETY: the source allocation is still pre-exit and uniquely owned.
                unsafe { kernel.release() };
            }
            // SAFETY: same ownership argument as for `kernel`.
            unsafe { self.bootstrap.release() };
            // SAFETY: same ownership argument as for `kernel`.
            unsafe { self.bootfs.release() };
            if let Some(acpi) = self.acpi_rsdp {
                // SAFETY: the retained copy is still pre-exit and uniquely owned.
                unsafe { acpi.storage.release() };
            }
            if let FirmwareEntropy::Available { storage, .. } = self.entropy {
                // SAFETY: the retained entropy copy is still pre-exit and uniquely owned.
                unsafe { storage.release() };
            }
        }
    }

    struct LoadedFiles {
        kernel: Vec<u8>,
        bootstrap: Vec<u8>,
        bootfs: Vec<u8>,
        config: Option<Vec<u8>>,
    }

    /// Reads all required inputs, preserves their page-backed copies, and
    /// gathers optional firmware metadata while boot services remain active.
    pub fn prepare_pre_exit() -> Result<PreparedPreExit, FirmwarePreparationError> {
        let files = read_loader_files()?;
        let validated = ArtifactInputs {
            kernel: Some(&files.kernel),
            bootstrap: Some(&files.bootstrap),
            bootfs: Some(&files.bootfs),
        }
        .validate()
        .map_err(|_| FirmwarePreparationError::Artifact(PreparationError::EmptyArtifact))?;

        super::normalize_optional_config(files.config.as_deref())
            .map_err(FirmwarePreparationError::Config)?;

        // The copied RSDP and page-backed artifacts remain valid after the
        // configuration-table and protocol guards below are dropped.
        let acpi_rsdp = find_and_retain_acpi_rsdp()?;
        let framebuffer = find_framebuffer();
        let entropy = collect_entropy();

        retain_artifacts(
            validated.kernel,
            validated.bootstrap,
            validated.bootfs,
            acpi_rsdp,
            framebuffer,
            entropy,
        )
    }

    /// Discover the exact linked CR3-replacement stub on the UEFI target. The
    /// returned `(start, byte_len, entry)` must be supplied unchanged to the
    /// transition planner; it is not a loader-local layout constant.
    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    #[allow(dead_code)] // Called once generated layout inputs permit final transaction wiring.
    pub fn discover_linked_handoff_stub() -> Result<(u64, u64, u64), FirmwarePreparationError> {
        crate::handoff_x86_64::linked_handoff_stub()
            .map_err(|_| FirmwarePreparationError::LinkedHandoffStub)
    }

    /// Complete target-only WYR0-B transaction. All firmware allocations are
    /// guarded until the irreversible EBS call. Successful exit converts them
    /// into tokens that have no firmware release operation.
    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    pub fn run_handoff(policy: GeneratedHandoffPolicy) -> Status {
        if policy.validate().is_err() {
            return Status::ABORTED;
        }
        let prepared = match prepare_pre_exit() {
            Ok(value) => value,
            Err(_) => return Status::ABORTED,
        };
        let pending = PendingResources::new(prepared);
        let prepared = match pending.prepare(policy) {
            Ok(value) => value,
            Err(_) => return Status::ABORTED,
        };
        prepared.exit_boot_services().complete(policy)
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    fn post_exit_halt() -> ! {
        // SAFETY: no firmware service remains. Disabling interrupts prevents
        // an unspecified firmware IDT from re-entering a failed handoff.
        unsafe { core::arch::asm!("cli", "2:", "hlt", "jmp 2b", options(noreturn)) }
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    struct PendingResources {
        prepared: Option<PreparedPreExit>,
        kernel_pages: Option<RetainedPages>,
        boot_info: Option<RetainedPages>,
        memory_map: Option<RetainedPages>,
        modules: Option<RetainedPages>,
        transition_stack: Option<RetainedPages>,
        page_tables: Option<RetainedPages>,
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    impl PendingResources {
        fn new(prepared: PreparedPreExit) -> Self {
            Self {
                prepared: Some(prepared),
                kernel_pages: None,
                boot_info: None,
                memory_map: None,
                modules: None,
                transition_stack: None,
                page_tables: None,
            }
        }

        fn prepare(
            mut self,
            policy: GeneratedHandoffPolicy,
        ) -> Result<PreparedHandoff, FirmwarePreparationError> {
            let kernel_image_byte_len = u64::try_from(
                self.prepared
                    .as_ref()
                    .ok_or(FirmwarePreparationError::KernelSourceReleased)?
                    .kernel_elf_bytes()?
                    .len(),
            )
            .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?;
            let elf_policy = KernelElfPolicy {
                virtual_addresses: AddressRange::new(
                    policy.elf_window_start,
                    policy.elf_window_end_exclusive,
                ),
                link_base: policy.link_base,
                mapping_granule: policy.base_page_size,
            };
            let capacity = kernel_elf::kernel_load_segment_capacity(
                self.prepared
                    .as_ref()
                    .ok_or(FirmwarePreparationError::KernelSourceReleased)?
                    .kernel_elf_bytes()?,
                elf_policy,
            )
            .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?;
            let mut load_segments = fallible_segments(capacity)?;
            let plan = kernel_elf::plan_kernel_elf(
                self.prepared
                    .as_ref()
                    .ok_or(FirmwarePreparationError::KernelSourceReleased)?
                    .kernel_elf_bytes()?,
                elf_policy,
                &mut load_segments,
            )
            .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?;
            let kernel_entry = plan.entry_point;
            let kernel_bytes = plan.segments.iter().try_fold(0_usize, |total, segment| {
                let length = usize::try_from(segment.mapping_byte_len)
                    .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?;
                total
                    .checked_add(length)
                    .ok_or(FirmwarePreparationError::InvalidPreExitAllocation)
            })?;
            self.kernel_pages = Some(RetainedPages::allocate_zeroed_pages(
                pages_for_payload(kernel_bytes).map_err(FirmwarePreparationError::Artifact)?,
            )?);
            let kernel_base = self
                .kernel_pages
                .as_ref()
                .ok_or(FirmwarePreparationError::InvalidPreExitAllocation)?
                .physical_start();
            let mut kernel_segments = fallible_kernel_segment_pages(capacity)?;
            let mut next_offset = 0_u64;
            for segment in plan.segments {
                kernel_segments.push(KernelSegmentPages {
                    segment: *segment,
                    pages: RetainedPhysicalRange {
                        physical_start: kernel_base
                            .checked_add(next_offset)
                            .ok_or(FirmwarePreparationError::InvalidPreExitAllocation)?,
                        byte_len: segment.mapping_byte_len,
                        lifetime: AllocationLifetime::RetainedUntilKernelPageTableReplacement,
                    },
                });
                next_offset = next_offset
                    .checked_add(segment.mapping_byte_len)
                    .ok_or(FirmwarePreparationError::InvalidPreExitAllocation)?;
            }

            let map_cap = usize::try_from(policy.max_normalized_memory_map_entries)
                .map_err(|_| FirmwarePreparationError::InvalidGeneratedPolicy)?;
            let module_cap = usize::try_from(policy.max_module_entries)
                .map_err(|_| FirmwarePreparationError::InvalidGeneratedPolicy)?;
            super::bounded_intake_count(2, policy.max_module_entries)
                .map_err(FirmwarePreparationError::Artifact)?;
            self.boot_info = Some(allocate_typed_table::<DwBootInfoV1>(1)?);
            self.memory_map = Some(allocate_typed_table::<DwBootMemoryRangeV1>(map_cap)?);
            self.modules = Some(allocate_typed_table::<DwBootModuleV1>(module_cap)?);
            let stack_pages = usize::try_from(policy.transition_stack_size / policy.base_page_size)
                .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?;
            self.transition_stack = Some(RetainedPages::allocate_zeroed_pages(stack_pages)?);

            let original = self
                .prepared
                .as_ref()
                .ok_or(FirmwarePreparationError::KernelSourceReleased)?;
            let module_ranges = [
                original.bootstrap.retained_physical_range()?,
                original.bootfs.retained_physical_range()?,
            ];
            let validated_rsdp = original
                .acpi_rsdp
                .as_ref()
                .map(|rsdp| {
                    Ok(ValidatedRsdpMappingInput {
                        retained_allocation: rsdp.storage.retained_physical_range()?,
                        record_physical_start: rsdp.storage.physical_start(),
                        record_byte_len: u64::try_from(rsdp.byte_len)
                            .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?,
                    })
                })
                .transpose()?;
            let entropy_range = match &original.entropy {
                FirmwareEntropy::Available { storage, .. } => {
                    Some(storage.retained_physical_range()?)
                }
                FirmwareEntropy::Unavailable | FirmwareEntropy::Failed => None,
            };
            let framebuffer_pixels = original.framebuffer.map(|framebuffer| PhysicalRange {
                physical_start: framebuffer.physical_base,
                byte_len: framebuffer.byte_len,
            });
            let (stub_start, stub_len, handoff_stub_entry) = discover_linked_handoff_stub()?;
            let handoff_stub = RetainedPhysicalRange {
                physical_start: stub_start,
                byte_len: stub_len,
                lifetime: AllocationLifetime::RetainedUntilKernelPageTableReplacement,
            };
            let mapping_capacity = capacity
                .checked_add(9)
                .ok_or(FirmwarePreparationError::InvalidPreExitAllocation)?;
            let mut mapping_output = fallible_mappings(mapping_capacity)?;
            let mut materialization_output = fallible_materializations(capacity)?;
            let transition_policy = transition_policy(policy);

            let page_count = {
                let identity = identity_inputs(
                    &self,
                    &module_ranges,
                    validated_rsdp,
                    entropy_range,
                    framebuffer_pixels,
                    handoff_stub,
                    handoff_stub_entry,
                )?;
                let input = TransitionPreflightInput {
                    policy: transition_policy,
                    kernel_entry,
                    kernel_image_byte_len,
                    kernel_segments: &kernel_segments,
                    identity,
                };
                let preflight = transition::preflight_transition(
                    &input,
                    &mut mapping_output,
                    &mut materialization_output,
                )
                .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?;
                usize::try_from(preflight.page_table_page_count())
                    .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?
            };
            self.page_tables = Some(RetainedPages::allocate_zeroed_pages(page_count)?);

            let materializations = {
                let identity = identity_inputs(
                    &self,
                    &module_ranges,
                    validated_rsdp,
                    entropy_range,
                    framebuffer_pixels,
                    handoff_stub,
                    handoff_stub_entry,
                )?;
                let input = TransitionPreflightInput {
                    policy: transition_policy,
                    kernel_entry,
                    kernel_image_byte_len,
                    kernel_segments: &kernel_segments,
                    identity,
                };
                let preflight = transition::preflight_transition(
                    &input,
                    &mut mapping_output,
                    &mut materialization_output,
                )
                .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?;
                let page_table_range = self
                    .page_tables
                    .as_ref()
                    .ok_or(FirmwarePreparationError::InvalidPreExitAllocation)?
                    .retained_physical_range()?;
                let finalized = transition::finalize_transition(preflight, page_table_range)
                    .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?;
                copy_materializations(finalized.pre_exit().kernel_materializations)?
            };

            {
                let prepared = self
                    .prepared
                    .as_mut()
                    .ok_or(FirmwarePreparationError::KernelSourceReleased)?;
                let kernel_pages = self
                    .kernel_pages
                    .as_mut()
                    .ok_or(FirmwarePreparationError::InvalidPreExitAllocation)?;
                let base = kernel_pages.physical_start();
                prepared.materialize_kernel_and_release(|image| {
                    for materialization in &materializations {
                        let start = usize::try_from(materialization.file_offset)
                            .map_err(|_| FirmwarePreparationError::CopyRangeInvalid)?;
                        let len = usize::try_from(materialization.file_size)
                            .map_err(|_| FirmwarePreparationError::CopyRangeInvalid)?;
                        let end = start
                            .checked_add(len)
                            .ok_or(FirmwarePreparationError::CopyRangeInvalid)?;
                        let destination = materialization
                            .copy_destination
                            .checked_sub(base)
                            .and_then(|offset| usize::try_from(offset).ok())
                            .ok_or(FirmwarePreparationError::CopyRangeInvalid)?;
                        kernel_pages.copy_zeroed_from(
                            destination,
                            image
                                .get(start..end)
                                .ok_or(FirmwarePreparationError::CopyRangeInvalid)?,
                        )?;
                    }
                    Ok(())
                })?;
            }
            let materialized_inputs = materialized_inputs(
                self.prepared
                    .take()
                    .ok_or(FirmwarePreparationError::KernelSourceReleased)?,
            )?;

            Ok(PreparedHandoff {
                inputs: Some(materialized_inputs),
                kernel_pages: self.kernel_pages.take(),
                boot_info: self.boot_info.take(),
                memory_map: self.memory_map.take(),
                modules: self.modules.take(),
                transition_stack: self.transition_stack.take(),
                page_tables: self.page_tables.take(),
                kernel_segments,
                mapping_output,
                materialization_output,
                module_ranges,
                validated_rsdp,
                entropy_range,
                framebuffer_pixels,
                handoff_stub,
                handoff_stub_entry,
                kernel_entry,
                kernel_image_byte_len,
            })
        }
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    impl Drop for PendingResources {
        fn drop(&mut self) {
            release_pages(&mut self.page_tables);
            release_pages(&mut self.transition_stack);
            release_pages(&mut self.modules);
            release_pages(&mut self.memory_map);
            release_pages(&mut self.boot_info);
            release_pages(&mut self.kernel_pages);
            if let Some(prepared) = self.prepared.take() {
                prepared.release_before_exit();
            }
        }
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    struct PreparedHandoff {
        inputs: Option<MaterializedInputs>,
        kernel_pages: Option<RetainedPages>,
        boot_info: Option<RetainedPages>,
        memory_map: Option<RetainedPages>,
        modules: Option<RetainedPages>,
        transition_stack: Option<RetainedPages>,
        page_tables: Option<RetainedPages>,
        kernel_segments: Vec<KernelSegmentPages>,
        mapping_output: Vec<TransitionMapping>,
        materialization_output: Vec<KernelMaterialization>,
        module_ranges: [RetainedPhysicalRange; 2],
        validated_rsdp: Option<ValidatedRsdpMappingInput>,
        entropy_range: Option<RetainedPhysicalRange>,
        framebuffer_pixels: Option<PhysicalRange>,
        handoff_stub: RetainedPhysicalRange,
        handoff_stub_entry: u64,
        kernel_entry: u64,
        kernel_image_byte_len: u64,
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    impl PreparedHandoff {
        fn exit_boot_services(mut self) -> ExitedHandoff {
            let inputs = self.inputs.take().expect("prepared handoff inputs");
            let kernel_pages = self.kernel_pages.take().expect("prepared kernel pages");
            let boot_info = self.boot_info.take().expect("prepared BootInfo pages");
            let memory_map_pages = self.memory_map.take().expect("prepared memory-map pages");
            let modules = self.modules.take().expect("prepared module pages");
            let transition_stack = self.transition_stack.take().expect("prepared stack pages");
            let page_tables = self.page_tables.take().expect("prepared page-table pages");
            let kernel_segments = core::mem::take(&mut self.kernel_segments);
            let mapping_output = core::mem::take(&mut self.mapping_output);
            let materialization_output = core::mem::take(&mut self.materialization_output);
            uefi::println!("wyrmroot-loader: final UEFI memory map / ExitBootServices");
            // SAFETY: no firmware protocol guard or pool-backed input remains;
            // this wrapper owns final map capture and its one retry.
            let mut memory_map = unsafe { boot::exit_boot_services(Some(MemoryType::LOADER_DATA)) };
            memory_map.sort();
            ExitedHandoff {
                inputs: inputs.into_post_exit(),
                kernel_pages: kernel_pages.into_post_exit(),
                boot_info: boot_info.into_post_exit(),
                memory_map_pages: memory_map_pages.into_post_exit(),
                modules: modules.into_post_exit(),
                transition_stack: transition_stack.into_post_exit(),
                page_tables: page_tables.into_post_exit(),
                memory_map,
                kernel_segments,
                mapping_output,
                materialization_output,
                module_ranges: self.module_ranges,
                validated_rsdp: self.validated_rsdp,
                entropy_range: self.entropy_range,
                framebuffer_pixels: self.framebuffer_pixels,
                handoff_stub: self.handoff_stub,
                handoff_stub_entry: self.handoff_stub_entry,
                kernel_entry: self.kernel_entry,
                kernel_image_byte_len: self.kernel_image_byte_len,
            }
        }
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    impl Drop for PreparedHandoff {
        fn drop(&mut self) {
            release_pages(&mut self.page_tables);
            release_pages(&mut self.transition_stack);
            release_pages(&mut self.modules);
            release_pages(&mut self.memory_map);
            release_pages(&mut self.boot_info);
            release_pages(&mut self.kernel_pages);
            if let Some(inputs) = self.inputs.take() {
                inputs.release_before_exit();
            }
        }
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    struct ExitedHandoff {
        inputs: PostExitInputs,
        kernel_pages: PostExitPages,
        boot_info: PostExitPages,
        memory_map_pages: PostExitPages,
        modules: PostExitPages,
        transition_stack: PostExitPages,
        page_tables: PostExitPages,
        memory_map: uefi::mem::memory_map::MemoryMapOwned,
        kernel_segments: Vec<KernelSegmentPages>,
        mapping_output: Vec<TransitionMapping>,
        materialization_output: Vec<KernelMaterialization>,
        module_ranges: [RetainedPhysicalRange; 2],
        validated_rsdp: Option<ValidatedRsdpMappingInput>,
        entropy_range: Option<RetainedPhysicalRange>,
        framebuffer_pixels: Option<PhysicalRange>,
        handoff_stub: RetainedPhysicalRange,
        handoff_stub_entry: u64,
        kernel_entry: u64,
        kernel_image_byte_len: u64,
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    impl ExitedHandoff {
        fn complete(self, policy: GeneratedHandoffPolicy) -> ! {
            let ExitedHandoff {
                inputs,
                kernel_pages,
                mut boot_info,
                mut memory_map_pages,
                mut modules,
                transition_stack,
                mut page_tables,
                memory_map,
                kernel_segments,
                mut mapping_output,
                mut materialization_output,
                module_ranges,
                validated_rsdp,
                entropy_range,
                framebuffer_pixels,
                handoff_stub,
                handoff_stub_entry,
                kernel_entry,
                kernel_image_byte_len,
            } = self;

            let kernel_allocation = match kernel_pages.retained_physical_range() {
                Ok(value) => value,
                Err(_) => post_exit_halt(),
            };
            let kernel_segment_bytes =
                match kernel_segments.iter().try_fold(0_u64, |total, segment| {
                    total.checked_add(segment.pages.byte_len)
                }) {
                    Some(value) => value,
                    None => post_exit_halt(),
                };
            if kernel_segments
                .first()
                .map(|segment| segment.pages.physical_start)
                != Some(kernel_allocation.physical_start)
                || kernel_segment_bytes != kernel_allocation.byte_len
            {
                post_exit_halt();
            }

            let map_cap = match usize::try_from(policy.max_normalized_memory_map_entries) {
                Ok(value) => value,
                Err(_) => post_exit_halt(),
            };
            let module_cap = match usize::try_from(policy.max_module_entries) {
                Ok(value) => value,
                Err(_) => post_exit_halt(),
            };
            let module_plan = match modules::plan_modules(
                ModuleInput {
                    kind: DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP,
                    physical_start: inputs.bootstrap.physical_start(),
                    byte_len: match u64::try_from(inputs.bootstrap.payload_byte_len) {
                        Ok(value) => value,
                        Err(_) => post_exit_halt(),
                    },
                },
                ModuleInput {
                    kind: DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS,
                    physical_start: inputs.bootfs.physical_start(),
                    byte_len: match u64::try_from(inputs.bootfs.payload_byte_len) {
                        Ok(value) => value,
                        Err(_) => post_exit_halt(),
                    },
                },
            ) {
                Ok(value) => value,
                Err(_) => post_exit_halt(),
            };
            let module_records = module_plan.to_abi_modules();
            if super::bounded_intake_count(module_records.len(), policy.max_module_entries).is_err()
            {
                post_exit_halt();
            }

            let boot_info_storage = match boot_info.boot_info_allocation() {
                Ok(value) => value,
                Err(_) => post_exit_halt(),
            };
            let memory_map_storage = match memory_map_pages.boot_info_allocation() {
                Ok(value) => value,
                Err(_) => post_exit_halt(),
            };
            let module_table_storage = match modules.boot_info_allocation() {
                Ok(value) => value,
                Err(_) => post_exit_halt(),
            };
            let acpi_rsdp = match inputs.acpi_rsdp.as_ref() {
                Some(rsdp) => Some(AcpiRsdpInput {
                    storage: match rsdp.storage.boot_info_allocation() {
                        Ok(value) => value,
                        Err(_) => post_exit_halt(),
                    },
                    byte_len: match u64::try_from(rsdp.byte_len) {
                        Ok(value) => value,
                        Err(_) => post_exit_halt(),
                    },
                }),
                None => None,
            };
            let framebuffer = inputs
                .framebuffer
                .map(|framebuffer| BootInfoFramebufferInput {
                    physical_start: framebuffer.physical_base,
                    byte_len: framebuffer.byte_len,
                    width: framebuffer.width,
                    height: framebuffer.height,
                    pixels_per_scanline: framebuffer.pixels_per_scan_line,
                    pixel_format: match framebuffer.pixel_format {
                        FramebufferPixelFormat::Rgb => BootInfoPixelFormat::Rgbx8,
                        FramebufferPixelFormat::Bgr => BootInfoPixelFormat::Bgrx8,
                        FramebufferPixelFormat::Bitmask {
                            red_mask,
                            green_mask,
                            blue_mask,
                            reserved_mask,
                        } => BootInfoPixelFormat::Bitmask {
                            red_mask,
                            green_mask,
                            blue_mask,
                            reserved_mask,
                        },
                    },
                });
            let entropy = match &inputs.entropy {
                PostExitEntropy::Available {
                    storage,
                    source,
                    conditioned,
                } => Some(EntropyInput {
                    storage: match storage.boot_info_allocation() {
                        Ok(value) => value,
                        Err(_) => post_exit_halt(),
                    },
                    byte_len: match u64::try_from(storage.payload_byte_len) {
                        Ok(value) => value,
                        Err(_) => post_exit_halt(),
                    },
                    source: match source {
                        FirmwareEntropySource::UefiRngProtocol => {
                            BootInfoEntropySource::UefiRngProtocol
                        }
                    },
                    conditioned: *conditioned,
                }),
                PostExitEntropy::Unavailable | PostExitEntropy::Failed => None,
            };

            let memory_records =
                match unsafe { memory_map_pages.typed_slice_mut::<DwBootMemoryRangeV1>(map_cap) } {
                    Ok(value) => value,
                    Err(_) => post_exit_halt(),
                };
            let (normalized, final_map_accepted) =
                match super::accept_final_memory_map(memory_map::normalize_and_coalesce(
                    memory_map
                        .entries()
                        .copied()
                        .map(firmware_memory_descriptor),
                    memory_records,
                )) {
                    Ok(value) => value,
                    Err(error) => super::dispatch_post_exit_failure(error, |_| post_exit_halt()),
                };
            let module_output =
                match unsafe { modules.typed_slice_mut::<DwBootModuleV1>(module_records.len()) } {
                    Ok(value) => value,
                    Err(_) => post_exit_halt(),
                };
            let boot_info_output = match unsafe { boot_info.typed_slice_mut::<DwBootInfoV1>(1) } {
                Ok(value) => &mut value[0],
                Err(_) => post_exit_halt(),
            };
            let boot_input = BootInfoInput {
                phase: FirmwarePhase::AfterExitBootServices,
                boot_info_storage,
                memory_map_storage,
                module_table_storage,
                memory_map: normalized,
                modules: &module_records,
                acpi_rsdp,
                framebuffer,
                command_line: None,
                entropy,
            };
            let mut boot_output = BootInfoOutput {
                boot_info: boot_info_output,
                modules: module_output,
            };
            let (_, boot_info_accepted) =
                match super::accept_boot_info(boot_info::build_with_limits(
                    &boot_input,
                    &mut boot_output,
                    BootInfoLimits {
                        max_memory_map_entries: map_cap,
                        max_module_entries: module_cap,
                    },
                )) {
                    Ok(value) => value,
                    Err(error) => super::dispatch_post_exit_failure(error, |_| post_exit_halt()),
                };

            let transition_policy = transition_policy(policy);
            let identity = IdentityMapInputs {
                boot_info: match boot_info.retained_physical_range() {
                    Ok(value) => value,
                    Err(_) => post_exit_halt(),
                },
                memory_map_table: match memory_map_pages.retained_physical_range() {
                    Ok(value) => value,
                    Err(_) => post_exit_halt(),
                },
                module_table: match modules.retained_physical_range() {
                    Ok(value) => value,
                    Err(_) => post_exit_halt(),
                },
                module_data: &module_ranges,
                command_line: None,
                entropy: entropy_range,
                validated_rsdp,
                handoff_stub,
                handoff_stub_entry,
                transition_stack: match transition_stack.retained_physical_range() {
                    Ok(value) => value,
                    Err(_) => post_exit_halt(),
                },
                framebuffer_pixels,
            };
            let transition_input = TransitionPreflightInput {
                policy: transition_policy,
                kernel_entry,
                kernel_image_byte_len,
                kernel_segments: &kernel_segments,
                identity,
            };
            let preflight = match transition::preflight_transition(
                &transition_input,
                &mut mapping_output,
                &mut materialization_output,
            ) {
                Ok(value) => value,
                Err(_) => post_exit_halt(),
            };
            let page_table_storage = match page_tables.retained_physical_range() {
                Ok(value) => value,
                Err(_) => post_exit_halt(),
            };
            let plan = match transition::finalize_transition(preflight, page_table_storage) {
                Ok(value) => value,
                Err(_) => post_exit_halt(),
            };
            let entropy_coherence = match (entropy, entropy_range) {
                (Some(value), Some(range)) => Some((value.storage, range)),
                (None, None) => None,
                _ => post_exit_halt(),
            };
            let rsdp_coherence = match (acpi_rsdp, validated_rsdp) {
                (Some(value), Some(mapping)) => Some((value.storage, mapping)),
                (None, None) => None,
                _ => post_exit_halt(),
            };
            let retained_addresses = match super::validate_retained_address_coherence(
                plan.mappings(),
                super::RetainedAddressFacts {
                    boot_info: boot_info_storage,
                    memory_map: memory_map_storage,
                    module_table: module_table_storage,
                    module_records: &module_records,
                    module_allocations: &module_ranges,
                    entropy: entropy_coherence,
                    rsdp: rsdp_coherence,
                },
            ) {
                Ok(value) => value,
                Err(_) => post_exit_halt(),
            };
            let physical_address_bits = match query_maxphyaddr() {
                Ok(value) => value,
                Err(_) => post_exit_halt(),
            };
            let table_pages = match unsafe {
                page_tables.typed_slice_mut::<crate::uefi_page_table::PageTablePage>(
                    page_tables.allocation_byte_len / super::UEFI_PAGE_BYTES,
                )
            } {
                Ok(value) => value,
                Err(_) => post_exit_halt(),
            };
            let mut table = match crate::uefi_page_table::UefiPageTable::new(
                page_table_storage.physical_start,
                physical_address_bits,
                table_pages,
            ) {
                Ok(value) => value,
                Err(_) => post_exit_halt(),
            };
            let post_exit = match transition::confirm_exit_boot_services(true) {
                Some(value) => value,
                None => post_exit_halt(),
            };
            let page_table_result = (|| {
                transition::populate_page_table(&plan, post_exit, &mut table).map_err(|_| ())?;
                table.finish().map_err(|_| ())
            })();
            let (page_table_root, page_table_accepted) =
                match super::accept_page_table(page_table_result) {
                    Ok(value) => value,
                    Err(error) => super::dispatch_post_exit_failure(error, |_| post_exit_halt()),
                };
            let serial_result = (|| {
                // SAFETY: EBS completed and this loader exclusively owns COM1
                // for the final bounded marker path.
                let mut serial = unsafe { crate::handoff_x86_64::Com1Writer::initialize(100_000) }
                    .map_err(|_| ())?;
                crate::handoff_x86_64::write_final_handoff_marker(&mut serial, 100_000)
                    .map_err(|_| ())?;
                Ok::<(), ()>(())
            })();
            let (_, serial_accepted) = match super::accept_serial_diagnostic(serial_result) {
                Ok(value) => value,
                Err(error) => super::dispatch_post_exit_failure(error, |_| post_exit_halt()),
            };
            // SAFETY: EBS completed, this is the BSP in x86_64 supervisor
            // mode, and the helper validates NX/WP/paging/segment state.
            let entry_state =
                match unsafe { crate::handoff_x86_64::enable_and_verify_entry_state(true) } {
                    Ok(value) => value,
                    Err(_) => post_exit_halt(),
                };
            let (transfer, transfer_accepted) = match super::accept_transfer(
                crate::handoff_x86_64::prepare_x86_64_transfer(&plan, page_table_root, entry_state),
            ) {
                Ok(value) => value,
                Err(error) => super::dispatch_post_exit_failure(error, |_| post_exit_halt()),
            };
            let jump_authorization = super::authorize_jump(
                final_map_accepted,
                boot_info_accepted,
                page_table_accepted,
                serial_accepted,
                transfer_accepted,
                retained_addresses,
            );
            // SAFETY: `transfer` binds the finalized transition mappings,
            // table root, BootInfo pointer, stack, linked stub, and verified
            // machine state. This path is deliberately nonreturning.
            unsafe { jump_to_kernel_authorized(jump_authorization, transfer) }
        }
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    struct MaterializedInputs {
        bootstrap: RetainedPages,
        bootfs: RetainedPages,
        acpi_rsdp: Option<AcpiRsdp>,
        framebuffer: Option<FramebufferMetadata>,
        entropy: FirmwareEntropy,
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    impl MaterializedInputs {
        fn release_before_exit(self) {
            // SAFETY: this type exists only while boot services remain live,
            // and consumes every uniquely owned retained allocation.
            unsafe { self.bootstrap.release() };
            // SAFETY: same unique pre-EBS ownership as `bootstrap`.
            unsafe { self.bootfs.release() };
            if let Some(rsdp) = self.acpi_rsdp {
                // SAFETY: the retained RSDP copy is still pre-EBS and unique.
                unsafe { rsdp.storage.release() };
            }
            if let FirmwareEntropy::Available { storage, .. } = self.entropy {
                // SAFETY: the retained entropy copy is still pre-EBS and unique.
                unsafe { storage.release() };
            }
        }

        fn into_post_exit(self) -> PostExitInputs {
            let acpi_rsdp = self.acpi_rsdp.map(|rsdp| {
                let _validated_revision = rsdp.revision;
                PostExitAcpiRsdp {
                    storage: rsdp.storage.into_post_exit(),
                    byte_len: rsdp.byte_len,
                }
            });
            let entropy = match self.entropy {
                FirmwareEntropy::Available {
                    storage,
                    source,
                    conditioned,
                } => PostExitEntropy::Available {
                    storage: storage.into_post_exit(),
                    source,
                    conditioned,
                },
                FirmwareEntropy::Unavailable => PostExitEntropy::Unavailable,
                FirmwareEntropy::Failed => PostExitEntropy::Failed,
            };
            PostExitInputs {
                bootstrap: self.bootstrap.into_post_exit(),
                bootfs: self.bootfs.into_post_exit(),
                acpi_rsdp,
                framebuffer: self.framebuffer,
                entropy,
            }
        }
    }

    /// Page ownership after successful EBS. Deliberately has no release API.
    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    struct PostExitPages {
        ptr: NonNull<u8>,
        allocation_byte_len: usize,
        payload_byte_len: usize,
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    impl RetainedPages {
        fn into_post_exit(self) -> PostExitPages {
            PostExitPages {
                ptr: self.ptr,
                allocation_byte_len: self.allocation_byte_len,
                payload_byte_len: self.payload_byte_len,
            }
        }
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    impl PostExitPages {
        fn physical_start(&self) -> u64 {
            self.ptr.as_ptr() as u64
        }

        fn retained_physical_range(
            &self,
        ) -> Result<RetainedPhysicalRange, FirmwarePreparationError> {
            Ok(RetainedPhysicalRange {
                physical_start: self.physical_start(),
                byte_len: u64::try_from(self.allocation_byte_len)
                    .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?,
                lifetime: AllocationLifetime::RetainedUntilKernelPageTableReplacement,
            })
        }

        fn boot_info_allocation(&self) -> Result<HandoffAllocation, FirmwarePreparationError> {
            Ok(HandoffAllocation {
                physical_start: self.physical_start(),
                byte_len: u64::try_from(self.allocation_byte_len)
                    .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?,
                lifetime: BootInfoAllocationLifetime::RetainedUntilDeepwyrmPageTableReplacement,
            })
        }

        unsafe fn typed_slice_mut<T>(
            &mut self,
            count: usize,
        ) -> Result<&mut [T], FirmwarePreparationError> {
            let element_size = size_of::<T>();
            if element_size == 0 || (self.ptr.as_ptr() as usize) % align_of::<T>() != 0 {
                return Err(FirmwarePreparationError::TypedViewInvalid);
            }
            let byte_len = count
                .checked_mul(element_size)
                .ok_or(FirmwarePreparationError::TypedViewInvalid)?;
            if byte_len > self.allocation_byte_len {
                return Err(FirmwarePreparationError::TypedViewInvalid);
            }
            // SAFETY: this token uniquely owns the retained allocation after
            // EBS and `byte_len` was checked against its full extent.
            Ok(unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr().cast::<T>(), count) })
        }
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    struct PostExitAcpiRsdp {
        storage: PostExitPages,
        byte_len: usize,
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    enum PostExitEntropy {
        Available {
            storage: PostExitPages,
            source: FirmwareEntropySource,
            conditioned: bool,
        },
        Unavailable,
        Failed,
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    struct PostExitInputs {
        bootstrap: PostExitPages,
        bootfs: PostExitPages,
        acpi_rsdp: Option<PostExitAcpiRsdp>,
        framebuffer: Option<FramebufferMetadata>,
        entropy: PostExitEntropy,
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    fn release_pages(storage: &mut Option<RetainedPages>) {
        super::take_owned_resource_once(storage, |storage| {
            // SAFETY: every caller is a pre-EBS rollback/drop path and owns the
            // allocation exclusively through its `Option` token.
            unsafe { storage.release() };
        });
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    unsafe fn jump_to_kernel_authorized(
        _authorization: super::JumpAuthorization,
        transfer: crate::handoff_x86_64::X86_64Transfer,
    ) -> ! {
        // SAFETY: authorization is constructed only after the final-map,
        // BootInfo, page-table, serial, and transfer gates all succeed.
        unsafe { crate::handoff_x86_64::jump_to_kernel(transfer) }
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    fn allocate_typed_table<T>(count: usize) -> Result<RetainedPages, FirmwarePreparationError> {
        let byte_len = count
            .checked_mul(size_of::<T>())
            .ok_or(FirmwarePreparationError::InvalidPreExitAllocation)?;
        RetainedPages::allocate_zeroed_pages(
            pages_for_payload(byte_len).map_err(FirmwarePreparationError::Artifact)?,
        )
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    fn transition_policy(policy: GeneratedHandoffPolicy) -> TransitionPolicy {
        TransitionPolicy {
            mapping_granule: policy.base_page_size,
            rsdp_max_intersecting_pages: policy.max_acpi_rsdp_intersecting_pages,
            transition_stack_size: policy.transition_stack_size,
            transition_stack_alignment: policy.transition_stack_alignment,
            stack_pointer_alignment: 16,
            boot_info_alignment: policy.boot_info_alignment,
        }
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    fn identity_inputs<'a>(
        resources: &PendingResources,
        module_ranges: &'a [RetainedPhysicalRange],
        validated_rsdp: Option<ValidatedRsdpMappingInput>,
        entropy: Option<RetainedPhysicalRange>,
        framebuffer_pixels: Option<PhysicalRange>,
        handoff_stub: RetainedPhysicalRange,
        handoff_stub_entry: u64,
    ) -> Result<IdentityMapInputs<'a>, FirmwarePreparationError> {
        Ok(IdentityMapInputs {
            boot_info: resources
                .boot_info
                .as_ref()
                .ok_or(FirmwarePreparationError::InvalidPreExitAllocation)?
                .retained_physical_range()?,
            memory_map_table: resources
                .memory_map
                .as_ref()
                .ok_or(FirmwarePreparationError::InvalidPreExitAllocation)?
                .retained_physical_range()?,
            module_table: resources
                .modules
                .as_ref()
                .ok_or(FirmwarePreparationError::InvalidPreExitAllocation)?
                .retained_physical_range()?,
            module_data: module_ranges,
            command_line: None,
            entropy,
            validated_rsdp,
            handoff_stub,
            handoff_stub_entry,
            transition_stack: resources
                .transition_stack
                .as_ref()
                .ok_or(FirmwarePreparationError::InvalidPreExitAllocation)?
                .retained_physical_range()?,
            framebuffer_pixels,
        })
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    fn copy_materializations(
        values: &[KernelMaterialization],
    ) -> Result<Vec<KernelMaterialization>, FirmwarePreparationError> {
        let mut result = Vec::new();
        result
            .try_reserve_exact(values.len())
            .map_err(|_| FirmwarePreparationError::Allocation)?;
        result.extend_from_slice(values);
        Ok(result)
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    fn materialized_inputs(
        prepared: PreparedPreExit,
    ) -> Result<MaterializedInputs, FirmwarePreparationError> {
        if prepared.kernel.is_some() {
            prepared.release_before_exit();
            return Err(FirmwarePreparationError::KernelSourceReleased);
        }
        Ok(MaterializedInputs {
            bootstrap: prepared.bootstrap,
            bootfs: prepared.bootfs,
            acpi_rsdp: prepared.acpi_rsdp,
            framebuffer: prepared.framebuffer,
            entropy: prepared.entropy,
        })
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    fn fallible_vec<T: Clone>(count: usize, value: T) -> Result<Vec<T>, FirmwarePreparationError> {
        let mut result = Vec::new();
        result
            .try_reserve_exact(count)
            .map_err(|_| FirmwarePreparationError::Allocation)?;
        result.resize(count, value);
        Ok(result)
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    fn dummy_segment() -> KernelLoadSegment {
        KernelLoadSegment {
            program_header_index: 0,
            file_offset: 0,
            file_size: 0,
            virtual_address: 0,
            mapping_virtual_address: 0,
            mapping_byte_len: 0,
            segment_page_offset: 0,
            memory_size: 0,
            alignment: 1,
            permissions: SegmentPermissions {
                read: false,
                write: false,
                execute: false,
            },
        }
    }
    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    fn fallible_segments(count: usize) -> Result<Vec<KernelLoadSegment>, FirmwarePreparationError> {
        fallible_vec(count, dummy_segment())
    }
    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    fn fallible_kernel_segment_pages(
        count: usize,
    ) -> Result<Vec<KernelSegmentPages>, FirmwarePreparationError> {
        let pages = RetainedPhysicalRange {
            physical_start: 0,
            byte_len: 0,
            lifetime: AllocationLifetime::ReleasedBeforeKernelPageTableReplacement,
        };
        fallible_vec(
            count,
            KernelSegmentPages {
                segment: dummy_segment(),
                pages,
            },
        )
        .map(|mut values| {
            values.clear();
            values
        })
    }
    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    fn fallible_mappings(count: usize) -> Result<Vec<TransitionMapping>, FirmwarePreparationError> {
        let value = TransitionMapping {
            kind: transition::MappingKind::BootInfo,
            physical_start: 0,
            virtual_start: 0,
            byte_len: 0,
            permissions: transition::MappingPermissions {
                writable: false,
                executable: false,
            },
            lifetime: AllocationLifetime::ReleasedBeforeKernelPageTableReplacement,
        };
        fallible_vec(count, value)
    }
    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    fn fallible_materializations(
        count: usize,
    ) -> Result<Vec<KernelMaterialization>, FirmwarePreparationError> {
        let allocation = RetainedPhysicalRange {
            physical_start: 0,
            byte_len: 0,
            lifetime: AllocationLifetime::ReleasedBeforeKernelPageTableReplacement,
        };
        fallible_vec(
            count,
            KernelMaterialization {
                program_header_index: 0,
                allocation,
                file_offset: 0,
                file_size: 0,
                copy_destination: 0,
            },
        )
    }
    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    fn firmware_memory_descriptor(
        descriptor: uefi::mem::memory_map::MemoryDescriptor,
    ) -> FirmwareMemoryDescriptor {
        use uefi::mem::memory_map::MemoryType;
        let kind = match descriptor.ty {
            MemoryType::CONVENTIONAL => Some(UefiMemoryKind::Conventional),
            MemoryType::LOADER_CODE | MemoryType::LOADER_DATA => Some(UefiMemoryKind::Loader),
            MemoryType::BOOT_SERVICES_CODE | MemoryType::BOOT_SERVICES_DATA => {
                Some(UefiMemoryKind::BootServices)
            }
            MemoryType::RUNTIME_SERVICES_CODE | MemoryType::RUNTIME_SERVICES_DATA => {
                Some(UefiMemoryKind::RuntimeServices)
            }
            MemoryType::RESERVED
            | MemoryType::PAL_CODE
            | MemoryType::PERSISTENT_MEMORY
            | MemoryType::UNACCEPTED => Some(UefiMemoryKind::Reserved),
            MemoryType::UNUSABLE => Some(UefiMemoryKind::Unusable),
            MemoryType::ACPI_RECLAIM => Some(UefiMemoryKind::AcpiReclaim),
            MemoryType::ACPI_NON_VOLATILE => Some(UefiMemoryKind::AcpiNvs),
            MemoryType::MMIO | MemoryType::MMIO_PORT_SPACE => Some(UefiMemoryKind::Mmio),
            _ => None,
        };
        FirmwareMemoryDescriptor {
            kind,
            physical_start: descriptor.phys_start,
            page_count: descriptor.page_count,
            firmware_attributes: descriptor.att.bits(),
        }
    }

    fn read_loader_files() -> Result<LoadedFiles, FirmwarePreparationError> {
        let mut filesystem: ScopedProtocol<_> =
            boot::get_image_file_system(boot::image_handle())
                .map_err(|_| FirmwarePreparationError::FileSystem)?;
        let mut root = filesystem
            .open_volume()
            .map_err(|_| FirmwarePreparationError::FileSystem)?;

        let kernel_path =
            CString16::try_from(KERNEL_PATH).map_err(|_| FirmwarePreparationError::FileSystem)?;
        let bootstrap_path = CString16::try_from(BOOTSTRAP_PATH)
            .map_err(|_| FirmwarePreparationError::FileSystem)?;
        let bootfs_path =
            CString16::try_from(BOOTFS_PATH).map_err(|_| FirmwarePreparationError::FileSystem)?;
        let config_path =
            CString16::try_from(CONFIG_PATH).map_err(|_| FirmwarePreparationError::FileSystem)?;

        let kernel = read_bounded_file(&mut root, &kernel_path, MAX_KERNEL_ARTIFACT_BYTES)?;
        let bootstrap =
            read_bounded_file(&mut root, &bootstrap_path, MAX_BOOTSTRAP_ARTIFACT_BYTES)?;
        let bootfs = read_bounded_file(&mut root, &bootfs_path, MAX_BOOTFS_ARTIFACT_BYTES)?;
        total_artifact_bytes([kernel.len(), bootstrap.len(), bootfs.len()])
            .map_err(FirmwarePreparationError::Artifact)?;
        let config = read_optional_bounded_file(&mut root, &config_path, MAX_CONFIG_BYTES)?;

        Ok(LoadedFiles {
            kernel,
            bootstrap,
            bootfs,
            config,
        })
    }

    fn read_bounded_file(
        root: &mut Directory,
        path: &CString16,
        cap: usize,
    ) -> Result<Vec<u8>, FirmwarePreparationError> {
        let file = root
            .open(path, FileMode::Read, FileAttribute::empty())
            .map_err(|_| FirmwarePreparationError::FileSystem)?;
        read_opened_bounded_file(file, cap)
    }

    fn read_optional_bounded_file(
        root: &mut Directory,
        path: &CString16,
        cap: usize,
    ) -> Result<Option<Vec<u8>>, FirmwarePreparationError> {
        let file = match root.open(path, FileMode::Read, FileAttribute::empty()) {
            Ok(file) => file,
            Err(error) if error.status() == Status::NOT_FOUND => return Ok(None),
            Err(_) => return Err(FirmwarePreparationError::FileSystem),
        };
        read_opened_bounded_file(file, cap).map(Some)
    }

    fn read_opened_bounded_file(
        file: uefi::proto::media::file::FileHandle,
        cap: usize,
    ) -> Result<Vec<u8>, FirmwarePreparationError> {
        let mut file = file
            .into_regular_file()
            .ok_or(FirmwarePreparationError::FileSystem)?;
        let info = file
            .get_boxed_info::<FileInfo>()
            .map_err(|_| FirmwarePreparationError::FileSystem)?;
        let byte_len = bounded_artifact_len(info.file_size(), cap)
            .map_err(FirmwarePreparationError::Artifact)?;

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(byte_len)
            .map_err(|_| FirmwarePreparationError::Allocation)?;
        // `try_reserve_exact` has already reserved `byte_len`, so this resize
        // cannot request another allocation. The zero initialization prevents
        // an unread tail from ever becoming observable on a short read.
        bytes.resize(byte_len, 0);
        let read_len = file
            .read(&mut bytes)
            .map_err(|_| FirmwarePreparationError::FileSystem)?;
        if read_len != byte_len {
            return Err(FirmwarePreparationError::ShortRead);
        }
        Ok(bytes)
    }

    fn retain_artifacts(
        kernel: &[u8],
        bootstrap: &[u8],
        bootfs: &[u8],
        acpi_rsdp: Option<AcpiRsdp>,
        framebuffer: Option<FramebufferMetadata>,
        entropy: CollectedEntropy,
    ) -> Result<PreparedPreExit, FirmwarePreparationError> {
        let kernel = match retain_payload(kernel) {
            Ok(value) => value,
            Err(error) => {
                release_acpi(acpi_rsdp);
                return Err(error);
            }
        };
        let bootstrap = match retain_payload(bootstrap) {
            Ok(value) => value,
            Err(error) => {
                // SAFETY: no reference to the retained allocation escaped.
                unsafe { kernel.release() };
                release_acpi(acpi_rsdp);
                return Err(error);
            }
        };
        let bootfs = match retain_payload(bootfs) {
            Ok(value) => value,
            Err(error) => {
                // SAFETY: no reference to either retained allocation escaped.
                unsafe { bootstrap.release() };
                // SAFETY: no reference to either retained allocation escaped.
                unsafe { kernel.release() };
                release_acpi(acpi_rsdp);
                return Err(error);
            }
        };
        let entropy = match retain_entropy(entropy) {
            Ok(value) => value,
            Err(error) => {
                // SAFETY: no reference to the retained allocations escaped.
                unsafe { bootfs.release() };
                // SAFETY: no reference to the retained allocations escaped.
                unsafe { bootstrap.release() };
                // SAFETY: no reference to the retained allocations escaped.
                unsafe { kernel.release() };
                release_acpi(acpi_rsdp);
                return Err(error);
            }
        };

        Ok(PreparedPreExit {
            kernel: Some(kernel),
            bootstrap,
            bootfs,
            acpi_rsdp,
            framebuffer,
            entropy,
        })
    }

    fn release_acpi(acpi_rsdp: Option<AcpiRsdp>) {
        if let Some(acpi) = acpi_rsdp {
            // SAFETY: this cleanup path owns the copy and runs before ExitBootServices.
            unsafe { acpi.storage.release() };
        }
    }

    fn retain_payload(payload: &[u8]) -> Result<RetainedPages, FirmwarePreparationError> {
        let page_count =
            pages_for_payload(payload.len()).map_err(FirmwarePreparationError::Artifact)?;
        let mut retained = RetainedPages::allocate_zeroed_pages(page_count)?;
        // SAFETY: retained storage has exactly the checked full allocation
        // extent. The pure helper clears all slack before copying the payload.
        let allocation = unsafe {
            core::slice::from_raw_parts_mut(retained.ptr.as_ptr(), retained.allocation_byte_len)
        };
        super::initialize_payload_allocation(allocation, payload)
            .map_err(FirmwarePreparationError::Artifact)?;
        retained.payload_byte_len = payload.len();
        Ok(retained)
    }

    enum CollectedEntropy {
        Available([u8; 32]),
        Unavailable,
        Failed,
    }

    fn collect_entropy() -> CollectedEntropy {
        let Ok(handle) = boot::get_handle_for_protocol::<Rng>() else {
            return CollectedEntropy::Unavailable;
        };
        let Ok(mut rng) = boot::open_protocol_exclusive::<Rng>(handle) else {
            return CollectedEntropy::Unavailable;
        };
        let mut bytes = [0_u8; 32];
        match rng.get_rng(None, &mut bytes) {
            Ok(()) => CollectedEntropy::Available(bytes),
            Err(_) => CollectedEntropy::Failed,
        }
    }

    fn retain_entropy(
        entropy: CollectedEntropy,
    ) -> Result<FirmwareEntropy, FirmwarePreparationError> {
        match entropy {
            CollectedEntropy::Available(bytes) => retain_payload(&bytes).map(|storage| {
                FirmwareEntropy::Available {
                    storage,
                    source: FirmwareEntropySource::UefiRngProtocol,
                    // The UEFI RNG protocol does not itself attest that the
                    // bytes have passed Deepwyrm's conditioning policy.
                    conditioned: false,
                }
            }),
            CollectedEntropy::Unavailable => Ok(FirmwareEntropy::Unavailable),
            CollectedEntropy::Failed => Ok(FirmwareEntropy::Failed),
        }
    }

    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    fn verify_generated_base_page_size() -> Result<(), FirmwarePreparationError> {
        (usize::try_from(deepwyrm_abi::DW_BOOT_BASE_PAGE_SIZE).ok() == Some(super::UEFI_PAGE_BYTES))
            .then_some(())
            .ok_or(FirmwarePreparationError::GeneratedPageGranuleMismatch)
    }

    /// Reads the architectural MAXPHYADDR fact from CPUID. The returned value
    /// is deliberately not a Deepwyrm layout constant: pass it to
    /// `UefiPageTable::new`, which enforces the supported encoder range before
    /// any physical address can be encoded.
    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    #[allow(dead_code)] // Called by the pending generated-policy table builder.
    pub fn query_maxphyaddr() -> Result<u8, FirmwarePreparationError> {
        let maximum_extended_leaf = __cpuid(0x8000_0000).eax;
        if maximum_extended_leaf < 0x8000_0008 {
            return Err(FirmwarePreparationError::CpuMaxPhysicalAddressUnavailable);
        }
        let physical_bits = __cpuid(0x8000_0008).eax as u8;
        if physical_bits == 0 {
            return Err(FirmwarePreparationError::CpuMaxPhysicalAddressUnavailable);
        }
        Ok(physical_bits)
    }

    fn find_and_retain_acpi_rsdp() -> Result<Option<AcpiRsdp>, FirmwarePreparationError> {
        let selected = system::with_config_table(|entries| {
            super::select_rsdp_candidate(entries.iter().filter_map(|entry| {
                if entry.guid == ConfigTableEntry::ACPI2_GUID {
                    Some(super::AcpiRsdpConfigCandidate {
                        kind: super::AcpiRsdpConfigKind::Acpi2,
                        physical_start: entry.address as u64,
                    })
                } else if entry.guid == ConfigTableEntry::ACPI_GUID {
                    Some(super::AcpiRsdpConfigCandidate {
                        kind: super::AcpiRsdpConfigKind::Acpi1,
                        physical_start: entry.address as u64,
                    })
                } else {
                    None
                }
            }))
        })
        .map_err(FirmwarePreparationError::Acpi)?;
        let Some(selected) = selected else {
            return Ok(None);
        };
        let address = usize::try_from(selected.physical_start).map_err(|_| {
            FirmwarePreparationError::Acpi(PreparationError::InvalidAcpiRsdpAlignment)
        })?;
        validate_acpi_rsdp_address(address).map_err(FirmwarePreparationError::Acpi)?;

        // SAFETY: UEFI owns configuration-table memory until handoff. The ACPI
        // entry promises an RSDP at this aligned address; only the fixed v1
        // prefix is read to determine the revision and extended byte length.
        let prefix =
            unsafe { core::slice::from_raw_parts(address as *const u8, ACPI_RSDP_V1_BYTES) };
        let byte_len = if prefix[15] < 2 {
            ACPI_RSDP_V1_BYTES
        } else {
            // SAFETY: this is the v2 length field, immediately following the v1 prefix.
            let header = unsafe {
                core::slice::from_raw_parts(address as *const u8, ACPI_RSDP_V2_MIN_BYTES)
            };
            usize::try_from(u32::from_le_bytes(
                header[20..24].try_into().expect("fixed slice length"),
            ))
            .map_err(|_| FirmwarePreparationError::Acpi(PreparationError::InvalidAcpiRsdpLength))?
        };
        if byte_len > MAX_ACPI_RSDP_BYTES {
            return Err(FirmwarePreparationError::Acpi(
                PreparationError::InvalidAcpiRsdpLength,
            ));
        }
        // SAFETY: the size is bounded above and was sourced from the validated
        // RSDP header while firmware configuration tables are still available.
        let bytes = unsafe { core::slice::from_raw_parts(address as *const u8, byte_len) };
        let AcpiRsdpLayout { revision, byte_len } =
            validate_acpi_rsdp(bytes).map_err(FirmwarePreparationError::Acpi)?;
        let storage = retain_payload(&bytes[..byte_len])?;
        Ok(Some(AcpiRsdp {
            storage,
            revision,
            byte_len,
        }))
    }

    fn find_framebuffer() -> Option<FramebufferMetadata> {
        let handle = boot::get_handle_for_protocol::<GraphicsOutput>().ok()?;
        let mut gop = boot::open_protocol_exclusive::<GraphicsOutput>(handle).ok()?;
        let info = gop.current_mode_info();
        let pixel_format = match info.pixel_format() {
            PixelFormat::Rgb => FramebufferPixelFormat::Rgb,
            PixelFormat::Bgr => FramebufferPixelFormat::Bgr,
            PixelFormat::Bitmask => {
                let masks = info.pixel_bitmask()?;
                FramebufferPixelFormat::Bitmask {
                    red_mask: masks.red,
                    green_mask: masks.green,
                    blue_mask: masks.blue,
                    reserved_mask: masks.reserved,
                }
            }
            PixelFormat::BltOnly => return None,
        };
        let mut framebuffer = gop.frame_buffer();
        let (width, height) = info.resolution();
        Some(FramebufferMetadata {
            physical_base: framebuffer.as_mut_ptr() as u64,
            byte_len: framebuffer.size() as u64,
            width: u32::try_from(width).ok()?,
            height: u32::try_from(height).ok()?,
            pixels_per_scan_line: u32::try_from(info.stride()).ok()?,
            pixel_format,
        })
    }
}

#[cfg(all(feature = "firmware", target_arch = "x86_64", target_os = "uefi"))]
pub use firmware::{GeneratedHandoffPolicy, run_handoff};
