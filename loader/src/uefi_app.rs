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
    use deepwyrm_abi::{DwBootInfoV1, DwBootMemoryRangeV1, DwBootModuleV1};
    use uefi::boot::{
        self, AllocateType, MemoryType, MemoryType as UefiMemoryType, ScopedProtocol,
    };
    use uefi::mem::memory_map::MemoryMapMut;
    use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
    use uefi::proto::media::file::{Directory, File, FileAttribute, FileInfo, FileMode};
    use uefi::proto::rng::Rng;
    use uefi::table::cfg::ConfigTableEntry;
    use uefi::{CString16, Status, system};
    use wyrmroot_efi_loader::artifacts::{
        ArtifactInputs, BOOTFS_PATH, BOOTSTRAP_PATH, KERNEL_PATH,
    };

    use super::{
        ACPI_RSDP_V1_BYTES, ACPI_RSDP_V2_MIN_BYTES, AcpiRsdpLayout, CONFIG_PATH,
        MAX_ACPI_RSDP_BYTES, MAX_BOOTFS_ARTIFACT_BYTES, MAX_BOOTSTRAP_ARTIFACT_BYTES,
        MAX_CONFIG_BYTES, MAX_KERNEL_ARTIFACT_BYTES, PreparationError, bounded_artifact_len,
        pages_for_payload, total_artifact_bytes, validate_acpi_rsdp, validate_acpi_rsdp_address,
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

    /// State surviving the UEFI boot-services transition.
    #[allow(dead_code)] // The handoff owner creates this after all pre-exit allocations exist.
    #[derive(Debug)]
    pub struct PreparedPostExit {
        pub pre_exit: PreparedPreExit,
        pub memory_map: uefi::mem::memory_map::MemoryMapOwned,
    }

    #[allow(dead_code)] // Invoked only after EBS by final allocation-free normalization.
    impl PreparedPostExit {
        /// Sorts the final UEFI memory map in place. `MemoryMapMut::sort`
        /// performs no allocation; the forthcoming generated coalescer must
        /// consume this sorted map into preallocated BootInfo storage.
        pub fn sort_final_memory_map(&mut self) {
            self.memory_map.sort();
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

    /// Uses uefi-rs's spec-compliant final-map / ExitBootServices retry wrapper.
    /// The entry deliberately does not call this yet: transition stack, page
    /// table, kernel segments, and canonical BootInfo must be allocated before
    /// the final map is captured.
    #[allow(dead_code)] // The entry must not invoke this before transition/BootInfo integration.
    pub fn exit_boot_services_after_handoff_preparation(
        pre_exit: PreparedPreExit,
    ) -> PreparedPostExit {
        // All protocol guards, files, and pool-backed input buffers have been
        // dropped. `pre_exit` has only copied scalars and retained page storage.
        uefi::println!("wyrmroot-loader: final UEFI memory map / ExitBootServices");
        // SAFETY: the uefi-rs wrapper owns the final map/key/retry sequence.
        // Callers must not retain UEFI protocol or pool-backed values.
        let memory_map = unsafe { boot::exit_boot_services(Some(MemoryType::LOADER_DATA)) };
        PreparedPostExit {
            pre_exit,
            memory_map,
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

#[cfg(feature = "firmware")]
pub use firmware::prepare_pre_exit;
