//! The firmware-side UEFI application: everything that runs before
//! ExitBootServices and the transfer to the kernel.

extern crate alloc;

use alloc::vec::Vec;
#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
use core::arch::x86_64::__cpuid;
#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
use core::mem::{align_of, size_of};
use core::ptr::{self, NonNull};

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
use deepwyrm_abi::{
    DW_BOOT_MODULE_KIND_DEEPWYRM_BOOT_DEVICE_TABLE_V1,
    DW_BOOT_MODULE_KIND_DEEPWYRM_X86_64_PAGING_HANDOFF_V1, DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS,
    DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP, DW_BOOT_X86_64_PAGING_HANDOFF_MAX_BYTE_LEN,
    DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAME_STRIDE,
    DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAMES_OFFSET, DW_BOOT_X86_64_PAGING_HANDOFF_V1_SIZE,
    DwBootInfoV1, DwBootMemoryRangeV1, DwBootModuleV1, DwBootX86_64PagingHandoffV1,
};
use uefi::boot::{self, AllocateType, MemoryType, MemoryType as UefiMemoryType, ScopedProtocol};
use uefi::fs::{Path as UefiPath, PathBuf as UefiPathBuf};
use uefi::mem::memory_map::{MemoryMap, MemoryMapMut};
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
use uefi::proto::media::file::{Directory, File, FileAttribute, FileInfo, FileMode};
use uefi::proto::rng::Rng;
use uefi::table::cfg::ConfigTableEntry;
use uefi::{CString16, Status, system};
use wyrmroot_efi_loader::artifacts::{
    ArtifactInputs, BOOT_DEVICE_TABLE_PATH, BOOTFS_PATH, BOOTSTRAP_PATH, KERNEL_PATH,
};
#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
use wyrmroot_efi_loader::boot_info::{
    AllocationLifetime as BootInfoAllocationLifetime, HandoffAllocation,
};
use wyrmroot_efi_loader::transition::{AllocationLifetime, RetainedPhysicalRange};

use super::{
    ACPI_RSDP_V1_BYTES, ACPI_RSDP_V2_MIN_BYTES, AcpiRsdpLayout, CONFIG_PATH, MAX_ACPI_RSDP_BYTES,
    MAX_BOOTFS_ARTIFACT_BYTES, MAX_BOOTSTRAP_ARTIFACT_BYTES, MAX_CONFIG_BYTES,
    MAX_KERNEL_ARTIFACT_BYTES, PreparationError, bounded_artifact_len, pages_for_payload,
    total_artifact_bytes, validate_acpi_rsdp, validate_acpi_rsdp_address,
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
        TransitionMapping, TransitionPolicy, TransitionPreflightInput, ValidatedRsdpMappingInput,
    },
};

mod handoff;
mod intake;
mod post_exit;
pub(crate) use handoff::*;
pub(crate) use intake::*;
pub(crate) use post_exit::*;

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
    pub(crate) ptr: NonNull<u8>,
    pub(crate) page_count: usize,
    pub(crate) allocation_byte_len: usize,
    pub(crate) payload_byte_len: usize,
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

    pub(crate) unsafe fn release(self) {
        // SAFETY: this helper is called only before ExitBootServices, with
        // the exact pointer/count returned by `allocate_pages`, and no
        // references into the allocation escape its caller on that path.
        unsafe { boot::free_pages(self.ptr, self.page_count) }
            .expect("retained pre-exit pages must be releasable");
    }

    /// Allocates exactly `page_count` fresh LoaderData pages and clears the
    /// full allocation before any kernel segment or handoff table copy.
    pub(crate) fn allocate_zeroed_pages(
        page_count: usize,
    ) -> Result<Self, FirmwarePreparationError> {
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

    /// The only raw conversion point. It is private so no caller can cast
    /// retained pages into an arbitrary public type.
    #[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
    pub(crate) unsafe fn typed_slice_mut<T>(
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
    pub(crate) purpose: Option<PreExitAllocationPurpose>,
    pub(crate) storage: Option<RetainedPages>,
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
    pub(crate) prepared: PreparedPreExit,
    pub(crate) slots: &'slots mut [PreExitAllocationSlot],
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
    pub(crate) kernel: Option<RetainedPages>,
    pub bootstrap: RetainedPages,
    pub bootfs: RetainedPages,
    pub boot_device_table: Option<RetainedPages>,
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
        Ok(unsafe { core::slice::from_raw_parts(kernel.ptr.as_ptr(), kernel.payload_byte_len) })
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
        if let Some(boot_device_table) = self.boot_device_table {
            // SAFETY: same ownership argument as for `bootfs`.
            unsafe { boot_device_table.release() };
        }
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

pub(crate) struct LoadedFiles {
    pub(crate) kernel: Vec<u8>,
    pub(crate) bootstrap: Vec<u8>,
    pub(crate) bootfs: Vec<u8>,
    pub(crate) boot_device_table: Option<Vec<u8>>,
    pub(crate) config: Option<Vec<u8>>,
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
        files.boot_device_table.as_deref(),
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
pub(crate) fn pre_exit_abort(stage: &str, error: FirmwarePreparationError) -> Status {
    // Firmware console services are still valid here. Keep diagnostics to
    // one bounded enum discriminant and stage label; no post-EBS path may
    // call this helper or retain firmware output authority.
    uefi::println!("wyrmroot-loader: {stage} failed: {error:?}");
    Status::ABORTED
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
pub fn run_handoff(policy: GeneratedHandoffPolicy) -> Status {
    if let Err(error) = policy.validate() {
        return pre_exit_abort("policy-validation", error);
    }
    let prepared = match prepare_pre_exit() {
        Ok(value) => value,
        Err(error) => return pre_exit_abort("pre-exit-preparation", error),
    };
    let pending = PendingResources::new(prepared);
    let prepared = match pending.prepare(policy) {
        Ok(value) => value,
        Err(error) => return pre_exit_abort("transition-preparation", error),
    };
    prepared.exit_boot_services().complete(policy)
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
pub(crate) fn post_exit_halt() -> ! {
    // SAFETY: no firmware service remains. Disabling interrupts prevents
    // an unspecified firmware IDT from re-entering a failed handoff.
    unsafe { core::arch::asm!("cli", "2:", "hlt", "jmp 2b", options(noreturn)) }
}
