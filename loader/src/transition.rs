//! Pure planning for the loader-owned x86_64 transition address space.
//!
//! This module does not allocate firmware pages or manipulate page tables directly. Values such
//! as the base-page granule and transition-stack size are caller-supplied from Deepwyrm's generated
//! layout policy. A successful plan contains only the mappings required by the reviewed handoff:
//! kernel segments at their ELF virtual addresses, narrowly retained handoff data by identity,
//! the current handoff stub, and a dedicated transition stack. Framebuffer pixels are never added.

use crate::kernel_elf::{KernelLoadSegment, SegmentPermissions};
use deepwyrm_abi::{
    DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT,
    DW_BOOT_X86_64_PAGING_HANDOFF_MIN_TABLE_FRAME_COUNT, DW_BOOT_X86_64_PAGING_HANDOFF_PD_INDEX,
    DW_BOOT_X86_64_PAGING_HANDOFF_PDPT_INDEX, DW_BOOT_X86_64_PAGING_HANDOFF_PML4_INDEX,
    DW_BOOT_X86_64_PAGING_HANDOFF_PT_INDEX,
    DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS,
};

/// How long a physical allocation remains owned and valid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocationLifetime {
    /// Retained until Deepwyrm installs its replacement page tables and copies early handoff data.
    RetainedUntilKernelPageTableReplacement,
    /// Invalid for transition mappings because the kernel could observe reclaimed storage.
    ReleasedBeforeKernelPageTableReplacement,
}

/// An exact physical payload and its ownership lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedPhysicalRange {
    pub physical_start: u64,
    pub byte_len: u64,
    pub lifetime: AllocationLifetime,
}

/// Caller-allocated physical pages backing one validated kernel `PT_LOAD` segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelSegmentPages {
    pub segment: KernelLoadSegment,
    /// Page-aligned physical allocation. Its length must exactly cover the rounded virtual range.
    pub pages: RetainedPhysicalRange,
}

/// Machine-readable layout values generated from the Deepwyrm x86_64 layout contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionPolicy {
    pub mapping_granule: u64,
    /// Generated Deep limit for retained RSDP record pages mapped during early intake.
    pub rsdp_max_intersecting_pages: u64,
    pub transition_stack_size: u64,
    pub transition_stack_alignment: u64,
    pub stack_pointer_alignment: u64,
    pub boot_info_alignment: u64,
}

/// One validated RSDP record inside its exact retained page allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedRsdpMappingInput {
    pub retained_allocation: RetainedPhysicalRange,
    pub record_physical_start: u64,
    pub record_byte_len: u64,
}

/// Narrowly permitted identity mappings used during early handoff intake.
#[derive(Clone, Copy)]
pub struct IdentityMapInputs<'a> {
    pub boot_info: RetainedPhysicalRange,
    pub memory_map_table: RetainedPhysicalRange,
    pub module_table: RetainedPhysicalRange,
    pub module_data: &'a [RetainedPhysicalRange],
    pub command_line: Option<RetainedPhysicalRange>,
    pub entropy: Option<RetainedPhysicalRange>,
    /// Optional validated RSDP record. Its mapping is derived; callers cannot supply ACPI pages.
    pub validated_rsdp: Option<ValidatedRsdpMappingInput>,
    pub handoff_stub: RetainedPhysicalRange,
    /// Address of the currently executing transfer stub inside `handoff_stub`.
    pub handoff_stub_entry: u64,
    pub transition_stack: RetainedPhysicalRange,
    /// Descriptor-only input used to prove pixels are not mapped, including indirectly by overlap.
    pub framebuffer_pixels: Option<PhysicalRange>,
}

/// Complete mapping facts needed before page-table storage can be allocated.
pub struct TransitionPreflightInput<'a> {
    pub policy: TransitionPolicy,
    pub kernel_entry: u64,
    pub kernel_image_byte_len: u64,
    pub kernel_segments: &'a [KernelSegmentPages],
    pub identity: IdentityMapInputs<'a>,
}

/// Complete transition planning input.
pub struct TransitionInput<'a> {
    pub policy: TransitionPolicy,
    pub kernel_entry: u64,
    pub kernel_image_byte_len: u64,
    pub kernel_segments: &'a [KernelSegmentPages],
    /// Physical pages reserved before `ExitBootServices` for the new page-table hierarchy.
    pub page_table_storage: RetainedPhysicalRange,
    pub identity: IdentityMapInputs<'a>,
}

/// A physical range not owned or mapped by this transition planner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalRange {
    pub physical_start: u64,
    pub byte_len: u64,
}

/// Why a transition mapping exists. No catch-all mapping kind is intentionally provided.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingKind {
    KernelSegment {
        program_header_index: u16,
    },
    BootInfo,
    MemoryMapTable,
    ModuleTable,
    ModuleData {
        index: usize,
    },
    CommandLine,
    Entropy,
    RequiredAcpiRsdp,
    HandoffStub,
    TransitionStack,
    /// Writable/NX identity alias over exactly the used transition-table prefix.
    TransitionTableIdentity,
}

/// x86_64 supervisor-page permissions. Reads are implicit on present x86_64 pages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingPermissions {
    pub writable: bool,
    /// When false, the page-table implementation must set execute-disable/NX.
    pub executable: bool,
}

/// One complete, granule-aligned page-table operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionMapping {
    pub kind: MappingKind,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub byte_len: u64,
    pub permissions: MappingPermissions,
    pub lifetime: AllocationLifetime,
}

/// Generated empty-leaf reservation used by Deepwyrm's temporary table mapper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TemporaryMappingReservation {
    pub virtual_address: u64,
    pub indices: [u16; 4],
}

/// Pre-`ExitBootServices` work required to materialize one kernel segment.
///
/// The entire physical allocation must first be zeroed, then `file_size` bytes copied from the
/// kernel ELF at `file_offset` to `copy_destination`. This initializes BSS and page padding without
/// exposing stale firmware-page contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelMaterialization {
    pub program_header_index: u16,
    pub allocation: RetainedPhysicalRange,
    pub file_offset: u64,
    pub file_size: u64,
    pub copy_destination: u64,
}

/// All allocations/content that must exist before the final memory-map capture and EBS attempt.
#[derive(Debug, Eq, PartialEq)]
pub struct PreExitPlan<'a> {
    pub kernel_materializations: &'a [KernelMaterialization],
    pub kernel_image_byte_len: u64,
    pub page_table_storage: RetainedPhysicalRange,
    pub page_table_page_count: u64,
    /// Exact prefix of the capacity allocation that must become reachable tables.
    pub used_page_table_page_count: u64,
    pub transition_stack: RetainedPhysicalRange,
    pub boot_info_storage: RetainedPhysicalRange,
    pub handoff_stub: RetainedPhysicalRange,
}

/// Validated allocation-free sizing result produced before page-table pages are allocated.
///
/// This plan validates every eventual mapping and materialization, but intentionally makes no
/// claim about page-table storage. Pass it to [`finalize_transition`] after allocating the exact
/// number of pages returned by [`TransitionPreflightPlan::page_table_page_count`].
#[derive(Debug, Eq, PartialEq)]
pub struct TransitionPreflightPlan<'a> {
    mappings: &'a [TransitionMapping],
    kernel_materializations: &'a [KernelMaterialization],
    policy: TransitionPolicy,
    kernel_image_byte_len: u64,
    minimum_page_table_page_count: u64,
    page_table_capacity_page_count: u64,
    transition_stack: RetainedPhysicalRange,
    boot_info_storage: RetainedPhysicalRange,
    handoff_stub: RetainedPhysicalRange,
    framebuffer_pixels: Option<PhysicalRange>,
    kernel_entry: u64,
    boot_info_identity_pointer: u64,
    transition_stack_pointer: u64,
    stack_pointer_alignment: u64,
    handoff_stub_entry: u64,
}

impl<'a> TransitionPreflightPlan<'a> {
    /// Generated maximum allocation capacity. The exact used prefix depends on
    /// the physical base returned by firmware and is fixed during finalization.
    pub fn page_table_page_count(&self) -> u64 {
        self.page_table_capacity_page_count
    }

    pub fn minimum_page_table_page_count(&self) -> u64 {
        self.minimum_page_table_page_count
    }

    pub fn mappings(&self) -> &'a [TransitionMapping] {
        self.mappings
    }

    pub fn kernel_materializations(&self) -> &'a [KernelMaterialization] {
        self.kernel_materializations
    }
}

/// Validated transition mappings and raw entry values.
#[derive(Debug, Eq, PartialEq)]
pub struct TransitionPlan<'a> {
    pre_exit: PreExitPlan<'a>,
    mappings: &'a [TransitionMapping],
    table_identity_mapping: TransitionMapping,
    temporary_mapping: TemporaryMappingReservation,
    mapping_granule: u64,
    kernel_entry: u64,
    boot_info_identity_pointer: u64,
    /// One-past the dedicated transition stack, aligned as required by the entry contract.
    transition_stack_pointer: u64,
    stack_pointer_alignment: u64,
    handoff_stub_entry: u64,
}

impl<'a> TransitionPlan<'a> {
    pub fn pre_exit(&self) -> &PreExitPlan<'a> {
        &self.pre_exit
    }

    pub fn mappings(&self) -> &'a [TransitionMapping] {
        self.mappings
    }

    pub fn table_identity_mapping(&self) -> TransitionMapping {
        self.table_identity_mapping
    }

    pub fn temporary_mapping(&self) -> TemporaryMappingReservation {
        self.temporary_mapping
    }

    pub fn used_page_table_page_count(&self) -> u64 {
        self.pre_exit.used_page_table_page_count
    }

    pub fn mapping_granule(&self) -> u64 {
        self.mapping_granule
    }

    pub fn kernel_entry(&self) -> u64 {
        self.kernel_entry
    }

    pub fn boot_info_identity_pointer(&self) -> u64 {
        self.boot_info_identity_pointer
    }

    pub fn transition_stack_pointer(&self) -> u64 {
        self.transition_stack_pointer
    }

    pub fn stack_pointer_alignment(&self) -> u64 {
        self.stack_pointer_alignment
    }

    pub fn handoff_stub_entry(&self) -> u64 {
        self.handoff_stub_entry
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionError {
    InvalidPolicy,
    MappingCountOverflow,
    OutputTooSmall {
        required: usize,
        available: usize,
    },
    EmptyRange {
        kind: MappingKind,
    },
    RangeOverflow {
        kind: MappingKind,
    },
    MappingRoundOverflow {
        kind: MappingKind,
    },
    AllocationNotRetained {
        kind: MappingKind,
    },
    PhysicalPagesUnaligned {
        kind: MappingKind,
    },
    KernelPageLengthMismatch {
        program_header_index: u16,
    },
    InvalidKernelSegment {
        program_header_index: u16,
    },
    WritableExecutable {
        kind: MappingKind,
    },
    PageZeroWouldBeMapped {
        kind: MappingKind,
    },
    VirtualOverlap {
        first: MappingKind,
        second: MappingKind,
    },
    PhysicalAlias {
        first: MappingKind,
        second: MappingKind,
    },
    FramebufferPixelsWouldBeMapped {
        kind: MappingKind,
    },
    KernelEntryNotExecutable,
    BootInfoMisaligned,
    HandoffStubEntryOutsideMapping,
    InvalidTransitionStack,
    InvalidPageTableStorage,
    PageTableStorageLengthMismatch {
        required_pages: u64,
        provided_pages: u64,
    },
    PageTableCountOverflow,
    NonCanonicalVirtualRange {
        kind: MappingKind,
    },
    InvalidFramebufferRange,
    InvalidRsdpRecord,
    RsdpRecordRangeOverflow,
    RsdpRetainedAllocationMismatch,
    RsdpMappingPageLimitExceeded {
        required_pages: u64,
        maximum_pages: u64,
    },
    KernelSourceOutsideImage {
        program_header_index: u16,
    },
    PageTableStorageAlias {
        with: MappingKind,
    },
    FramebufferPixelsWouldBackPageTables,
    TemporaryMappingConflict {
        with: MappingKind,
    },
    PageTableFixedPointCapacityExceeded {
        required_pages: u64,
        maximum_pages: u64,
    },
    PageTableFixedPointRegressed,
    PageTableFixedPointDidNotConverge,
}

/// Compatibility wrapper that preflights, sizes, and finalizes a transition in one call.
pub fn plan_transition<'plan>(
    input: &TransitionInput<'_>,
    mapping_output: &'plan mut [TransitionMapping],
    materialization_output: &'plan mut [KernelMaterialization],
) -> Result<TransitionPlan<'plan>, TransitionError> {
    let preflight_input = TransitionPreflightInput {
        policy: input.policy,
        kernel_entry: input.kernel_entry,
        kernel_image_byte_len: input.kernel_image_byte_len,
        kernel_segments: input.kernel_segments,
        identity: input.identity,
    };
    let preflight = preflight_transition(&preflight_input, mapping_output, materialization_output)?;
    finalize_transition(preflight, input.page_table_storage)
}

/// Validate every transition mapping and return its exact four-level page-table allocation size.
///
/// This function is allocation-free and does not accept or inspect page-table backing storage.
/// Mappings are deterministically sorted by virtual address. On failure, caller-owned outputs are
/// unspecified and must not be applied.
pub fn preflight_transition<'plan>(
    input: &TransitionPreflightInput<'_>,
    mapping_output: &'plan mut [TransitionMapping],
    materialization_output: &'plan mut [KernelMaterialization],
) -> Result<TransitionPreflightPlan<'plan>, TransitionError> {
    validate_policy(input.policy)?;
    let required = required_mapping_count(input)?;
    if required > mapping_output.len() {
        return Err(TransitionError::OutputTooSmall {
            required,
            available: mapping_output.len(),
        });
    }
    if input.kernel_segments.len() > materialization_output.len() {
        return Err(TransitionError::OutputTooSmall {
            required: input.kernel_segments.len(),
            available: materialization_output.len(),
        });
    }
    let mut used = 0;
    for (materialization_index, kernel) in input.kernel_segments.iter().enumerate() {
        let kind = MappingKind::KernelSegment {
            program_header_index: kernel.segment.program_header_index,
        };
        validate_kernel_segment(kernel, input.policy, input.kernel_image_byte_len)?;
        push_mapping(
            mapping_output,
            &mut used,
            TransitionMapping {
                kind,
                physical_start: kernel.pages.physical_start,
                virtual_start: kernel.segment.mapping_virtual_address,
                byte_len: kernel.segment.mapping_byte_len,
                permissions: permissions_from_segment(kernel.segment.permissions),
                lifetime: kernel.pages.lifetime,
            },
        );
        let copy_destination = kernel
            .pages
            .physical_start
            .checked_add(kernel.segment.segment_page_offset)
            .ok_or(TransitionError::RangeOverflow { kind })?;
        copy_destination
            .checked_add(kernel.segment.file_size)
            .ok_or(TransitionError::RangeOverflow { kind })?;
        materialization_output[materialization_index] = KernelMaterialization {
            program_header_index: kernel.segment.program_header_index,
            allocation: kernel.pages,
            file_offset: kernel.segment.file_offset,
            file_size: kernel.segment.file_size,
            copy_destination,
        };
    }

    push_identity(
        mapping_output,
        &mut used,
        MappingKind::BootInfo,
        input.identity.boot_info,
        read_only_nx(),
        input.policy,
    )?;
    push_identity(
        mapping_output,
        &mut used,
        MappingKind::MemoryMapTable,
        input.identity.memory_map_table,
        read_only_nx(),
        input.policy,
    )?;
    push_identity(
        mapping_output,
        &mut used,
        MappingKind::ModuleTable,
        input.identity.module_table,
        read_only_nx(),
        input.policy,
    )?;
    for (index, range) in input.identity.module_data.iter().copied().enumerate() {
        push_identity(
            mapping_output,
            &mut used,
            MappingKind::ModuleData { index },
            range,
            read_only_nx(),
            input.policy,
        )?;
    }
    if let Some(range) = input.identity.command_line {
        push_identity(
            mapping_output,
            &mut used,
            MappingKind::CommandLine,
            range,
            read_only_nx(),
            input.policy,
        )?;
    }
    if let Some(range) = input.identity.entropy {
        push_identity(
            mapping_output,
            &mut used,
            MappingKind::Entropy,
            range,
            read_only_nx(),
            input.policy,
        )?;
    }
    if let Some(rsdp) = input.identity.validated_rsdp {
        push_validated_rsdp(mapping_output, &mut used, rsdp, input.policy)?;
    }
    push_identity(
        mapping_output,
        &mut used,
        MappingKind::HandoffStub,
        input.identity.handoff_stub,
        MappingPermissions {
            writable: false,
            executable: true,
        },
        input.policy,
    )?;
    validate_transition_stack(input.identity.transition_stack, input.policy)?;
    push_identity(
        mapping_output,
        &mut used,
        MappingKind::TransitionStack,
        input.identity.transition_stack,
        MappingPermissions {
            writable: true,
            executable: false,
        },
        input.policy,
    )?;

    let mappings = &mut mapping_output[..used];
    mappings.sort_unstable_by(|left, right| {
        left.virtual_start
            .cmp(&right.virtual_start)
            .then(left.physical_start.cmp(&right.physical_start))
            .then(mapping_kind_order(left.kind).cmp(&mapping_kind_order(right.kind)))
    });
    validate_mapping_set(mappings, input.identity.framebuffer_pixels, input.policy)?;
    reject_temporary_mapping_collision(mappings)?;
    let minimum_page_table_page_count = required_page_table_pages(mappings, None, input.policy)?;
    let page_table_capacity_page_count =
        u64::from(DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT);
    if minimum_page_table_page_count > page_table_capacity_page_count {
        return Err(TransitionError::PageTableFixedPointCapacityExceeded {
            required_pages: minimum_page_table_page_count,
            maximum_pages: page_table_capacity_page_count,
        });
    }
    if !input.kernel_segments.iter().any(|kernel| {
        let segment = kernel.segment;
        let Some(end) = segment.virtual_address.checked_add(segment.memory_size) else {
            return false;
        };
        segment.permissions.execute
            && input.kernel_entry >= segment.virtual_address
            && input.kernel_entry < end
    }) {
        return Err(TransitionError::KernelEntryNotExecutable);
    }

    let boot_info_pointer = input.identity.boot_info.physical_start;
    if !boot_info_pointer.is_multiple_of(input.policy.boot_info_alignment) {
        return Err(TransitionError::BootInfoMisaligned);
    }
    let stack_pointer = input
        .identity
        .transition_stack
        .physical_start
        .checked_add(input.identity.transition_stack.byte_len)
        .ok_or(TransitionError::InvalidTransitionStack)?;
    if !stack_pointer.is_multiple_of(input.policy.stack_pointer_alignment) {
        return Err(TransitionError::InvalidTransitionStack);
    }
    let stub_end = checked_end(input.identity.handoff_stub, MappingKind::HandoffStub)?;
    if input.identity.handoff_stub_entry < input.identity.handoff_stub.physical_start
        || input.identity.handoff_stub_entry >= stub_end
    {
        return Err(TransitionError::HandoffStubEntryOutsideMapping);
    }

    Ok(TransitionPreflightPlan {
        mappings,
        kernel_materializations: &materialization_output[..input.kernel_segments.len()],
        policy: input.policy,
        kernel_image_byte_len: input.kernel_image_byte_len,
        minimum_page_table_page_count,
        page_table_capacity_page_count,
        transition_stack: input.identity.transition_stack,
        boot_info_storage: input.identity.boot_info,
        handoff_stub: input.identity.handoff_stub,
        framebuffer_pixels: input.identity.framebuffer_pixels,
        kernel_entry: input.kernel_entry,
        boot_info_identity_pointer: boot_info_pointer,
        transition_stack_pointer: stack_pointer,
        stack_pointer_alignment: input.policy.stack_pointer_alignment,
        handoff_stub_entry: input.identity.handoff_stub_entry,
    })
}

/// Attach caller-allocated page-table storage to a validated preflight result.
///
/// Storage must have the exact preflight size, remain retained, and be disjoint from every planned
/// mapping and from excluded framebuffer pixels.
pub fn finalize_transition<'plan>(
    preflight: TransitionPreflightPlan<'plan>,
    page_table_storage: RetainedPhysicalRange,
) -> Result<TransitionPlan<'plan>, TransitionError> {
    validate_page_table_storage(page_table_storage, preflight.policy)?;
    let required_page_table_bytes = preflight
        .page_table_capacity_page_count
        .checked_mul(preflight.policy.mapping_granule)
        .ok_or(TransitionError::PageTableCountOverflow)?;
    if page_table_storage.byte_len != required_page_table_bytes {
        return Err(TransitionError::PageTableStorageLengthMismatch {
            required_pages: preflight.page_table_capacity_page_count,
            provided_pages: page_table_storage.byte_len / preflight.policy.mapping_granule,
        });
    }
    validate_page_table_storage_disjoint(
        page_table_storage,
        preflight.mappings,
        preflight.framebuffer_pixels,
        preflight.policy,
    )?;

    let maximum_pages = preflight.page_table_capacity_page_count;
    let mut used_pages = preflight.minimum_page_table_page_count;
    let mut iterations = 0_u64;
    loop {
        iterations = iterations
            .checked_add(1)
            .ok_or(TransitionError::PageTableFixedPointDidNotConverge)?;
        if iterations > maximum_pages {
            return Err(TransitionError::PageTableFixedPointDidNotConverge);
        }
        if used_pages > maximum_pages {
            return Err(TransitionError::PageTableFixedPointCapacityExceeded {
                required_pages: used_pages,
                maximum_pages,
            });
        }
        let identity_byte_len = used_pages
            .checked_mul(preflight.policy.mapping_granule)
            .ok_or(TransitionError::PageTableCountOverflow)?;
        let next = required_page_table_pages(
            preflight.mappings,
            Some((page_table_storage.physical_start, identity_byte_len)),
            preflight.policy,
        )?;
        if next == used_pages {
            break;
        }
        if next < used_pages {
            return Err(TransitionError::PageTableFixedPointRegressed);
        }
        used_pages = next;
    }
    let identity_byte_len = used_pages
        .checked_mul(preflight.policy.mapping_granule)
        .ok_or(TransitionError::PageTableCountOverflow)?;
    let table_identity_mapping = TransitionMapping {
        kind: MappingKind::TransitionTableIdentity,
        physical_start: page_table_storage.physical_start,
        virtual_start: page_table_storage.physical_start,
        byte_len: identity_byte_len,
        permissions: MappingPermissions {
            writable: true,
            executable: false,
        },
        lifetime: AllocationLifetime::RetainedUntilKernelPageTableReplacement,
    };
    validate_table_identity_mapping(table_identity_mapping, preflight.mappings, preflight.policy)?;

    Ok(TransitionPlan {
        pre_exit: PreExitPlan {
            kernel_materializations: preflight.kernel_materializations,
            kernel_image_byte_len: preflight.kernel_image_byte_len,
            page_table_storage,
            page_table_page_count: preflight.page_table_capacity_page_count,
            used_page_table_page_count: used_pages,
            transition_stack: preflight.transition_stack,
            boot_info_storage: preflight.boot_info_storage,
            handoff_stub: preflight.handoff_stub,
        },
        mappings: preflight.mappings,
        table_identity_mapping,
        temporary_mapping: generated_temporary_mapping(),
        mapping_granule: preflight.policy.mapping_granule,
        kernel_entry: preflight.kernel_entry,
        boot_info_identity_pointer: preflight.boot_info_identity_pointer,
        transition_stack_pointer: preflight.transition_stack_pointer,
        stack_pointer_alignment: preflight.stack_pointer_alignment,
        handoff_stub_entry: preflight.handoff_stub_entry,
    })
}

fn required_mapping_count(input: &TransitionPreflightInput<'_>) -> Result<usize, TransitionError> {
    let mut count = input.kernel_segments.len();
    for additional in [
        3usize,
        input.identity.module_data.len(),
        usize::from(input.identity.command_line.is_some()),
        usize::from(input.identity.entropy.is_some()),
        usize::from(input.identity.validated_rsdp.is_some()),
        2usize,
    ] {
        count = count
            .checked_add(additional)
            .ok_or(TransitionError::MappingCountOverflow)?;
    }
    Ok(count)
}

fn validate_policy(policy: TransitionPolicy) -> Result<(), TransitionError> {
    if !policy.mapping_granule.is_power_of_two()
        || policy.rsdp_max_intersecting_pages == 0
        || policy.transition_stack_size == 0
        || !policy
            .transition_stack_size
            .is_multiple_of(policy.mapping_granule)
        || !policy.transition_stack_alignment.is_power_of_two()
        || policy.transition_stack_alignment < policy.mapping_granule
        || !policy.stack_pointer_alignment.is_power_of_two()
        || !policy.boot_info_alignment.is_power_of_two()
        || DW_BOOT_X86_64_PAGING_HANDOFF_MIN_TABLE_FRAME_COUNT as usize
            != generated_temporary_mapping().indices.len()
        || DW_BOOT_X86_64_PAGING_HANDOFF_MIN_TABLE_FRAME_COUNT
            > DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT
        || generated_temporary_mapping().indices != indices_for_generated_temporary_mapping()
    {
        return Err(TransitionError::InvalidPolicy);
    }
    Ok(())
}

const fn generated_temporary_mapping() -> TemporaryMappingReservation {
    TemporaryMappingReservation {
        virtual_address: DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS,
        indices: [
            DW_BOOT_X86_64_PAGING_HANDOFF_PML4_INDEX,
            DW_BOOT_X86_64_PAGING_HANDOFF_PDPT_INDEX,
            DW_BOOT_X86_64_PAGING_HANDOFF_PD_INDEX,
            DW_BOOT_X86_64_PAGING_HANDOFF_PT_INDEX,
        ],
    }
}

const fn indices_for_generated_temporary_mapping() -> [u16; 4] {
    let address = DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS;
    [
        ((address >> 39) & 0x1ff) as u16,
        ((address >> 30) & 0x1ff) as u16,
        ((address >> 21) & 0x1ff) as u16,
        ((address >> 12) & 0x1ff) as u16,
    ]
}

fn push_validated_rsdp(
    output: &mut [TransitionMapping],
    used: &mut usize,
    rsdp: ValidatedRsdpMappingInput,
    policy: TransitionPolicy,
) -> Result<(), TransitionError> {
    let kind = MappingKind::RequiredAcpiRsdp;
    validate_retained(rsdp.retained_allocation, kind)?;
    if rsdp.record_byte_len == 0 {
        return Err(TransitionError::InvalidRsdpRecord);
    }
    let record_end = rsdp
        .record_physical_start
        .checked_add(rsdp.record_byte_len)
        .ok_or(TransitionError::RsdpRecordRangeOverflow)?;
    let mapping_start = align_down(rsdp.record_physical_start, policy.mapping_granule);
    let mapping_end = align_up(record_end, policy.mapping_granule)
        .ok_or(TransitionError::RsdpRecordRangeOverflow)?;
    let mapping_byte_len = mapping_end
        .checked_sub(mapping_start)
        .filter(|length| *length != 0)
        .ok_or(TransitionError::RsdpRecordRangeOverflow)?;
    let required_pages = mapping_byte_len / policy.mapping_granule;
    if required_pages > policy.rsdp_max_intersecting_pages {
        return Err(TransitionError::RsdpMappingPageLimitExceeded {
            required_pages,
            maximum_pages: policy.rsdp_max_intersecting_pages,
        });
    }
    if rsdp.retained_allocation.physical_start != mapping_start
        || rsdp.retained_allocation.byte_len != mapping_byte_len
    {
        return Err(TransitionError::RsdpRetainedAllocationMismatch);
    }
    push_mapping(
        output,
        used,
        TransitionMapping {
            kind,
            physical_start: mapping_start,
            virtual_start: mapping_start,
            byte_len: mapping_byte_len,
            permissions: read_only_nx(),
            lifetime: rsdp.retained_allocation.lifetime,
        },
    );
    Ok(())
}

fn validate_kernel_segment(
    input: &KernelSegmentPages,
    policy: TransitionPolicy,
    kernel_image_byte_len: u64,
) -> Result<(), TransitionError> {
    let segment = input.segment;
    let kind = MappingKind::KernelSegment {
        program_header_index: segment.program_header_index,
    };
    if segment.memory_size == 0
        || segment.file_size > segment.memory_size
        || !segment.alignment.is_power_of_two()
        || segment.alignment < policy.mapping_granule
    {
        return Err(TransitionError::InvalidKernelSegment {
            program_header_index: segment.program_header_index,
        });
    }
    let source_end = segment.file_offset.checked_add(segment.file_size).ok_or(
        TransitionError::KernelSourceOutsideImage {
            program_header_index: segment.program_header_index,
        },
    )?;
    if source_end > kernel_image_byte_len {
        return Err(TransitionError::KernelSourceOutsideImage {
            program_header_index: segment.program_header_index,
        });
    }
    validate_retained(input.pages, kind)?;
    if !input
        .pages
        .physical_start
        .is_multiple_of(policy.mapping_granule)
    {
        return Err(TransitionError::PhysicalPagesUnaligned { kind });
    }
    let virtual_start = align_down(segment.virtual_address, policy.mapping_granule);
    let page_offset = segment.virtual_address - virtual_start;
    let covered = page_offset
        .checked_add(segment.memory_size)
        .ok_or(TransitionError::RangeOverflow { kind })?;
    let required = align_up(covered, policy.mapping_granule)
        .ok_or(TransitionError::MappingRoundOverflow { kind })?;
    if segment.mapping_virtual_address != virtual_start
        || segment.mapping_byte_len != required
        || segment.segment_page_offset != page_offset
    {
        return Err(TransitionError::InvalidKernelSegment {
            program_header_index: segment.program_header_index,
        });
    }
    if input.pages.byte_len != segment.mapping_byte_len {
        return Err(TransitionError::KernelPageLengthMismatch {
            program_header_index: segment.program_header_index,
        });
    }
    if segment.permissions.write && segment.permissions.execute {
        return Err(TransitionError::WritableExecutable { kind });
    }
    Ok(())
}

fn validate_page_table_storage(
    storage: RetainedPhysicalRange,
    policy: TransitionPolicy,
) -> Result<(), TransitionError> {
    if storage.byte_len == 0
        || storage.lifetime != AllocationLifetime::RetainedUntilKernelPageTableReplacement
        || storage
            .physical_start
            .checked_add(storage.byte_len)
            .is_none()
        || !storage
            .physical_start
            .is_multiple_of(policy.mapping_granule)
        || !storage.byte_len.is_multiple_of(policy.mapping_granule)
    {
        return Err(TransitionError::InvalidPageTableStorage);
    }
    Ok(())
}

fn validate_page_table_storage_disjoint(
    storage: RetainedPhysicalRange,
    mappings: &[TransitionMapping],
    framebuffer: Option<PhysicalRange>,
    policy: TransitionPolicy,
) -> Result<(), TransitionError> {
    let storage_end = storage
        .physical_start
        .checked_add(storage.byte_len)
        .ok_or(TransitionError::InvalidPageTableStorage)?;
    for mapping in mappings {
        let mapping_end = mapping.physical_start + mapping.byte_len;
        if storage.physical_start < mapping_end && mapping.physical_start < storage_end {
            return Err(TransitionError::PageTableStorageAlias { with: mapping.kind });
        }
    }
    if storage.physical_start < policy.mapping_granule {
        return Err(TransitionError::InvalidPageTableStorage);
    }
    if let Some(framebuffer) = framebuffer {
        if framebuffer.byte_len == 0 {
            return Err(TransitionError::InvalidFramebufferRange);
        }
        let framebuffer_end = framebuffer
            .physical_start
            .checked_add(framebuffer.byte_len)
            .ok_or(TransitionError::InvalidFramebufferRange)?;
        if storage.physical_start < framebuffer_end && framebuffer.physical_start < storage_end {
            return Err(TransitionError::FramebufferPixelsWouldBackPageTables);
        }
    }
    Ok(())
}

fn reject_temporary_mapping_collision(
    mappings: &[TransitionMapping],
) -> Result<(), TransitionError> {
    let temporary = generated_temporary_mapping().virtual_address;
    let slot_len = 1_u64 << 39;
    let slot_start = temporary & !(slot_len - 1);
    let slot_end = slot_start + slot_len;
    for mapping in mappings {
        let end = mapping
            .virtual_start
            .checked_add(mapping.byte_len)
            .ok_or(TransitionError::RangeOverflow { kind: mapping.kind })?;
        if mapping.virtual_start < slot_end && slot_start < end {
            return Err(TransitionError::TemporaryMappingConflict { with: mapping.kind });
        }
    }
    Ok(())
}

fn validate_table_identity_mapping(
    identity: TransitionMapping,
    mappings: &[TransitionMapping],
    policy: TransitionPolicy,
) -> Result<(), TransitionError> {
    let end = identity
        .virtual_start
        .checked_add(identity.byte_len)
        .ok_or(TransitionError::PageTableCountOverflow)?;
    if identity.virtual_start == 0
        || !identity
            .virtual_start
            .is_multiple_of(policy.mapping_granule)
        || !identity.byte_len.is_multiple_of(policy.mapping_granule)
        || canonical_four_level_half(identity.virtual_start) != Some(false)
        || canonical_four_level_half(end - 1) != Some(false)
    {
        return Err(TransitionError::InvalidPageTableStorage);
    }
    for mapping in mappings {
        let mapping_end = mapping.virtual_start + mapping.byte_len;
        if identity.virtual_start < mapping_end && mapping.virtual_start < end {
            return Err(TransitionError::VirtualOverlap {
                first: MappingKind::TransitionTableIdentity,
                second: mapping.kind,
            });
        }
    }
    Ok(())
}

fn validate_transition_stack(
    stack: RetainedPhysicalRange,
    policy: TransitionPolicy,
) -> Result<(), TransitionError> {
    if stack.byte_len != policy.transition_stack_size
        || !stack
            .physical_start
            .is_multiple_of(policy.transition_stack_alignment)
    {
        return Err(TransitionError::InvalidTransitionStack);
    }
    validate_retained(stack, MappingKind::TransitionStack)
        .map_err(|_| TransitionError::InvalidTransitionStack)?;
    stack
        .physical_start
        .checked_add(stack.byte_len)
        .ok_or(TransitionError::InvalidTransitionStack)?;
    Ok(())
}

fn push_identity(
    output: &mut [TransitionMapping],
    used: &mut usize,
    kind: MappingKind,
    range: RetainedPhysicalRange,
    permissions: MappingPermissions,
    policy: TransitionPolicy,
) -> Result<(), TransitionError> {
    validate_retained(range, kind)?;
    let exact_end = checked_end(range, kind)?;
    let mapping_start = align_down(range.physical_start, policy.mapping_granule);
    let mapping_end = align_up(exact_end, policy.mapping_granule)
        .ok_or(TransitionError::MappingRoundOverflow { kind })?;
    let byte_len = mapping_end - mapping_start;
    push_mapping(
        output,
        used,
        TransitionMapping {
            kind,
            physical_start: mapping_start,
            virtual_start: mapping_start,
            byte_len,
            permissions,
            lifetime: range.lifetime,
        },
    );
    Ok(())
}

fn push_mapping(output: &mut [TransitionMapping], used: &mut usize, mapping: TransitionMapping) {
    output[*used] = mapping;
    *used += 1;
}

fn validate_retained(
    range: RetainedPhysicalRange,
    kind: MappingKind,
) -> Result<(), TransitionError> {
    if range.byte_len == 0 {
        return Err(TransitionError::EmptyRange { kind });
    }
    if range.lifetime != AllocationLifetime::RetainedUntilKernelPageTableReplacement {
        return Err(TransitionError::AllocationNotRetained { kind });
    }
    checked_end(range, kind)?;
    Ok(())
}

fn checked_end(range: RetainedPhysicalRange, kind: MappingKind) -> Result<u64, TransitionError> {
    range
        .physical_start
        .checked_add(range.byte_len)
        .ok_or(TransitionError::RangeOverflow { kind })
}

fn validate_mapping_set(
    mappings: &[TransitionMapping],
    framebuffer: Option<PhysicalRange>,
    policy: TransitionPolicy,
) -> Result<(), TransitionError> {
    for mapping in mappings {
        if mapping.virtual_start == 0 {
            return Err(TransitionError::PageZeroWouldBeMapped { kind: mapping.kind });
        }
        if mapping.permissions.writable && mapping.permissions.executable {
            return Err(TransitionError::WritableExecutable { kind: mapping.kind });
        }
        if !mapping
            .physical_start
            .is_multiple_of(policy.mapping_granule)
            || !mapping.virtual_start.is_multiple_of(policy.mapping_granule)
            || !mapping.byte_len.is_multiple_of(policy.mapping_granule)
        {
            return Err(TransitionError::PhysicalPagesUnaligned { kind: mapping.kind });
        }
        mapping
            .physical_start
            .checked_add(mapping.byte_len)
            .ok_or(TransitionError::RangeOverflow { kind: mapping.kind })?;
        mapping
            .virtual_start
            .checked_add(mapping.byte_len)
            .ok_or(TransitionError::RangeOverflow { kind: mapping.kind })?;
        let virtual_end = mapping.virtual_start + mapping.byte_len;
        let start_half = canonical_four_level_half(mapping.virtual_start);
        let end_half = canonical_four_level_half(virtual_end - 1);
        if start_half.is_none() || start_half != end_half {
            return Err(TransitionError::NonCanonicalVirtualRange { kind: mapping.kind });
        }
    }

    for pair in mappings.windows(2) {
        let left = pair[0];
        let right = pair[1];
        if left.virtual_start + left.byte_len > right.virtual_start {
            return Err(TransitionError::VirtualOverlap {
                first: left.kind,
                second: right.kind,
            });
        }
    }
    for (position, left) in mappings.iter().enumerate() {
        let left_end = left.physical_start + left.byte_len;
        for right in &mappings[position + 1..] {
            let right_end = right.physical_start + right.byte_len;
            if left.physical_start < right_end && right.physical_start < left_end {
                return Err(TransitionError::PhysicalAlias {
                    first: left.kind,
                    second: right.kind,
                });
            }
        }
    }

    if let Some(framebuffer) = framebuffer {
        if framebuffer.byte_len == 0 {
            return Err(TransitionError::InvalidFramebufferRange);
        }
        let exact_end = framebuffer
            .physical_start
            .checked_add(framebuffer.byte_len)
            .ok_or(TransitionError::InvalidFramebufferRange)?;
        let excluded_start = align_down(framebuffer.physical_start, policy.mapping_granule);
        let excluded_end = align_up(exact_end, policy.mapping_granule)
            .ok_or(TransitionError::InvalidFramebufferRange)?;
        for mapping in mappings {
            let mapping_end = mapping.physical_start + mapping.byte_len;
            if mapping.physical_start < excluded_end && excluded_start < mapping_end {
                return Err(TransitionError::FramebufferPixelsWouldBeMapped { kind: mapping.kind });
            }
        }
    }

    Ok(())
}

fn required_page_table_pages(
    mappings: &[TransitionMapping],
    table_identity: Option<(u64, u64)>,
    policy: TransitionPolicy,
) -> Result<u64, TransitionError> {
    const X86_64_PAGE_TABLE_ENTRIES: u64 = 512;
    let pt_coverage = policy
        .mapping_granule
        .checked_mul(X86_64_PAGE_TABLE_ENTRIES)
        .ok_or(TransitionError::PageTableCountOverflow)?;
    let pd_coverage = pt_coverage
        .checked_mul(X86_64_PAGE_TABLE_ENTRIES)
        .ok_or(TransitionError::PageTableCountOverflow)?;
    let pdpt_coverage = pd_coverage
        .checked_mul(X86_64_PAGE_TABLE_ENTRIES)
        .ok_or(TransitionError::PageTableCountOverflow)?;

    let temporary = generated_temporary_mapping().virtual_address;
    let pt_pages =
        distinct_regions_with_additions(mappings, table_identity, temporary, pt_coverage)?;
    let pd_pages =
        distinct_regions_with_additions(mappings, table_identity, temporary, pd_coverage)?;
    let pdpt_pages =
        distinct_regions_with_additions(mappings, table_identity, temporary, pdpt_coverage)?;
    1u64.checked_add(pt_pages)
        .and_then(|count| count.checked_add(pd_pages))
        .and_then(|count| count.checked_add(pdpt_pages))
        .ok_or(TransitionError::PageTableCountOverflow)
}

fn distinct_regions_with_additions(
    mappings: &[TransitionMapping],
    table_identity: Option<(u64, u64)>,
    temporary: u64,
    coverage: u64,
) -> Result<u64, TransitionError> {
    let mut count = distinct_regions(mappings, coverage)?;
    if let Some((start, byte_len)) = table_identity {
        let end = start
            .checked_add(byte_len)
            .ok_or(TransitionError::PageTableCountOverflow)?;
        let first = start / coverage;
        let last = (end - 1) / coverage;
        let mut additional = last
            .checked_sub(first)
            .and_then(|span| span.checked_add(1))
            .ok_or(TransitionError::PageTableCountOverflow)?;
        let mut covered_through = None;
        for mapping in mappings {
            let mapping_end = mapping
                .virtual_start
                .checked_add(mapping.byte_len)
                .ok_or(TransitionError::PageTableCountOverflow)?;
            let mapping_first = mapping.virtual_start / coverage;
            let mapping_last = (mapping_end - 1) / coverage;
            let overlap_first = mapping_first.max(first);
            let overlap_last = mapping_last.min(last);
            if overlap_first <= overlap_last {
                let uncovered_first = covered_through
                    .and_then(|previous: u64| previous.checked_add(1))
                    .map_or(overlap_first, |next| next.max(overlap_first));
                if uncovered_first <= overlap_last {
                    additional = additional
                        .checked_sub(overlap_last - uncovered_first + 1)
                        .ok_or(TransitionError::PageTableCountOverflow)?;
                }
                covered_through =
                    Some(covered_through.map_or(overlap_last, |value| value.max(overlap_last)));
            }
        }
        count = count
            .checked_add(additional)
            .ok_or(TransitionError::PageTableCountOverflow)?;
    }

    let temporary_region = temporary / coverage;
    let covered_by_mapping = mappings.iter().any(|mapping| {
        let end = mapping.virtual_start + mapping.byte_len;
        mapping.virtual_start / coverage <= temporary_region
            && temporary_region <= (end - 1) / coverage
    });
    let covered_by_identity = table_identity.is_some_and(|(start, byte_len)| {
        start / coverage <= temporary_region
            && temporary_region <= (start + byte_len - 1) / coverage
    });
    if !covered_by_mapping && !covered_by_identity {
        count = count
            .checked_add(1)
            .ok_or(TransitionError::PageTableCountOverflow)?;
    }
    Ok(count)
}

fn distinct_regions(mappings: &[TransitionMapping], coverage: u64) -> Result<u64, TransitionError> {
    let mut count = 0u64;
    let mut previous_last = None;
    for mapping in mappings {
        let end = mapping
            .virtual_start
            .checked_add(mapping.byte_len)
            .ok_or(TransitionError::PageTableCountOverflow)?;
        let first = mapping.virtual_start / coverage;
        let last = (end - 1) / coverage;
        let mut added = last
            .checked_sub(first)
            .and_then(|span| span.checked_add(1))
            .ok_or(TransitionError::PageTableCountOverflow)?;
        if previous_last == Some(first) {
            added -= 1;
        }
        count = count
            .checked_add(added)
            .ok_or(TransitionError::PageTableCountOverflow)?;
        previous_last = Some(last);
    }
    Ok(count)
}

fn canonical_four_level_half(address: u64) -> Option<bool> {
    let upper = address >> 48;
    let sign = address & (1 << 47) != 0;
    match (sign, upper) {
        (false, 0) => Some(false),
        (true, 0xffff) => Some(true),
        _ => None,
    }
}

fn permissions_from_segment(permissions: SegmentPermissions) -> MappingPermissions {
    MappingPermissions {
        writable: permissions.write,
        executable: permissions.execute,
    }
}

const fn read_only_nx() -> MappingPermissions {
    MappingPermissions {
        writable: false,
        executable: false,
    }
}

fn mapping_kind_order(kind: MappingKind) -> (u8, usize) {
    match kind {
        MappingKind::KernelSegment {
            program_header_index,
        } => (0, usize::from(program_header_index)),
        MappingKind::BootInfo => (1, 0),
        MappingKind::MemoryMapTable => (2, 0),
        MappingKind::ModuleTable => (3, 0),
        MappingKind::ModuleData { index } => (4, index),
        MappingKind::CommandLine => (5, 0),
        MappingKind::Entropy => (6, 0),
        MappingKind::RequiredAcpiRsdp => (7, 0),
        MappingKind::HandoffStub => (8, 0),
        MappingKind::TransitionStack => (9, 0),
        MappingKind::TransitionTableIdentity => (10, 0),
    }
}

fn align_down(value: u64, alignment: u64) -> u64 {
    value & !(alignment - 1)
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value
        .checked_add(alignment - 1)
        .map(|end| align_down(end, alignment))
}

/// Minimal page-table population boundary. Implementations must operate on a fresh transition
/// table; a failure invalidates the table and must prevent kernel entry.
pub trait TransitionPageTable {
    type Error;

    /// Record that the entire virtual page-zero granule is absent.
    fn leave_page_zero_unmapped(&mut self, byte_len: u64) -> Result<(), Self::Error>;
    /// Materialize the intermediate hierarchy while preserving an exactly-zero leaf.
    fn reserve_temporary_mapping(
        &mut self,
        reservation: TemporaryMappingReservation,
    ) -> Result<(), Self::Error>;
    fn map(&mut self, mapping: TransitionMapping) -> Result<(), Self::Error>;
}

#[derive(Debug, Eq, PartialEq)]
pub enum PageTablePopulationError<Error> {
    PageZero(Error),
    TemporaryMapping(Error),
    Mapping { kind: MappingKind, error: Error },
}

/// Proof token separating all pre-exit allocations/copies from post-exit table population.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostExitBootServices {
    _private: (),
}

/// Convert the firmware adapter's EBS result into the post-exit capability required below.
pub fn confirm_exit_boot_services(complete: bool) -> Option<PostExitBootServices> {
    complete.then_some(PostExitBootServices { _private: () })
}

/// Apply a validated plan to a caller-owned fresh transition page table.
pub fn populate_page_table<Table: TransitionPageTable>(
    plan: &TransitionPlan<'_>,
    _post_exit: PostExitBootServices,
    table: &mut Table,
) -> Result<(), PageTablePopulationError<Table::Error>> {
    table
        .leave_page_zero_unmapped(plan.mapping_granule())
        .map_err(PageTablePopulationError::PageZero)?;
    table
        .reserve_temporary_mapping(plan.temporary_mapping())
        .map_err(PageTablePopulationError::TemporaryMapping)?;
    for mapping in plan.mappings() {
        table
            .map(*mapping)
            .map_err(|error| PageTablePopulationError::Mapping {
                kind: mapping.kind,
                error,
            })?;
    }
    let table_identity = plan.table_identity_mapping();
    table
        .map(table_identity)
        .map_err(|error| PageTablePopulationError::Mapping {
            kind: table_identity.kind,
            error,
        })?;
    Ok(())
}
