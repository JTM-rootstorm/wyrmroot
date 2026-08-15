//! Pure planning for the firmware-loaded WYR0 boot modules.
//!
//! This module performs no firmware calls and does not inspect ELF or bootfs
//! contents. It validates the physical storage ranges that the loader will
//! later hand to `DwBootInfoV1`, preserving the exact byte length while
//! tracking the page-rounded allocation extent.

use core::cmp::Ordering;

use deepwyrm_abi::{
    DW_BOOT_BASE_PAGE_SIZE, DW_BOOT_MODULE_FLAG_READ_ONLY,
    DW_BOOT_MODULE_KIND_DEEPWYRM_X86_64_PAGING_HANDOFF_V1, DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS,
    DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP, DW_BOOT_MODULE_V1_SIZE, DW_BOOT_MODULE_V1_VERSION,
    DW_BOOT_X86_64_PAGING_HANDOFF_MAX_BYTE_LEN,
    DW_BOOT_X86_64_PAGING_HANDOFF_MIN_TABLE_FRAME_COUNT,
    DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAME_STRIDE,
    DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAMES_OFFSET, DwBootModuleFlags, DwBootModuleKind,
    DwBootModuleV1,
};

/// The base page size required by the generated Deepwyrm boot contract.
pub const PAGE_SIZE: u64 = DW_BOOT_BASE_PAGE_SIZE as u64;

/// Ownership/lifetime state carried by a loader allocation plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocationState {
    /// The loader owns the firmware allocation and must retain it through the
    /// kernel handoff. No firmware allocation is performed by this module.
    LoaderRetainedThroughHandoff,
}

/// A firmware-loaded module description supplied to [`plan_modules`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModuleInput {
    pub kind: DwBootModuleKind,
    pub physical_start: u64,
    pub byte_len: u64,
}

/// A validated page-backed allocation and its exact payload extent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlannedModule {
    pub kind: DwBootModuleKind,
    pub physical_start: u64,
    pub byte_len: u64,
    pub allocated_len: u64,
    pub allocation: AllocationState,
}

impl PlannedModule {
    fn from_input(input: ModuleInput) -> Result<Self, ModulePlanError> {
        if input.byte_len == 0 {
            return Err(ModulePlanError::ZeroLength { kind: input.kind });
        }
        if input.kind == DW_BOOT_MODULE_KIND_DEEPWYRM_X86_64_PAGING_HANDOFF_V1
            && !valid_paging_handoff_extent(input.byte_len)
        {
            return Err(ModulePlanError::InvalidPagingHandoffExtent);
        }
        if !input.physical_start.is_multiple_of(PAGE_SIZE) {
            return Err(ModulePlanError::UnalignedStart {
                kind: input.kind,
                physical_start: input.physical_start,
            });
        }

        let end = input
            .physical_start
            .checked_add(input.byte_len)
            .ok_or(ModulePlanError::RangeOverflow { kind: input.kind })?;
        let allocated_len = input
            .byte_len
            .checked_add(PAGE_SIZE - 1)
            .ok_or(ModulePlanError::AllocationOverflow { kind: input.kind })?
            / PAGE_SIZE
            * PAGE_SIZE;
        input
            .physical_start
            .checked_add(allocated_len)
            .ok_or(ModulePlanError::AllocationOverflow { kind: input.kind })?;

        // Keep the checked payload end live as an explicit validation, even
        // when page rounding does not extend the allocation.
        let _ = end;
        Ok(Self {
            kind: input.kind,
            physical_start: input.physical_start,
            byte_len: input.byte_len,
            allocated_len,
            allocation: AllocationState::LoaderRetainedThroughHandoff,
        })
    }

    fn allocation_end(self) -> u64 {
        self.physical_start + self.allocated_len
    }

    fn to_abi(self) -> DwBootModuleV1 {
        DwBootModuleV1 {
            size: DW_BOOT_MODULE_V1_SIZE,
            version: DW_BOOT_MODULE_V1_VERSION,
            kind: self.kind,
            flags: if self.kind == DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS
                || self.kind == DW_BOOT_MODULE_KIND_DEEPWYRM_X86_64_PAGING_HANDOFF_V1
            {
                DW_BOOT_MODULE_FLAG_READ_ONLY
            } else {
                DwBootModuleFlags(0)
            },
            physical_start: self.physical_start,
            byte_len: self.byte_len,
            reserved: [0; 4],
        }
    }
}

fn valid_paging_handoff_extent(byte_len: u64) -> bool {
    let offset = u64::from(DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAMES_OFFSET);
    let stride = u64::from(DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAME_STRIDE);
    let minimum = offset + u64::from(DW_BOOT_X86_64_PAGING_HANDOFF_MIN_TABLE_FRAME_COUNT) * stride;
    (minimum..=u64::from(DW_BOOT_X86_64_PAGING_HANDOFF_MAX_BYTE_LEN)).contains(&byte_len)
        && (byte_len - offset).is_multiple_of(stride)
}

/// The deterministic bootstrap, bootfs, then internal paging-carrier module plan.
///
/// The third entry is deliberately not a loader-private convention: its kind
/// and read-only flag come from the generated Deepwyrm ABI.  Keeping the
/// carrier in this one plan prevents a second, unbounded module path from
/// bypassing overlap and allocation-extent validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModulePlan {
    modules: [PlannedModule; 3],
}

impl ModulePlan {
    pub fn bootstrap(self) -> PlannedModule {
        self.modules[0]
    }

    pub fn bootfs(self) -> PlannedModule {
        self.modules[1]
    }

    pub fn paging_handoff(self) -> PlannedModule {
        self.modules[2]
    }

    /// Convert in canonical order without maintaining a parallel ABI type.
    pub fn to_abi_modules(self) -> [DwBootModuleV1; 3] {
        [
            self.bootstrap().to_abi(),
            self.bootfs().to_abi(),
            self.paging_handoff().to_abi(),
        ]
    }
}

/// Validate and order the required WYR0 modules.
pub fn plan_modules(
    bootstrap: ModuleInput,
    bootfs: ModuleInput,
    paging_handoff: ModuleInput,
) -> Result<ModulePlan, ModulePlanError> {
    require_kind(bootstrap, DW_BOOT_MODULE_KIND_WYRMROOT_BOOTSTRAP)?;
    require_kind(bootfs, DW_BOOT_MODULE_KIND_WYRMROOT_BOOTFS)?;
    require_kind(
        paging_handoff,
        DW_BOOT_MODULE_KIND_DEEPWYRM_X86_64_PAGING_HANDOFF_V1,
    )?;
    let bootstrap = PlannedModule::from_input(bootstrap)?;
    let bootfs = PlannedModule::from_input(bootfs)?;
    let paging_handoff = PlannedModule::from_input(paging_handoff)?;
    if ranges_overlap(bootstrap, bootfs)
        || ranges_overlap(bootstrap, paging_handoff)
        || ranges_overlap(bootfs, paging_handoff)
    {
        return Err(ModulePlanError::OverlappingAllocations);
    }
    Ok(ModulePlan {
        modules: [bootstrap, bootfs, paging_handoff],
    })
}

fn require_kind(input: ModuleInput, expected: DwBootModuleKind) -> Result<(), ModulePlanError> {
    if input.kind != expected {
        return Err(ModulePlanError::UnexpectedKind {
            expected,
            actual: input.kind,
        });
    }
    Ok(())
}

fn ranges_overlap(left: PlannedModule, right: PlannedModule) -> bool {
    match left.physical_start.cmp(&right.physical_start) {
        Ordering::Less => left.allocation_end() > right.physical_start,
        Ordering::Equal => true,
        Ordering::Greater => right.allocation_end() > left.physical_start,
    }
}

/// Rejection reasons for malformed or unsafe module plans.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModulePlanError {
    UnexpectedKind {
        expected: DwBootModuleKind,
        actual: DwBootModuleKind,
    },
    ZeroLength {
        kind: DwBootModuleKind,
    },
    UnalignedStart {
        kind: DwBootModuleKind,
        physical_start: u64,
    },
    RangeOverflow {
        kind: DwBootModuleKind,
    },
    AllocationOverflow {
        kind: DwBootModuleKind,
    },
    InvalidPagingHandoffExtent,
    OverlappingAllocations,
}
