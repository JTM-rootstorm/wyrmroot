//! Post-exit pages, inputs and the authorized jump.

use super::*;

/// Page ownership after successful EBS. Deliberately has no release API.
#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
pub(crate) struct PostExitPages {
    pub(crate) ptr: NonNull<u8>,
    pub(crate) allocation_byte_len: usize,
    pub(crate) payload_byte_len: usize,
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
impl RetainedPages {
    pub(crate) fn into_post_exit(self) -> PostExitPages {
        PostExitPages {
            ptr: self.ptr,
            allocation_byte_len: self.allocation_byte_len,
            payload_byte_len: self.payload_byte_len,
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
impl PostExitPages {
    pub(crate) fn physical_start(&self) -> u64 {
        self.ptr.as_ptr() as u64
    }

    pub(crate) fn retained_physical_range(
        &self,
    ) -> Result<RetainedPhysicalRange, FirmwarePreparationError> {
        Ok(RetainedPhysicalRange {
            physical_start: self.physical_start(),
            byte_len: u64::try_from(self.allocation_byte_len)
                .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?,
            lifetime: AllocationLifetime::RetainedUntilKernelPageTableReplacement,
        })
    }

    pub(crate) fn boot_info_allocation(
        &self,
    ) -> Result<HandoffAllocation, FirmwarePreparationError> {
        Ok(HandoffAllocation {
            physical_start: self.physical_start(),
            byte_len: u64::try_from(self.allocation_byte_len)
                .map_err(|_| FirmwarePreparationError::InvalidPreExitAllocation)?,
            lifetime: BootInfoAllocationLifetime::RetainedUntilDeepwyrmPageTableReplacement,
        })
    }

    pub(crate) fn write_paging_handoff_carrier(
        &mut self,
        attestation: &crate::uefi_page_table::PageTableAttestation<'_, '_, '_>,
    ) -> Result<usize, FirmwarePreparationError> {
        if size_of::<DwBootX86_64PagingHandoffV1>()
            != DW_BOOT_X86_64_PAGING_HANDOFF_V1_SIZE as usize
            || DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAMES_OFFSET as usize
                != size_of::<DwBootX86_64PagingHandoffV1>()
        {
            return Err(FirmwarePreparationError::TypedViewInvalid);
        }
        let total = usize::try_from(
            attestation
                .carrier_byte_len()
                .map_err(|_| FirmwarePreparationError::TypedViewInvalid)?,
        )
        .map_err(|_| FirmwarePreparationError::TypedViewInvalid)?;
        if total > self.allocation_byte_len
            || (self.ptr.as_ptr() as usize) % align_of::<DwBootX86_64PagingHandoffV1>() != 0
        {
            return Err(FirmwarePreparationError::TypedViewInvalid);
        }
        let frame_count = usize::try_from(attestation.used_page_count())
            .map_err(|_| FirmwarePreparationError::TypedViewInvalid)?;
        let frame_offset = DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAMES_OFFSET as usize;
        let frame_bytes = frame_count
            .checked_mul(size_of::<u64>())
            .ok_or(FirmwarePreparationError::TypedViewInvalid)?;
        if frame_offset.checked_add(frame_bytes) != Some(total) {
            return Err(FirmwarePreparationError::TypedViewInvalid);
        }
        // SAFETY: the carrier allocation is uniquely owned after EBS. The
        // generated header and frame-list extents were checked to be
        // aligned, disjoint, and wholly inside that allocation.
        let (header, frames) = unsafe {
            (
                &mut *self.ptr.as_ptr().cast::<DwBootX86_64PagingHandoffV1>(),
                core::slice::from_raw_parts_mut(
                    self.ptr.as_ptr().add(frame_offset).cast::<u64>(),
                    frame_count,
                ),
            )
        };
        let written = attestation
            .write_carrier(header, frames)
            .map_err(|_| FirmwarePreparationError::TypedViewInvalid)?;
        if usize::try_from(written).ok() != Some(total) {
            return Err(FirmwarePreparationError::TypedViewInvalid);
        }
        self.payload_byte_len = total;
        Ok(total)
    }

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
        // SAFETY: this token uniquely owns the retained allocation after
        // EBS and `byte_len` was checked against its full extent.
        Ok(unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr().cast::<T>(), count) })
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
pub(crate) struct PostExitAcpiRsdp {
    pub(crate) storage: PostExitPages,
    pub(crate) byte_len: usize,
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
pub(crate) enum PostExitEntropy {
    Available {
        storage: PostExitPages,
        source: FirmwareEntropySource,
        conditioned: bool,
    },
    Unavailable,
    Failed,
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
pub(crate) struct PostExitInputs {
    pub(crate) bootstrap: PostExitPages,
    pub(crate) bootfs: PostExitPages,
    pub(crate) boot_device_table: Option<PostExitPages>,
    pub(crate) acpi_rsdp: Option<PostExitAcpiRsdp>,
    pub(crate) framebuffer: Option<FramebufferMetadata>,
    pub(crate) entropy: PostExitEntropy,
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
pub(crate) fn release_pages(storage: &mut Option<RetainedPages>) {
    super::super::take_owned_resource_once(storage, |storage| {
        // SAFETY: every caller is a pre-EBS rollback/drop path and owns the
        // allocation exclusively through its `Option` token.
        unsafe { storage.release() };
    });
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
pub(crate) unsafe fn jump_to_kernel_authorized(
    _authorization: super::super::JumpAuthorization,
    transfer: crate::handoff_x86_64::X86_64Transfer<'_, '_, '_>,
) -> ! {
    // SAFETY: authorization is constructed only after the final-map,
    // BootInfo, page-table, serial, and transfer gates all succeed.
    unsafe { crate::handoff_x86_64::jump_to_kernel(transfer) }
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
pub(crate) fn allocate_typed_table<T>(
    count: usize,
) -> Result<RetainedPages, FirmwarePreparationError> {
    let byte_len = count
        .checked_mul(size_of::<T>())
        .ok_or(FirmwarePreparationError::InvalidPreExitAllocation)?;
    RetainedPages::allocate_zeroed_pages(
        pages_for_payload(byte_len).map_err(FirmwarePreparationError::Artifact)?,
    )
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
pub(crate) fn transition_policy(policy: GeneratedHandoffPolicy) -> TransitionPolicy {
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
pub(crate) fn identity_inputs<'a>(
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
pub(crate) fn copy_materializations(
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
pub(crate) fn materialized_inputs(
    prepared: PreparedPreExit,
) -> Result<MaterializedInputs, FirmwarePreparationError> {
    if prepared.kernel.is_some() {
        prepared.release_before_exit();
        return Err(FirmwarePreparationError::KernelSourceReleased);
    }
    Ok(MaterializedInputs {
        bootstrap: prepared.bootstrap,
        bootfs: prepared.bootfs,
        boot_device_table: prepared.boot_device_table,
        acpi_rsdp: prepared.acpi_rsdp,
        framebuffer: prepared.framebuffer,
        entropy: prepared.entropy,
    })
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
pub(crate) fn fallible_vec<T: Clone>(
    count: usize,
    value: T,
) -> Result<Vec<T>, FirmwarePreparationError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| FirmwarePreparationError::Allocation)?;
    result.resize(count, value);
    Ok(result)
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
pub(crate) fn dummy_segment() -> KernelLoadSegment {
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
pub(crate) fn fallible_segments(
    count: usize,
) -> Result<Vec<KernelLoadSegment>, FirmwarePreparationError> {
    fallible_vec(count, dummy_segment())
}
#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
pub(crate) fn fallible_kernel_segment_pages(
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
pub(crate) fn fallible_mappings(
    count: usize,
) -> Result<Vec<TransitionMapping>, FirmwarePreparationError> {
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
pub(crate) fn fallible_materializations(
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
pub(crate) fn firmware_memory_descriptor(
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
