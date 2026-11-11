//! Production generated DeviceResource and Interrupt syscall facade.
//!
//! This module contains only ordinary generated ABI operations.

use deepwyrm_syscall::{
    DW_ABI_FEATURE_DEVICE_RESOURCE_INTERRUPT, DW_ABI_INFO_V1_SIZE, DW_ABI_VERSION,
    DW_BASE_PAGE_SIZE, DW_DEVICE_RESOURCE_INFO_V1_SIZE, DW_INTERRUPT_INFO_V1_SIZE,
    DW_OBJECT_INFO_DEVICE_RESOURCE_V1, DW_OBJECT_INFO_INTERRUPT_V1, DW_STATUS_NOT_SUPPORTED,
    DW_STATUS_SUCCESS, DwAbiInfoV1, DwDeviceResourceInfoV1, DwHandle, DwInterruptInfoV1, DwRights,
    DwStatus,
};

use crate::{NativeError, NativeOutputError, capability_native::generated_raw_call};

/// Queries and validates the generated ABI discovery record.
pub(crate) fn abi_info() -> Result<DwAbiInfoV1, NativeError> {
    let mut info = DwAbiInfoV1::default();
    let mut required = 0_u64;
    require_success(generated_raw_call(
        deepwyrm_syscall::DW_SYSCALL_ABI_GET_INFO,
        [
            core::ptr::from_mut(&mut info) as u64,
            u64::from(DW_ABI_INFO_V1_SIZE),
            core::ptr::from_mut(&mut required) as u64,
            0,
            0,
            0,
        ],
    ))?;
    validate_abi_info(info, required)?;
    Ok(info)
}

fn validate_abi_info(info: DwAbiInfoV1, required: u64) -> Result<(), NativeError> {
    if required != u64::from(DW_ABI_INFO_V1_SIZE)
        || info.size != DW_ABI_INFO_V1_SIZE
        || info.version != 1
        || info.abi_version != DW_ABI_VERSION
        || info.page_size != DW_BASE_PAGE_SIZE
        || info.reserved != [0; 4]
    {
        Err(NativeError::Output(NativeOutputError::InvalidObjectInfo))
    } else {
        Ok(())
    }
}

/// Requires the complete generated DeviceResource/Interrupt family before a
/// caller attempts any member syscall.
pub fn require_device_resource_interrupt_feature() -> Result<DwAbiInfoV1, NativeError> {
    let info = abi_info()?;
    if info.feature_bits & DW_ABI_FEATURE_DEVICE_RESOURCE_INTERRUPT == 0 {
        Err(NativeError::Status(DW_STATUS_NOT_SUPPORTED))
    } else {
        Ok(info)
    }
}

/// Claims one generated boot DeviceResource through the received resource domain.
pub fn claim_device_resource(
    resource_domain: DwHandle,
    resource_id: u64,
    requested_rights: DwRights,
) -> Result<DwHandle, NativeError> {
    let mut resource = DwHandle(0);
    require_success(generated_raw_call(
        deepwyrm_syscall::DW_SYSCALL_DEVICE_RESOURCE_CLAIM,
        [
            resource_domain.0,
            resource_id,
            requested_rights.0,
            core::ptr::from_mut(&mut resource) as u64,
            0,
            0,
        ],
    ))?;
    nonzero_handle(resource)
}

/// Reads one checked scalar from a generated DeviceResource PIO range.
pub fn device_pio_read(resource: DwHandle, offset: u32, width: u32) -> Result<u32, NativeError> {
    let mut value = 0_u32;
    require_success(generated_raw_call(
        deepwyrm_syscall::DW_SYSCALL_DEVICE_PIO_READ,
        [
            resource.0,
            u64::from(offset),
            u64::from(width),
            core::ptr::from_mut(&mut value) as u64,
            0,
            0,
        ],
    ))?;
    Ok(value)
}

/// Reads 1, 2 or 4 bytes of a PCI_FUNCTION DeviceResource's standard config
/// space, at an aligned offset below 256.
pub fn device_pci_config_read(
    resource: DwHandle,
    offset: u32,
    width: u32,
) -> Result<u32, NativeError> {
    let mut value = 0_u32;
    require_success(generated_raw_call(
        deepwyrm_syscall::DW_SYSCALL_DEVICE_PCI_CONFIG_READ,
        [
            resource.0,
            u64::from(offset),
            u64::from(width),
            core::ptr::from_mut(&mut value) as u64,
            0,
            0,
        ],
    ))?;
    Ok(value)
}

/// Sets a PCI_FUNCTION's command-register memory-space and bus-master bits;
/// the kernel preserves every other bit and always clears I/O decoding.
pub fn device_pci_command(
    resource: DwHandle,
    memory_space: bool,
    bus_master: bool,
) -> Result<(), NativeError> {
    require_success(deepwyrm_syscall::device_pci_command(
        resource,
        memory_space,
        bus_master,
    ))
}

/// Creates a MemoryObject over one whole admitted memory BAR of a
/// PCI_FUNCTION; map it with the ordinary mapping calls (uncached, never
/// executable).
pub fn device_mmio_object_create(
    resource: DwHandle,
    bar: u32,
    requested_rights: DwRights,
) -> Result<DwHandle, NativeError> {
    let mut memory = DwHandle(0);
    require_success(deepwyrm_syscall::device_mmio_object_create(
        resource,
        bar,
        requested_rights,
        &mut memory,
    ))?;
    nonzero_handle(memory)
}

/// Maps a page-aligned range of a MemoryObject into the function's IOMMU
/// domain and returns the device-visible address (IOVA).
pub fn dma_map(
    resource: DwHandle,
    memory_object: DwHandle,
    offset: u64,
    byte_len: u64,
    access: u32,
) -> Result<u64, NativeError> {
    let mut iova = 0_u64;
    require_success(deepwyrm_syscall::dma_map(
        resource,
        memory_object,
        offset,
        byte_len,
        access,
        &mut iova,
    ))?;
    if iova == 0 || !iova.is_multiple_of(crate::PAGE_SIZE) {
        return Err(NativeError::Output(NativeOutputError::InvalidObjectInfo));
    }
    Ok(iova)
}

/// Removes one whole `dma_map` mapping by its exact IOVA and length.
pub fn dma_unmap(resource: DwHandle, iova: u64, byte_len: u64) -> Result<(), NativeError> {
    require_success(deepwyrm_syscall::dma_unmap(resource, iova, byte_len))
}

/// Writes one checked scalar to a generated DeviceResource PIO range.
pub fn device_pio_write(
    resource: DwHandle,
    offset: u32,
    width: u32,
    value: u32,
) -> Result<(), NativeError> {
    require_success(generated_raw_call(
        deepwyrm_syscall::DW_SYSCALL_DEVICE_PIO_WRITE,
        [
            resource.0,
            u64::from(offset),
            u64::from(width),
            u64::from(value),
            0,
            0,
        ],
    ))
}

/// Creates one generated Interrupt derived from a live DeviceResource.
pub fn create_interrupt(
    resource: DwHandle,
    requested_rights: DwRights,
) -> Result<DwHandle, NativeError> {
    let mut interrupt = DwHandle(0);
    require_success(generated_raw_call(
        deepwyrm_syscall::DW_SYSCALL_INTERRUPT_CREATE,
        [
            resource.0,
            requested_rights.0,
            core::ptr::from_mut(&mut interrupt) as u64,
            0,
            0,
            0,
        ],
    ))?;
    nonzero_handle(interrupt)
}

/// Acknowledges a generated pending Interrupt and requests its public rearm.
pub fn interrupt_ack(interrupt: DwHandle) -> Result<(), NativeError> {
    require_success(generated_raw_call(
        deepwyrm_syscall::DW_SYSCALL_INTERRUPT_ACK,
        [interrupt.0, 0, 0, 0, 0, 0],
    ))
}

/// Freshly queries immutable DeviceResource identity and lease information.
pub fn device_resource_info(resource: DwHandle) -> Result<DwDeviceResourceInfoV1, NativeError> {
    let mut info = DwDeviceResourceInfoV1::default();
    query_info(
        resource,
        DW_OBJECT_INFO_DEVICE_RESOURCE_V1,
        &mut info,
        DW_DEVICE_RESOURCE_INFO_V1_SIZE,
    )
}

/// Freshly queries generated Interrupt source and binding information.
pub fn interrupt_info(interrupt: DwHandle) -> Result<DwInterruptInfoV1, NativeError> {
    let mut info = DwInterruptInfoV1::default();
    query_info(
        interrupt,
        DW_OBJECT_INFO_INTERRUPT_V1,
        &mut info,
        DW_INTERRUPT_INFO_V1_SIZE,
    )
}

fn query_info<T: Default>(
    handle: DwHandle,
    topic: u32,
    info: &mut T,
    expected_size: u32,
) -> Result<T, NativeError> {
    let mut required = 0_u64;
    require_success(generated_raw_call(
        deepwyrm_syscall::DW_SYSCALL_OBJECT_GET_INFO_V1,
        [
            handle.0,
            u64::from(topic),
            core::ptr::from_mut(info) as u64,
            core::mem::size_of::<T>() as u64,
            core::ptr::from_mut(&mut required) as u64,
            0,
        ],
    ))?;
    if required != u64::from(expected_size) {
        return Err(NativeError::Output(NativeOutputError::InvalidObjectInfo));
    }
    Ok(core::mem::take(info))
}

fn nonzero_handle(handle: DwHandle) -> Result<DwHandle, NativeError> {
    if handle.0 == 0 {
        Err(NativeError::Output(NativeOutputError::InvalidObjectInfo))
    } else {
        Ok(handle)
    }
}

fn require_success(status: DwStatus) -> Result<(), NativeError> {
    if status == DW_STATUS_SUCCESS {
        Ok(())
    } else {
        Err(NativeError::Status(status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_info() -> DwAbiInfoV1 {
        DwAbiInfoV1 {
            size: DW_ABI_INFO_V1_SIZE,
            version: 1,
            abi_version: DW_ABI_VERSION,
            page_size: DW_BASE_PAGE_SIZE,
            feature_bits: DW_ABI_FEATURE_DEVICE_RESOURCE_INTERRUPT,
            max_channel_payload: 0,
            max_channel_handles: 0,
            reserved: [0; 4],
        }
    }

    #[test]
    fn abi_discovery_requires_exact_framing_version_page_size_and_reserved_fields() {
        let canonical = canonical_info();
        assert_eq!(
            validate_abi_info(canonical, u64::from(DW_ABI_INFO_V1_SIZE)),
            Ok(())
        );

        let mut cases = [canonical; 6];
        cases[0].size = 63;
        cases[1].version = 2;
        cases[2].abi_version = DW_ABI_VERSION.wrapping_add(1);
        cases[3].page_size = DW_BASE_PAGE_SIZE * 2;
        cases[4].reserved[0] = 1;
        cases[5].reserved[3] = 1;
        for info in cases {
            assert_eq!(
                validate_abi_info(info, u64::from(DW_ABI_INFO_V1_SIZE)),
                Err(NativeError::Output(NativeOutputError::InvalidObjectInfo))
            );
        }
        assert_eq!(
            validate_abi_info(canonical, u64::from(DW_ABI_INFO_V1_SIZE - 1)),
            Err(NativeError::Output(NativeOutputError::InvalidObjectInfo))
        );
    }
}
