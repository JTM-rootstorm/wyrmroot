//! Native Deepwyrm adapter for the WYR0 failure-atomic loader transaction.

use deepwyrm_syscall::{
    self, DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE, DW_ADDRESS_REGION_MAP_ARGS_V1_VERSION,
    DW_ADDRESS_REGION_MAP_FLAG_FIXED, DW_MEMORY_PROTECTION_READ, DW_MEMORY_PROTECTION_WRITE,
    DW_PROCESS_CREATE_ARGS_V1_SIZE, DW_PROCESS_CREATE_RESULT_V1_SIZE, DW_STATUS_SUCCESS,
    DW_TERMINATION_AUTHORIZED, DW_THREAD_START_ARGS_V1_SIZE, DwAddressRegionMapArgsV1,
    DwAddressRegionMapFlags, DwHandle, DwHandleTransferV1, DwMemoryObjectCreateFlags,
    DwMemoryProtection, DwOffset, DwProcessCreateArgsV1, DwProcessCreateResultV1, DwRights, DwSize,
    DwThreadStartArgsV1, DwUserAddress,
};
use wyrmroot_loader::process::{LoaderPlatform, ProcessCreateRequest, ProcessCreateResult};

use crate::{NativeError, NativeOutputError};

const LOADER_ABORT_CODE: u32 = 0x5759_5230;

/// Stateless syscall-backed implementation of the WYR0 loader platform boundary.
pub struct NativeLoaderPlatform;

impl LoaderPlatform for NativeLoaderPlatform {
    type Error = NativeError;

    fn channel_create(&mut self, rights: DwRights) -> Result<(DwHandle, DwHandle), Self::Error> {
        let mut first = DwHandle(0);
        let mut second = DwHandle(0);
        success(deepwyrm_syscall::channel_create(
            rights,
            &mut first,
            &mut second,
        ))?;
        if first.0 == 0 || second.0 == 0 || first == second {
            return Err(NativeError::Output(NativeOutputError::InvalidLoaderOutput));
        }
        Ok((first, second))
    }

    fn duplicate(&mut self, handle: DwHandle, rights: DwRights) -> Result<DwHandle, Self::Error> {
        let mut duplicate = DwHandle(0);
        success(deepwyrm_syscall::handle_duplicate(
            handle,
            rights,
            &mut duplicate,
        ))?;
        nonzero(duplicate)
    }

    fn close(&mut self, handle: DwHandle) -> Result<(), Self::Error> {
        success(deepwyrm_syscall::handle_close(handle))
    }

    fn process_create(
        &mut self,
        request: ProcessCreateRequest,
    ) -> Result<ProcessCreateResult, Self::Error> {
        let args = DwProcessCreateArgsV1 {
            size: DW_PROCESS_CREATE_ARGS_V1_SIZE,
            version: 1,
            task_group: request.task_group,
            bootstrap_channel: request.bootstrap_channel,
            process_rights: request.process_rights,
            root_region_rights: request.root_rights,
            child_bootstrap_rights: request.child_bootstrap_rights,
            flags: 0,
            reserved: [0; 4],
        };
        let mut result = DwProcessCreateResultV1::default();
        success(deepwyrm_syscall::process_create(&args, &mut result))?;
        if result.size != DW_PROCESS_CREATE_RESULT_V1_SIZE
            || result.version != 1
            || result.process.0 == 0
            || result.root_address_region.0 == 0
            || result.child_bootstrap_handle.0 == 0
            || result.reserved != [0; 4]
        {
            return Err(NativeError::Output(NativeOutputError::InvalidLoaderOutput));
        }
        Ok(ProcessCreateResult {
            process: result.process,
            root: result.root_address_region,
            child_bootstrap: result.child_bootstrap_handle,
        })
    }

    fn memory_create(&mut self, bytes: u64, rights: DwRights) -> Result<DwHandle, Self::Error> {
        let mut memory = DwHandle(0);
        success(deepwyrm_syscall::memory_object_create(
            DwSize(bytes),
            DwMemoryObjectCreateFlags(0),
            rights,
            &mut memory,
        ))?;
        nonzero(memory)
    }

    #[allow(
        unsafe_code,
        reason = "a successful checked RW mapping owns this exact extent until the mandatory unmap below"
    )]
    fn materialize_parent(
        &mut self,
        parent_root: DwHandle,
        memory: DwHandle,
        object_size: u64,
        destination_offset: u64,
        source: &[u8],
    ) -> Result<(), Self::Error> {
        let length = usize::try_from(object_size)
            .map_err(|_| NativeError::Output(NativeOutputError::InvalidMappedRange))?;
        let destination = usize::try_from(destination_offset)
            .map_err(|_| NativeError::Output(NativeOutputError::InvalidMappedRange))?;
        let end = destination
            .checked_add(source.len())
            .filter(|end| *end <= length)
            .ok_or(NativeError::Output(NativeOutputError::InvalidMappedRange))?;
        let arguments = map_arguments(0, object_size, rw_protection(), DwAddressRegionMapFlags(0));
        let mut address = DwUserAddress(0);
        success(deepwyrm_syscall::address_region_map(
            parent_root,
            memory,
            &arguments,
            &mut address,
        ))?;
        if let Err(error) = super::native::validate_mapped_range(address, object_size) {
            if address.0 != 0 && address.0.is_multiple_of(crate::PAGE_SIZE) {
                let _ = deepwyrm_syscall::address_region_unmap(
                    parent_root,
                    address,
                    DwSize(object_size),
                );
            }
            return Err(error);
        }
        // SAFETY: the validated mapping covers exactly `length` writable bytes and remains
        // exclusively owned by this call until the mandatory unmap. The slice never escapes.
        let bytes = unsafe { core::slice::from_raw_parts_mut(address.0 as *mut u8, length) };
        bytes.fill(0);
        bytes[destination..end].copy_from_slice(source);
        success(deepwyrm_syscall::address_region_unmap(
            parent_root,
            address,
            DwSize(object_size),
        ))
    }

    fn map_child(
        &mut self,
        child_root: DwHandle,
        memory: DwHandle,
        address: u64,
        bytes: u64,
        protection: DwMemoryProtection,
    ) -> Result<(), Self::Error> {
        let arguments = map_arguments(address, bytes, protection, DW_ADDRESS_REGION_MAP_FLAG_FIXED);
        let mut mapped = DwUserAddress(0);
        success(deepwyrm_syscall::address_region_map(
            child_root,
            memory,
            &arguments,
            &mut mapped,
        ))?;
        if mapped.0 != address {
            if mapped.0 != 0 && mapped.0.is_multiple_of(crate::PAGE_SIZE) {
                let _ = deepwyrm_syscall::address_region_unmap(child_root, mapped, DwSize(bytes));
            }
            return Err(NativeError::Output(NativeOutputError::InvalidMappedRange));
        }
        Ok(())
    }

    fn unmap_child(&mut self, root: DwHandle, address: u64, bytes: u64) -> Result<(), Self::Error> {
        success(deepwyrm_syscall::address_region_unmap(
            root,
            DwUserAddress(address),
            DwSize(bytes),
        ))
    }

    fn thread_create(
        &mut self,
        process: DwHandle,
        rights: DwRights,
    ) -> Result<DwHandle, Self::Error> {
        let mut thread = DwHandle(0);
        success(deepwyrm_syscall::thread_create(
            process,
            rights,
            &mut thread,
        ))?;
        nonzero(thread)
    }

    fn send_init(
        &mut self,
        channel: DwHandle,
        bytes: &[u8],
        transfers: &[DwHandleTransferV1],
    ) -> Result<(), Self::Error> {
        success(deepwyrm_syscall::channel_send(channel, bytes, transfers, 0))
    }

    fn thread_start(
        &mut self,
        thread: DwHandle,
        entry: u64,
        stack_pointer: u64,
        child_bootstrap: DwHandle,
        startup_abi: u64,
    ) -> Result<(), Self::Error> {
        let args = DwThreadStartArgsV1 {
            size: DW_THREAD_START_ARGS_V1_SIZE,
            version: 1,
            thread,
            entry: DwUserAddress(entry),
            stack_pointer: DwUserAddress(stack_pointer),
            startup_argument0: child_bootstrap.0,
            startup_argument1: startup_abi,
            flags: 0,
            reserved: [0; 3],
        };
        success(deepwyrm_syscall::thread_start(&args))
    }

    fn thread_terminate(&mut self, thread: DwHandle) -> Result<(), Self::Error> {
        success(deepwyrm_syscall::thread_terminate(
            thread,
            DW_TERMINATION_AUTHORIZED,
            LOADER_ABORT_CODE,
        ))
    }

    fn process_terminate(&mut self, process: DwHandle) -> Result<(), Self::Error> {
        success(deepwyrm_syscall::process_terminate(
            process,
            DW_TERMINATION_AUTHORIZED,
            LOADER_ABORT_CODE,
        ))
    }
}

fn map_arguments(
    address: u64,
    bytes: u64,
    protections: DwMemoryProtection,
    flags: DwAddressRegionMapFlags,
) -> DwAddressRegionMapArgsV1 {
    DwAddressRegionMapArgsV1 {
        size: DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE,
        version: DW_ADDRESS_REGION_MAP_ARGS_V1_VERSION,
        memory_object_offset: DwOffset(0),
        byte_len: DwSize(bytes),
        requested_address: DwUserAddress(address),
        protections,
        flags,
        reserved: [0; 4],
    }
}

const fn rw_protection() -> DwMemoryProtection {
    DwMemoryProtection(DW_MEMORY_PROTECTION_READ.0 | DW_MEMORY_PROTECTION_WRITE.0)
}

fn success(status: deepwyrm_syscall::DwStatus) -> Result<(), NativeError> {
    if status == DW_STATUS_SUCCESS {
        Ok(())
    } else {
        Err(NativeError::Status(status))
    }
}

fn nonzero(handle: DwHandle) -> Result<DwHandle, NativeError> {
    if handle.0 == 0 {
        Err(NativeError::Output(NativeOutputError::InvalidLoaderOutput))
    } else {
        Ok(handle)
    }
}
