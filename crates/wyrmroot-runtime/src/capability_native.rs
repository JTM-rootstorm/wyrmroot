//! Safe native wrappers needed by the WYR0-I capability controller.
//!
//! The public surface uses only generated Deepwyrm types and constants. The small raw-call
//! boundary exists because the accepted syscall consumer crate has not yet added typed wrappers
//! for TaskGroup, Event, and Timer operations that are already present in the generated ABI.

use deepwyrm_syscall::{
    self, DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE, DW_ADDRESS_REGION_MAP_ARGS_V1_VERSION,
    DW_MEMORY_PROTECTION_READ, DW_MEMORY_PROTECTION_WRITE, DW_STATUS_SUCCESS,
    DW_WAIT_RESULT_V1_SIZE, DwAddressRegionMapArgsV1, DwAddressRegionMapFlags, DwDeadline,
    DwHandle, DwMemoryObjectCreateFlags, DwMemoryProtection, DwOffset, DwRights, DwSignals, DwSize,
    DwStatus, DwSyscallId, DwUserAddress, DwWaitItemV1, DwWaitResultV1,
};

use crate::{NativeError, NativeOutputError, PAGE_SIZE, wait_many};

/// One controller-owned mapping whose lifetime is explicit and whose writable alias can be
/// irreversibly removed before publication.
#[must_use = "memory mappings must be explicitly unmapped"]
pub struct OwnedMemoryMapping {
    root: DwHandle,
    address: DwUserAddress,
    bytes: u64,
    writable: bool,
}

impl OwnedMemoryMapping {
    pub fn with_bytes_mut<R>(
        &mut self,
        use_bytes: impl FnOnce(&mut [u8]) -> R,
    ) -> Result<R, NativeError> {
        if !self.writable {
            return Err(NativeError::Status(
                deepwyrm_syscall::DW_STATUS_ACCESS_DENIED,
            ));
        }
        let length = usize::try_from(self.bytes)
            .map_err(|_| NativeError::Output(NativeOutputError::InvalidMappedRange))?;
        // SAFETY: construction validated a nonzero aligned userspace range returned by a
        // successful RW mapping. The affine mapping token owns the only slice exposed here and
        // the callback cannot retain the borrow beyond this call.
        let bytes = unsafe { core::slice::from_raw_parts_mut(self.address.0 as *mut u8, length) };
        Ok(use_bytes(bytes))
    }

    pub fn with_bytes<R>(&self, use_bytes: impl FnOnce(&[u8]) -> R) -> Result<R, NativeError> {
        let length = usize::try_from(self.bytes)
            .map_err(|_| NativeError::Output(NativeOutputError::InvalidMappedRange))?;
        // SAFETY: construction validated this live readable range. The shared slice is bounded by
        // the mapping token and cannot escape the callback borrow.
        let bytes = unsafe { core::slice::from_raw_parts(self.address.0 as *const u8, length) };
        Ok(use_bytes(bytes))
    }

    /// Irreversibly removes writable authority from the live mapping.
    pub fn protect_read_only(&mut self) -> Result<(), NativeError> {
        if self.writable {
            require_success(deepwyrm_syscall::address_region_protect(
                self.root,
                self.address,
                DwSize(self.bytes),
                DW_MEMORY_PROTECTION_READ,
            ))?;
            self.writable = false;
        }
        Ok(())
    }
}

pub fn duplicate_handle(handle: DwHandle, rights: DwRights) -> Result<DwHandle, NativeError> {
    let mut duplicate = DwHandle(0);
    require_success(deepwyrm_syscall::handle_duplicate(
        handle,
        rights,
        &mut duplicate,
    ))?;
    if duplicate.0 == 0 {
        return Err(NativeError::Output(NativeOutputError::InvalidObjectInfo));
    }
    Ok(duplicate)
}

pub fn create_channel(rights: DwRights) -> Result<(DwHandle, DwHandle), NativeError> {
    let mut first = DwHandle(0);
    let mut second = DwHandle(0);
    require_success(deepwyrm_syscall::channel_create(
        rights,
        &mut first,
        &mut second,
    ))?;
    if first.0 == 0 || second.0 == 0 || first == second {
        return Err(NativeError::Output(NativeOutputError::InvalidLoaderOutput));
    }
    Ok((first, second))
}

pub fn create_memory_object(bytes: u64, rights: DwRights) -> Result<DwHandle, NativeError> {
    let mut memory = DwHandle(0);
    require_success(deepwyrm_syscall::memory_object_create(
        DwSize(bytes),
        DwMemoryObjectCreateFlags(0),
        rights,
        &mut memory,
    ))?;
    if memory.0 == 0 {
        return Err(NativeError::Output(NativeOutputError::InvalidObjectInfo));
    }
    Ok(memory)
}

pub fn map_memory_read_write(
    root: DwHandle,
    memory: DwHandle,
    bytes: u64,
) -> Result<OwnedMemoryMapping, NativeError> {
    map_memory(
        root,
        memory,
        bytes,
        DwMemoryProtection(DW_MEMORY_PROTECTION_READ.0 | DW_MEMORY_PROTECTION_WRITE.0),
        true,
    )
}

pub fn map_memory_read_only(
    root: DwHandle,
    memory: DwHandle,
    bytes: u64,
) -> Result<OwnedMemoryMapping, NativeError> {
    map_memory(root, memory, bytes, DW_MEMORY_PROTECTION_READ, false)
}

fn map_memory(
    root: DwHandle,
    memory: DwHandle,
    bytes: u64,
    protections: DwMemoryProtection,
    writable: bool,
) -> Result<OwnedMemoryMapping, NativeError> {
    if bytes == 0 || !bytes.is_multiple_of(PAGE_SIZE) {
        return Err(NativeError::Output(NativeOutputError::InvalidMappedRange));
    }
    let arguments = DwAddressRegionMapArgsV1 {
        size: DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE,
        version: DW_ADDRESS_REGION_MAP_ARGS_V1_VERSION,
        memory_object_offset: DwOffset(0),
        byte_len: DwSize(bytes),
        requested_address: DwUserAddress(0),
        protections,
        flags: DwAddressRegionMapFlags(0),
        reserved: [0; 4],
    };
    let mut address = DwUserAddress(0);
    require_success(deepwyrm_syscall::address_region_map(
        root,
        memory,
        &arguments,
        &mut address,
    ))?;
    if let Err(error) = crate::native::validate_mapped_range(address, bytes) {
        if address.0 != 0 && address.0.is_multiple_of(PAGE_SIZE) {
            let _ = deepwyrm_syscall::address_region_unmap(root, address, DwSize(bytes));
        }
        return Err(error);
    }
    Ok(OwnedMemoryMapping {
        root,
        address,
        bytes,
        writable,
    })
}

pub fn unmap_memory(mapping: OwnedMemoryMapping) -> Result<(), NativeError> {
    require_success(deepwyrm_syscall::address_region_unmap(
        mapping.root,
        mapping.address,
        DwSize(mapping.bytes),
    ))
}

pub fn wait_one(
    handle: DwHandle,
    signals: DwSignals,
    deadline: DwDeadline,
) -> Result<DwWaitResultV1, NativeError> {
    let item = DwWaitItemV1 { handle, signals };
    let result = wait_many(core::slice::from_ref(&item), deadline)?;
    if result.size != DW_WAIT_RESULT_V1_SIZE || result.version != 1 || result.index != 0 {
        return Err(NativeError::Output(NativeOutputError::InvalidWaitResult));
    }
    Ok(result)
}

pub fn terminate_process(
    process: DwHandle,
    reason: deepwyrm_syscall::DwTerminationReason,
    detail: u32,
) -> Result<(), NativeError> {
    require_success(deepwyrm_syscall::process_terminate(process, reason, detail))
}

pub fn create_task_group(parent: DwHandle, rights: DwRights) -> Result<DwHandle, NativeError> {
    let mut child = DwHandle(0);
    require_success(raw::call(
        deepwyrm_syscall::DW_SYSCALL_TASK_GROUP_CREATE,
        [
            parent.0,
            rights.0,
            core::ptr::from_mut(&mut child) as u64,
            0,
            0,
            0,
        ],
    ))?;
    if child.0 == 0 {
        return Err(NativeError::Output(NativeOutputError::InvalidObjectInfo));
    }
    Ok(child)
}

pub fn create_event(rights: DwRights) -> Result<DwHandle, NativeError> {
    let mut event = DwHandle(0);
    require_success(raw::call(
        deepwyrm_syscall::DW_SYSCALL_EVENT_CREATE,
        [rights.0, core::ptr::from_mut(&mut event) as u64, 0, 0, 0, 0],
    ))?;
    if event.0 == 0 {
        return Err(NativeError::Output(NativeOutputError::InvalidObjectInfo));
    }
    Ok(event)
}

pub fn signal_event(event: DwHandle, clear: DwSignals, set: DwSignals) -> Result<(), NativeError> {
    require_success(raw::call(
        deepwyrm_syscall::DW_SYSCALL_EVENT_SIGNAL,
        [event.0, clear.0, set.0, 0, 0, 0],
    ))
}

pub fn create_timer(rights: DwRights) -> Result<DwHandle, NativeError> {
    let mut timer = DwHandle(0);
    require_success(raw::call(
        deepwyrm_syscall::DW_SYSCALL_TIMER_CREATE,
        [rights.0, core::ptr::from_mut(&mut timer) as u64, 0, 0, 0, 0],
    ))?;
    if timer.0 == 0 {
        return Err(NativeError::Output(NativeOutputError::InvalidObjectInfo));
    }
    Ok(timer)
}

pub fn set_timer(timer: DwHandle, deadline: DwDeadline) -> Result<(), NativeError> {
    require_success(raw::call(
        deepwyrm_syscall::DW_SYSCALL_TIMER_SET,
        [timer.0, deadline.0, 0, 0, 0, 0],
    ))
}

pub fn cancel_timer(timer: DwHandle) -> Result<(), NativeError> {
    require_success(raw::call(
        deepwyrm_syscall::DW_SYSCALL_TIMER_CANCEL,
        [timer.0, 0, 0, 0, 0, 0],
    ))
}

fn require_success(status: DwStatus) -> Result<(), NativeError> {
    if status == DW_STATUS_SUCCESS {
        Ok(())
    } else {
        Err(NativeError::Status(status))
    }
}

#[allow(
    unsafe_code,
    reason = "one audited generated-ID boundary supplies safe wrappers for accepted ABI operations missing from the consumer crate"
)]
mod raw {
    use super::*;

    unsafe extern "C" {
        fn dw_syscall6(
            number: u64,
            arg0: u64,
            arg1: u64,
            arg2: u64,
            arg3: u64,
            arg4: u64,
            arg5: u64,
        ) -> i64;
    }

    pub(super) fn call(id: DwSyscallId, arguments: [u64; 6]) -> DwStatus {
        // SAFETY: every caller supplies only generated IDs/scalars and keeps any referenced output
        // object uniquely borrowed for the complete synchronous syscall.
        unsafe {
            DwStatus(dw_syscall6(
                id.0.into(),
                arguments[0],
                arguments[1],
                arguments[2],
                arguments[3],
                arguments[4],
                arguments[5],
            ) as i32)
        }
    }
}
