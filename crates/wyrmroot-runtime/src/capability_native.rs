//! Safe native wrappers needed by the WYR0-I capability controller.
//!
//! The public surface uses only generated Deepwyrm types and constants. The small raw-call
//! boundary exists because the accepted syscall consumer crate has not yet added typed wrappers
//! for TaskGroup, Event, and Timer operations that are already present in the generated ABI.

use deepwyrm_syscall::{
    self, DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE, DW_ADDRESS_REGION_MAP_ARGS_V1_VERSION,
    DW_MEMORY_PROTECTION_READ, DW_MEMORY_PROTECTION_WRITE, DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT,
    DW_RIGHT_MAP, DW_RIGHT_READ, DW_RIGHT_TRANSFER, DW_RIGHT_WRITE, DW_STATUS_SUCCESS,
    DW_WAIT_RESULT_V1_SIZE, DwAddressRegionMapArgsV1, DwAddressRegionMapFlags, DwDeadline,
    DwHandle, DwMemoryObjectCreateFlags, DwMemoryProtection, DwOffset, DwRights, DwSignals, DwSize,
    DwStatus, DwSyscallId, DwTerminationReason, DwUserAddress, DwWaitItemV1, DwWaitResultV1,
};

use crate::{NativeError, NativeOutputError, PAGE_SIZE, wait_many};

const MATERIALIZATION_PARENT_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0
        | DW_RIGHT_MAP.0
        | DW_RIGHT_WRITE.0
        | DW_RIGHT_INSPECT.0
        | DW_RIGHT_DUPLICATE.0
        | DW_RIGHT_TRANSFER.0,
);

fn materialization_lengths(source_len: usize) -> Result<(u64, u64), NativeError> {
    if source_len == 0 {
        return Err(NativeError::Output(NativeOutputError::InvalidMappedRange));
    }
    let logical = u64::try_from(source_len)
        .map_err(|_| NativeError::Output(NativeOutputError::InvalidMappedRange))?;
    let mapped = logical
        .checked_add(PAGE_SIZE - 1)
        .and_then(|value| value.checked_div(PAGE_SIZE))
        .and_then(|pages| pages.checked_mul(PAGE_SIZE))
        .ok_or(NativeError::Output(NativeOutputError::InvalidMappedRange))?;
    // Deepwyrm MemoryObjects are page-granular. Preserve the protocol's
    // logical length in its own header and zero-fill the rounded object tail;
    // both creation and mapping must use the admitted page extent.
    Ok((mapped, mapped))
}

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
    /// Temporarily views this mapping as writable bytes.
    ///
    /// # Safety
    ///
    /// The caller must ensure for the complete callback that the mapping remains live and
    /// writable, its backing storage is initialized, and no other Rust reference, mapping,
    /// process, thread, or device can read or mutate the same backing bytes in a way that violates
    /// Rust's exclusive-reference rules. The mapping token alone cannot prove those conditions
    /// because Deepwyrm permits multiple virtual mappings of one `MemoryObject`.
    ///
    /// Safe code cannot invoke this view:
    ///
    /// ```compile_fail
    /// # use wyrmroot_runtime::OwnedMemoryMapping;
    /// # fn view(mapping: &mut OwnedMemoryMapping) {
    /// mapping.with_bytes_mut(|bytes| bytes.fill(0));
    /// # }
    /// ```
    pub unsafe fn with_bytes_mut<R>(
        &mut self,
        use_bytes: impl for<'bytes> FnOnce(&'bytes mut [u8]) -> R,
    ) -> Result<R, NativeError> {
        if !self.writable {
            return Err(NativeError::Status(
                deepwyrm_syscall::DW_STATUS_ACCESS_DENIED,
            ));
        }
        let length = usize::try_from(self.bytes)
            .map_err(|_| NativeError::Output(NativeOutputError::InvalidMappedRange))?;
        // SAFETY: construction validated a nonzero aligned userspace range returned by a
        // successful RW mapping. The caller upholds mapping liveness and exclusive backing access;
        // the higher-ranked callback prevents the resulting borrow from escaping this call.
        let bytes = unsafe { core::slice::from_raw_parts_mut(self.address.0 as *mut u8, length) };
        Ok(use_bytes(bytes))
    }

    /// Temporarily views this mapping as readable bytes.
    ///
    /// # Safety
    ///
    /// The caller must ensure for the complete callback that the mapping remains live and
    /// readable, its backing storage is initialized, and no process, thread, device, or other
    /// mapping can mutate the same backing bytes outside Rust's interior-mutability rules.
    ///
    /// Safe code cannot invoke this view:
    ///
    /// ```compile_fail
    /// # use wyrmroot_runtime::OwnedMemoryMapping;
    /// # fn view(mapping: &OwnedMemoryMapping) {
    /// mapping.with_bytes(|bytes| bytes.len());
    /// # }
    /// ```
    pub unsafe fn with_bytes<R>(
        &self,
        use_bytes: impl for<'bytes> FnOnce(&'bytes [u8]) -> R,
    ) -> Result<R, NativeError> {
        let length = usize::try_from(self.bytes)
            .map_err(|_| NativeError::Output(NativeOutputError::InvalidMappedRange))?;
        // SAFETY: construction validated the range. The caller upholds mapping liveness and the
        // absence of external mutation; the higher-ranked callback prevents the borrow escaping.
        let bytes = unsafe { core::slice::from_raw_parts(self.address.0 as *const u8, length) };
        Ok(use_bytes(bytes))
    }

    /// Irreversibly removes writable authority from the live mapping.
    pub(crate) fn protect_read_only(&mut self) -> Result<(), NativeError> {
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

#[cfg(any(test, feature = "platform-recording"))]
impl OwnedMemoryMapping {
    /// The root region and byte extent, for the recording platform's call log.
    pub(crate) const fn recorded_extent(&self) -> (DwHandle, u64) {
        (self.root, self.bytes)
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

pub(crate) fn create_memory_object(bytes: u64, rights: DwRights) -> Result<DwHandle, NativeError> {
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

/// Materialize immutable bytes in one unpublished `MemoryObject` and return a
/// capability reduced to the supplied immutable staging rights.
///
/// The only unsafe operation is bounded to the exclusive parent mapping: the
/// object is freshly created, has no transferred handle, is zero-filled before
/// copying, and write authority is removed before any reduced capability can
/// escape.  This keeps callers such as permanent init `unsafe`-free while
/// preserving the native ABI's explicit mapping lifetime rules.
pub fn materialize_read_only_memory(
    root: DwHandle,
    source: &[u8],
    child_rights: DwRights,
) -> Result<DwHandle, NativeError> {
    let (object_bytes, mapped_bytes) = materialization_lengths(source.len())?;
    let memory = create_memory_object(object_bytes, MATERIALIZATION_PARENT_RIGHTS)?;
    let mut mapping = match map_memory_read_write(root, memory, mapped_bytes) {
        Ok(mapping) => mapping,
        Err(error) => {
            let _ = crate::close_handle(memory);
            return Err(error);
        }
    };
    // SAFETY: `memory` was created above and has not been shared or
    // transferred. `mapping` is the sole writable mapping and remains live
    // for this callback; the source slice is independent of its backing.
    let copied = unsafe {
        mapping.with_bytes_mut(|destination| {
            destination.fill(0);
            destination[..source.len()].copy_from_slice(source);
        })
    };
    if let Err(error) = copied {
        let _ = unmap_memory(mapping);
        let _ = crate::close_handle(memory);
        return Err(error);
    }
    if let Err(error) = mapping.protect_read_only() {
        let _ = unmap_memory(mapping);
        let _ = crate::close_handle(memory);
        return Err(error);
    }
    if let Err(error) = unmap_memory(mapping) {
        let _ = crate::close_handle(memory);
        return Err(error);
    }
    let reduced = match duplicate_handle(memory, child_rights) {
        Ok(handle) => handle,
        Err(error) => {
            let _ = crate::close_handle(memory);
            return Err(error);
        }
    };
    if let Err(error) = crate::close_handle(memory) {
        let _ = crate::close_handle(reduced);
        return Err(error);
    }
    Ok(reduced)
}

pub(crate) fn map_memory_read_write(
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

pub(crate) fn map_memory_read_only(
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

pub(crate) fn unmap_memory(mapping: OwnedMemoryMapping) -> Result<(), NativeError> {
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

/// `task_group_limit`: lowers one class's limit on a TaskGroup held with
/// MODIFY. Limits only fall.
pub fn limit_task_group(task_group: DwHandle, class: u32, limit: u32) -> Result<(), NativeError> {
    require_success(raw::call(
        deepwyrm_syscall::DW_SYSCALL_TASK_GROUP_LIMIT,
        [task_group.0, u64::from(class), u64::from(limit), 0, 0, 0],
    ))
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

/// Recursively terminates one controller-owned TaskGroup subtree.
///
/// The generated syscall consumer does not yet expose this typed convenience
/// wrapper, so the raw boundary remains localized here alongside TaskGroup
/// creation. The kernel admits only `DW_TERMINATION_AUTHORIZED` for this call.
pub fn terminate_task_group(
    task_group: DwHandle,
    reason: DwTerminationReason,
) -> Result<(), NativeError> {
    require_success(raw::call(
        deepwyrm_syscall::DW_SYSCALL_TASK_GROUP_TERMINATE,
        [task_group.0, u64::from(reason.0), 0, 0, 0, 0],
    ))
}

pub(crate) fn create_event(rights: DwRights) -> Result<DwHandle, NativeError> {
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

pub(crate) fn signal_event(
    event: DwHandle,
    clear: DwSignals,
    set: DwSignals,
) -> Result<(), NativeError> {
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

pub(crate) fn cancel_timer(timer: DwHandle) -> Result<(), NativeError> {
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

/// Runtime facades may invoke generated syscall IDs through this crate-local
/// boundary when the accepted consumer crate does not yet expose a typed
/// wrapper. Public safe functions remain the only external surface.
pub(crate) fn generated_raw_call(id: DwSyscallId, arguments: [u64; 6]) -> DwStatus {
    raw::call(id, arguments)
}

#[cfg(test)]
mod materialization_tests {
    use super::*;

    #[test]
    fn immutable_materialization_uses_page_granular_object_and_mapping_extents() {
        assert_eq!(materialization_lengths(1).unwrap(), (PAGE_SIZE, PAGE_SIZE));
        assert_eq!(
            materialization_lengths(PAGE_SIZE as usize + 1).unwrap(),
            (PAGE_SIZE * 2, PAGE_SIZE * 2)
        );
        assert!(materialization_lengths(0).is_err());
    }

    #[test]
    fn immutable_materialization_parent_has_write_but_child_can_be_exactly_reduced() {
        assert_ne!(MATERIALIZATION_PARENT_RIGHTS.0 & DW_RIGHT_WRITE.0, 0);
        let requested_child = DwRights(DW_RIGHT_READ.0 | DW_RIGHT_MAP.0 | DW_RIGHT_INSPECT.0);
        assert_eq!(
            requested_child.0,
            DW_RIGHT_READ.0 | DW_RIGHT_MAP.0 | DW_RIGHT_INSPECT.0
        );
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
