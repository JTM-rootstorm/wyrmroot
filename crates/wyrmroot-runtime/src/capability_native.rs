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
    DwStatus, DwSyscallId, DwTerminationReason, DwUserAddress, DwWaitItemV1, DwWaitResultV1,
};

use crate::{NativeError, NativeOutputError, PAGE_SIZE, wait_many};

#[cfg(feature = "wyr1-test-evidence")]
const WYR1_TEST_EVIDENCE_SYSCALL: DwSyscallId = DwSyscallId(0xffff_ff19);
#[cfg(feature = "wyr1-test-evidence")]
pub const WYR1_EVIDENCE_RECORD_BYTES: usize = 114;
#[cfg(feature = "wyr1b-test-evidence")]
const WYR1B_TEST_EVIDENCE_SYSCALL: DwSyscallId = DwSyscallId(0xffff_ff1b);
#[cfg(feature = "wyr1b-test-evidence")]
pub const WYR1B_EVIDENCE_RECORD_BYTES: usize = 96;

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

/// Submits one selector-25-only WYR1 evidence record to the test collector.
/// Production kernels and other selectors reject the reserved raw operation.
#[cfg(feature = "wyr1-test-evidence")]
pub fn submit_wyr1_evidence(record: &[u8; WYR1_EVIDENCE_RECORD_BYTES]) -> Result<(), NativeError> {
    require_success(raw::call(
        WYR1_TEST_EVIDENCE_SYSCALL,
        [
            record.as_ptr() as u64,
            WYR1_EVIDENCE_RECORD_BYTES as u64,
            0,
            0,
            0,
            0,
        ],
    ))
}

/// Submits one selector-27-only WRB1 record to the test collector.
/// Production kernels and every other selector reject the reserved operation.
#[cfg(feature = "wyr1b-test-evidence")]
pub fn submit_wyr1b_evidence(
    record: &[u8; WYR1B_EVIDENCE_RECORD_BYTES],
) -> Result<(), NativeError> {
    require_success(raw::call(
        WYR1B_TEST_EVIDENCE_SYSCALL,
        [
            record.as_ptr() as u64,
            WYR1B_EVIDENCE_RECORD_BYTES as u64,
            0,
            0,
            0,
            0,
        ],
    ))
}

#[cfg(feature = "dw1b-test-evidence")]
const DW1B_TEST_EVIDENCE_SYSCALL: deepwyrm_syscall::DwSyscallId =
    deepwyrm_syscall::DwSyscallId(0xFFFF_FF1A);

/// Arms selector 26 from the exact init0 controller.
#[cfg(feature = "dw1b-test-evidence")]
pub fn arm_dw1b_preemption(
    hog_process: DwHandle,
    progress_process: DwHandle,
) -> Result<(), NativeError> {
    require_success(raw::call(
        DW1B_TEST_EVIDENCE_SYSCALL,
        [1, hog_process.0, progress_process.0, 8, 0, 0],
    ))
}

/// Submits selector 26 progress only after the fixed eight-round exchange.
#[cfg(feature = "dw1b-test-evidence")]
pub fn submit_dw1b_progress(digest: u64) -> Result<(), NativeError> {
    require_success(raw::call(
        DW1B_TEST_EVIDENCE_SYSCALL,
        [2, 8, digest, 0, 0, 0],
    ))
}

// Selector 28 is a private kernel test protocol.  This deliberately lives
// beside the other selector-private veneers and is never exported through the
// generated Deepwyrm ABI.
#[cfg(feature = "dw1c-test-evidence")]
const DW1C_TEST_EVIDENCE_SYSCALL: deepwyrm_syscall::DwSyscallId =
    deepwyrm_syscall::DwSyscallId(0xFFFF_FF1C);

/// The fixed selector-28 controller table has ten entries, in token order.
#[cfg(feature = "dw1c-test-evidence")]
pub const DW1C_ACTOR_COUNT: usize = 10;

/// Private ARM table entry consumed only by selector 28's collector.
///
/// The layout is explicitly little-endian `u64` fields at the syscall
/// boundary; it is not a public ABI record.
#[cfg(feature = "dw1c-test-evidence")]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Dw1cActorBindV1 {
    pub token: u64,
    pub role: u64,
    pub process: DwHandle,
}

/// Arms selector 28 with its fixed ten actor bindings and 240-second bound.
#[cfg(feature = "dw1c-test-evidence")]
pub fn arm_dw1c_preemption(
    bindings: &[Dw1cActorBindV1; DW1C_ACTOR_COUNT],
) -> Result<(), NativeError> {
    require_success(raw::call(
        DW1C_TEST_EVIDENCE_SYSCALL,
        [
            1,
            bindings.as_ptr() as u64,
            DW1C_ACTOR_COUNT as u64,
            240,
            0,
            0,
        ],
    ))
}

/// Submits one fixed-workload progress claim for a CPU-bound actor.
#[cfg(feature = "dw1c-test-evidence")]
pub fn submit_dw1c_progress(token: u64, count: u64, digest: u64) -> Result<(), NativeError> {
    require_success(raw::call(
        DW1C_TEST_EVIDENCE_SYSCALL,
        [2, token, count, digest, 0, 0],
    ))
}

/// Commits the completed selector-28 workload after tokens 1 through 5 have
/// submitted their exact bounded progress claims.
#[cfg(feature = "dw1c-test-evidence")]
pub fn submit_dw1c_workload_complete(digest: u64) -> Result<(), NativeError> {
    require_success(raw::call(
        DW1C_TEST_EVIDENCE_SYSCALL,
        [3, 0x1f, digest, 0, 0, 0],
    ))
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
