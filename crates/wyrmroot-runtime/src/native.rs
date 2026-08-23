//! Safe, allocation-free policy wrappers over Deepwyrm's native syscall crate.

use deepwyrm_syscall::{
    DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE, DW_ADDRESS_REGION_MAP_ARGS_V1_VERSION,
    DW_CHANNEL_RECEIVE_RESULT_V1_SIZE, DW_CLOCK_MONOTONIC_ACTIVE, DW_MEMORY_OBJECT_INFO_V1_SIZE,
    DW_MEMORY_PROTECTION_READ, DW_OBJECT_INFO_V1_SIZE, DW_SIGNALS_KNOWN_MASK, DW_STATUS_SUCCESS,
    DW_TASK_TERMINATION_INFO_V1_SIZE, DW_WAIT_MODE_ANY, DW_WAIT_RESULT_V1_SIZE,
    DwAddressRegionMapArgsV1, DwAddressRegionMapFlags, DwChannelReceiveResultV1, DwDeadline,
    DwHandle, DwHandleTransferV1, DwMemoryObjectInfoV1, DwObjectInfoV1, DwObjectType, DwOffset,
    DwReceivedHandleInfoV1, DwRights, DwSize, DwStatus, DwTaskTerminationInfoV1, DwUserAddress,
    DwWaitItemV1, DwWaitResultV1,
};

use crate::{CapabilityInfo, MappingPlan};

const X86_64_USER_END_EXCLUSIVE: u64 = 1_u64 << 47;

/// Exit code used when the freestanding runtime aborts after a panic or violated invariant.
pub const PANIC_EXIT_CODE: u32 = u32::MAX;

/// A successful kernel response violated the pinned generated ABI contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeOutputError {
    /// An object-info record had the wrong size, version, or reserved fields.
    InvalidObjectInfo,
    /// A MemoryObject-info record had the wrong size, version, or reserved fields.
    InvalidMemoryObjectInfo,
    /// Channel receive counts or generated records were inconsistent with the supplied buffers.
    InvalidChannelReceive,
    /// A successful map returned a zero, unaligned, or overflowing userspace range.
    InvalidMappedRange,
    /// A successful loader syscall returned malformed handles or records.
    InvalidLoaderOutput,
    /// A successful wait returned a malformed or unrelated generated result.
    InvalidWaitResult,
    /// A successful task-state query returned a malformed generated record.
    InvalidTaskTerminationInfo,
    /// A finite monotonic deadline could not be represented after the requested interval.
    DeadlineOverflow,
}

/// Failure from a native runtime operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeError {
    /// The kernel returned an exact native Deepwyrm status.
    Status(DwStatus),
    /// The kernel reported success but returned malformed output for the pinned ABI.
    Output(NativeOutputError),
}

/// Exact byte and handle counts produced by one successful Channel receive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveCounts {
    /// Payload bytes initialized in the caller's byte buffer.
    pub bytes: usize,
    /// Handle records initialized in the caller's handle buffer.
    pub handles: usize,
}

/// One successful read-only bootfs mapping.
#[derive(Debug, Eq, PartialEq)]
pub struct MappedBootfs {
    root_region: DwHandle,
    address: DwUserAddress,
    logical_size: u64,
    mapped_size: u64,
}

impl MappedBootfs {
    /// Returns the exact logical archive length; page-rounded padding is excluded.
    pub const fn logical_size(&self) -> u64 {
        self.logical_size
    }

    /// Returns the page-rounded range that will be supplied to unmap.
    pub const fn mapped_size(&self) -> u64 {
        self.mapped_size
    }

    /// Borrows exactly the logical bootfs bytes for one non-escaping callback.
    ///
    /// The callback is higher-ranked over the temporary slice lifetime, so a parser object or
    /// entry borrowing these bytes cannot escape the callback. This keeps safe callers from
    /// retaining archive borrows across [`unmap_bootfs`], which consumes the mapping token.
    ///
    /// ```compile_fail
    /// # use wyrmroot_runtime::MappedBootfs;
    /// # fn leak(mapping: &MappedBootfs) -> &[u8] {
    /// mapping.with_logical_bytes(|bytes| bytes)
    /// # }
    /// ```
    #[allow(
        unsafe_code,
        reason = "the token is created only after Deepwyrm successfully maps the validated read-only range, and the higher-ranked callback prevents the resulting slice from escaping before teardown"
    )]
    pub fn with_logical_bytes<R>(
        &self,
        use_bytes: impl for<'bytes> FnOnce(&'bytes [u8]) -> R,
    ) -> R {
        let byte_len = usize::try_from(self.logical_size)
            .expect("validated WYR0-C bootfs logical size fits the x86_64 native target");
        let pointer = self.address.0 as *const u8;
        // SAFETY: `map_bootfs_read_only` accepted a successful page-aligned Deepwyrm mapping
        // whose mapped extent covers `logical_size`. The token is non-Copy and its raw address is
        // not exposed. The higher-ranked callback prevents any borrow from escaping this call.
        let bytes = unsafe { core::slice::from_raw_parts(pointer, byte_len) };
        use_bytes(bytes)
    }
}

/// Closes one caller-local native handle.
pub fn close_handle(handle: DwHandle) -> Result<(), NativeError> {
    require_success(deepwyrm_syscall::handle_close(handle))
}

/// Queries fresh type and rights metadata through the generated basic-info record.
pub fn query_capability_info(
    handle: DwHandle,
) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
    let mut info = DwObjectInfoV1::default();
    let mut required_size = 0;
    require_success(deepwyrm_syscall::object_get_basic_info_v1(
        handle,
        &mut info,
        &mut required_size,
    ))?;
    validate_object_info(&info, required_size)?;
    Ok(CapabilityInfo {
        object_type: info.object_type,
        rights: info.rights,
    })
}

/// Queries the exact logical size of a MemoryObject, excluding page-rounded padding.
pub fn query_memory_object_size(handle: DwHandle) -> Result<u64, NativeError> {
    let mut info = DwMemoryObjectInfoV1::default();
    let mut required_size = 0;
    require_success(deepwyrm_syscall::object_get_memory_object_info_v1(
        handle,
        &mut info,
        &mut required_size,
    ))?;
    validate_memory_object_info(&info, required_size)?;
    Ok(info.byte_size)
}

/// Queries the generated Process or Thread lifecycle and termination record.
pub fn query_task_termination_info(
    handle: DwHandle,
) -> Result<DwTaskTerminationInfoV1, NativeError> {
    let mut info = DwTaskTerminationInfoV1::default();
    let mut required_size = 0;
    require_success(deepwyrm_syscall::object_get_task_state_v1(
        handle,
        &mut info,
        &mut required_size,
    ))?;
    validate_task_termination_info(&info, required_size)?;
    Ok(info)
}

/// Reads the ABI-0 active monotonic clock through the exact generated syscall veneer.
pub fn monotonic_active_now() -> Result<u64, NativeError> {
    let mut nanoseconds = 0_u64;
    require_success(deepwyrm_syscall::clock_get(
        DW_CLOCK_MONOTONIC_ACTIVE.0,
        &mut nanoseconds,
    ))?;
    Ok(nanoseconds)
}

/// Produces one checked finite absolute deadline in the active monotonic domain.
pub fn monotonic_deadline_after(interval_nanoseconds: u64) -> Result<DwDeadline, NativeError> {
    deadline_after(monotonic_active_now()?, interval_nanoseconds)
}

fn deadline_after(now: u64, interval_nanoseconds: u64) -> Result<DwDeadline, NativeError> {
    now.checked_add(interval_nanoseconds)
        .map(DwDeadline)
        .ok_or(NativeError::Output(NativeOutputError::DeadlineOverflow))
}

/// Waits for one of the caller-selected signals using ABI-0 WAIT_ANY.
pub fn wait_many(
    items: &[DwWaitItemV1],
    deadline: DwDeadline,
) -> Result<DwWaitResultV1, NativeError> {
    let mut result = DwWaitResultV1::default();
    require_success(deepwyrm_syscall::wait_many(
        items,
        DW_WAIT_MODE_ANY,
        deadline,
        &mut result,
    ))?;
    validate_wait_result(&result, items)?;
    Ok(result)
}

/// Sends one native Channel datagram with optional moved handles.
pub fn send_channel(
    channel: DwHandle,
    bytes: &[u8],
    transfers: &[DwHandleTransferV1],
) -> Result<(), NativeError> {
    require_success(deepwyrm_syscall::channel_send(channel, bytes, transfers, 0))
}

/// Receives one complete native Channel datagram into fixed caller-owned buffers.
pub fn receive_channel(
    channel: DwHandle,
    bytes: &mut [u8],
    handles: &mut [DwReceivedHandleInfoV1],
) -> Result<ReceiveCounts, NativeError> {
    let mut result = DwChannelReceiveResultV1::default();
    require_success(deepwyrm_syscall::channel_receive(
        channel,
        bytes,
        handles,
        &mut result,
    ))?;
    validate_channel_receive(&result, bytes.len(), handles)
}

/// Maps a validated bootfs extent read-only at a kernel-selected address.
pub fn map_bootfs_read_only(
    root_region: DwHandle,
    bootfs: DwHandle,
    plan: MappingPlan,
) -> Result<MappedBootfs, NativeError> {
    let arguments = DwAddressRegionMapArgsV1 {
        size: DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE,
        version: DW_ADDRESS_REGION_MAP_ARGS_V1_VERSION,
        memory_object_offset: DwOffset(0),
        byte_len: DwSize(plan.mapped_size()),
        requested_address: DwUserAddress(0),
        protections: DW_MEMORY_PROTECTION_READ,
        flags: DwAddressRegionMapFlags(0),
        reserved: [0; 4],
    };
    let mut address = DwUserAddress(0);
    require_success(deepwyrm_syscall::address_region_map(
        root_region,
        bootfs,
        &arguments,
        &mut address,
    ))?;
    validate_mapped_range(address, plan.mapped_size())?;
    Ok(MappedBootfs {
        root_region,
        address,
        logical_size: plan.logical_size(),
        mapped_size: plan.mapped_size(),
    })
}

/// Unmaps exactly one range returned by [`map_bootfs_read_only`], consuming its borrow token.
pub fn unmap_bootfs(mapping: MappedBootfs) -> Result<(), NativeError> {
    require_success(deepwyrm_syscall::address_region_unmap(
        mapping.root_region,
        mapping.address,
        DwSize(mapping.mapped_size),
    ))
}

/// Terminates the calling process normally. A rejected exit request fails closed by spinning.
pub fn exit_process(exit_code: u32) -> ! {
    let _unexpected_status = deepwyrm_syscall::process_exit(exit_code);
    fail_stop()
}

/// Terminates the calling thread normally. A rejected exit request fails closed by spinning.
pub fn exit_thread(exit_code: u32) -> ! {
    let _unexpected_status = deepwyrm_syscall::thread_exit(exit_code);
    fail_stop()
}

/// Freestanding panic policy: terminate the process with a deterministic nonzero code.
pub fn panic_abort() -> ! {
    exit_process(PANIC_EXIT_CODE)
}

fn require_success(status: DwStatus) -> Result<(), NativeError> {
    if status == DW_STATUS_SUCCESS {
        Ok(())
    } else {
        Err(NativeError::Status(status))
    }
}

fn validate_object_info(info: &DwObjectInfoV1, required_size: u64) -> Result<(), NativeError> {
    if required_size == u64::from(DW_OBJECT_INFO_V1_SIZE)
        && info.size == DW_OBJECT_INFO_V1_SIZE
        && info.version == 1
        && info.reserved0 == 0
        && info.reserved == [0; 4]
    {
        Ok(())
    } else {
        Err(NativeError::Output(NativeOutputError::InvalidObjectInfo))
    }
}

fn validate_memory_object_info(
    info: &DwMemoryObjectInfoV1,
    required_size: u64,
) -> Result<(), NativeError> {
    if required_size == u64::from(DW_MEMORY_OBJECT_INFO_V1_SIZE)
        && info.size == DW_MEMORY_OBJECT_INFO_V1_SIZE
        && info.version == 1
        && info.reserved == [0; 2]
    {
        Ok(())
    } else {
        Err(NativeError::Output(
            NativeOutputError::InvalidMemoryObjectInfo,
        ))
    }
}

fn validate_task_termination_info(
    info: &DwTaskTerminationInfoV1,
    required_size: u64,
) -> Result<(), NativeError> {
    if required_size == u64::from(DW_TASK_TERMINATION_INFO_V1_SIZE)
        && info.size == DW_TASK_TERMINATION_INFO_V1_SIZE
        && info.version == 1
        && info.reserved0 == 0
        && info.reserved == [0; 3]
    {
        Ok(())
    } else {
        Err(NativeError::Output(
            NativeOutputError::InvalidTaskTerminationInfo,
        ))
    }
}

fn validate_wait_result(
    result: &DwWaitResultV1,
    items: &[DwWaitItemV1],
) -> Result<(), NativeError> {
    let index = usize::try_from(result.index)
        .map_err(|_| NativeError::Output(NativeOutputError::InvalidWaitResult))?;
    let Some(item) = items.get(index) else {
        return Err(NativeError::Output(NativeOutputError::InvalidWaitResult));
    };
    if result.size == DW_WAIT_RESULT_V1_SIZE
        && result.version == 1
        && result.reserved0 == 0
        && result.reserved == [0; 3]
        && result.observed.0 & !DW_SIGNALS_KNOWN_MASK.0 == 0
        && result.observed.0 & item.signals.0 != 0
    {
        Ok(())
    } else {
        Err(NativeError::Output(NativeOutputError::InvalidWaitResult))
    }
}

fn validate_channel_receive(
    result: &DwChannelReceiveResultV1,
    byte_capacity: usize,
    handles: &[DwReceivedHandleInfoV1],
) -> Result<ReceiveCounts, NativeError> {
    let bytes = usize::try_from(result.actual_bytes)
        .map_err(|_| NativeError::Output(NativeOutputError::InvalidChannelReceive))?;
    let handle_count = usize::try_from(result.actual_handles)
        .map_err(|_| NativeError::Output(NativeOutputError::InvalidChannelReceive))?;
    let valid_handles = handles.get(..handle_count).is_some_and(|records| {
        records.iter().all(|record| {
            record.handle.0 != 0 && record.reserved0 == 0 && record.reserved == [0; 2]
        })
    });
    if result.size == DW_CHANNEL_RECEIVE_RESULT_V1_SIZE
        && result.version == 1
        && result.reserved == [0; 4]
        && bytes <= byte_capacity
        && handle_count <= handles.len()
        && result.required_bytes == result.actual_bytes
        && result.required_handles == result.actual_handles
        && valid_handles
    {
        Ok(ReceiveCounts {
            bytes,
            handles: handle_count,
        })
    } else {
        Err(NativeError::Output(
            NativeOutputError::InvalidChannelReceive,
        ))
    }
}

pub(crate) fn validate_mapped_range(
    address: DwUserAddress,
    mapped_size: u64,
) -> Result<(), NativeError> {
    let end_exclusive = address
        .0
        .checked_add(mapped_size)
        .ok_or(NativeError::Output(NativeOutputError::InvalidMappedRange))?;
    if address.0 >= crate::PAGE_SIZE
        && address.0.is_multiple_of(crate::PAGE_SIZE)
        && mapped_size != 0
        && mapped_size.is_multiple_of(crate::PAGE_SIZE)
        && end_exclusive <= X86_64_USER_END_EXCLUSIVE
    {
        Ok(())
    } else {
        Err(NativeError::Output(NativeOutputError::InvalidMappedRange))
    }
}

#[inline(never)]
fn fail_stop() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_handling_preserves_native_values() {
        assert_eq!(require_success(DW_STATUS_SUCCESS), Ok(()));
        let failure = DwStatus(-77);
        assert_eq!(require_success(failure), Err(NativeError::Status(failure)));
    }

    #[test]
    fn finite_monotonic_deadline_uses_checked_absolute_addition() {
        assert_eq!(deadline_after(7, 99), Ok(DwDeadline(106)));
        assert_eq!(
            deadline_after(u64::MAX, 1),
            Err(NativeError::Output(NativeOutputError::DeadlineOverflow))
        );
    }

    #[test]
    fn validates_generated_object_info_envelopes() {
        let basic = DwObjectInfoV1 {
            size: DW_OBJECT_INFO_V1_SIZE,
            version: 1,
            ..DwObjectInfoV1::default()
        };
        assert_eq!(
            validate_object_info(&basic, u64::from(DW_OBJECT_INFO_V1_SIZE)),
            Ok(())
        );
        assert!(validate_object_info(&basic, 0).is_err());

        let memory = DwMemoryObjectInfoV1 {
            size: DW_MEMORY_OBJECT_INFO_V1_SIZE,
            version: 1,
            byte_size: 17,
            ..DwMemoryObjectInfoV1::default()
        };
        assert_eq!(
            validate_memory_object_info(&memory, u64::from(DW_MEMORY_OBJECT_INFO_V1_SIZE)),
            Ok(())
        );
        let mut malformed = memory;
        malformed.reserved[0] = 1;
        assert!(
            validate_memory_object_info(&malformed, u64::from(DW_MEMORY_OBJECT_INFO_V1_SIZE))
                .is_err()
        );

        let task = DwTaskTerminationInfoV1 {
            size: DW_TASK_TERMINATION_INFO_V1_SIZE,
            version: 1,
            ..DwTaskTerminationInfoV1::default()
        };
        assert_eq!(
            validate_task_termination_info(&task, u64::from(DW_TASK_TERMINATION_INFO_V1_SIZE)),
            Ok(())
        );
        let mut malformed_task = task;
        malformed_task.reserved0 = 1;
        assert!(
            validate_task_termination_info(
                &malformed_task,
                u64::from(DW_TASK_TERMINATION_INFO_V1_SIZE)
            )
            .is_err()
        );
    }

    #[test]
    fn validates_channel_counts_and_received_handle_records() {
        let mut handles = [DwReceivedHandleInfoV1 {
            handle: DwHandle(9),
            ..DwReceivedHandleInfoV1::default()
        }];
        let result = DwChannelReceiveResultV1 {
            size: DW_CHANNEL_RECEIVE_RESULT_V1_SIZE,
            version: 1,
            actual_bytes: 4,
            actual_handles: 1,
            required_bytes: 4,
            required_handles: 1,
            reserved: [0; 4],
        };
        assert_eq!(
            validate_channel_receive(&result, 4, &handles),
            Ok(ReceiveCounts {
                bytes: 4,
                handles: 1
            })
        );
        handles[0].handle = DwHandle(0);
        assert!(validate_channel_receive(&result, 4, &handles).is_err());
        assert!(validate_channel_receive(&result, 3, &handles).is_err());
    }

    #[test]
    fn validates_wait_results_against_the_requested_items() {
        let items = [DwWaitItemV1 {
            handle: DwHandle(9),
            signals: deepwyrm_syscall::DW_SIGNAL_EXITED,
        }];
        let result = DwWaitResultV1 {
            size: DW_WAIT_RESULT_V1_SIZE,
            version: 1,
            index: 0,
            observed: deepwyrm_syscall::DW_SIGNAL_EXITED,
            ..DwWaitResultV1::default()
        };
        assert_eq!(validate_wait_result(&result, &items), Ok(()));
        let mut malformed = result;
        malformed.index = 1;
        assert!(validate_wait_result(&malformed, &items).is_err());
        malformed = result;
        malformed.observed = deepwyrm_syscall::DW_SIGNAL_READABLE;
        assert!(validate_wait_result(&malformed, &items).is_err());
    }

    #[test]
    fn validates_page_bounded_mapping_outputs() {
        assert_eq!(validate_mapped_range(DwUserAddress(0x4000), 0x2000), Ok(()));
        assert!(validate_mapped_range(DwUserAddress(0), 0x1000).is_err());
        assert!(validate_mapped_range(DwUserAddress(0x4001), 0x1000).is_err());
        assert!(validate_mapped_range(DwUserAddress(u64::MAX - 0xfff), 0x2000).is_err());
        assert!(validate_mapped_range(DwUserAddress(X86_64_USER_END_EXCLUSIVE), 0x1000).is_err());
        assert!(
            validate_mapped_range(
                DwUserAddress(X86_64_USER_END_EXCLUSIVE - crate::PAGE_SIZE),
                crate::PAGE_SIZE,
            )
            .is_ok()
        );
    }

    #[repr(align(4096))]
    struct AlignedBytes([u8; 4096]);

    #[test]
    fn mapped_bootfs_exposes_only_logical_bytes_inside_callback() {
        static BYTES: AlignedBytes = AlignedBytes([0x5a; 4096]);
        let mapping = MappedBootfs {
            root_region: DwHandle(9),
            address: DwUserAddress(BYTES.0.as_ptr() as u64),
            logical_size: 17,
            mapped_size: 4096,
        };
        let observed = mapping.with_logical_bytes(|bytes| {
            assert_eq!(bytes.len(), 17);
            assert!(bytes.iter().all(|byte| *byte == 0x5a));
            bytes.len()
        });
        assert_eq!(observed, 17);
    }
}
