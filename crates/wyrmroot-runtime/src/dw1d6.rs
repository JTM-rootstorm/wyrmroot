//! Selector-30-only generated DeviceResource/Interrupt facade.
//!
//! The five ordinary operations below use only generated DW1-D IDs, records,
//! and object metadata.  The final four functions are the intentionally
//! narrow selector-private `0xffff_ff1d` carrier; it is unavailable unless
//! the D6 product explicitly enables this module.

use deepwyrm_syscall::{
    DW_DEVICE_RESOURCE_INFO_V1_SIZE, DW_INTERRUPT_INFO_V1_SIZE, DW_OBJECT_INFO_DEVICE_RESOURCE_V1,
    DW_OBJECT_INFO_INTERRUPT_V1, DW_STATUS_SUCCESS, DwDeviceResourceInfoV1, DwHandle,
    DwInterruptInfoV1, DwRights, DwStatus, DwSyscallId,
};

use crate::{NativeError, NativeOutputError, capability_native::generated_raw_call};

const D6_PRIVATE_SYSCALL: DwSyscallId = DwSyscallId(0xffff_ff1d);

/// The only selector-private evidence events that a Wyrmroot actor may report.
/// Kernel-observed facts (boot table, finalization, grant return, reaping,
/// accounting, and terminal completion) deliberately have no variant here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum D6ReportEvent {
    BootstrapOutsideDomainClaimRejected,
    BootstrapReady,
    OwnerScratchSaved,
    OwnerChallengeWritten,
    OwnerChallengeReadBack,
    OwnerScratchRestored,
}

impl D6ReportEvent {
    const fn wire(self) -> u64 {
        match self {
            Self::BootstrapOutsideDomainClaimRejected => 0x03,
            Self::BootstrapReady => 0x17,
            Self::OwnerScratchSaved => 0x05,
            Self::OwnerChallengeWritten => 0x06,
            Self::OwnerChallengeReadBack => 0x07,
            Self::OwnerScratchRestored => 0x08,
        }
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

/// Arms the exact owner/trigger pair with the frozen selector-private carrier.
pub fn d6_arm(
    owner: DwHandle,
    trigger: DwHandle,
    nonce: u64,
    challenge: u64,
) -> Result<(), NativeError> {
    private_call([1, owner.0, trigger.0, nonce, challenge, 0])
}

/// Binds the caller's exact generated Interrupt to the selector-private source.
pub fn d6_bind(
    interrupt: DwHandle,
    lease_generation: u64,
    nonce: u64,
    challenge: u64,
) -> Result<(), NativeError> {
    private_call([2, interrupt.0, lease_generation, nonce, challenge, 0])
}

/// Requests the next monotonic selector-private synthetic delivery.
pub fn d6_deliver(sequence: u64, nonce: u64, challenge: u64) -> Result<(), NativeError> {
    private_call([3, sequence, nonce, challenge, 0, 0])
}

/// Emits one DWD6E1 relational event through the authenticated kernel collector.
pub fn d6_report(
    event: D6ReportEvent,
    value: u64,
    auxiliary: u64,
    nonce: u64,
    challenge: u64,
) -> Result<(), NativeError> {
    private_call([4, event.wire(), value, auxiliary, nonce, challenge])
}

fn private_call(arguments: [u64; 6]) -> Result<(), NativeError> {
    require_success(generated_raw_call(D6_PRIVATE_SYSCALL, arguments))
}

fn nonzero_handle(handle: DwHandle) -> Result<DwHandle, NativeError> {
    if handle.0 == 0 {
        Err(NativeError::Output(NativeOutputError::InvalidObjectInfo))
    } else {
        Ok(handle)
    }
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

fn require_success(status: DwStatus) -> Result<(), NativeError> {
    if status == DW_STATUS_SUCCESS {
        Ok(())
    } else {
        Err(NativeError::Status(status))
    }
}
