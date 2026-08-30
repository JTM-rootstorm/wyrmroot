//! Selector-30-only evidence carrier.
//!
//! Ordinary generated DeviceResource/Interrupt operations live in the
//! production `device` module. Only this narrow private `0xffff_ff1d` carrier
//! remains unavailable unless the D6 product explicitly enables this module.

use deepwyrm_syscall::{DW_STATUS_SUCCESS, DwHandle, DwStatus, DwSyscallId};

use crate::{NativeError, capability_native::generated_raw_call};

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

fn require_success(status: DwStatus) -> Result<(), NativeError> {
    if status == DW_STATUS_SUCCESS {
        Ok(())
    } else {
        Err(NativeError::Status(status))
    }
}
