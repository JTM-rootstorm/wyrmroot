//! Explicitly feature-gated native surfaces for primordial kernel test variants.
//!
//! Production Wyrmroot executables never compile this module. The blocking variant calls only the
//! linked Deepwyrm-generated syscall veneer with generated IDs and ABI types. The two terminal
//! fault variants are deliberately target-only and never return to ordinary Rust code.

#[cfg(target_os = "wyrmroot")]
use core::sync::atomic::{AtomicU32, Ordering};

#[cfg(not(target_os = "wyrmroot"))]
use deepwyrm_syscall::DW_STATUS_NOT_SUPPORTED;
#[cfg(target_os = "wyrmroot")]
use deepwyrm_syscall::{
    DW_CLOCK_MONOTONIC_ACTIVE, DW_SIGNAL_READABLE, DW_SYSCALL_ATOMIC_WAIT32, DW_SYSCALL_CLOCK_GET,
    DW_SYSCALL_WAIT_ONE, DwSyscallId,
};
#[cfg(any(target_os = "wyrmroot", test))]
use deepwyrm_syscall::{
    DW_STATUS_SUCCESS, DW_STATUS_TIMED_OUT, DW_WAIT_RESULT_V1_SIZE, DwDeadline, DwSignals,
    DwWaitResultV1,
};
use deepwyrm_syscall::{DwHandle, DwStatus};

#[cfg(any(target_os = "wyrmroot", test))]
const TEST_WAIT_DELTA_NS: u64 = 50_000_000;

#[cfg(target_os = "wyrmroot")]
#[repr(align(4))]
struct AlignedAtomicWord(AtomicU32);

#[cfg(target_os = "wyrmroot")]
static ATOMIC_WAIT_WORD: AlignedAtomicWord = AlignedAtomicWord(AtomicU32::new(0));

/// Failure of an explicitly selected primordial kernel-test behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrimordialTestError {
    /// Reading the active monotonic clock failed.
    Clock(DwStatus),
    /// Adding the fixed future interval overflowed the generated deadline scalar.
    DeadlineOverflow,
    /// `wait_one` did not return the exact timeout required by the test contract.
    WaitOneStatus(DwStatus),
    /// `wait_one` did not preserve or return a structurally valid timeout record.
    InvalidWaitResult,
    /// The atomic test word did not retain the expected value before blocking.
    AtomicValueChanged,
    /// `atomic_wait32` did not return the exact timeout required by the test contract.
    AtomicWaitStatus(DwStatus),
}

#[cfg(target_os = "wyrmroot")]
unsafe extern "C" {
    /// Linked from the exact pinned `deepwyrm-syscall` generated assembly.
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

/// Exercise deadline-backed `wait_one` and `atomic_wait32` cleanup before bootstrap READY.
#[cfg(target_os = "wyrmroot")]
pub fn primordial_blocking_cleanup(channel: DwHandle) -> Result<(), PrimordialTestError> {
    let wait_deadline = future_deadline(monotonic_active_now()?)?;
    wait_one_until_timeout(channel, DW_SIGNAL_READABLE, wait_deadline)?;

    if ATOMIC_WAIT_WORD.0.load(Ordering::Relaxed) != 0 {
        return Err(PrimordialTestError::AtomicValueChanged);
    }
    let atomic_deadline = future_deadline(monotonic_active_now()?)?;
    atomic_wait32_until_timeout(&ATOMIC_WAIT_WORD.0, 0, atomic_deadline)
}

/// Host-only validation placeholder: the behavior can execute only in a Wyrmroot-native artifact.
#[cfg(not(target_os = "wyrmroot"))]
pub fn primordial_blocking_cleanup(_channel: DwHandle) -> Result<(), PrimordialTestError> {
    Err(PrimordialTestError::Clock(DW_STATUS_NOT_SUPPORTED))
}

/// Raise the architectural invalid-opcode exception after the test bootstrap has sent READY.
#[cfg(target_os = "wyrmroot")]
pub fn trigger_user_exception() -> ! {
    // SAFETY: this feature-selected terminal path intentionally raises #UD and never returns.
    unsafe { core::arch::asm!("ud2", options(noreturn, nomem, nostack)) }
}

/// Host-only validation placeholder: the behavior can execute only in a Wyrmroot-native artifact.
#[cfg(not(target_os = "wyrmroot"))]
pub fn trigger_user_exception() -> ! {
    panic!("primordial user-exception variant requires the Wyrmroot target")
}

/// Enter an unknown syscall with `RSP=0` so Deepwyrm must reject unsafe userspace return state.
#[cfg(target_os = "wyrmroot")]
pub fn trigger_invalid_syscall_return() -> ! {
    let unknown = u64::from(DwSyscallId(u32::MAX).0);
    // SAFETY: this is an explicitly selected terminal kernel test. It cannot call the ordinary
    // generated veneer because a SysV call would push a return address after RSP becomes zero.
    // The generated syscall-ID type still carries the deliberate open-namespace unknown value;
    // every argument register is zero and no ordinary Rust frame is expected to survive.
    unsafe {
        core::arch::asm!(
            "xor rdi, rdi",
            "xor rsi, rsi",
            "xor rdx, rdx",
            "xor r10, r10",
            "xor r8, r8",
            "xor r9, r9",
            "xor rsp, rsp",
            "syscall",
            "ud2",
            in("rax") unknown,
            options(noreturn)
        )
    }
}

/// Host-only validation placeholder: the behavior can execute only in a Wyrmroot-native artifact.
#[cfg(not(target_os = "wyrmroot"))]
pub fn trigger_invalid_syscall_return() -> ! {
    panic!("primordial invalid-return variant requires the Wyrmroot target")
}

#[cfg(target_os = "wyrmroot")]
fn monotonic_active_now() -> Result<u64, PrimordialTestError> {
    let mut nanoseconds = 0_u64;
    let status = raw_generated_syscall(
        DW_SYSCALL_CLOCK_GET,
        [
            u64::from(DW_CLOCK_MONOTONIC_ACTIVE.0),
            core::ptr::from_mut(&mut nanoseconds) as u64,
            0,
            0,
            0,
            0,
        ],
    );
    if status == DW_STATUS_SUCCESS {
        Ok(nanoseconds)
    } else {
        Err(PrimordialTestError::Clock(status))
    }
}

#[cfg(any(target_os = "wyrmroot", test))]
fn future_deadline(now: u64) -> Result<DwDeadline, PrimordialTestError> {
    now.checked_add(TEST_WAIT_DELTA_NS)
        .map(DwDeadline)
        .ok_or(PrimordialTestError::DeadlineOverflow)
}

#[cfg(target_os = "wyrmroot")]
fn wait_one_until_timeout(
    channel: DwHandle,
    signals: DwSignals,
    deadline: DwDeadline,
) -> Result<(), PrimordialTestError> {
    let mut result = empty_wait_result();
    let status = raw_generated_syscall(
        DW_SYSCALL_WAIT_ONE,
        [
            channel.0,
            signals.0,
            deadline.0,
            core::ptr::from_mut(&mut result) as u64,
            0,
            0,
        ],
    );
    validate_wait_timeout(status, &result)
}

#[cfg(target_os = "wyrmroot")]
fn atomic_wait32_until_timeout(
    word: &AtomicU32,
    expected: u32,
    deadline: DwDeadline,
) -> Result<(), PrimordialTestError> {
    if word.load(Ordering::Relaxed) != expected {
        return Err(PrimordialTestError::AtomicValueChanged);
    }
    let status = raw_generated_syscall(
        DW_SYSCALL_ATOMIC_WAIT32,
        [
            core::ptr::from_ref(word) as u64,
            u64::from(expected),
            deadline.0,
            0,
            0,
            0,
        ],
    );
    validate_atomic_timeout(status)
}

#[cfg(any(target_os = "wyrmroot", test))]
fn empty_wait_result() -> DwWaitResultV1 {
    DwWaitResultV1 {
        size: DW_WAIT_RESULT_V1_SIZE,
        version: 1,
        index: 0,
        reserved0: 0,
        observed: DwSignals(0),
        reserved: [0; 3],
    }
}

#[cfg(any(target_os = "wyrmroot", test))]
fn validate_wait_timeout(
    status: DwStatus,
    result: &DwWaitResultV1,
) -> Result<(), PrimordialTestError> {
    if status != DW_STATUS_TIMED_OUT {
        return Err(PrimordialTestError::WaitOneStatus(status));
    }
    if *result != empty_wait_result() {
        return Err(PrimordialTestError::InvalidWaitResult);
    }
    Ok(())
}

#[cfg(any(target_os = "wyrmroot", test))]
fn validate_atomic_timeout(status: DwStatus) -> Result<(), PrimordialTestError> {
    if status == DW_STATUS_TIMED_OUT {
        Ok(())
    } else {
        Err(PrimordialTestError::AtomicWaitStatus(status))
    }
}

#[cfg(target_os = "wyrmroot")]
fn raw_generated_syscall(number: DwSyscallId, arguments: [u64; 6]) -> DwStatus {
    // SAFETY: this test-only boundary calls the linked generated register-shuffle veneer. Every
    // known ID and argument layout above comes from the pinned generated ABI. Pointer arguments
    // remain live, aligned, and exclusively borrowed for the complete synchronous call.
    let raw = unsafe {
        dw_syscall6(
            u64::from(number.0),
            arguments[0],
            arguments[1],
            arguments[2],
            arguments[3],
            arguments[4],
            arguments[5],
        )
    };
    DwStatus(raw as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn future_deadline_uses_the_exact_checked_delta() {
        assert_eq!(future_deadline(7), Ok(DwDeadline(50_000_007)));
        assert_eq!(
            future_deadline(u64::MAX - TEST_WAIT_DELTA_NS + 1),
            Err(PrimordialTestError::DeadlineOverflow)
        );
    }

    #[test]
    fn wait_timeout_requires_exact_status_and_generated_record_shape() {
        let result = empty_wait_result();
        assert_eq!(validate_wait_timeout(DW_STATUS_TIMED_OUT, &result), Ok(()));
        assert_eq!(
            validate_wait_timeout(DW_STATUS_SUCCESS, &result),
            Err(PrimordialTestError::WaitOneStatus(DW_STATUS_SUCCESS))
        );
        let mut malformed = result;
        malformed.reserved[0] = 1;
        assert_eq!(
            validate_wait_timeout(DW_STATUS_TIMED_OUT, &malformed),
            Err(PrimordialTestError::InvalidWaitResult)
        );
        assert_eq!(validate_atomic_timeout(DW_STATUS_TIMED_OUT), Ok(()));
        assert_eq!(
            validate_atomic_timeout(DW_STATUS_SUCCESS),
            Err(PrimordialTestError::AtomicWaitStatus(DW_STATUS_SUCCESS))
        );
    }
}
