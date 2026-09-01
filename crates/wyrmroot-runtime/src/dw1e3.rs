//! Selector-31-only DW1-E3 evidence carrier.
//!
//! The public Deepwyrm ABI remains unchanged. This module is compiled only
//! into the selected q35 COM2 product and keeps the private `0xffff_ff1f`
//! operation behind four typed, six-word calls.

use deepwyrm_syscall::{DW_STATUS_SUCCESS, DwHandle, DwStatus, DwSyscallId};

use crate::{NativeError, capability_native::generated_raw_call};

const E3_PRIVATE_SYSCALL: DwSyscallId = DwSyscallId(0xffff_ff1f);

/// Events whose facts are owned by a ring-3 selector actor. Kernel-owned
/// route, delivery, acknowledgement, retirement, accounting, and terminal
/// events deliberately have no variant here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Dw1e3ReportEvent {
    Challenge1UartDrain,
    Challenge1Response,
    Driver1PeerClosed,
    Challenge2UartDrain,
    Challenge2Response,
}

impl Dw1e3ReportEvent {
    const fn wire(self) -> u64 {
        match self {
            Self::Challenge1UartDrain => 0x07,
            Self::Challenge1Response => 0x09,
            Self::Driver1PeerClosed => 0x0a,
            Self::Challenge2UartDrain => 0x15,
            Self::Challenge2Response => 0x17,
        }
    }
}

/// Returns the required nonzero uppercase 16-hex build/run nonce.
pub fn dw1e3_build_nonce() -> Result<u64, NativeError> {
    parse_nonce(env!("DEEPWYRM_DW1E_EVIDENCE_NONCE")).ok_or(NativeError::Output(
        crate::NativeOutputError::InvalidWaitResult,
    ))
}

/// Returns the frozen raw-payload nonce for one selector-31 challenge leg.
/// E3A has no separate payload nonce and therefore retains the evidence nonce
/// for generation one. E3B must provide both distinct payload nonces so the
/// build/evidence correlation never becomes raw-wire payload authority.
pub fn dw1e3_challenge_nonce(generation: u64) -> Result<u64, NativeError> {
    let evidence = dw1e3_build_nonce()?;
    select_challenge_nonce(
        generation,
        evidence,
        option_env!("WYRMROOT_DW1E3_CHALLENGE_1_NONCE"),
        option_env!("WYRMROOT_DW1E3_CHALLENGE_2_NONCE"),
    )
    .ok_or_else(invalid_private)
}

/// Binds the caller's exact Interrupt and attempt generation as the current
/// driver reporter. Object, binding, lease, and reporter Process identities
/// are resolved by the kernel from the real handle and caller. Selector-31
/// reuses this exact action for U2 only after the kernel has finalized U1's
/// binding; callers must never treat it as a rebinding escape hatch.
pub fn dw1e3_bind_driver(
    interrupt: DwHandle,
    attempt_generation: u64,
    nonce: u64,
) -> Result<(), NativeError> {
    private_call(
        bind_driver_arguments(interrupt, attempt_generation, nonce).ok_or_else(invalid_private)?,
    )
}

/// Binds the caller as controller and resolves its exact launched raw-probe
/// reporter from the retained Process handle. The retained U1 probe is bound
/// only long enough to report its ordered peer close. E3B then reuses this
/// action for a separately launched U2 probe; an old reporter is stale.
pub fn dw1e3_bind_probe(probe: DwHandle, nonce: u64) -> Result<(), NativeError> {
    private_call(bind_probe_arguments(probe, nonce).ok_or_else(invalid_private)?)
}

/// Arms one already-attached stream/challenge generation before host input.
pub fn dw1e3_arm_challenge(
    stream_generation: u64,
    challenge_generation: u64,
    expected_length: u64,
    expected_fnv1a64: u64,
    nonce: u64,
) -> Result<(), NativeError> {
    private_call(
        arm_arguments(
            stream_generation,
            challenge_generation,
            expected_length,
            expected_fnv1a64,
            nonce,
        )
        .ok_or_else(invalid_private)?,
    )
}

/// Submits one actor-owned event. The kernel supplies the authenticated actor
/// and complete generation tuple; userspace supplies only the event result.
pub fn dw1e3_report(
    event: Dw1e3ReportEvent,
    value: u64,
    auxiliary: u64,
    nonce: u64,
) -> Result<(), NativeError> {
    private_call(report_arguments(event, value, auxiliary, nonce).ok_or_else(invalid_private)?)
}

/// Makes the controller-only selector terminal claim through the existing
/// action-4 carrier. It is neither a probe report nor a fifth private action;
/// callers must have independently joined U2 response and TEMT facts first.
pub fn dw1e3_terminal_claim(nonce: u64) -> Result<(), NativeError> {
    private_call(terminal_claim_arguments(nonce).ok_or_else(invalid_private)?)
}

const fn bind_driver_arguments(
    interrupt: DwHandle,
    attempt_generation: u64,
    nonce: u64,
) -> Option<[u64; 6]> {
    if interrupt.0 == 0 || attempt_generation == 0 || nonce == 0 {
        None
    } else {
        Some([1, interrupt.0, attempt_generation, nonce, 0, 0])
    }
}

const fn bind_probe_arguments(probe: DwHandle, nonce: u64) -> Option<[u64; 6]> {
    if probe.0 == 0 || nonce == 0 {
        None
    } else {
        Some([2, probe.0, nonce, 0, 0, 0])
    }
}

const fn arm_arguments(
    stream_generation: u64,
    challenge_generation: u64,
    expected_length: u64,
    expected_fnv1a64: u64,
    nonce: u64,
) -> Option<[u64; 6]> {
    if stream_generation == 0
        || challenge_generation == 0
        || expected_length == 0
        || expected_fnv1a64 == 0
        || nonce == 0
    {
        None
    } else {
        Some([
            3,
            stream_generation,
            challenge_generation,
            expected_length,
            expected_fnv1a64,
            nonce,
        ])
    }
}

const fn report_arguments(
    event: Dw1e3ReportEvent,
    value: u64,
    auxiliary: u64,
    nonce: u64,
) -> Option<[u64; 6]> {
    let result_valid = match event {
        Dw1e3ReportEvent::Challenge1UartDrain
        | Dw1e3ReportEvent::Challenge1Response
        | Dw1e3ReportEvent::Challenge2UartDrain
        | Dw1e3ReportEvent::Challenge2Response => value != 0 && auxiliary != 0,
        Dw1e3ReportEvent::Driver1PeerClosed => value != 0 && auxiliary == 0,
    };
    if !result_valid || nonce == 0 {
        None
    } else {
        Some([4, event.wire(), value, auxiliary, nonce, 0])
    }
}

const fn terminal_claim_arguments(nonce: u64) -> Option<[u64; 6]> {
    if nonce == 0 {
        None
    } else {
        Some([4, 0xff, 0, 0, nonce, 0])
    }
}

const fn invalid_private() -> NativeError {
    NativeError::Output(crate::NativeOutputError::InvalidWaitResult)
}

fn private_call(arguments: [u64; 6]) -> Result<(), NativeError> {
    require_success(generated_raw_call(E3_PRIVATE_SYSCALL, arguments))
}

fn require_success(status: DwStatus) -> Result<(), NativeError> {
    if status == DW_STATUS_SUCCESS {
        Ok(())
    } else {
        Err(NativeError::Status(status))
    }
}

fn parse_nonce(text: &str) -> Option<u64> {
    if text.len() != 16 {
        return None;
    }
    let mut value = 0u64;
    for byte in text.bytes() {
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'A'..=b'F' => u64::from(byte - b'A' + 10),
            _ => return None,
        };
        value = value.checked_mul(16)?.checked_add(digit)?;
    }
    (value != 0).then_some(value)
}

fn select_challenge_nonce(
    generation: u64,
    evidence: u64,
    challenge1_text: Option<&str>,
    challenge2_text: Option<&str>,
) -> Option<u64> {
    let challenge1 = match challenge1_text {
        Some(text) => Some(parse_nonce(text)?),
        None => None,
    };
    let challenge2 = match challenge2_text {
        Some(text) => Some(parse_nonce(text)?),
        None => None,
    };
    match (challenge1, challenge2) {
        (None, None) if generation == 1 => Some(evidence),
        (Some(challenge1), Some(challenge2))
            if challenge1 != evidence && challenge2 != evidence && challenge1 != challenge2 =>
        {
            match generation {
                1 => Some(challenge1),
                2 => Some(challenge2),
                _ => None,
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use deepwyrm_syscall::DwHandle;

    use super::{
        Dw1e3ReportEvent, arm_arguments, bind_driver_arguments, bind_probe_arguments, parse_nonce,
        report_arguments, select_challenge_nonce, terminal_claim_arguments,
    };

    #[test]
    fn nonce_is_exact_uppercase_nonzero_hex() {
        assert_eq!(parse_nonce("0123456789ABCDEF"), Some(0x0123_4567_89ab_cdef));
        assert_eq!(parse_nonce("0000000000000000"), None);
        assert_eq!(parse_nonce("0123456789abcdef"), None);
        assert_eq!(parse_nonce("1234"), None);
    }

    #[test]
    fn payload_nonces_are_distinct_from_evidence_and_each_other() {
        let evidence = 0x1111_2222_3333_4444;
        let challenge1 = "5555666677778888";
        let challenge2 = "9999AAAABBBBCCCC";
        assert_eq!(
            select_challenge_nonce(1, evidence, Some(challenge1), Some(challenge2)),
            Some(0x5555_6666_7777_8888)
        );
        assert_eq!(
            select_challenge_nonce(2, evidence, Some(challenge1), Some(challenge2)),
            Some(0x9999_aaaa_bbbb_cccc)
        );
        assert_eq!(select_challenge_nonce(2, evidence, None, None), None);
        assert_eq!(
            select_challenge_nonce(1, evidence, None, None),
            Some(evidence)
        );
        assert_eq!(
            select_challenge_nonce(1, evidence, Some(challenge1), None),
            None
        );
        assert_eq!(
            select_challenge_nonce(1, evidence, Some("not-a-hex-nonce"), Some(challenge2)),
            None
        );
        assert_eq!(
            select_challenge_nonce(1, evidence, Some("1111222233334444"), Some(challenge2)),
            None
        );
    }

    #[test]
    fn selector_private_actions_are_exact_and_reject_zero_required_words() {
        assert_eq!(
            bind_driver_arguments(DwHandle(9), 10, 11),
            Some([1, 9, 10, 11, 0, 0])
        );
        assert_eq!(
            bind_probe_arguments(DwHandle(12), 11),
            Some([2, 12, 11, 0, 0, 0])
        );
        assert_eq!(
            arm_arguments(12, 13, 24, 14, 11),
            Some([3, 12, 13, 24, 14, 11])
        );
        assert_eq!(
            report_arguments(Dw1e3ReportEvent::Challenge1Response, 24, 15, 11),
            Some([4, 9, 24, 15, 11, 0])
        );
        assert_eq!(bind_driver_arguments(DwHandle(0), 10, 11), None);
        assert_eq!(bind_probe_arguments(DwHandle(0), 11), None);
        assert_eq!(bind_probe_arguments(DwHandle(12), 0), None);
        assert_eq!(arm_arguments(12, 0, 24, 14, 11), None);
        assert_eq!(terminal_claim_arguments(11), Some([4, 0xff, 0, 0, 11, 0]));
        assert_eq!(terminal_claim_arguments(0), None);
        assert_eq!(
            report_arguments(Dw1e3ReportEvent::Challenge1UartDrain, 24, 0, 11),
            None
        );
    }
}
