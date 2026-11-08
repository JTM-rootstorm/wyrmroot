use super::*;
use wyrmroot_r1_saturation::record::{encode_failure, encode_step, encode_terminal};
use wyrmroot_r1_saturation::{ProbeFailure, ProbeOutcome, ProbeStep};

const NONCE: u64 = 0x8100_0000_0000_0001;

fn step(sequence: u64, plan: ProbePlan) -> [u8; RECORD_BYTES] {
    encode_step(sequence, NONCE, plan, ProbeStep::LaunchHog { index: 0 }, 9)
}

#[test]
fn a_normal_transcript_relays_in_order_and_ends_once() {
    let plan = ProbePlan::SMP;
    let mut relay = R1Relay::new(plan);
    assert!(!relay.complete());
    for sequence in 1..=5 {
        assert_eq!(
            relay.accept(&step(sequence, plan), 0),
            Ok(RelayAction::Submit)
        );
    }
    assert_eq!(relay.submitted(), 5);
    let terminal = encode_terminal(6, NONCE, plan, ProbeOutcome::Passed, 36);
    assert_eq!(relay.accept(&terminal, 0), Ok(RelayAction::SubmitTerminal));
    assert!(relay.terminal_seen());
    assert!(relay.complete());
    assert_eq!(relay.submitted(), 6);
    // Nothing may follow the terminal record: the kernel has already flushed.
    assert_eq!(
        relay.accept(&step(7, plan), 0),
        Err(RelayError::AfterTerminal)
    );
    assert_eq!(relay.submitted(), 6);
}

#[test]
fn a_failing_transcript_still_reaches_its_terminal_record() {
    // The card requires a failing run to report a classification rather than
    // simply stopping, so the relay must carry the failure *and* the terminal.
    let plan = ProbePlan::SMP;
    let mut relay = R1Relay::new(plan);
    assert_eq!(relay.accept(&step(1, plan), 0), Ok(RelayAction::Submit));
    let failure = encode_failure(2, NONCE, plan, ProbeFailure::HogAcceptTimeout { index: 0 });
    assert_eq!(relay.accept(&failure, 0), Ok(RelayAction::Submit));
    let terminal = encode_terminal(
        3,
        NONCE,
        plan,
        ProbeOutcome::Failed(ProbeFailure::HogAcceptTimeout { index: 0 }),
        2,
    );
    assert_eq!(relay.accept(&terminal, 0), Ok(RelayAction::SubmitTerminal));
    assert!(relay.complete());
}

#[test]
fn a_report_describing_another_topology_is_refused() {
    // This is the check only init can make: the kernel knows the build nonce,
    // init knows which plan it launched. A control-plan record arriving from an
    // SMP probe would otherwise be relayed and read as an SMP result.
    let mut relay = R1Relay::new(ProbePlan::SMP);
    let foreign = step(1, ProbePlan::CONTROL);
    assert_eq!(
        relay.accept(&foreign, 0),
        Err(RelayError::WrongTopology {
            online_cpus: 1,
            hog_count: 3,
        })
    );
    assert_eq!(relay.submitted(), 0);
    // The refusal did not consume the sequence, so the real record still fits.
    assert_eq!(
        relay.accept(&step(1, ProbePlan::SMP), 0),
        Ok(RelayAction::Submit)
    );
}

#[test]
fn sequence_gaps_and_replays_are_refused_without_advancing() {
    let plan = ProbePlan::SMP;
    let mut relay = R1Relay::new(plan);
    assert_eq!(
        relay.accept(&step(2, plan), 0),
        Err(RelayError::OutOfOrder {
            expected: 1,
            observed: 2,
        })
    );
    assert_eq!(relay.accept(&step(1, plan), 0), Ok(RelayAction::Submit));
    // A replay of an already-relayed record must not be submitted twice.
    assert_eq!(
        relay.accept(&step(1, plan), 0),
        Err(RelayError::OutOfOrder {
            expected: 2,
            observed: 1,
        })
    );
    assert_eq!(relay.submitted(), 1);
}

#[test]
fn a_record_carrying_handles_is_refused_before_anything_is_read() {
    let plan = ProbePlan::SMP;
    let mut relay = R1Relay::new(plan);
    assert_eq!(
        relay.accept(&step(1, plan), 1),
        Err(RelayError::UnexpectedHandles)
    );
    assert_eq!(relay.submitted(), 0);
    // Even a malformed frame is rejected for its handles first: the supervisor
    // must not begin parsing a datagram that is already inadmissible.
    assert_eq!(relay.accept(&[], 1), Err(RelayError::UnexpectedHandles));
}

#[test]
fn malformed_frames_are_refused_with_the_wire_formats_own_reason() {
    let plan = ProbePlan::SMP;
    let mut relay = R1Relay::new(plan);
    assert_eq!(
        relay.accept(&[0_u8; 32], 0),
        Err(RelayError::Malformed(
            wyrmroot_r1_saturation::record::HeaderError::WrongLength
        ))
    );
    let mut magic = step(1, plan);
    magic[0] = b'X';
    assert_eq!(
        relay.accept(&magic, 0),
        Err(RelayError::Malformed(
            wyrmroot_r1_saturation::record::HeaderError::WrongMagic
        ))
    );
    assert_eq!(relay.submitted(), 0);
}

#[test]
fn the_relay_stops_at_the_collectors_own_capacity() {
    let plan = ProbePlan::SMP;
    let mut relay = R1Relay::new(plan);
    for sequence in 1..=RELAY_CAPACITY as u64 {
        assert_eq!(
            relay.accept(&step(sequence, plan), 0),
            Ok(RelayAction::Submit),
            "record {sequence} must fit"
        );
    }
    assert_eq!(relay.submitted(), RELAY_CAPACITY);
    assert_eq!(
        relay.accept(&step(RELAY_CAPACITY as u64 + 1, plan), 0),
        Err(RelayError::Full)
    );
    // A refused record at the bound leaves the relay unchanged rather than
    // half-recorded, so the failure is reportable.
    assert_eq!(relay.submitted(), RELAY_CAPACITY);
    assert!(!relay.terminal_seen());
}

#[test]
fn an_unterminated_transcript_never_reads_as_complete() {
    let plan = ProbePlan::CONTROL;
    let mut relay = R1Relay::new(plan);
    assert_eq!(relay.accept(&step(1, plan), 0), Ok(RelayAction::Submit));
    assert!(!relay.complete());
    assert!(!relay.terminal_seen());
}
