//! Falsification tests for the R6A launch-transaction arena.
//!
//! Every invariant the module claims has a test that fails if the invariant is
//! removed, not merely a test that exercises the happy path.

use super::*;
use crate::wyr1b::{EndpointKind, RegistryTopology};
use crate::wyr1b_job::LaunchSessionScope;

fn grant(role_generation: u64) -> EndpointGrant {
    RegistryTopology::new(7)
        .expect("nonzero registry generation")
        .issue(role_generation, EndpointKind::LaunchSession)
        .expect("nonzero role generation")
}

/// Two grants that differ, built from one topology so the endpoint IDs are the
/// real issued sequence rather than hand-written numbers.
fn two_grants() -> (EndpointGrant, EndpointGrant) {
    let mut topology = RegistryTopology::new(7).expect("nonzero registry generation");
    let first = topology
        .issue(1, EndpointKind::LaunchSession)
        .expect("first session");
    let second = topology
        .issue(1, EndpointKind::LaunchSession)
        .expect("second session");
    assert_ne!(first, second);
    (first, second)
}

fn reservation(transaction_id: u64) -> Reservation {
    Reservation {
        connection_id: 11,
        generation: 3,
        transaction_id,
    }
}

fn resources() -> LaunchResources {
    LaunchResources {
        process: DwHandle(0x21),
        launch_channel: DwHandle(0x22),
        task_group: DwHandle(0x23),
    }
}

/// Walks the whole accepted path and closes, so the failure tests below are
/// known to differ from a working transaction in exactly one step.
fn drive_to_published(
    arena: &mut LaunchTransactions,
    token: LaunchToken,
) -> Result<(), LaunchTransactionError> {
    arena.attach_job(token, 5)?;
    arena.advance(token, LaunchStage::Constructed)?;
    arena.attach_resources(token, LaunchProfile::ProbeChild, resources())?;
    arena.arm_ready_deadline(token, DwDeadline(9_000))?;
    arena.advance(token, LaunchStage::AwaitingReady)?;
    arena.advance(token, LaunchStage::Published)?;
    Ok(())
}

#[test]
fn an_accepted_launch_runs_reserved_to_complete_and_frees_its_slot() {
    let mut arena = LaunchTransactions::new();
    let token = arena
        .open(
            grant(1),
            DwHandle(0x10),
            LaunchSessionScope::Historical,
            reservation(0x99),
        )
        .expect("first transaction");
    assert_eq!(arena.stage(token), Ok(LaunchStage::Reserved));
    assert_eq!(arena.open_count(), 1);
    drive_to_published(&mut arena, token).expect("accepted path");
    assert_eq!(arena.profile(token), Ok(Some(LaunchProfile::ProbeChild)));
    assert_eq!(arena.ready_deadline(token), Ok(Some(DwDeadline(9_000))));
    arena.advance(token, LaunchStage::Cleanup).expect("cleanup");
    assert_eq!(arena.take_resources(token), Ok(Some(resources())));
    arena
        .advance(token, LaunchStage::Complete)
        .expect("complete");
    assert_eq!(arena.close(token), Ok(5));
    assert_eq!(arena.open_count(), 0);
    assert_eq!(arena.stage(token), Err(LaunchTransactionError::Stale));
}

/// The invariant worth the most: the three handles cannot be dropped by
/// freeing the slot that names them.
#[test]
fn a_slot_holding_the_childs_handles_refuses_to_close() {
    let mut arena = LaunchTransactions::new();
    let token = arena
        .open(
            grant(1),
            DwHandle(0x10),
            LaunchSessionScope::Historical,
            reservation(0x99),
        )
        .expect("transaction");
    drive_to_published(&mut arena, token).expect("accepted path");
    arena.advance(token, LaunchStage::Cleanup).expect("cleanup");
    arena
        .advance(token, LaunchStage::Complete)
        .expect("complete");
    assert_eq!(
        arena.close(token),
        Err(LaunchTransactionError::ResourcesHeld)
    );
    // And the same slot closes once the handles have a new owner.
    assert_eq!(arena.take_resources(token), Ok(Some(resources())));
    assert_eq!(arena.close(token), Ok(5));
}

#[test]
fn a_transaction_that_has_not_completed_refuses_to_close() {
    let mut arena = LaunchTransactions::new();
    let token = arena
        .open(
            grant(1),
            DwHandle(0x10),
            LaunchSessionScope::Historical,
            reservation(0x99),
        )
        .expect("transaction");
    assert_eq!(arena.close(token), Err(LaunchTransactionError::Incomplete));
    arena.advance(token, LaunchStage::Failing).expect("failing");
    assert_eq!(arena.close(token), Err(LaunchTransactionError::Incomplete));
    arena.advance(token, LaunchStage::Cleanup).expect("cleanup");
    assert_eq!(arena.close(token), Err(LaunchTransactionError::Incomplete));
}

/// §9.5 makes the READY observation the precondition for `LAUNCH_ACCEPTED`.
/// A counter-shaped stage would let a construction skip straight past it.
#[test]
fn construction_cannot_skip_the_ready_observation() {
    let mut arena = LaunchTransactions::new();
    let token = arena
        .open(
            grant(1),
            DwHandle(0x10),
            LaunchSessionScope::Historical,
            reservation(0x99),
        )
        .expect("transaction");
    arena
        .advance(token, LaunchStage::Constructed)
        .expect("constructed");
    assert_eq!(
        arena.advance(token, LaunchStage::Published),
        Err(LaunchTransactionError::StageTransition)
    );
    assert_eq!(arena.stage(token), Ok(LaunchStage::Constructed));
}

#[test]
fn a_stage_cannot_go_backwards_or_leave_a_terminal_stage() {
    let mut arena = LaunchTransactions::new();
    let token = arena
        .open(
            grant(1),
            DwHandle(0x10),
            LaunchSessionScope::Historical,
            reservation(0x99),
        )
        .expect("transaction");
    arena
        .advance(token, LaunchStage::Constructed)
        .expect("constructed");
    assert_eq!(
        arena.advance(token, LaunchStage::Reserved),
        Err(LaunchTransactionError::StageTransition)
    );
    arena.advance(token, LaunchStage::Failing).expect("failing");
    arena.advance(token, LaunchStage::Cleanup).expect("cleanup");
    arena
        .advance(token, LaunchStage::Complete)
        .expect("complete");
    assert_eq!(
        arena.advance(token, LaunchStage::Cleanup),
        Err(LaunchTransactionError::StageTransition)
    );
}

/// Every edge §7 draws, and nothing else.
#[test]
fn the_stage_graph_is_exactly_the_plans_diagram() {
    use LaunchStage::*;
    const EDGES: [(LaunchStage, LaunchStage); 9] = [
        (Reserved, Constructed),
        (Reserved, Failing),
        (Constructed, AwaitingReady),
        (Constructed, Failing),
        (AwaitingReady, Published),
        (AwaitingReady, Failing),
        (Published, Cleanup),
        (Failing, Cleanup),
        (Cleanup, Complete),
    ];
    const STAGES: [LaunchStage; 7] = [
        Reserved,
        Constructed,
        AwaitingReady,
        Published,
        Failing,
        Cleanup,
        Complete,
    ];
    for from in STAGES {
        for to in STAGES {
            let drawn = EDGES.contains(&(from, to));
            assert_eq!(
                from.may_advance_to(to),
                drawn,
                "edge {from:?} -> {to:?} disagrees with the plan diagram"
            );
        }
    }
}

/// The sizing claim, enforced rather than assumed.
#[test]
fn one_session_cannot_hold_two_launches_in_flight() {
    let (first, second) = two_grants();
    let mut arena = LaunchTransactions::new();
    let token = arena
        .open(
            first,
            DwHandle(0x10),
            LaunchSessionScope::Historical,
            reservation(0x99),
        )
        .expect("first transaction");
    assert_eq!(
        arena.open(
            first,
            DwHandle(0x10),
            LaunchSessionScope::Historical,
            reservation(0x9a)
        ),
        Err(LaunchTransactionError::SessionBusy)
    );
    // A different session is admitted, and the busy one is admitted again once
    // its transaction closes.
    arena
        .open(
            second,
            DwHandle(0x11),
            LaunchSessionScope::Historical,
            reservation(0x9b),
        )
        .expect("second session");
    arena.advance(token, LaunchStage::Failing).expect("failing");
    arena.advance(token, LaunchStage::Cleanup).expect("cleanup");
    arena
        .advance(token, LaunchStage::Complete)
        .expect("complete");
    arena.close(token).expect("close");
    arena
        .open(
            first,
            DwHandle(0x10),
            LaunchSessionScope::Historical,
            reservation(0x9c),
        )
        .expect("first session again");
}

#[test]
fn the_arena_refuses_a_transaction_beyond_its_bound() {
    let mut topology = RegistryTopology::new(7).expect("registry generation");
    let mut arena = LaunchTransactions::new();
    for index in 0..LAUNCH_TRANSACTION_SLOTS {
        let grant = topology
            .issue(1, EndpointKind::LaunchSession)
            .expect("session grant");
        arena
            .open(
                grant,
                DwHandle(0x10 + index as u64),
                LaunchSessionScope::Historical,
                reservation(0x99),
            )
            .expect("slot within the bound");
    }
    assert_eq!(arena.open_count(), LAUNCH_TRANSACTION_SLOTS);
    let overflow = topology
        .issue(1, EndpointKind::LaunchSession)
        .expect("session grant");
    assert_eq!(
        arena.open(
            overflow,
            DwHandle(0xff),
            LaunchSessionScope::Historical,
            reservation(0x99)
        ),
        Err(LaunchTransactionError::Capacity)
    );
}

/// A reply written long after its request can only satisfy §9's echo rule if
/// the envelope survived the wait.
#[test]
fn the_response_envelope_survives_the_whole_transaction() {
    let mut arena = LaunchTransactions::new();
    let session = DwHandle(0x10);
    let request = reservation(0x4321);
    let token = arena
        .open(grant(1), session, LaunchSessionScope::Historical, request)
        .expect("transaction");
    drive_to_published(&mut arena, token).expect("accepted path");
    assert_eq!(arena.response_envelope(token), Ok((session, request)));
    arena.advance(token, LaunchStage::Cleanup).expect("cleanup");
    arena.take_resources(token).expect("take");
    arena
        .advance(token, LaunchStage::Complete)
        .expect("complete");
    assert_eq!(arena.response_envelope(token), Ok((session, request)));
}

#[test]
fn the_first_failure_fixes_the_reported_code() {
    let mut arena = LaunchTransactions::new();
    let token = arena
        .open(
            grant(1),
            DwHandle(0x10),
            LaunchSessionScope::Historical,
            reservation(0x99),
        )
        .expect("transaction");
    let loader = LaunchFailure {
        code: 8,
        cleanup_failed: false,
    };
    assert_eq!(arena.fail(token, loader), Ok(loader));
    // A later cleanup failure records itself without relabelling the reply.
    let cleanup = LaunchFailure {
        code: 9,
        cleanup_failed: true,
    };
    assert_eq!(
        arena.fail(token, cleanup),
        Ok(LaunchFailure {
            code: 8,
            cleanup_failed: true
        })
    );
    assert_eq!(
        arena.failure(token),
        Ok(Some(LaunchFailure {
            code: 8,
            cleanup_failed: true
        }))
    );
}

#[test]
fn a_disposition_outside_the_contracts_error_codes_is_refused() {
    let mut arena = LaunchTransactions::new();
    let token = arena
        .open(
            grant(1),
            DwHandle(0x10),
            LaunchSessionScope::Historical,
            reservation(0x99),
        )
        .expect("transaction");
    for code in [0, 11, u32::MAX] {
        assert_eq!(
            arena.fail(
                token,
                LaunchFailure {
                    code,
                    cleanup_failed: false
                }
            ),
            Err(LaunchTransactionError::ErrorCode)
        );
    }
    assert_eq!(arena.failure(token), Ok(None));
}

#[test]
fn attaching_resources_twice_is_refused_rather_than_overwriting() {
    let mut arena = LaunchTransactions::new();
    let token = arena
        .open(
            grant(1),
            DwHandle(0x10),
            LaunchSessionScope::Historical,
            reservation(0x99),
        )
        .expect("transaction");
    arena
        .attach_resources(token, LaunchProfile::ProbeChild, resources())
        .expect("first attach");
    let second = LaunchResources {
        process: DwHandle(0x31),
        launch_channel: DwHandle(0x32),
        task_group: DwHandle(0x33),
    };
    assert_eq!(
        arena.attach_resources(token, LaunchProfile::ProbeChild, second),
        Err(LaunchTransactionError::ResourceIdentity)
    );
    assert_eq!(arena.resources(token), Ok(Some(resources())));
}

#[test]
fn zero_identities_are_refused_everywhere_they_can_appear() {
    let mut arena = LaunchTransactions::new();
    assert_eq!(
        arena.open(
            grant(1),
            DwHandle(0),
            LaunchSessionScope::Historical,
            reservation(0x99)
        ),
        Err(LaunchTransactionError::ResourceIdentity)
    );
    for zeroed in [
        Reservation {
            connection_id: 0,
            generation: 3,
            transaction_id: 1,
        },
        Reservation {
            connection_id: 11,
            generation: 0,
            transaction_id: 1,
        },
        Reservation {
            connection_id: 11,
            generation: 3,
            transaction_id: 0,
        },
    ] {
        assert_eq!(
            arena.open(
                grant(1),
                DwHandle(0x10),
                LaunchSessionScope::Historical,
                zeroed
            ),
            Err(LaunchTransactionError::ResourceIdentity)
        );
    }
    let token = arena
        .open(
            grant(1),
            DwHandle(0x10),
            LaunchSessionScope::Historical,
            reservation(0x99),
        )
        .expect("transaction");
    assert_eq!(
        arena.attach_job(token, 0),
        Err(LaunchTransactionError::ResourceIdentity)
    );
    for zeroed in [
        LaunchResources {
            process: DwHandle(0),
            launch_channel: DwHandle(0x22),
            task_group: DwHandle(0x23),
        },
        LaunchResources {
            process: DwHandle(0x21),
            launch_channel: DwHandle(0),
            task_group: DwHandle(0x23),
        },
        LaunchResources {
            process: DwHandle(0x21),
            launch_channel: DwHandle(0x22),
            task_group: DwHandle(0),
        },
    ] {
        assert_eq!(
            arena.attach_resources(token, LaunchProfile::ProbeChild, zeroed),
            Err(LaunchTransactionError::ResourceIdentity)
        );
    }
}

/// A freed slot is reused, so a token kept across the free must not address
/// whatever moved in.
#[test]
fn a_token_kept_across_a_close_cannot_address_the_reused_slot() {
    let (first, second) = two_grants();
    let mut arena = LaunchTransactions::new();
    let stale = arena
        .open(
            first,
            DwHandle(0x10),
            LaunchSessionScope::Historical,
            reservation(0x99),
        )
        .expect("first transaction");
    arena.advance(stale, LaunchStage::Failing).expect("failing");
    arena.advance(stale, LaunchStage::Cleanup).expect("cleanup");
    arena
        .advance(stale, LaunchStage::Complete)
        .expect("complete");
    arena.close(stale).expect("close");
    let fresh = arena
        .open(
            second,
            DwHandle(0x11),
            LaunchSessionScope::Historical,
            reservation(0x9a),
        )
        .expect("second transaction");
    assert_eq!(fresh.slot(), stale.slot());
    assert_ne!(fresh.generation(), stale.generation());
    assert_eq!(arena.stage(stale), Err(LaunchTransactionError::Stale));
    assert_eq!(
        arena.advance(stale, LaunchStage::Constructed),
        Err(LaunchTransactionError::Stale)
    );
    assert_eq!(arena.stage(fresh), Ok(LaunchStage::Reserved));
}

/// A generation that wrapped could not be told from a stale token, so the slot
/// retires instead of being reused.
#[test]
fn an_exhausted_slot_retires_rather_than_reusing_its_generation() {
    let (first, second) = two_grants();
    let mut arena = LaunchTransactions::new();
    arena.generations[0] = u64::MAX - 1;
    let token = arena
        .open(
            first,
            DwHandle(0x10),
            LaunchSessionScope::Historical,
            reservation(0x99),
        )
        .expect("last generation");
    assert_eq!(token.generation(), u64::MAX);
    arena.advance(token, LaunchStage::Failing).expect("failing");
    arena.advance(token, LaunchStage::Cleanup).expect("cleanup");
    arena
        .advance(token, LaunchStage::Complete)
        .expect("complete");
    arena.close(token).expect("close");
    assert!(arena.retired[0]);
    let fresh = arena
        .open(
            second,
            DwHandle(0x11),
            LaunchSessionScope::Historical,
            reservation(0x9a),
        )
        .expect("a different slot");
    assert_ne!(fresh.slot(), 0);
}

#[test]
fn a_session_and_a_job_each_find_their_own_open_transaction() {
    let (first, second) = two_grants();
    let mut arena = LaunchTransactions::new();
    let left = arena
        .open(
            first,
            DwHandle(0x10),
            LaunchSessionScope::Historical,
            reservation(0x99),
        )
        .expect("first transaction");
    let right = arena
        .open(
            second,
            DwHandle(0x11),
            LaunchSessionScope::Historical,
            reservation(0x9a),
        )
        .expect("second transaction");
    arena.attach_job(left, 5).expect("left job");
    arena.attach_job(right, 6).expect("right job");
    assert_eq!(arena.session_transaction(first), Some(left));
    assert_eq!(arena.session_transaction(second), Some(right));
    assert_eq!(arena.job_transaction(5), Some(left));
    assert_eq!(arena.job_transaction(6), Some(right));
    assert_eq!(arena.job_transaction(0), None);
    assert_eq!(arena.job_transaction(7), None);
    arena.advance(left, LaunchStage::Failing).expect("failing");
    arena.advance(left, LaunchStage::Cleanup).expect("cleanup");
    arena
        .advance(left, LaunchStage::Complete)
        .expect("complete");
    arena.close(left).expect("close");
    assert_eq!(arena.session_transaction(first), None);
    assert_eq!(arena.job_transaction(5), None);
    assert_eq!(arena.job_transaction(6), Some(right));
}

/// The arena's cost, named where it is paid.
///
/// R6A asserted this against a single constant, `LAUNCH_ARENA_BUDGET_BYTES`,
/// because the arena was not yet a field of anything and arithmetic was the
/// only check available. R6B-2 wires it into `JobDispatcher`, so
/// `resident_fits_locked_native_stack_partition` now measures the real total
/// and is the gate that binds.
///
/// The constant could not survive that wiring anyway: it is the *default*
/// tier's headroom, and the resident gate it was derived from selects three
/// budgets, not one -- 40 KiB under `wyr1d-selector32` or `wyr1e-production`,
/// 22 KiB under `wyr1c6-selector29`, 20 KiB otherwise. Charging every build
/// against the smallest is the same wrong-tier arithmetic reset plan §7.1 and
/// §7.2 were corrected for at R6E. So this checks what is true in every tier:
/// the arena's ungated part fits the tightest headroom, and whatever the
/// evidence features add on top is gated out of that tier entirely.
#[test]
fn the_arenas_ungated_cost_fits_the_tightest_resident_tier() {
    use core::mem::size_of;
    let ungated = cfg!(not(any(
        feature = "wyr1e-selector33",
        feature = "wyr1e8-selector33"
    )));
    if ungated {
        assert!(
            size_of::<LaunchTransactions>() <= LAUNCH_ARENA_BUDGET_BYTES,
            "arena is {} bytes against {LAUNCH_ARENA_BUDGET_BYTES} of default-tier headroom",
            size_of::<LaunchTransactions>()
        );
    }
}
