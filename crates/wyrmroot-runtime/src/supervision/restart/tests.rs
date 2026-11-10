use super::*;

fn supervisor() -> RestartSupervisor {
    RestartSupervisor::new(WYR0_I_SUPERVISION_POLICY).unwrap()
}

fn begin_started(supervisor: &mut RestartSupervisor, now_ns: u64) {
    supervisor.begin(now_ns, 1, 11).unwrap();
    supervisor.child_started(1, 11, now_ns).unwrap();
}

fn fail_and_restart(
    supervisor: &mut RestartSupervisor,
    generation: u64,
    transaction: u64,
    now_ns: u64,
) -> u64 {
    supervisor
        .fail_attempt(
            generation,
            transaction,
            now_ns,
            AttemptFailure::MalformedReady,
        )
        .unwrap();
    supervisor
        .cleanup_complete(generation, transaction, now_ns + 1)
        .unwrap();
    let RestartState::Backoff { deadline_ns, .. } = supervisor.state() else {
        panic!("replacement backoff was not entered");
    };
    let next_transaction = transaction + 1;
    supervisor
        .start_replacement(deadline_ns, generation + 1, next_transaction)
        .unwrap();
    supervisor
        .child_started(generation + 1, next_transaction, deadline_ns)
        .unwrap();
    deadline_ns
}

#[test]
fn ready_before_deadline_is_generation_and_transaction_exact() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 100);
    supervisor.ready(1, 11, 1_000_000_099).unwrap();
    assert!(matches!(
        supervisor.state(),
        RestartState::Ready { generation: 1, .. }
    ));
}

#[test]
fn ordinary_failure_of_aged_ready_role_keeps_boot_anchored_window() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 0);
    supervisor.ready(1, 11, 1).unwrap();
    supervisor
        .fail_attempt(1, 11, 3_000_000_000, AttemptFailure::WaitFailed)
        .unwrap();
    supervisor.cleanup_complete(1, 11, 3_000_000_001).unwrap();
    assert_eq!(
        supervisor.state(),
        RestartState::PermanentFailure {
            final_failure: AttemptFailure::WaitFailed,
            cleanup: CleanupDisposition::Complete,
        }
    );
    assert_eq!(supervisor.history().len(), 1);
    assert_eq!(supervisor.episode_started_at_ns, 0);
}

#[test]
fn admitted_recovery_retires_original_owner_as_first_bounded_attempt() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 0);
    let owner_started_at = fail_and_restart(&mut supervisor, 1, 11, 1);
    supervisor.ready(2, 12, owner_started_at + 1).unwrap();
    assert_eq!(supervisor.history().len(), 1);

    supervisor
        .admit_recovery(2, 12, 3_000_000_000, AttemptFailure::WaitFailed)
        .unwrap();
    assert_eq!(supervisor.policy, WYR0_I_SUPERVISION_POLICY);
    assert_eq!(supervisor.history().len(), 0);
    assert_eq!(supervisor.episode_started_at_ns, 3_000_000_000);
    assert_eq!(supervisor.last_generation, 2);
    assert_eq!(
        supervisor.state(),
        RestartState::CleaningUp {
            attempt: 1,
            generation: 2,
            transaction_id: 12,
            failure: AttemptFailure::WaitFailed,
            action: CleanupAction::TerminateTaskGroup,
            classified_at_ns: 3_000_000_000,
            deadline_ns: 4_000_000_000,
            retry: true,
        }
    );
    supervisor.cleanup_complete(2, 12, 3_000_000_001).unwrap();
    assert_eq!(
        supervisor.history().as_slice(),
        &[Some(AttemptRecord {
            attempt: 1,
            generation: 2,
            transaction_id: 12,
            started_at_ns: owner_started_at,
            terminal_at_ns: 3_000_000_000,
            failure: AttemptFailure::WaitFailed,
            cleanup: CleanupDisposition::Complete,
        })]
    );
    assert_eq!(
        supervisor.state(),
        RestartState::Backoff {
            next_attempt: 2,
            next_generation: 3,
            deadline_ns: 3_025_000_001,
        }
    );
    for generation in 3..=5 {
        let RestartState::Backoff { deadline_ns, .. } = supervisor.state() else {
            panic!("replacement not bounded by backoff");
        };
        supervisor
            .start_replacement(deadline_ns, generation, generation + 10)
            .unwrap();
        supervisor
            .fail_attempt(
                generation,
                generation + 10,
                deadline_ns,
                AttemptFailure::StartFailed,
            )
            .unwrap();
        supervisor
            .cleanup_complete(generation, generation + 10, deadline_ns + 1)
            .unwrap();
    }
    assert_eq!(supervisor.history().len(), 4);
    assert_eq!(
        supervisor.state(),
        RestartState::PermanentFailure {
            final_failure: AttemptFailure::StartFailed,
            cleanup: CleanupDisposition::Complete,
        }
    );
}

#[test]
fn recovery_admission_rejections_preserve_every_field() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 0);
    let started_at = fail_and_restart(&mut supervisor, 1, 11, 1);
    supervisor.ready(2, 12, started_at + 1).unwrap();
    for (generation, transaction, now, failure, error) in [
        (
            0,
            12,
            3_000_000_000,
            AttemptFailure::WaitFailed,
            RestartTransitionError::ZeroIdentity,
        ),
        (
            2,
            0,
            3_000_000_000,
            AttemptFailure::WaitFailed,
            RestartTransitionError::ZeroIdentity,
        ),
        (
            1,
            12,
            3_000_000_000,
            AttemptFailure::WaitFailed,
            RestartTransitionError::StaleGeneration,
        ),
        (
            2,
            11,
            3_000_000_000,
            AttemptFailure::WaitFailed,
            RestartTransitionError::TransactionMismatch,
        ),
        (
            2,
            12,
            started_at,
            AttemptFailure::WaitFailed,
            RestartTransitionError::TimeRegression,
        ),
        (
            2,
            12,
            3_000_000_000,
            AttemptFailure::CreationFailed,
            RestartTransitionError::InvalidState,
        ),
        (
            2,
            12,
            u64::MAX - 1_000_000_000,
            AttemptFailure::WaitFailed,
            RestartTransitionError::ArithmeticOverflow,
        ),
    ] {
        let before = supervisor;
        assert_eq!(
            supervisor.admit_recovery(generation, transaction, now, failure),
            Err(error)
        );
        assert_eq!(supervisor, before);
    }
    // Exercise overflow after the candidate's time/history changes, not
    // only overflow rejected before the candidate is constructed.
    supervisor.policy.restart_window_ns = 1;
    let before = supervisor;
    assert_eq!(
        supervisor.admit_recovery(2, 12, u64::MAX - 1, AttemptFailure::WaitFailed),
        Err(RestartTransitionError::ArithmeticOverflow)
    );
    assert_eq!(supervisor, before);
}

#[test]
fn recovery_admission_rejects_non_ready_states_and_duplicate() {
    fn reject(supervisor: &mut RestartSupervisor, now: u64) {
        let before = *supervisor;
        assert_eq!(
            supervisor.admit_recovery(1, 11, now, AttemptFailure::WaitFailed),
            Err(RestartTransitionError::InvalidState)
        );
        assert_eq!(*supervisor, before);
    }
    let mut supervisor = supervisor();
    reject(&mut supervisor, 0);
    supervisor.begin(0, 1, 11).unwrap();
    reject(&mut supervisor, 0);
    supervisor.child_started(1, 11, 1).unwrap();
    reject(&mut supervisor, 1);
    supervisor.ready(1, 11, 2).unwrap();
    supervisor
        .admit_recovery(1, 11, 3_000_000_000, AttemptFailure::WaitFailed)
        .unwrap();
    reject(&mut supervisor, 3_000_000_001);
    let mut failed = supervisor;
    failed.cleanup_failed(1, 11, 3_000_000_001).unwrap();
    reject(&mut failed, 3_000_000_002);
    supervisor.cleanup_complete(1, 11, 3_000_000_001).unwrap();
    reject(&mut supervisor, 3_000_000_002);
}

#[test]
fn admitted_recovery_preserves_absolute_window_and_cleanup_edges() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 0);
    supervisor.ready(1, 11, 1).unwrap();
    supervisor
        .admit_recovery(1, 11, 3_000_000_000, AttemptFailure::WaitFailed)
        .unwrap();
    let mut late_cleanup = supervisor;
    late_cleanup.cleanup_complete(1, 11, 4_000_000_000).unwrap();
    assert_eq!(
        late_cleanup.state(),
        RestartState::PermanentFailure {
            final_failure: AttemptFailure::WaitFailed,
            cleanup: CleanupDisposition::Failed,
        }
    );
    supervisor.cleanup_complete(1, 11, 3_000_000_001).unwrap();
    let mut late_start = supervisor;
    late_start.start_replacement(5_000_000_001, 2, 12).unwrap();
    assert_eq!(
        late_start.state(),
        RestartState::PermanentFailure {
            final_failure: AttemptFailure::WaitFailed,
            cleanup: CleanupDisposition::Complete,
        }
    );
    supervisor.start_replacement(5_000_000_000, 2, 12).unwrap();
    assert!(matches!(
        supervisor.state(),
        RestartState::Starting {
            attempt: 2,
            deadline_ns: 6_000_000_000,
            ..
        }
    ));
}

#[test]
fn ready_deadline_is_bound_to_attempt_start_not_child_start() {
    let mut before = supervisor();
    before.begin(100, 1, 11).unwrap();
    let RestartState::Starting { deadline_ns, .. } = before.state() else {
        panic!("attempt did not enter Starting");
    };
    assert_eq!(deadline_ns, 1_000_000_100);
    before.child_started(1, 11, deadline_ns - 1).unwrap();
    assert!(matches!(
        before.state(),
        RestartState::AwaitingReady {
            deadline_ns: 1_000_000_100,
            ..
        }
    ));

    let mut at_deadline = supervisor();
    at_deadline.begin(100, 1, 11).unwrap();
    assert_eq!(
        at_deadline.child_started(1, 11, 1_000_000_100),
        Err(RestartTransitionError::AttemptFailed(
            AttemptFailure::ReadyTimeout
        ))
    );
    assert!(matches!(
        at_deadline.state(),
        RestartState::CleaningUp {
            failure: AttemptFailure::ReadyTimeout,
            action: CleanupAction::TerminateTaskGroup,
            ..
        }
    ));
}

#[test]
fn starting_deadline_expiry_closes_unpublished_state() {
    let mut supervisor = supervisor();
    supervisor.begin(50, 1, 11).unwrap();
    assert_eq!(
        supervisor.deadline_elapsed(1, 11, 1_000_000_050, 1_000_000_049),
        Err(RestartTransitionError::DeadlineNotReached)
    );
    supervisor
        .deadline_elapsed(1, 11, 1_000_000_050, 1_000_000_050)
        .unwrap();
    assert!(matches!(
        supervisor.state(),
        RestartState::CleaningUp {
            failure: AttemptFailure::ReadyTimeout,
            action: CleanupAction::CloseUnpublished,
            ..
        }
    ));
}

#[test]
fn child_exit_before_ready_is_classified_and_requires_terminal_cleanup() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 0);
    supervisor
        .terminal(1, 11, 7, TerminalDisposition::NormalExit(0))
        .unwrap();
    assert!(matches!(
        supervisor.state(),
        RestartState::CleaningUp {
            failure: AttemptFailure::ExitBeforeReady(TerminalDisposition::NormalExit(0)),
            action: CleanupAction::CloseTerminal,
            ..
        }
    ));
}

#[test]
fn malformed_and_wrong_transaction_ready_are_distinct() {
    let mut malformed = supervisor();
    begin_started(&mut malformed, 0);
    malformed
        .fail_attempt(1, 11, 1, AttemptFailure::MalformedReady)
        .unwrap();
    assert!(matches!(
        malformed.state(),
        RestartState::CleaningUp {
            failure: AttemptFailure::MalformedReady,
            ..
        }
    ));

    let mut wrong = supervisor();
    begin_started(&mut wrong, 0);
    assert_eq!(
        wrong.ready(1, 12, 1),
        Err(RestartTransitionError::AttemptFailed(
            AttemptFailure::WrongTransactionReady
        ))
    );
    assert!(matches!(
        wrong.state(),
        RestartState::CleaningUp {
            failure: AttemptFailure::WrongTransactionReady,
            ..
        }
    ));
}

#[test]
fn ready_then_normal_exit_and_exception_remain_distinct() {
    let mut normal = supervisor();
    begin_started(&mut normal, 0);
    normal.ready(1, 11, 1).unwrap();
    normal
        .terminal(1, 11, 2, TerminalDisposition::NormalExit(0))
        .unwrap();
    assert!(matches!(
        normal.state(),
        RestartState::CleaningUp {
            failure: AttemptFailure::ExitAfterReady(TerminalDisposition::NormalExit(0)),
            ..
        }
    ));
    normal.cleanup_complete(1, 11, 3).unwrap();
    assert_eq!(normal.state(), RestartState::Stopped);

    let mut exception = supervisor();
    begin_started(&mut exception, 0);
    exception.ready(1, 11, 1).unwrap();
    exception
        .terminal(1, 11, 2, TerminalDisposition::UnhandledException)
        .unwrap();
    assert!(matches!(
        exception.state(),
        RestartState::CleaningUp {
            failure: AttemptFailure::ExitAfterReady(TerminalDisposition::UnhandledException),
            ..
        }
    ));
}

#[test]
fn authorized_termination_and_task_group_teardown_remain_distinct() {
    let mut authorized = supervisor();
    begin_started(&mut authorized, 0);
    authorized
        .terminal(1, 11, 1, TerminalDisposition::AuthorizedTermination)
        .unwrap();
    assert!(matches!(
        authorized.state(),
        RestartState::CleaningUp {
            failure: AttemptFailure::ExitBeforeReady(TerminalDisposition::AuthorizedTermination),
            ..
        }
    ));

    let mut teardown = supervisor();
    begin_started(&mut teardown, 0);
    teardown
        .terminal(1, 11, 1, TerminalDisposition::TaskGroupTeardown)
        .unwrap();
    assert!(matches!(
        teardown.state(),
        RestartState::CleaningUp {
            failure: AttemptFailure::ExitBeforeReady(TerminalDisposition::TaskGroupTeardown),
            ..
        }
    ));
}

#[test]
fn startup_timeout_requests_task_group_cancellation_then_cleanup() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 50);
    assert_eq!(
        supervisor.deadline_elapsed(1, 11, 1_000_000_050, 1_000_000_049),
        Err(RestartTransitionError::DeadlineNotReached)
    );
    supervisor
        .deadline_elapsed(1, 11, 1_000_000_050, 1_000_000_050)
        .unwrap();
    assert!(matches!(
        supervisor.state(),
        RestartState::CleaningUp {
            failure: AttemptFailure::ReadyTimeout,
            action: CleanupAction::TerminateTaskGroup,
            ..
        }
    ));
    supervisor.cleanup_complete(1, 11, 1_000_000_051).unwrap();
    assert!(matches!(supervisor.state(), RestartState::Backoff { .. }));
}

#[test]
fn timeout_wins_at_the_exact_ready_deadline() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 50);
    assert_eq!(
        supervisor.ready(1, 11, 1_000_000_050),
        Err(RestartTransitionError::AttemptFailed(
            AttemptFailure::ReadyTimeout
        ))
    );
    assert!(matches!(
        supervisor.state(),
        RestartState::CleaningUp {
            failure: AttemptFailure::ReadyTimeout,
            ..
        }
    ));
}

#[test]
fn wait_failure_is_classified_and_requires_bounded_termination() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 0);
    supervisor
        .fail_attempt(1, 11, 1, AttemptFailure::WaitFailed)
        .unwrap();
    assert!(matches!(
        supervisor.state(),
        RestartState::CleaningUp {
            failure: AttemptFailure::WaitFailed,
            action: CleanupAction::TerminateTaskGroup,
            ..
        }
    ));
}

#[test]
fn duplicate_ready_after_ready_forces_cleanup() {
    let mut running = supervisor();
    begin_started(&mut running, 0);
    running.ready(1, 11, 1).unwrap();
    running
        .fail_attempt(1, 11, 2, AttemptFailure::DuplicateReady)
        .unwrap();
    assert!(matches!(
        running.state(),
        RestartState::CleaningUp {
            failure: AttemptFailure::DuplicateReady,
            action: CleanupAction::TerminateTaskGroup,
            ..
        }
    ));

    let mut exited = supervisor();
    begin_started(&mut exited, 0);
    exited.ready(1, 11, 1).unwrap();
    exited
        .fail_attempt(1, 11, 2, AttemptFailure::ReadinessFailedAfterExit)
        .unwrap();
    assert!(matches!(
        exited.state(),
        RestartState::CleaningUp {
            failure: AttemptFailure::ReadinessFailedAfterExit,
            action: CleanupAction::CloseTerminal,
            ..
        }
    ));
}

#[test]
fn peer_close_while_awaiting_ready_is_separate_failure() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 0);
    supervisor
        .fail_attempt(1, 11, 3, AttemptFailure::PeerClosedBeforeReady)
        .unwrap();
    assert!(matches!(
        supervisor.state(),
        RestartState::CleaningUp {
            failure: AttemptFailure::PeerClosedBeforeReady,
            ..
        }
    ));
}

#[test]
fn backoff_cannot_fire_early() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 0);
    supervisor
        .fail_attempt(1, 11, 1, AttemptFailure::MalformedReady)
        .unwrap();
    supervisor.cleanup_complete(1, 11, 2).unwrap();
    let RestartState::Backoff { deadline_ns, .. } = supervisor.state() else {
        panic!("backoff missing");
    };
    assert_eq!(
        supervisor.start_replacement(deadline_ns - 1, 2, 12),
        Err(RestartTransitionError::DeadlineNotReached)
    );
    supervisor.start_replacement(deadline_ns, 2, 12).unwrap();
    assert!(matches!(
        supervisor.state(),
        RestartState::Starting { generation: 2, .. }
    ));
}

#[test]
fn fourth_failure_enters_permanent_failure_exactly_once() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 0);
    let mut now = 1;
    for generation in 1..=3 {
        now = fail_and_restart(&mut supervisor, generation, 10 + generation, now);
    }
    supervisor
        .fail_attempt(4, 14, now + 1, AttemptFailure::MalformedReady)
        .unwrap();
    supervisor.cleanup_complete(4, 14, now + 2).unwrap();
    assert!(matches!(
        supervisor.state(),
        RestartState::PermanentFailure { .. }
    ));
    assert_eq!(supervisor.history().len(), 4);
    assert_eq!(
        supervisor.cleanup_complete(4, 14, now + 3),
        Err(RestartTransitionError::InvalidState)
    );
    assert_eq!(
        supervisor.start_replacement(now + 3, 5, 15),
        Err(RestartTransitionError::InvalidState)
    );
}

#[test]
fn stale_ready_and_exit_cannot_mutate_replacement_generation() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 0);
    let now = fail_and_restart(&mut supervisor, 1, 11, 1);
    assert_eq!(
        supervisor.ready(1, 11, now + 1),
        Err(RestartTransitionError::StaleGeneration)
    );
    assert_eq!(
        supervisor.terminal(1, 11, now + 1, TerminalDisposition::NormalExit(0)),
        Err(RestartTransitionError::StaleGeneration)
    );
    assert!(matches!(
        supervisor.state(),
        RestartState::AwaitingReady { generation: 2, .. }
    ));
}

#[test]
fn stale_timer_cannot_mutate_replacement_generation() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 0);
    let first_deadline = match supervisor.state() {
        RestartState::AwaitingReady { deadline_ns, .. } => deadline_ns,
        _ => unreachable!(),
    };
    let now = fail_and_restart(&mut supervisor, 1, 11, 1);
    let replacement = supervisor.state();
    assert_eq!(
        supervisor.deadline_elapsed(1, 11, first_deadline, now + 1),
        Err(RestartTransitionError::StaleGeneration)
    );
    assert_eq!(supervisor.state(), replacement);
}

#[test]
fn cleanup_acknowledgement_is_generation_and_transaction_exact() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 0);
    supervisor
        .fail_attempt(1, 11, 1, AttemptFailure::MalformedReady)
        .unwrap();
    assert_eq!(
        supervisor.cleanup_complete(1, 12, 2),
        Err(RestartTransitionError::TransactionMismatch)
    );
    assert!(matches!(
        supervisor.state(),
        RestartState::CleaningUp { .. }
    ));
    supervisor.cleanup_complete(1, 11, 2).unwrap();
}

#[test]
fn cleanup_failure_is_visible_and_blocks_false_restart() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 0);
    supervisor
        .fail_attempt(1, 11, 1, AttemptFailure::MalformedReady)
        .unwrap();
    supervisor.cleanup_failed(1, 11, 2).unwrap();
    assert!(matches!(
        supervisor.state(),
        RestartState::PermanentFailure {
            cleanup: CleanupDisposition::Failed,
            ..
        }
    ));
    assert_eq!(
        supervisor.history().as_slice()[0].unwrap().cleanup,
        CleanupDisposition::Failed
    );
}

#[test]
fn fail_closed_retirement_records_complete_cleanup_without_replacement() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 0);
    supervisor.ready(1, 11, 1).unwrap();

    supervisor
        .retire_active_fail_closed(
            1,
            11,
            u64::MAX,
            AttemptFailure::WaitFailed,
            CleanupDisposition::Complete,
        )
        .unwrap();

    assert_eq!(
        supervisor.state(),
        RestartState::PermanentFailure {
            final_failure: AttemptFailure::WaitFailed,
            cleanup: CleanupDisposition::Complete,
        }
    );
    assert_eq!(
        supervisor.history().as_slice(),
        &[Some(AttemptRecord {
            attempt: 1,
            generation: 1,
            transaction_id: 11,
            started_at_ns: 0,
            terminal_at_ns: u64::MAX,
            failure: AttemptFailure::WaitFailed,
            cleanup: CleanupDisposition::Complete,
        })]
    );
}

#[test]
fn fail_closed_retirement_is_identity_exact_and_records_failed_cleanup() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 0);
    supervisor.ready(1, 11, 1).unwrap();
    let ready = supervisor.state();

    assert_eq!(
        supervisor.retire_active_fail_closed(
            1,
            12,
            2,
            AttemptFailure::WaitFailed,
            CleanupDisposition::Failed,
        ),
        Err(RestartTransitionError::TransactionMismatch)
    );
    assert_eq!(supervisor.state(), ready);
    assert!(supervisor.history().is_empty());

    supervisor
        .retire_active_fail_closed(
            1,
            11,
            2,
            AttemptFailure::WaitFailed,
            CleanupDisposition::Failed,
        )
        .unwrap();
    assert_eq!(
        supervisor.state(),
        RestartState::PermanentFailure {
            final_failure: AttemptFailure::WaitFailed,
            cleanup: CleanupDisposition::Failed,
        }
    );
}

#[test]
fn late_cleanup_completion_is_a_visible_failure() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 0);
    supervisor
        .fail_attempt(1, 11, 1, AttemptFailure::MalformedReady)
        .unwrap();
    supervisor.cleanup_complete(1, 11, 1_000_000_002).unwrap();
    assert!(matches!(
        supervisor.state(),
        RestartState::PermanentFailure {
            cleanup: CleanupDisposition::Failed,
            ..
        }
    ));
}

#[test]
fn timeout_wins_at_the_exact_cleanup_deadline() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 0);
    supervisor
        .fail_attempt(1, 11, 1, AttemptFailure::MalformedReady)
        .unwrap();
    supervisor.cleanup_complete(1, 11, 1_000_000_001).unwrap();
    assert!(matches!(
        supervisor.state(),
        RestartState::PermanentFailure {
            cleanup: CleanupDisposition::Failed,
            ..
        }
    ));
}

#[test]
fn history_preserves_terminal_classification_time() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 0);
    supervisor
        .fail_attempt(1, 11, 10, AttemptFailure::MalformedReady)
        .unwrap();
    supervisor.cleanup_complete(1, 11, 20).unwrap();
    assert_eq!(
        supervisor.history().as_slice()[0].unwrap().terminal_at_ns,
        10
    );
}

#[test]
fn explicit_cancellation_reaches_stopped_without_restart() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 0);
    supervisor.ready(1, 11, 1).unwrap();
    supervisor.cancel(1, 11, 2).unwrap();
    supervisor.cleanup_complete(1, 11, 3).unwrap();
    assert_eq!(supervisor.state(), RestartState::Stopped);
    assert_eq!(supervisor.history().len(), 1);
}

#[test]
fn new_episode_must_advance_generation_and_time() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 10);
    assert_eq!(
        supervisor.cancel(1, 11, 9),
        Err(RestartTransitionError::TimeRegression)
    );
    supervisor.cancel(1, 11, 11).unwrap();
    supervisor.cleanup_complete(1, 11, 12).unwrap();
    assert_eq!(
        supervisor.begin(13, 1, 12),
        Err(RestartTransitionError::GenerationNotAdvanced)
    );
    supervisor.begin(13, 2, 12).unwrap();
}

#[test]
fn matching_duplicate_event_in_cleanup_is_invalid_state() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 0);
    supervisor
        .fail_attempt(1, 11, 1, AttemptFailure::MalformedReady)
        .unwrap();
    assert_eq!(
        supervisor.terminal(1, 11, 2, TerminalDisposition::NormalExit(0)),
        Err(RestartTransitionError::InvalidState)
    );
    assert!(matches!(
        supervisor.state(),
        RestartState::CleaningUp { .. }
    ));
}

#[test]
fn replacement_start_at_window_end_is_last_admissible_instant() {
    let mut at_end = supervisor();
    begin_started(&mut at_end, 0);
    at_end
        .fail_attempt(1, 11, 1, AttemptFailure::MalformedReady)
        .unwrap();
    at_end.cleanup_complete(1, 11, 2).unwrap();
    at_end.start_replacement(2_000_000_000, 2, 12).unwrap();
    assert!(matches!(at_end.state(), RestartState::Starting { .. }));

    let mut after_end = supervisor();
    begin_started(&mut after_end, 0);
    after_end
        .fail_attempt(1, 11, 1, AttemptFailure::MalformedReady)
        .unwrap();
    after_end.cleanup_complete(1, 11, 2).unwrap();
    after_end.start_replacement(2_000_000_001, 2, 12).unwrap();
    assert!(matches!(
        after_end.state(),
        RestartState::PermanentFailure { .. }
    ));
}

#[test]
fn replacement_attempt_gets_one_fixed_deadline_from_replacement_start() {
    let mut supervisor = supervisor();
    begin_started(&mut supervisor, 0);
    supervisor
        .fail_attempt(1, 11, 1, AttemptFailure::MalformedReady)
        .unwrap();
    supervisor.cleanup_complete(1, 11, 2).unwrap();
    let RestartState::Backoff { deadline_ns, .. } = supervisor.state() else {
        panic!("replacement backoff was not entered");
    };
    supervisor.start_replacement(deadline_ns, 2, 12).unwrap();
    let attempt_deadline = deadline_ns + WYR0_I_SUPERVISION_POLICY.ready_timeout_ns;
    assert!(matches!(
        supervisor.state(),
        RestartState::Starting {
            deadline_ns: current,
            ..
        } if current == attempt_deadline
    ));
    assert_eq!(
        supervisor.child_started(2, 12, attempt_deadline),
        Err(RestartTransitionError::AttemptFailed(
            AttemptFailure::ReadyTimeout
        ))
    );
}

#[test]
fn deadline_and_generation_arithmetic_fail_closed() {
    let mut deadline = supervisor();
    assert_eq!(
        deadline.begin(u64::MAX, 1, 1),
        Err(RestartTransitionError::ArithmeticOverflow)
    );
    assert_eq!(deadline.state(), RestartState::Stopped);

    let mut generation = supervisor();
    generation.begin(0, u64::MAX, 1).unwrap();
    generation
        .fail_attempt(u64::MAX, 1, 1, AttemptFailure::CreationFailed)
        .unwrap();
    generation.cleanup_complete(u64::MAX, 1, 2).unwrap();
    assert!(matches!(
        generation.state(),
        RestartState::PermanentFailure { .. }
    ));
}
