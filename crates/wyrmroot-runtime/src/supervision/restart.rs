//! Finite, generation-safe restart policy layered above child READY/exit observation.
//!
//! This policy engine deliberately owns no loader, registry, dependency, file-backed control, or service
//! discovery behavior. Callers retain native Process, TaskGroup, Channel, mapping, and accounting
//! authority and perform the cleanup action exposed by [`RestartState::CleaningUp`]. A replacement
//! cannot become startable until the caller confirms that the previous generation was cleaned.

/// Maximum number of terminal attempts retained by the WYR0-I policy.
pub const RESTART_HISTORY_CAPACITY: usize = 4;

/// WYR0-I finite restart policy values, expressed in monotonic-active nanoseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupervisionPolicy {
    /// Total attempts in one episode, including the initial launch.
    pub max_attempts: u8,
    /// Fixed delay before a replacement may be started.
    pub backoff_ns: u64,
    /// Maximum duration from the initial attempt to a replacement start.
    pub restart_window_ns: u64,
    /// Maximum duration from a successful start to exact READY.
    pub ready_timeout_ns: u64,
    /// Maximum duration allowed for termination and generation cleanup.
    pub cleanup_timeout_ns: u64,
}

/// Locked WYR0-I policy. These values are Wyrmroot policy, not stable platform ABI.
pub const WYR0_I_SUPERVISION_POLICY: SupervisionPolicy = SupervisionPolicy {
    max_attempts: 4,
    backoff_ns: 25_000_000,
    restart_window_ns: 2_000_000_000,
    ready_timeout_ns: 1_000_000_000,
    cleanup_timeout_ns: 1_000_000_000,
};

/// Structured Process termination classification supplied by the native observer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalDisposition {
    /// Exact structured normal application exit, including its application code.
    NormalExit(u32),
    /// Explicit controller-authorized Process termination.
    AuthorizedTermination,
    /// Descendant retirement caused by terminating its TaskGroup ancestor.
    TaskGroupTeardown,
    /// Unhandled architectural or policy exception.
    UnhandledException,
}

/// Why one launch attempt entered cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptFailure {
    /// Process construction failed before publication.
    CreationFailed,
    /// Initial Thread start failed before a READY wait could begin.
    StartFailed,
    /// Process termination was observed before exact READY.
    ExitBeforeReady(TerminalDisposition),
    /// READY bytes or handle cardinality were malformed.
    MalformedReady,
    /// A second READY or other launch datagram arrived after exact READY.
    DuplicateReady,
    /// Terminal-channel drain found malformed/duplicate readiness after Process `EXITED`.
    ReadinessFailedAfterExit,
    /// READY named a transaction other than the current attempt transaction.
    WrongTransactionReady,
    /// The launch endpoint closed before exact READY.
    PeerClosedBeforeReady,
    /// The bounded native wait operation failed before a terminal disposition was available.
    WaitFailed,
    /// Fresh structured Process termination state could not be queried after `EXITED`.
    ExitQueryFailed,
    /// The absolute READY deadline elapsed.
    ReadyTimeout,
    /// A process that had reached READY later terminated.
    ExitAfterReady(TerminalDisposition),
    /// The controller explicitly cancelled this supervision episode.
    Cancelled,
}

/// Native authority the caller must use to retire the current generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupAction {
    /// No runnable child was published; close partial construction state.
    CloseUnpublished,
    /// Terminate the controller-owned child TaskGroup, then close all generation state.
    TerminateTaskGroup,
    /// Process terminal state is already observed; close generation state without retermination.
    CloseTerminal,
}

/// Result of retiring the attempt's handles, mappings, endpoints, and reservations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupDisposition {
    /// Every controller-owned resource was released exactly once.
    Complete,
    /// Cleanup failed; replacement publication is forbidden.
    Failed,
}

/// One bounded terminal-attempt record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptRecord {
    /// One-based attempt number within this episode.
    pub attempt: u8,
    /// Nonzero controller-owned logical peer generation.
    pub generation: u64,
    /// Nonzero controller-owned launch transaction.
    pub transaction_id: u64,
    /// Monotonic-active instant at which the attempt was prepared.
    pub started_at_ns: u64,
    /// Monotonic-active instant at which failure/exit was classified.
    pub terminal_at_ns: u64,
    /// Exact classified reason for retiring this attempt.
    pub failure: AttemptFailure,
    /// Whether controller-owned generation cleanup completed.
    pub cleanup: CleanupDisposition,
}

/// Fixed-capacity terminal history for one supervision episode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestartHistory {
    records: [Option<AttemptRecord>; RESTART_HISTORY_CAPACITY],
    len: u8,
}

impl RestartHistory {
    const fn new() -> Self {
        Self {
            records: [None; RESTART_HISTORY_CAPACITY],
            len: 0,
        }
    }

    /// Number of terminal attempts retained.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns whether no terminal attempt has been recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the retained records in oldest-to-newest order.
    #[must_use]
    pub fn as_slice(&self) -> &[Option<AttemptRecord>] {
        &self.records[..self.len()]
    }

    fn push(&mut self, record: AttemptRecord) -> Result<(), RestartTransitionError> {
        let index = self.len();
        let Some(slot) = self.records.get_mut(index) else {
            return Err(RestartTransitionError::HistoryExhausted);
        };
        *slot = Some(record);
        self.len = self
            .len
            .checked_add(1)
            .ok_or(RestartTransitionError::ArithmeticOverflow)?;
        Ok(())
    }
}

/// Observable finite state for one logical supervised peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartState {
    /// No active supervision episode or an explicitly cancelled episode.
    Stopped,
    /// The caller may construct/start this exact generation and transaction.
    Starting {
        attempt: u8,
        generation: u64,
        transaction_id: u64,
    },
    /// Child start succeeded and exact READY is required by this absolute deadline.
    AwaitingReady {
        attempt: u8,
        generation: u64,
        transaction_id: u64,
        deadline_ns: u64,
    },
    /// Exact READY was accepted for the current generation and transaction.
    Ready {
        attempt: u8,
        generation: u64,
        transaction_id: u64,
    },
    /// The caller must perform the specified bounded native cleanup before any replacement.
    CleaningUp {
        attempt: u8,
        generation: u64,
        transaction_id: u64,
        failure: AttemptFailure,
        action: CleanupAction,
        classified_at_ns: u64,
        deadline_ns: u64,
        retry: bool,
    },
    /// Cleanup completed; replacement start is forbidden before this deadline.
    Backoff {
        next_attempt: u8,
        next_generation: u64,
        deadline_ns: u64,
    },
    /// The finite budget/window was exhausted or cleanup failed.
    PermanentFailure {
        final_failure: AttemptFailure,
        cleanup: CleanupDisposition,
    },
}

/// Invalid event or fail-closed arithmetic condition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartTransitionError {
    /// The policy has an invalid zero/out-of-range field.
    InvalidPolicy,
    /// A generation or transaction identifier was zero.
    ZeroIdentity,
    /// An event is not valid in the current state.
    InvalidState,
    /// An event belongs to an old or future generation.
    StaleGeneration,
    /// An event names the wrong transaction for the current generation.
    TransactionMismatch,
    /// An absolute monotonic deadline has not yet been reached.
    DeadlineNotReached,
    /// An observation arrived at or after its absolute deadline.
    DeadlineExpired,
    /// A timer callback did not name the current state's exact absolute deadline.
    DeadlineMismatch,
    /// A caller-supplied monotonic-active timestamp regressed.
    TimeRegression,
    /// A new episode did not advance the controller-owned peer generation.
    GenerationNotAdvanced,
    /// The input was classified as an attempt failure and cleanup is now required.
    AttemptFailed(AttemptFailure),
    /// Checked monotonic/counter arithmetic overflowed.
    ArithmeticOverflow,
    /// The fixed history would overflow.
    HistoryExhausted,
}

/// Allocation-free WYR0-I restart state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestartSupervisor {
    policy: SupervisionPolicy,
    state: RestartState,
    history: RestartHistory,
    episode_started_at_ns: u64,
    attempt_started_at_ns: u64,
    last_observed_ns: u64,
    last_generation: u64,
}

impl RestartSupervisor {
    /// Creates an idle supervisor after validating its finite policy.
    pub fn new(policy: SupervisionPolicy) -> Result<Self, RestartTransitionError> {
        if policy.max_attempts == 0
            || usize::from(policy.max_attempts) > RESTART_HISTORY_CAPACITY
            || policy.backoff_ns == 0
            || policy.restart_window_ns == 0
            || policy.ready_timeout_ns == 0
            || policy.cleanup_timeout_ns == 0
        {
            return Err(RestartTransitionError::InvalidPolicy);
        }
        Ok(Self {
            policy,
            state: RestartState::Stopped,
            history: RestartHistory::new(),
            episode_started_at_ns: 0,
            attempt_started_at_ns: 0,
            last_observed_ns: 0,
            last_generation: 0,
        })
    }

    /// Returns the exact current state.
    #[must_use]
    pub const fn state(&self) -> RestartState {
        self.state
    }

    /// Returns the fixed terminal-attempt history.
    #[must_use]
    pub const fn history(&self) -> &RestartHistory {
        &self.history
    }

    /// Begins a new episode with nonzero controller-owned generation and transaction identities.
    pub fn begin(
        &mut self,
        now_ns: u64,
        generation: u64,
        transaction_id: u64,
    ) -> Result<(), RestartTransitionError> {
        if self.state != RestartState::Stopped {
            return Err(RestartTransitionError::InvalidState);
        }
        validate_identity(generation, transaction_id)?;
        if generation <= self.last_generation {
            return Err(RestartTransitionError::GenerationNotAdvanced);
        }
        self.observe_time(now_ns)?;
        self.history = RestartHistory::new();
        self.episode_started_at_ns = now_ns;
        self.attempt_started_at_ns = now_ns;
        self.last_generation = generation;
        self.state = RestartState::Starting {
            attempt: 1,
            generation,
            transaction_id,
        };
        Ok(())
    }

    /// Records successful child start and begins the absolute READY deadline.
    pub fn child_started(
        &mut self,
        generation: u64,
        transaction_id: u64,
        now_ns: u64,
    ) -> Result<(), RestartTransitionError> {
        let RestartState::Starting {
            attempt,
            generation: current_generation,
            transaction_id: current_transaction,
        } = self.state
        else {
            return Err(RestartTransitionError::InvalidState);
        };
        validate_event_identity(
            generation,
            transaction_id,
            current_generation,
            current_transaction,
        )?;
        self.observe_time(now_ns)?;
        let deadline_ns = checked_deadline(now_ns, self.policy.ready_timeout_ns)?;
        self.state = RestartState::AwaitingReady {
            attempt,
            generation,
            transaction_id,
            deadline_ns,
        };
        Ok(())
    }

    /// Accepts one exact READY for the current generation before its deadline.
    pub fn ready(
        &mut self,
        generation: u64,
        transaction_id: u64,
        now_ns: u64,
    ) -> Result<(), RestartTransitionError> {
        let RestartState::AwaitingReady {
            attempt,
            generation: current_generation,
            transaction_id: current_transaction,
            deadline_ns,
        } = self.state
        else {
            return self.identity_error_or_invalid_state(generation, transaction_id);
        };
        validate_identity(generation, transaction_id)?;
        if generation != current_generation {
            return Err(RestartTransitionError::StaleGeneration);
        }
        self.observe_time(now_ns)?;
        if transaction_id != current_transaction {
            self.enter_cleanup(
                now_ns,
                AttemptFailure::WrongTransactionReady,
                CleanupAction::TerminateTaskGroup,
                true,
            )?;
            return Err(RestartTransitionError::AttemptFailed(
                AttemptFailure::WrongTransactionReady,
            ));
        }
        if now_ns >= deadline_ns {
            self.enter_cleanup(
                now_ns,
                AttemptFailure::ReadyTimeout,
                CleanupAction::TerminateTaskGroup,
                true,
            )?;
            return Err(RestartTransitionError::AttemptFailed(
                AttemptFailure::ReadyTimeout,
            ));
        }
        self.state = RestartState::Ready {
            attempt,
            generation,
            transaction_id,
        };
        Ok(())
    }

    /// Records a malformed/wrong READY, peer-close, or construction/start failure.
    pub fn fail_attempt(
        &mut self,
        generation: u64,
        transaction_id: u64,
        now_ns: u64,
        failure: AttemptFailure,
    ) -> Result<(), RestartTransitionError> {
        let (current_generation, current_transaction, action) = match self.state {
            RestartState::Starting {
                generation,
                transaction_id,
                ..
            } => (generation, transaction_id, CleanupAction::CloseUnpublished),
            RestartState::AwaitingReady {
                generation,
                transaction_id,
                ..
            } => (
                generation,
                transaction_id,
                CleanupAction::TerminateTaskGroup,
            ),
            RestartState::Ready {
                generation,
                transaction_id,
                ..
            } => (
                generation,
                transaction_id,
                CleanupAction::TerminateTaskGroup,
            ),
            _ => return self.identity_error_or_invalid_state(generation, transaction_id),
        };
        validate_event_identity(
            generation,
            transaction_id,
            current_generation,
            current_transaction,
        )?;
        self.observe_time(now_ns)?;
        match failure {
            AttemptFailure::CreationFailed | AttemptFailure::StartFailed
                if matches!(self.state, RestartState::Starting { .. }) => {}
            AttemptFailure::MalformedReady
            | AttemptFailure::WrongTransactionReady
            | AttemptFailure::PeerClosedBeforeReady
                if matches!(self.state, RestartState::AwaitingReady { .. }) => {}
            AttemptFailure::DuplicateReady if matches!(self.state, RestartState::Ready { .. }) => {}
            AttemptFailure::ReadinessFailedAfterExit
                if matches!(
                    self.state,
                    RestartState::AwaitingReady { .. } | RestartState::Ready { .. }
                ) => {}
            AttemptFailure::WaitFailed
                if matches!(
                    self.state,
                    RestartState::AwaitingReady { .. } | RestartState::Ready { .. }
                ) => {}
            AttemptFailure::ExitQueryFailed
                if matches!(
                    self.state,
                    RestartState::AwaitingReady { .. } | RestartState::Ready { .. }
                ) => {}
            _ => return Err(RestartTransitionError::InvalidState),
        }
        let action = if matches!(
            failure,
            AttemptFailure::ExitQueryFailed | AttemptFailure::ReadinessFailedAfterExit
        ) {
            CleanupAction::CloseTerminal
        } else {
            action
        };
        self.enter_cleanup(now_ns, failure, action, true)
    }

    /// Records a structured terminal Process disposition for the current generation.
    pub fn terminal(
        &mut self,
        generation: u64,
        transaction_id: u64,
        now_ns: u64,
        disposition: TerminalDisposition,
    ) -> Result<(), RestartTransitionError> {
        let (current_generation, current_transaction, was_ready) = match self.state {
            RestartState::Starting {
                generation,
                transaction_id,
                ..
            }
            | RestartState::AwaitingReady {
                generation,
                transaction_id,
                ..
            } => (generation, transaction_id, false),
            RestartState::Ready {
                generation,
                transaction_id,
                ..
            } => (generation, transaction_id, true),
            _ => return self.identity_error_or_invalid_state(generation, transaction_id),
        };
        validate_event_identity(
            generation,
            transaction_id,
            current_generation,
            current_transaction,
        )?;
        self.observe_time(now_ns)?;
        let failure = if was_ready {
            AttemptFailure::ExitAfterReady(disposition)
        } else {
            AttemptFailure::ExitBeforeReady(disposition)
        };
        let retry = !matches!(
            (was_ready, disposition),
            (true, TerminalDisposition::NormalExit(0))
        );
        self.enter_cleanup(now_ns, failure, CleanupAction::CloseTerminal, retry)
    }

    /// Advances an expired READY or cleanup deadline; backoff uses [`Self::start_replacement`].
    pub fn deadline_elapsed(
        &mut self,
        generation: u64,
        transaction_id: u64,
        expected_deadline_ns: u64,
        now_ns: u64,
    ) -> Result<(), RestartTransitionError> {
        match self.state {
            RestartState::AwaitingReady {
                generation: current_generation,
                transaction_id: current_transaction,
                deadline_ns,
                ..
            } => {
                validate_event_identity(
                    generation,
                    transaction_id,
                    current_generation,
                    current_transaction,
                )?;
                validate_deadline(expected_deadline_ns, deadline_ns)?;
                self.observe_time(now_ns)?;
                require_reached(now_ns, deadline_ns)?;
                self.enter_cleanup(
                    now_ns,
                    AttemptFailure::ReadyTimeout,
                    CleanupAction::TerminateTaskGroup,
                    true,
                )
            }
            RestartState::CleaningUp {
                generation: current_generation,
                transaction_id: current_transaction,
                failure,
                deadline_ns,
                ..
            } => {
                validate_event_identity(
                    generation,
                    transaction_id,
                    current_generation,
                    current_transaction,
                )?;
                validate_deadline(expected_deadline_ns, deadline_ns)?;
                self.observe_time(now_ns)?;
                require_reached(now_ns, deadline_ns)?;
                self.finish_cleanup(now_ns, failure, CleanupDisposition::Failed)
            }
            _ => Err(RestartTransitionError::InvalidState),
        }
    }

    /// Requests bounded cancellation of the current generation without scheduling replacement.
    pub fn cancel(
        &mut self,
        generation: u64,
        transaction_id: u64,
        now_ns: u64,
    ) -> Result<(), RestartTransitionError> {
        let (current_generation, current_transaction, action) = match self.state {
            RestartState::Starting {
                generation,
                transaction_id,
                ..
            } => (generation, transaction_id, CleanupAction::CloseUnpublished),
            RestartState::AwaitingReady {
                generation,
                transaction_id,
                ..
            }
            | RestartState::Ready {
                generation,
                transaction_id,
                ..
            } => (
                generation,
                transaction_id,
                CleanupAction::TerminateTaskGroup,
            ),
            _ => return self.identity_error_or_invalid_state(generation, transaction_id),
        };
        validate_event_identity(
            generation,
            transaction_id,
            current_generation,
            current_transaction,
        )?;
        self.observe_time(now_ns)?;
        self.enter_cleanup(now_ns, AttemptFailure::Cancelled, action, false)
    }

    /// Confirms exactly-once cleanup of endpoints, handles, mappings, and reservations.
    pub fn cleanup_complete(
        &mut self,
        generation: u64,
        transaction_id: u64,
        now_ns: u64,
    ) -> Result<(), RestartTransitionError> {
        let RestartState::CleaningUp {
            generation: current_generation,
            transaction_id: current_transaction,
            ..
        } = self.state
        else {
            return self.identity_error_or_invalid_state(generation, transaction_id);
        };
        validate_event_identity(
            generation,
            transaction_id,
            current_generation,
            current_transaction,
        )?;
        self.observe_time(now_ns)?;
        self.finish_cleanup(
            now_ns,
            self.current_failure()?,
            CleanupDisposition::Complete,
        )
    }

    /// Makes a cleanup failure explicit and permanently prevents replacement publication.
    pub fn cleanup_failed(
        &mut self,
        generation: u64,
        transaction_id: u64,
        now_ns: u64,
    ) -> Result<(), RestartTransitionError> {
        let RestartState::CleaningUp {
            generation: current_generation,
            transaction_id: current_transaction,
            ..
        } = self.state
        else {
            return self.identity_error_or_invalid_state(generation, transaction_id);
        };
        validate_event_identity(
            generation,
            transaction_id,
            current_generation,
            current_transaction,
        )?;
        self.observe_time(now_ns)?;
        self.finish_cleanup(now_ns, self.current_failure()?, CleanupDisposition::Failed)
    }

    /// Starts the exact next generation after backoff and inside the finite episode window.
    pub fn start_replacement(
        &mut self,
        now_ns: u64,
        generation: u64,
        transaction_id: u64,
    ) -> Result<(), RestartTransitionError> {
        let RestartState::Backoff {
            next_attempt,
            next_generation,
            deadline_ns,
        } = self.state
        else {
            return Err(RestartTransitionError::InvalidState);
        };
        validate_identity(generation, transaction_id)?;
        if generation != next_generation {
            return Err(RestartTransitionError::StaleGeneration);
        }
        self.observe_time(now_ns)?;
        require_reached(now_ns, deadline_ns)?;
        let window_end =
            checked_deadline(self.episode_started_at_ns, self.policy.restart_window_ns)?;
        if now_ns > window_end {
            let final_failure = self.last_failure()?;
            self.state = RestartState::PermanentFailure {
                final_failure,
                cleanup: CleanupDisposition::Complete,
            };
            return Ok(());
        }
        self.attempt_started_at_ns = now_ns;
        self.last_generation = generation;
        self.state = RestartState::Starting {
            attempt: next_attempt,
            generation,
            transaction_id,
        };
        Ok(())
    }

    fn enter_cleanup(
        &mut self,
        now_ns: u64,
        failure: AttemptFailure,
        action: CleanupAction,
        retry: bool,
    ) -> Result<(), RestartTransitionError> {
        let (attempt, generation, transaction_id) = match self.state {
            RestartState::Starting {
                attempt,
                generation,
                transaction_id,
            }
            | RestartState::AwaitingReady {
                attempt,
                generation,
                transaction_id,
                ..
            }
            | RestartState::Ready {
                attempt,
                generation,
                transaction_id,
            } => (attempt, generation, transaction_id),
            _ => return Err(RestartTransitionError::InvalidState),
        };
        let deadline_ns = checked_deadline(now_ns, self.policy.cleanup_timeout_ns)?;
        self.state = RestartState::CleaningUp {
            attempt,
            generation,
            transaction_id,
            failure,
            action,
            classified_at_ns: now_ns,
            deadline_ns,
            retry,
        };
        Ok(())
    }

    fn finish_cleanup(
        &mut self,
        now_ns: u64,
        failure: AttemptFailure,
        requested_cleanup: CleanupDisposition,
    ) -> Result<(), RestartTransitionError> {
        let RestartState::CleaningUp {
            attempt,
            generation,
            transaction_id,
            failure: current_failure,
            retry,
            classified_at_ns,
            deadline_ns,
            ..
        } = self.state
        else {
            return Err(RestartTransitionError::InvalidState);
        };
        if failure != current_failure {
            return Err(RestartTransitionError::InvalidState);
        }
        let cleanup = if requested_cleanup == CleanupDisposition::Complete && now_ns >= deadline_ns
        {
            CleanupDisposition::Failed
        } else {
            requested_cleanup
        };
        self.history.push(AttemptRecord {
            attempt,
            generation,
            transaction_id,
            started_at_ns: self.attempt_started_at_ns,
            terminal_at_ns: classified_at_ns,
            failure,
            cleanup,
        })?;

        if cleanup == CleanupDisposition::Failed {
            self.state = RestartState::PermanentFailure {
                final_failure: failure,
                cleanup,
            };
            return Ok(());
        }
        if !retry {
            self.state = RestartState::Stopped;
            return Ok(());
        }
        let Some(next_attempt) = attempt.checked_add(1) else {
            return Err(RestartTransitionError::ArithmeticOverflow);
        };
        if next_attempt > self.policy.max_attempts {
            self.state = RestartState::PermanentFailure {
                final_failure: failure,
                cleanup,
            };
            return Ok(());
        }
        let Some(next_generation) = generation.checked_add(1) else {
            self.state = RestartState::PermanentFailure {
                final_failure: failure,
                cleanup,
            };
            return Ok(());
        };
        let deadline_ns = checked_deadline(now_ns, self.policy.backoff_ns)?;
        let window_end =
            checked_deadline(self.episode_started_at_ns, self.policy.restart_window_ns)?;
        if deadline_ns > window_end {
            self.state = RestartState::PermanentFailure {
                final_failure: failure,
                cleanup,
            };
        } else {
            self.state = RestartState::Backoff {
                next_attempt,
                next_generation,
                deadline_ns,
            };
        }
        Ok(())
    }

    fn current_failure(&self) -> Result<AttemptFailure, RestartTransitionError> {
        match self.state {
            RestartState::CleaningUp { failure, .. } => Ok(failure),
            _ => Err(RestartTransitionError::InvalidState),
        }
    }

    fn last_failure(&self) -> Result<AttemptFailure, RestartTransitionError> {
        let Some(index) = self.history.len().checked_sub(1) else {
            return Err(RestartTransitionError::InvalidState);
        };
        self.history.as_slice()[index]
            .map(|record| record.failure)
            .ok_or(RestartTransitionError::InvalidState)
    }

    fn identity_error_or_invalid_state(
        &self,
        generation: u64,
        transaction_id: u64,
    ) -> Result<(), RestartTransitionError> {
        match active_identity(self.state) {
            Some((current_generation, current_transaction)) => match validate_event_identity(
                generation,
                transaction_id,
                current_generation,
                current_transaction,
            ) {
                Ok(()) => Err(RestartTransitionError::InvalidState),
                Err(error) => Err(error),
            },
            None => Err(RestartTransitionError::InvalidState),
        }
    }

    fn observe_time(&mut self, now_ns: u64) -> Result<(), RestartTransitionError> {
        if now_ns < self.last_observed_ns {
            return Err(RestartTransitionError::TimeRegression);
        }
        self.last_observed_ns = now_ns;
        Ok(())
    }
}

fn active_identity(state: RestartState) -> Option<(u64, u64)> {
    match state {
        RestartState::Starting {
            generation,
            transaction_id,
            ..
        }
        | RestartState::AwaitingReady {
            generation,
            transaction_id,
            ..
        }
        | RestartState::Ready {
            generation,
            transaction_id,
            ..
        }
        | RestartState::CleaningUp {
            generation,
            transaction_id,
            ..
        } => Some((generation, transaction_id)),
        _ => None,
    }
}

fn validate_identity(generation: u64, transaction_id: u64) -> Result<(), RestartTransitionError> {
    if generation == 0 || transaction_id == 0 {
        Err(RestartTransitionError::ZeroIdentity)
    } else {
        Ok(())
    }
}

fn validate_event_identity(
    generation: u64,
    transaction_id: u64,
    current_generation: u64,
    current_transaction: u64,
) -> Result<(), RestartTransitionError> {
    validate_identity(generation, transaction_id)?;
    if generation != current_generation {
        return Err(RestartTransitionError::StaleGeneration);
    }
    if transaction_id != current_transaction {
        return Err(RestartTransitionError::TransactionMismatch);
    }
    Ok(())
}

fn checked_deadline(now_ns: u64, duration_ns: u64) -> Result<u64, RestartTransitionError> {
    now_ns
        .checked_add(duration_ns)
        .ok_or(RestartTransitionError::ArithmeticOverflow)
}

fn validate_deadline(
    expected_deadline_ns: u64,
    current_deadline_ns: u64,
) -> Result<(), RestartTransitionError> {
    if expected_deadline_ns == current_deadline_ns {
        Ok(())
    } else {
        Err(RestartTransitionError::DeadlineMismatch)
    }
}

fn require_reached(now_ns: u64, deadline_ns: u64) -> Result<(), RestartTransitionError> {
    if now_ns < deadline_ns {
        Err(RestartTransitionError::DeadlineNotReached)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
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
                failure: AttemptFailure::ExitBeforeReady(
                    TerminalDisposition::AuthorizedTermination
                ),
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
    fn deadline_and_generation_arithmetic_fail_closed() {
        let mut deadline = supervisor();
        deadline.begin(u64::MAX, 1, 1).unwrap();
        assert_eq!(
            deadline.child_started(1, 1, u64::MAX),
            Err(RestartTransitionError::ArithmeticOverflow)
        );

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
}
