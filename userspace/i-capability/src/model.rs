//! Deterministic orchestration checks over the accepted I-C/I-D policy engines.

use wyrmroot_runtime::{
    AccountedResource, AccountingError, AttemptFailure, AttemptRecord, CleanupDisposition,
    ReadinessAccounting, ReservationRequest, RestartState, RestartSupervisor,
    RestartTransitionError, TerminalDisposition, WYR0_I_SUPERVISION_POLICY,
};

use crate::evidence::NORMAL_TRANSACTION;

const ACCOUNTING_PEER_ONE: u8 = 0;
const GENERATION_ONE: u64 = 1;
const TRANSACTION: u64 = NORMAL_TRANSACTION;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelError {
    Accounting(AccountingError),
    Supervision(RestartTransitionError),
    ExpectedRejectionMissing,
    UnexpectedFinalState,
    LeakedAccounting,
}

impl From<AccountingError> for ModelError {
    fn from(value: AccountingError) -> Self {
        Self::Accounting(value)
    }
}

impl From<RestartTransitionError> for ModelError {
    fn from(value: RestartTransitionError) -> Self {
        Self::Supervision(value)
    }
}

pub fn prove_overload_replay_and_cleanup() -> Result<(), ModelError> {
    let mut ledger = ReadinessAccounting::new()?;
    ledger.begin_generation(ACCOUNTING_PEER_ONE, GENERATION_ONE)?;

    let exact_request =
        ReservationRequest::empty().add(AccountedResource::RetainedPayloadBytes, 4096)?;
    let mut exact = ledger.reserve(ACCOUNTING_PEER_ONE, GENERATION_ONE, exact_request)?;
    let over = ReservationRequest::empty().add(AccountedResource::RetainedPayloadBytes, 1)?;
    if ledger.reserve(ACCOUNTING_PEER_ONE, GENERATION_ONE, over)
        != Err(AccountingError::PerPeerLimit(
            AccountedResource::RetainedPayloadBytes,
        ))
    {
        return Err(ModelError::ExpectedRejectionMissing);
    }
    ledger.release(&mut exact)?;

    let mut transaction =
        ledger.begin_transaction(ACCOUNTING_PEER_ONE, GENERATION_ONE, TRANSACTION)?;
    if ledger.begin_transaction(ACCOUNTING_PEER_ONE, GENERATION_ONE, TRANSACTION)
        != Err(AccountingError::DuplicateTransaction)
    {
        return Err(ModelError::ExpectedRejectionMissing);
    }
    ledger.complete_transaction(&mut transaction)?;
    if ledger.begin_transaction(ACCOUNTING_PEER_ONE, GENERATION_ONE, TRANSACTION)
        != Err(AccountingError::ReplayedTransaction)
        || ledger.begin_transaction(ACCOUNTING_PEER_ONE, GENERATION_ONE + 1, TRANSACTION + 1)
            != Err(AccountingError::StaleGeneration)
    {
        return Err(ModelError::ExpectedRejectionMissing);
    }

    let record = AttemptRecord {
        attempt: 1,
        generation: GENERATION_ONE,
        transaction_id: TRANSACTION,
        started_at_ns: 1,
        terminal_at_ns: 2,
        failure: AttemptFailure::ExitAfterReady(TerminalDisposition::NormalExit(0)),
        cleanup: CleanupDisposition::Complete,
    };
    ledger.record_restart_history(ACCOUNTING_PEER_ONE, GENERATION_ONE, &record)?;
    ledger.retire_generation(ACCOUNTING_PEER_ONE, GENERATION_ONE)?;
    ledger.finish_restart_episode(ACCOUNTING_PEER_ONE)?;

    for resource in [
        AccountedResource::LiveProcessGenerations,
        AccountedResource::InFlightTransactions,
        AccountedResource::CompletedReplayEntries,
        AccountedResource::RetainedMessages,
        AccountedResource::RetainedPayloadBytes,
        AccountedResource::DelegatedHandles,
        AccountedResource::SharedMemoryObjects,
        AccountedResource::SharedMemoryBytes,
        AccountedResource::MappedBytes,
        AccountedResource::WaitOperations,
        AccountedResource::Events,
        AccountedResource::Timers,
        AccountedResource::RestartHistoryRecords,
    ] {
        if ledger.aggregate_count(resource) != 0 {
            return Err(ModelError::LeakedAccounting);
        }
    }
    Ok(())
}

pub fn prove_restart_replacement_and_exhaustion() -> Result<(), ModelError> {
    let mut replacement = RestartSupervisor::new(WYR0_I_SUPERVISION_POLICY)?;
    replacement.begin(1, 1, 0x2407_0001)?;
    fail_ready_attempt(&mut replacement, 1, 0x2407_0001, 2)?;
    let RestartState::Backoff { deadline_ns, .. } = replacement.state() else {
        return Err(ModelError::UnexpectedFinalState);
    };
    replacement.start_replacement(deadline_ns, 2, 0x2407_0002)?;
    replacement.child_started(2, 0x2407_0002, deadline_ns)?;
    replacement.ready(2, 0x2407_0002, deadline_ns + 1)?;
    if !matches!(
        replacement.state(),
        RestartState::Ready {
            attempt: 2,
            generation: 2,
            ..
        }
    ) {
        return Err(ModelError::UnexpectedFinalState);
    }

    let mut exhausted = RestartSupervisor::new(WYR0_I_SUPERVISION_POLICY)?;
    exhausted.begin(1, 1, 0x2408_0001)?;
    let mut now = 2;
    for generation in 1_u64..=4 {
        let transaction = 0x2408_0000 + generation;
        if generation > 1 {
            let RestartState::Backoff { deadline_ns, .. } = exhausted.state() else {
                return Err(ModelError::UnexpectedFinalState);
            };
            exhausted.start_replacement(deadline_ns, generation, transaction)?;
            now = deadline_ns;
        }
        fail_ready_attempt(&mut exhausted, generation, transaction, now)?;
        now = now.saturating_add(2);
    }
    if !matches!(
        exhausted.state(),
        RestartState::PermanentFailure {
            cleanup: CleanupDisposition::Complete,
            ..
        }
    ) || exhausted.history().len() != 4
    {
        return Err(ModelError::UnexpectedFinalState);
    }
    Ok(())
}

fn fail_ready_attempt(
    supervisor: &mut RestartSupervisor,
    generation: u64,
    transaction: u64,
    now: u64,
) -> Result<(), RestartTransitionError> {
    supervisor.child_started(generation, transaction, now)?;
    supervisor.ready(generation, transaction, now + 1)?;
    supervisor.terminal(
        generation,
        transaction,
        now + 2,
        TerminalDisposition::NormalExit(1),
    )?;
    supervisor.cleanup_complete(generation, transaction, now + 3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_policy_engines_join_without_leaks_or_fifth_spawn() {
        prove_overload_replay_and_cleanup().unwrap();
        prove_restart_replacement_and_exhaustion().unwrap();
    }
}
