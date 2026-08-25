//! Fixed-capacity WYR0-I controller admission and replay accounting.
//!
//! This module accounts only for resources whose admission the Wyrmroot controller owns. It is
//! not a generic kernel quota controller and cannot contain resources a native peer can mint or
//! map directly through authority it already holds.

use core::sync::atomic::{AtomicU64, Ordering};
use deepwyrm_syscall::{DW_CHANNEL_MAX_HANDLES, DW_CHANNEL_MAX_PAYLOAD};

use crate::supervision::{AttemptRecord, CleanupDisposition};

static NEXT_CONTROLLER_ID: AtomicU64 = AtomicU64::new(1);

/// Maximum simultaneously admitted logical peer slots.
pub const MAX_ACCOUNTED_PEERS: usize = 4;
/// Maximum live transactions retained for one peer generation.
pub const MAX_LIVE_TRANSACTIONS_PER_PEER: usize = 4;
/// Maximum completed transaction IDs retained for replay rejection per peer generation.
pub const MAX_REPLAY_ENTRIES_PER_PEER: usize = 8;

/// Truthful enforcement classification used by WYR0-I certificates and consumers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnforcementClass {
    /// Existing Deepwyrm object/ABI semantics enforce the bound.
    Kernel,
    /// Wyrmroot enforces the bound because it owns admission/delegation.
    Wyrmroot,
    /// Current ABI cannot generically contain an arbitrary compromised native peer.
    Future,
}

/// Controller-owned resource classes tracked by the bounded ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AccountedResource {
    LiveProcessGenerations,
    InFlightTransactions,
    CompletedReplayEntries,
    RetainedMessages,
    RetainedPayloadBytes,
    DelegatedHandles,
    SharedMemoryObjects,
    SharedMemoryBytes,
    MappedBytes,
    WaitOperations,
    Events,
    Timers,
    RestartHistoryRecords,
}

impl AccountedResource {
    const COUNT: usize = 13;

    const ALL: [Self; Self::COUNT] = [
        Self::LiveProcessGenerations,
        Self::InFlightTransactions,
        Self::CompletedReplayEntries,
        Self::RetainedMessages,
        Self::RetainedPayloadBytes,
        Self::DelegatedHandles,
        Self::SharedMemoryObjects,
        Self::SharedMemoryBytes,
        Self::MappedBytes,
        Self::WaitOperations,
        Self::Events,
        Self::Timers,
        Self::RestartHistoryRecords,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    const fn managed(self) -> bool {
        matches!(
            self,
            Self::LiveProcessGenerations
                | Self::InFlightTransactions
                | Self::CompletedReplayEntries
                | Self::RestartHistoryRecords
        )
    }
}

/// One canonical per-peer and aggregate WYR0-I budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceBudget {
    pub resource: AccountedResource,
    pub per_peer: u64,
    pub aggregate: u64,
    pub enforcement: EnforcementClass,
}

/// Canonical controller-owned WYR0-I budgets from the reached capability contract.
pub const WYR0_I_RESOURCE_BUDGETS: [ResourceBudget; AccountedResource::COUNT] = [
    budget(AccountedResource::LiveProcessGenerations, 1, 4),
    budget(AccountedResource::InFlightTransactions, 4, 16),
    budget(AccountedResource::CompletedReplayEntries, 8, 32),
    budget(AccountedResource::RetainedMessages, 8, 32),
    budget(AccountedResource::RetainedPayloadBytes, 4096, 16384),
    budget(AccountedResource::DelegatedHandles, 8, 32),
    budget(AccountedResource::SharedMemoryObjects, 2, 8),
    budget(AccountedResource::SharedMemoryBytes, 8192, 32768),
    budget(AccountedResource::MappedBytes, 16384, 65536),
    budget(AccountedResource::WaitOperations, 4, 16),
    budget(AccountedResource::Events, 2, 8),
    budget(AccountedResource::Timers, 2, 8),
    budget(AccountedResource::RestartHistoryRecords, 4, 16),
];

const fn budget(resource: AccountedResource, per_peer: u64, aggregate: u64) -> ResourceBudget {
    ResourceBudget {
        resource,
        per_peer,
        aggregate,
        enforcement: EnforcementClass::Wyrmroot,
    }
}

/// Directly mintable resource families that remain future generic-containment work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenericContainmentGap {
    PeerCreatedMemoryObjects,
    PeerCreatedChannels,
    PeerCreatedEvents,
    PeerCreatedTimers,
    PeerHandleTableEntries,
    PeerCreatedMappings,
    PeerInitiatedWaits,
    TaskGroupResourceAndCpuQuotas,
}

impl GenericContainmentGap {
    /// These are explicit non-claims in WYR0-I.
    #[must_use]
    pub const fn enforcement(self) -> EnforcementClass {
        let _ = self;
        EnforcementClass::Future
    }
}

/// Multi-resource request checked and committed atomically.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReservationRequest {
    amounts: [u64; AccountedResource::COUNT],
}

impl ReservationRequest {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            amounts: [0; AccountedResource::COUNT],
        }
    }

    /// Adds an amount with checked arithmetic. Managed resources use their dedicated transitions.
    pub fn add(
        mut self,
        resource: AccountedResource,
        amount: u64,
    ) -> Result<Self, AccountingError> {
        if resource.managed() {
            return Err(AccountingError::ManagedResource(resource));
        }
        let slot = &mut self.amounts[resource.index()];
        *slot = slot
            .checked_add(amount)
            .ok_or(AccountingError::CounterOverflow)?;
        Ok(self)
    }

    #[must_use]
    pub const fn amount(&self, resource: AccountedResource) -> u64 {
        self.amounts[resource.index()]
    }

    fn is_empty(&self) -> bool {
        self.amounts.iter().all(|amount| *amount == 0)
    }
}

/// Reservation lifecycle owned by one non-cloneable token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationState {
    Reserved,
    Published,
    Released,
}

/// Exact affine reservation returned before a peer-visible operation is published.
#[derive(Debug, Eq, PartialEq)]
pub struct ReservationToken {
    controller_id: u64,
    peer: u8,
    generation: u64,
    amounts: [u64; AccountedResource::COUNT],
    state: ReservationState,
}

impl ReservationToken {
    #[must_use]
    pub const fn state(&self) -> ReservationState {
        self.state
    }

    #[must_use]
    pub const fn peer(&self) -> u8 {
        self.peer
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Affine identity for one live transaction admission.
#[derive(Debug, Eq, PartialEq)]
pub struct TransactionToken {
    controller_id: u64,
    peer: u8,
    generation: u64,
    transaction_id: u64,
    active: bool,
}

impl TransactionToken {
    #[must_use]
    pub const fn transaction_id(&self) -> u64 {
        self.transaction_id
    }
}

/// Snapshot returned when controller cleanup retires one generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationRetirement {
    released: [u64; AccountedResource::COUNT],
    preserved_restart_history: u64,
}

impl GenerationRetirement {
    #[must_use]
    pub const fn released(&self, resource: AccountedResource) -> u64 {
        self.released[resource.index()]
    }

    #[must_use]
    pub const fn preserved_restart_history(&self) -> u64 {
        self.preserved_restart_history
    }
}

/// Fail-closed accounting/admission result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountingError {
    ControllerIdExhausted,
    InvalidBudgetPolicy,
    InvalidPeer,
    ZeroGeneration,
    ZeroTransaction,
    PeerAlreadyActive,
    PeerInactive,
    GenerationNotAdvanced,
    StaleGeneration,
    EmptyReservation,
    ManagedResource(AccountedResource),
    PerPeerLimit(AccountedResource),
    AggregateLimit(AccountedResource),
    CounterOverflow,
    CounterUnderflow,
    TokenOriginMismatch,
    TokenAlreadyPublished,
    TokenAlreadyReleased,
    DuplicateTransaction,
    ReplayedTransaction,
    TransactionCapacity,
    TransactionTokenInactive,
    TransactionNotLive,
    KernelChannelEnvelope,
    EpisodeStillActive,
    RestartHistoryMismatch,
    TerminalRecordMissing,
    CleanupIncomplete,
    OutstandingGenerationResource(AccountedResource),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PeerAccounting {
    active: bool,
    generation: u64,
    counters: [u64; AccountedResource::COUNT],
    live_transactions: [u64; MAX_LIVE_TRANSACTIONS_PER_PEER],
    replay: [u64; MAX_REPLAY_ENTRIES_PER_PEER],
    replay_len: u8,
    replay_next: u8,
    last_history_generation: u64,
    terminal_generation: u64,
    terminal_cleanup_complete: bool,
}

impl PeerAccounting {
    const fn new() -> Self {
        Self {
            active: false,
            generation: 0,
            counters: [0; AccountedResource::COUNT],
            live_transactions: [0; MAX_LIVE_TRANSACTIONS_PER_PEER],
            replay: [0; MAX_REPLAY_ENTRIES_PER_PEER],
            replay_len: 0,
            replay_next: 0,
            last_history_generation: 0,
            terminal_generation: 0,
            terminal_cleanup_complete: false,
        }
    }

    fn replay_contains(&self, transaction_id: u64) -> bool {
        self.replay[..usize::from(self.replay_len)].contains(&transaction_id)
    }
}

/// Allocation-free readiness ledger for one controller instance.
#[derive(Debug, Eq, PartialEq)]
pub struct ReadinessAccounting {
    controller_id: u64,
    budgets: [ResourceBudget; AccountedResource::COUNT],
    peers: [PeerAccounting; MAX_ACCOUNTED_PEERS],
    aggregate: [u64; AccountedResource::COUNT],
}

impl ReadinessAccounting {
    pub fn new() -> Result<Self, AccountingError> {
        Self::with_budgets(WYR0_I_RESOURCE_BUDGETS)
    }

    /// Creates a reusable controller ledger with caller-selected bounded Wyrmroot budgets.
    pub fn with_budgets(
        budgets: [ResourceBudget; AccountedResource::COUNT],
    ) -> Result<Self, AccountingError> {
        for (index, policy) in budgets.iter().enumerate() {
            if policy.resource.index() != index
                || policy.per_peer == 0
                || policy.aggregate == 0
                || policy.per_peer > policy.aggregate
                || policy.aggregate > policy.per_peer.saturating_mul(MAX_ACCOUNTED_PEERS as u64)
                || policy.enforcement != EnforcementClass::Wyrmroot
            {
                return Err(AccountingError::InvalidBudgetPolicy);
            }
        }
        if budgets[AccountedResource::LiveProcessGenerations.index()].per_peer != 1
            || budgets[AccountedResource::InFlightTransactions.index()].per_peer
                > MAX_LIVE_TRANSACTIONS_PER_PEER as u64
            || budgets[AccountedResource::CompletedReplayEntries.index()].per_peer
                > MAX_REPLAY_ENTRIES_PER_PEER as u64
            || budgets[AccountedResource::RestartHistoryRecords.index()].per_peer > 4
        {
            return Err(AccountingError::InvalidBudgetPolicy);
        }
        let controller_id = allocate_controller_id()?;
        Ok(Self {
            controller_id,
            budgets,
            peers: [PeerAccounting::new(); MAX_ACCOUNTED_PEERS],
            aggregate: [0; AccountedResource::COUNT],
        })
    }

    /// Reserves the authoritative Process-generation slot before child publication.
    pub fn begin_generation(&mut self, peer: u8, generation: u64) -> Result<(), AccountingError> {
        if generation == 0 {
            return Err(AccountingError::ZeroGeneration);
        }
        let peer_index = peer_index(peer)?;
        let current = &self.peers[peer_index];
        if current.active {
            return Err(AccountingError::PeerAlreadyActive);
        }
        if generation <= current.generation {
            return Err(AccountingError::GenerationNotAdvanced);
        }

        let resource = AccountedResource::LiveProcessGenerations;
        let aggregate = checked_admit(
            self.aggregate[resource.index()],
            1,
            self.budget(resource).aggregate,
            AccountingError::AggregateLimit(resource),
        )?;
        let history = current.counters[AccountedResource::RestartHistoryRecords.index()];
        let last_history_generation = current.last_history_generation;
        let peer_state = &mut self.peers[peer_index];
        peer_state.active = true;
        peer_state.generation = generation;
        peer_state.counters = [0; AccountedResource::COUNT];
        peer_state.counters[AccountedResource::RestartHistoryRecords.index()] = history;
        peer_state.counters[resource.index()] = 1;
        peer_state.live_transactions = [0; MAX_LIVE_TRANSACTIONS_PER_PEER];
        peer_state.replay = [0; MAX_REPLAY_ENTRIES_PER_PEER];
        peer_state.replay_len = 0;
        peer_state.replay_next = 0;
        peer_state.last_history_generation = last_history_generation;
        peer_state.terminal_generation = 0;
        peer_state.terminal_cleanup_complete = false;
        self.aggregate[resource.index()] = aggregate;
        Ok(())
    }

    /// Checks all peer and aggregate counters before committing any reservation.
    pub fn reserve(
        &mut self,
        peer: u8,
        generation: u64,
        request: ReservationRequest,
    ) -> Result<ReservationToken, AccountingError> {
        if request.is_empty() {
            return Err(AccountingError::EmptyReservation);
        }
        let peer_index = self.validate_generation(peer, generation)?;
        let mut next_peer = self.peers[peer_index].counters;
        let mut next_aggregate = self.aggregate;
        for resource in AccountedResource::ALL {
            let amount = request.amount(resource);
            if amount == 0 {
                continue;
            }
            if resource.managed() {
                return Err(AccountingError::ManagedResource(resource));
            }
            let policy = self.budget(resource);
            next_peer[resource.index()] = checked_admit(
                next_peer[resource.index()],
                amount,
                policy.per_peer,
                AccountingError::PerPeerLimit(resource),
            )?;
            next_aggregate[resource.index()] = checked_admit(
                next_aggregate[resource.index()],
                amount,
                policy.aggregate,
                AccountingError::AggregateLimit(resource),
            )?;
        }

        self.peers[peer_index].counters = next_peer;
        self.aggregate = next_aggregate;
        Ok(ReservationToken {
            controller_id: self.controller_id,
            peer,
            generation,
            amounts: request.amounts,
            state: ReservationState::Reserved,
        })
    }

    /// Marks a successfully completed native operation as peer-visible.
    pub fn publish(&self, token: &mut ReservationToken) -> Result<(), AccountingError> {
        self.validate_reservation_token(token)?;
        match token.state {
            ReservationState::Reserved => token.state = ReservationState::Published,
            ReservationState::Published => return Err(AccountingError::TokenAlreadyPublished),
            ReservationState::Released => return Err(AccountingError::TokenAlreadyReleased),
        }
        Ok(())
    }

    /// Releases one exact reservation after rollback, completion, or peer cleanup.
    pub fn release(&mut self, token: &mut ReservationToken) -> Result<(), AccountingError> {
        self.validate_reservation_token(token)?;
        if token.state == ReservationState::Released {
            return Err(AccountingError::TokenAlreadyReleased);
        }
        let peer_index = self.validate_generation(token.peer, token.generation)?;
        let mut next_peer = self.peers[peer_index].counters;
        let mut next_aggregate = self.aggregate;
        for resource in AccountedResource::ALL {
            let amount = token.amounts[resource.index()];
            next_peer[resource.index()] = next_peer[resource.index()]
                .checked_sub(amount)
                .ok_or(AccountingError::CounterUnderflow)?;
            next_aggregate[resource.index()] = next_aggregate[resource.index()]
                .checked_sub(amount)
                .ok_or(AccountingError::CounterUnderflow)?;
        }
        self.peers[peer_index].counters = next_peer;
        self.aggregate = next_aggregate;
        token.state = ReservationState::Released;
        Ok(())
    }

    /// Admits a nonzero transaction ID only after duplicate/replay checks.
    pub fn begin_transaction(
        &mut self,
        peer: u8,
        generation: u64,
        transaction_id: u64,
    ) -> Result<TransactionToken, AccountingError> {
        if transaction_id == 0 {
            return Err(AccountingError::ZeroTransaction);
        }
        let peer_index = self.validate_generation(peer, generation)?;
        let peer_state = &self.peers[peer_index];
        if peer_state.live_transactions.contains(&transaction_id) {
            return Err(AccountingError::DuplicateTransaction);
        }
        if peer_state.replay_contains(transaction_id) {
            return Err(AccountingError::ReplayedTransaction);
        }
        let Some(live_slot) = peer_state
            .live_transactions
            .iter()
            .position(|candidate| *candidate == 0)
        else {
            return Err(AccountingError::TransactionCapacity);
        };
        let resource = AccountedResource::InFlightTransactions;
        let policy = self.budget(resource);
        let next_peer = checked_admit(
            peer_state.counters[resource.index()],
            1,
            policy.per_peer,
            AccountingError::PerPeerLimit(resource),
        )?;
        let next_aggregate = checked_admit(
            self.aggregate[resource.index()],
            1,
            policy.aggregate,
            AccountingError::AggregateLimit(resource),
        )?;
        self.peers[peer_index].counters[resource.index()] = next_peer;
        self.peers[peer_index].live_transactions[live_slot] = transaction_id;
        self.aggregate[resource.index()] = next_aggregate;
        Ok(TransactionToken {
            controller_id: self.controller_id,
            peer,
            generation,
            transaction_id,
            active: true,
        })
    }

    /// Completes one live transaction and moves its ID into the fixed replay FIFO.
    pub fn complete_transaction(
        &mut self,
        token: &mut TransactionToken,
    ) -> Result<(), AccountingError> {
        let peer_index = self.validate_transaction_token(token)?;
        let transaction_slot = self.peers[peer_index]
            .live_transactions
            .iter()
            .position(|candidate| *candidate == token.transaction_id)
            .ok_or(AccountingError::TransactionNotLive)?;
        let replay_resource = AccountedResource::CompletedReplayEntries;
        let in_flight_resource = AccountedResource::InFlightTransactions;
        let replay_capacity = usize::try_from(self.budget(replay_resource).per_peer)
            .map_err(|_| AccountingError::InvalidBudgetPolicy)?;
        let replay_grows = usize::from(self.peers[peer_index].replay_len) < replay_capacity;

        let next_peer_replay = if replay_grows {
            checked_admit(
                self.peers[peer_index].counters[replay_resource.index()],
                1,
                self.budget(replay_resource).per_peer,
                AccountingError::PerPeerLimit(replay_resource),
            )?
        } else {
            self.peers[peer_index].counters[replay_resource.index()]
        };
        let next_aggregate_replay = if replay_grows {
            checked_admit(
                self.aggregate[replay_resource.index()],
                1,
                self.budget(replay_resource).aggregate,
                AccountingError::AggregateLimit(replay_resource),
            )?
        } else {
            self.aggregate[replay_resource.index()]
        };
        let next_peer_in_flight = self.peers[peer_index].counters[in_flight_resource.index()]
            .checked_sub(1)
            .ok_or(AccountingError::CounterUnderflow)?;
        let next_aggregate_in_flight = self.aggregate[in_flight_resource.index()]
            .checked_sub(1)
            .ok_or(AccountingError::CounterUnderflow)?;

        let replay_slot = usize::from(self.peers[peer_index].replay_next);
        let peer_state = &mut self.peers[peer_index];
        peer_state.live_transactions[transaction_slot] = 0;
        peer_state.counters[in_flight_resource.index()] = next_peer_in_flight;
        peer_state.counters[replay_resource.index()] = next_peer_replay;
        peer_state.replay[replay_slot] = token.transaction_id;
        peer_state.replay_next = ((replay_slot + 1) % replay_capacity) as u8;
        if replay_grows {
            peer_state.replay_len += 1;
        }
        self.aggregate[in_flight_resource.index()] = next_aggregate_in_flight;
        self.aggregate[replay_resource.index()] = next_aggregate_replay;
        token.active = false;
        Ok(())
    }

    /// Rolls back one live transaction without adding replay state.
    pub fn abort_transaction(
        &mut self,
        token: &mut TransactionToken,
    ) -> Result<(), AccountingError> {
        let peer_index = self.validate_transaction_token(token)?;
        let transaction_slot = self.peers[peer_index]
            .live_transactions
            .iter()
            .position(|candidate| *candidate == token.transaction_id)
            .ok_or(AccountingError::TransactionNotLive)?;
        let resource = AccountedResource::InFlightTransactions;
        let next_peer = self.peers[peer_index].counters[resource.index()]
            .checked_sub(1)
            .ok_or(AccountingError::CounterUnderflow)?;
        let next_aggregate = self.aggregate[resource.index()]
            .checked_sub(1)
            .ok_or(AccountingError::CounterUnderflow)?;
        self.peers[peer_index].live_transactions[transaction_slot] = 0;
        self.peers[peer_index].counters[resource.index()] = next_peer;
        self.aggregate[resource.index()] = next_aggregate;
        token.active = false;
        Ok(())
    }

    /// Mirrors one I-C terminal history record without duplicating I-C restart policy.
    pub fn record_restart_history(
        &mut self,
        peer: u8,
        generation: u64,
        record: &AttemptRecord,
    ) -> Result<(), AccountingError> {
        let peer_index = self.validate_generation(peer, generation)?;
        let current_count =
            self.peers[peer_index].counters[AccountedResource::RestartHistoryRecords.index()];
        let expected_attempt = current_count
            .checked_add(1)
            .ok_or(AccountingError::CounterOverflow)?;
        if record.generation != generation
            || u64::from(record.attempt) != expected_attempt
            || generation <= self.peers[peer_index].last_history_generation
        {
            return Err(AccountingError::RestartHistoryMismatch);
        }
        let resource = AccountedResource::RestartHistoryRecords;
        let policy = self.budget(resource);
        let next_peer = checked_admit(
            self.peers[peer_index].counters[resource.index()],
            1,
            policy.per_peer,
            AccountingError::PerPeerLimit(resource),
        )?;
        let next_aggregate = checked_admit(
            self.aggregate[resource.index()],
            1,
            policy.aggregate,
            AccountingError::AggregateLimit(resource),
        )?;
        self.peers[peer_index].counters[resource.index()] = next_peer;
        self.peers[peer_index].last_history_generation = generation;
        self.peers[peer_index].terminal_generation = generation;
        self.peers[peer_index].terminal_cleanup_complete =
            record.cleanup == CleanupDisposition::Complete;
        self.aggregate[resource.index()] = next_aggregate;
        Ok(())
    }

    /// Retires one generation after native resource cleanup, releasing per-generation ledger state.
    pub fn retire_generation(
        &mut self,
        peer: u8,
        generation: u64,
    ) -> Result<GenerationRetirement, AccountingError> {
        let peer_index = self.validate_generation(peer, generation)?;
        if self.peers[peer_index].terminal_generation != generation {
            return Err(AccountingError::TerminalRecordMissing);
        }
        if !self.peers[peer_index].terminal_cleanup_complete {
            return Err(AccountingError::CleanupIncomplete);
        }
        for resource in AccountedResource::ALL {
            if !matches!(
                resource,
                AccountedResource::LiveProcessGenerations
                    | AccountedResource::CompletedReplayEntries
                    | AccountedResource::RestartHistoryRecords
            ) && self.peers[peer_index].counters[resource.index()] != 0
            {
                return Err(AccountingError::OutstandingGenerationResource(resource));
            }
        }
        let history_index = AccountedResource::RestartHistoryRecords.index();
        let history = self.peers[peer_index].counters[history_index];
        let mut released = self.peers[peer_index].counters;
        released[history_index] = 0;

        let mut next_aggregate = self.aggregate;
        for resource in AccountedResource::ALL {
            if resource == AccountedResource::RestartHistoryRecords {
                continue;
            }
            next_aggregate[resource.index()] = next_aggregate[resource.index()]
                .checked_sub(released[resource.index()])
                .ok_or(AccountingError::CounterUnderflow)?;
        }

        let peer_state = &mut self.peers[peer_index];
        peer_state.active = false;
        peer_state.counters = [0; AccountedResource::COUNT];
        peer_state.counters[history_index] = history;
        peer_state.live_transactions = [0; MAX_LIVE_TRANSACTIONS_PER_PEER];
        peer_state.replay = [0; MAX_REPLAY_ENTRIES_PER_PEER];
        peer_state.replay_len = 0;
        peer_state.replay_next = 0;
        peer_state.terminal_generation = 0;
        peer_state.terminal_cleanup_complete = false;
        self.aggregate = next_aggregate;
        Ok(GenerationRetirement {
            released,
            preserved_restart_history: history,
        })
    }

    /// Releases episode-scoped restart history after the peer has no active generation.
    pub fn finish_restart_episode(&mut self, peer: u8) -> Result<u64, AccountingError> {
        let peer_index = peer_index(peer)?;
        if self.peers[peer_index].active {
            return Err(AccountingError::EpisodeStillActive);
        }
        let resource = AccountedResource::RestartHistoryRecords;
        let history = self.peers[peer_index].counters[resource.index()];
        let next_aggregate = self.aggregate[resource.index()]
            .checked_sub(history)
            .ok_or(AccountingError::CounterUnderflow)?;
        self.peers[peer_index].counters[resource.index()] = 0;
        self.peers[peer_index].last_history_generation = 0;
        self.aggregate[resource.index()] = next_aggregate;
        Ok(history)
    }

    #[must_use]
    pub fn peer_count(&self, peer: u8, resource: AccountedResource) -> Option<u64> {
        self.peers
            .get(usize::from(peer))
            .map(|state| state.counters[resource.index()])
    }

    #[must_use]
    pub const fn aggregate_count(&self, resource: AccountedResource) -> u64 {
        self.aggregate[resource.index()]
    }

    fn validate_generation(&self, peer: u8, generation: u64) -> Result<usize, AccountingError> {
        if generation == 0 {
            return Err(AccountingError::ZeroGeneration);
        }
        let peer_index = peer_index(peer)?;
        let peer_state = &self.peers[peer_index];
        if !peer_state.active {
            return Err(AccountingError::PeerInactive);
        }
        if generation != peer_state.generation {
            return Err(AccountingError::StaleGeneration);
        }
        Ok(peer_index)
    }

    const fn budget(&self, resource: AccountedResource) -> ResourceBudget {
        self.budgets[resource.index()]
    }

    fn validate_reservation_token(&self, token: &ReservationToken) -> Result<(), AccountingError> {
        if token.controller_id != self.controller_id {
            return Err(AccountingError::TokenOriginMismatch);
        }
        if token.state == ReservationState::Released {
            return Err(AccountingError::TokenAlreadyReleased);
        }
        self.validate_generation(token.peer, token.generation)?;
        Ok(())
    }

    fn validate_transaction_token(
        &self,
        token: &TransactionToken,
    ) -> Result<usize, AccountingError> {
        if token.controller_id != self.controller_id {
            return Err(AccountingError::TokenOriginMismatch);
        }
        if !token.active {
            return Err(AccountingError::TransactionTokenInactive);
        }
        self.validate_generation(token.peer, token.generation)
    }
}

/// Validates kernel-owned per-datagram limits using generated Deepwyrm constants.
pub fn validate_kernel_channel_envelope(
    payload_bytes: u64,
    handles: u64,
) -> Result<(), AccountingError> {
    if payload_bytes > u64::from(DW_CHANNEL_MAX_PAYLOAD)
        || handles > u64::from(DW_CHANNEL_MAX_HANDLES)
    {
        Err(AccountingError::KernelChannelEnvelope)
    } else {
        Ok(())
    }
}

/// Classification for the generated per-datagram bounds checked above.
#[must_use]
pub const fn kernel_channel_enforcement() -> EnforcementClass {
    EnforcementClass::Kernel
}

fn checked_admit(
    current: u64,
    amount: u64,
    limit: u64,
    over_limit: AccountingError,
) -> Result<u64, AccountingError> {
    let next = current
        .checked_add(amount)
        .ok_or(AccountingError::CounterOverflow)?;
    if next > limit {
        Err(over_limit)
    } else {
        Ok(next)
    }
}

fn allocate_controller_id() -> Result<u64, AccountingError> {
    NEXT_CONTROLLER_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| AccountingError::ControllerIdExhausted)
}

fn peer_index(peer: u8) -> Result<usize, AccountingError> {
    let index = usize::from(peer);
    if index < MAX_ACCOUNTED_PEERS {
        Ok(index)
    } else {
        Err(AccountingError::InvalidPeer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervision::AttemptFailure;

    fn accounting() -> ReadinessAccounting {
        ReadinessAccounting::new().unwrap()
    }

    fn request(resource: AccountedResource, amount: u64) -> ReservationRequest {
        ReservationRequest::empty().add(resource, amount).unwrap()
    }

    fn attempt_record(attempt: u8, generation: u64) -> AttemptRecord {
        AttemptRecord {
            attempt,
            generation,
            transaction_id: u64::from(attempt) + 10,
            started_at_ns: u64::from(attempt),
            terminal_at_ns: u64::from(attempt) + 1,
            failure: AttemptFailure::MalformedReady,
            cleanup: CleanupDisposition::Complete,
        }
    }

    #[test]
    fn canonical_budgets_and_enforcement_truth_are_exact() {
        assert_eq!(WYR0_I_RESOURCE_BUDGETS.len(), AccountedResource::COUNT);
        for (index, policy) in WYR0_I_RESOURCE_BUDGETS.iter().enumerate() {
            assert_eq!(policy.resource.index(), index);
            assert_eq!(policy.enforcement, EnforcementClass::Wyrmroot);
        }
        assert_eq!(
            GenericContainmentGap::PeerCreatedMemoryObjects.enforcement(),
            EnforcementClass::Future
        );
        assert_eq!(kernel_channel_enforcement(), EnforcementClass::Kernel);
        assert_eq!(
            validate_kernel_channel_envelope(
                u64::from(DW_CHANNEL_MAX_PAYLOAD),
                u64::from(DW_CHANNEL_MAX_HANDLES)
            ),
            Ok(())
        );
        assert_eq!(
            validate_kernel_channel_envelope(u64::from(DW_CHANNEL_MAX_PAYLOAD) + 1, 0),
            Err(AccountingError::KernelChannelEnvelope)
        );
        assert_eq!(
            validate_kernel_channel_envelope(0, u64::from(DW_CHANNEL_MAX_HANDLES) + 1),
            Err(AccountingError::KernelChannelEnvelope)
        );
    }

    #[test]
    fn exact_peer_limit_succeeds_and_one_over_is_atomic() {
        let mut ledger = accounting();
        ledger.begin_generation(0, 1).unwrap();
        let mut exact = ledger
            .reserve(0, 1, request(AccountedResource::RetainedPayloadBytes, 4096))
            .unwrap();
        assert_eq!(
            ledger.reserve(0, 1, request(AccountedResource::RetainedPayloadBytes, 1)),
            Err(AccountingError::PerPeerLimit(
                AccountedResource::RetainedPayloadBytes
            ))
        );
        assert_eq!(
            ledger.peer_count(0, AccountedResource::RetainedPayloadBytes),
            Some(4096)
        );
        assert_eq!(
            ledger.aggregate_count(AccountedResource::RetainedPayloadBytes),
            4096
        );
        ledger.release(&mut exact).unwrap();
    }

    #[test]
    fn aggregate_limit_rejects_without_partial_peer_publication() {
        let mut budgets = WYR0_I_RESOURCE_BUDGETS;
        budgets[AccountedResource::RetainedMessages.index()].per_peer = 2;
        budgets[AccountedResource::RetainedMessages.index()].aggregate = 2;
        let mut ledger = ReadinessAccounting::with_budgets(budgets).unwrap();
        for peer in 0..3 {
            ledger.begin_generation(peer, 1).unwrap();
        }
        let mut first = ledger
            .reserve(0, 1, request(AccountedResource::RetainedMessages, 1))
            .unwrap();
        let mut second = ledger
            .reserve(1, 1, request(AccountedResource::RetainedMessages, 1))
            .unwrap();
        assert_eq!(
            ledger.reserve(2, 1, request(AccountedResource::RetainedMessages, 1)),
            Err(AccountingError::AggregateLimit(
                AccountedResource::RetainedMessages
            ))
        );
        assert_eq!(
            ledger.peer_count(2, AccountedResource::RetainedMessages),
            Some(0)
        );
        assert_eq!(
            ledger.aggregate_count(AccountedResource::RetainedMessages),
            2
        );
        for token in [&mut first, &mut second] {
            ledger.release(token).unwrap();
        }
    }

    #[test]
    fn multi_resource_reservation_is_all_or_none() {
        let mut ledger = accounting();
        ledger.begin_generation(0, 1).unwrap();
        let request = ReservationRequest::empty()
            .add(AccountedResource::RetainedMessages, 1)
            .unwrap()
            .add(AccountedResource::RetainedPayloadBytes, 4097)
            .unwrap();
        assert_eq!(
            ledger.reserve(0, 1, request),
            Err(AccountingError::PerPeerLimit(
                AccountedResource::RetainedPayloadBytes
            ))
        );
        assert_eq!(
            ledger.peer_count(0, AccountedResource::RetainedMessages),
            Some(0)
        );
        assert_eq!(
            ledger.aggregate_count(AccountedResource::RetainedMessages),
            0
        );
    }

    #[test]
    fn multi_resource_aggregate_failure_does_not_commit_earlier_resources() {
        let mut budgets = WYR0_I_RESOURCE_BUDGETS;
        budgets[AccountedResource::RetainedMessages.index()].per_peer = 1;
        budgets[AccountedResource::RetainedMessages.index()].aggregate = 1;
        budgets[AccountedResource::DelegatedHandles.index()].per_peer = 1;
        budgets[AccountedResource::DelegatedHandles.index()].aggregate = 1;
        let mut ledger = ReadinessAccounting::with_budgets(budgets).unwrap();
        ledger.begin_generation(0, 1).unwrap();
        ledger.begin_generation(1, 1).unwrap();
        let mut prefilled = ledger
            .reserve(0, 1, request(AccountedResource::DelegatedHandles, 1))
            .unwrap();
        let combined = ReservationRequest::empty()
            .add(AccountedResource::RetainedMessages, 1)
            .unwrap()
            .add(AccountedResource::DelegatedHandles, 1)
            .unwrap();

        assert_eq!(
            ledger.reserve(1, 1, combined),
            Err(AccountingError::AggregateLimit(
                AccountedResource::DelegatedHandles
            ))
        );
        assert_eq!(
            ledger.peer_count(1, AccountedResource::RetainedMessages),
            Some(0)
        );
        assert_eq!(
            ledger.aggregate_count(AccountedResource::RetainedMessages),
            0
        );
        ledger.release(&mut prefilled).unwrap();
    }

    #[test]
    fn reservation_publish_and_release_are_exactly_once_and_origin_bound() {
        let mut ledger = accounting();
        ledger.begin_generation(0, 1).unwrap();
        let mut token = ledger
            .reserve(0, 1, request(AccountedResource::DelegatedHandles, 2))
            .unwrap();
        ledger.publish(&mut token).unwrap();
        assert_eq!(
            ledger.publish(&mut token),
            Err(AccountingError::TokenAlreadyPublished)
        );
        let mut other = ReadinessAccounting::new().unwrap();
        other.begin_generation(0, 1).unwrap();
        assert_eq!(
            other.release(&mut token),
            Err(AccountingError::TokenOriginMismatch)
        );
        ledger.release(&mut token).unwrap();
        assert_eq!(
            ledger.release(&mut token),
            Err(AccountingError::TokenAlreadyReleased)
        );

        let mut transaction = ledger.begin_transaction(0, 1, 44).unwrap();
        assert_eq!(
            other.complete_transaction(&mut transaction),
            Err(AccountingError::TokenOriginMismatch)
        );
        ledger.abort_transaction(&mut transaction).unwrap();
    }

    #[test]
    fn release_underflow_is_all_or_none() {
        let mut ledger = accounting();
        ledger.begin_generation(0, 1).unwrap();
        let mut token = ledger
            .reserve(0, 1, request(AccountedResource::RetainedMessages, 1))
            .unwrap();
        ledger.aggregate[AccountedResource::RetainedMessages.index()] = 0;
        assert_eq!(
            ledger.release(&mut token),
            Err(AccountingError::CounterUnderflow)
        );
        assert_eq!(token.state(), ReservationState::Reserved);
        assert_eq!(
            ledger.peer_count(0, AccountedResource::RetainedMessages),
            Some(1)
        );
        ledger.aggregate[AccountedResource::RetainedMessages.index()] = 1;
        ledger.release(&mut token).unwrap();
    }

    #[test]
    fn would_block_rollback_releases_message_bytes_and_handles_once() {
        let mut ledger = accounting();
        ledger.begin_generation(0, 1).unwrap();
        let send = ReservationRequest::empty()
            .add(AccountedResource::RetainedMessages, 1)
            .unwrap()
            .add(AccountedResource::RetainedPayloadBytes, 64)
            .unwrap()
            .add(AccountedResource::DelegatedHandles, 2)
            .unwrap();
        let mut token = ledger.reserve(0, 1, send).unwrap();
        assert_eq!(token.state(), ReservationState::Reserved);
        ledger.release(&mut token).unwrap();
        for resource in [
            AccountedResource::RetainedMessages,
            AccountedResource::RetainedPayloadBytes,
            AccountedResource::DelegatedHandles,
        ] {
            assert_eq!(ledger.peer_count(0, resource), Some(0));
            assert_eq!(ledger.aggregate_count(resource), 0);
        }
    }

    #[test]
    fn duplicate_and_replayed_transactions_do_not_allocate() {
        let mut ledger = accounting();
        ledger.begin_generation(0, 1).unwrap();
        let mut transaction = ledger.begin_transaction(0, 1, 9).unwrap();
        assert_eq!(
            ledger.begin_transaction(0, 1, 9),
            Err(AccountingError::DuplicateTransaction)
        );
        ledger.complete_transaction(&mut transaction).unwrap();
        assert_eq!(
            ledger.begin_transaction(0, 1, 9),
            Err(AccountingError::ReplayedTransaction)
        );
        assert_eq!(
            ledger.aggregate_count(AccountedResource::InFlightTransactions),
            0
        );
        assert_eq!(
            ledger.aggregate_count(AccountedResource::CompletedReplayEntries),
            1
        );
    }

    #[test]
    fn aborted_transaction_releases_once_without_creating_replay() {
        let mut ledger = accounting();
        ledger.begin_generation(0, 1).unwrap();
        let mut token = ledger.begin_transaction(0, 1, 9).unwrap();
        ledger.abort_transaction(&mut token).unwrap();
        assert_eq!(
            ledger.abort_transaction(&mut token),
            Err(AccountingError::TransactionTokenInactive)
        );
        assert_eq!(
            ledger.aggregate_count(AccountedResource::InFlightTransactions),
            0
        );
        assert_eq!(
            ledger.aggregate_count(AccountedResource::CompletedReplayEntries),
            0
        );
        assert_eq!(
            ledger.begin_transaction(0, 1, 9).unwrap().transaction_id(),
            9
        );
    }

    #[test]
    fn replay_fifo_evicts_oldest_at_fixed_capacity() {
        let mut ledger = accounting();
        ledger.begin_generation(0, 1).unwrap();
        for transaction_id in 1..=9 {
            let mut token = ledger.begin_transaction(0, 1, transaction_id).unwrap();
            ledger.complete_transaction(&mut token).unwrap();
        }
        assert_eq!(
            ledger.aggregate_count(AccountedResource::CompletedReplayEntries),
            8
        );
        let mut oldest = ledger.begin_transaction(0, 1, 1).unwrap();
        assert_eq!(oldest.transaction_id(), 1);
        assert_eq!(
            ledger.begin_transaction(0, 1, 2),
            Err(AccountingError::ReplayedTransaction)
        );
        ledger.complete_transaction(&mut oldest).unwrap();
        assert_eq!(
            ledger.begin_transaction(0, 1, 1),
            Err(AccountingError::ReplayedTransaction)
        );
        assert_eq!(
            ledger.begin_transaction(0, 1, 2).unwrap().transaction_id(),
            2
        );
    }

    #[test]
    fn replay_aggregate_failure_preserves_live_transaction_for_rollback() {
        let mut budgets = WYR0_I_RESOURCE_BUDGETS;
        budgets[AccountedResource::CompletedReplayEntries.index()].per_peer = 1;
        budgets[AccountedResource::CompletedReplayEntries.index()].aggregate = 1;
        let mut ledger = ReadinessAccounting::with_budgets(budgets).unwrap();
        ledger.begin_generation(0, 1).unwrap();
        ledger.begin_generation(1, 1).unwrap();
        let mut first = ledger.begin_transaction(0, 1, 1).unwrap();
        ledger.complete_transaction(&mut first).unwrap();
        let mut blocked = ledger.begin_transaction(1, 1, 2).unwrap();

        assert_eq!(
            ledger.complete_transaction(&mut blocked),
            Err(AccountingError::AggregateLimit(
                AccountedResource::CompletedReplayEntries
            ))
        );
        assert_eq!(
            ledger.aggregate_count(AccountedResource::InFlightTransactions),
            1
        );
        ledger.abort_transaction(&mut blocked).unwrap();
        assert_eq!(
            ledger.aggregate_count(AccountedResource::InFlightTransactions),
            0
        );
    }

    #[test]
    fn outstanding_transaction_blocks_retirement_before_replacement_generation() {
        let mut ledger = accounting();
        ledger.begin_generation(0, 1).unwrap();
        let mut transaction = ledger.begin_transaction(0, 1, 9).unwrap();
        ledger
            .record_restart_history(0, 1, &attempt_record(1, 1))
            .unwrap();
        assert_eq!(
            ledger.retire_generation(0, 1),
            Err(AccountingError::OutstandingGenerationResource(
                AccountedResource::InFlightTransactions
            ))
        );
        ledger.abort_transaction(&mut transaction).unwrap();
        ledger.retire_generation(0, 1).unwrap();
        ledger.begin_generation(0, 2).unwrap();
        assert_eq!(
            ledger.begin_transaction(0, 2, 9).unwrap().transaction_id(),
            9
        );
    }

    #[test]
    fn terminal_record_and_complete_cleanup_are_required_for_retirement() {
        let mut missing = accounting();
        missing.begin_generation(0, 1).unwrap();
        assert_eq!(
            missing.retire_generation(0, 1),
            Err(AccountingError::TerminalRecordMissing)
        );

        let mut failed = accounting();
        failed.begin_generation(0, 1).unwrap();
        let mut record = attempt_record(1, 1);
        record.cleanup = CleanupDisposition::Failed;
        failed.record_restart_history(0, 1, &record).unwrap();
        assert_eq!(
            failed.retire_generation(0, 1),
            Err(AccountingError::CleanupIncomplete)
        );
    }

    #[test]
    fn peer_retirement_releases_generation_state_once_and_replacement_is_fresh() {
        let mut ledger = accounting();
        ledger.begin_generation(0, 1).unwrap();
        let mut retained = ledger
            .reserve(0, 1, request(AccountedResource::MappedBytes, 4096))
            .unwrap();
        let mut transaction = ledger.begin_transaction(0, 1, 7).unwrap();
        ledger.complete_transaction(&mut transaction).unwrap();
        ledger
            .record_restart_history(0, 1, &attempt_record(1, 1))
            .unwrap();
        assert_eq!(
            ledger.retire_generation(0, 1),
            Err(AccountingError::OutstandingGenerationResource(
                AccountedResource::MappedBytes
            ))
        );
        ledger.release(&mut retained).unwrap();
        let report = ledger.retire_generation(0, 1).unwrap();
        assert_eq!(report.released(AccountedResource::MappedBytes), 0);
        assert_eq!(
            report.released(AccountedResource::CompletedReplayEntries),
            1
        );
        assert_eq!(report.preserved_restart_history(), 1);
        assert_eq!(
            ledger.retire_generation(0, 1),
            Err(AccountingError::PeerInactive)
        );
        ledger.begin_generation(0, 2).unwrap();
        let replacement = ledger.begin_transaction(0, 2, 7).unwrap();
        assert_eq!(replacement.transaction_id(), 7);
        assert_eq!(
            ledger.peer_count(0, AccountedResource::RestartHistoryRecords),
            Some(1)
        );
    }

    #[test]
    fn restart_history_is_episode_scoped_bounded_and_aggregate() {
        let mut ledger = accounting();
        for peer in 0..4 {
            for generation in 1..=4 {
                ledger.begin_generation(peer, generation).unwrap();
                ledger
                    .record_restart_history(
                        peer,
                        generation,
                        &attempt_record(u8::try_from(generation).unwrap(), generation),
                    )
                    .unwrap();
                if generation < 4 {
                    ledger.retire_generation(peer, generation).unwrap();
                }
            }
            assert_eq!(
                ledger.record_restart_history(peer, 4, &attempt_record(4, 4)),
                Err(AccountingError::RestartHistoryMismatch)
            );
        }
        assert_eq!(
            ledger.aggregate_count(AccountedResource::RestartHistoryRecords),
            16
        );
        for peer in 0..4 {
            ledger.retire_generation(peer, 4).unwrap();
            assert_eq!(ledger.finish_restart_episode(peer).unwrap(), 4);
        }
        assert_eq!(
            ledger.aggregate_count(AccountedResource::RestartHistoryRecords),
            0
        );
    }

    #[test]
    fn overflow_empty_managed_and_invalid_identity_fail_closed() {
        let mut invalid_budgets = WYR0_I_RESOURCE_BUDGETS;
        invalid_budgets[0].aggregate = 0;
        assert_eq!(
            ReadinessAccounting::with_budgets(invalid_budgets),
            Err(AccountingError::InvalidBudgetPolicy)
        );
        let mut impossible_budgets = WYR0_I_RESOURCE_BUDGETS;
        impossible_budgets[AccountedResource::InFlightTransactions.index()].per_peer = 5;
        assert_eq!(
            ReadinessAccounting::with_budgets(impossible_budgets),
            Err(AccountingError::InvalidBudgetPolicy)
        );
        let mut ledger = accounting();
        assert_eq!(
            ledger.begin_generation(4, 1),
            Err(AccountingError::InvalidPeer)
        );
        ledger.begin_generation(0, 1).unwrap();
        assert_eq!(
            ledger.begin_generation(0, 2),
            Err(AccountingError::PeerAlreadyActive)
        );
        assert_eq!(
            ledger.reserve(0, 1, ReservationRequest::empty()),
            Err(AccountingError::EmptyReservation)
        );
        assert_eq!(
            ReservationRequest::empty().add(AccountedResource::InFlightTransactions, 1),
            Err(AccountingError::ManagedResource(
                AccountedResource::InFlightTransactions
            ))
        );
        assert_eq!(
            ReservationRequest::empty()
                .add(AccountedResource::MappedBytes, u64::MAX)
                .unwrap()
                .add(AccountedResource::MappedBytes, 1),
            Err(AccountingError::CounterOverflow)
        );

        let mut overflow_budgets = WYR0_I_RESOURCE_BUDGETS;
        overflow_budgets[AccountedResource::MappedBytes.index()].per_peer = u64::MAX;
        overflow_budgets[AccountedResource::MappedBytes.index()].aggregate = u64::MAX;
        let mut overflow_ledger = ReadinessAccounting::with_budgets(overflow_budgets).unwrap();
        overflow_ledger.begin_generation(0, 1).unwrap();
        let mut one = overflow_ledger
            .reserve(0, 1, request(AccountedResource::MappedBytes, 1))
            .unwrap();
        assert_eq!(
            overflow_ledger.reserve(0, 1, request(AccountedResource::MappedBytes, u64::MAX)),
            Err(AccountingError::CounterOverflow)
        );
        assert_eq!(
            overflow_ledger.peer_count(0, AccountedResource::MappedBytes),
            Some(1)
        );
        overflow_ledger.release(&mut one).unwrap();
    }
}
