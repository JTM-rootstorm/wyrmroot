// SPDX-License-Identifier: GPL-3.0-or-later
//! Pure E0B ownership model for one transactional Wyrmsh launch generation.
//!
//! This is design evidence only. It deliberately does not implement WRLJ,
//! WRLP, WRCN, loader, registry, or supervisor production behavior.

use std::collections::{BTreeMap, BTreeSet};
use wyrmroot_launch_proto as _;

const MAX_FAILED_GENERATIONS: u8 = 4;
const MAX_METADATA_PAGES: u16 = 16;
const MAX_METADATA_RECORDS: u16 = 32;
const MAX_REGISTRY_ENDPOINTS: usize = 64;
const MAX_REGISTRY_CLIENTS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ResourceId(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StreamRole {
    Stdin,
    Stdout,
    Stderr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EndpointRole {
    ConsolePeer(StreamRole),
    ShellStream(StreamRole),
    ConsoleStatus,
    ShellStatus,
    Registry,
    RegistryClient,
    ShellJobsController,
    ShellJobsClient,
    ReadyController,
    ReadyChild,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResourceKind {
    Endpoint(EndpointRole),
    OuterReservation,
    Process,
    TaskGroup,
}

impl ResourceKind {
    const fn tag(self) -> u64 {
        match self {
            Self::Endpoint(_) => 1,
            Self::OuterReservation => 2,
            Self::Process => 3,
            Self::TaskGroup => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Owner {
    Consoled(u64),
    Init,
    Registryd(u64),
    LaunchController(u64),
    Shell(u64),
    Closed,
    Reaped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Resource {
    kind: ResourceKind,
    owner: Owner,
    close_count: u8,
    reap_count: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelError {
    AlreadyClosed,
    AlreadyReaped,
    CleanupBlocked,
    Exhausted,
    Identity,
    Ownership,
    Stale,
    WrongState,
}

#[derive(Debug, Default)]
struct Ledger {
    next: BTreeMap<u64, u64>,
    resources: BTreeMap<ResourceId, Resource>,
}

impl Ledger {
    fn create(&mut self, kind: ResourceKind, owner: Owner) -> Result<ResourceId, ModelError> {
        let serial = self.next.entry(kind.tag()).or_insert(0);
        *serial = serial.checked_add(1).ok_or(ModelError::Identity)?;
        let raw = kind
            .tag()
            .checked_mul(1_000_000)
            .and_then(|prefix| prefix.checked_add(*serial))
            .ok_or(ModelError::Identity)?;
        if raw == 0 {
            return Err(ModelError::Identity);
        }
        let id = ResourceId(raw);
        if self
            .resources
            .insert(
                id,
                Resource {
                    kind,
                    owner,
                    close_count: 0,
                    reap_count: 0,
                },
            )
            .is_some()
        {
            return Err(ModelError::Identity);
        }
        Ok(id)
    }

    fn owner(&self, id: ResourceId) -> Result<Owner, ModelError> {
        self.resources
            .get(&id)
            .map(|resource| resource.owner)
            .ok_or(ModelError::Identity)
    }

    fn move_atomic(
        &mut self,
        ids: &[ResourceId],
        from: Owner,
        to: Owner,
    ) -> Result<(), ModelError> {
        let unique = ids.iter().copied().collect::<BTreeSet<_>>();
        if ids.is_empty() || unique.len() != ids.len() || from == to {
            return Err(ModelError::Identity);
        }
        for id in ids {
            let resource = self.resources.get(id).ok_or(ModelError::Identity)?;
            if resource.owner != from || resource.close_count != 0 || resource.reap_count != 0 {
                return Err(ModelError::Ownership);
            }
        }
        for id in ids {
            self.resources.get_mut(id).unwrap().owner = to;
        }
        Ok(())
    }

    fn close(&mut self, id: ResourceId, owner: Owner) -> Result<(), ModelError> {
        let resource = self.resources.get_mut(&id).ok_or(ModelError::Identity)?;
        if resource.close_count != 0 || resource.owner == Owner::Closed {
            return Err(ModelError::AlreadyClosed);
        }
        if resource.reap_count != 0 || resource.owner == Owner::Reaped {
            return Err(ModelError::AlreadyReaped);
        }
        if resource.owner != owner {
            return Err(ModelError::Ownership);
        }
        if matches!(
            resource.kind,
            ResourceKind::Process | ResourceKind::TaskGroup
        ) {
            return Err(ModelError::WrongState);
        }
        resource.close_count = resource.close_count.checked_add(1).unwrap();
        resource.owner = Owner::Closed;
        Ok(())
    }

    fn reap(&mut self, id: ResourceId, owner: Owner) -> Result<(), ModelError> {
        let resource = self.resources.get_mut(&id).ok_or(ModelError::Identity)?;
        if resource.reap_count != 0 || resource.owner == Owner::Reaped {
            return Err(ModelError::AlreadyReaped);
        }
        if resource.close_count != 0 || resource.owner == Owner::Closed {
            return Err(ModelError::AlreadyClosed);
        }
        if resource.owner != owner {
            return Err(ModelError::Ownership);
        }
        if !matches!(
            resource.kind,
            ResourceKind::Process | ResourceKind::TaskGroup
        ) {
            return Err(ModelError::WrongState);
        }
        resource.reap_count = resource.reap_count.checked_add(1).unwrap();
        resource.owner = Owner::Reaped;
        Ok(())
    }

    fn resource(&self, id: ResourceId) -> Resource {
        *self.resources.get(&id).unwrap()
    }

    fn assert_exact_accounting(&self) {
        for resource in self.resources.values() {
            match resource.kind {
                ResourceKind::Process | ResourceKind::TaskGroup => {
                    assert_eq!(resource.owner, Owner::Reaped);
                    assert_eq!(resource.close_count, 0);
                    assert_eq!(resource.reap_count, 1);
                }
                ResourceKind::Endpoint(_) | ResourceKind::OuterReservation => {
                    assert_eq!(resource.owner, Owner::Closed);
                    assert_eq!(resource.close_count, 1);
                    assert_eq!(resource.reap_count, 0);
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GenerationIds {
    shell: u64,
    console: u64,
    status: u64,
    registry_generation: u64,
    registry_endpoint: u64,
    registry_endpoint_generation: u64,
    launch_connection: u64,
    launch_generation: u64,
    outer_connection: u64,
    outer_connection_generation: u64,
    outer_transaction: u64,
    wrlp_transaction: u64,
}

impl GenerationIds {
    fn new(
        seed: u64,
        registry_generation: u64,
        console: u64,
        outer_connection: u64,
        outer_connection_generation: u64,
    ) -> Result<Self, ModelError> {
        let value = |offset: u64| seed.checked_add(offset).ok_or(ModelError::Identity);
        let ids = Self {
            shell: value(1)?,
            console,
            status: value(2)?,
            registry_generation,
            registry_endpoint: value(3)?,
            registry_endpoint_generation: value(4)?,
            launch_connection: value(5)?,
            launch_generation: value(6)?,
            outer_connection,
            outer_connection_generation,
            outer_transaction: value(7)?,
            wrlp_transaction: value(8)?,
        };
        let values = [
            ids.shell,
            ids.console,
            ids.status,
            ids.registry_generation,
            ids.registry_endpoint,
            ids.registry_endpoint_generation,
            ids.launch_connection,
            ids.launch_generation,
            ids.outer_connection,
            ids.outer_connection_generation,
            ids.outer_transaction,
            ids.wrlp_transaction,
        ];
        if registry_generation == 0
            || values.contains(&0)
            || values.iter().copied().collect::<BTreeSet<_>>().len() != values.len()
        {
            return Err(ModelError::Identity);
        }
        Ok(ids)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EventIdentity {
    shell: u64,
    console: u64,
    status: u64,
    registry_generation: u64,
    registry_endpoint: u64,
    registry_endpoint_generation: u64,
    launch_connection: u64,
    launch_generation: u64,
    outer_connection: u64,
    outer_connection_generation: u64,
    outer_transaction: u64,
    wrlp_transaction: u64,
}

impl From<GenerationIds> for EventIdentity {
    fn from(ids: GenerationIds) -> Self {
        Self {
            shell: ids.shell,
            console: ids.console,
            status: ids.status,
            registry_generation: ids.registry_generation,
            registry_endpoint: ids.registry_endpoint,
            registry_endpoint_generation: ids.registry_endpoint_generation,
            launch_connection: ids.launch_connection,
            launch_generation: ids.launch_generation,
            outer_connection: ids.outer_connection,
            outer_connection_generation: ids.outer_connection_generation,
            outer_transaction: ids.outer_transaction,
            wrlp_transaction: ids.wrlp_transaction,
        }
    }
}

/// READY carries only WRLP/process correlation. It intentionally has no outer
/// WRLJ transaction, job ID, or status-snapshot job correlation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReadyEvent {
    shell: u64,
    process: ResourceId,
    bootstrap_channel: ResourceId,
    wrlp_transaction: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TerminalEvent(EventIdentity);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MetadataPage {
    event: EventIdentity,
    transaction: u64,
    index: u16,
    page_count: u16,
    record_count: u16,
    total_records: u16,
    handles: u16,
    canonical: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MetadataProbe {
    page_count: Option<u16>,
    next_index: u16,
    total_records: Option<u16>,
    records_seen: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    ConsoleReserved,
    OuterCapsPrepared,
    OuterMoveCommitted,
    OuterReserved,
    RegistryPairPrepared,
    RegistrySweep,
    RegistryMoveCommitted,
    RegistryInstallProcessed,
    MetadataProbePending,
    MetadataProbeReply,
    NestedPairPrepared,
    NestedInstalled,
    LoaderPrepared,
    LoaderCommitted,
    InitMoveCommitted,
    Ready,
    RunningConfirmed,
    OuterPublished,
    AcceptedSent,
    LaunchReleased,
    Operating,
    Cleaning,
    AwaitingRegistryPeerClose,
    Cleaned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Failure {
    Injected(Phase),
    PolicyRejected,
    ResponseRace,
    StatusLost,
    Cleanup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JobState {
    Visible,
    Orphan,
    Reaped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InnerJob {
    id: u64,
    session: (u64, u64),
    process: ResourceId,
    task_group: ResourceId,
    state: JobState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RegistrySlot {
    generation: u64,
    server: ResourceId,
    peer: ResourceId,
}

#[derive(Debug)]
struct Attempt {
    ids: GenerationIds,
    phase: Phase,
    outer_reservation: Option<ResourceId>,
    console_peers: Option<[ResourceId; 4]>,
    child_caps: Option<[ResourceId; 4]>,
    registry_server: Option<ResourceId>,
    registry_client: Option<ResourceId>,
    // The nested session owns these endpoints and its own jobs only. The
    // outer ConsoleLauncher accounting remains sole owner of S1 process,
    // task-group, and WRLP launch resources.
    shell_jobs_controller: Option<ResourceId>,
    shell_jobs_client: Option<ResourceId>,
    ready_controller: Option<ResourceId>,
    ready_child: Option<ResourceId>,
    process: Option<ResourceId>,
    task_group: Option<ResourceId>,
    roles_moved: bool,
    registry_move_committed: bool,
    registry_install_processed: bool,
    metadata_probe_replied: bool,
    metadata_probe: Option<MetadataProbe>,
    shell_registry_transaction: Option<u64>,
    registry_slot_retired: bool,
    nested_installed: bool,
    nested_remove_count: u8,
    session_published: bool,
    outer_job_id: Option<u64>,
    accepted_delivered: bool,
    terminal_observed: bool,
    original_failure: Option<Failure>,
    reported_failure: Option<Failure>,
    cleanup_blocked: bool,
    jobs: Vec<InnerJob>,
}

impl Attempt {
    fn matches(&self, event: EventIdentity) -> bool {
        event == self.ids.into()
    }

    fn resource_ids(&self) -> Vec<ResourceId> {
        let mut ids = Vec::new();
        ids.extend(self.outer_reservation);
        for group in [self.console_peers, self.child_caps] {
            ids.extend(group.into_iter().flatten());
        }
        ids.extend(
            [
                self.registry_server,
                self.registry_client,
                self.shell_jobs_controller,
                self.shell_jobs_client,
                self.ready_controller,
                self.ready_child,
                self.process,
                self.task_group,
            ]
            .into_iter()
            .flatten(),
        );
        for job in &self.jobs {
            ids.extend([job.process, job.task_group]);
        }
        ids
    }
}

#[derive(Debug)]
struct Model {
    ledger: Ledger,
    current: Option<Attempt>,
    retired: Vec<Attempt>,
    active_registry_generation: u64,
    active_console_generation: u64,
    outer_connection: u64,
    outer_connection_generation: u64,
    poisoned_registry_generation: Option<u64>,
    console_recovery_required: bool,
    next_seed: u64,
    next_job_id: u64,
    failed_generations: u8,
    cleanup_permanently_blocked: bool,
    unrelated_registry_slots: Vec<RegistrySlot>,
}

impl Model {
    fn new() -> Self {
        Self {
            ledger: Ledger::default(),
            current: None,
            retired: Vec::new(),
            active_registry_generation: 90_001,
            active_console_generation: 80_001,
            outer_connection: 70_001,
            outer_connection_generation: 70_002,
            poisoned_registry_generation: None,
            console_recovery_required: false,
            next_seed: 100,
            next_job_id: 10_000,
            failed_generations: 0,
            cleanup_permanently_blocked: false,
            unrelated_registry_slots: Vec::new(),
        }
    }

    fn begin(&mut self) -> Result<EventIdentity, ModelError> {
        if self.current.is_some()
            || self.poisoned_registry_generation.is_some()
            || self.console_recovery_required
            || self.cleanup_permanently_blocked
        {
            return Err(ModelError::CleanupBlocked);
        }
        if self.failed_generations >= MAX_FAILED_GENERATIONS {
            return Err(ModelError::Exhausted);
        }
        let ids = GenerationIds::new(
            self.next_seed,
            self.active_registry_generation,
            self.active_console_generation,
            self.outer_connection,
            self.outer_connection_generation,
        )?;
        self.next_seed = self
            .next_seed
            .checked_add(100)
            .ok_or(ModelError::Identity)?;
        self.current = Some(Attempt {
            ids,
            phase: Phase::ConsoleReserved,
            outer_reservation: None,
            console_peers: None,
            child_caps: None,
            registry_server: None,
            registry_client: None,
            shell_jobs_controller: None,
            shell_jobs_client: None,
            ready_controller: None,
            ready_child: None,
            process: None,
            task_group: None,
            roles_moved: false,
            registry_move_committed: false,
            registry_install_processed: false,
            metadata_probe_replied: false,
            metadata_probe: None,
            shell_registry_transaction: None,
            registry_slot_retired: false,
            nested_installed: false,
            nested_remove_count: 0,
            session_published: false,
            outer_job_id: None,
            accepted_delivered: false,
            terminal_observed: false,
            original_failure: None,
            reported_failure: None,
            cleanup_blocked: false,
            jobs: Vec::new(),
        });
        Ok(ids.into())
    }

    fn attempt(&self) -> &Attempt {
        self.current.as_ref().unwrap()
    }

    fn attempt_mut(&mut self) -> &mut Attempt {
        self.current.as_mut().unwrap()
    }

    fn require_phase(&self, phase: Phase) -> Result<(), ModelError> {
        if self.attempt().phase == phase {
            Ok(())
        } else {
            Err(ModelError::WrongState)
        }
    }

    fn prepare_outer_caps(&mut self) -> Result<(), ModelError> {
        self.require_phase(Phase::ConsoleReserved)?;
        let console_generation = self.attempt().ids.console;
        let owner = Owner::Consoled(console_generation);
        let mut pair = |peer_role, child_role| -> Result<(ResourceId, ResourceId), ModelError> {
            Ok((
                self.ledger
                    .create(ResourceKind::Endpoint(peer_role), owner)?,
                self.ledger
                    .create(ResourceKind::Endpoint(child_role), owner)?,
            ))
        };
        let stdin = pair(
            EndpointRole::ConsolePeer(StreamRole::Stdin),
            EndpointRole::ShellStream(StreamRole::Stdin),
        )?;
        let stdout = pair(
            EndpointRole::ConsolePeer(StreamRole::Stdout),
            EndpointRole::ShellStream(StreamRole::Stdout),
        )?;
        let stderr = pair(
            EndpointRole::ConsolePeer(StreamRole::Stderr),
            EndpointRole::ShellStream(StreamRole::Stderr),
        )?;
        let status = pair(EndpointRole::ConsoleStatus, EndpointRole::ShellStatus)?;
        let attempt = self.attempt_mut();
        attempt.console_peers = Some([stdin.0, stdout.0, stderr.0, status.0]);
        attempt.child_caps = Some([stdin.1, stdout.1, stderr.1, status.1]);
        attempt.phase = Phase::OuterCapsPrepared;
        Ok(())
    }

    fn outer_send_failed_before_move(&mut self) -> Result<(), ModelError> {
        self.require_phase(Phase::OuterCapsPrepared)?;
        let owner = Owner::Consoled(self.attempt().ids.console);
        for id in self
            .attempt()
            .console_peers
            .unwrap()
            .into_iter()
            .chain(self.attempt().child_caps.unwrap())
        {
            self.ledger.close(id, owner)?;
        }
        self.attempt_mut().phase = Phase::Cleaned;
        self.finish_current(false)
    }

    fn commit_outer_move(&mut self) -> Result<(), ModelError> {
        self.require_phase(Phase::OuterCapsPrepared)?;
        let console = self.attempt().ids.console;
        let child_caps = self.attempt().child_caps.unwrap();
        // Exactly three streams and one status control endpoint move atomically.
        assert!(matches!(
            self.ledger.resource(child_caps[3]).kind,
            ResourceKind::Endpoint(EndpointRole::ShellStatus)
        ));
        self.ledger
            .move_atomic(&child_caps, Owner::Consoled(console), Owner::Init)?;
        self.attempt_mut().phase = Phase::OuterMoveCommitted;
        Ok(())
    }

    fn reserve_outer_accounting(&mut self) -> Result<(), ModelError> {
        self.require_phase(Phase::OuterMoveCommitted)?;
        let reservation = self
            .ledger
            .create(ResourceKind::OuterReservation, Owner::Init)?;
        let attempt = self.attempt_mut();
        attempt.outer_reservation = Some(reservation);
        attempt.phase = Phase::OuterReserved;
        Ok(())
    }

    fn receiver_policy_rejects_after_move(&mut self) -> Result<(), ModelError> {
        self.require_phase(Phase::OuterMoveCommitted)?;
        let child_caps = self.attempt().child_caps.unwrap();
        for id in child_caps {
            self.ledger.close(id, Owner::Init)?;
        }
        let console = self.attempt().ids.console;
        for id in self.attempt().console_peers.unwrap() {
            self.ledger.close(id, Owner::Consoled(console))?;
        }
        let attempt = self.attempt_mut();
        attempt.original_failure = Some(Failure::PolicyRejected);
        attempt.reported_failure = Some(Failure::PolicyRejected);
        attempt.phase = Phase::Cleaned;
        self.failed_generations = self.failed_generations.checked_add(1).unwrap();
        self.finish_current(false)
    }

    fn prepare_registry_pair(&mut self) -> Result<(), ModelError> {
        self.require_phase(Phase::OuterReserved)?;
        let server = self
            .ledger
            .create(ResourceKind::Endpoint(EndpointRole::Registry), Owner::Init)?;
        let client = self.ledger.create(
            ResourceKind::Endpoint(EndpointRole::RegistryClient),
            Owner::Init,
        )?;
        let attempt = self.attempt_mut();
        attempt.registry_server = Some(server);
        attempt.registry_client = Some(client);
        attempt.phase = Phase::RegistryPairPrepared;
        Ok(())
    }

    fn registry_sweep(&mut self) -> Result<(), ModelError> {
        self.require_phase(Phase::RegistryMoveCommitted)?;
        let generation = self.attempt().ids.registry_generation;
        let installed = self
            .retired
            .iter()
            .filter(|attempt| {
                attempt.ids.registry_generation == generation
                    && attempt.registry_server.is_some_and(|server| {
                        self.ledger.owner(server) == Ok(Owner::Registryd(generation))
                    })
            })
            .count()
            .checked_add(
                self.unrelated_registry_slots
                    .iter()
                    .filter(|slot| {
                        slot.generation == generation
                            && self.ledger.owner(slot.server) == Ok(Owner::Registryd(generation))
                    })
                    .count(),
            )
            .ok_or(ModelError::Exhausted)?;
        if installed > MAX_REGISTRY_ENDPOINTS {
            return Err(ModelError::Exhausted);
        }
        for attempt in self
            .retired
            .iter_mut()
            .filter(|attempt| attempt.ids.registry_generation == generation)
        {
            let Some(server) = attempt.registry_server else {
                continue;
            };
            if self.ledger.owner(server)? != Owner::Registryd(generation) {
                continue;
            }
            let client = attempt.registry_client.ok_or(ModelError::WrongState)?;
            // One registry-side snapshot may retire only a peer whose child
            // endpoint destruction is already observable as PEER_CLOSED.
            if self.ledger.owner(client)? != Owner::Closed {
                continue;
            }
            self.ledger.close(server, Owner::Registryd(generation))?;
            attempt.registry_slot_retired = true;
            attempt.phase = Phase::Cleaned;
        }
        for slot in self
            .unrelated_registry_slots
            .iter()
            .filter(|slot| slot.generation == generation)
        {
            if self.ledger.owner(slot.server)? == Owner::Registryd(generation)
                && self.ledger.owner(slot.peer)? == Owner::Closed
            {
                self.ledger
                    .close(slot.server, Owner::Registryd(generation))?;
            }
        }
        if self.retired.iter().any(|attempt| {
            attempt.ids.registry_generation == generation
                && attempt.terminal_observed
                && attempt.registry_server.is_some_and(|server| {
                    self.ledger.owner(server) == Ok(Owner::Registryd(generation))
                })
        }) {
            return Err(ModelError::CleanupBlocked);
        }
        self.attempt_mut().phase = Phase::RegistrySweep;
        Ok(())
    }

    fn install_unrelated_registry_slot(&mut self) -> Result<RegistrySlot, ModelError> {
        let generation = self.active_registry_generation;
        let server = self
            .ledger
            .create(ResourceKind::Endpoint(EndpointRole::Registry), Owner::Init)?;
        let peer = self.ledger.create(
            ResourceKind::Endpoint(EndpointRole::RegistryClient),
            Owner::Init,
        )?;
        self.ledger
            .move_atomic(&[server], Owner::Init, Owner::Registryd(generation))?;
        let slot = RegistrySlot {
            generation,
            server,
            peer,
        };
        self.unrelated_registry_slots.push(slot);
        Ok(slot)
    }

    fn commit_registry_move(&mut self) -> Result<(), ModelError> {
        self.require_phase(Phase::RegistryPairPrepared)?;
        let generation = self.attempt().ids.registry_generation;
        for attempt in self.retired.iter().filter(|attempt| {
            attempt.ids.registry_generation == generation && attempt.registry_move_committed
        }) {
            let client_destroyed = attempt
                .registry_client
                .is_none_or(|client| self.ledger.owner(client) == Ok(Owner::Closed));
            let process_reaped = attempt
                .process
                .is_none_or(|process| self.ledger.owner(process) == Ok(Owner::Reaped));
            let task_group_reaped = attempt
                .task_group
                .is_none_or(|group| self.ledger.owner(group) == Ok(Owner::Reaped));
            let accounting_released = attempt
                .outer_reservation
                .is_none_or(|reservation| self.ledger.owner(reservation) == Ok(Owner::Closed));
            let no_shell_owner = attempt
                .resource_ids()
                .into_iter()
                .all(|id| self.ledger.owner(id) != Ok(Owner::Shell(attempt.ids.shell)));
            if !attempt.terminal_observed
                || !client_destroyed
                || !process_reaped
                || !task_group_reaped
                || !accounting_released
                || !no_shell_owner
            {
                return Err(ModelError::CleanupBlocked);
            }
        }
        let server = self.attempt().registry_server.unwrap();
        self.ledger
            .move_atomic(&[server], Owner::Init, Owner::Registryd(generation))?;
        let attempt = self.attempt_mut();
        attempt.registry_move_committed = true;
        attempt.phase = Phase::RegistryMoveCommitted;
        Ok(())
    }

    fn registry_process_install(&mut self) -> Result<(), ModelError> {
        self.require_phase(Phase::RegistrySweep)?;
        let server = self.attempt().registry_server.unwrap();
        let generation = self.attempt().ids.registry_generation;
        if self.ledger.owner(server)? != Owner::Registryd(generation) {
            return Err(ModelError::Ownership);
        }
        if self.retired.iter().any(|attempt| {
            attempt.ids.registry_generation == generation
                && attempt.terminal_observed
                && !attempt.registry_slot_retired
        }) {
            return Err(ModelError::CleanupBlocked);
        }
        let installed_clients = self
            .retired
            .iter()
            .filter(|attempt| {
                attempt.ids.registry_generation == generation
                    && attempt.registry_server.is_some_and(|server| {
                        self.ledger.owner(server) == Ok(Owner::Registryd(generation))
                    })
            })
            .count()
            .checked_add(
                self.unrelated_registry_slots
                    .iter()
                    .filter(|slot| {
                        slot.generation == generation
                            && self.ledger.owner(slot.server) == Ok(Owner::Registryd(generation))
                    })
                    .count(),
            )
            .ok_or(ModelError::Exhausted)?;
        if installed_clients >= MAX_REGISTRY_CLIENTS {
            return Err(ModelError::Exhausted);
        }
        let attempt = self.attempt_mut();
        attempt.registry_install_processed = true;
        attempt.phase = Phase::RegistryInstallProcessed;
        Ok(())
    }

    fn send_registry_metadata_probe(&mut self) -> Result<(), ModelError> {
        self.require_phase(Phase::RegistryInstallProcessed)?;
        let client = self.attempt().registry_client.unwrap();
        if self.ledger.owner(client)? != Owner::Init {
            return Err(ModelError::Ownership);
        }
        let attempt = self.attempt_mut();
        attempt.metadata_probe = Some(MetadataProbe {
            page_count: None,
            next_index: 0,
            total_records: None,
            records_seen: 0,
        });
        attempt.phase = Phase::MetadataProbePending;
        Ok(())
    }

    fn registry_metadata_probe_page(&mut self, page: MetadataPage) -> Result<(), ModelError> {
        self.require_phase(Phase::MetadataProbePending)?;
        if !self.attempt().matches(page.event) || page.transaction != 1 {
            return Err(ModelError::Stale);
        }
        if !(1..=MAX_METADATA_PAGES).contains(&page.page_count)
            || page.total_records > MAX_METADATA_RECORDS
            || page.record_count > 2
            || page.handles != 0
            || !page.canonical
        {
            return Err(ModelError::Identity);
        }
        let probe = self
            .attempt()
            .metadata_probe
            .ok_or(ModelError::WrongState)?;
        if page.index != probe.next_index
            || probe
                .page_count
                .is_some_and(|count| count != page.page_count)
            || probe
                .total_records
                .is_some_and(|total| total != page.total_records)
        {
            return Err(ModelError::Stale);
        }
        let final_page = page.index + 1 == page.page_count;
        if (page.total_records == 0
            && (page.page_count != 1 || page.index != 0 || page.record_count != 0))
            || (page.total_records != 0
                && ((!final_page && page.record_count != 2)
                    || (final_page && page.record_count == 0)))
        {
            return Err(ModelError::Identity);
        }
        let records_seen = probe
            .records_seen
            .checked_add(page.record_count)
            .ok_or(ModelError::Identity)?;
        if (final_page && records_seen != page.total_records)
            || (!final_page && records_seen >= page.total_records)
        {
            return Err(ModelError::Identity);
        }
        let attempt = self.attempt_mut();
        if final_page {
            attempt.metadata_probe_replied = true;
            attempt.metadata_probe = None;
            attempt.phase = Phase::MetadataProbeReply;
        } else {
            attempt.metadata_probe = Some(MetadataProbe {
                page_count: Some(page.page_count),
                next_index: page.index + 1,
                total_records: Some(page.total_records),
                records_seen,
            });
        }
        Ok(())
    }

    fn registry_rejects_install_after_move(&mut self) -> Result<(), ModelError> {
        self.require_phase(Phase::RegistrySweep)?;
        let generation = self.attempt().ids.registry_generation;
        let server = self.attempt().registry_server.unwrap();
        let client = self.attempt().registry_client.unwrap();
        self.ledger.close(server, Owner::Registryd(generation))?;
        self.ledger.close(client, Owner::Init)?;
        let attempt = self.attempt_mut();
        attempt.registry_slot_retired = true;
        attempt.original_failure = Some(Failure::PolicyRejected);
        attempt.reported_failure = Some(Failure::PolicyRejected);
        attempt.phase = Phase::Cleaning;
        Ok(())
    }

    fn prepare_nested_session(&mut self) -> Result<(), ModelError> {
        self.require_phase(Phase::MetadataProbeReply)?;
        let controller = self.ledger.create(
            ResourceKind::Endpoint(EndpointRole::ShellJobsController),
            Owner::Init,
        )?;
        let client = self.ledger.create(
            ResourceKind::Endpoint(EndpointRole::ShellJobsClient),
            Owner::Init,
        )?;
        let attempt = self.attempt_mut();
        attempt.shell_jobs_controller = Some(controller);
        attempt.shell_jobs_client = Some(client);
        attempt.phase = Phase::NestedPairPrepared;
        Ok(())
    }

    fn install_nested_unpublished(&mut self) -> Result<(), ModelError> {
        self.require_phase(Phase::NestedPairPrepared)?;
        let controller = self.attempt().shell_jobs_controller.unwrap();
        let generation = self.attempt().ids.launch_generation;
        self.ledger.move_atomic(
            &[controller],
            Owner::Init,
            Owner::LaunchController(generation),
        )?;
        let attempt = self.attempt_mut();
        attempt.nested_installed = true;
        attempt.phase = Phase::NestedInstalled;
        Ok(())
    }

    fn prepare_loader(&mut self) -> Result<(), ModelError> {
        self.require_phase(Phase::NestedInstalled)?;
        let process = self.ledger.create(ResourceKind::Process, Owner::Init)?;
        let task_group = self.ledger.create(ResourceKind::TaskGroup, Owner::Init)?;
        let ready_controller = self.ledger.create(
            ResourceKind::Endpoint(EndpointRole::ReadyController),
            Owner::Init,
        )?;
        let ready_child = self.ledger.create(
            ResourceKind::Endpoint(EndpointRole::ReadyChild),
            Owner::Init,
        )?;
        let attempt = self.attempt_mut();
        attempt.process = Some(process);
        attempt.task_group = Some(task_group);
        attempt.ready_controller = Some(ready_controller);
        attempt.ready_child = Some(ready_child);
        attempt.phase = Phase::LoaderPrepared;
        Ok(())
    }

    fn commit_loader_construction(&mut self) -> Result<(), ModelError> {
        self.require_phase(Phase::LoaderPrepared)?;
        let child = self.attempt().ready_child.unwrap();
        let shell = self.attempt().ids.shell;
        self.ledger
            .move_atomic(&[child], Owner::Init, Owner::Shell(shell))?;
        self.attempt_mut().phase = Phase::LoaderCommitted;
        Ok(())
    }

    fn commit_six_role_init_move(&mut self) -> Result<(), ModelError> {
        self.require_phase(Phase::LoaderCommitted)?;
        let attempt = self.attempt();
        if !attempt.metadata_probe_replied || attempt.metadata_probe.is_some() {
            return Err(ModelError::WrongState);
        }
        let child_caps = attempt.child_caps.unwrap();
        let registry_client = attempt.registry_client.unwrap();
        let shell_jobs_client = attempt.shell_jobs_client.unwrap();
        let shell = attempt.ids.shell;
        let roles = [
            child_caps[0],
            child_caps[1],
            child_caps[2],
            child_caps[3],
            registry_client,
            shell_jobs_client,
        ];
        assert_eq!(roles.iter().copied().collect::<BTreeSet<_>>().len(), 6);
        self.ledger
            .move_atomic(&roles, Owner::Init, Owner::Shell(shell))?;
        let attempt = self.attempt_mut();
        attempt.roles_moved = true;
        // Init consumed startup probe transaction 1 completely; the shell's
        // first registry operation begins at transaction 2.
        attempt.shell_registry_transaction = Some(2);
        attempt.phase = Phase::InitMoveCommitted;
        Ok(())
    }

    fn init_send_failed_before_move(&mut self) -> Result<(), ModelError> {
        self.require_phase(Phase::LoaderCommitted)?;
        self.fail_current(Failure::Injected(Phase::LoaderCommitted))
    }

    fn ready_event(&self) -> ReadyEvent {
        ReadyEvent {
            shell: self.attempt().ids.shell,
            process: self.attempt().process.unwrap(),
            bootstrap_channel: self.attempt().ready_controller.unwrap(),
            wrlp_transaction: self.attempt().ids.wrlp_transaction,
        }
    }

    fn observe_ready(&mut self, ready: ReadyEvent) -> Result<(), ModelError> {
        self.require_phase(Phase::InitMoveCommitted)?;
        if ready.shell != self.attempt().ids.shell
            || ready.process != self.attempt().process.unwrap()
            || ready.bootstrap_channel != self.attempt().ready_controller.unwrap()
            || ready.wrlp_transaction != self.attempt().ids.wrlp_transaction
        {
            return Err(ModelError::Stale);
        }
        assert_eq!(self.attempt().outer_job_id, None);
        self.attempt_mut().phase = Phase::Ready;
        Ok(())
    }

    fn confirm_fresh_process_running(&mut self, event: EventIdentity) -> Result<(), ModelError> {
        self.require_phase(Phase::Ready)?;
        if !self.attempt().matches(event) {
            return Err(ModelError::Stale);
        }
        let process = self.attempt().process.ok_or(ModelError::WrongState)?;
        if self.ledger.owner(process)? != Owner::Init {
            return Err(ModelError::Ownership);
        }
        self.attempt_mut().phase = Phase::RunningConfirmed;
        Ok(())
    }

    fn publish_outer_and_session(&mut self) -> Result<u64, ModelError> {
        self.require_phase(Phase::RunningConfirmed)?;
        self.next_job_id = self
            .next_job_id
            .checked_add(1)
            .ok_or(ModelError::Identity)?;
        let id = self.next_job_id;
        let attempt = self.attempt_mut();
        attempt.outer_job_id = Some(id);
        attempt.session_published = true;
        attempt.phase = Phase::OuterPublished;
        Ok(id)
    }

    fn deliver_launch_accepted(&mut self) -> Result<(), ModelError> {
        self.require_phase(Phase::OuterPublished)?;
        self.attempt_mut().accepted_delivered = true;
        self.attempt_mut().phase = Phase::AcceptedSent;
        Ok(())
    }

    fn release_bootstrap_launch_peer(&mut self) -> Result<(), ModelError> {
        self.require_phase(Phase::AcceptedSent)?;
        let shell = self.attempt().ids.shell;
        self.ledger
            .close(self.attempt().ready_controller.unwrap(), Owner::Init)?;
        self.ledger
            .close(self.attempt().ready_child.unwrap(), Owner::Shell(shell))?;
        self.attempt_mut().phase = Phase::LaunchReleased;
        Ok(())
    }

    fn begin_shell_operations(&mut self) -> Result<(), ModelError> {
        self.require_phase(Phase::LaunchReleased)?;
        self.attempt_mut().phase = Phase::Operating;
        Ok(())
    }

    fn start_inner_job(&mut self) -> Result<u64, ModelError> {
        self.require_phase(Phase::Operating)?;
        self.next_job_id = self
            .next_job_id
            .checked_add(1)
            .ok_or(ModelError::Identity)?;
        let id = self.next_job_id;
        let process = self.ledger.create(ResourceKind::Process, Owner::Init)?;
        let task_group = self.ledger.create(ResourceKind::TaskGroup, Owner::Init)?;
        let ids = self.attempt().ids;
        self.attempt_mut().jobs.push(InnerJob {
            id,
            session: (ids.launch_connection, ids.launch_generation),
            process,
            task_group,
            state: JobState::Visible,
        });
        Ok(id)
    }

    fn visible_jobs(&self) -> Vec<u64> {
        self.current
            .as_ref()
            .into_iter()
            .flat_map(|attempt| &attempt.jobs)
            .filter(|job| job.state == JobState::Visible)
            .map(|job| job.id)
            .collect()
    }

    fn orphan_jobs(&self) -> Vec<u64> {
        self.current
            .iter()
            .chain(&self.retired)
            .flat_map(|attempt| &attempt.jobs)
            .filter(|job| job.state == JobState::Orphan)
            .map(|job| job.id)
            .collect()
    }

    fn fail_current(&mut self, failure: Failure) -> Result<(), ModelError> {
        if matches!(self.attempt().phase, Phase::Cleaned | Phase::Cleaning) {
            return Err(ModelError::WrongState);
        }
        let registry_ambiguous =
            self.attempt().registry_move_committed && !self.attempt().registry_slot_retired;
        if registry_ambiguous {
            self.poisoned_registry_generation = Some(self.attempt().ids.registry_generation);
        }
        let attempt = self.attempt_mut();
        attempt.original_failure = Some(failure);
        attempt.reported_failure = Some(failure);
        attempt.phase = Phase::Cleaning;
        Ok(())
    }

    fn record_cleanup_failure(&mut self) -> Result<(), ModelError> {
        self.require_phase(Phase::Cleaning)?;
        let attempt = self.attempt_mut();
        attempt.cleanup_blocked = true;
        attempt.reported_failure = Some(Failure::Cleanup);
        self.cleanup_permanently_blocked = true;
        Err(ModelError::CleanupBlocked)
    }

    fn close_shell_resources(&mut self) -> Result<(), ModelError> {
        let shell = self.attempt().ids.shell;
        let ids = self.attempt().resource_ids();
        for id in ids {
            if self.ledger.owner(id)? == Owner::Shell(shell) {
                self.ledger.close(id, Owner::Shell(shell))?;
            }
        }
        self.attempt_mut().terminal_observed = true;
        Ok(())
    }

    fn observe_consoled_peer_cleanup(&mut self) -> Result<(), ModelError> {
        let console = self.attempt().ids.console;
        for group in [self.attempt().console_peers, self.attempt().child_caps] {
            for id in group.into_iter().flatten() {
                if self.ledger.owner(id)? == Owner::Consoled(console) {
                    self.ledger.close(id, Owner::Consoled(console))?;
                }
            }
        }
        Ok(())
    }

    fn remove_or_disconnect_nested(&mut self) -> Result<(), ModelError> {
        if !self.attempt().nested_installed {
            return Ok(());
        }
        let generation = self.attempt().ids.launch_generation;
        let controller = self.attempt().shell_jobs_controller.unwrap();
        if self.attempt().session_published {
            for job in &mut self.attempt_mut().jobs {
                if job.state == JobState::Visible {
                    job.state = JobState::Orphan;
                }
            }
        } else {
            if self.attempt().nested_remove_count != 0 {
                return Err(ModelError::AlreadyClosed);
            }
            self.attempt_mut().nested_remove_count = 1;
        }
        if self.ledger.owner(controller)? == Owner::LaunchController(generation) {
            self.ledger
                .close(controller, Owner::LaunchController(generation))?;
        }
        Ok(())
    }

    fn close_init_locals_and_reap(
        &mut self,
        delayed_reap: Option<ResourceId>,
    ) -> Result<(), ModelError> {
        let orphan_resources = self
            .attempt()
            .jobs
            .iter()
            .filter(|job| job.state == JobState::Orphan)
            .flat_map(|job| [job.process, job.task_group])
            .collect::<BTreeSet<_>>();
        let ids = self.attempt().resource_ids();
        for id in ids {
            if orphan_resources.contains(&id) || delayed_reap == Some(id) {
                continue;
            }
            match self.ledger.owner(id)? {
                Owner::Init => match self.ledger.resource(id).kind {
                    ResourceKind::Process | ResourceKind::TaskGroup => {
                        self.ledger.reap(id, Owner::Init)?;
                    }
                    ResourceKind::Endpoint(_) | ResourceKind::OuterReservation => {
                        self.ledger.close(id, Owner::Init)?;
                    }
                },
                Owner::Registryd(_) | Owner::Closed | Owner::Reaped => {}
                Owner::Consoled(_) | Owner::LaunchController(_) | Owner::Shell(_) => {
                    return Err(ModelError::Ownership);
                }
            }
        }
        Ok(())
    }

    fn cleanup_after_failure(&mut self) -> Result<(), ModelError> {
        self.require_phase(Phase::Cleaning)?;
        if self.attempt().cleanup_blocked {
            return Err(ModelError::CleanupBlocked);
        }
        self.close_shell_resources()?;
        self.observe_consoled_peer_cleanup()?;
        self.remove_or_disconnect_nested()?;
        self.close_init_locals_and_reap(None)?;
        self.failed_generations = self.failed_generations.checked_add(1).unwrap();
        if self.registry_server_is_live() {
            self.attempt_mut().phase = Phase::AwaitingRegistryPeerClose;
            Ok(())
        } else {
            self.attempt_mut().phase = Phase::Cleaned;
            self.finish_current(false)
        }
    }

    /// Registryd, not init, observes the ordinary client peer close and retires
    /// the installed slot. This is not an INSTALL acknowledgement.
    fn registry_actor_observes_client_peer_close(
        &mut self,
        event: EventIdentity,
    ) -> Result<(), ModelError> {
        if self
            .current
            .as_ref()
            .is_some_and(|attempt| attempt.matches(event))
        {
            if !matches!(
                self.attempt().phase,
                Phase::AwaitingRegistryPeerClose | Phase::Cleaning
            ) {
                return Err(ModelError::WrongState);
            }
            let server = self
                .attempt()
                .registry_server
                .ok_or(ModelError::WrongState)?;
            self.ledger
                .close(server, Owner::Registryd(event.registry_generation))?;
            self.attempt_mut().registry_slot_retired = true;
            if self.attempt().phase == Phase::AwaitingRegistryPeerClose {
                self.attempt_mut().phase = Phase::Cleaned;
                self.finish_current(false)?;
            }
            return Ok(());
        }
        let retired = self
            .retired
            .iter_mut()
            .find(|attempt| attempt.matches(event))
            .ok_or(ModelError::Stale)?;
        if retired.phase != Phase::AwaitingRegistryPeerClose {
            return Err(ModelError::WrongState);
        }
        let server = retired.registry_server.ok_or(ModelError::WrongState)?;
        self.ledger
            .close(server, Owner::Registryd(event.registry_generation))?;
        retired.registry_slot_retired = true;
        retired.phase = Phase::Cleaned;
        Ok(())
    }

    fn finish_shell_cleanup_before_registry_observation(&mut self) -> Result<(), ModelError> {
        self.require_phase(Phase::AwaitingRegistryPeerClose)?;
        self.retired.push(self.current.take().unwrap());
        Ok(())
    }

    fn registry_generation_terminal_reaped(&mut self, generation: u64) -> Result<(), ModelError> {
        if self.poisoned_registry_generation != Some(generation) {
            return Err(ModelError::Stale);
        }
        if let Some(attempt) = &mut self.current
            && attempt.ids.registry_generation == generation
        {
            if let Some(server) = attempt.registry_server
                && self.ledger.owner(server)? == Owner::Registryd(generation)
            {
                self.ledger.close(server, Owner::Registryd(generation))?;
            }
            attempt.registry_slot_retired = true;
        }
        self.poisoned_registry_generation = None;
        self.active_registry_generation = self
            .active_registry_generation
            .checked_add(1)
            .ok_or(ModelError::Identity)?;
        self.console_recovery_required = true;
        if self
            .current
            .as_ref()
            .is_some_and(|attempt| attempt.phase == Phase::AwaitingRegistryPeerClose)
        {
            self.attempt_mut().phase = Phase::Cleaned;
            self.finish_current(false)?;
        }
        Ok(())
    }

    fn rebuild_console_launcher_authority(&mut self) -> Result<(), ModelError> {
        if !self.console_recovery_required || self.current.is_some() {
            return Err(ModelError::WrongState);
        }
        self.active_console_generation = self
            .active_console_generation
            .checked_add(1)
            .ok_or(ModelError::Identity)?;
        self.outer_connection = self
            .outer_connection
            .checked_add(2)
            .ok_or(ModelError::Identity)?;
        self.outer_connection_generation = self
            .outer_connection_generation
            .checked_add(2)
            .ok_or(ModelError::Identity)?;
        self.console_recovery_required = false;
        Ok(())
    }

    fn normal_exit(&mut self, terminal: TerminalEvent) -> Result<(), ModelError> {
        self.require_phase(Phase::Operating)?;
        if !self.attempt().matches(terminal.0) {
            return Err(ModelError::Stale);
        }
        self.close_shell_resources()?;
        self.observe_consoled_peer_cleanup()?;
        self.remove_or_disconnect_nested()?;
        self.close_init_locals_and_reap(None)?;
        self.attempt_mut().phase = Phase::AwaitingRegistryPeerClose;
        Ok(())
    }

    fn normal_exit_with_delayed_task_group(
        &mut self,
        terminal: TerminalEvent,
    ) -> Result<ResourceId, ModelError> {
        self.require_phase(Phase::Operating)?;
        if !self.attempt().matches(terminal.0) {
            return Err(ModelError::Stale);
        }
        let task_group = self.attempt().task_group.unwrap();
        self.close_shell_resources()?;
        self.observe_consoled_peer_cleanup()?;
        self.remove_or_disconnect_nested()?;
        self.close_init_locals_and_reap(Some(task_group))?;
        self.attempt_mut().phase = Phase::AwaitingRegistryPeerClose;
        self.finish_shell_cleanup_before_registry_observation()?;
        Ok(task_group)
    }

    fn complete_delayed_task_group_reap(&mut self, event: EventIdentity) -> Result<(), ModelError> {
        let task_group = self
            .retired
            .iter()
            .find(|attempt| attempt.matches(event))
            .and_then(|attempt| attempt.task_group)
            .ok_or(ModelError::Stale)?;
        self.ledger.reap(task_group, Owner::Init)
    }

    fn shell_exits_before_response(&mut self, terminal: TerminalEvent) -> Result<(), ModelError> {
        if !matches!(
            self.attempt().phase,
            Phase::Ready | Phase::RunningConfirmed | Phase::OuterPublished
        ) {
            return Err(ModelError::WrongState);
        }
        if !self.attempt().matches(terminal.0) {
            return Err(ModelError::Stale);
        }
        self.close_shell_resources()?;
        self.attempt_mut().original_failure = Some(Failure::ResponseRace);
        self.attempt_mut().reported_failure = Some(Failure::ResponseRace);
        self.attempt_mut().phase = Phase::Cleaning;
        Ok(())
    }

    fn status_peer_lost(&mut self, event: EventIdentity) -> Result<(), ModelError> {
        self.require_phase(Phase::Operating)?;
        if !self.attempt().matches(event) {
            return Err(ModelError::Stale);
        }
        let status = self.attempt().child_caps.unwrap()[3];
        self.ledger
            .close(status, Owner::Shell(self.attempt().ids.shell))?;
        self.attempt_mut().original_failure = Some(Failure::StatusLost);
        self.attempt_mut().reported_failure = Some(Failure::StatusLost);
        self.attempt_mut().phase = Phase::Cleaning;
        self.poisoned_registry_generation = Some(event.registry_generation);
        Ok(())
    }

    fn reap_orphan(&mut self, job_id: u64) -> Result<(), ModelError> {
        let (process, task_group) = self
            .current
            .iter_mut()
            .chain(&mut self.retired)
            .flat_map(|attempt| &mut attempt.jobs)
            .find(|job| job.id == job_id && job.state == JobState::Orphan)
            .map(|job| {
                job.state = JobState::Reaped;
                (job.process, job.task_group)
            })
            .ok_or(ModelError::Stale)?;
        self.ledger.reap(process, Owner::Init)?;
        self.ledger.reap(task_group, Owner::Init)?;
        Ok(())
    }

    fn registry_server_is_live(&self) -> bool {
        self.attempt()
            .registry_server
            .is_some_and(|server| matches!(self.ledger.owner(server), Ok(Owner::Registryd(_))))
    }

    fn finish_current(&mut self, count_failure: bool) -> Result<(), ModelError> {
        if self.attempt().phase != Phase::Cleaned {
            return Err(ModelError::WrongState);
        }
        if count_failure {
            self.failed_generations = self.failed_generations.checked_add(1).unwrap();
        }
        let attempt = self.current.take().unwrap();
        self.retired.push(attempt);
        Ok(())
    }

    fn current_failure(&self) -> (Option<Failure>, Option<Failure>) {
        (
            self.attempt().original_failure,
            self.attempt().reported_failure,
        )
    }

    fn stage_to(&mut self, phase: Phase) -> Result<EventIdentity, ModelError> {
        let event = self.begin()?;
        if phase == Phase::ConsoleReserved {
            return Ok(event);
        }
        self.prepare_outer_caps()?;
        if phase == Phase::OuterCapsPrepared {
            return Ok(event);
        }
        self.commit_outer_move()?;
        if phase == Phase::OuterMoveCommitted {
            return Ok(event);
        }
        self.reserve_outer_accounting()?;
        if phase == Phase::OuterReserved {
            return Ok(event);
        }
        self.prepare_registry_pair()?;
        if phase == Phase::RegistryPairPrepared {
            return Ok(event);
        }
        self.commit_registry_move()?;
        if phase == Phase::RegistryMoveCommitted {
            return Ok(event);
        }
        self.registry_sweep()?;
        if phase == Phase::RegistrySweep {
            return Ok(event);
        }
        self.registry_process_install()?;
        if phase == Phase::RegistryInstallProcessed {
            return Ok(event);
        }
        self.send_registry_metadata_probe()?;
        if phase == Phase::MetadataProbePending {
            return Ok(event);
        }
        self.registry_metadata_probe_page(metadata_page(event, 0, 1, 0, 0))?;
        if phase == Phase::MetadataProbeReply {
            return Ok(event);
        }
        self.prepare_nested_session()?;
        if phase == Phase::NestedPairPrepared {
            return Ok(event);
        }
        self.install_nested_unpublished()?;
        if phase == Phase::NestedInstalled {
            return Ok(event);
        }
        self.prepare_loader()?;
        if phase == Phase::LoaderPrepared {
            return Ok(event);
        }
        self.commit_loader_construction()?;
        if phase == Phase::LoaderCommitted {
            return Ok(event);
        }
        self.commit_six_role_init_move()?;
        if phase == Phase::InitMoveCommitted {
            return Ok(event);
        }
        let ready = self.ready_event();
        self.observe_ready(ready)?;
        if phase == Phase::Ready {
            return Ok(event);
        }
        self.confirm_fresh_process_running(event)?;
        if phase == Phase::RunningConfirmed {
            return Ok(event);
        }
        self.publish_outer_and_session()?;
        if phase == Phase::OuterPublished {
            return Ok(event);
        }
        self.deliver_launch_accepted()?;
        if phase == Phase::AcceptedSent {
            return Ok(event);
        }
        self.release_bootstrap_launch_peer()?;
        if phase == Phase::LaunchReleased {
            return Ok(event);
        }
        self.begin_shell_operations()?;
        if phase == Phase::Operating {
            return Ok(event);
        }
        Err(ModelError::WrongState)
    }

    fn close_pre_registry_failure_locally(&mut self) -> Result<(), ModelError> {
        self.fail_current(Failure::Injected(self.attempt().phase))?;
        self.cleanup_after_failure()
    }
}

fn stale(event: EventIdentity) -> EventIdentity {
    EventIdentity {
        shell: event.shell + 10_000,
        ..event
    }
}

fn metadata_page(
    event: EventIdentity,
    index: u16,
    page_count: u16,
    record_count: u16,
    total_records: u16,
) -> MetadataPage {
    MetadataPage {
        event,
        transaction: 1,
        index,
        page_count,
        record_count,
        total_records,
        handles: 0,
        canonical: true,
    }
}

fn complete_poisoned_failure(model: &mut Model, event: EventIdentity) {
    model.cleanup_after_failure().unwrap();
    assert_eq!(model.begin(), Err(ModelError::CleanupBlocked));
    model
        .registry_generation_terminal_reaped(event.registry_generation)
        .unwrap();
    assert_eq!(model.begin(), Err(ModelError::CleanupBlocked));
    model.rebuild_console_launcher_authority().unwrap();
}

fn launch_operating(model: &mut Model) -> EventIdentity {
    model.stage_to(Phase::Operating).unwrap()
}

fn finish_launch_after_registry_sweep(model: &mut Model, event: EventIdentity) {
    model.registry_process_install().unwrap();
    model.send_registry_metadata_probe().unwrap();
    model
        .registry_metadata_probe_page(metadata_page(event, 0, 1, 0, 0))
        .unwrap();
    model.prepare_nested_session().unwrap();
    model.install_nested_unpublished().unwrap();
    model.prepare_loader().unwrap();
    model.commit_loader_construction().unwrap();
    model.commit_six_role_init_move().unwrap();
    let ready = model.ready_event();
    model.observe_ready(ready).unwrap();
    model.confirm_fresh_process_running(event).unwrap();
    model.publish_outer_and_session().unwrap();
    model.deliver_launch_accepted().unwrap();
    model.release_bootstrap_launch_peer().unwrap();
    model.begin_shell_operations().unwrap();
}

#[test]
fn ordinary_s1_to_s2_uses_fresh_authority_and_exact_cleanup() {
    let mut model = Model::new();
    let s1 = launch_operating(&mut model);
    let first_resources = model.attempt().resource_ids();
    model.normal_exit(TerminalEvent(s1)).unwrap();
    model
        .finish_shell_cleanup_before_registry_observation()
        .unwrap();
    let s2 = model.begin().unwrap();
    model.prepare_outer_caps().unwrap();
    model.commit_outer_move().unwrap();
    model.reserve_outer_accounting().unwrap();
    model.prepare_registry_pair().unwrap();
    model.commit_registry_move().unwrap();
    // Registryd's bounded sweep observes R1 peer closure before processing R2.
    model.registry_sweep().unwrap();
    let r1 = model.retired[0].registry_server.unwrap();
    assert_eq!(model.ledger.owner(r1), Ok(Owner::Closed));
    finish_launch_after_registry_sweep(&mut model, s2);
    assert_ne!(s1.shell, s2.shell);
    assert_eq!(s1.console, s2.console);
    assert_ne!(s1.status, s2.status);
    assert_ne!(s1.registry_endpoint, s2.registry_endpoint);
    assert_ne!(
        s1.registry_endpoint_generation,
        s2.registry_endpoint_generation
    );
    assert_ne!(s1.launch_connection, s2.launch_connection);
    assert_ne!(s1.launch_generation, s2.launch_generation);
    assert_eq!(s1.outer_connection, s2.outer_connection);
    assert_eq!(
        s1.outer_connection_generation,
        s2.outer_connection_generation
    );
    assert_ne!(s1.outer_transaction, s2.outer_transaction);
    assert_ne!(s1.wrlp_transaction, s2.wrlp_transaction);
    assert_eq!(s1.registry_generation, s2.registry_generation);
    let second_resources = model.attempt().resource_ids();
    assert!(
        first_resources
            .iter()
            .all(|id| !second_resources.contains(id))
    );
    model.normal_exit(TerminalEvent(s2)).unwrap();
    model.registry_actor_observes_client_peer_close(s2).unwrap();
    model.ledger.assert_exact_accounting();
}

#[test]
fn every_prepare_and_commit_edge_has_a_cleanup_path() {
    let boundaries = [
        Phase::ConsoleReserved,
        Phase::OuterCapsPrepared,
        Phase::OuterMoveCommitted,
        Phase::OuterReserved,
        Phase::RegistryPairPrepared,
        Phase::RegistryMoveCommitted,
        Phase::RegistrySweep,
        Phase::RegistryInstallProcessed,
        Phase::MetadataProbePending,
        Phase::MetadataProbeReply,
        Phase::NestedPairPrepared,
        Phase::NestedInstalled,
        Phase::LoaderPrepared,
        Phase::LoaderCommitted,
        Phase::InitMoveCommitted,
        Phase::Ready,
        Phase::RunningConfirmed,
        Phase::OuterPublished,
        Phase::AcceptedSent,
        Phase::LaunchReleased,
        Phase::Operating,
    ];
    for boundary in boundaries {
        let mut model = Model::new();
        let event = model.stage_to(boundary).unwrap();
        model.fail_current(Failure::Injected(boundary)).unwrap();
        model.cleanup_after_failure().unwrap();
        if model.poisoned_registry_generation.is_some() {
            model
                .registry_generation_terminal_reaped(event.registry_generation)
                .unwrap();
            model.rebuild_console_launcher_authority().unwrap();
        }
        assert!(model.current.is_none(), "boundary {boundary:?}");
        model.ledger.assert_exact_accounting();
        assert_eq!(model.begin().is_ok(), model.failed_generations < 4);
    }
}

#[test]
fn failed_sends_retain_sender_ownership_but_post_move_rejection_does_not() {
    let mut before_move = Model::new();
    before_move.stage_to(Phase::OuterCapsPrepared).unwrap();
    let child = before_move.attempt().child_caps.unwrap()[0];
    let console = before_move.attempt().ids.console;
    assert_eq!(
        before_move.ledger.owner(child),
        Ok(Owner::Consoled(console))
    );
    before_move.outer_send_failed_before_move().unwrap();
    assert_eq!(before_move.ledger.resource(child).close_count, 1);

    let mut after_move = Model::new();
    after_move.stage_to(Phase::OuterMoveCommitted).unwrap();
    let child = after_move.attempt().child_caps.unwrap()[0];
    let console = after_move.attempt().ids.console;
    assert_eq!(after_move.ledger.owner(child), Ok(Owner::Init));
    after_move.receiver_policy_rejects_after_move().unwrap();
    assert_eq!(after_move.ledger.resource(child).close_count, 1);
    assert_eq!(
        after_move.ledger.close(child, Owner::Consoled(console)),
        Err(ModelError::AlreadyClosed)
    );

    let mut init_send = Model::new();
    let event = init_send.stage_to(Phase::LoaderCommitted).unwrap();
    let roles = init_send.attempt().child_caps.unwrap();
    init_send.init_send_failed_before_move().unwrap();
    assert!(
        roles
            .iter()
            .all(|id| init_send.ledger.owner(*id) == Ok(Owner::Init))
    );
    complete_poisoned_failure(&mut init_send, event);
}

#[test]
fn registry_receiver_processing_and_metadata_probe_precede_init_move() {
    let mut delayed = Model::new();
    let event = delayed.stage_to(Phase::RegistryMoveCommitted).unwrap();
    let unrelated = delayed.install_unrelated_registry_slot().unwrap();
    assert!(delayed.attempt().registry_move_committed);
    assert!(!delayed.attempt().registry_install_processed);
    assert!(!delayed.attempt().metadata_probe_replied);
    assert_eq!(
        delayed.prepare_nested_session(),
        Err(ModelError::WrongState)
    );
    delayed.registry_sweep().unwrap();
    assert_eq!(
        delayed.ledger.owner(unrelated.server),
        Ok(Owner::Registryd(unrelated.generation))
    );
    delayed.registry_process_install().unwrap();
    assert!(delayed.attempt().registry_install_processed);
    delayed.send_registry_metadata_probe().unwrap();
    let mut bad = metadata_page(event, 0, MAX_METADATA_PAGES + 1, 1, 1);
    assert_eq!(
        delayed.registry_metadata_probe_page(bad),
        Err(ModelError::Identity)
    );
    bad = metadata_page(event, 0, 1, 0, 0);
    bad.handles = 1;
    assert_eq!(
        delayed.registry_metadata_probe_page(bad),
        Err(ModelError::Identity)
    );
    bad.handles = 0;
    bad.canonical = false;
    assert_eq!(
        delayed.registry_metadata_probe_page(bad),
        Err(ModelError::Identity)
    );
    bad = metadata_page(stale(event), 0, 3, 2, 5);
    assert_eq!(
        delayed.registry_metadata_probe_page(bad),
        Err(ModelError::Stale)
    );
    bad = metadata_page(event, 0, 3, 2, 5);
    bad.transaction = 2;
    assert_eq!(
        delayed.registry_metadata_probe_page(bad),
        Err(ModelError::Stale)
    );
    delayed
        .registry_metadata_probe_page(metadata_page(event, 0, 3, 2, 5))
        .unwrap();
    assert_eq!(
        delayed.prepare_nested_session(),
        Err(ModelError::WrongState)
    );
    assert_eq!(
        delayed.registry_metadata_probe_page(metadata_page(event, 2, 3, 1, 5)),
        Err(ModelError::Stale)
    );
    delayed
        .registry_metadata_probe_page(metadata_page(event, 1, 3, 2, 5))
        .unwrap();
    assert_eq!(delayed.attempt().phase, Phase::MetadataProbePending);
    delayed
        .registry_metadata_probe_page(metadata_page(event, 2, 3, 1, 5))
        .unwrap();
    assert!(delayed.attempt().metadata_probe_replied);
    assert_eq!(delayed.attempt().metadata_probe, None);
    delayed.prepare_nested_session().unwrap();
    delayed.install_nested_unpublished().unwrap();
    delayed.prepare_loader().unwrap();
    delayed.commit_loader_construction().unwrap();
    delayed.commit_six_role_init_move().unwrap();
    assert_eq!(delayed.attempt().shell_registry_transaction, Some(2));

    let mut rejected = Model::new();
    rejected.stage_to(Phase::RegistrySweep).unwrap();
    let server = rejected.attempt().registry_server.unwrap();
    let generation = rejected.attempt().ids.registry_generation;
    rejected.registry_rejects_install_after_move().unwrap();
    assert_eq!(rejected.ledger.resource(server).close_count, 1);
    assert_eq!(
        rejected.ledger.close(server, Owner::Init),
        Err(ModelError::AlreadyClosed)
    );
    assert_eq!(rejected.poisoned_registry_generation, None);
    rejected.cleanup_after_failure().unwrap();
    assert_eq!(rejected.active_registry_generation, generation);
    assert!(rejected.begin().is_ok());
}

#[test]
fn next_install_waits_for_exact_outer_task_group_reap() {
    let mut model = Model::new();
    let s1 = launch_operating(&mut model);
    let task_group = model
        .normal_exit_with_delayed_task_group(TerminalEvent(s1))
        .unwrap();
    assert_eq!(model.ledger.owner(task_group), Ok(Owner::Init));

    let s2 = model.begin().unwrap();
    model.prepare_outer_caps().unwrap();
    model.commit_outer_move().unwrap();
    model.reserve_outer_accounting().unwrap();
    model.prepare_registry_pair().unwrap();
    assert_eq!(
        model.commit_registry_move(),
        Err(ModelError::CleanupBlocked)
    );
    model.complete_delayed_task_group_reap(s1).unwrap();
    model.commit_registry_move().unwrap();
    model.registry_sweep().unwrap();
    finish_launch_after_registry_sweep(&mut model, s2);
    model.normal_exit(TerminalEvent(s2)).unwrap();
    model.registry_actor_observes_client_peer_close(s2).unwrap();
    model.ledger.assert_exact_accounting();
}

#[test]
fn registry_install_is_local_before_move_and_poisoned_after_ambiguous_move() {
    let mut local = Model::new();
    local.stage_to(Phase::RegistryPairPrepared).unwrap();
    let registry_server = local.attempt().registry_server.unwrap();
    local.close_pre_registry_failure_locally().unwrap();
    assert_eq!(local.poisoned_registry_generation, None);
    assert_eq!(local.ledger.resource(registry_server).close_count, 1);
    assert!(local.begin().is_ok());

    let mut ambiguous = Model::new();
    let event = ambiguous.stage_to(Phase::RegistryMoveCommitted).unwrap();
    let registry_server = ambiguous.attempt().registry_server.unwrap();
    ambiguous
        .fail_current(Failure::Injected(Phase::RegistryMoveCommitted))
        .unwrap();
    ambiguous.cleanup_after_failure().unwrap();
    assert_eq!(
        ambiguous.ledger.owner(registry_server),
        Ok(Owner::Registryd(event.registry_generation))
    );
    assert_eq!(ambiguous.begin(), Err(ModelError::CleanupBlocked));
    ambiguous
        .registry_generation_terminal_reaped(event.registry_generation)
        .unwrap();
    assert_eq!(ambiguous.ledger.resource(registry_server).close_count, 1);
    assert_eq!(ambiguous.begin(), Err(ModelError::CleanupBlocked));
    ambiguous.rebuild_console_launcher_authority().unwrap();
    assert!(ambiguous.begin().is_ok());
}

#[test]
fn ready_response_race_never_accepts_a_terminal_shell() {
    let mut model = Model::new();
    let event = model.stage_to(Phase::Ready).unwrap();
    assert_eq!(model.attempt().outer_job_id, None);
    model
        .shell_exits_before_response(TerminalEvent(event))
        .unwrap();
    model
        .registry_actor_observes_client_peer_close(event)
        .unwrap();
    model.cleanup_after_failure().unwrap();
    assert!(!model.retired.last().unwrap().accepted_delivered);

    let mut published = Model::new();
    let event = published.stage_to(Phase::OuterPublished).unwrap();
    published
        .shell_exits_before_response(TerminalEvent(event))
        .unwrap();
    published
        .registry_actor_observes_client_peer_close(event)
        .unwrap();
    published.cleanup_after_failure().unwrap();
    let retired = published.retired.last().unwrap();
    assert!(retired.outer_job_id.is_some());
    assert!(!retired.accepted_delivered);
}

#[test]
fn stale_events_and_duplicate_accounting_are_rejected() {
    let mut model = Model::new();
    let event = model.stage_to(Phase::InitMoveCommitted).unwrap();
    let ready = model.ready_event();
    assert_eq!(
        model.observe_ready(ReadyEvent {
            wrlp_transaction: ready.wrlp_transaction + 1,
            ..ready
        }),
        Err(ModelError::Stale)
    );
    assert_eq!(model.attempt().phase, Phase::InitMoveCommitted);
    model.observe_ready(ready).unwrap();
    model.confirm_fresh_process_running(event).unwrap();
    model.publish_outer_and_session().unwrap();
    model.deliver_launch_accepted().unwrap();
    model.release_bootstrap_launch_peer().unwrap();
    model.begin_shell_operations().unwrap();
    assert_eq!(
        model.normal_exit(TerminalEvent(EventIdentity {
            outer_connection_generation: event.outer_connection_generation + 1,
            ..event
        })),
        Err(ModelError::Stale)
    );
    assert_eq!(
        model.normal_exit(TerminalEvent(stale(event))),
        Err(ModelError::Stale)
    );
    model.normal_exit(TerminalEvent(event)).unwrap();
    assert_eq!(
        model.registry_actor_observes_client_peer_close(stale(event)),
        Err(ModelError::Stale)
    );
    let process = model.attempt().process.unwrap();
    let status = model.attempt().child_caps.unwrap()[3];
    assert_eq!(
        model.ledger.reap(process, Owner::Init),
        Err(ModelError::AlreadyReaped)
    );
    assert_eq!(
        model.ledger.close(status, Owner::Shell(event.shell)),
        Err(ModelError::AlreadyClosed)
    );
    model
        .registry_actor_observes_client_peer_close(event)
        .unwrap();
}

#[test]
fn cleanup_failure_is_sticky_and_dominates_the_trigger() {
    let mut model = Model::new();
    model.stage_to(Phase::NestedInstalled).unwrap();
    let original = Failure::Injected(Phase::NestedInstalled);
    model.fail_current(original).unwrap();
    assert_eq!(
        model.record_cleanup_failure(),
        Err(ModelError::CleanupBlocked)
    );
    assert_eq!(
        model.current_failure(),
        (Some(original), Some(Failure::Cleanup))
    );
    assert_eq!(
        model.cleanup_after_failure(),
        Err(ModelError::CleanupBlocked)
    );
    assert_eq!(model.begin(), Err(ModelError::CleanupBlocked));
}

#[test]
fn delayed_cleanup_and_failure_exhaustion_block_overlap() {
    let mut model = Model::new();
    for generation in 0..MAX_FAILED_GENERATIONS {
        let event = model.stage_to(Phase::RegistryMoveCommitted).unwrap();
        model
            .fail_current(Failure::Injected(Phase::RegistryMoveCommitted))
            .unwrap();
        assert_eq!(model.begin(), Err(ModelError::CleanupBlocked));
        model.cleanup_after_failure().unwrap();
        assert_eq!(model.begin(), Err(ModelError::CleanupBlocked));
        model
            .registry_generation_terminal_reaped(event.registry_generation)
            .unwrap();
        model.rebuild_console_launcher_authority().unwrap();
        if generation + 1 < MAX_FAILED_GENERATIONS {
            assert!(model.current.is_none());
        }
    }
    assert_eq!(model.begin(), Err(ModelError::Exhausted));
}

#[test]
fn unpublished_session_removes_once_and_published_orphans_stay_isolated() {
    let mut unpublished = Model::new();
    let event = unpublished.stage_to(Phase::NestedInstalled).unwrap();
    unpublished
        .fail_current(Failure::Injected(Phase::NestedInstalled))
        .unwrap();
    complete_poisoned_failure(&mut unpublished, event);
    assert_eq!(unpublished.retired.last().unwrap().nested_remove_count, 1);

    let mut model = Model::new();
    let s1 = launch_operating(&mut model);
    let shell_process = model.attempt().process.unwrap();
    let nested_controller = model.attempt().shell_jobs_controller.unwrap();
    let old_job = model.start_inner_job().unwrap();
    let old_process = model.attempt().jobs[0].process;
    model.normal_exit(TerminalEvent(s1)).unwrap();
    model.registry_actor_observes_client_peer_close(s1).unwrap();
    assert_eq!(model.ledger.resource(shell_process).reap_count, 1);
    assert_eq!(model.ledger.resource(nested_controller).close_count, 1);
    assert_eq!(
        model.ledger.reap(shell_process, Owner::Init),
        Err(ModelError::AlreadyReaped)
    );
    assert_eq!(model.orphan_jobs(), vec![old_job]);
    assert_eq!(model.ledger.owner(old_process), Ok(Owner::Init));

    let s2 = launch_operating(&mut model);
    assert!(model.visible_jobs().is_empty());
    assert_eq!(model.orphan_jobs(), vec![old_job]);
    assert_eq!(model.ledger.owner(old_process), Ok(Owner::Init));
    model.reap_orphan(old_job).unwrap();
    assert!(model.orphan_jobs().is_empty());
    assert_eq!(model.ledger.resource(old_process).reap_count, 1);
    model.normal_exit(TerminalEvent(s2)).unwrap();
    model.registry_actor_observes_client_peer_close(s2).unwrap();
    model.ledger.assert_exact_accounting();
}

#[test]
fn status_loss_is_fatal_and_ready_has_no_circular_job_dependency() {
    let mut model = Model::new();
    let event = model.stage_to(Phase::InitMoveCommitted).unwrap();
    assert_eq!(model.attempt().outer_job_id, None);
    let ready = model.ready_event();
    model.observe_ready(ready).unwrap();
    assert_eq!(model.attempt().outer_job_id, None);
    model.confirm_fresh_process_running(event).unwrap();
    model.publish_outer_and_session().unwrap();
    model.deliver_launch_accepted().unwrap();
    model.release_bootstrap_launch_peer().unwrap();
    model.begin_shell_operations().unwrap();
    model.status_peer_lost(event).unwrap();
    assert_eq!(
        model.current_failure(),
        (Some(Failure::StatusLost), Some(Failure::StatusLost))
    );
    complete_poisoned_failure(&mut model, event);
}

#[test]
fn pre_registry_rejection_does_not_block_a_later_install() {
    let mut model = Model::new();
    model.stage_to(Phase::OuterMoveCommitted).unwrap();
    model.receiver_policy_rejects_after_move().unwrap();
    let replacement = launch_operating(&mut model);
    model.normal_exit(TerminalEvent(replacement)).unwrap();
    model
        .registry_actor_observes_client_peer_close(replacement)
        .unwrap();
    model.ledger.assert_exact_accounting();
}

#[test]
fn registry_recovery_refreshes_console_and_outer_launcher_authority() {
    let mut model = Model::new();
    let old = model.stage_to(Phase::RegistryMoveCommitted).unwrap();
    model
        .fail_current(Failure::Injected(Phase::RegistryMoveCommitted))
        .unwrap();
    model.cleanup_after_failure().unwrap();
    model
        .registry_generation_terminal_reaped(old.registry_generation)
        .unwrap();
    assert_eq!(model.begin(), Err(ModelError::CleanupBlocked));
    model.rebuild_console_launcher_authority().unwrap();
    let new = model.begin().unwrap();
    assert_ne!(old.console, new.console);
    assert_ne!(old.outer_connection, new.outer_connection);
    assert_ne!(
        old.outer_connection_generation,
        new.outer_connection_generation
    );
}

#[test]
fn registry_sweep_and_client_admission_use_separate_bounds() {
    let mut full_snapshot = Model::new();
    let event = full_snapshot
        .stage_to(Phase::RegistryMoveCommitted)
        .unwrap();
    let mut first = None;
    for _ in 0..MAX_REGISTRY_ENDPOINTS {
        let slot = full_snapshot.install_unrelated_registry_slot().unwrap();
        first.get_or_insert(slot);
    }
    let first = first.unwrap();
    full_snapshot.ledger.close(first.peer, Owner::Init).unwrap();
    full_snapshot.registry_sweep().unwrap();
    assert_eq!(full_snapshot.ledger.owner(first.server), Ok(Owner::Closed));
    assert!(full_snapshot.attempt().matches(event));

    let mut within_client_limit = Model::new();
    within_client_limit
        .stage_to(Phase::RegistryMoveCommitted)
        .unwrap();
    for _ in 0..(MAX_REGISTRY_CLIENTS - 1) {
        within_client_limit
            .install_unrelated_registry_slot()
            .unwrap();
    }
    within_client_limit.registry_sweep().unwrap();
    within_client_limit.registry_process_install().unwrap();

    let mut exhausted_clients = Model::new();
    exhausted_clients
        .stage_to(Phase::RegistryMoveCommitted)
        .unwrap();
    for _ in 0..MAX_REGISTRY_CLIENTS {
        exhausted_clients.install_unrelated_registry_slot().unwrap();
    }
    exhausted_clients.registry_sweep().unwrap();
    assert_eq!(
        exhausted_clients.registry_process_install(),
        Err(ModelError::Exhausted)
    );
}
