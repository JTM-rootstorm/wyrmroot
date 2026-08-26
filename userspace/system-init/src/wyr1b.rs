//! WYR1-B controller-owned registry topology and launch/job state.

use wyrmroot_bootfs::{
    archive::{Archive, LookupError},
    launch_policy::{LAUNCH_POLICY_PATH, LaunchPolicy, PolicyError},
};
use wyrmroot_launch_proto::{MAX_COMPLETED_JOBS, MAX_LIVE_JOBS, Reservation};
use wyrmroot_loader::{
    launch::LaunchProfile,
    process::{
        JobLoadRequest, LoadAuthority, LoadError, LoadedProcess, LoaderPlatform, load_job_process,
    },
};
use wyrmroot_registry_proto::{Correlation, CorrelationEnvironment};
use wyrmroot_runtime::{
    ObservedSupervisionError, SupervisionPlatform, await_child_ready_profile_observed, sha256,
};

const MAX_CONNECTIONS: usize = 16;
const REPLAY_RECORDS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointKind {
    Publication,
    RegistryClient,
    LaunchSession,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointGrant {
    pub registry_generation: u64,
    pub endpoint_id: u64,
    pub endpoint_generation: u64,
    pub role_generation: u64,
    pub kind: EndpointKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryTopology {
    registry_generation: u64,
    next_endpoint_id: u64,
}

impl RegistryTopology {
    pub fn new(registry_generation: u64) -> Result<Self, JobError> {
        if registry_generation == 0 {
            return Err(JobError::ZeroIdentity);
        }
        Ok(Self {
            registry_generation,
            next_endpoint_id: 1,
        })
    }

    pub fn issue(
        &mut self,
        role_generation: u64,
        kind: EndpointKind,
    ) -> Result<EndpointGrant, JobError> {
        if role_generation == 0 {
            return Err(JobError::ZeroIdentity);
        }
        let endpoint_id = self.next_endpoint_id;
        self.next_endpoint_id = self
            .next_endpoint_id
            .checked_add(1)
            .ok_or(JobError::ArithmeticOverflow)?;
        Ok(EndpointGrant {
            registry_generation: self.registry_generation,
            endpoint_id,
            endpoint_generation: 1,
            role_generation,
            kind,
        })
    }

    pub fn restart(&mut self, next_generation: u64) -> Result<(), JobError> {
        if next_generation <= self.registry_generation {
            return Err(JobError::StaleGeneration);
        }
        self.registry_generation = next_generation;
        Ok(())
    }

    pub const fn accepts(&self, grant: EndpointGrant) -> bool {
        grant.registry_generation == self.registry_generation
    }
}

pub fn correlation_environment(grant: EndpointGrant) -> Result<CorrelationEnvironment, JobError> {
    if !matches!(
        grant.kind,
        EndpointKind::Publication | EndpointKind::RegistryClient
    ) {
        return Err(JobError::WrongState);
    }
    CorrelationEnvironment::new(Correlation {
        registry_generation: grant.registry_generation,
        endpoint_id: grant.endpoint_id,
        endpoint_generation: grant.endpoint_generation,
    })
    .map_err(|_| JobError::ZeroIdentity)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyView<'a> {
    policy: LaunchPolicy<'a>,
    archive: Archive<'a>,
}

impl<'a> PolicyView<'a> {
    pub fn from_bootfs(
        archive: Archive<'a>,
        expected_boot_generation: [u8; 32],
    ) -> Result<Self, JobError> {
        let entry = archive
            .lookup(LAUNCH_POLICY_PATH.as_bytes())
            .map_err(JobError::Bootfs)?;
        if entry.is_executable() {
            return Err(JobError::PolicyExecutable);
        }
        let policy = LaunchPolicy::parse(entry.data()).map_err(JobError::Policy)?;
        if policy.boot_generation_sha256() != expected_boot_generation {
            return Err(JobError::BootGenerationMismatch);
        }
        for index in 0..policy.len() {
            let policy_entry = policy.entry(index).ok_or(JobError::PolicyMissing)??;
            let artifact = archive
                .lookup(policy_entry.path.as_bytes())
                .map_err(JobError::Bootfs)?;
            if !artifact.is_executable() {
                return Err(JobError::ArtifactNotExecutable);
            }
            if sha256::digest(artifact.data()) != policy_entry.content_sha256 {
                return Err(JobError::ArtifactIdentityMismatch);
            }
        }
        Ok(Self { policy, archive })
    }

    pub fn authorize(&self, path: &str, streams: usize) -> Result<&'a [u8], JobError> {
        let entry = self.policy.find(path).ok_or(JobError::PolicyMissing)?;
        match streams {
            0 if entry.allow_no_streams => {}
            3 if entry.allow_three_streams => {}
            _ => return Err(JobError::StreamPolicy),
        }
        let artifact = self
            .archive
            .lookup(path.as_bytes())
            .map_err(JobError::Bootfs)?;
        if !artifact.is_executable() || sha256::digest(artifact.data()) != entry.content_sha256 {
            return Err(JobError::ArtifactIdentityMismatch);
        }
        Ok(artifact.data())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobPhase {
    Reserved,
    Running,
    Terminating,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobSnapshot {
    pub job_id: u64,
    pub phase: JobPhase,
    pub orphaned: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobResources {
    pub process: u64,
    pub task_group: u64,
    pub launch_channel: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobResult {
    pub classification: u32,
    pub application_code: u32,
    pub exception_class: u32,
    pub exception_detail: u32,
    pub exception_address: u64,
    pub cleanup_result: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaunchTicket {
    slot: usize,
    pub job_id: u64,
    owner: ConnectionIdentity,
    transaction_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RequestTicket {
    owner: ConnectionIdentity,
    transaction_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConnectionIdentity {
    id: u64,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Replay {
    values: [u64; REPLAY_RECORDS],
    start: usize,
    len: usize,
}
impl Replay {
    const fn new() -> Self {
        Self {
            values: [0; REPLAY_RECORDS],
            start: 0,
            len: 0,
        }
    }
    fn contains(&self, value: u64) -> bool {
        (0..self.len).any(|index| self.values[(self.start + index) % REPLAY_RECORDS] == value)
    }
    fn push(&mut self, value: u64) {
        if self.len < REPLAY_RECORDS {
            self.values[(self.start + self.len) % REPLAY_RECORDS] = value;
            self.len += 1;
        } else {
            self.values[self.start] = value;
            self.start = (self.start + 1) % REPLAY_RECORDS;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Connection {
    identity: ConnectionIdentity,
    replay: Replay,
    open: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Job {
    id: u64,
    owner: ConnectionIdentity,
    phase: JobPhase,
    orphaned: bool,
    process: u64,
    task_group: u64,
    launch_channel: u64,
    terminal: Option<JobResult>,
    cleanup_result: u32,
    published: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Completed {
    id: u64,
    owner: ConnectionIdentity,
    result: JobResult,
    visible: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub struct JobController {
    connections: [Option<Connection>; MAX_CONNECTIONS],
    jobs: [Option<Job>; MAX_LIVE_JOBS],
    completed: [Option<Completed>; MAX_COMPLETED_JOBS],
    completed_start: usize,
    completed_len: usize,
    next_job_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobError {
    ZeroIdentity,
    ArithmeticOverflow,
    Capacity,
    DuplicateConnection,
    UnknownConnection,
    ClosedConnection,
    StaleGeneration,
    TransactionReplay,
    ForeignJob,
    UnknownJob,
    WrongState,
    ResourceIdentity,
    Policy(PolicyError),
    PolicyMissing,
    PolicyExecutable,
    Bootfs(LookupError),
    BootGenerationMismatch,
    ArtifactNotExecutable,
    ArtifactIdentityMismatch,
    StreamPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadedJob {
    pub job_id: u64,
    pub loaded: LoadedProcess,
    pub task_group: u64,
}

/// A loader-committed launch which is deliberately not yet visible to the
/// session owner. The dispatcher publishes it only after the exact profile
/// READY observation, so a READY-and-exited race cannot yield acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedJob {
    ticket: LaunchTicket,
    profile: LaunchProfile,
    transaction_id: u64,
    pub loaded: LoadedProcess,
    pub task_group: u64,
}

impl PreparedJob {
    pub(crate) const fn job_id(self) -> u64 {
        self.ticket.job_id
    }
}

/// Proof supplied only after the native dispatcher has consumed the exact
/// profile/transaction READY record and separately excluded child exit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExactReadyObservation {
    profile: LaunchProfile,
    transaction_id: u64,
    process: deepwyrm_syscall::DwHandle,
    launch_channel: deepwyrm_syscall::DwHandle,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ReadyObservationError<E> {
    Ready(ObservedSupervisionError<E>),
    TerminalQuery(E),
    ReadyAndExited(deepwyrm_syscall::DwTaskTerminationInfoV1),
    NotRunning(deepwyrm_syscall::DwTaskTerminationInfoV1),
}

/// Constructs the publication proof only after parsing this child's exact
/// READY and performing a fresh Process termination query.
pub(crate) fn observe_prepared_ready<W: SupervisionPlatform>(
    waits: &mut W,
    prepared: &PreparedJob,
    deadline: deepwyrm_syscall::DwDeadline,
) -> Result<ExactReadyObservation, ReadyObservationError<W::Error>> {
    await_child_ready_profile_observed(
        waits,
        prepared.loaded.process,
        prepared.loaded.launch_channel,
        prepared.profile,
        prepared.transaction_id,
        deadline,
    )
    .map_err(ReadyObservationError::Ready)?;
    let terminal = waits
        .query_task_termination(prepared.loaded.process)
        .map_err(ReadyObservationError::TerminalQuery)?;
    if terminal.state == deepwyrm_syscall::DW_TASK_STATE_EXITED {
        return Err(ReadyObservationError::ReadyAndExited(terminal));
    }
    if terminal.state != deepwyrm_syscall::DW_TASK_STATE_RUNNING {
        return Err(ReadyObservationError::NotRunning(terminal));
    }
    Ok(ExactReadyObservation {
        profile: prepared.profile,
        transaction_id: prepared.transaction_id,
        process: prepared.loaded.process,
        launch_channel: prepared.loaded.launch_channel,
    })
}

#[derive(Debug, Eq, PartialEq)]
pub enum LaunchEngineError<E> {
    Job(JobError),
    Validation {
        error: JobError,
        abort_failed: bool,
        cleanup_failed: bool,
    },
    Loader {
        error: LoadError<E>,
        streams_consumed: bool,
        abort_failed: bool,
        cleanup_failed: bool,
    },
    Publication {
        error: JobError,
        ticket: LaunchTicket,
        loaded: LoadedProcess,
        task_group: u64,
    },
}

impl From<PolicyError> for JobError {
    fn from(value: PolicyError) -> Self {
        Self::Policy(value)
    }
}

impl JobController {
    pub const fn new() -> Self {
        Self {
            connections: [None; MAX_CONNECTIONS],
            jobs: [None; MAX_LIVE_JOBS],
            completed: [None; MAX_COMPLETED_JOBS],
            completed_start: 0,
            completed_len: 0,
            next_job_id: 1,
        }
    }

    pub fn open_connection(&mut self, id: u64, generation: u64) -> Result<(), JobError> {
        let identity = identity(id, generation)?;
        if self
            .connections
            .iter()
            .flatten()
            .any(|value| value.identity.id == id)
        {
            return Err(JobError::DuplicateConnection);
        }
        let slot = self
            .connections
            .iter()
            .position(Option::is_none)
            .ok_or(JobError::Capacity)?;
        self.connections[slot] = Some(Connection {
            identity,
            replay: Replay::new(),
            open: true,
        });
        Ok(())
    }

    pub(crate) fn reserve_request(
        &mut self,
        request: Reservation,
    ) -> Result<RequestTicket, JobError> {
        Ok(RequestTicket {
            owner: self.reserve_transaction(request)?,
            transaction_id: request.transaction_id,
        })
    }

    pub fn begin_launch(&mut self, request: Reservation) -> Result<LaunchTicket, JobError> {
        let ticket = self.reserve_request(request)?;
        self.begin_reserved_launch(ticket)
    }

    pub(crate) fn begin_reserved_launch(
        &mut self,
        request: RequestTicket,
    ) -> Result<LaunchTicket, JobError> {
        let slot = self
            .jobs
            .iter()
            .position(Option::is_none)
            .ok_or(JobError::Capacity)?;
        let job_id = self.next_job_id;
        self.next_job_id = self
            .next_job_id
            .checked_add(1)
            .ok_or(JobError::ArithmeticOverflow)?;
        self.jobs[slot] = Some(Job {
            id: job_id,
            owner: request.owner,
            phase: JobPhase::Reserved,
            orphaned: false,
            process: 0,
            task_group: 0,
            launch_channel: 0,
            terminal: None,
            cleanup_result: 0,
            published: false,
        });
        Ok(LaunchTicket {
            slot,
            job_id,
            owner: request.owner,
            transaction_id: request.transaction_id,
        })
    }

    pub fn commit_launch(
        &mut self,
        ticket: LaunchTicket,
        process: u64,
        task_group: u64,
        launch_channel: u64,
    ) -> Result<(), JobError> {
        if process == 0 || task_group == 0 || launch_channel == 0 {
            return Err(JobError::ResourceIdentity);
        }
        let job = self
            .jobs
            .get_mut(ticket.slot)
            .and_then(Option::as_mut)
            .ok_or(JobError::UnknownJob)?;
        if job.id != ticket.job_id || job.owner != ticket.owner || job.phase != JobPhase::Reserved {
            return Err(JobError::WrongState);
        }
        if job.process == 0 && job.task_group == 0 && job.launch_channel == 0 {
            job.process = process;
            job.task_group = task_group;
            job.launch_channel = launch_channel;
        } else if job.process != process
            || job.task_group != task_group
            || job.launch_channel != launch_channel
        {
            return Err(JobError::ResourceIdentity);
        }
        job.phase = JobPhase::Running;
        job.published = true;
        Ok(())
    }

    pub(crate) fn stage_launch(
        &mut self,
        ticket: LaunchTicket,
        process: u64,
        task_group: u64,
        launch_channel: u64,
    ) -> Result<(), JobError> {
        if process == 0 || task_group == 0 || launch_channel == 0 {
            return Err(JobError::ResourceIdentity);
        }
        let job = self
            .jobs
            .get_mut(ticket.slot)
            .and_then(Option::as_mut)
            .ok_or(JobError::UnknownJob)?;
        if job.id != ticket.job_id
            || job.owner != ticket.owner
            || job.phase != JobPhase::Reserved
            || job.process != 0
            || job.task_group != 0
            || job.launch_channel != 0
        {
            return Err(JobError::WrongState);
        }
        job.process = process;
        job.task_group = task_group;
        job.launch_channel = launch_channel;
        Ok(())
    }

    pub fn abort_launch(&mut self, ticket: LaunchTicket) -> Result<(), JobError> {
        let job = self
            .jobs
            .get(ticket.slot)
            .and_then(Option::as_ref)
            .ok_or(JobError::UnknownJob)?;
        if job.id != ticket.job_id || job.owner != ticket.owner || job.phase != JobPhase::Reserved {
            return Err(JobError::WrongState);
        }
        self.jobs[ticket.slot] = None;
        Ok(())
    }

    pub fn query(&mut self, request: Reservation, job_id: u64) -> Result<JobSnapshot, JobError> {
        let ticket = self.reserve_request(request)?;
        self.query_reserved(ticket, job_id)
    }

    pub(crate) fn query_reserved(
        &self,
        request: RequestTicket,
        job_id: u64,
    ) -> Result<JobSnapshot, JobError> {
        let job = self.owned_job(request.owner, job_id)?;
        Ok(JobSnapshot {
            job_id,
            phase: job.phase,
            orphaned: job.orphaned,
        })
    }

    pub fn terminate(
        &mut self,
        request: Reservation,
        job_id: u64,
    ) -> Result<JobResources, JobError> {
        let ticket = self.reserve_request(request)?;
        let resources = self.authorize_terminate_reserved(ticket, job_id)?;
        self.commit_terminate(job_id, resources)?;
        Ok(resources)
    }

    pub(crate) fn authorize_terminate_reserved(
        &self,
        request: RequestTicket,
        job_id: u64,
    ) -> Result<JobResources, JobError> {
        let index = self.owned_job_index(request.owner, job_id)?;
        let job = self.jobs[index].as_ref().unwrap();
        if job.phase != JobPhase::Running {
            return Err(JobError::WrongState);
        }
        Ok(JobResources {
            process: job.process,
            task_group: job.task_group,
            launch_channel: job.launch_channel,
        })
    }

    pub(crate) fn commit_terminate(
        &mut self,
        job_id: u64,
        resources: JobResources,
    ) -> Result<(), JobError> {
        let job = self
            .jobs
            .iter_mut()
            .flatten()
            .find(|job| job.id == job_id)
            .ok_or(JobError::UnknownJob)?;
        if job.phase != JobPhase::Running
            || job.process != resources.process
            || job.task_group != resources.task_group
            || job.launch_channel != resources.launch_channel
        {
            return Err(JobError::ResourceIdentity);
        }
        job.phase = JobPhase::Terminating;
        Ok(())
    }

    pub(crate) fn record_cleanup_bits(&mut self, job_id: u64, bits: u32) -> Result<(), JobError> {
        if bits & !wyrmroot_launch_proto::CLEANUP_RESULT_MASK != 0 {
            return Err(JobError::ResourceIdentity);
        }
        let job = self
            .jobs
            .iter_mut()
            .flatten()
            .find(|job| job.id == job_id)
            .ok_or(JobError::UnknownJob)?;
        job.cleanup_result |= bits;
        Ok(())
    }

    pub fn complete(
        &mut self,
        job_id: u64,
        process: u64,
        task_group: u64,
        launch_channel: u64,
        result: JobResult,
    ) -> Result<(), JobError> {
        let index = self
            .jobs
            .iter()
            .position(|job| job.as_ref().is_some_and(|job| job.id == job_id))
            .ok_or(JobError::UnknownJob)?;
        let job = self.jobs[index].take().unwrap();
        if job.phase == JobPhase::Reserved
            || job.process != process
            || job.task_group != task_group
            || job.launch_channel != launch_channel
        {
            self.jobs[index] = Some(job);
            return Err(JobError::ResourceIdentity);
        }
        self.push_completed(Completed {
            id: job.id,
            owner: job.owner,
            result,
            visible: job.published && !job.orphaned,
        });
        Ok(())
    }

    pub(crate) fn terminal_result(&self, job_id: u64) -> Result<Option<JobResult>, JobError> {
        self.jobs
            .iter()
            .flatten()
            .find(|job| job.id == job_id)
            .map(|job| job.terminal)
            .ok_or(JobError::UnknownJob)
    }

    pub(crate) fn apply_cleanup_progress(
        &mut self,
        job_id: u64,
        mut terminal: JobResult,
        closed_mask: u32,
        failed_bits: u32,
    ) -> Result<Option<JobResult>, JobError> {
        const CLOSE_MASK: u32 = (1 << 2) | (1 << 3) | (1 << 4);
        if closed_mask & !CLOSE_MASK != 0
            || failed_bits & !wyrmroot_launch_proto::CLEANUP_RESULT_MASK != 0
        {
            return Err(JobError::ResourceIdentity);
        }
        terminal.cleanup_result = 0;
        let index = self
            .jobs
            .iter()
            .position(|job| job.as_ref().is_some_and(|job| job.id == job_id))
            .ok_or(JobError::UnknownJob)?;
        let job = self.jobs[index].as_mut().unwrap();
        if let Some(previous) = job.terminal {
            let mut previous = previous;
            previous.cleanup_result = 0;
            if previous != terminal {
                return Err(JobError::ResourceIdentity);
            }
        } else {
            job.terminal = Some(terminal);
        }
        if closed_mask & (1 << 2) != 0 {
            job.launch_channel = 0;
        }
        if closed_mask & (1 << 3) != 0 {
            job.process = 0;
        }
        if closed_mask & (1 << 4) != 0 {
            job.task_group = 0;
        }
        job.cleanup_result |= failed_bits;
        if job.process != 0 || job.task_group != 0 || job.launch_channel != 0 {
            return Ok(None);
        }
        let job = self.jobs[index].take().unwrap();
        let mut result = job.terminal.ok_or(JobError::WrongState)?;
        result.cleanup_result = job.cleanup_result;
        if !job.published {
            return Ok(Some(result));
        }
        self.push_completed(Completed {
            id: job.id,
            owner: job.owner,
            result,
            visible: !job.orphaned,
        });
        Ok(Some(result))
    }

    pub fn result(&mut self, request: Reservation, job_id: u64) -> Result<JobResult, JobError> {
        let ticket = self.reserve_request(request)?;
        self.result_reserved(ticket, job_id)
    }

    pub(crate) fn result_reserved(
        &self,
        request: RequestTicket,
        job_id: u64,
    ) -> Result<JobResult, JobError> {
        self.completed
            .iter()
            .flatten()
            .find(|record| record.id == job_id && record.owner == request.owner && record.visible)
            .map(|record| record.result)
            .ok_or(JobError::UnknownJob)
    }

    pub(crate) fn result_for_owner(
        &self,
        connection_id: u64,
        generation: u64,
        job_id: u64,
    ) -> Result<JobResult, JobError> {
        let owner = identity(connection_id, generation)?;
        self.completed
            .iter()
            .flatten()
            .find(|record| record.id == job_id && record.owner == owner && record.visible)
            .map(|record| record.result)
            .ok_or(JobError::UnknownJob)
    }

    pub fn close_job(&mut self, request: Reservation, job_id: u64) -> Result<(), JobError> {
        let ticket = self.reserve_request(request)?;
        self.close_job_reserved(ticket, job_id)
    }

    pub(crate) fn close_job_reserved(
        &mut self,
        request: RequestTicket,
        job_id: u64,
    ) -> Result<(), JobError> {
        if self
            .jobs
            .iter_mut()
            .flatten()
            .find(|job| {
                job.id == job_id && job.owner == request.owner && job.phase != JobPhase::Reserved
            })
            .is_some_and(|job| {
                job.orphaned = true;
                true
            })
        {
            return Ok(());
        }
        if let Some(record) =
            self.completed.iter_mut().flatten().find(|record| {
                record.id == job_id && record.owner == request.owner && record.visible
            })
        {
            record.visible = false;
            return Ok(());
        }
        Err(JobError::ForeignJob)
    }

    /// Lists only active jobs visible to the exact owning session. Completion
    /// records deliberately use `result` rather than leaking into this list.
    pub fn list(&mut self, request: Reservation, out: &mut [u64]) -> Result<usize, JobError> {
        let ticket = self.reserve_request(request)?;
        self.list_reserved(ticket, out)
    }

    pub(crate) fn list_reserved(
        &self,
        request: RequestTicket,
        out: &mut [u64],
    ) -> Result<usize, JobError> {
        let mut count = 0usize;
        for job in self.jobs.iter().flatten() {
            if job.owner == request.owner && !job.orphaned && job.phase != JobPhase::Reserved {
                let slot = out.get_mut(count).ok_or(JobError::Capacity)?;
                *slot = job.id;
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn disconnect(&mut self, id: u64, generation: u64) -> Result<(), JobError> {
        let identity = identity(id, generation)?;
        let connection = self.connection_mut(identity)?;
        connection.open = false;
        for job in self
            .jobs
            .iter_mut()
            .flatten()
            .filter(|job| job.owner == identity)
        {
            job.orphaned = true;
        }
        for record in self
            .completed
            .iter_mut()
            .flatten()
            .filter(|record| record.owner == identity)
        {
            record.visible = false;
        }
        Ok(())
    }

    /// Reclaims closed session slots only after their retained orphan jobs
    /// have terminally completed. IDs are never reassigned by this operation.
    pub fn reclaim_closed_sessions(&mut self) {
        for slot in &mut self.connections {
            let Some(connection) = *slot else {
                continue;
            };
            if !connection.open
                && !self
                    .jobs
                    .iter()
                    .flatten()
                    .any(|job| job.owner == connection.identity)
            {
                *slot = None;
            }
        }
    }

    pub fn live_jobs(&self) -> usize {
        self.jobs.iter().flatten().count()
    }
    pub fn orphan_jobs(&self) -> usize {
        self.jobs
            .iter()
            .flatten()
            .filter(|job| job.orphaned)
            .count()
    }

    #[cfg(test)]
    pub(crate) const fn completed_results(&self) -> usize {
        self.completed_len
    }

    pub(crate) fn loaded_job(&self, job_id: u64) -> Result<LoadedJob, JobError> {
        let job = self
            .jobs
            .iter()
            .flatten()
            .find(|job| {
                job.id == job_id
                    && (job.process != 0 || job.task_group != 0 || job.launch_channel != 0)
            })
            .ok_or(JobError::UnknownJob)?;
        Ok(LoadedJob {
            job_id: job.id,
            loaded: LoadedProcess {
                process: deepwyrm_syscall::DwHandle(job.process),
                launch_channel: deepwyrm_syscall::DwHandle(job.launch_channel),
            },
            task_group: job.task_group,
        })
    }

    pub(crate) fn forced_termination_resources(
        &self,
        job_id: u64,
    ) -> Result<Option<JobResources>, JobError> {
        let job = self
            .jobs
            .iter()
            .flatten()
            .find(|job| job.id == job_id)
            .ok_or(JobError::UnknownJob)?;
        if job.phase == JobPhase::Terminating || job.terminal.is_some() || job.task_group == 0 {
            return Ok(None);
        }
        Ok(Some(JobResources {
            process: job.process,
            task_group: job.task_group,
            launch_channel: job.launch_channel,
        }))
    }

    pub(crate) fn commit_forced_termination(
        &mut self,
        job_id: u64,
        resources: JobResources,
    ) -> Result<(), JobError> {
        let job = self
            .jobs
            .iter_mut()
            .flatten()
            .find(|job| job.id == job_id)
            .ok_or(JobError::UnknownJob)?;
        if job.task_group != resources.task_group
            || job.process != resources.process
            || job.launch_channel != resources.launch_channel
            || job.terminal.is_some()
        {
            return Err(JobError::ResourceIdentity);
        }
        job.phase = JobPhase::Terminating;
        Ok(())
    }

    pub(crate) fn cleanup_job_id(&self, cursor: usize) -> Option<(usize, u64)> {
        for offset in 0..MAX_LIVE_JOBS {
            let index = (cursor + offset) % MAX_LIVE_JOBS;
            if let Some(job) = self.jobs[index]
                && (job.process != 0 || job.task_group != 0 || job.launch_channel != 0)
            {
                return Some(((index + 1) % MAX_LIVE_JOBS, job.id));
            }
        }
        None
    }

    fn reserve_transaction(
        &mut self,
        request: Reservation,
    ) -> Result<ConnectionIdentity, JobError> {
        let identity = identity(request.connection_id, request.generation)?;
        if request.transaction_id == 0 {
            return Err(JobError::ZeroIdentity);
        }
        let connection = self.connection_mut(identity)?;
        if !connection.open {
            return Err(JobError::ClosedConnection);
        }
        if connection.replay.contains(request.transaction_id) {
            return Err(JobError::TransactionReplay);
        }
        connection.replay.push(request.transaction_id);
        Ok(identity)
    }

    fn connection_mut(
        &mut self,
        identity: ConnectionIdentity,
    ) -> Result<&mut Connection, JobError> {
        let connection = self
            .connections
            .iter_mut()
            .flatten()
            .find(|value| value.identity.id == identity.id)
            .ok_or(JobError::UnknownConnection)?;
        if connection.identity != identity {
            return Err(JobError::StaleGeneration);
        }
        Ok(connection)
    }

    fn owned_job(&self, owner: ConnectionIdentity, id: u64) -> Result<&Job, JobError> {
        let job = self
            .jobs
            .iter()
            .flatten()
            .find(|job| job.id == id)
            .ok_or(JobError::UnknownJob)?;
        if job.owner != owner || job.orphaned {
            return Err(JobError::ForeignJob);
        }
        if job.phase == JobPhase::Reserved {
            return Err(JobError::UnknownJob);
        }
        Ok(job)
    }
    fn owned_job_index(&self, owner: ConnectionIdentity, id: u64) -> Result<usize, JobError> {
        let index = self
            .jobs
            .iter()
            .position(|job| job.as_ref().is_some_and(|job| job.id == id))
            .ok_or(JobError::UnknownJob)?;
        if self.jobs[index].as_ref().unwrap().owner != owner
            || self.jobs[index].as_ref().unwrap().orphaned
        {
            return Err(JobError::ForeignJob);
        }
        if self.jobs[index].as_ref().unwrap().phase == JobPhase::Reserved {
            return Err(JobError::UnknownJob);
        }
        Ok(index)
    }
    fn push_completed(&mut self, value: Completed) {
        if self.completed_len < MAX_COMPLETED_JOBS {
            let index = (self.completed_start + self.completed_len) % MAX_COMPLETED_JOBS;
            self.completed[index] = Some(value);
            self.completed_len += 1;
        } else {
            self.completed[self.completed_start] = Some(value);
            self.completed_start = (self.completed_start + 1) % MAX_COMPLETED_JOBS;
        }
    }
}

/// Performs policy validation and loader construction while retaining the
/// reservation. The caller must either observe the exact READY then call
/// [`commit_prepared_job`], or abort and clean up the loaded process.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)] // D/E's serialized native dispatcher hookup consumes this next.
pub(crate) fn prepare_authorized_job<'a, L: LoaderPlatform>(
    jobs: &mut JobController,
    policy: &PolicyView<'a>,
    loader: &mut L,
    authority: LoadAuthority,
    task_group: u64,
    reservation: Reservation,
    request: wyrmroot_launch_proto::LaunchRequest<'a>,
    streams: &'a [deepwyrm_syscall::DwHandle],
) -> Result<PreparedJob, LaunchEngineError<L::Error>> {
    let ticket = jobs
        .begin_launch(reservation)
        .map_err(LaunchEngineError::Job)?;
    prepare_reserved_job(
        jobs,
        policy,
        loader,
        authority,
        task_group,
        reservation,
        ticket,
        request,
        streams,
    )
}

/// Continues a launch whose correlatable transaction was reserved before
/// semantic message validation.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_reserved_job<'a, L: LoaderPlatform>(
    jobs: &mut JobController,
    policy: &PolicyView<'a>,
    loader: &mut L,
    authority: LoadAuthority,
    task_group: u64,
    reservation: Reservation,
    ticket: LaunchTicket,
    request: wyrmroot_launch_proto::LaunchRequest<'a>,
    streams: &'a [deepwyrm_syscall::DwHandle],
) -> Result<PreparedJob, LaunchEngineError<L::Error>> {
    if ticket.owner
        != identity(reservation.connection_id, reservation.generation)
            .map_err(LaunchEngineError::Job)?
        || ticket.transaction_id != reservation.transaction_id
    {
        return Err(LaunchEngineError::Job(JobError::ResourceIdentity));
    }
    let reject = |jobs: &mut JobController,
                  loader: &mut L,
                  error: JobError|
     -> LaunchEngineError<L::Error> {
        let cleanup_failed = close_streams_reverse(streams, |stream| loader.close(stream));
        let abort_failed = jobs.abort_launch(ticket).is_err();
        LaunchEngineError::Validation {
            error,
            abort_failed,
            cleanup_failed,
        }
    };
    if request.stream_count != streams.len() {
        return Err(reject(jobs, loader, JobError::StreamPolicy));
    }
    let profile = match request.stream_count {
        0 => LaunchProfile::JobV2,
        3 => LaunchProfile::JobV2Streams,
        _ => return Err(reject(jobs, loader, JobError::StreamPolicy)),
    };
    let image = match policy.authorize(request.path, request.stream_count) {
        Ok(image) => image,
        Err(error) => return Err(reject(jobs, loader, error)),
    };
    let mut argv = [""; wyrmroot_launch_proto::MAX_ARGV];
    for (index, slot) in argv.iter_mut().take(request.argc()).enumerate() {
        let Some(argument) = request.arg(index) else {
            return Err(reject(jobs, loader, JobError::PolicyMissing));
        };
        *slot = argument;
    }
    let mut environment = [""; wyrmroot_launch_proto::MAX_ENVIRONMENT];
    for (index, slot) in environment
        .iter_mut()
        .take(request.environment_count())
        .enumerate()
    {
        let Some(value) = request.environment(index) else {
            return Err(reject(jobs, loader, JobError::PolicyMissing));
        };
        *slot = value;
    }
    let loaded = match load_job_process(
        loader,
        LoadAuthority {
            task_group: deepwyrm_syscall::DwHandle(task_group),
            ..authority
        },
        JobLoadRequest {
            image,
            policy_path: request.path,
            argv: &argv[..request.argc()],
            environment: &environment[..request.environment_count()],
            streams,
            transaction_id: reservation.transaction_id,
        },
    ) {
        Ok(loaded) => loaded,
        Err(failure) => {
            let cleanup_failed = if failure.streams_consumed {
                false
            } else {
                close_streams_reverse(streams, |stream| loader.close(stream))
            };
            let abort_failed = jobs.abort_launch(ticket).is_err();
            return Err(LaunchEngineError::Loader {
                error: failure.error,
                streams_consumed: failure.streams_consumed,
                abort_failed,
                cleanup_failed,
            });
        }
    };
    if let Err(error) = jobs.stage_launch(
        ticket,
        loaded.process.0,
        task_group,
        loaded.launch_channel.0,
    ) {
        return Err(LaunchEngineError::Publication {
            error,
            ticket,
            loaded,
            task_group,
        });
    }
    Ok(PreparedJob {
        ticket,
        profile,
        transaction_id: reservation.transaction_id,
        loaded,
        task_group,
    })
}

fn close_streams_reverse<E>(
    streams: &[deepwyrm_syscall::DwHandle],
    mut close: impl FnMut(deepwyrm_syscall::DwHandle) -> Result<(), E>,
) -> bool {
    let mut failed = false;
    for &stream in streams.iter().rev() {
        failed |= close(stream).is_err();
    }
    failed
}

/// Publishes a prepared job only after the dispatcher has observed READY.
#[allow(dead_code)] // Kept crate-private until the D/E native dispatcher lands.
pub(crate) fn commit_prepared_job(
    jobs: &mut JobController,
    prepared: PreparedJob,
    ready: ExactReadyObservation,
) -> Result<LoadedJob, JobError> {
    if ready.profile != prepared.profile
        || ready.transaction_id != prepared.transaction_id
        || ready.process != prepared.loaded.process
        || ready.launch_channel != prepared.loaded.launch_channel
    {
        return Err(JobError::ResourceIdentity);
    }
    jobs.commit_launch(
        prepared.ticket,
        prepared.loaded.process.0,
        prepared.task_group,
        prepared.loaded.launch_channel.0,
    )?;
    Ok(LoadedJob {
        job_id: prepared.ticket.job_id,
        loaded: prepared.loaded,
        task_group: prepared.task_group,
    })
}

/// Aborts a not-yet-visible prepared job reservation. The caller remains
/// responsible for terminating/reaping and closing its loaded handles.
#[allow(dead_code)] // Kept alongside commit for the serialized dispatcher join.
pub(crate) fn abort_prepared_job(
    jobs: &mut JobController,
    prepared: PreparedJob,
) -> Result<(), JobError> {
    jobs.abort_launch(prepared.ticket)
}

impl Default for JobController {
    fn default() -> Self {
        Self::new()
    }
}
fn identity(id: u64, generation: u64) -> Result<ConnectionIdentity, JobError> {
    if id == 0 || generation == 0 {
        Err(JobError::ZeroIdentity)
    } else {
        Ok(ConnectionIdentity { id, generation })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ready_token(
        profile: LaunchProfile,
        transaction_id: u64,
        process: deepwyrm_syscall::DwHandle,
        launch_channel: deepwyrm_syscall::DwHandle,
    ) -> ExactReadyObservation {
        ExactReadyObservation {
            profile,
            transaction_id,
            process,
            launch_channel,
        }
    }
    fn reservation(id: u64, generation: u64, transaction_id: u64) -> Reservation {
        Reservation {
            connection_id: id,
            generation,
            transaction_id,
        }
    }
    fn normal() -> JobResult {
        JobResult {
            classification: 1,
            application_code: 0,
            exception_class: 0,
            exception_detail: 0,
            exception_address: 0,
            cleanup_result: 0,
        }
    }

    #[test]
    fn launch_is_transactional_owner_scoped_and_structured() {
        let mut jobs = JobController::new();
        jobs.open_connection(1, 1).unwrap();
        jobs.open_connection(2, 1).unwrap();
        let ticket = jobs.begin_launch(reservation(1, 1, 1)).unwrap();
        assert_eq!(jobs.live_jobs(), 1);
        jobs.commit_launch(ticket, 10, 11, 12).unwrap();
        assert_eq!(
            jobs.query(reservation(1, 1, 2), ticket.job_id)
                .unwrap()
                .phase,
            JobPhase::Running
        );
        assert_eq!(
            jobs.query(reservation(2, 1, 1), ticket.job_id),
            Err(JobError::ForeignJob)
        );
        assert_eq!(
            jobs.terminate(reservation(1, 1, 3), ticket.job_id),
            Ok(JobResources {
                process: 10,
                task_group: 11,
                launch_channel: 12,
            })
        );
        jobs.complete(ticket.job_id, 10, 11, 12, normal()).unwrap();
        assert_eq!(
            jobs.result(reservation(1, 1, 4), ticket.job_id),
            Ok(normal())
        );
        assert_eq!(
            jobs.result(reservation(1, 1, 4), ticket.job_id),
            Err(JobError::TransactionReplay)
        );
    }

    #[test]
    fn reserved_jobs_are_invisible_until_exact_ready_commit_or_abort() {
        let mut jobs = JobController::new();
        jobs.open_connection(1, 1).unwrap();
        let ticket = jobs.begin_launch(reservation(1, 1, 1)).unwrap();
        let mut listed = [0; MAX_LIVE_JOBS];
        assert_eq!(jobs.list(reservation(1, 1, 2), &mut listed), Ok(0));
        assert_eq!(
            jobs.query(reservation(1, 1, 3), ticket.job_id),
            Err(JobError::UnknownJob)
        );
        assert_eq!(
            jobs.terminate(reservation(1, 1, 4), ticket.job_id),
            Err(JobError::UnknownJob)
        );
        jobs.commit_launch(ticket, 10, 11, 12).unwrap();
        assert_eq!(jobs.list(reservation(1, 1, 5), &mut listed), Ok(1));
        assert_eq!(listed[0], ticket.job_id);
        let abort = jobs.begin_launch(reservation(1, 1, 6)).unwrap();
        jobs.abort_launch(abort).unwrap();
        assert_eq!(jobs.list(reservation(1, 1, 7), &mut listed), Ok(1));
    }

    #[test]
    fn rejected_fresh_launch_is_replay_protected_without_job_publication() {
        let mut jobs = JobController::new();
        jobs.open_connection(1, 1).unwrap();
        let request = reservation(1, 1, 9);
        let ticket = jobs.begin_launch(request).unwrap();
        jobs.abort_launch(ticket).unwrap();
        assert_eq!(jobs.live_jobs(), 0);
        assert_eq!(jobs.begin_launch(request), Err(JobError::TransactionReplay));
    }

    #[test]
    fn unpublished_staged_cleanup_never_creates_a_visible_or_completed_record() {
        let mut jobs = JobController::new();
        jobs.open_connection(1, 1).unwrap();
        let ticket = jobs.begin_launch(reservation(1, 1, 1)).unwrap();
        jobs.stage_launch(ticket, 10, 11, 12).unwrap();
        assert_eq!(jobs.completed_results(), 0);
        assert_eq!(
            jobs.apply_cleanup_progress(ticket.job_id, normal(), 0x1c, 0),
            Ok(Some(normal()))
        );
        assert_eq!(jobs.live_jobs(), 0);
        assert_eq!(jobs.completed_results(), 0);
        assert_eq!(
            jobs.result(reservation(1, 1, 2), ticket.job_id),
            Err(JobError::UnknownJob)
        );
    }

    #[test]
    fn retained_stream_cleanup_is_reverse_ordered_exactly_once() {
        let streams = [
            deepwyrm_syscall::DwHandle(10),
            deepwyrm_syscall::DwHandle(11),
            deepwyrm_syscall::DwHandle(12),
        ];
        let mut closed = [deepwyrm_syscall::DwHandle(0); 3];
        let mut count = 0;
        let failed = close_streams_reverse(&streams, |stream| {
            closed[count] = stream;
            count += 1;
            if stream.0 == 11 { Err(()) } else { Ok(()) }
        });
        assert!(failed);
        assert_eq!(count, 3);
        assert_eq!(
            closed,
            [
                deepwyrm_syscall::DwHandle(12),
                deepwyrm_syscall::DwHandle(11),
                deepwyrm_syscall::DwHandle(10),
            ]
        );
    }

    #[test]
    fn prepared_job_needs_exact_ready_token_before_publication_or_abort() {
        let mut jobs = JobController::new();
        jobs.open_connection(1, 1).unwrap();
        let ticket = jobs.begin_launch(reservation(1, 1, 1)).unwrap();
        let prepared = PreparedJob {
            ticket,
            profile: LaunchProfile::JobV2,
            transaction_id: 1,
            loaded: LoadedProcess {
                process: deepwyrm_syscall::DwHandle(10),
                launch_channel: deepwyrm_syscall::DwHandle(12),
            },
            task_group: 11,
        };
        let committed = commit_prepared_job(
            &mut jobs,
            prepared,
            ready_token(
                LaunchProfile::JobV2,
                1,
                prepared.loaded.process,
                prepared.loaded.launch_channel,
            ),
        )
        .unwrap();
        assert_eq!(committed.job_id, ticket.job_id);
        let aborted = PreparedJob {
            ticket: jobs.begin_launch(reservation(1, 1, 2)).unwrap(),
            ..prepared
        };
        abort_prepared_job(&mut jobs, aborted).unwrap();
    }

    #[test]
    fn ready_observation_is_bound_to_the_exact_prepared_child() {
        let mut jobs = JobController::new();
        jobs.open_connection(1, 1).unwrap();
        let prepared = PreparedJob {
            ticket: jobs.begin_launch(reservation(1, 1, 7)).unwrap(),
            profile: LaunchProfile::JobV2Streams,
            transaction_id: 7,
            loaded: LoadedProcess {
                process: deepwyrm_syscall::DwHandle(30),
                launch_channel: deepwyrm_syscall::DwHandle(31),
            },
            task_group: 32,
        };
        for wrong in [
            ready_token(
                LaunchProfile::JobV2,
                7,
                prepared.loaded.process,
                prepared.loaded.launch_channel,
            ),
            ready_token(
                prepared.profile,
                8,
                prepared.loaded.process,
                prepared.loaded.launch_channel,
            ),
            ready_token(
                prepared.profile,
                7,
                deepwyrm_syscall::DwHandle(33),
                prepared.loaded.launch_channel,
            ),
            ready_token(
                prepared.profile,
                7,
                prepared.loaded.process,
                deepwyrm_syscall::DwHandle(34),
            ),
        ] {
            assert_eq!(
                commit_prepared_job(&mut jobs, prepared, wrong),
                Err(JobError::ResourceIdentity)
            );
        }
        assert_eq!(jobs.live_jobs(), 1);
        abort_prepared_job(&mut jobs, prepared).unwrap();
    }

    struct ReadyWithState(deepwyrm_syscall::DwTaskState);

    impl SupervisionPlatform for ReadyWithState {
        type Error = ();

        fn wait_many(
            &mut self,
            _items: &[deepwyrm_syscall::DwWaitItemV1],
            _deadline: deepwyrm_syscall::DwDeadline,
        ) -> Result<deepwyrm_syscall::DwWaitResultV1, Self::Error> {
            Ok(deepwyrm_syscall::DwWaitResultV1 {
                index: 0,
                observed: deepwyrm_syscall::DW_SIGNAL_READABLE,
                ..deepwyrm_syscall::DwWaitResultV1::default()
            })
        }

        fn receive_channel(
            &mut self,
            _channel: deepwyrm_syscall::DwHandle,
            bytes: &mut [u8],
            _handles: &mut [deepwyrm_syscall::DwReceivedHandleInfoV1],
        ) -> Result<wyrmroot_runtime::ReceiveCounts, Self::Error> {
            let size =
                wyrmroot_loader::launch::encode_ready_for_profile(LaunchProfile::JobV2, 7, bytes)
                    .unwrap();
            Ok(wyrmroot_runtime::ReceiveCounts {
                bytes: size,
                handles: 0,
            })
        }

        fn query_task_termination(
            &mut self,
            _process: deepwyrm_syscall::DwHandle,
        ) -> Result<deepwyrm_syscall::DwTaskTerminationInfoV1, Self::Error> {
            Ok(deepwyrm_syscall::DwTaskTerminationInfoV1 {
                state: self.0,
                reason: deepwyrm_syscall::DW_TERMINATION_NORMAL_EXIT,
                ..deepwyrm_syscall::DwTaskTerminationInfoV1::default()
            })
        }
    }

    #[test]
    fn combined_ready_and_exit_never_constructs_publication_proof() {
        let mut jobs = JobController::new();
        jobs.open_connection(1, 1).unwrap();
        let prepared = PreparedJob {
            ticket: jobs.begin_launch(reservation(1, 1, 7)).unwrap(),
            profile: LaunchProfile::JobV2,
            transaction_id: 7,
            loaded: LoadedProcess {
                process: deepwyrm_syscall::DwHandle(30),
                launch_channel: deepwyrm_syscall::DwHandle(31),
            },
            task_group: 32,
        };
        let observed = observe_prepared_ready(
            &mut ReadyWithState(deepwyrm_syscall::DW_TASK_STATE_EXITED),
            &prepared,
            deepwyrm_syscall::DwDeadline(100),
        );
        assert!(matches!(
            observed,
            Err(ReadyObservationError::ReadyAndExited(info))
                if info.state == deepwyrm_syscall::DW_TASK_STATE_EXITED
        ));
        let mut listed = [0; MAX_LIVE_JOBS];
        assert_eq!(jobs.list(reservation(1, 1, 8), &mut listed), Ok(0));
        abort_prepared_job(&mut jobs, prepared).unwrap();
    }

    #[test]
    fn ready_with_created_or_unknown_state_never_constructs_publication_proof() {
        for state in [
            deepwyrm_syscall::DW_TASK_STATE_CREATED,
            deepwyrm_syscall::DwTaskState(u32::MAX),
        ] {
            let mut jobs = JobController::new();
            jobs.open_connection(1, 1).unwrap();
            let prepared = PreparedJob {
                ticket: jobs.begin_launch(reservation(1, 1, 7)).unwrap(),
                profile: LaunchProfile::JobV2,
                transaction_id: 7,
                loaded: LoadedProcess {
                    process: deepwyrm_syscall::DwHandle(30),
                    launch_channel: deepwyrm_syscall::DwHandle(31),
                },
                task_group: 32,
            };
            assert!(matches!(
                observe_prepared_ready(
                    &mut ReadyWithState(state),
                    &prepared,
                    deepwyrm_syscall::DwDeadline(100),
                ),
                Err(ReadyObservationError::NotRunning(info)) if info.state == state
            ));
            abort_prepared_job(&mut jobs, prepared).unwrap();
        }
    }

    #[test]
    fn disconnected_jobs_are_retained_and_reaped_without_reattachment() {
        let mut jobs = JobController::new();
        jobs.open_connection(1, 1).unwrap();
        let ticket = jobs.begin_launch(reservation(1, 1, 1)).unwrap();
        jobs.commit_launch(ticket, 10, 11, 12).unwrap();
        jobs.disconnect(1, 1).unwrap();
        assert_eq!(jobs.orphan_jobs(), 1);
        assert_eq!(
            jobs.query(reservation(1, 1, 2), ticket.job_id),
            Err(JobError::ClosedConnection)
        );
        jobs.complete(ticket.job_id, 10, 11, 12, normal()).unwrap();
        assert_eq!(jobs.live_jobs(), 0);
        jobs.open_connection(2, 1).unwrap();
        assert_eq!(
            jobs.result(reservation(2, 1, 1), ticket.job_id),
            Err(JobError::UnknownJob)
        );
    }

    #[test]
    fn session_visibility_list_and_reclamation_are_owner_scoped() {
        let mut jobs = JobController::new();
        jobs.open_connection(1, 1).unwrap();
        jobs.open_connection(2, 1).unwrap();
        let first = jobs.begin_launch(reservation(1, 1, 1)).unwrap();
        jobs.commit_launch(first, 10, 11, 12).unwrap();
        let second = jobs.begin_launch(reservation(2, 1, 1)).unwrap();
        jobs.commit_launch(second, 20, 21, 22).unwrap();
        let mut listed = [0; MAX_LIVE_JOBS];
        assert_eq!(jobs.list(reservation(1, 1, 2), &mut listed), Ok(1));
        assert_eq!(listed[0], first.job_id);
        jobs.disconnect(1, 1).unwrap();
        jobs.reclaim_closed_sessions();
        assert_eq!(
            jobs.open_connection(1, 2),
            Err(JobError::DuplicateConnection)
        );
        jobs.complete(first.job_id, 10, 11, 12, normal()).unwrap();
        jobs.reclaim_closed_sessions();
        jobs.open_connection(1, 2).unwrap();
        assert_eq!(
            jobs.query(reservation(1, 2, 1), second.job_id),
            Err(JobError::ForeignJob)
        );
    }

    #[test]
    fn registry_grants_die_with_registry_generation() {
        let mut topology = RegistryTopology::new(1).unwrap();
        let grant = topology.issue(7, EndpointKind::Publication).unwrap();
        assert!(topology.accepts(grant));
        topology.restart(2).unwrap();
        assert!(!topology.accepts(grant));
        let replacement = topology.issue(8, EndpointKind::Publication).unwrap();
        assert!(topology.accepts(replacement));
        assert!(replacement.endpoint_id > grant.endpoint_id);
        assert_eq!(topology.restart(2), Err(JobError::StaleGeneration));
    }

    #[test]
    fn publisher_and_client_grants_pack_exact_correlation_environment() {
        let mut topology = RegistryTopology::new(7).unwrap();
        for kind in [EndpointKind::Publication, EndpointKind::RegistryClient] {
            let grant = topology.issue(3, kind).unwrap();
            let environment = correlation_environment(grant).unwrap();
            let entries = [
                environment.entry(0).unwrap(),
                environment.entry(1).unwrap(),
                environment.entry(2).unwrap(),
            ];
            assert_eq!(
                wyrmroot_registry_proto::parse_correlation_environment(&entries),
                Ok(Correlation {
                    registry_generation: grant.registry_generation,
                    endpoint_id: grant.endpoint_id,
                    endpoint_generation: grant.endpoint_generation,
                })
            );
        }
        let launch = topology.issue(3, EndpointKind::LaunchSession).unwrap();
        assert_eq!(correlation_environment(launch), Err(JobError::WrongState));
    }
}
