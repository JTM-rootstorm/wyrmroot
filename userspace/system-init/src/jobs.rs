//! WYR1-B controller-owned registry topology and launch/job state.

use wyrmroot_bootfs::{
    archive::{Archive, LookupError},
    launch_policy::{
        JOB_V2_PROFILE_ID, LAUNCH_POLICY_PATH, LaunchPolicy, PolicyError, WYRMSH_PATH,
        WYRMSH_PROFILE_ID,
    },
};
use wyrmroot_launch_proto::{MAX_COMPLETED_JOBS, MAX_LIVE_JOBS, Reservation};
use wyrmroot_loader::{
    launch::LaunchProfile,
    process::{
        JobLoadRequest, LoadAuthority, LoadError, LoadedProcess, LoaderPlatform, load_job_process,
    },
};
use wyrmroot_runtime::{
    ObservedSupervisionError, SupervisionPlatform, await_child_ready_profile_observed, sha256,
};

pub(crate) const MAX_CONNECTIONS: usize = 16;
/// Closed connections that may keep live orphans. The rest of
/// `MAX_CONNECTIONS` stays free for live consoles, shells and their
/// replacements, so orphans can never stop a new shell from starting
/// (F4 WYR1-F4-M1).
pub(crate) const MAX_ORPHAN_CONNECTIONS: usize = 8;
/// Concurrent shell jobs, orphans included. Deepwyrm's production geometry
/// (`LIVE_SHELL_JOBS`) is sized for exactly this many, so a launch beyond it
/// is refused here rather than draining a pool a service needs to restart
/// (F4 DW1-F4-M1).
pub(crate) const MAX_SHELL_JOBS: usize = 4;
/// Live orphan jobs across every closed connection. The rest of
/// `MAX_SHELL_JOBS` stays free for the live shell.
pub(crate) const MAX_ORPHAN_JOBS: usize = MAX_SHELL_JOBS / 2;
// Init's own wait usage does not grow with jobs. Init is single-threaded and
// polls each session with a one-item, deadline-now wait and each job with
// `query_task_termination`; its only blocking job wait is one item, while a
// launch awaits READY. So init holds at most one registered wait item at a
// time, and deepwyrm's two exit waits per live job are a conservative
// allowance.

/// Live shell jobs one ShellJobs connection may hold, so one shell cannot
/// take every `MAX_SHELL_JOBS` slot from another.
pub(crate) const MAX_JOBS_PER_SHELL: usize = MAX_SHELL_JOBS - 1;
/// Each job's own TaskGroup limits: a job creates no kernel objects of its
/// own and registers at most four wait items, enough for a small wait-many
/// (deepwyrm's `JOB_OWN_WAITS`). Init
/// creates the job's Process, Thread, memory and channels, so those are
/// charged to init and bounded by `MAX_SHELL_JOBS`.
pub const JOB_TASK_GROUP_LIMITS: [(u32, u32); 8] = [
    (deepwyrm_syscall::DW_TASK_GROUP_LIMIT_CHANNEL, 0),
    (deepwyrm_syscall::DW_TASK_GROUP_LIMIT_EVENT, 0),
    (deepwyrm_syscall::DW_TASK_GROUP_LIMIT_TIMER, 0),
    (deepwyrm_syscall::DW_TASK_GROUP_LIMIT_MEMORY_OBJECT, 0),
    (deepwyrm_syscall::DW_TASK_GROUP_LIMIT_THREAD, 0),
    (deepwyrm_syscall::DW_TASK_GROUP_LIMIT_PROCESS, 0),
    (deepwyrm_syscall::DW_TASK_GROUP_LIMIT_TASK_GROUP, 0),
    (deepwyrm_syscall::DW_TASK_GROUP_LIMIT_WAIT, 4),
];
const _: () = assert!(MAX_ORPHAN_CONNECTIONS + 4 <= MAX_CONNECTIONS);
pub(crate) const REPLAY_RECORDS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EndpointKind {
    Publication,
    RegistryClient,
    LaunchSession,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EndpointGrant {
    pub(crate) registry_generation: u64,
    pub(crate) endpoint_id: u64,
    pub(crate) endpoint_generation: u64,
    pub(crate) role_generation: u64,
    pub(crate) kind: EndpointKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RegistryTopology {
    pub(crate) registry_generation: u64,
    pub(crate) next_endpoint_id: u64,
}

impl RegistryTopology {
    pub(crate) fn new(registry_generation: u64) -> Result<Self, JobError> {
        if registry_generation == 0 {
            return Err(JobError::ZeroIdentity);
        }
        Ok(Self {
            registry_generation,
            next_endpoint_id: 1,
        })
    }

    pub(crate) fn issue(
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

    pub(crate) fn restart(&mut self, next_generation: u64) -> Result<(), JobError> {
        if next_generation <= self.registry_generation {
            return Err(JobError::StaleGeneration);
        }
        self.registry_generation = next_generation;
        Ok(())
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.registry_generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PolicyView<'a> {
    pub(crate) policy: LaunchPolicy<'a>,
    pub(crate) archive: Archive<'a>,
}

impl<'a> PolicyView<'a> {
    pub(crate) fn from_bootfs(
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

    pub(crate) fn authorize(&self, path: &str, streams: usize) -> Result<&'a [u8], JobError> {
        let entry = self.policy.find(path).ok_or(JobError::PolicyMissing)?;
        if entry.startup_abi != 2 || entry.profile_id != JOB_V2_PROFILE_ID {
            return Err(JobError::PolicyMissing);
        }
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

    pub(crate) fn authorize_wyrmsh(&self) -> Result<&'a [u8], JobError> {
        let entry = self
            .policy
            .find(WYRMSH_PATH)
            .ok_or(JobError::PolicyMissing)?;
        if entry.startup_abi != 2
            || entry.profile_id != WYRMSH_PROFILE_ID
            || entry.allow_no_streams
            || !entry.allow_three_streams
        {
            return Err(JobError::PolicyMissing);
        }
        let artifact = self
            .archive
            .lookup(WYRMSH_PATH.as_bytes())
            .map_err(JobError::Bootfs)?;
        if !artifact.is_executable() || sha256::digest(artifact.data()) != entry.content_sha256 {
            return Err(JobError::ArtifactIdentityMismatch);
        }
        Ok(artifact.data())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JobPhase {
    Reserved,
    Running,
    Terminating,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JobSnapshot {
    pub(crate) job_id: u64,
    pub(crate) phase: JobPhase,
    pub(crate) orphaned: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JobResources {
    pub(crate) process: u64,
    pub(crate) task_group: u64,
    pub(crate) launch_channel: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JobResult {
    pub(crate) classification: u32,
    pub(crate) application_code: u32,
    pub(crate) exception_class: u32,
    pub(crate) exception_detail: u32,
    pub(crate) exception_address: u64,
    pub(crate) cleanup_result: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LaunchTicket {
    pub(crate) slot: usize,
    pub(crate) job_id: u64,
    pub(crate) owner: ConnectionIdentity,
    pub(crate) transaction_id: u64,
}

impl LaunchTicket {
    pub(crate) const fn job_id(self) -> u64 {
        self.job_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RequestTicket {
    pub(crate) owner: ConnectionIdentity,
    pub(crate) transaction_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConnectionIdentity {
    pub(crate) id: u64,
    pub(crate) generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Replay {
    pub(crate) values: [u64; REPLAY_RECORDS],
    pub(crate) start: usize,
    pub(crate) len: usize,
}
impl Replay {
    pub(crate) const fn new() -> Self {
        Self {
            values: [0; REPLAY_RECORDS],
            start: 0,
            len: 0,
        }
    }
    pub(crate) fn contains(&self, value: u64) -> bool {
        (0..self.len).any(|index| self.values[(self.start + index) % REPLAY_RECORDS] == value)
    }
    pub(crate) fn push(&mut self, value: u64) {
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
pub(crate) struct Connection {
    pub(crate) identity: ConnectionIdentity,
    pub(crate) replay: Replay,
    pub(crate) open: bool,
    /// Order in which the connection closed; zero while it is open.
    pub(crate) closed_order: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Job {
    pub(crate) id: u64,
    pub(crate) owner: ConnectionIdentity,
    pub(crate) phase: JobPhase,
    pub(crate) orphaned: bool,
    /// Launched through a ShellJobs session; counted by `MAX_SHELL_JOBS`.
    pub(crate) shell_job: bool,
    pub(crate) process: u64,
    pub(crate) task_group: u64,
    pub(crate) launch_channel: u64,
    pub(crate) terminal: Option<JobResult>,
    pub(crate) cleanup_result: u32,
    pub(crate) published: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Completed {
    pub(crate) id: u64,
    pub(crate) owner: ConnectionIdentity,
    pub(crate) result: JobResult,
    pub(crate) visible: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct JobController {
    pub(crate) connections: [Option<Connection>; MAX_CONNECTIONS],
    pub(crate) jobs: [Option<Job>; MAX_LIVE_JOBS],
    pub(crate) completed: [Option<Completed>; MAX_COMPLETED_JOBS],
    pub(crate) completed_start: usize,
    pub(crate) completed_len: usize,
    pub(crate) next_job_id: u64,
    pub(crate) next_closed_order: u64,
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
pub(crate) struct LoadedJob {
    pub(crate) job_id: u64,
    pub(crate) loaded: LoadedProcess,
    pub(crate) task_group: u64,
}

/// A loader-committed launch which is deliberately not yet visible to the
/// session owner. The dispatcher publishes it only after the exact profile
/// READY observation, so a READY-and-exited race cannot yield acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedJob {
    pub(crate) ticket: LaunchTicket,
    pub(crate) profile: LaunchProfile,
    pub(crate) transaction_id: u64,
    pub(crate) loaded: LoadedProcess,
    pub(crate) task_group: u64,
}

impl PreparedJob {
    /// The profile the arena has to record, so a deferred finish can ask the
    /// model to rebuild this job. See [`JobController::staged_job`].
    pub(crate) const fn profile(self) -> LaunchProfile {
        self.profile
    }

    pub(crate) const fn job_id(self) -> u64 {
        self.ticket.job_id
    }
}

/// Proof supplied only after the native dispatcher has consumed the exact
/// profile/transaction READY record and separately excluded child exit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExactReadyObservation {
    pub(crate) profile: LaunchProfile,
    pub(crate) transaction_id: u64,
    pub(crate) process: deepwyrm_syscall::DwHandle,
    pub(crate) launch_channel: deepwyrm_syscall::DwHandle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LaunchChannelRelease {
    pub(crate) slot: usize,
    pub(crate) job_id: u64,
    pub(crate) launch_channel: u64,
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
pub(crate) enum LaunchEngineError<E> {
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
    pub(crate) const fn new() -> Self {
        Self {
            connections: [None; MAX_CONNECTIONS],
            jobs: [None; MAX_LIVE_JOBS],
            completed: [None; MAX_COMPLETED_JOBS],
            completed_start: 0,
            completed_len: 0,
            next_job_id: 1,
            next_closed_order: 1,
        }
    }

    pub(crate) fn open_connection(&mut self, id: u64, generation: u64) -> Result<(), JobError> {
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
            closed_order: 0,
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

    pub(crate) fn begin_reserved_launch(
        &mut self,
        request: RequestTicket,
        shell_job: bool,
    ) -> Result<LaunchTicket, JobError> {
        if shell_job {
            let shell_jobs = || self.jobs.iter().flatten().filter(|job| job.shell_job);
            if shell_jobs().count() >= MAX_SHELL_JOBS
                || shell_jobs()
                    .filter(|job| job.owner == request.owner)
                    .count()
                    >= MAX_JOBS_PER_SHELL
            {
                return Err(JobError::Capacity);
            }
        }
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
            shell_job,
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

    pub(crate) fn commit_launch(
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

    /// Rebuilds the prepared job a deferred launch left staged in the model.
    ///
    /// Reset card R6B-2. `PreparedJob` used to be a local of the one frame that
    /// both constructed and published, so its [`LaunchTicket`] never had to
    /// outlive the dispatch. A launch that returns to the event loop between
    /// those two halves has to name that job again on a later tick.
    ///
    /// The launch arena is the wrong place to keep the ticket. `slot` is this
    /// controller's own index into its job table, and a copy of it held outside
    /// the controller is a name for a position, not for a job -- if the job
    /// were freed and the position reused, the stale ticket would still parse.
    /// So the ticket is not stored anywhere; it is re-derived here.
    ///
    /// The caller supplies only what the wire gave it and the arena recorded at
    /// construction: the owning connection, the job id, the request's
    /// transaction id and the profile. This finds the job by identity and
    /// refuses unless it is still exactly what construction left behind --
    /// owned by that connection, still `Reserved`, and staged with all three
    /// handles. The returned `PreparedJob` carries the model's own record of
    /// those handles, not the caller's, so a caller whose copy has drifted
    /// fails the identity checks in [`commit_prepared_job`] rather than
    /// committing the model's job against its own stale handles.
    pub(crate) fn staged_job(
        &self,
        owner_id: u64,
        owner_generation: u64,
        job_id: u64,
        transaction_id: u64,
        profile: LaunchProfile,
    ) -> Result<PreparedJob, JobError> {
        let owner = identity(owner_id, owner_generation)?;
        let (slot, job) = self
            .jobs
            .iter()
            .enumerate()
            .find_map(|(slot, job)| {
                job.as_ref()
                    .filter(|job| job.id == job_id)
                    .map(|job| (slot, job))
            })
            .ok_or(JobError::UnknownJob)?;
        if job.owner != owner {
            return Err(JobError::ForeignJob);
        }
        if job.phase != JobPhase::Reserved || job.published {
            return Err(JobError::WrongState);
        }
        if job.process == 0 || job.task_group == 0 || job.launch_channel == 0 {
            return Err(JobError::WrongState);
        }
        Ok(PreparedJob {
            ticket: LaunchTicket {
                slot,
                job_id,
                owner,
                transaction_id,
            },
            profile,
            transaction_id,
            loaded: LoadedProcess {
                process: deepwyrm_syscall::DwHandle(job.process),
                launch_channel: deepwyrm_syscall::DwHandle(job.launch_channel),
            },
            task_group: job.task_group,
        })
    }

    pub(crate) fn abort_launch(&mut self, ticket: LaunchTicket) -> Result<(), JobError> {
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

    pub(crate) fn authorize_terminate_reserved(
        &self,
        request: RequestTicket,
        job_id: u64,
    ) -> Result<JobResources, JobError> {
        // Completion may win after a pending WAIT is cancelled. The owning
        // session still sees that result, but there is no live job to terminate.
        if self.result_reserved(request, job_id).is_ok() {
            return Err(JobError::WrongState);
        }
        let index = self.owned_job_index(request.owner, job_id)?;
        let job = self.jobs[index].as_ref().unwrap();
        if job.phase != JobPhase::Running || job.terminal.is_some() {
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

    /// The TaskGroup of a running job whose forced termination the kernel
    /// refused (cleanup bit 0), so the poll loop can try it again rather
    /// than leave the job holding its slot.
    pub(crate) fn termination_to_retry(&self, job_id: u64) -> Option<JobResources> {
        let job = self.jobs.iter().flatten().find(|job| job.id == job_id)?;
        (job.cleanup_result & 1 != 0
            && job.phase == JobPhase::Running
            && job.terminal.is_none()
            && job.task_group != 0)
            .then_some(JobResources {
                process: job.process,
                task_group: job.task_group,
                launch_channel: job.launch_channel,
            })
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

    pub(crate) fn terminal_result(&self, job_id: u64) -> Result<Option<JobResult>, JobError> {
        self.jobs
            .iter()
            .flatten()
            .find(|job| job.id == job_id)
            .map(|job| job.terminal)
            .ok_or(JobError::UnknownJob)
    }

    /// Stages controller release of the launch Channel before the acceptance
    /// response. Failed response/close paths restore the returned token;
    /// successful physical close leaves terminal cleanup nothing to close.
    pub(crate) fn release_launch_channel(
        &mut self,
        job_id: u64,
        launch_channel: u64,
    ) -> Result<LaunchChannelRelease, JobError> {
        let slot = self
            .jobs
            .iter()
            .position(|job| job.as_ref().is_some_and(|job| job.id == job_id))
            .ok_or(JobError::UnknownJob)?;
        let job = self.jobs[slot].as_mut().unwrap();
        if job.phase != JobPhase::Running
            || !job.published
            || launch_channel == 0
            || job.launch_channel != launch_channel
        {
            return Err(JobError::ResourceIdentity);
        }
        job.launch_channel = 0;
        Ok(LaunchChannelRelease {
            slot,
            job_id,
            launch_channel,
        })
    }

    /// Restores an immediately preceding release transition when the physical
    /// close failed. The dispatcher is serialized, so no intervening mutation
    /// of this exact job is possible.
    pub(crate) fn restore_launch_channel(&mut self, release: LaunchChannelRelease) {
        let job = self.jobs[release.slot]
            .as_mut()
            .expect("released job remains present until its endpoint close resolves");
        assert!(
            job.id == release.job_id
                && job.phase == JobPhase::Running
                && job.published
                && job.launch_channel == 0
                && release.launch_channel != 0,
            "serialized launch-channel release identity changed"
        );
        job.launch_channel = release.launch_channel;
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

    pub(crate) fn disconnect(&mut self, id: u64, generation: u64) -> Result<(), JobError> {
        let identity = identity(id, generation)?;
        let closed_order = self.next_closed_order;
        self.next_closed_order = closed_order
            .checked_add(1)
            .ok_or(JobError::ArithmeticOverflow)?;
        let connection = self.connection_mut(identity)?;
        connection.open = false;
        connection.closed_order = closed_order;
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
    /// Orphans that must be terminated to bring closed connections back within
    /// `MAX_ORPHAN_CONNECTIONS` and `MAX_ORPHAN_JOBS`: every still-running
    /// orphan of the oldest closed connections, oldest first. Retain-and-reap
    /// (WYR1-B 9.4) keeps recent background jobs running; only the bound is
    /// new. Returns how many job IDs were written to `out`.
    pub(crate) fn orphans_to_retire(&self, out: &mut [u64; MAX_LIVE_JOBS]) -> usize {
        let running = |job: &&Job| {
            job.shell_job
                && job.orphaned
                && job.terminal.is_none()
                && job.phase == JobPhase::Running
        };
        let holds = |identity: ConnectionIdentity| {
            self.jobs
                .iter()
                .flatten()
                .filter(running)
                .filter(|job| job.owner == identity)
                .count()
        };
        let mut connections = 0;
        let mut orphans = 0;
        for connection in self.connections.iter().flatten() {
            let held = holds(connection.identity);
            if !connection.open && held != 0 {
                connections += 1;
                orphans += held;
            }
        }
        let mut written = 0;
        let mut retired_up_to = 0;
        while connections > MAX_ORPHAN_CONNECTIONS || orphans > MAX_ORPHAN_JOBS {
            let Some(oldest) = self
                .connections
                .iter()
                .flatten()
                .filter(|connection| {
                    !connection.open
                        && connection.closed_order > retired_up_to
                        && holds(connection.identity) != 0
                })
                .min_by_key(|connection| connection.closed_order)
            else {
                break;
            };
            retired_up_to = oldest.closed_order;
            for job in self
                .jobs
                .iter()
                .flatten()
                .filter(running)
                .filter(|job| job.owner == oldest.identity)
            {
                out[written] = job.id;
                written += 1;
                orphans -= 1;
            }
            connections -= 1;
        }
        written
    }

    pub(crate) fn reclaim_closed_sessions(&mut self) {
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

    pub(crate) fn live_jobs(&self) -> usize {
        self.jobs.iter().flatten().count()
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

    pub(crate) fn loaded_job_for_owner(
        &self,
        connection_id: u64,
        generation: u64,
    ) -> Result<Option<LoadedJob>, JobError> {
        let owner = identity(connection_id, generation)?;
        Ok(self.jobs.iter().flatten().find_map(|job| {
            (job.owner == owner
                && (job.process != 0 || job.task_group != 0 || job.launch_channel != 0))
                .then_some(LoadedJob {
                    job_id: job.id,
                    loaded: LoadedProcess {
                        process: deepwyrm_syscall::DwHandle(job.process),
                        launch_channel: deepwyrm_syscall::DwHandle(job.launch_channel),
                    },
                    task_group: job.task_group,
                })
        }))
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

    pub(crate) fn reserve_transaction(
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

    pub(crate) fn connection_mut(
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

    pub(crate) fn owned_job(&self, owner: ConnectionIdentity, id: u64) -> Result<&Job, JobError> {
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
    pub(crate) fn owned_job_index(
        &self,
        owner: ConnectionIdentity,
        id: u64,
    ) -> Result<usize, JobError> {
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
    pub(crate) fn push_completed(&mut self, value: Completed) {
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

/// Continues a launch whose correlatable transaction was reserved before
/// semantic message validation.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
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

pub(crate) fn close_streams_reverse<E>(
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

impl Default for JobController {
    fn default() -> Self {
        Self::new()
    }
}
pub(crate) fn identity(id: u64, generation: u64) -> Result<ConnectionIdentity, JobError> {
    if id == 0 || generation == 0 {
        Err(JobError::ZeroIdentity)
    } else {
        Ok(ConnectionIdentity { id, generation })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn hog(controller: &mut JobController, owner: ConnectionIdentity, id: u64) {
        let slot = controller.jobs.iter().position(Option::is_none).unwrap();
        controller.jobs[slot] = Some(Job {
            id,
            owner,
            phase: JobPhase::Running,
            orphaned: false,
            shell_job: true,
            process: 100 + id,
            task_group: 200 + id,
            launch_channel: 300 + id,
            terminal: None,
            cleanup_result: 0,
            published: true,
        });
    }

    fn retire(controller: &mut JobController, ids: &[u64]) {
        for &job_id in ids {
            let job = controller
                .jobs
                .iter_mut()
                .flatten()
                .find(|job| job.id == job_id)
                .unwrap();
            assert!(job.orphaned && job.shell_job);
            // The kernel ends the task group; the poll loop reaps it.
            job.phase = JobPhase::Terminating;
        }
        for slot in &mut controller.jobs {
            if slot.is_some_and(|job| job.phase == JobPhase::Terminating) {
                *slot = None;
            }
        }
    }

    /// F4 WYR1-F4-M1: repeated `spawn bin/cpu-hog; exit` keeps the newest
    /// orphans running but never more than `MAX_ORPHAN_JOBS`, so the live
    /// shell always keeps job capacity and a new connection can always open.
    #[test]
    fn orphans_beyond_the_bound_are_retired_oldest_first() {
        let mut controller = JobController::new();
        let mut out = [0; MAX_LIVE_JOBS];
        for shell in 1..=40_u64 {
            controller.reclaim_closed_sessions();
            controller.open_connection(shell, 1).unwrap();
            hog(&mut controller, identity(shell, 1).unwrap(), shell);
            controller.disconnect(shell, 1).unwrap();
            let count = controller.orphans_to_retire(&mut out);
            retire(&mut controller, &out[..count]);
            assert!(controller.jobs.iter().flatten().count() <= MAX_ORPHAN_JOBS);
            if shell > MAX_ORPHAN_JOBS as u64 {
                assert_eq!(out[..count], [shell - MAX_ORPHAN_JOBS as u64]);
            } else {
                assert_eq!(count, 0);
            }
        }
    }

    #[test]
    fn a_connection_over_the_bound_loses_all_its_orphans() {
        let mut controller = JobController::new();
        let mut out = [0; MAX_LIVE_JOBS];
        controller.open_connection(1, 1).unwrap();
        controller.open_connection(2, 1).unwrap();
        for id in 1..=3 {
            hog(&mut controller, identity(1, 1).unwrap(), id);
        }
        hog(&mut controller, identity(2, 1).unwrap(), 4);
        controller.disconnect(1, 1).unwrap();
        let count = controller.orphans_to_retire(&mut out);
        let mut retired = [0; 3];
        retired.copy_from_slice(&out[..count]);
        retired.sort_unstable();
        assert_eq!(retired, [1, 2, 3]);
        retire(&mut controller, &[1, 2, 3]);
        controller.disconnect(2, 1).unwrap();
        assert_eq!(controller.orphans_to_retire(&mut out), 0);
    }

    #[test]
    fn open_connections_are_never_retired() {
        let mut controller = JobController::new();
        let mut out = [0; MAX_LIVE_JOBS];
        controller.open_connection(1, 1).unwrap();
        for id in 1..=MAX_LIVE_JOBS as u64 {
            hog(&mut controller, identity(1, 1).unwrap(), id);
        }
        assert_eq!(controller.orphans_to_retire(&mut out), 0);
    }

    /// F4 DW1-F4-M1: a fifth concurrent shell job is refused; the kernel is
    /// sized for four. One shell holds at most `MAX_JOBS_PER_SHELL`, so it
    /// cannot take every slot from another. The shell's own launch is not a
    /// shell job.
    #[test]
    fn shell_jobs_are_capped_at_the_kernel_geometry() {
        let mut controller = JobController::new();
        controller.open_connection(1, 1).unwrap();
        controller.open_connection(2, 1).unwrap();
        let ticket = |controller: &mut JobController, connection_id, transaction_id| {
            controller
                .reserve_request(Reservation {
                    connection_id,
                    generation: 1,
                    transaction_id,
                })
                .unwrap()
        };
        for transaction in 1..=MAX_JOBS_PER_SHELL as u64 {
            let request = ticket(&mut controller, 1, transaction);
            controller.begin_reserved_launch(request, true).unwrap();
        }
        let request = ticket(&mut controller, 1, 50);
        assert_eq!(
            controller.begin_reserved_launch(request, true),
            Err(JobError::Capacity)
        );
        for transaction in (MAX_JOBS_PER_SHELL + 1)..=MAX_SHELL_JOBS {
            let request = ticket(&mut controller, 2, transaction as u64);
            controller.begin_reserved_launch(request, true).unwrap();
        }
        let request = ticket(&mut controller, 2, 100);
        assert_eq!(
            controller.begin_reserved_launch(request, true),
            Err(JobError::Capacity)
        );
        let request = ticket(&mut controller, 1, 101);
        assert!(controller.begin_reserved_launch(request, false).is_ok());
    }

    /// A job whose forced termination the kernel refused is offered for a
    /// retry until it is committed; a healthy running job is not.
    #[test]
    fn a_refused_termination_is_retried() {
        let mut controller = JobController::new();
        controller.open_connection(1, 1).unwrap();
        hog(&mut controller, identity(1, 1).unwrap(), 1);
        hog(&mut controller, identity(1, 1).unwrap(), 2);
        assert_eq!(controller.termination_to_retry(1), None);
        controller.record_cleanup_bits(1, 1 << 0).unwrap();
        let resources = controller
            .termination_to_retry(1)
            .expect("refused termination offered for retry");
        assert_eq!(controller.termination_to_retry(2), None);
        controller.commit_forced_termination(1, resources).unwrap();
        assert_eq!(controller.termination_to_retry(1), None);
    }
}
