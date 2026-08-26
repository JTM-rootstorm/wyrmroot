//! WYR1-B controller-owned registry topology and launch/job state.

use wyrmroot_bootfs::{
    archive::{Archive, LookupError},
    launch_policy::{LAUNCH_POLICY_PATH, LaunchPolicy, PolicyError},
};
use wyrmroot_launch_proto::{MAX_COMPLETED_JOBS, MAX_LIVE_JOBS, Reservation};
use wyrmroot_runtime::sha256;

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
        self.next_endpoint_id = 1;
        Ok(())
    }

    pub const fn accepts(&self, grant: EndpointGrant) -> bool {
        grant.registry_generation == self.registry_generation
    }
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

    pub fn begin_launch(&mut self, request: Reservation) -> Result<LaunchTicket, JobError> {
        let owner = self.reserve_transaction(request)?;
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
            owner,
            phase: JobPhase::Reserved,
            orphaned: false,
            process: 0,
            task_group: 0,
        });
        Ok(LaunchTicket {
            slot,
            job_id,
            owner,
        })
    }

    pub fn commit_launch(
        &mut self,
        ticket: LaunchTicket,
        process: u64,
        task_group: u64,
    ) -> Result<(), JobError> {
        if process == 0 || task_group == 0 {
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
        job.process = process;
        job.task_group = task_group;
        job.phase = JobPhase::Running;
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
        let owner = self.reserve_transaction(request)?;
        let job = self.owned_job(owner, job_id)?;
        Ok(JobSnapshot {
            job_id,
            phase: job.phase,
            orphaned: job.orphaned,
        })
    }

    pub fn terminate(&mut self, request: Reservation, job_id: u64) -> Result<(u64, u64), JobError> {
        let owner = self.reserve_transaction(request)?;
        let index = self.owned_job_index(owner, job_id)?;
        let job = self.jobs[index].as_mut().unwrap();
        if job.phase != JobPhase::Running {
            return Err(JobError::WrongState);
        }
        job.phase = JobPhase::Terminating;
        Ok((job.process, job.task_group))
    }

    pub fn complete(
        &mut self,
        job_id: u64,
        process: u64,
        task_group: u64,
        result: JobResult,
    ) -> Result<(), JobError> {
        let index = self
            .jobs
            .iter()
            .position(|job| job.as_ref().is_some_and(|job| job.id == job_id))
            .ok_or(JobError::UnknownJob)?;
        let job = self.jobs[index].take().unwrap();
        if job.phase == JobPhase::Reserved || job.process != process || job.task_group != task_group
        {
            self.jobs[index] = Some(job);
            return Err(JobError::ResourceIdentity);
        }
        self.push_completed(Completed {
            id: job.id,
            owner: job.owner,
            result,
            visible: !job.orphaned,
        });
        Ok(())
    }

    pub fn result(&mut self, request: Reservation, job_id: u64) -> Result<JobResult, JobError> {
        let owner = self.reserve_transaction(request)?;
        self.completed
            .iter()
            .flatten()
            .find(|record| record.id == job_id && record.owner == owner && record.visible)
            .map(|record| record.result)
            .ok_or(JobError::UnknownJob)
    }

    pub fn close_job(&mut self, request: Reservation, job_id: u64) -> Result<(), JobError> {
        let owner = self.reserve_transaction(request)?;
        if self
            .jobs
            .iter_mut()
            .flatten()
            .find(|job| job.id == job_id && job.owner == owner)
            .is_some_and(|job| {
                job.orphaned = true;
                true
            })
        {
            return Ok(());
        }
        if let Some(record) = self
            .completed
            .iter_mut()
            .flatten()
            .find(|record| record.id == job_id && record.owner == owner && record.visible)
        {
            record.visible = false;
            return Ok(());
        }
        Err(JobError::ForeignJob)
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
        jobs.commit_launch(ticket, 10, 11).unwrap();
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
            Ok((10, 11))
        );
        jobs.complete(ticket.job_id, 10, 11, normal()).unwrap();
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
    fn disconnected_jobs_are_retained_and_reaped_without_reattachment() {
        let mut jobs = JobController::new();
        jobs.open_connection(1, 1).unwrap();
        let ticket = jobs.begin_launch(reservation(1, 1, 1)).unwrap();
        jobs.commit_launch(ticket, 10, 11).unwrap();
        jobs.disconnect(1, 1).unwrap();
        assert_eq!(jobs.orphan_jobs(), 1);
        assert_eq!(
            jobs.query(reservation(1, 1, 2), ticket.job_id),
            Err(JobError::ClosedConnection)
        );
        jobs.complete(ticket.job_id, 10, 11, normal()).unwrap();
        assert_eq!(jobs.live_jobs(), 0);
        jobs.open_connection(2, 1).unwrap();
        assert_eq!(
            jobs.result(reservation(2, 1, 1), ticket.job_id),
            Err(JobError::UnknownJob)
        );
    }

    #[test]
    fn registry_grants_die_with_registry_generation() {
        let mut topology = RegistryTopology::new(1).unwrap();
        let grant = topology.issue(7, EndpointKind::Publication).unwrap();
        assert!(topology.accepts(grant));
        topology.restart(2).unwrap();
        assert!(!topology.accepts(grant));
        assert_eq!(topology.restart(2), Err(JobError::StaleGeneration));
    }
}
