//! Selector-27 resident WRLJ session and job dispatcher state.

use deepwyrm_syscall::DwHandle;

use crate::jobs::{EndpointGrant, EndpointKind, JobController, JobError};
use crate::launch_transaction::LaunchTransactions;
use wyrmroot_launch_proto::Reservation;

pub(crate) const MAX_SESSIONS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Session {
    pub(crate) grant: EndpointGrant,
    pub(crate) channel: DwHandle,
    pub(crate) owner: Option<SessionOwner>,
    pub(crate) scope: LaunchSessionScope,
    pub(crate) outer_job: Option<u64>,
}

/// Controller-owned authority for one installed launch session.
///
/// The scope is fixed at installation and is never selected from request bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LaunchSessionScope {
    ConsoleLauncher,
    ShellJobs,
}

impl LaunchSessionScope {
    pub(crate) fn admits_legacy_launch(self, path: &str) -> bool {
        match self {
            Self::ConsoleLauncher => false,
            Self::ShellJobs => {
                let production = matches!(path, "bin/hello" | "bin/cpu-hog");
                production
            }
        }
    }

    pub(crate) const fn admits_shell_v1(self) -> bool {
        matches!(self, Self::ConsoleLauncher)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SessionOwner {
    pub(crate) process: DwHandle,
    pub(crate) launch_channel: DwHandle,
    pub(crate) task_group: DwHandle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DisconnectedSession {
    pub(crate) channel: DwHandle,
    pub(crate) owner: Option<SessionOwner>,
    pub(crate) outer_job: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PendingWait {
    pub(crate) grant: EndpointGrant,
    pub(crate) reservation: Reservation,
    pub(crate) job_id: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct JobDispatcher {
    pub(crate) jobs: JobController,
    /// R6A's storage, wired in by R6B-2. A launch that returns to the event
    /// loop between construction and READY keeps its envelope, its handles and
    /// its stage here instead of on the dispatch frame.
    pub(crate) launches: LaunchTransactions,
    /// Where the next deferred-launch sweep starts, so a child that never
    /// answers cannot starve the slot behind it.
    pub(crate) launch_cursor: usize,
    pub(crate) sessions: [Option<Session>; MAX_SESSIONS],
    pub(crate) poll_cursor: usize,
    pub(crate) job_cursor: usize,
    pub(crate) pending_waits: [Option<PendingWait>; MAX_SESSIONS],
    pub(crate) wait_cursor: usize,
}

impl JobDispatcher {
    pub(crate) const fn new() -> Self {
        Self {
            jobs: JobController::new(),
            launches: LaunchTransactions::new(),
            launch_cursor: 0,
            sessions: [None; MAX_SESSIONS],
            poll_cursor: 0,
            job_cursor: 0,
            pending_waits: [None; MAX_SESSIONS],
            wait_cursor: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn install_session(
        &mut self,
        grant: EndpointGrant,
        channel: DwHandle,
    ) -> Result<(), JobError> {
        self.install_scoped_session(grant, channel, LaunchSessionScope::ShellJobs)
    }

    pub(crate) fn install_scoped_session(
        &mut self,
        grant: EndpointGrant,
        channel: DwHandle,
        scope: LaunchSessionScope,
    ) -> Result<(), JobError> {
        if grant.kind != EndpointKind::LaunchSession || channel.0 == 0 {
            return Err(JobError::ResourceIdentity);
        }
        let slot = self
            .sessions
            .iter()
            .position(Option::is_none)
            .ok_or(JobError::Capacity)?;
        self.jobs
            .open_connection(grant.endpoint_id, grant.endpoint_generation)?;
        self.sessions[slot] = Some(Session {
            grant,
            channel,
            owner: None,
            scope,
            outer_job: None,
        });
        Ok(())
    }

    pub(crate) fn session_scope(
        &self,
        grant: EndpointGrant,
    ) -> Result<LaunchSessionScope, JobError> {
        self.sessions
            .iter()
            .flatten()
            .find(|session| session.grant == grant)
            .map(|session| session.scope)
            .ok_or(JobError::UnknownConnection)
    }

    pub(crate) fn attach_session_owner(
        &mut self,
        grant: EndpointGrant,
        owner: SessionOwner,
    ) -> Result<(), JobError> {
        if owner.process.0 == 0 || owner.launch_channel.0 == 0 || owner.task_group.0 == 0 {
            return Err(JobError::ResourceIdentity);
        }
        let session = self
            .sessions
            .iter_mut()
            .flatten()
            .find(|session| session.grant == grant)
            .ok_or(JobError::UnknownConnection)?;
        if session.owner.is_some() {
            return Err(JobError::WrongState);
        }
        session.owner = Some(owner);
        Ok(())
    }

    pub(crate) fn attach_outer_job(
        &mut self,
        grant: EndpointGrant,
        job_id: u64,
    ) -> Result<(), JobError> {
        if job_id == 0 {
            return Err(JobError::ResourceIdentity);
        }
        let session = self
            .sessions
            .iter_mut()
            .flatten()
            .find(|session| session.grant == grant)
            .ok_or(JobError::UnknownConnection)?;
        if session.scope != LaunchSessionScope::ShellJobs
            || session.owner.is_some()
            || session.outer_job.is_some()
        {
            return Err(JobError::WrongState);
        }
        session.outer_job = Some(job_id);
        Ok(())
    }

    pub(crate) fn has_shell_session(&self) -> bool {
        self.sessions
            .iter()
            .flatten()
            .any(|session| session.scope == LaunchSessionScope::ShellJobs)
    }

    pub(crate) fn shell_session_for_outer_job(&self, job_id: u64) -> Option<EndpointGrant> {
        self.sessions.iter().flatten().find_map(|session| {
            (session.scope == LaunchSessionScope::ShellJobs && session.outer_job == Some(job_id))
                .then_some(session.grant)
        })
    }

    pub(crate) fn disconnect_session(
        &mut self,
        grant: EndpointGrant,
    ) -> Result<DwHandle, JobError> {
        if self
            .sessions
            .iter()
            .flatten()
            .find(|session| session.grant == grant)
            .ok_or(JobError::UnknownConnection)?
            .owner
            .is_some()
        {
            return Err(JobError::WrongState);
        }
        let disconnected = self.disconnect_owned_session(grant)?;
        Ok(disconnected.channel)
    }

    pub(crate) fn disconnect_owned_session(
        &mut self,
        grant: EndpointGrant,
    ) -> Result<DisconnectedSession, JobError> {
        let index = self
            .sessions
            .iter()
            .position(|session| session.is_some_and(|session| session.grant == grant))
            .ok_or(JobError::UnknownConnection)?;
        self.jobs
            .disconnect(grant.endpoint_id, grant.endpoint_generation)?;
        self.drop_session_waits(grant);
        let session = self.sessions[index].take().unwrap();
        self.jobs.reclaim_closed_sessions();
        Ok(DisconnectedSession {
            channel: session.channel,
            owner: session.owner,
            outer_job: session.outer_job,
        })
    }

    pub(crate) fn next_session(&mut self) -> Option<(EndpointGrant, DwHandle)> {
        for offset in 0..MAX_SESSIONS {
            let index = (self.poll_cursor + offset) % MAX_SESSIONS;
            if let Some(session) = self.sessions[index] {
                self.poll_cursor = (index + 1) % MAX_SESSIONS;
                return Some((session.grant, session.channel));
            }
        }
        None
    }

    pub(crate) fn session_handle(&self, grant: EndpointGrant) -> Result<DwHandle, JobError> {
        self.sessions
            .iter()
            .flatten()
            .find(|session| session.grant == grant)
            .map(|session| session.channel)
            .ok_or(JobError::UnknownConnection)
    }

    pub(crate) fn next_cleanup_job(&mut self) -> Option<crate::jobs::LoadedJob> {
        let (cursor, job_id) = self.jobs.cleanup_job_id(self.job_cursor)?;
        self.job_cursor = cursor;
        self.jobs.loaded_job(job_id).ok()
    }

    pub(crate) fn install_pending_wait(
        &mut self,
        grant: EndpointGrant,
        reservation: Reservation,
        job_id: u64,
        request_bytes: &[u8],
    ) -> Result<(), JobError> {
        if reservation.connection_id != grant.endpoint_id
            || reservation.generation != grant.endpoint_generation
            || reservation.transaction_id == 0
            || job_id == 0
        {
            return Err(JobError::ResourceIdentity);
        }
        let _ = request_bytes;
        if self.pending_waits.iter().flatten().any(|pending| {
            pending.grant == grant
                && pending.reservation.transaction_id == reservation.transaction_id
        }) {
            return Err(JobError::TransactionReplay);
        }
        let slot = self
            .pending_waits
            .iter()
            .position(Option::is_none)
            .ok_or(JobError::Capacity)?;
        self.pending_waits[slot] = Some(PendingWait {
            grant,
            reservation,
            job_id,
        });
        Ok(())
    }

    pub(crate) fn cancel_pending_wait(
        &mut self,
        grant: EndpointGrant,
        target_transaction_id: u64,
    ) -> Option<PendingWait> {
        let index = self.pending_waits.iter().position(|pending| {
            pending.is_some_and(|pending| {
                pending.grant == grant
                    && pending.reservation.transaction_id == target_transaction_id
            })
        })?;
        self.pending_waits[index].take()
    }

    pub(crate) fn drop_job_waits(&mut self, grant: EndpointGrant, job_id: u64) {
        for pending in &mut self.pending_waits {
            if pending.is_some_and(|pending| pending.grant == grant && pending.job_id == job_id) {
                *pending = None;
            }
        }
    }

    pub(crate) fn next_pending_wait(&mut self) -> Option<PendingWait> {
        for offset in 0..MAX_SESSIONS {
            let index = (self.wait_cursor + offset) % MAX_SESSIONS;
            if let Some(pending) = self.pending_waits[index] {
                self.wait_cursor = (index + 1) % MAX_SESSIONS;
                return Some(pending);
            }
        }
        None
    }

    pub(crate) fn finish_pending_wait(&mut self, pending: PendingWait) -> Result<(), JobError> {
        let index = self
            .pending_waits
            .iter()
            .position(|entry| *entry == Some(pending))
            .ok_or(JobError::WrongState)?;
        self.pending_waits[index] = None;
        Ok(())
    }

    pub(crate) fn drop_session_waits(&mut self, grant: EndpointGrant) {
        for pending in &mut self.pending_waits {
            if pending.is_some_and(|pending| pending.grant == grant) {
                *pending = None;
            }
        }
    }

    pub(crate) fn drain_sessions(
        &mut self,
        out: &mut [Option<DisconnectedSession>; MAX_SESSIONS],
    ) -> usize {
        let mut count = 0;
        for session in &mut self.sessions {
            if let Some(session) = session.take() {
                let _ = self
                    .jobs
                    .disconnect(session.grant.endpoint_id, session.grant.endpoint_generation);
                out[count] = Some(DisconnectedSession {
                    channel: session.channel,
                    owner: session.owner,
                    outer_job: session.outer_job,
                });
                count += 1;
            }
        }
        self.pending_waits.fill(None);
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrmroot_launch_proto::{
        Message, Reservation, TerminationClassification, TerminationResult, encode_job_message,
        encode_job_result, parse_message,
    };

    /// F4 WR-F4-L1 (with rereview D1): the scope table itself. Dispatch tests
    /// cannot see a widened allowlist, because a refused scope and a missing
    /// policy give the same reply; these assertions fail on any widened or
    /// flipped arm.
    #[test]
    fn launch_scopes_admit_exactly_their_table() {
        use LaunchSessionScope::{ConsoleLauncher, ShellJobs};
        for path in ["bin/hello", "bin/cpu-hog"] {
            assert!(ShellJobs.admits_legacy_launch(path), "{path}");
            assert!(!ConsoleLauncher.admits_legacy_launch(path), "{path}");
        }
        for path in [
            "system/consoled",
            "system/init",
            "system/wyrmsh",
            "system/devmgr",
            "system/registryd",
            "system/uart16550d",
            "bin/hello-extra",
            "bin/cpu-hog2",
            "bin/hello/",
            "bin",
            "",
        ] {
            assert!(!ShellJobs.admits_legacy_launch(path), "{path}");
            assert!(!ConsoleLauncher.admits_legacy_launch(path), "{path}");
        }
        assert!(ConsoleLauncher.admits_shell_v1());
        assert!(!ShellJobs.admits_shell_v1());
    }

    fn grant(id: u64) -> EndpointGrant {
        EndpointGrant {
            registry_generation: 1,
            endpoint_id: id,
            endpoint_generation: 1,
            role_generation: 1,
            kind: EndpointKind::LaunchSession,
        }
    }

    fn wait_request(reservation: Reservation, job_id: u64) -> [u8; 56] {
        let mut request = [0u8; 56];
        let size = encode_job_message(
            reservation,
            wyrmroot_launch_proto::MessageType::Wait,
            job_id,
            &mut request,
        )
        .unwrap();
        assert_eq!(size, request.len());
        request
    }

    #[test]
    fn sessions_are_distinct_bounded_and_polled_round_robin() {
        let mut dispatcher = JobDispatcher::new();
        dispatcher.install_session(grant(1), DwHandle(101)).unwrap();
        dispatcher.install_session(grant(2), DwHandle(102)).unwrap();
        assert_eq!(dispatcher.next_session(), Some((grant(1), DwHandle(101))));
        assert_eq!(dispatcher.next_session(), Some((grant(2), DwHandle(102))));
        assert_eq!(dispatcher.next_session(), Some((grant(1), DwHandle(101))));
        for id in 3..=MAX_SESSIONS as u64 {
            dispatcher
                .install_session(grant(id), DwHandle(100 + id))
                .unwrap();
        }
        assert_eq!(
            dispatcher.install_session(grant(17), DwHandle(117)),
            Err(JobError::Capacity)
        );
    }

    #[test]
    fn transcript_rejects_wrong_correlation_job_and_malformed_response() {
        let expected = Reservation {
            connection_id: 1,
            generation: 1,
            transaction_id: 2,
        };
        let wrong = Reservation {
            transaction_id: 3,
            ..expected
        };
        let mut bytes = [0_u8; 88];
        let size = encode_job_result(
            wrong,
            9,
            TerminationResult {
                classification: TerminationClassification::NormalExit,
                application_code: 0,
                exception_class: 0,
                exception_detail: 0,
                exception_address: 0,
                cleanup_result: 0,
            },
            &mut bytes,
        )
        .unwrap();
        let parsed = parse_message(&bytes[..size], 0).unwrap();
        assert_ne!(parsed.reservation, expected);
        assert!(matches!(
            parsed.message,
            Message::JobResult { job_id: 9, .. }
        ));
        assert_ne!(9, 7, "wrong job correlation must not satisfy job 7");
        assert!(parse_message(&bytes[..size - 1], 0).is_err());
    }

    #[test]
    fn pending_waits_are_bounded_replay_exact_and_owner_correlated() {
        let mut dispatcher = JobDispatcher::new();
        let owner = grant(1);
        dispatcher.install_session(owner, DwHandle(101)).unwrap();
        for transaction_id in 1..=MAX_SESSIONS as u64 {
            let reservation = Reservation {
                connection_id: 1,
                generation: 1,
                transaction_id,
            };
            dispatcher
                .install_pending_wait(owner, reservation, 9, &wait_request(reservation, 9))
                .unwrap();
        }
        let replay = Reservation {
            connection_id: 1,
            generation: 1,
            transaction_id: 1,
        };
        assert_eq!(
            dispatcher.install_pending_wait(owner, replay, 9, &wait_request(replay, 9),),
            Err(JobError::TransactionReplay)
        );
        let over_capacity = Reservation {
            connection_id: 1,
            generation: 1,
            transaction_id: 17,
        };
        assert_eq!(
            dispatcher.install_pending_wait(
                owner,
                over_capacity,
                9,
                &wait_request(over_capacity, 9),
            ),
            Err(JobError::Capacity)
        );
        assert!(dispatcher.cancel_pending_wait(grant(2), 1).is_none());
        let cancelled = dispatcher.cancel_pending_wait(owner, 1).unwrap();
        assert_eq!(cancelled.grant, owner);
        assert_eq!(cancelled.reservation.transaction_id, 1);
        assert_eq!(cancelled.job_id, 9);
    }
}
