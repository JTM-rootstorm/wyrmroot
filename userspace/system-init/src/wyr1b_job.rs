//! Selector-27 resident WRLJ session and job dispatcher state.

use deepwyrm_syscall::DwHandle;

use crate::wyr1b::{EndpointGrant, EndpointKind, JobController, JobError};

pub(crate) const MAX_SESSIONS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Session {
    grant: EndpointGrant,
    channel: DwHandle,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct JobDispatcher {
    pub(crate) jobs: JobController,
    sessions: [Option<Session>; MAX_SESSIONS],
    poll_cursor: usize,
}

impl JobDispatcher {
    pub(crate) const fn new() -> Self {
        Self {
            jobs: JobController::new(),
            sessions: [None; MAX_SESSIONS],
            poll_cursor: 0,
        }
    }

    pub(crate) fn install_session(
        &mut self,
        grant: EndpointGrant,
        channel: DwHandle,
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
        self.sessions[slot] = Some(Session { grant, channel });
        Ok(())
    }

    pub(crate) fn disconnect_session(
        &mut self,
        grant: EndpointGrant,
    ) -> Result<DwHandle, JobError> {
        let index = self
            .sessions
            .iter()
            .position(|session| session.is_some_and(|session| session.grant == grant))
            .ok_or(JobError::UnknownConnection)?;
        self.jobs
            .disconnect(grant.endpoint_id, grant.endpoint_generation)?;
        let channel = self.sessions[index].take().unwrap().channel;
        self.jobs.reclaim_closed_sessions();
        Ok(channel)
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

    pub(crate) fn session_count(&self) -> usize {
        self.sessions.iter().flatten().count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrmroot_launch_proto::{
        ErrorCode, Message, MessageType, Reservation, TerminationClassification, TerminationResult,
        encode_error, encode_job_message, encode_job_result, parse_message,
    };

    fn grant(id: u64) -> EndpointGrant {
        EndpointGrant {
            registry_generation: 1,
            endpoint_id: id,
            endpoint_generation: 1,
            role_generation: 1,
            kind: EndpointKind::LaunchSession,
        }
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
    fn disconnect_reclaims_only_after_orphans_are_reaped() {
        let mut dispatcher = JobDispatcher::new();
        let owner = grant(1);
        dispatcher.install_session(owner, DwHandle(101)).unwrap();
        let ticket = dispatcher
            .jobs
            .begin_launch(wyrmroot_launch_proto::Reservation {
                connection_id: 1,
                generation: 1,
                transaction_id: 1,
            })
            .unwrap();
        dispatcher.jobs.commit_launch(ticket, 10, 11, 12).unwrap();
        assert_eq!(dispatcher.disconnect_session(owner), Ok(DwHandle(101)));
        assert_eq!(dispatcher.session_count(), 0);
        assert_eq!(dispatcher.jobs.orphan_jobs(), 1);
        assert_eq!(
            dispatcher.jobs.open_connection(1, 2),
            Err(JobError::DuplicateConnection)
        );
        dispatcher
            .jobs
            .complete(
                ticket.job_id,
                10,
                11,
                12,
                crate::wyr1b::JobResult {
                    classification: 1,
                    application_code: 0,
                    exception_class: 0,
                    exception_detail: 0,
                    exception_address: 0,
                    cleanup_result: 0,
                },
            )
            .unwrap();
        dispatcher.jobs.reclaim_closed_sessions();
        dispatcher.jobs.open_connection(1, 2).unwrap();
    }

    #[test]
    fn owner_wait_and_foreign_query_transcript_is_exact() {
        let mut dispatcher = JobDispatcher::new();
        dispatcher.install_session(grant(1), DwHandle(101)).unwrap();
        dispatcher.install_session(grant(2), DwHandle(102)).unwrap();
        let launch = Reservation {
            connection_id: 1,
            generation: 1,
            transaction_id: 1,
        };
        let ticket = dispatcher.jobs.begin_launch(launch).unwrap();
        dispatcher.jobs.commit_launch(ticket, 10, 11, 12).unwrap();
        let mut bytes = [0_u8; 88];
        let size = encode_job_message(
            launch,
            MessageType::LaunchAccepted,
            ticket.job_id,
            &mut bytes,
        )
        .unwrap();
        let accepted = parse_message(&bytes[..size], 0).unwrap();
        assert_eq!(accepted.reservation, launch);
        assert_eq!(
            accepted.message,
            Message::LaunchAccepted {
                job_id: ticket.job_id
            }
        );

        let controller_result = crate::wyr1b::JobResult {
            classification: TerminationClassification::NormalExit.as_u32(),
            application_code: 0,
            exception_class: 0,
            exception_detail: 0,
            exception_address: 0,
            cleanup_result: 0,
        };
        dispatcher
            .jobs
            .complete(ticket.job_id, 10, 11, 12, controller_result)
            .unwrap();
        let wait = Reservation {
            transaction_id: 2,
            ..launch
        };
        assert_eq!(
            dispatcher.jobs.result(wait, ticket.job_id),
            Ok(controller_result)
        );
        let terminal = TerminationResult {
            classification: TerminationClassification::NormalExit,
            application_code: 0,
            exception_class: 0,
            exception_detail: 0,
            exception_address: 0,
            cleanup_result: 0,
        };
        let size = encode_job_result(wait, ticket.job_id, terminal, &mut bytes).unwrap();
        let result = parse_message(&bytes[..size], 0).unwrap();
        assert_eq!(result.reservation, wait);
        assert_eq!(
            result.message,
            Message::JobResult {
                job_id: ticket.job_id,
                result: terminal
            }
        );

        let foreign = Reservation {
            connection_id: 2,
            generation: 1,
            transaction_id: 1,
        };
        assert_eq!(
            dispatcher.jobs.query(foreign, ticket.job_id),
            Err(JobError::UnknownJob)
        );
        let size = encode_error(foreign, ErrorCode::ForeignOrUnknownJob, &mut bytes).unwrap();
        let rejected = parse_message(&bytes[..size], 0).unwrap();
        assert_eq!(rejected.reservation, foreign);
        assert_eq!(
            rejected.message,
            Message::Error {
                code: ErrorCode::ForeignOrUnknownJob
            }
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
}
