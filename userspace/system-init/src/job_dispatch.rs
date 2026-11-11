//! The resident job dispatcher: sessions, requests, deferred launches.

use crate::job_sessions::{JobDispatcher, LaunchSessionScope, SessionOwner};
use crate::jobs::{EndpointGrant, EndpointKind, JobError, PolicyView, RequestTicket};
use crate::launch_transaction::{LaunchStage, LaunchToken};
use crate::*;
use deepwyrm_syscall::{DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DW_TASK_STATE_EXITED};
use wyrmroot_launch_proto::{
    ErrorCode as LaunchErrorCode, Message as LaunchMessage, MessageType as LaunchMessageType,
    Reservation as LaunchReservation, TerminationResult, encode_error as encode_launch_error,
    encode_job_list, encode_job_message, encode_job_result, encode_job_state,
    encode_shell_v1_accepted, parse_message as parse_launch_message, parse_reservation_prefix,
    parse_shell_v1_request, parse_shell_v1_reservation_prefix,
};
use wyrmroot_loader::{
    launch::LaunchProfile,
    process::{WyrmshLoadRequest, load_wyrmsh_process},
};

#[allow(clippy::too_many_arguments, clippy::needless_option_as_deref)]
pub(crate) fn dispatch_reserved_operation_observed<S, W>(
    system: &mut S,
    _waits: &mut W,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    grant: EndpointGrant,
    reservation: LaunchReservation,
    ticket: RequestTicket,
    message: LaunchMessage<'_>,
    request_bytes: &[u8],
    scope: LaunchSessionScope,
    mut evidence: Option<&mut ShellControllerState>,
) -> Result<(), InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut response = [0_u8; 320];
    let result: Result<Option<usize>, JobError> = match message {
        LaunchMessage::Query { job_id } => {
            jobs.jobs
                .query_reserved(ticket, job_id)
                .and_then(|snapshot| {
                    let phase = match snapshot.phase {
                        crate::jobs::JobPhase::Running => wyrmroot_launch_proto::JobPhase::Running,
                        crate::jobs::JobPhase::Terminating => {
                            wyrmroot_launch_proto::JobPhase::Terminating
                        }
                        crate::jobs::JobPhase::Reserved => return Err(JobError::WrongState),
                    };
                    encode_job_state(reservation, job_id, phase, &mut response)
                        .map(Some)
                        .map_err(|_| JobError::WrongState)
                })
        }
        LaunchMessage::Wait { job_id } => (|| -> Result<Option<usize>, JobError> {
            match jobs.jobs.result_reserved(ticket, job_id) {
                Ok(controller) => {
                    let terminal =
                        controller_result_to_wire(controller).map_err(|_| JobError::WrongState)?;
                    observe_session_shutdown_result(scope, evidence.as_deref_mut(), terminal);
                    encode_job_result(reservation, job_id, terminal, &mut response)
                        .map(Some)
                        .map_err(|_| JobError::WrongState)
                }
                Err(JobError::UnknownJob) => {
                    jobs.jobs.query_reserved(ticket, job_id)?;
                    jobs.install_pending_wait(grant, reservation, job_id, request_bytes)?;
                    Ok(None)
                }
                Err(error) => Err(error),
            }
        })(),
        LaunchMessage::Terminate { job_id } => {
            let resources = match jobs.jobs.authorize_terminate_reserved(ticket, job_id) {
                Ok(resources) => resources,
                Err(error) => {
                    return send_observed_job_error(
                        system,
                        session,
                        reservation,
                        job_error_code(error),
                    );
                }
            };
            if system
                .terminate_task_group(DwHandle(resources.task_group))
                .is_err()
            {
                jobs.jobs
                    .record_cleanup_bits(job_id, 1 << 0)
                    .map_err(InitError::Jobs)?;
                return send_observed_job_error(
                    system,
                    session,
                    reservation,
                    LaunchErrorCode::CleanupFailure,
                );
            }
            jobs.jobs
                .commit_terminate(job_id, resources)
                .and_then(|()| {
                    encode_job_message(
                        reservation,
                        LaunchMessageType::TerminationAccepted,
                        job_id,
                        &mut response,
                    )
                    .map(Some)
                    .map_err(|_| JobError::WrongState)
                })
        }
        LaunchMessage::ListJobs => {
            let mut ids = [0_u64; wyrmroot_launch_proto::MAX_LIVE_JOBS];
            jobs.jobs.list_reserved(ticket, &mut ids).and_then(|count| {
                encode_job_list(reservation, &ids[..count], &mut response)
                    .map(Some)
                    .map_err(|_| JobError::WrongState)
            })
        }
        LaunchMessage::CloseJob { job_id } => {
            jobs.jobs.close_job_reserved(ticket, job_id).and_then(|()| {
                jobs.drop_job_waits(grant, job_id);
                encode_job_message(
                    reservation,
                    LaunchMessageType::Closed,
                    job_id,
                    &mut response,
                )
                .map(Some)
                .map_err(|_| JobError::WrongState)
            })
        }
        LaunchMessage::Cancel {
            target_transaction_id,
        } => {
            if jobs
                .cancel_pending_wait(grant, target_transaction_id)
                .is_none()
            {
                return send_observed_job_error(
                    system,
                    session,
                    reservation,
                    LaunchErrorCode::CancellationUnavailable,
                );
            }
            encode_job_message(
                reservation,
                LaunchMessageType::Cancelled,
                target_transaction_id,
                &mut response,
            )
            .map(Some)
            .map_err(|_| JobError::WrongState)
        }
        _ => Err(JobError::WrongState),
    };
    match result {
        Ok(Some(size)) => {
            system
                .send_channel(session, &response[..size])
                .map_err(InitError::Native)?;
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(error) => send_observed_job_error(system, session, reservation, job_error_code(error)),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JobDispatchOutcome {
    Responded,
    Launched(crate::jobs::LoadedJob),
    /// The child exists and its READY deadline is armed, but nothing has been
    /// published yet. Reset card R6B-2: the transaction is in the arena and the
    /// dispatcher has gone back to the event loop.
    Constructed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JobWireVersion {
    Legacy,
    ShellV1,
}

pub(crate) fn close_shell_session_for_job<S: InitPlatform>(
    system: &mut S,
    jobs: &mut JobDispatcher,
    job_id: u64,
) -> Result<(), InitError> {
    let Some(grant) = jobs.shell_session_for_outer_job(job_id) else {
        return Ok(());
    };
    let disconnected = jobs
        .disconnect_owned_session(grant)
        .map_err(InitError::Jobs)?;
    if disconnected.owner.is_some()
        || disconnected.outer_job != Some(job_id)
        || system.close_handle(disconnected.channel).is_err()
    {
        return Err(InitError::Cleanup);
    }
    Ok(())
}

pub(crate) fn cleanup_shell_before_publication<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    loaded: crate::jobs::LoadedJob,
) -> Result<TerminationResult, InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    cleanup_shell_before_publication_before(system, waits, jobs, loaded, None)
}

pub(crate) fn cleanup_shell_before_publication_before<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    loaded: crate::jobs::LoadedJob,
    deadline_cap: Option<u64>,
) -> Result<TerminationResult, InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let cleanup = force_cleanup_job_before(system, waits, jobs, loaded, deadline_cap);
    let session_cleanup = close_shell_session_for_job(system, jobs, loaded.job_id);
    match (cleanup, session_cleanup) {
        (Ok(result), Ok(())) => Ok(result),
        _ => Err(InitError::Cleanup),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AcceptedShell {
    pub(crate) loaded: crate::jobs::LoadedJob,
    pub(crate) request: wyrmroot_launch_proto::ShellV1Request,
    pub(crate) registry_grant: EndpointGrant,
    pub(crate) shell_grant: EndpointGrant,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn accept_reserved_shell<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: &PolicyView<'_>,
    jobs: &mut JobDispatcher,
    reservation: LaunchReservation,
    request_ticket: RequestTicket,
    request: wyrmroot_launch_proto::ShellV1Request,
    received: &[DwReceivedHandleInfoV1],
    context: &mut ShellLaunchContext<'_>,
) -> Result<AcceptedShell, InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    if jobs.has_shell_session() {
        let failed = close_received_reverse(system, received, received.len());
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Jobs(JobError::Capacity)
        });
    }
    let image = match policy.authorize_wyrmsh() {
        Ok(image) => image,
        Err(error) => {
            let failed = close_received_reverse(system, received, received.len());
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Jobs(error)
            });
        }
    };
    let ticket = match jobs.jobs.begin_reserved_launch(request_ticket, false) {
        Ok(ticket) => ticket,
        Err(error) => {
            let failed = close_received_reverse(system, received, received.len());
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Jobs(error)
            });
        }
    };
    if let Err(error) = context.state.reserve_shell_generation(request) {
        let failed = close_received_reverse(system, received, received.len())
            | jobs.jobs.abort_launch(ticket).is_err();
        return Err(if failed { InitError::Cleanup } else { error });
    }
    let group = match system.create_attempt_task_group(authority.task_group) {
        Ok(group) => group,
        Err(error) => {
            let failed = close_received_reverse(system, received, received.len())
                | jobs.jobs.abort_launch(ticket).is_err();
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Native(error)
            });
        }
    };
    let install_transaction = match context
        .state
        .reserve_install_transaction(context.topology.generation())
    {
        Ok(transaction) => transaction,
        Err(error) => {
            let failed = close_received_reverse(system, received, received.len())
                | system.close_handle(group).is_err()
                | jobs.jobs.abort_launch(ticket).is_err();
            return Err(if failed { InitError::Cleanup } else { error });
        }
    };
    let registry_grant = match context.topology.issue(
        request.requested_child_generation,
        EndpointKind::RegistryClient,
    ) {
        Ok(grant) => grant,
        Err(error) => {
            let failed = close_received_reverse(system, received, received.len())
                | system.close_handle(group).is_err()
                | jobs.jobs.abort_launch(ticket).is_err();
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Jobs(error)
            });
        }
    };
    let (registry_server, registry_client) = match create_controller_channel_pair(system) {
        Ok(pair) => pair,
        Err(error) => {
            let failed = close_received_reverse(system, received, received.len())
                | system.close_handle(group).is_err()
                | jobs.jobs.abort_launch(ticket).is_err();
            return Err(if failed { InitError::Cleanup } else { error });
        }
    };
    if let Err(error) = install_wyrmsh_registry_client(
        system,
        context.registry_control,
        registry_grant,
        registry_server,
        install_transaction,
    ) {
        let failed = close_received_reverse(system, received, received.len())
            | system.close_handle(registry_server).is_err()
            | system.close_handle(registry_client).is_err()
            | system.close_handle(group).is_err()
            | jobs.jobs.abort_launch(ticket).is_err();
        return Err(if failed { InitError::Cleanup } else { error });
    }
    let fail_after_install = |system: &mut S,
                              jobs: &mut JobDispatcher,
                              context: &mut ShellLaunchContext<'_>,
                              original: InitError,
                              close_client: bool|
     -> InitError {
        context.state.poison(registry_grant.registry_generation);
        let failed = close_received_reverse(system, received, received.len())
            | (close_client && system.close_handle(registry_client).is_err())
            | system.close_handle(group).is_err()
            | jobs.jobs.abort_launch(ticket).is_err();
        if failed { InitError::Cleanup } else { original }
    };
    if let Err(error) = preflight_wyrmsh_registry(system, registry_client, registry_grant, None) {
        return Err(fail_after_install(system, jobs, context, error, true));
    }
    let shell_grant = match context.topology.issue(
        request.requested_child_generation,
        EndpointKind::LaunchSession,
    ) {
        Ok(grant) => grant,
        Err(error) => {
            return Err(fail_after_install(
                system,
                jobs,
                context,
                InitError::Jobs(error),
                true,
            ));
        }
    };
    let (shell_controller, shell_child) = match create_controller_channel_pair(system) {
        Ok(pair) => pair,
        Err(error) => {
            return Err(fail_after_install(system, jobs, context, error, true));
        }
    };
    if let Err(error) = jobs.install_scoped_session(
        shell_grant,
        shell_controller,
        crate::job_sessions::LaunchSessionScope::ShellJobs,
    ) {
        let failed = system.close_handle(shell_controller).is_err()
            | system.close_handle(shell_child).is_err();
        return Err(fail_after_install(
            system,
            jobs,
            context,
            if failed {
                InitError::Cleanup
            } else {
                InitError::Jobs(error)
            },
            true,
        ));
    }
    let loaded = match load_wyrmsh_process(
        loader,
        LoadAuthority {
            task_group: group,
            ..authority
        },
        WyrmshLoadRequest {
            image,
            stdin: received[0].handle,
            stdout: received[1].handle,
            stderr: received[2].handle,
            console_status: received[3].handle,
            registry_client,
            launch_session: shell_child,
            registry_generation: registry_grant.registry_generation,
            registry_endpoint_id: registry_grant.endpoint_id,
            registry_endpoint_generation: registry_grant.endpoint_generation,
            launch_connection_id: shell_grant.endpoint_id,
            launch_connection_generation: shell_grant.endpoint_generation,
            console_generation: request.console_generation,
            status_generation: request.status_generation,
            child_generation: request.requested_child_generation,
            outer_launch_transaction: reservation.transaction_id,
            transaction_id: install_transaction,
        },
    ) {
        Ok(loaded) => loaded,
        Err(failure) => {
            let disconnected = jobs.disconnect_session(shell_grant);
            let mut failed =
                disconnected.map_or(true, |channel| system.close_handle(channel).is_err());
            if !failure.stdin_consumed {
                failed |= close_received_reverse(system, received, received.len());
                failed |= system.close_handle(registry_client).is_err();
                failed |= system.close_handle(shell_child).is_err();
            }
            failed |= system.close_handle(group).is_err();
            failed |= jobs.jobs.abort_launch(ticket).is_err();
            context.state.poison(registry_grant.registry_generation);
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Loader(failure.error)
            });
        }
    };
    if let Err(error) =
        jobs.jobs
            .stage_launch(ticket, loaded.process.0, group.0, loaded.launch_channel.0)
    {
        let failed = cleanup_loaded(system, waits, loaded, group, true).is_err()
            | jobs
                .disconnect_session(shell_grant)
                .map_or(true, |channel| system.close_handle(channel).is_err())
            | jobs.jobs.abort_launch(ticket).is_err();
        context.state.poison(registry_grant.registry_generation);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Jobs(error)
        });
    }
    let loaded_job = crate::jobs::LoadedJob {
        job_id: ticket.job_id(),
        loaded,
        task_group: group.0,
    };
    if let Err(error) = jobs.attach_outer_job(shell_grant, loaded_job.job_id) {
        let failed = force_cleanup_job(system, waits, jobs, loaded_job).is_err()
            | jobs
                .disconnect_session(shell_grant)
                .map_or(true, |channel| system.close_handle(channel).is_err());
        context.state.poison(registry_grant.registry_generation);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Jobs(error)
        });
    }
    let ready_deadline = match report_deadline(system) {
        Ok(deadline) => deadline,
        Err(error) => {
            let failed = cleanup_shell_before_publication(system, waits, jobs, loaded_job).is_err();
            context.state.poison(registry_grant.registry_generation);
            return Err(if failed { InitError::Cleanup } else { error });
        }
    };
    let exact_ready = await_child_ready_profile_observed(
        waits,
        loaded.process,
        loaded.launch_channel,
        LaunchProfile::Wyrmsh,
        install_transaction,
        ready_deadline,
    )
    .is_ok();
    let running = waits
        .query_task_termination(loaded.process)
        .is_ok_and(|info| info.state == deepwyrm_syscall::DW_TASK_STATE_RUNNING);
    if !exact_ready || !running {
        let failed = cleanup_shell_before_publication(system, waits, jobs, loaded_job).is_err();
        context.state.poison(registry_grant.registry_generation);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Supervision
        });
    }
    if let Err(error) =
        jobs.jobs
            .commit_launch(ticket, loaded.process.0, group.0, loaded.launch_channel.0)
    {
        let failed = cleanup_shell_before_publication(system, waits, jobs, loaded_job).is_err();
        context.state.poison(registry_grant.registry_generation);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Jobs(error)
        });
    }
    Ok(AcceptedShell {
        loaded: loaded_job,
        request,
        registry_grant,
        shell_grant,
    })
}

pub(crate) fn send_versioned_job_error<S: InitPlatform>(
    system: &mut S,
    session: DwHandle,
    reservation: LaunchReservation,
    version: JobWireVersion,
    code: LaunchErrorCode,
) -> Result<(), InitError> {
    match version {
        JobWireVersion::Legacy => send_job_error(system, session, reservation, code),
        JobWireVersion::ShellV1 => send_shell_v1_error(system, session, reservation, code),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_one_job_request<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: Option<&PolicyView<'_>>,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    grant: EndpointGrant,
) -> Result<JobDispatchOutcome, InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    dispatch_one_job_request_inner(
        system, loader, waits, authority, policy, jobs, session, grant, None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_one_job_request_with_shell<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: Option<&PolicyView<'_>>,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    grant: EndpointGrant,
    shell: &mut ShellLaunchContext<'_>,
) -> Result<JobDispatchOutcome, InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    dispatch_one_job_request_inner(
        system,
        loader,
        waits,
        authority,
        policy,
        jobs,
        session,
        grant,
        Some(shell),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_one_job_request_inner<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: Option<&PolicyView<'_>>,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    grant: EndpointGrant,
    mut shell: Option<&mut ShellLaunchContext<'_>>,
) -> Result<JobDispatchOutcome, InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let scope = jobs.session_scope(grant).map_err(InitError::Jobs)?;
    let legacy_handle_limit = wyrmroot_launch_proto::STREAM_COUNT;
    let mut bytes = [0_u8; wyrmroot_launch_proto::MAX_LAUNCH_MESSAGE_BYTES];
    let mut received =
        [DwReceivedHandleInfoV1::default(); wyrmroot_launch_proto::SHELL_V1_HANDLE_COUNT];
    let counts = system
        .receive_channel(session, &mut bytes, &mut received)
        .map_err(InitError::Native)?;
    if counts.bytes > bytes.len() || counts.handles > received.len() {
        let failed = close_received_reverse(system, &received, counts.handles);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Jobs(JobError::StreamPolicy)
        });
    }
    let (version, reservation) = match parse_reservation_prefix(&bytes[..counts.bytes]) {
        Ok(reservation) => (JobWireVersion::Legacy, reservation),
        Err(_) => match parse_shell_v1_reservation_prefix(&bytes[..counts.bytes]) {
            Ok(reservation) => (JobWireVersion::ShellV1, reservation),
            Err(_) => {
                let failed = close_received_reverse(system, &received, counts.handles);
                return Err(if failed {
                    InitError::Cleanup
                } else if counts.handles > legacy_handle_limit {
                    InitError::Jobs(JobError::StreamPolicy)
                } else {
                    InitError::Jobs(JobError::WrongState)
                });
            }
        },
    };
    if version == JobWireVersion::Legacy && counts.handles > legacy_handle_limit {
        let failed = close_received_reverse(system, &received, counts.handles);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Jobs(JobError::StreamPolicy)
        });
    }
    if reservation.connection_id != grant.endpoint_id
        || reservation.generation != grant.endpoint_generation
    {
        let failed = close_received_reverse(system, &received, counts.handles);
        if failed {
            return Err(InitError::Cleanup);
        }
        send_versioned_job_error(
            system,
            session,
            reservation,
            version,
            LaunchErrorCode::StaleOrUnknownSession,
        )?;
        return Ok(JobDispatchOutcome::Responded);
    }
    let request_ticket = match jobs.jobs.reserve_request(reservation) {
        Ok(ticket) => ticket,
        Err(error) => {
            let failed = close_received_reverse(system, &received, counts.handles);
            if failed {
                return Err(InitError::Cleanup);
            }
            send_versioned_job_error(system, session, reservation, version, job_error_code(error))?;
            return Ok(JobDispatchOutcome::Responded);
        }
    };
    if version == JobWireVersion::ShellV1 {
        let parsed_shell = match parse_shell_v1_request(&bytes[..counts.bytes], counts.handles) {
            Ok(parsed) => parsed,
            Err(_) => {
                let failed = close_received_reverse(system, &received, counts.handles);
                if failed {
                    return Err(InitError::Cleanup);
                }
                send_shell_v1_error(
                    system,
                    session,
                    reservation,
                    LaunchErrorCode::MalformedRequest,
                )?;
                return Ok(JobDispatchOutcome::Responded);
            }
        };
        if !scope.admits_shell_v1() {
            if close_received_reverse(system, &received, counts.handles) {
                return Err(InitError::Cleanup);
            }
            send_shell_v1_error(
                system,
                session,
                reservation,
                LaunchErrorCode::PolicyRejected,
            )?;
            return Ok(JobDispatchOutcome::Responded);
        }
        for info in &received[..counts.handles] {
            if let Err(error) = validate_controller_channel(system, info.handle) {
                if close_received_reverse(system, &received, counts.handles) {
                    return Err(InitError::Cleanup);
                }
                send_shell_v1_error(system, session, reservation, launch_error_code(&error))?;
                return Ok(JobDispatchOutcome::Responded);
            }
        }
        let (Some(policy), Some(shell)) = (policy, shell.as_deref_mut()) else {
            if close_received_reverse(system, &received, counts.handles) {
                return Err(InitError::Cleanup);
            }
            send_shell_v1_error(system, session, reservation, LaunchErrorCode::LoaderFailure)?;
            return Ok(JobDispatchOutcome::Responded);
        };
        let accepted = match accept_reserved_shell(
            system,
            loader,
            waits,
            authority,
            policy,
            jobs,
            reservation,
            request_ticket,
            parsed_shell.request,
            &received[..counts.handles],
            shell,
        ) {
            Ok(accepted) => accepted,
            Err(error) => {
                let response = send_shell_v1_error(
                    system,
                    session,
                    reservation,
                    shell_launch_error_code(&error),
                );
                return if error == InitError::Cleanup {
                    Err(error)
                } else {
                    response?;
                    Ok(JobDispatchOutcome::Responded)
                };
            }
        };
        let loaded = accepted.loaded;
        let release = jobs
            .jobs
            .release_launch_channel(loaded.job_id, loaded.loaded.launch_channel.0)
            .map_err(InitError::Jobs)?;
        let mut response = [0_u8; wyrmroot_launch_proto::SHELL_V1_REPLY_BYTES];
        let response_size = encode_shell_v1_accepted(reservation, loaded.job_id, &mut response)
            .map_err(|_| InitError::Accounting)?;
        if let Err(error) = system.send_channel(session, &response[..response_size]) {
            jobs.jobs.restore_launch_channel(release);
            shell.state.poison(shell.topology.generation());
            return Err(
                if cleanup_shell_before_publication(system, waits, jobs, loaded).is_err() {
                    InitError::Cleanup
                } else {
                    InitError::Native(error)
                },
            );
        }
        if system.close_handle(loaded.loaded.launch_channel).is_err() {
            jobs.jobs.restore_launch_channel(release);
            jobs.jobs
                .record_cleanup_bits(loaded.job_id, 1 << 2)
                .map_err(InitError::Jobs)?;
            shell.state.poison(shell.topology.generation());
            let _ = cleanup_shell_before_publication(system, waits, jobs, loaded);
            return Err(InitError::Cleanup);
        }
        return Ok(JobDispatchOutcome::Launched(
            jobs.jobs
                .loaded_job(loaded.job_id)
                .map_err(InitError::Jobs)?,
        ));
    }
    let parsed = match parse_launch_message(&bytes[..counts.bytes], counts.handles) {
        Ok(parsed) => parsed,
        Err(_) => {
            let failed = close_received_reverse(system, &received, counts.handles);
            if failed {
                return Err(InitError::Cleanup);
            }
            send_job_error(
                system,
                session,
                reservation,
                LaunchErrorCode::MalformedRequest,
            )?;
            return Ok(JobDispatchOutcome::Responded);
        }
    };
    match parsed.message {
        LaunchMessage::Launch(request) => {
            if !scope.admits_legacy_launch(request.path) {
                if close_received_reverse(system, &received, counts.handles) {
                    return Err(InitError::Cleanup);
                }
                send_observed_job_error(
                    system,
                    session,
                    reservation,
                    LaunchErrorCode::PolicyRejected,
                )?;
                return Ok(JobDispatchOutcome::Responded);
            }
            let Some(policy) = policy else {
                if close_received_reverse(system, &received, counts.handles) {
                    return Err(InitError::Cleanup);
                }
                send_observed_job_error(
                    system,
                    session,
                    reservation,
                    LaunchErrorCode::PolicyRejected,
                )?;
                return Ok(JobDispatchOutcome::Responded);
            };
            defer_reserved_launch(
                system,
                loader,
                waits,
                authority,
                policy,
                jobs,
                session,
                grant,
                scope,
                reservation,
                request_ticket,
                request,
                &received[..legacy_handle_limit],
                counts.handles,
            )
        }
        message => {
            if close_received_reverse(system, &received, counts.handles) {
                return Err(InitError::Cleanup);
            }
            dispatch_reserved_operation_observed(
                system,
                waits,
                jobs,
                session,
                grant,
                reservation,
                request_ticket,
                message,
                &bytes[..counts.bytes],
                scope,
                shell.map(|context| &mut *context.state),
            )?;
            Ok(JobDispatchOutcome::Responded)
        }
    }
}

#[cfg(test)]
#[path = "../../consoled/src/stream_transfer.rs"]
mod consoled_stream_transfer;

#[cfg(test)]
mod tests;

mod deferred_launch;
mod job_poll;
pub(crate) use deferred_launch::*;
pub(crate) use job_poll::*;
