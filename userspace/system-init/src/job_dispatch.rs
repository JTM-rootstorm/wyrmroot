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
    let ticket = match jobs.jobs.begin_reserved_launch(request_ticket) {
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

/// Rolls back the launch a departing session left parked, if it left one.
///
/// Reset card R6C's cancel edge. A session that peer-closes, or that is
/// disconnected by the tick's emergency cleanup, may have a transaction still
/// sitting at `AwaitingReady`: its child is constructed and unpublished, and the
/// only names for that child's Process, launch Channel and TaskGroup are in the
/// arena slot. Disconnecting the session without this would close the Channel
/// the slot recorded and leave the child to be collected at its deadline --
/// bounded, but by then the reply would be attempted on a closed handle and the
/// resources would have sat for the whole budget.
///
/// Nothing is sent. The peer that would have received `LAUNCH_ACCEPTED` or
/// `ERROR` is exactly the peer that has gone.
pub(crate) fn cancel_parked_launch<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    grant: EndpointGrant,
) -> Result<(), InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let Some(token) = jobs.launches.session_transaction(grant) else {
        return Ok(());
    };
    if jobs
        .launches
        .stage(token)
        .map_err(launch_transaction_error)?
        != LaunchStage::AwaitingReady
    {
        // Every other open stage is reached and left inside one call. A
        // transaction found in one here would mean a launch was parked at a
        // stage nothing polls, which is an accounting fault rather than a
        // cancel.
        return Err(InitError::Accounting);
    }
    let reservation = jobs
        .launches
        .response_envelope(token)
        .map_err(launch_transaction_error)?
        .1;
    let job_id = jobs
        .launches
        .job_id(token)
        .map_err(launch_transaction_error)?;
    let profile = jobs
        .launches
        .profile(token)
        .map_err(launch_transaction_error)?
        .ok_or(InitError::Accounting)?;
    let prepared = jobs
        .jobs
        .staged_job(
            grant.endpoint_id,
            grant.endpoint_generation,
            job_id,
            reservation.transaction_id,
            profile,
        )
        .map_err(InitError::Jobs)?;
    jobs.launches
        .take_resources(token)
        .map_err(launch_transaction_error)?;
    let cleanup_failed = rollback_prepared_job(system, waits, jobs, prepared).is_err();
    close_deferred_launch(jobs, token, false)?;
    if cleanup_failed {
        return Err(InitError::Cleanup);
    }
    Ok(())
}

/// Whether a parked launch has anything to say yet.
///
/// Reset card R6C. `finish_deferred_launch` ends in `observe_prepared_ready`,
/// which waits on the child's launch Channel and Process until one of them
/// signals or the READY deadline expires. R6B-2 moved that wait to a tick of
/// its own; it did not stop it being a wait, so a child that never answers
/// still held the tick that went to finish it.
///
/// This is the gate. It polls the same two handles the observation will wait
/// on, with an already-passed deadline, so it cannot block:
///
/// - something signalled that the observation can act on without waiting again
///   -- a READY message, or the child's exit -- so the launch is finished now;
/// - nothing signalled and the budget is spent, so the launch is failed here
///   without observing at all. Handing the spent deadline back to
///   `observe_prepared_ready` and letting its own `wait_many` time out would
///   reach the same disposition in production, but by way of a second clock --
///   the one the wait sees rather than the one the loop measured against. One
///   clock decides, and it is this one;
/// - nothing signalled and there is budget left, so the launch stays parked and
///   the tick goes on to the sessions.
///
/// READY is checked before expiry deliberately. A child that signalled in the
/// same instant its deadline passed is published, exactly as the one-frame
/// `wait_many` would have published it -- the deadline bounds how long the
/// supervisor waits, not how late an answer may be.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ParkedLaunch {
    /// Silent, with budget left. Stays parked.
    Waiting,
    /// Its Channel or its Process said something. Finish it.
    Signalled,
    /// Silent, and out of budget. Fail it.
    Expired,
}

pub(crate) fn parked_launch_disposition<S: ResidentPlatform>(
    system: &mut S,
    jobs: &JobDispatcher,
    token: LaunchToken,
    now_ns: u64,
) -> Result<ParkedLaunch, InitError> {
    let resources = jobs
        .launches
        .resources(token)
        .map_err(launch_transaction_error)?
        .ok_or(InitError::Accounting)?;
    let deadline = jobs
        .launches
        .ready_deadline(token)
        .map_err(launch_transaction_error)?
        .ok_or(InitError::Accounting)?;
    // R6D. `PEER_CLOSED` is deliberately not asked for, and this is the whole
    // reason the gate is a signal set rather than "did anything happen".
    //
    // `await_child_ready_profile_observed` branches on what its own wait
    // selects. `READABLE` is the READY message, which it receives and parses;
    // `EXITED` is the early-exit record, which it queries and returns. Both
    // finish without waiting again. But a launch Channel that is `PEER_CLOSED`
    // and *not* `READABLE` sends it into a second `wait_many` for the Process's
    // `EXITED`, and that one is bounded only by the launch's own deadline. A
    // child that dropped its end of the Channel and then declined to die would
    // hold the tick for the whole budget -- one failing child blocking every
    // other launch client, which is exactly what R6D has to refute.
    //
    // So a peer-closed-but-silent child is left parked. Its Channel stays
    // closed, so the condition is level-triggered and every later tick sees it
    // again; it leaves through `Expired` when the budget runs out, by the same
    // door as a child that said nothing at all. What is lost is the terminal
    // record `PeerClosedBeforeReady` would have carried, and only when the
    // Process outlives its Channel by the whole budget.
    let items = [
        DwWaitItemV1 {
            handle: resources.launch_channel,
            signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0),
        },
        DwWaitItemV1 {
            handle: resources.process,
            signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_EXITED.0),
        },
    ];
    match system.wait_many(&items, DwDeadline(now_ns)) {
        Ok(_) => Ok(ParkedLaunch::Signalled),
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {
            if now_ns >= deadline.0 {
                Ok(ParkedLaunch::Expired)
            } else {
                Ok(ParkedLaunch::Waiting)
            }
        }
        Err(error) => Err(InitError::Native(error)),
    }
}

/// Runs the half of a launch that was left parked, on a tick of its own.
///
/// Reset card R6B-2. This is `finish_constructed_launch` with its inputs read
/// back out of the arena instead of off the frame that constructed them, and
/// with the evidence record finished from the digests taken then. The sequence
/// inside `finish_constructed_launch` is untouched, including every rollback.
///
/// The prepared job is not stored; it is asked for. `JobController::staged_job`
/// rebuilds it from the model's own record of the job, which is why a slot can
/// be resolved a tick later without the arena holding a `LaunchTicket` that
/// names a job-table position the model may have reused. The handles the model
/// hands back are checked against the ones the arena recorded, because two
/// records of the same child disagreeing is exactly the state neither of them
/// could detect alone.
pub(crate) fn finish_deferred_launch<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    token: LaunchToken,
    mut shell: Option<&mut ShellLaunchContext<'_>>,
    disposition: ParkedLaunch,
) -> Result<(), InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    // A build with no evidence surface and no recovery trigger has nothing to
    // ask the shell context for; it still takes one, because the caller is the
    // same poll loop in every build.
    let _ = &mut shell;
    let (session, reservation) = jobs
        .launches
        .response_envelope(token)
        .map_err(launch_transaction_error)?;
    let grant = jobs
        .launches
        .grant(token)
        .map_err(launch_transaction_error)?;
    let job_id = jobs
        .launches
        .job_id(token)
        .map_err(launch_transaction_error)?;
    let deadline = jobs
        .launches
        .ready_deadline(token)
        .map_err(launch_transaction_error)?
        .ok_or(InitError::Accounting)?;
    let profile = jobs
        .launches
        .profile(token)
        .map_err(launch_transaction_error)?
        .ok_or(InitError::Accounting)?;
    let recorded = jobs
        .launches
        .resources(token)
        .map_err(launch_transaction_error)?
        .ok_or(InitError::Accounting)?;
    let prepared = jobs
        .jobs
        .staged_job(
            grant.endpoint_id,
            grant.endpoint_generation,
            job_id,
            reservation.transaction_id,
            profile,
        )
        .map_err(InitError::Jobs)?;
    if prepared.loaded.process != recorded.process
        || prepared.loaded.launch_channel != recorded.launch_channel
        || prepared.task_group != recorded.task_group.0
    {
        return Err(InitError::Accounting);
    }
    // The transaction stops owning the handles here. Whichever way the rest of
    // this goes -- published, or rolled back -- they are accounted for by the
    // model or closed by the rollback, and a slot that still claimed them could
    // not be closed at all.
    jobs.launches
        .take_resources(token)
        .map_err(launch_transaction_error)?;
    let constructed = ConstructedLaunch {
        prepared,
        deadline,
        session,
        reservation,
    };
    let outcome = match disposition {
        ParkedLaunch::Signalled => finish_constructed_launch(system, waits, jobs, constructed),
        // Out of budget, and nothing to observe. This is the disposition the
        // one-frame path reached when its `wait_many` hit the deadline, and the
        // rollback is the same one: the child is not published, and whether the
        // teardown itself failed is what decides between `Cleanup` and
        // `Supervision`.
        ParkedLaunch::Waiting | ParkedLaunch::Expired => Err(
            if rollback_prepared_job(system, waits, jobs, constructed.prepared).is_err() {
                InitError::Cleanup
            } else {
                InitError::Supervision
            },
        ),
    };
    let published = match outcome {
        Ok(_) => Ok(()),
        Err(error) => {
            // Best-effort, and deliberately not `?`. The reply is owed to a
            // session that may already be gone -- peer close, or an emergency
            // disconnect elsewhere in the tick, closes the Channel this slot
            // recorded, and sending on a closed handle fails. What is *not*
            // best-effort is emptying the slot below: a transaction left open
            // here would be handed back by `awaiting_ready_from` on every
            // subsequent tick, for ever, holding a child nothing else can name.
            let reply =
                send_deferred_launch_error(system, session, reservation, launch_error_code(&error));
            Err(match reply {
                Ok(()) => error,
                // A failed reply does not relabel the launch's own failure, for
                // the same reason `LaunchTransactions::fail` keeps the first
                // disposition: the caller asked why the launch failed, not what
                // went wrong telling it.
                Err(InitError::Cleanup) => InitError::Cleanup,
                Err(_) => error,
            })
        }
    };
    close_deferred_launch(jobs, token, published.is_ok())?;
    // One launch failing is not the tick failing. The one-frame path answered a
    // failed launch with an `ERROR` reply and returned `Responded`, and only a
    // failed *cleanup* escalated -- because a cleanup that did not happen means
    // resources nobody can name, while a child that missed READY has already
    // been rolled back by the time we get here. R6C keeps that split: a launch
    // that never answers must not take down the supervisor, which is most of
    // what R6D has to prove.
    match published {
        Ok(()) => Ok(()),
        Err(InitError::Cleanup) => Err(InitError::Cleanup),
        Err(_) => Ok(()),
    }
}

/// Walks the parked transaction out of the arena by the same door every
/// transaction leaves by: a disposition, then `Cleanup`, then `Complete`.
pub(crate) fn close_deferred_launch(
    jobs: &mut JobDispatcher,
    token: LaunchToken,
    published: bool,
) -> Result<(), InitError> {
    let disposition = if published {
        LaunchStage::Published
    } else {
        LaunchStage::Failing
    };
    jobs.launches
        .advance(token, disposition)
        .map_err(launch_transaction_error)?;
    jobs.launches
        .advance(token, LaunchStage::Cleanup)
        .map_err(launch_transaction_error)?;
    jobs.launches
        .advance(token, LaunchStage::Complete)
        .map_err(launch_transaction_error)?;
    jobs.launches
        .close(token)
        .map(|_| ())
        .map_err(launch_transaction_error)
}

/// Sends the error reply a deferred launch owes its session, and records it.
pub(crate) fn send_deferred_launch_error<S: ResidentPlatform>(
    system: &mut S,
    session: DwHandle,
    reservation: LaunchReservation,
    code: LaunchErrorCode,
) -> Result<(), InitError> {
    let mut response = [0_u8; 88];
    let size =
        encode_launch_error(reservation, code, &mut response).map_err(|_| InitError::Accounting)?;
    system
        .send_channel(session, &response[..size])
        .map_err(InitError::Native)?;
    Ok(())
}

/// E3C adapter for the selected console controller. The caller supplies the
/// current registry generation and poison state; request bytes cannot select
/// either authority.
#[allow(clippy::too_many_arguments)]
pub(crate) fn poll_job_dispatcher_with_shell<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    jobs: &mut JobDispatcher,
    now_ns: u64,
    shell: &mut ShellLaunchContext<'_>,
) -> Result<JobDispatcherPollOutcome, InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    poll_job_dispatcher_inner(system, loader, waits, authority, jobs, now_ns, Some(shell))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn poll_job_dispatcher_inner<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    jobs: &mut JobDispatcher,
    now_ns: u64,
    mut shell: Option<&mut ShellLaunchContext<'_>>,
) -> Result<JobDispatcherPollOutcome, InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut outcome = JobDispatcherPollOutcome::Stable;
    // Reset cards R6B-2 and R6C. A launch parked by a previous tick is looked at
    // before any new request is read -- the child is already alive and its READY
    // deadline is already running, so it has the older claim -- but it is only
    // *finished* if its own handles say something has happened, or if its budget
    // has run out. R6B-2 moved the blocking observation off the frame that read
    // the request; R6C is what stops it blocking the tick as well.
    //
    // The tick does not end here either way. A parked child that is still
    // silent costs one non-blocking poll of two handles, and the session poll
    // below runs regardless, which is the property R6D has to prove: a child
    // that never answers cannot take a session's turn.
    //
    // The cursor moves past the slot it looked at, so a silent child cannot
    // starve the one behind it.
    if let Some(token) = jobs.launches.awaiting_ready_from(jobs.launch_cursor) {
        jobs.launch_cursor = token.slot().wrapping_add(1);
        match parked_launch_disposition(system, jobs, token, now_ns)? {
            ParkedLaunch::Waiting => {}
            disposition => finish_deferred_launch(
                system,
                waits,
                jobs,
                token,
                shell.as_deref_mut(),
                disposition,
            )?,
        }
    }
    if let Some((grant, session)) = jobs.next_session() {
        let item = DwWaitItemV1 {
            handle: session,
            signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        };
        match system.wait_many(core::slice::from_ref(&item), DwDeadline(now_ns)) {
            Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {}
            Err(error) => return Err(InitError::Native(error)),
            Ok(observed) if observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 => {
                // Read before the dispatch, which may disconnect the session.
                let scope = jobs.session_scope(grant).map_err(InitError::Jobs)?;
                let size = system
                    .query_memory_object_size(authority.bootfs)
                    .map_err(InitError::Native)?;
                let plan = MappingPlan::for_bootfs(size).map_err(InitError::Mapping)?;
                let dispatched = system
                    .with_bootfs_bytes(
                        authority.parent_root,
                        authority.bootfs,
                        plan,
                        |system, bootfs| {
                            let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
                            let manifest = archive
                                .lookup(MANIFEST_PATH.as_bytes())
                                .map_err(map_lookup)?;
                            let boot_generation: [u8; 32] = manifest
                                .data()
                                .get(48..80)
                                .ok_or(InitError::Accounting)?
                                .try_into()
                                .map_err(|_| InitError::Accounting)?;
                            let policy = PolicyView::from_bootfs(archive, boot_generation)
                                .map_err(InitError::Jobs)?;
                            if let Some(shell) = shell.as_deref_mut() {
                                dispatch_one_job_request_with_shell(
                                    system,
                                    loader,
                                    waits,
                                    authority,
                                    Some(&policy),
                                    jobs,
                                    session,
                                    grant,
                                    shell,
                                )
                            } else {
                                dispatch_one_job_request(
                                    system,
                                    loader,
                                    waits,
                                    authority,
                                    Some(&policy),
                                    jobs,
                                    session,
                                    grant,
                                )
                            }
                        },
                    )
                    .map_err(InitError::Native)?;
                if let Err(dispatch_error) = dispatched {
                    // R6C. Whatever this session had in flight goes with it.
                    let cancel_failed = cancel_parked_launch(system, waits, jobs, grant).is_err();
                    // Both arms ran the same emergency cleanup; only one said
                    // which half of it failed. The other collapsed to a bare
                    // `Cleanup`, losing the initiating error entirely -- the
                    // collapse `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` 3.2 says
                    // owes an instance. One arm now, and the reported kind is
                    // unchanged: a failed cleanup still reports kind 04.
                    let disconnected = jobs.disconnect_owned_session(grant);
                    let emergency_cleanup = match disconnected {
                        Ok(session) => {
                            let channel_close_failed =
                                system.close_handle(session.channel).is_err();
                            let owner_cleanup_failed =
                                cleanup_session_owner(system, waits, session.owner, true);
                            EmergencyCleanup::Attempted {
                                channel_close_failed,
                                owner_cleanup_failed,
                            }
                        }
                        Err(_) => EmergencyCleanup::DisconnectFailed,
                    };
                    let emergency_cleanup = match emergency_cleanup {
                        EmergencyCleanup::Attempted {
                            channel_close_failed,
                            owner_cleanup_failed,
                        } => EmergencyCleanup::Attempted {
                            channel_close_failed,
                            owner_cleanup_failed: owner_cleanup_failed | cancel_failed,
                        },
                        other => other,
                    };
                    // F3A.7j. Named by the session's scope, so a failed
                    // request says whose it was; `attribute_failure` keeps
                    // an operation the error already carries.
                    let operation = match scope {
                        LaunchSessionScope::ConsoleLauncher => {
                            RecoveryOperation::DispatchConsoleJob
                        }
                        LaunchSessionScope::ShellJobs => RecoveryOperation::DispatchShellJob,
                    };
                    let attributed =
                        attribute_failure(operation, Err::<(), _>(dispatch_error)).unwrap_err();
                    return Err(dispatch_failure(attributed, emergency_cleanup));
                }
            }
            Ok(observed) if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 => {
                let scope = jobs.session_scope(grant).map_err(InitError::Jobs)?;
                let defer_console_retirement = false;
                // When recovery owns this session and its process as one
                // coordinated retirement, observe peer close without consuming
                // either owner ahead of that join.
                if !defer_console_retirement {
                    // R6C's cancel. The peer that asked for this launch is gone
                    // before it was told the child exists, so nothing owns the
                    // child and nothing is owed a reply. Rolling it back here
                    // rather than leaving it to its deadline means the session's
                    // resources and its child's go in one step -- and means the
                    // slot is not still holding a Channel this branch is about
                    // to close.
                    cancel_parked_launch(system, waits, jobs, grant)?;
                    let outer = if scope == crate::job_sessions::LaunchSessionScope::ConsoleLauncher
                    {
                        jobs.jobs
                            .loaded_job_for_owner(grant.endpoint_id, grant.endpoint_generation)
                            .map_err(InitError::Jobs)?
                    } else {
                        None
                    };
                    let disconnected = jobs
                        .disconnect_owned_session(grant)
                        .map_err(InitError::Jobs)?;
                    let mut failed = system.close_handle(disconnected.channel).is_err()
                        | cleanup_session_owner(system, waits, disconnected.owner, true)
                        | disconnected.outer_job.is_some_and(|job_id| {
                            let loaded = jobs.jobs.loaded_job(job_id);
                            loaded.map_or(true, |loaded| {
                                force_cleanup_job(system, waits, jobs, loaded).is_err()
                            })
                        });
                    if let Some(outer) = outer {
                        failed |=
                            cleanup_shell_before_publication(system, waits, jobs, outer).is_err();
                    }
                    if failed {
                        return Err(InitError::Cleanup);
                    }
                    outcome = JobDispatcherPollOutcome::SessionClosed { grant, scope };
                }
            }
            Ok(_) => return Err(InitError::Supervision),
        }
    }
    if let Some(loaded) = jobs.next_cleanup_job() {
        let terminal_staged = jobs
            .jobs
            .terminal_result(loaded.job_id)
            .map_err(InitError::Jobs)?
            .is_some();
        let exited = if terminal_staged {
            true
        } else if loaded.loaded.process.0 == 0 {
            return Err(InitError::Accounting);
        } else {
            match waits.query_task_termination(loaded.loaded.process) {
                Ok(info) => info.state == DW_TASK_STATE_EXITED,
                Err(_) => {
                    jobs.jobs
                        .record_cleanup_bits(loaded.job_id, 1 << 1)
                        .map_err(InitError::Jobs)?;
                    return Err(InitError::Cleanup);
                }
            }
        };
        if exited {
            let result = reap_job(system, waits, jobs, loaded)?;
            let nested = close_shell_session_for_job(system, jobs, loaded.job_id);
            if result.cleanup_result != 0 || nested.is_err() {
                return Err(InitError::Cleanup);
            }
        }
    }
    if let Some(shell) = shell {
        service_pending_wait_inner(system, waits, jobs, Some(&mut *shell.state))?;
    } else {
        service_pending_wait(system, waits, jobs)?;
    }
    Ok(outcome)
}

/// Latches a console child's session shutdown, at either WAIT reply.
///
/// F3A.7g. Both replies encode the same terminal result and both are reached
/// for the same child, so the fact is read once, here, rather than at two
/// sites that could drift apart.
///
/// The scope is what makes this specific. A `ConsoleLauncher` session belongs
/// to `consoled`, which launches exactly one child -- its shell -- so any
/// terminal result crossing it is that shell's. A `ShellJobs` session belongs
/// to the shell itself, and the jobs *it* launches are ordinary user programs
/// whose exit codes it prints; one of those happening to exit with the same
/// value must not end the session.
pub(crate) fn observe_session_shutdown_result(
    scope: LaunchSessionScope,
    state: Option<&mut ShellControllerState>,
    terminal: wyrmroot_launch_proto::TerminationResult,
) {
    if scope != LaunchSessionScope::ConsoleLauncher
        || terminal.classification != wyrmroot_launch_proto::TerminationClassification::NormalExit
        || terminal.application_code != wyrmroot_launch_proto::SHELL_SESSION_SHUTDOWN_STATUS
    {
        return;
    }
    if let Some(state) = state {
        state.observe_session_shutdown();
    }
}

pub(crate) fn service_pending_wait<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
) -> Result<(), InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    service_pending_wait_inner(system, waits, jobs, None)
}

#[allow(unused_mut)]
pub(crate) fn service_pending_wait_inner<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    mut evidence: Option<&mut ShellControllerState>,
) -> Result<(), InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let Some(pending) = jobs.next_pending_wait() else {
        return Ok(());
    };
    let scope = jobs.session_scope(pending.grant).map_err(InitError::Jobs)?;
    let result = match jobs.jobs.result_for_owner(
        pending.reservation.connection_id,
        pending.reservation.generation,
        pending.job_id,
    ) {
        Ok(result) => result,
        Err(JobError::UnknownJob) => return Ok(()),
        Err(error) => return Err(InitError::Jobs(error)),
    };
    let session = jobs
        .session_handle(pending.grant)
        .map_err(InitError::Jobs)?;
    let terminal = controller_result_to_wire(result)?;
    observe_session_shutdown_result(scope, evidence, terminal);
    let mut response = [0_u8; 88];
    let size = encode_job_result(pending.reservation, pending.job_id, terminal, &mut response)
        .map_err(|_| InitError::Accounting)?;
    if let Err(error) = system.send_channel(session, &response[..size]) {
        jobs.finish_pending_wait(pending).map_err(InitError::Jobs)?;
        let disconnected = jobs
            .disconnect_owned_session(pending.grant)
            .map_err(InitError::Jobs)?;
        let failed = system.close_handle(disconnected.channel).is_err()
            | cleanup_session_owner(system, waits, disconnected.owner, true);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Native(error)
        });
    }
    jobs.finish_pending_wait(pending).map_err(InitError::Jobs)
}

pub(crate) fn cleanup_session_owner<S, W>(
    system: &mut S,
    waits: &mut W,
    owner: Option<SessionOwner>,
    terminate: bool,
) -> bool
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    cleanup_session_owner_before(system, waits, owner, terminate, None)
}

pub(crate) fn cleanup_session_owner_before<S, W>(
    system: &mut S,
    waits: &mut W,
    owner: Option<SessionOwner>,
    terminate: bool,
    deadline_cap: Option<u64>,
) -> bool
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    owner.is_some_and(|owner| {
        cleanup_loaded_before(
            system,
            waits,
            LoadedProcess {
                process: owner.process,
                launch_channel: owner.launch_channel,
            },
            owner.task_group,
            terminate,
            deadline_cap,
        )
        .is_err()
    })
}

/// Retires one product consoled generation and its foreground shell while
/// preserving already-published background jobs as invisible controller-owned
/// orphans. The caller retains the dispatcher so those jobs can still reap.
pub(crate) fn retire_console_product<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    peer: InstalledPeer,
    terminate: bool,
) -> Result<(), InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    retire_console_product_inner(system, waits, jobs, peer, terminate, None).map(|_| ())
}

pub(crate) fn retire_console_product_inner<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    peer: InstalledPeer,
    terminate: bool,
    deadline_cap: Option<u64>,
) -> Result<Option<TerminationResult>, InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let outer = jobs
        .jobs
        .loaded_job_for_owner(peer.grant.endpoint_id, peer.grant.endpoint_generation)
        .map_err(InitError::Jobs)?;
    let disconnected = jobs
        .disconnect_owned_session(peer.grant)
        .map_err(InitError::Jobs)?;
    let expected_owner = SessionOwner {
        process: peer.loaded.process,
        launch_channel: peer.loaded.launch_channel,
        task_group: peer.task_group,
    };
    // Accounting disagreement must not short-circuit cleanup of resources we
    // still own. Preserve the mismatch as a cleanup failure after attempting
    // every independent close in this generation.
    let owner_mismatch = disconnected.owner != Some(expected_owner);
    let outer_mismatch = disconnected.outer_job.is_some();
    let channel_close_failed = system.close_handle(disconnected.channel).is_err();
    let owner_cleanup_failed =
        cleanup_session_owner_before(system, waits, disconnected.owner, terminate, deadline_cap);
    let mut failed = owner_mismatch | outer_mismatch | channel_close_failed | owner_cleanup_failed;
    let outer_result = match outer {
        Some(outer) => {
            match cleanup_shell_before_publication_before(system, waits, jobs, outer, deadline_cap)
            {
                Ok(result) => Some(result),
                Err(_) => {
                    failed = true;
                    None
                }
            }
        }
        None => None,
    };
    if failed {
        Err(InitError::Cleanup)
    } else {
        Ok(outer_result)
    }
}

pub(crate) fn drain_job_dispatcher<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
) -> Result<(), InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut sessions = [None; crate::job_sessions::MAX_SESSIONS];
    let session_count = jobs.drain_sessions(&mut sessions);
    let mut failed = false;
    for session in sessions[..session_count].iter().rev().flatten().copied() {
        failed |= system.close_handle(session.channel).is_err()
            | cleanup_session_owner(system, waits, session.owner, true);
    }
    let job_count = jobs.jobs.live_jobs();
    for _ in 0..job_count {
        let Some(loaded) = jobs.next_cleanup_job() else {
            break;
        };
        if let Some(resources) = jobs
            .jobs
            .forced_termination_resources(loaded.job_id)
            .map_err(InitError::Jobs)?
        {
            if system
                .terminate_task_group(DwHandle(resources.task_group))
                .is_err()
            {
                jobs.jobs
                    .record_cleanup_bits(loaded.job_id, 1 << 0)
                    .map_err(InitError::Jobs)?;
                failed = true;
            } else {
                jobs.jobs
                    .commit_forced_termination(loaded.job_id, resources)
                    .map_err(InitError::Jobs)?;
            }
        }
        match reap_job(system, waits, jobs, loaded) {
            Ok(result) => failed |= result.cleanup_result != 0,
            Err(_) => failed = true,
        }
    }
    if jobs.jobs.live_jobs() != 0 || failed {
        Err(InitError::Cleanup)
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../consoled/src/stream_transfer.rs"]
mod consoled_stream_transfer;

#[cfg(test)]
mod tests;
