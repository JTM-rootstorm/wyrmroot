//! Polling the dispatcher, pending waits, session cleanup and retirement.

use super::*;

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
