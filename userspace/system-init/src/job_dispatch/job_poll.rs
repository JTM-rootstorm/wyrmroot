//! Polling the dispatcher, pending waits, session cleanup and retirement.

use super::*;

/// E3C adapter for the selected console controller. The caller supplies the
/// current registry generation and poison state; request bytes cannot select
/// either authority.
#[allow(clippy::too_many_arguments)]
/// Terminates the orphans that keep closed connections over their bounds
/// (F4 WYR1-F4-M1). Each job's task group is ended here; the poll loop then
/// observes the exit and reaps it, as for any other job, and the empty
/// connection slot is reclaimed. Returns whether any termination failed.
pub(crate) fn retire_excess_orphans<S: ResidentPlatform>(
    system: &mut S,
    jobs: &mut JobDispatcher,
) -> Result<bool, InitError> {
    let mut retire = [0; wyrmroot_launch_proto::MAX_LIVE_JOBS];
    let count = jobs.jobs.orphans_to_retire(&mut retire);
    let mut failed = false;
    // Every listed orphan is attempted; an accounting error on one is
    // reported after the rest, not instead of them.
    let mut first_error = None;
    for &job_id in &retire[..count] {
        match terminate_orphan(system, jobs, job_id) {
            Ok(terminated) => failed |= !terminated,
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(failed),
    }
}

/// Ends one job's TaskGroup, recording a refusal as cleanup bit 0 for the
/// poll loop to retry. Returns whether the termination was committed (or
/// the job needs none).
fn terminate_orphan<S: ResidentPlatform>(
    system: &mut S,
    jobs: &mut JobDispatcher,
    job_id: u64,
) -> Result<bool, InitError> {
    let Some(resources) = jobs
        .jobs
        .forced_termination_resources(job_id)
        .map_err(InitError::Jobs)?
    else {
        return Ok(true);
    };
    if system
        .terminate_task_group(DwHandle(resources.task_group))
        .is_err()
    {
        jobs.jobs
            .record_cleanup_bits(job_id, 1 << 0)
            .map_err(InitError::Jobs)?;
        return Ok(false);
    }
    jobs.jobs
        .commit_forced_termination(job_id, resources)
        .map_err(InitError::Jobs)?;
    Ok(true)
}

pub(crate) fn poll_job_dispatcher_with_shell<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    jobs: &mut JobDispatcher,
    now_ns: u64,
    shell: &mut ShellLaunchContext<'_>,
) -> Result<JobDispatcherPoll, InitError>
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
) -> Result<JobDispatcherPoll, InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut poll = JobDispatcherPoll::STABLE;
    // A session the image read retired since the last poll is this poll's to
    // report: its fault reaches the caller like any other.
    if let Some(fault) = jobs.image_fault.take() {
        poll.faulted(fault);
    }
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
            disposition => {
                // Finishing it sends its session a reply. A session whose
                // queue is full keeps its launch parked until there is room,
                // and is retired -- its launch rolled back with it -- only
                // when its patience runs out.
                let grant = jobs
                    .launches
                    .grant(token)
                    .map_err(launch_transaction_error)?;
                let gate = match jobs.session_scope(grant) {
                    Ok(scope) => Some((scope, reply_gate(system, jobs, grant, now_ns)?)),
                    // Its session went without it; it is finished unanswered.
                    Err(_) => None,
                };
                let unanswerable = match gate {
                    Some((_, ReplyGate::Blocked)) => None,
                    Some((_, ReplyGate::Expired)) => {
                        Some((grant, FaultCause::ReplyQueueNeverDrained))
                    }
                    Some((_, ReplyGate::Open)) | None => finish_deferred_launch(
                        system,
                        waits,
                        jobs,
                        token,
                        shell.as_deref_mut(),
                        disposition,
                        now_ns,
                    )?,
                };
                if let Some((grant, cause)) = unanswerable
                    && let Ok(scope) = jobs.session_scope(grant)
                {
                    retire_session(system, waits, jobs, grant, scope)?;
                    poll.faulted(SessionFault {
                        grant,
                        scope,
                        cause,
                    });
                }
            }
        }
    }
    if let Some((grant, session)) = jobs.next_session() {
        // A reply held for this session goes first. Until it has gone, the
        // session's requests are not read -- each would be owed a reply
        // there is nowhere to put -- but its peer closing is still seen.
        let reading = match flush_held_reply(system, jobs, grant, session, now_ns)? {
            HeldFlush::Clear => true,
            HeldFlush::StillHeld => false,
            HeldFlush::Unanswerable(cause) => {
                let scope = jobs.session_scope(grant).map_err(InitError::Jobs)?;
                retire_session(system, waits, jobs, grant, scope)?;
                poll.faulted(SessionFault {
                    grant,
                    scope,
                    cause,
                });
                return finish_poll(system, waits, jobs, shell, now_ns, poll);
            }
        };
        let item = DwWaitItemV1 {
            handle: session,
            signals: deepwyrm_syscall::DwSignals(if reading {
                DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0
            } else {
                DW_SIGNAL_PEER_CLOSED.0
            }),
        };
        match system.wait_many(core::slice::from_ref(&item), DwDeadline(now_ns)) {
            Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {}
            Err(error) => return Err(InitError::Native(error)),
            Ok(observed) if observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 => {
                // Read before the dispatch, which may disconnect the session.
                let scope = jobs.session_scope(grant).map_err(InitError::Jobs)?;
                let dispatched = with_launch_policy(system, authority, |system, policy| {
                    if let Some(shell) = shell.as_deref_mut() {
                        dispatch_one_job_request_with_shell(
                            system,
                            loader,
                            waits,
                            authority,
                            Some(policy),
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
                            Some(policy),
                            jobs,
                            session,
                            grant,
                        )
                    }
                });
                // Init's own bootfs or launch policy failing to map or parse
                // is init's failure, whichever session's turn it was.
                let dispatched = match dispatched {
                    Ok(dispatched) => dispatched,
                    Err(error) => Err(DispatchError::Fatal(error)),
                };
                match dispatched {
                    Ok(
                        JobDispatchOutcome::Responded
                        | JobDispatchOutcome::Launched(_)
                        | JobDispatchOutcome::Constructed
                        | JobDispatchOutcome::ImageParked,
                    ) => {}
                    // The client's fault, and the client's loss: the session
                    // goes, by the same route as one whose peer closed, and
                    // the tick carries on to the jobs and waits behind it.
                    // Dispatched, and the reply found the queue full. It is
                    // held; a client with a reply already held is past what
                    // the queue allows.
                    Err(DispatchError::ReplyHeld) => {
                        if let Err(cause) = hold_reply(jobs, grant, now_ns) {
                            retire_session(system, waits, jobs, grant, scope)?;
                            poll.faulted(SessionFault {
                                grant,
                                scope,
                                cause,
                            });
                        }
                    }
                    Err(DispatchError::Client(cause)) => {
                        // F3A.7j. A retirement that cannot complete is named
                        // by the session it was for.
                        let operation = match scope {
                            LaunchSessionScope::ConsoleLauncher => {
                                RecoveryOperation::DispatchConsoleJob
                            }
                            LaunchSessionScope::ShellJobs => RecoveryOperation::DispatchShellJob,
                        };
                        attribute_failure(
                            operation,
                            retire_session(system, waits, jobs, grant, scope),
                        )?;
                        poll.faulted(SessionFault {
                            grant,
                            scope,
                            cause,
                        });
                    }
                    Err(DispatchError::Fatal(dispatch_error)) => {
                        // R6C. Whatever this session had in flight goes with it.
                        let cancel_failed = cancel_parked_launch(system, waits, jobs, grant)
                            .is_err()
                            | crate::image_launch::cancel_parked_image(system, jobs, Some(grant));
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
                                    owner_cleanup_failed: owner_cleanup_failed | cancel_failed,
                                }
                            }
                            Err(_) => EmergencyCleanup::DisconnectFailed,
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
            }
            Ok(observed) if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 => {
                let scope = jobs.session_scope(grant).map_err(InitError::Jobs)?;
                retire_session(system, waits, jobs, grant, scope)?;
                poll.closed(grant, scope);
            }
            Ok(_) => return Err(InitError::Supervision),
        }
    }
    finish_poll(system, waits, jobs, shell, now_ns, poll)
}

/// The half of the poll every path runs: reap one job, answer one WAIT.
fn finish_poll<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    shell: Option<&mut ShellLaunchContext<'_>>,
    now_ns: u64,
    mut poll: JobDispatcherPoll,
) -> Result<JobDispatcherPoll, InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
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
        if !exited && let Some(resources) = jobs.jobs.termination_to_retry(loaded.job_id) {
            // A termination the kernel refused earlier (and that was reported
            // then) is tried again each time the job comes round, so the job
            // cannot hold its slot forever. Once accepted, the job is reaped
            // as an ordinary forced termination.
            if system
                .terminate_task_group(DwHandle(resources.task_group))
                .is_ok()
            {
                jobs.jobs
                    .commit_retried_termination(loaded.job_id, resources)
                    .map_err(InitError::Jobs)?;
            }
        }
        if exited {
            let result = reap_job(system, waits, jobs, loaded)?;
            let nested = close_shell_session_for_job(system, jobs, loaded.job_id);
            if result.cleanup_result != 0 || nested.is_err() {
                return Err(InitError::Cleanup);
            }
        }
    }
    let unanswerable = service_pending_wait_inner(
        system,
        waits,
        jobs,
        shell.map(|shell| &mut *shell.state),
        now_ns,
    )?;
    if let Some(fault) = unanswerable {
        poll.faulted(fault);
    }
    Ok(poll)
}

/// What became of the reply held for a session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeldFlush {
    /// Nothing is held, or it has just been delivered.
    Clear,
    /// The queue is still full, with patience left.
    StillHeld,
    /// The peer is gone, or the queue never drained.
    Unanswerable(FaultCause),
}

fn flush_held_reply<S: ResidentPlatform>(
    system: &mut S,
    jobs: &mut JobDispatcher,
    grant: EndpointGrant,
    session: DwHandle,
    now_ns: u64,
) -> Result<HeldFlush, InitError> {
    let Some(held) = jobs.session_mut(grant).map_err(InitError::Jobs)?.held_reply else {
        return Ok(HeldFlush::Clear);
    };
    let sent = send_session_reply(system, jobs, session, held.bytes());
    // It is held already; the copy a refused send staged is not needed.
    jobs.staged_reply = None;
    let state = jobs.session_mut(grant).map_err(InitError::Jobs)?;
    match sent {
        Ok(()) => {
            state.held_reply = None;
            state.blocked_since = None;
            Ok(HeldFlush::Clear)
        }
        Err(ReplyError::QueueFull) => {
            let since = *state.blocked_since.get_or_insert(now_ns);
            Ok(if now_ns.saturating_sub(since) >= REPLY_PATIENCE_NS {
                HeldFlush::Unanswerable(FaultCause::ReplyQueueNeverDrained)
            } else {
                HeldFlush::StillHeld
            })
        }
        Err(ReplyError::PeerClosed) => Ok(HeldFlush::Unanswerable(FaultCause::ReplyUndeliverable(
            deepwyrm_syscall::DW_STATUS_PEER_CLOSED,
        ))),
        Err(ReplyError::Encode) => Err(InitError::Accounting),
        Err(ReplyError::Native(error)) => Err(InitError::Native(error)),
    }
}

/// Runs `use_policy` over the launch policy of init's own retained bootfs.
///
/// Every failure here is init's: the archive is the one init booted from.
pub(crate) fn with_launch_policy<S: ResidentPlatform, R>(
    system: &mut S,
    authority: LoadAuthority,
    use_policy: impl for<'a> FnOnce(&mut S, &PolicyView<'a>) -> R,
) -> Result<R, InitError> {
    let size = system
        .query_memory_object_size(authority.bootfs)
        .map_err(InitError::Native)?;
    let plan = MappingPlan::for_bootfs(size).map_err(InitError::Mapping)?;
    system
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
                let policy =
                    PolicyView::from_bootfs(archive, boot_generation).map_err(InitError::Jobs)?;
                Ok(use_policy(system, &policy))
            },
        )
        .map_err(InitError::Native)?
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

/// Answers one pending WAIT whose job has ended.
///
/// Returns the session it retired, if the session would not take the answer:
/// a `JOB_RESULT` that cannot be delivered is the waiting client's fault, and
/// costs it its session rather than costing init the tick.
#[allow(unused_mut)]
pub(crate) fn service_pending_wait_inner<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    mut evidence: Option<&mut ShellControllerState>,
    now_ns: u64,
) -> Result<Option<SessionFault>, InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let Some(pending) = jobs.next_pending_wait() else {
        return Ok(None);
    };
    let scope = jobs.session_scope(pending.grant).map_err(InitError::Jobs)?;
    let result = match jobs.jobs.result_for_owner(
        pending.reservation.connection_id,
        pending.reservation.generation,
        pending.job_id,
    ) {
        Ok(result) => result,
        Err(JobError::UnknownJob) => return Ok(None),
        Err(error) => return Err(InitError::Jobs(error)),
    };
    let session = jobs
        .session_handle(pending.grant)
        .map_err(InitError::Jobs)?;
    // The result is ready; whether it can be sent is the session's queue.
    // With no room the WAIT simply stays pending.
    let fault = |cause| SessionFault {
        grant: pending.grant,
        scope,
        cause,
    };
    match reply_gate(system, jobs, pending.grant, now_ns)? {
        ReplyGate::Open => {}
        ReplyGate::Blocked => return Ok(None),
        ReplyGate::Expired => {
            retire_session(system, waits, jobs, pending.grant, scope)?;
            return Ok(Some(fault(FaultCause::ReplyQueueNeverDrained)));
        }
    }
    let terminal = controller_result_to_wire(result)?;
    observe_session_shutdown_result(scope, evidence, terminal);
    let mut response = [0_u8; 88];
    let size = encode_job_result(pending.reservation, pending.job_id, terminal, &mut response)
        .map_err(|_| InitError::Accounting)?;
    let sent = send_session_reply(system, jobs, session, &response[..size]);
    jobs.finish_pending_wait(pending).map_err(InitError::Jobs)?;
    match settle_reply(jobs, pending.grant, sent, now_ns)? {
        None => Ok(None),
        Some(cause) => {
            retire_session(system, waits, jobs, pending.grant, scope)?;
            Ok(Some(fault(cause)))
        }
    }
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
    // An image still being read is owed to a session that is going.
    let mut failed = crate::image_launch::cancel_parked_image(system, jobs, None);
    let session_count = jobs.drain_sessions(&mut sessions);
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
