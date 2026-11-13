//! Parked and deferred launches: cancel, finish, close.

use super::*;

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
    now_ns: u64,
) -> Result<Option<(EndpointGrant, FaultCause)>, InitError>
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
    // The session, if it would not take the reply this launch owed it.
    let mut unanswerable = None;
    let mut reply_failure = None;
    let published = match outcome {
        Ok(_) => Ok(()),
        Err(error) => {
            // Deliberately not `?`. What must happen whatever the reply does
            // is emptying the slot below: a transaction left open here would
            // be handed back by `awaiting_ready_from` on every subsequent
            // tick, for ever, holding a child nothing else can name.
            //
            // The reply is owed to a session that may already be gone -- a
            // shell reaped elsewhere in the tick closes the Channel this
            // slot recorded -- and then it is owed to no one.
            if jobs.session_handle(grant) == Ok(session) {
                let reply = send_deferred_launch_error(
                    system,
                    jobs,
                    session,
                    reservation,
                    launch_error_code(&error),
                );
                // A reply that fails does not relabel the launch's own
                // failure, for the same reason `LaunchTransactions::fail`
                // keeps the first disposition. A full queue holds it; a
                // client that cannot be told is the caller's to retire.
                match settle_reply(jobs, grant, reply, now_ns) {
                    Ok(None) => {}
                    Ok(Some(cause)) => unanswerable = Some((grant, cause)),
                    Err(failure) => reply_failure = Some(failure),
                }
            }
            Err(error)
        }
    };
    close_deferred_launch(jobs, token, published.is_ok())?;
    if let Some(failure) = reply_failure {
        return Err(failure);
    }
    // One launch failing is not the tick failing. The one-frame path answered a
    // failed launch with an `ERROR` reply and returned `Responded`, and only a
    // failed *cleanup* escalated -- because a cleanup that did not happen means
    // resources nobody can name, while a child that missed READY has already
    // been rolled back by the time we get here. R6C keeps that split: a launch
    // that never answers must not take down the supervisor, which is most of
    // what R6D has to prove.
    match published {
        Ok(()) => Ok(None),
        Err(InitError::Cleanup) => Err(InitError::Cleanup),
        // `LAUNCH_ACCEPTED` refused for a reason no peer can cause.
        Err(InitError::Native(error)) if peer_cause(ChannelOperation::Send, error).is_none() => {
            Err(InitError::Native(error))
        }
        Err(_) => Ok(unanswerable),
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
    jobs: &mut JobDispatcher,
    session: DwHandle,
    reservation: LaunchReservation,
    code: LaunchErrorCode,
) -> Result<(), ReplyError> {
    send_job_error(system, jobs, session, reservation, code)
}
