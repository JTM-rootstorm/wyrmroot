//! Constructing, publishing and reaping one launched job.

use crate::job_sessions::{JobDispatcher, LaunchSessionScope};
use crate::jobs::{
    EndpointGrant, JobError, JobResult as ControllerJobResult, LaunchChannelRelease,
    LaunchEngineError, PolicyView, PreparedJob, RequestTicket, commit_prepared_job,
    observe_prepared_ready, prepare_reserved_job,
};
use crate::launch_transaction::{LaunchResources, LaunchStage, LaunchTransactionError};
use crate::*;
use deepwyrm_syscall::{
    DW_STATUS_NO_MEMORY, DW_STATUS_NO_RESOURCES, DW_TASK_STATE_EXITED, DW_TERMINATION_AUTHORIZED,
    DW_TERMINATION_NORMAL_EXIT, DW_TERMINATION_RESOURCE_POLICY, DW_TERMINATION_TASK_GROUP_TEARDOWN,
    DW_TERMINATION_UNHANDLED_EXCEPTION,
};
use wyrmroot_launch_proto::{
    ErrorCode as LaunchErrorCode, MessageType as LaunchMessageType,
    Reservation as LaunchReservation, TerminationClassification, TerminationResult,
    encode_error as encode_launch_error, encode_job_message,
    encode_shell_v1_error as encode_shell_v1_error_reply,
};

pub(crate) fn report_deadline<S: InitPlatform>(system: &mut S) -> Result<DwDeadline, InitError> {
    Ok(DwDeadline(
        system
            .now()
            .map_err(InitError::Native)?
            .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .ok_or(InitError::Accounting)?,
    ))
}

pub(crate) fn close_received_reverse<S: InitPlatform>(
    system: &mut S,
    handles: &[DwReceivedHandleInfoV1],
    count: usize,
) -> bool {
    let mut failed = false;
    for handle in handles[..count.min(handles.len())].iter().rev() {
        failed |= system.close_handle(handle.handle).is_err();
    }
    failed
}

pub(crate) fn launch_engine_error(error: LaunchEngineError<NativeError>) -> InitError {
    match error {
        LaunchEngineError::Job(error) => InitError::Jobs(error),
        LaunchEngineError::Validation {
            error,
            abort_failed,
            cleanup_failed,
        } => {
            if abort_failed || cleanup_failed {
                InitError::Cleanup
            } else {
                InitError::Jobs(error)
            }
        }
        LaunchEngineError::Loader {
            error,
            abort_failed,
            cleanup_failed,
            ..
        } => {
            if abort_failed || cleanup_failed {
                InitError::Cleanup
            } else {
                InitError::Loader(error)
            }
        }
        LaunchEngineError::Publication { error, .. } => InitError::Jobs(error),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn publish_launch_accepted<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    reservation: LaunchReservation,
    loaded: crate::jobs::LoadedJob,
    release: LaunchChannelRelease,
) -> Result<(LaunchChannelRelease, SentLaunchAccepted), InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut response = [0_u8; 88];
    let size = encode_job_message(
        reservation,
        LaunchMessageType::LaunchAccepted,
        loaded.job_id,
        &mut response,
    )
    .map_err(|_| InitError::Accounting)?;
    if let Err(error) = system.send_channel(session, &response[..size]) {
        jobs.jobs.restore_launch_channel(release);
        let cleanup_failed = force_cleanup_job_before(system, waits, jobs, loaded, None).is_err();
        return Err(if cleanup_failed {
            InitError::Cleanup
        } else {
            InitError::Native(error)
        });
    }
    Ok((release, SentLaunchAccepted {}))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SentLaunchAccepted {}

impl SentLaunchAccepted {}

pub(crate) fn force_cleanup_job<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    loaded: crate::jobs::LoadedJob,
) -> Result<TerminationResult, InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    force_cleanup_job_before(system, waits, jobs, loaded, None)
}

pub(crate) fn force_cleanup_job_before<S, W>(
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
        } else {
            jobs.jobs
                .commit_forced_termination(loaded.job_id, resources)
                .map_err(InitError::Jobs)?;
        }
    }
    let result = reap_job_before(system, waits, jobs, loaded, deadline_cap)?;
    if result.cleanup_result != 0 {
        Err(InitError::Cleanup)
    } else {
        Ok(result)
    }
}

pub(crate) fn rollback_prepared_job<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    prepared: crate::jobs::PreparedJob,
) -> Result<(), InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    force_cleanup_job(
        system,
        waits,
        jobs,
        crate::jobs::LoadedJob {
            job_id: prepared.job_id(),
            loaded: prepared.loaded,
            task_group: prepared.task_group,
        },
    )
    .map(|_| ())
}

/// Validates, reserves, loads and arms the READY deadline, and stops there.
///
/// Everything up to and including `report_deadline` is work the request's own
/// frame has to do: it consumes the moved stream handles and the borrowed
/// request, neither of which outlives the dispatch. What it returns is the
/// small record the observation needs afterwards.
#[allow(clippy::too_many_arguments)]
pub(crate) fn construct_reserved_launch<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: &PolicyView<'_>,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    reservation: LaunchReservation,
    request_ticket: RequestTicket,
    request: wyrmroot_launch_proto::LaunchRequest<'_>,
    received: &[DwReceivedHandleInfoV1],
    handle_count: usize,
) -> Result<ConstructedLaunch, InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    for info in &received[..handle_count] {
        if let Err(error) = validate_controller_channel(system, info.handle) {
            let failed = close_received_reverse(system, received, handle_count);
            return Err(if failed { InitError::Cleanup } else { error });
        }
    }
    let ticket = match jobs.jobs.begin_reserved_launch(request_ticket, true) {
        Ok(ticket) => ticket,
        Err(error) => {
            let failed = close_received_reverse(system, received, handle_count);
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Jobs(error)
            });
        }
    };
    let streams = [received[0].handle, received[1].handle, received[2].handle];
    let streams = &streams[..handle_count];
    let task_group = match system.create_attempt_task_group(authority.task_group) {
        Ok(task_group) => task_group,
        Err(error) => {
            return Err(
                if close_received_reverse(system, received, handle_count)
                    | jobs.jobs.abort_launch(ticket).is_err()
                {
                    InitError::Cleanup
                } else {
                    InitError::Native(error)
                },
            );
        }
    };
    if let Err(error) = system.limit_job_task_group(task_group) {
        return Err(
            if system.close_handle(task_group).is_err()
                | close_received_reverse(system, received, handle_count)
                | jobs.jobs.abort_launch(ticket).is_err()
            {
                InitError::Cleanup
            } else {
                InitError::Native(error)
            },
        );
    }
    let prepared = match prepare_reserved_job(
        &mut jobs.jobs,
        policy,
        loader,
        authority,
        task_group.0,
        reservation,
        ticket,
        request,
        streams,
    ) {
        Ok(prepared) => prepared,
        Err(LaunchEngineError::Publication {
            error,
            ticket,
            loaded,
            task_group,
        }) => {
            let cleanup_failed =
                cleanup_loaded(system, waits, loaded, DwHandle(task_group), true).is_err();
            let abort_failed = jobs.jobs.abort_launch(ticket).is_err();
            return Err(if cleanup_failed || abort_failed {
                InitError::Cleanup
            } else {
                InitError::Jobs(error)
            });
        }
        Err(error) => {
            let mapped = launch_engine_error(error);
            return Err(if system.close_handle(task_group).is_err() {
                InitError::Cleanup
            } else {
                mapped
            });
        }
    };
    let deadline = match report_deadline(system) {
        Ok(deadline) => deadline,
        Err(error) => {
            return Err(
                if rollback_prepared_job(system, waits, jobs, prepared).is_err() {
                    InitError::Cleanup
                } else {
                    error
                },
            );
        }
    };
    Ok(ConstructedLaunch {
        prepared,
        deadline,
        session,
        reservation,
    })
}

/// A launch whose child exists and whose READY has not been observed yet.
///
/// Reset plan §7: this is the boundary between `Constructed` and
/// `AwaitingReady`. Everything in it is a fact the observation and the
/// publication still need, and every one of them used to be a local of
/// `accept_reserved_launch`'s frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConstructedLaunch {
    pub(crate) prepared: PreparedJob,
    pub(crate) deadline: DwDeadline,
    pub(crate) session: DwHandle,
    pub(crate) reservation: LaunchReservation,
}

/// Observes the exact READY and publishes, or rolls the launch back.
///
/// Split out of `accept_reserved_launch` by reset card R6B. It is the half
/// that may not run in the frame that read the request: `observe_prepared_ready`
/// blocks until the child answers or `deadline` expires, and §3's invariant 6
/// says that wait must not hold the resident dispatcher. R6B moves the call
/// site; the sequence inside is unchanged.
#[allow(clippy::too_many_arguments)]
pub(crate) fn finish_constructed_launch<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    constructed: ConstructedLaunch,
) -> Result<(crate::jobs::LoadedJob, SentLaunchAccepted), InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let ConstructedLaunch {
        prepared,
        deadline,
        session,
        reservation,
    } = constructed;
    let observation = observe_prepared_ready(waits, &prepared, deadline);
    if observation.is_err() {
        return Err(
            if rollback_prepared_job(system, waits, jobs, prepared).is_err() {
                InitError::Cleanup
            } else {
                InitError::Supervision
            },
        );
    }
    let observation = observation.expect("checked exact READY observation");
    let loaded = match commit_prepared_job(&mut jobs.jobs, prepared, observation) {
        Ok(loaded) => loaded,
        Err(error) => {
            return Err(
                if rollback_prepared_job(system, waits, jobs, prepared).is_err() {
                    InitError::Cleanup
                } else {
                    InitError::Jobs(error)
                },
            );
        }
    };
    let release = jobs
        .jobs
        .release_launch_channel(loaded.job_id, loaded.loaded.launch_channel.0)
        .map_err(InitError::Jobs)?;
    let (release, sent_response) =
        publish_launch_accepted(system, waits, jobs, session, reservation, loaded, release)?;
    if system.close_handle(loaded.loaded.launch_channel).is_err() {
        jobs.jobs.restore_launch_channel(release);
        jobs.jobs
            .record_cleanup_bits(loaded.job_id, 1 << 2)
            .map_err(InitError::Jobs)?;
        if system
            .terminate_task_group(DwHandle(loaded.task_group))
            .is_err()
        {
            jobs.jobs
                .record_cleanup_bits(loaded.job_id, 1 << 0)
                .map_err(InitError::Jobs)?;
        } else {
            let resources = jobs
                .jobs
                .forced_termination_resources(loaded.job_id)
                .map_err(InitError::Jobs)?
                .ok_or(InitError::Accounting)?;
            jobs.jobs
                .commit_forced_termination(loaded.job_id, resources)
                .map_err(InitError::Jobs)?;
        }
        let loaded = jobs
            .jobs
            .loaded_job(loaded.job_id)
            .map_err(InitError::Jobs)?;
        return Ok((loaded, sent_response));
    }
    // The accepted job's retained resources are now owned by the model, which
    // recorded the released launch Channel. Returning the pre-release snapshot
    // would hand callers a closed launch-Channel handle to close again.
    let loaded = jobs
        .jobs
        .loaded_job(loaded.job_id)
        .map_err(InitError::Jobs)?;
    Ok((loaded, sent_response))
}

pub(crate) fn classify_termination(
    info: &DwTaskTerminationInfoV1,
) -> Result<TerminationClassification, InitError> {
    Ok(if info.reason == DW_TERMINATION_NORMAL_EXIT {
        TerminationClassification::NormalExit
    } else if info.reason == DW_TERMINATION_AUTHORIZED {
        TerminationClassification::Authorized
    } else if info.reason == DW_TERMINATION_UNHANDLED_EXCEPTION {
        TerminationClassification::UnhandledException
    } else if info.reason == DW_TERMINATION_RESOURCE_POLICY {
        TerminationClassification::ResourcePolicy
    } else if info.reason == DW_TERMINATION_TASK_GROUP_TEARDOWN {
        TerminationClassification::TaskGroupTeardown
    } else {
        return Err(InitError::Supervision);
    })
}

/// Bounded preterminal observation rounds allowed for one child Process exit.
///
/// A scripted controller may close a child's launch Channel and reap immediately,
/// so the child can still be pre-exit when the first observation runs. Each round
/// is one `WYR0_I_SUPERVISION_POLICY.ready_timeout_ns` wait followed by a fresh
/// level-triggered task-state query, which keeps the total bound explicit and
/// removes the dependence on a single wait observing the exact EXITED transition.
pub(crate) const JOB_EXIT_OBSERVATION_ROUNDS: u16 = WYR0_I_SUPERVISION_POLICY.max_attempts as u16;

/// Observes one child Process reaching its level-triggered EXITED state within
/// the bounded round budget above. `Err(())` means the caller must record
/// cleanup bit 1 and leave the job retained for a later cleanup attempt.
pub(crate) fn await_job_exit<S, W>(
    system: &mut S,
    waits: &mut W,
    process: DwHandle,
    deadline_cap: Option<u64>,
) -> Result<DwTaskTerminationInfoV1, ()>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut info = waits.query_task_termination(process).map_err(|_| ())?;
    let mut round = 0_u16;
    while info.state != DW_TASK_STATE_EXITED {
        if round == JOB_EXIT_OBSERVATION_ROUNDS {
            return Err(());
        }
        round += 1;
        let now = system.now().map_err(|_| ())?;
        if deadline_cap.is_some_and(|cap| now >= cap) {
            return Err(());
        }
        let deadline = now
            .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .map(|deadline| deadline_cap.map_or(deadline, |cap| deadline.min(cap)))
            .or(deadline_cap)
            .map(DwDeadline)
            .ok_or(())?;
        match waits.wait_many(
            core::slice::from_ref(&DwWaitItemV1 {
                handle: process,
                signals: DW_SIGNAL_EXITED,
            }),
            deadline,
        ) {
            Ok(_) => {}
            // A round that expires without the exit signal is not yet a cleanup
            // failure: the child may simply not have been scheduled. Any other
            // native wait failure stays fatal for this attempt.
            Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {}
            Err(_) => return Err(()),
        }
        info = waits.query_task_termination(process).map_err(|_| ())?;
        if deadline_cap.is_some() {
            let now = system.now().map_err(|_| ())?;
            if now >= deadline_cap.ok_or(())? {
                return Err(());
            }
        }
    }
    Ok(info)
}

pub(crate) fn reap_job<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    loaded: crate::jobs::LoadedJob,
) -> Result<TerminationResult, InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    reap_job_before(system, waits, jobs, loaded, None)
}

pub(crate) fn reap_job_before<S, W>(
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
    let terminal = match jobs
        .jobs
        .terminal_result(loaded.job_id)
        .map_err(InitError::Jobs)?
    {
        Some(terminal) => terminal,
        None => {
            if loaded.loaded.process.0 == 0 {
                return Err(InitError::Accounting);
            }
            let info = match await_job_exit(system, waits, loaded.loaded.process, deadline_cap) {
                Ok(info) => info,
                Err(()) => {
                    jobs.jobs
                        .record_cleanup_bits(loaded.job_id, 1 << 1)
                        .map_err(InitError::Jobs)?;
                    return Err(InitError::Cleanup);
                }
            };
            ControllerJobResult {
                classification: classify_termination(&info)?.as_u32(),
                application_code: info.application_code,
                exception_class: info.exception_type.0,
                exception_detail: info.detail,
                exception_address: info.fault_address,
                cleanup_result: 0,
            }
        }
    };
    let mut closed_mask = 0_u32;
    let mut failed_bits = 0_u32;
    if loaded.loaded.launch_channel.0 != 0 {
        if system.close_handle(loaded.loaded.launch_channel).is_err() {
            failed_bits |= 1 << 2;
        } else {
            closed_mask |= 1 << 2;
        }
    }
    if loaded.loaded.process.0 != 0 {
        if system.close_handle(loaded.loaded.process).is_err() {
            failed_bits |= 1 << 3;
        } else {
            closed_mask |= 1 << 3;
        }
    }
    if loaded.task_group != 0 {
        if system.close_handle(DwHandle(loaded.task_group)).is_err() {
            failed_bits |= 1 << 4;
        } else {
            closed_mask |= 1 << 4;
        }
    }
    let completed = jobs
        .jobs
        .apply_cleanup_progress(loaded.job_id, terminal, closed_mask, failed_bits)
        .map_err(InitError::Jobs)?;
    let Some(completed) = completed else {
        return Err(InitError::Cleanup);
    };
    jobs.jobs.reclaim_closed_sessions();
    controller_result_to_wire(completed)
}

pub(crate) const fn job_error_code(error: JobError) -> LaunchErrorCode {
    match error {
        JobError::TransactionReplay => LaunchErrorCode::TransactionReplay,
        JobError::UnknownConnection
        | JobError::ClosedConnection
        | JobError::StaleGeneration
        | JobError::DuplicateConnection
        | JobError::ZeroIdentity => LaunchErrorCode::StaleOrUnknownSession,
        JobError::ForeignJob | JobError::UnknownJob => LaunchErrorCode::ForeignOrUnknownJob,
        JobError::Capacity | JobError::ArithmeticOverflow => LaunchErrorCode::Capacity,
        JobError::Policy(_)
        | JobError::PolicyMissing
        | JobError::PolicyExecutable
        | JobError::Bootfs(_)
        | JobError::BootGenerationMismatch
        | JobError::ArtifactNotExecutable
        | JobError::ArtifactIdentityMismatch
        | JobError::StreamPolicy => LaunchErrorCode::PolicyRejected,
        JobError::WrongState | JobError::ResourceIdentity => LaunchErrorCode::InvalidState,
    }
}

/// A native failure during a launch, as the launch protocol's own vocabulary.
///
/// F3A.6n. `ErrorCode::Capacity` exists and was unreachable from the case it
/// describes. It is produced only by `job_error_code` from
/// `JobError::Capacity`, which is the *shell's own job table* filling up; a
/// **kernel** resource exhaustion arrived as `InitError::Native(status)` and
/// was reported as `LoaderFailure`. So "the loader broke" and "the system is
/// full" were the same word on the wire, and a reader could not tell a
/// defective artifact from a full machine.
///
/// `NO_MEMORY` and `NO_RESOURCES` are the kernel's two exhaustion statuses
/// (`deepwyrm/abi/schema/status.toml`, values -12 and -13). They are capacity
/// by any reading. Everything else native -- including an output-contract
/// fault, which is our own ABI handling and not the machine's limits -- keeps
/// `LoaderFailure`.
///
/// This is a §3.1 collapse and it stays one: `ErrorCode` is a bare
/// `#[repr(u32)]` enum with no payload, so the exact status cannot ride the
/// reply. Its own doc comment says Deepwyrm statuses "remain available only in
/// a terminal `JOB_RESULT`" -- an escape hatch a *refused* launch never has,
/// because no job is created. Until an out-of-band channel carries it per
/// §4.2, distinguishing the two classes is the whole improvement available
/// here, and it is the one the reader needs first.
pub(crate) const fn native_launch_error_code(error: NativeError) -> LaunchErrorCode {
    match error {
        NativeError::Status(status)
            if status.0 == DW_STATUS_NO_MEMORY.0 || status.0 == DW_STATUS_NO_RESOURCES.0 =>
        {
            LaunchErrorCode::Capacity
        }
        NativeError::Status(_) | NativeError::Output(_) => LaunchErrorCode::LoaderFailure,
    }
}

pub(crate) const fn launch_error_code(error: &InitError) -> LaunchErrorCode {
    match error {
        InitError::Jobs(error) => job_error_code(*error),
        InitError::Native(error) => native_launch_error_code(*error),
        // A load that failed *inside a platform stage* carries the kernel's
        // own cause, and that is where a handle- or memory-table exhaustion
        // during a launch actually surfaces -- not as a bare
        // `InitError::Native`. Reading only the outer variant would have left
        // the exhaustion case still answering `loader-failure`, which is the
        // mistake this change exists to correct.
        InitError::Loader(wyrmroot_loader::process::LoadError::Platform { cause, .. }) => {
            native_launch_error_code(*cause)
        }
        // The rest of `LoadError` genuinely names the loader or the artifact:
        // a malformed ELF, a bad startup block, a refused launch message.
        // `tools/e7_vm.py` pins `loader-failure` for a malformed ELF, and this
        // is the arm that keeps that answer.
        //
        // `Supervision` keeps the code rather than moving to a more accurate
        // one: nothing has been observed reaching it on this path, and moving
        // a code nothing has seen fire is churn with a conformance risk
        // attached.
        InitError::Loader(_) | InitError::Supervision => LaunchErrorCode::LoaderFailure,
        InitError::Cleanup | InitError::Accounting => LaunchErrorCode::CleanupFailure,
        _ => LaunchErrorCode::PolicyRejected,
    }
}

/// The shell launch path's mapping.
///
/// F3A.6n. The default arm used to be `LoaderFailure`, which is why the F
/// campaign's refused `spawn bin/cpu-hog` said `loader-failure` and meant
/// nothing: every `InitError` that was not `Jobs`, `Cleanup` or
/// `Accounting` claimed the loader had failed, including errors with no
/// relation to it. `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` §3.4 forbids a
/// wildcard over an error type at a status boundary and the compiler enforces
/// it -- but this is a *protocol reply* boundary, which that rule does not
/// reach, so the shape survived here.
///
/// Defaulting to a *specific* claim is the defect, not the defaulting. The
/// arms that can name their fault now do, by sharing `launch_error_code`'s
/// vocabulary, and what remains unclassified defaults to `PolicyRejected` --
/// "this request was refused" -- which claims nothing about where the fault
/// was. That is the honest answer for an error this function cannot attribute.
pub(crate) const fn shell_launch_error_code(error: &InitError) -> LaunchErrorCode {
    launch_error_code(error)
}

pub(crate) fn send_job_error<S: InitPlatform>(
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
        .map_err(InitError::Native)
}

/// Constructs the child, parks the transaction, and returns to the event loop.
///
/// Reset card R6B-2, and the whole of what it changes. The one-frame path is
/// `accept_reserved_launch`, which runs `construct_reserved_launch` and
/// `finish_constructed_launch` back to back; this runs only the first and
/// leaves the second to `finish_deferred_launch` on a later tick. Everything
/// the second half will need is written into the arena before this returns,
/// because the request buffer, the moved handles and the bootfs mapping all die
/// with this frame.
///
/// Failures before the child exists are answered here, exactly as they were:
/// the request bytes are still in hand, so the error reply and its evidence
/// record are unchanged. The one new failure is parking itself, and it is the
/// dangerous one -- a constructed child whose transaction never reached the
/// arena is a child nothing owns. It is rolled back before the reply, by the
/// same `rollback_prepared_job` the synchronous path uses.
#[allow(clippy::too_many_arguments)]
pub(crate) fn defer_reserved_launch<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: &PolicyView<'_>,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    grant: EndpointGrant,
    scope: LaunchSessionScope,
    reservation: LaunchReservation,
    request_ticket: RequestTicket,
    request: wyrmroot_launch_proto::LaunchRequest<'_>,
    moved: &[DwReceivedHandleInfoV1],
    handle_count: usize,
) -> Result<JobDispatchOutcome, InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let constructed = match construct_reserved_launch(
        system,
        loader,
        waits,
        authority,
        policy,
        jobs,
        session,
        reservation,
        request_ticket,
        request,
        moved,
        handle_count,
    ) {
        Ok(constructed) => constructed,
        Err(error) => {
            send_observed_job_error(system, session, reservation, launch_error_code(&error))?;
            return if error == InitError::Cleanup {
                Err(error)
            } else {
                Ok(JobDispatchOutcome::Responded)
            };
        }
    };
    if let Err(error) = park_constructed_launch(jobs, grant, scope, constructed) {
        let cleanup_failed =
            rollback_prepared_job(system, waits, jobs, constructed.prepared).is_err();
        send_observed_job_error(system, session, reservation, launch_error_code(&error))?;
        return Err(if cleanup_failed {
            InitError::Cleanup
        } else {
            error
        });
    }
    Ok(JobDispatchOutcome::Constructed)
}

/// Writes one constructed launch into the arena and leaves it `AwaitingReady`.
///
/// Every stage edge is taken explicitly rather than assigned, so the arena's
/// own graph gets to refuse a sequence the dispatcher should not be producing.
pub(crate) fn park_constructed_launch(
    jobs: &mut JobDispatcher,
    grant: EndpointGrant,
    scope: LaunchSessionScope,
    constructed: ConstructedLaunch,
) -> Result<(), InitError> {
    let token = jobs
        .launches
        .open(grant, constructed.session, scope, constructed.reservation)
        .map_err(launch_transaction_error)?;
    let record = || -> Result<(), LaunchTransactionError> {
        jobs.launches
            .attach_job(token, constructed.prepared.job_id())?;
        jobs.launches.advance(token, LaunchStage::Constructed)?;
        jobs.launches.attach_resources(
            token,
            constructed.prepared.profile(),
            LaunchResources {
                process: constructed.prepared.loaded.process,
                launch_channel: constructed.prepared.loaded.launch_channel,
                task_group: DwHandle(constructed.prepared.task_group),
            },
        )?;
        jobs.launches
            .arm_ready_deadline(token, constructed.deadline)?;
        jobs.launches.advance(token, LaunchStage::AwaitingReady)
    }();
    if let Err(error) = record {
        // The slot exists but does not describe the child. Empty it so it
        // cannot be mistaken for one that owns handles, and let the caller
        // roll the child back.
        let _ = jobs.launches.take_resources(token);
        let _ = jobs.launches.advance(token, LaunchStage::Failing);
        let _ = jobs.launches.advance(token, LaunchStage::Cleanup);
        let _ = jobs.launches.advance(token, LaunchStage::Complete);
        let _ = jobs.launches.close(token);
        return Err(launch_transaction_error(error));
    }
    Ok(())
}

/// The arena's refusals are accounting errors: every one of them means the
/// dispatcher asked for a transition its own sequence should have made
/// impossible.
pub(crate) fn launch_transaction_error(error: LaunchTransactionError) -> InitError {
    match error {
        LaunchTransactionError::Capacity => InitError::Jobs(JobError::Capacity),
        LaunchTransactionError::SessionBusy => InitError::Jobs(JobError::WrongState),
        _ => InitError::Accounting,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn send_observed_job_error<S: ResidentPlatform>(
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

pub(crate) fn send_shell_v1_error<S: InitPlatform>(
    system: &mut S,
    session: DwHandle,
    reservation: LaunchReservation,
    code: LaunchErrorCode,
) -> Result<(), InitError> {
    let mut response = [0_u8; wyrmroot_launch_proto::SHELL_V1_REPLY_BYTES];
    let size = encode_shell_v1_error_reply(reservation, code, &mut response)
        .map_err(|_| InitError::Accounting)?;
    system
        .send_channel(session, &response[..size])
        .map_err(InitError::Native)
}

pub(crate) fn controller_result_to_wire(
    result: ControllerJobResult,
) -> Result<TerminationResult, InitError> {
    let classification = match result.classification {
        1 => TerminationClassification::NormalExit,
        2 => TerminationClassification::Authorized,
        3 => TerminationClassification::UnhandledException,
        4 => TerminationClassification::ResourcePolicy,
        5 => TerminationClassification::TaskGroupTeardown,
        _ => return Err(InitError::Accounting),
    };
    Ok(TerminationResult {
        classification,
        application_code: result.application_code,
        exception_class: result.exception_class,
        exception_detail: result.exception_detail,
        exception_address: result.exception_address,
        cleanup_result: result.cleanup_result,
    })
}
