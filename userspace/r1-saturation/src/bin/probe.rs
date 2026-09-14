//! Reset card R1's dynamic-launch saturation probe.
//!
//! The scenario lives in `wyrmroot_r1_saturation` as a host-tested state
//! machine; this binary only supplies syscalls and reports what it observed. It
//! never decides the sequence, never skips a proof, and never synthesises a
//! reply — `SaturationProbe` advances on observation alone, so a step that did
//! not happen cannot be recorded as having happened.
//!
//! Reporting goes to permanent system-init over the bootstrap channel as
//! 64-byte `R1SP` records. Init relays them through the selector-private
//! evidence syscall. The probe deliberately holds no evidence authority of its
//! own: it is a dynamically launched child, and giving one a private kernel
//! operation would widen authority past every existing selector. This follows
//! the wyr1b-gate precedent exactly.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

use deepwyrm_syscall::{
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DW_SIGNAL_READABLE,
    DW_SIGNAL_WRITABLE, DW_STATUS_TIMED_OUT, DW_STATUS_WOULD_BLOCK, DwHandle,
    DwReceivedHandleInfoV1, DwRights, DwSignals,
};
use wyrmroot_launch_proto::{
    Message as LaunchMessage, MessageType as LaunchType, Reservation, TerminationClassification,
    encode_job_message, encode_launch, parse_message,
};
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, HEADER_BYTES as WRLP_BYTES, LaunchProfile, SELF_ROOT_RIGHTS,
    encode_ready_for_profile, parse_init,
};
use wyrmroot_r1_saturation::launch_parameters::parse_nonce;
use wyrmroot_r1_saturation::probe_status::{self, report_send_failure};
use wyrmroot_r1_saturation::record::{self, BYTES as RECORD_BYTES};
use wyrmroot_r1_saturation::{
    HOG_PATH, PROGRESS_PATH, ProbeFailure, ProbeOutcome, ProbePlan, ProbeStep, SaturationProbe,
    launch_parameters,
};
use wyrmroot_registry_proto::parse_correlation_environment;
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, NativeError, StartupBlock, close_handle,
    monotonic_deadline_after, panic_abort, query_capability_info, receive_channel, send_channel,
    validate_bootstrap_channel, wait_one,
};

/// The build nonce the kernel collector was compiled with. A mismatch would
/// have the collector refuse every record, so this is a compile-time constant
/// rather than anything the product can get wrong at run time.
const NONCE: u64 = match parse_nonce(env!("DEEPWYRM_R1_EVIDENCE_NONCE")) {
    Ok(value) => value,
    Err(_) => panic!("DEEPWYRM_R1_EVIDENCE_NONCE must be sixteen uppercase hex digits, nonzero"),
};

/// One definition, shared with the library that encodes the status-carrying
/// codes, so the two cannot drift apart.
const PROBE_ERROR_BASE: u32 = probe_status::ERROR_BASE;

/// How long the probe waits for a launch to be accepted.
///
/// This must **exceed** `WYR0_I_SUPERVISION_POLICY.ready_timeout_ns` (1 s), or
/// the probe's own impatience would mask the kernel's own rejection and report
/// a stall where a legitimate negative answer existed. It must also stay well
/// under the host's ordinary 30 s bound, because A27's whole failure was the
/// host timing out first and capturing no structured state.
const ACCEPT_TIMEOUT_NANOSECONDS: u64 = 3_000_000_000;

/// How long the probe waits for a terminal result. Longer than the accept
/// bound: the progress child must be admitted, scheduled, run and reaped while
/// hogs hold the CPUs, which is the condition under test.
const RESULT_TIMEOUT_NANOSECONDS: u64 = 8_000_000_000;

/// How long the probe waits for room on its report channel before giving up.
///
/// The channel is depth 2 and the kernel's send is non-blocking by contract: it
/// refuses with `WouldBlock` rather than dropping or blocking, so a sender that
/// outruns permanent init's drain *must* wait. Generous on purpose -- a report
/// that is merely queued behind init is not a failure of anything under test,
/// and reporting it as one is what stopped runs 12 and 13 at different depths of
/// the same scenario. Still bounded, because an init that has actually stopped
/// draining must end the run rather than hang it.
const REPORT_ROOM_TIMEOUT_NANOSECONDS: u64 = 5_000_000_000;

/// Largest launch/job datagram this probe sends or accepts, matching the
/// wyr1b-gate client's fixed frame so no path here allocates.
const FRAME_BYTES: usize = 416;

struct Reporter {
    parent: DwHandle,
    plan: ProbePlan,
    sequence: u64,
}

impl Reporter {
    /// Sequences start at one: the kernel collector requires a consecutive
    /// one-based sequence and refuses a zero.
    fn new(parent: DwHandle, plan: ProbePlan) -> Self {
        Self {
            parent,
            plan,
            sequence: 0,
        }
    }

    fn next_sequence(&mut self) -> u64 {
        self.sequence += 1;
        self.sequence
    }

    /// Sends one record, keeping the reason a send refused.
    ///
    /// This is the probe's only send path -- `step`, `failure` and `terminal` all
    /// route through it -- so when it fails the probe reports nothing at all, and
    /// its exit code is the only thing the host will see. Run 7 exited here with
    /// `0x81000030` and the native status was discarded, which left the run
    /// proving the send refused and not whether the handle lacked a right, the
    /// peer had closed, or the queue was full.
    fn emit(&mut self, record: [u8; RECORD_BYTES]) -> Result<(), u32> {
        match self.send_with_room(&record) {
            Ok(()) => Ok(()),
            Err(error) => {
                // The send is atomic: on refusal nothing was transmitted, so the
                // sequence it consumed must go back. Runs 9 and 11 both reported
                // `expected 6, observed 7` for exactly this -- a number burned by
                // a refused send, which the collector correctly read as a gap
                // and which sent this investigation after a lost datagram that
                // never existed.
                self.sequence -= 1;
                Err(error)
            }
        }
    }

    /// Sends one record, waiting for room rather than treating a full channel
    /// as a failure.
    ///
    /// `send_channel` is non-blocking by contract: `WouldBlock` means the peer's
    /// depth-2 queue or the shared payload pool had no room *at that instant*,
    /// not that anything is wrong. This path had no back-pressure at all, so the
    /// probe reported `WOULD_BLOCK` as a fatal `RunStopped` the first time it
    /// outran permanent init's drain -- run 13's `0x81009008`, and run 12's
    /// discarded code before it. How far the scenario got was decided by drain
    /// timing, which is why the two runs stopped at different hogs while every
    /// launch and accept in them succeeded.
    ///
    /// Waiting on `DW_SIGNAL_WRITABLE` alone is not enough to make the retry
    /// unnecessary: that signal asserts per-queue descriptor room and says
    /// nothing about the globally shared payload pool, so a send can still be
    /// refused immediately after the wait reports writable. The loop is written
    /// to survive that rather than to assume it away.
    fn send_with_room(&self, record: &[u8; RECORD_BYTES]) -> Result<(), u32> {
        let deadline = monotonic_deadline_after(REPORT_ROOM_TIMEOUT_NANOSECONDS)
            .map_err(report_send_failure)?;
        loop {
            match send_channel(self.parent, record, &[]) {
                Ok(()) => return Ok(()),
                Err(error) if !is_would_block(error) => return Err(report_send_failure(error)),
                Err(error) => {
                    // Out of time is reported as the refusal it actually was, so
                    // the host sees `WOULD_BLOCK` at the report-send site rather
                    // than a probe-invented timeout ordinal.
                    match wait_one(self.parent, DwSignals(DW_SIGNAL_WRITABLE.0), deadline) {
                        Ok(_) => {}
                        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {
                            return Err(report_send_failure(error));
                        }
                        Err(waited) => return Err(report_send_failure(waited)),
                    }
                }
            }
        }
    }

    fn step(&mut self, step: ProbeStep, job_id: u64) -> Result<(), u32> {
        let sequence = self.next_sequence();
        self.emit(record::encode_step(
            sequence, NONCE, self.plan, step, job_id,
        ))
    }

    fn failure(&mut self, failure: ProbeFailure) -> Result<(), u32> {
        let sequence = self.next_sequence();
        self.emit(record::encode_failure(sequence, NONCE, self.plan, failure))
    }

    /// The single terminal record. It is emitted on every exit path, including
    /// a failing one, because the kernel's terminal handling is what flushes the
    /// transcript — a run that failed without it reads to the host as a timeout
    /// rather than as a classified failure.
    fn terminal(&mut self, outcome: ProbeOutcome, steps_observed: usize) -> Result<(), u32> {
        let sequence = self.next_sequence();
        self.emit(record::encode_terminal(
            sequence,
            NONCE,
            self.plan,
            outcome,
            steps_observed,
        ))
    }
}

/// One JobV2 reservation per request. Transaction ids must not repeat within a
/// connection, so they come from a single counter rather than from the step.
struct Session {
    channel: DwHandle,
    connection_id: u64,
    generation: u64,
    transaction: u64,
}

impl Session {
    fn reserve(&mut self) -> Reservation {
        self.transaction += 1;
        Reservation {
            connection_id: self.connection_id,
            generation: self.generation,
            transaction_id: self.transaction,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Reply {
    Accepted {
        job_id: u64,
    },
    Result(JobResult),
    TerminationAccepted,
    /// The service refused. Carries the protocol error so a rejection is never
    /// reported as a liveness failure.
    Rejected {
        status: u32,
    },
    /// No reply inside the bound. This is the A27 shape.
    TimedOut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JobResult {
    job_id: u64,
    normal_zero: bool,
    application_code: u32,
    cleanup_result: u32,
}

fn probe_main(startup: StartupBlock<'_>) -> u32 {
    match run(startup) {
        Ok(code) => code,
        Err(code) => code,
    }
}

fn run(startup: StartupBlock<'_>) -> Result<u32, u32> {
    let parent = startup.bootstrap_channel().as_abi();
    validate_bootstrap_channel(
        query_capability_info(parent).map_err(|_| PROBE_ERROR_BASE + 0x0001)?,
        BOOTSTRAP_CHANNEL_EXPECTATION,
    )
    .map_err(|_| PROBE_ERROR_BASE + 0x0002)?;

    let plan = plan_from_arguments(&startup)?;
    let correlation = correlation_from_environment(&startup)?;

    wait_readable(
        parent,
        ACCEPT_TIMEOUT_NANOSECONDS,
        PROBE_ERROR_BASE + 0x0003,
    )?;
    let mut init = [0_u8; 64];
    let mut handles = [DwReceivedHandleInfoV1::default(); 2];
    let counts =
        receive_channel(parent, &mut init, &mut handles).map_err(|_| PROBE_ERROR_BASE + 0x0004)?;
    if counts.bytes > init.len() || counts.handles != 2 {
        close_received(&handles, counts.handles);
        return Err(PROBE_ERROR_BASE + 0x0005);
    }
    let parsed = match parse_init(LaunchProfile::LaunchClient, &init[..counts.bytes], &handles) {
        Ok(parsed) => parsed,
        Err(_) => {
            close_received(&handles, 2);
            return Err(PROBE_ERROR_BASE + 0x0006);
        }
    };
    // The probe must hold exactly the LaunchClient authority: a self root it
    // immediately drops, and one launch session. Validating the shape here means
    // a policy that handed it anything wider fails before a single launch.
    if validate_fresh(handles[0], DW_OBJECT_TYPE_ADDRESS_REGION, SELF_ROOT_RIGHTS).is_err()
        || validate_fresh(handles[1], DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS).is_err()
    {
        close_received(&handles, 2);
        return Err(PROBE_ERROR_BASE + 0x0007);
    }

    let mut ready = [0_u8; WRLP_BYTES];
    let size = match encode_ready_for_profile(
        LaunchProfile::LaunchClient,
        parsed.transaction_id,
        &mut ready,
    ) {
        Ok(size) => size,
        Err(_) => {
            close_received(&handles, 2);
            return Err(PROBE_ERROR_BASE + 0x0008);
        }
    };
    if send_channel(parent, &ready[..size], &[]).is_err() {
        close_received(&handles, 2);
        return Err(PROBE_ERROR_BASE + 0x0009);
    }
    if close_handle(handles[0].handle).is_err() {
        let _ = close_handle(handles[1].handle);
        return Err(PROBE_ERROR_BASE + 0x000A);
    }

    let mut session = Session {
        channel: handles[1].handle,
        connection_id: correlation.0,
        generation: correlation.1,
        transaction: 0,
    };
    let mut reporter = Reporter::new(parent, plan);
    let mut probe = SaturationProbe::new(plan).ok_or(PROBE_ERROR_BASE + 0x000B)?;

    // The terminal record is emitted whatever happened, because the kernel
    // collector flushes the transcript on it and nothing else: without one, every
    // record already relayed stays collected and unprinted. A probe failure is
    // classified as what it is rather than as whatever `probe.outcome()` happened
    // to hold, and its code is still reported afterwards, so the host learns both
    // the transcript and the reason the run stopped.
    let (outcome, stopped) = match drive(&mut probe, &mut session, &mut reporter) {
        Ok(outcome) => (outcome, None),
        Err(code) => (
            ProbeOutcome::Failed(ProbeFailure::RunStopped { code }),
            Some(code),
        ),
    };
    let terminal = reporter.terminal(outcome, probe.steps_observed());
    let _ = close_handle(session.channel);
    let _ = close_handle(parent);
    // The failure that stopped the run outranks a later terminal-send failure:
    // it is the cause, and the terminal send is a consequence of the same
    // refusing channel.
    if let Some(code) = stopped {
        return Err(code);
    }
    terminal?;
    match outcome {
        ProbeOutcome::Passed => Ok(0),
        ProbeOutcome::Failed(_) => Ok(PROBE_ERROR_BASE + 0x0100),
    }
}

/// Runs the scenario, returning either its observed outcome or the probe's own
/// failure code.
///
/// A failure here is the probe's, not the scheduler's: a refused report send or
/// a violated internal precondition. It used to be swallowed by a bare `break`,
/// which lost the code entirely and left the terminal record claiming whatever
/// `probe.outcome()` happened to hold -- `CleanupIncomplete` for a run that never
/// reached cleanup. The caller now classifies it honestly and reports the code.
fn drive(
    probe: &mut SaturationProbe,
    session: &mut Session,
    reporter: &mut Reporter,
) -> Result<ProbeOutcome, u32> {
    let budget = probe.plan().step_budget() + 1;
    for _ in 0..budget {
        let Some(step) = probe.next_step() else { break };
        advance(probe, session, reporter, step)?;
    }
    Ok(probe
        .outcome()
        // A run that exhausted its bounded budget without a terminal outcome is
        // itself a cleanup failure: the plan forbids treating an unbounded run
        // as a pass.
        .unwrap_or(ProbeOutcome::Failed(ProbeFailure::CleanupIncomplete {
            index: probe.admitted_hogs(),
        })))
}

fn advance(
    probe: &mut SaturationProbe,
    session: &mut Session,
    reporter: &mut Reporter,
    step: ProbeStep,
) -> Result<(), u32> {
    match step {
        ProbeStep::LaunchHog { index } => {
            submit_launch(session, HOG_PATH)?;
            if !probe.observe_hog_submitted(index) {
                return Err(PROBE_ERROR_BASE + 0x0010);
            }
            reporter.step(step, 0)
        }
        ProbeStep::AwaitHogAccepted { index } => {
            match await_reply(session, ACCEPT_TIMEOUT_NANOSECONDS)? {
                Reply::Accepted { job_id } => {
                    if !probe.observe_hog_accepted(index, job_id) {
                        return Err(PROBE_ERROR_BASE + 0x0011);
                    }
                    reporter.step(step, job_id)
                }
                Reply::TimedOut => {
                    probe.observe_hog_accept_timeout(index);
                    reporter.failure(ProbeFailure::HogAcceptTimeout { index })
                }
                Reply::Rejected { status } => {
                    probe.observe_hog_rejected(index, status);
                    reporter.failure(ProbeFailure::HogRejected { index, status })
                }
                _ => Err(PROBE_ERROR_BASE + 0x0012),
            }
        }
        ProbeStep::LaunchProgress { after_hog } => {
            submit_launch(session, PROGRESS_PATH)?;
            match await_reply(session, ACCEPT_TIMEOUT_NANOSECONDS)? {
                Reply::Accepted { job_id } => {
                    if !probe.observe_progress_accepted(after_hog, job_id) {
                        return Err(PROBE_ERROR_BASE + 0x0013);
                    }
                    reporter.step(step, job_id)
                }
                // A progress child refused admission while hogs hold the CPUs
                // is a distinct and interesting answer, not a stall.
                Reply::Rejected { status } => {
                    probe.observe_progress_rejected(after_hog, status);
                    reporter.failure(ProbeFailure::ProgressRejected { after_hog, status })
                }
                Reply::TimedOut => {
                    probe.observe_progress_accept_timeout(after_hog);
                    reporter.failure(ProbeFailure::ProgressAcceptTimeout { after_hog })
                }
                _ => Err(PROBE_ERROR_BASE + 0x0014),
            }
        }
        ProbeStep::AwaitProgressResult { after_hog } => {
            let job_id = submit_wait(session, probe, false, after_hog)?;
            match await_reply(session, RESULT_TIMEOUT_NANOSECONDS)? {
                Reply::Result(result) => {
                    let code = if result.normal_zero {
                        0
                    } else if result.application_code != 0 {
                        result.application_code
                    } else {
                        // A non-normal exit with a zero application code would
                        // otherwise be indistinguishable from a pass.
                        u32::MAX
                    };
                    if !probe.observe_progress_result(after_hog, result.job_id, code) {
                        return match probe.outcome() {
                            Some(ProbeOutcome::Failed(failure)) => reporter.failure(failure),
                            _ => Err(PROBE_ERROR_BASE + 0x0015),
                        };
                    }
                    reporter.step(step, result.job_id)
                }
                Reply::TimedOut => {
                    probe.observe_progress_result_timeout(after_hog);
                    reporter.failure(ProbeFailure::ProgressResultTimeout { after_hog })
                }
                Reply::Rejected { status } => {
                    probe.observe_progress_rejected(after_hog, status);
                    reporter.failure(ProbeFailure::ProgressRejected { after_hog, status })
                }
                _ => {
                    let _ = job_id;
                    Err(PROBE_ERROR_BASE + 0x0016)
                }
            }
        }
        ProbeStep::TerminateHog { index } => {
            let job_id = hog_job(probe, index)?;
            let reservation = session.reserve();
            let mut bytes = [0_u8; FRAME_BYTES];
            let size = encode_job_message(reservation, LaunchType::Terminate, job_id, &mut bytes)
                .map_err(|_| PROBE_ERROR_BASE + 0x0017)?;
            send_channel(session.channel, &bytes[..size], &[])
                .map_err(|_| PROBE_ERROR_BASE + 0x0018)?;
            match await_reply_for(session, reservation, RESULT_TIMEOUT_NANOSECONDS)? {
                Reply::TerminationAccepted => {
                    if !probe.observe_hog_terminated(index) {
                        return Err(PROBE_ERROR_BASE + 0x0019);
                    }
                    reporter.step(step, job_id)
                }
                // Cleanup that cannot even be requested is a cleanup failure,
                // never a pass with a note.
                _ => {
                    probe.observe_hog_result(index, 0, u32::MAX);
                    reporter.failure(ProbeFailure::CleanupIncomplete { index })
                }
            }
        }
        ProbeStep::AwaitHogResult { index } => {
            let job_id = submit_wait(session, probe, true, index)?;
            match await_reply(session, RESULT_TIMEOUT_NANOSECONDS)? {
                Reply::Result(result) => {
                    if !probe.observe_hog_result(index, result.job_id, result.cleanup_result) {
                        return match probe.outcome() {
                            Some(ProbeOutcome::Failed(failure)) => reporter.failure(failure),
                            _ => Err(PROBE_ERROR_BASE + 0x001A),
                        };
                    }
                    let _ = job_id;
                    reporter.step(step, result.job_id)
                }
                _ => {
                    probe.observe_hog_result(index, 0, u32::MAX);
                    reporter.failure(ProbeFailure::CleanupIncomplete { index })
                }
            }
        }
        ProbeStep::Complete => reporter.step(step, 0),
    }
}

fn hog_job(probe: &SaturationProbe, index: usize) -> Result<u64, u32> {
    probe.hog_job(index).ok_or(PROBE_ERROR_BASE + 0x001B)
}

fn submit_launch(session: &mut Session, path: &str) -> Result<(), u32> {
    let reservation = session.reserve();
    let mut bytes = [0_u8; FRAME_BYTES];
    let size = encode_launch(reservation, path, &[path], &[], false, &mut bytes)
        .map_err(|_| PROBE_ERROR_BASE + 0x0020)?;
    send_channel(session.channel, &bytes[..size], &[]).map_err(|_| PROBE_ERROR_BASE + 0x0021)?;
    Ok(())
}

fn submit_wait(
    session: &mut Session,
    probe: &SaturationProbe,
    hog: bool,
    index: usize,
) -> Result<u64, u32> {
    let job_id = if hog {
        hog_job(probe, index)?
    } else {
        probe.progress_job().ok_or(PROBE_ERROR_BASE + 0x0022)?
    };
    let reservation = session.reserve();
    let mut bytes = [0_u8; FRAME_BYTES];
    let size = encode_job_message(reservation, LaunchType::Wait, job_id, &mut bytes)
        .map_err(|_| PROBE_ERROR_BASE + 0x0023)?;
    send_channel(session.channel, &bytes[..size], &[]).map_err(|_| PROBE_ERROR_BASE + 0x0024)?;
    Ok(job_id)
}

/// Receives the reply to the most recent reservation.
fn await_reply(session: &mut Session, timeout: u64) -> Result<Reply, u32> {
    let reservation = Reservation {
        connection_id: session.connection_id,
        generation: session.generation,
        transaction_id: session.transaction,
    };
    await_reply_for(session, reservation, timeout)
}

fn await_reply_for(
    session: &Session,
    reservation: Reservation,
    timeout: u64,
) -> Result<Reply, u32> {
    match wait_readable(session.channel, timeout, PROBE_ERROR_BASE + 0x0025) {
        Ok(()) => {}
        Err(code) if code == TIMED_OUT_SENTINEL => return Ok(Reply::TimedOut),
        Err(code) => return Err(code),
    }
    let mut bytes = [0_u8; FRAME_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 4];
    let counts = receive_channel(session.channel, &mut bytes, &mut handles)
        .map_err(|_| PROBE_ERROR_BASE + 0x0026)?;
    // The probe expects no handles on any reply it asks for; accepting one
    // silently would leak a capability into a saturation test.
    if counts.handles != 0 {
        close_received(&handles, counts.handles);
        return Err(PROBE_ERROR_BASE + 0x0027);
    }
    let parsed = parse_message(&bytes[..counts.bytes], 0).map_err(|_| PROBE_ERROR_BASE + 0x0028)?;
    if parsed.reservation != reservation {
        return Err(PROBE_ERROR_BASE + 0x0029);
    }
    Ok(match parsed.message {
        LaunchMessage::LaunchAccepted { job_id } => Reply::Accepted { job_id },
        LaunchMessage::TerminationAccepted { .. } => Reply::TerminationAccepted,
        LaunchMessage::JobResult { job_id, result } => Reply::Result(JobResult {
            job_id,
            normal_zero: result.classification == TerminationClassification::NormalExit
                && result.application_code == 0
                && result.exception_class == 0
                && result.exception_detail == 0
                && result.exception_address == 0
                && result.cleanup_result == 0,
            application_code: result.application_code,
            cleanup_result: result.cleanup_result,
        }),
        LaunchMessage::Error { code } => Reply::Rejected {
            status: code as u32,
        },
        _ => return Err(PROBE_ERROR_BASE + 0x002A),
    })
}

/// Distinguishes "no reply inside the bound" from every other transport
/// failure. Reporting a generic error as a timeout is exactly the vagueness the
/// R1 gate exists to eliminate.
const TIMED_OUT_SENTINEL: u32 = PROBE_ERROR_BASE + 0x0FFF;

/// Whether a native error is the channel saying "no room right now".
///
/// The kernel maps both a full peer queue and an exhausted payload pool to this
/// one status, so userspace cannot tell which refused -- and does not need to:
/// waiting and retrying is correct for both.
fn is_would_block(error: NativeError) -> bool {
    matches!(error, NativeError::Status(status) if status == DW_STATUS_WOULD_BLOCK)
}

fn wait_readable(channel: DwHandle, timeout: u64, code: u32) -> Result<(), u32> {
    let deadline = monotonic_deadline_after(timeout).map_err(|_| code)?;
    match wait_one(channel, DwSignals(DW_SIGNAL_READABLE.0), deadline) {
        Ok(_) => Ok(()),
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {
            Err(TIMED_OUT_SENTINEL)
        }
        Err(_) => Err(code),
    }
}

fn validate_fresh(
    info: DwReceivedHandleInfoV1,
    expected_type: deepwyrm_syscall::DwObjectType,
    expected_rights: DwRights,
) -> Result<(), ()> {
    let observed = query_capability_info(info.handle).map_err(|_| ())?;
    if observed.object_type != expected_type || observed.rights != expected_rights {
        return Err(());
    }
    Ok(())
}

fn close_received(handles: &[DwReceivedHandleInfoV1], count: usize) {
    for info in handles.iter().take(count) {
        let _ = close_handle(info.handle);
    }
}

wyrmroot_runtime::native_entry!(crate::probe_main);

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    panic_abort()
}

fn plan_from_arguments(startup: &StartupBlock<'_>) -> Result<ProbePlan, u32> {
    // argv[0] is the program name; the plan is the two arguments after it.
    if startup.argc() != 3 {
        return Err(PROBE_ERROR_BASE + 0x000C);
    }
    let hogs = startup.arg(1).ok_or(PROBE_ERROR_BASE + 0x000D)?;
    let cpus = startup.arg(2).ok_or(PROBE_ERROR_BASE + 0x000D)?;
    launch_parameters::parse_plan(&[hogs.as_str(), cpus.as_str()])
        .map_err(|_| PROBE_ERROR_BASE + 0x000E)
}

fn correlation_from_environment(startup: &StartupBlock<'_>) -> Result<(u64, u64), u32> {
    if startup.envc() != 3 {
        return Err(PROBE_ERROR_BASE + 0x000F);
    }
    let entries = [
        startup.env(0).ok_or(PROBE_ERROR_BASE + 0x000F)?.as_str(),
        startup.env(1).ok_or(PROBE_ERROR_BASE + 0x000F)?.as_str(),
        startup.env(2).ok_or(PROBE_ERROR_BASE + 0x000F)?.as_str(),
    ];
    let correlation =
        parse_correlation_environment(&entries).map_err(|_| PROBE_ERROR_BASE + 0x000F)?;
    if correlation.endpoint_id == 0 || correlation.endpoint_generation == 0 {
        return Err(PROBE_ERROR_BASE + 0x000F);
    }
    Ok((correlation.endpoint_id, correlation.endpoint_generation))
}
