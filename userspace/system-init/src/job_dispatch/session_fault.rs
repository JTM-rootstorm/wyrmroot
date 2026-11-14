//! Faults that end a launch session instead of ending the supervisor.
//!
//! Permanent init's process is the system: an `Err` out of the resident tick
//! is REBOOT_REQUIRED. A launch session's client is not init. Whatever it
//! does on its own Channel -- bytes that are no WRLJ request, more handles
//! than a request may carry, a reply queue it never drains, an end it closed
//! mid-request -- is that client's fault and costs that client its session.
//! The session is retired by the same route as one whose peer closed: its
//! Channel is closed, a launch it left parked is rolled back, and its jobs
//! follow the orphan policy (`WYR1_B_REGISTRY_LAUNCH_CONTRACT.md` 9.4).
//!
//! What stays fatal is init's own substrate: a cleanup that did not happen
//! (a handle nobody can name any more), the job model disagreeing with
//! itself, and init's own bootfs or policy failing to map or parse.

use super::*;
use deepwyrm_syscall::{
    DW_SIGNAL_WRITABLE, DW_STATUS_ACCESS_DENIED, DW_STATUS_ALREADY_EXISTS, DW_STATUS_BAD_ADDRESS,
    DW_STATUS_BAD_HANDLE, DW_STATUS_BAD_STATE, DW_STATUS_BUFFER_TOO_SMALL, DW_STATUS_INTERRUPTED,
    DW_STATUS_INVALID_ARGUMENT, DW_STATUS_NO_MEMORY, DW_STATUS_NO_RESOURCES, DW_STATUS_NOT_FOUND,
    DW_STATUS_NOT_SUPPORTED, DW_STATUS_PEER_CLOSED, DW_STATUS_SUCCESS, DW_STATUS_WOULD_BLOCK,
    DW_STATUS_WRONG_OBJECT_TYPE, DwStatus,
};

/// How long a session may leave its reply queue full before it is retired.
///
/// A full queue is backpressure, not a fault: init can owe one session a
/// deferred-launch reply, a dispatched reply and a WAIT result in one tick,
/// and the kernel queues two. The replies wait; what does not wait for ever
/// is init. The budget is the one every other answer init waits for has, the
/// READY timeout.
pub(crate) const REPLY_PATIENCE_NS: u64 = WYR0_I_SUPERVISION_POLICY.ready_timeout_ns;

/// The size of an `ERROR`, a job message, a `VERSION` or a `JOB_RESULT`.
pub(crate) const JOB_REPLY_BYTES: usize = 88;
/// The size of the longest `JOB_LIST` the protocol admits.
pub(crate) const JOB_LIST_REPLY_BYTES: usize = 56 + 8 * wyrmroot_launch_proto::MAX_LIVE_JOBS;

/// The largest reply init can owe any launch session, whichever encoder
/// wrote it. A held reply is this size, and so is the dispatcher's reply
/// buffer.
pub(crate) const MAX_REPLY_BYTES: usize = {
    let mut largest = JOB_REPLY_BYTES;
    if JOB_LIST_REPLY_BYTES > largest {
        largest = JOB_LIST_REPLY_BYTES;
    }
    if wyrmroot_launch_proto::SHELL_V1_REPLY_BYTES > largest {
        largest = wyrmroot_launch_proto::SHELL_V1_REPLY_BYTES;
    }
    largest
};
const _: () = assert!(
    JOB_REPLY_BYTES <= MAX_REPLY_BYTES
        && JOB_LIST_REPLY_BYTES <= MAX_REPLY_BYTES
        && wyrmroot_launch_proto::SHELL_V1_REPLY_BYTES <= MAX_REPLY_BYTES
        && MAX_REPLY_BYTES <= u16::MAX as usize
);

/// Which Channel operation a kernel status came back from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChannelOperation {
    Send,
    Receive,
}

/// What the far end of a Channel can do to an operation on this end.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PeerCause {
    /// It closed its end.
    Closed,
    /// It has not drained what it was already sent.
    QueueFull,
    /// It sent a message with more bytes or handles than the receiver takes.
    MessageTooLarge,
}

/// Whether the peer of a Channel can have caused `error`, and how.
///
/// This is the whole of what a client may be blamed for. `None` is init's
/// own: malformed kernel output (a pinned-ABI breach), a handle or right
/// init no longer has, init's own memory or handle table running out, and
/// any status this table does not name.
pub(crate) const fn peer_cause(
    operation: ChannelOperation,
    error: NativeError,
) -> Option<PeerCause> {
    let status = match error {
        NativeError::Output(_) => return None,
        NativeError::Status(status) => status,
    };
    match (status, operation) {
        (DW_STATUS_PEER_CLOSED, ChannelOperation::Send | ChannelOperation::Receive) => {
            Some(PeerCause::Closed)
        }
        (DW_STATUS_WOULD_BLOCK, ChannelOperation::Send) => Some(PeerCause::QueueFull),
        // Nothing to receive on a Channel just seen readable is not
        // something its peer can arrange.
        (DW_STATUS_WOULD_BLOCK, ChannelOperation::Receive) => None,
        (DW_STATUS_BUFFER_TOO_SMALL, ChannelOperation::Receive) => Some(PeerCause::MessageTooLarge),
        (DW_STATUS_BUFFER_TOO_SMALL, ChannelOperation::Send) => None,
        (
            DW_STATUS_SUCCESS
            | DW_STATUS_INVALID_ARGUMENT
            | DW_STATUS_BAD_HANDLE
            | DW_STATUS_WRONG_OBJECT_TYPE
            | DW_STATUS_ACCESS_DENIED
            | DW_STATUS_BAD_STATE
            | DW_STATUS_NOT_FOUND
            | DW_STATUS_ALREADY_EXISTS
            | DW_STATUS_TIMED_OUT
            | DW_STATUS_INTERRUPTED
            | DW_STATUS_NO_MEMORY
            | DW_STATUS_NO_RESOURCES
            | DW_STATUS_NOT_SUPPORTED
            | DW_STATUS_BAD_ADDRESS,
            ChannelOperation::Send | ChannelOperation::Receive,
        ) => None,
        // A status the ABI this was built against does not define.
        (DwStatus(_), ChannelOperation::Send | ChannelOperation::Receive) => None,
    }
}

/// What a session's client did that ended its session.
///
/// Carried to the poll's report. Init has no reader's channel for a session
/// it retires and survives -- its only one is the exit status it dies with
/// -- so this is where the instance lives
/// (`DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` 3.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FaultCause {
    /// A queued request has more bytes or handles than any request carries;
    /// the kernel would not deliver it.
    RequestTooLarge,
    /// The peer closed between the request becoming readable and its
    /// receive.
    ClosedBeforeReceive,
    /// A received request claims more bytes than the buffer it came in.
    OversizedBytes,
    /// A received request claims more handles than the buffer it came in.
    OversizedHandles,
    /// Neither WRLJ envelope parses, so no reply can name the request.
    UnparseablePrefix,
    /// A reply was refused with this status: the peer closed, or its queue
    /// was full for a reply that cannot wait.
    ReplyUndeliverable(DwStatus),
    /// The reply queue stayed full for [`REPLY_PATIENCE_NS`].
    ReplyQueueNeverDrained,
    /// The queue was full for a reply larger than a session can have held.
    /// No reply init encodes today is; one that ever is costs its session
    /// and not init.
    ReplyTooLargeToHold,
}

/// One reply init still owes a session whose queue was full.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HeldReply {
    bytes: [u8; MAX_REPLY_BYTES],
    len: u16,
}

impl HeldReply {
    fn new(reply: &[u8]) -> Option<Self> {
        let mut bytes = [0; MAX_REPLY_BYTES];
        bytes.get_mut(..reply.len())?.copy_from_slice(reply);
        Some(Self {
            bytes,
            len: reply.len() as u16,
        })
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// Why a reply did not reach its session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReplyError {
    /// The reply could not be encoded. That is init's own arithmetic; the
    /// client had no part in it.
    Encode,
    /// The session's queue is full. The reply is staged in the dispatcher
    /// for whoever holds it.
    QueueFull,
    /// The peer is gone.
    PeerClosed,
    /// The kernel refused the send for a reason no peer can cause.
    Native(NativeError),
}

/// Sends one reply on a session Channel.
pub(crate) fn send_session_reply<S: InitPlatform>(
    system: &mut S,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    reply: &[u8],
) -> Result<(), ReplyError> {
    let Err(error) = system.send_channel(session, reply) else {
        return Ok(());
    };
    match peer_cause(ChannelOperation::Send, error) {
        Some(PeerCause::QueueFull) => {
            // `None` for a reply too large to hold, which `hold_reply`
            // turns into the session's fault.
            jobs.staged_reply = HeldReply::new(reply);
            Err(ReplyError::QueueFull)
        }
        Some(PeerCause::Closed) => Err(ReplyError::PeerClosed),
        Some(PeerCause::MessageTooLarge) | None => Err(ReplyError::Native(error)),
    }
}

/// How one request failed to be dispatched.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum DispatchError {
    /// The session's client broke the protocol or cannot be answered. The
    /// request's received handles are already closed; the caller retires the
    /// session and the tick goes on.
    Client(FaultCause),
    /// The request was dispatched and its reply found the queue full. The
    /// reply is staged; the caller holds it for the session.
    ReplyHeld,
    /// Init's own substrate failed.
    Fatal(InitError),
}

impl From<InitError> for DispatchError {
    fn from(error: InitError) -> Self {
        Self::Fatal(error)
    }
}

impl From<ReplyError> for DispatchError {
    fn from(error: ReplyError) -> Self {
        match error {
            ReplyError::Encode => Self::Fatal(InitError::Accounting),
            ReplyError::QueueFull => Self::ReplyHeld,
            ReplyError::PeerClosed => {
                Self::Client(FaultCause::ReplyUndeliverable(DW_STATUS_PEER_CLOSED))
            }
            ReplyError::Native(error) => Self::Fatal(InitError::Native(error)),
        }
    }
}

/// Whether a reply init owes a session can be sent this tick.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReplyGate {
    /// The queue has room.
    Open,
    /// The queue is full, or an earlier reply is still held. The reply
    /// stays where it is -- a pending WAIT pending, a parked launch parked.
    Blocked,
    /// The queue has been full for [`REPLY_PATIENCE_NS`].
    Expired,
}

/// Asks whether `grant`'s session can take a reply now, without waiting.
pub(crate) fn reply_gate<S: ResidentPlatform>(
    system: &mut S,
    jobs: &mut JobDispatcher,
    grant: EndpointGrant,
    now_ns: u64,
) -> Result<ReplyGate, InitError> {
    let session = jobs.session_mut(grant).map_err(InitError::Jobs)?;
    if session.held_reply.is_none() {
        let item = DwWaitItemV1 {
            handle: session.channel,
            signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_WRITABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        };
        match system.wait_many(core::slice::from_ref(&item), DwDeadline(now_ns)) {
            // Room, or a peer that is gone -- which the send itself reports.
            Ok(_) => {
                session.blocked_since = None;
                return Ok(ReplyGate::Open);
            }
            Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {}
            Err(error) => return Err(InitError::Native(error)),
        }
    }
    let since = *session.blocked_since.get_or_insert(now_ns);
    Ok(if now_ns.saturating_sub(since) >= REPLY_PATIENCE_NS {
        ReplyGate::Expired
    } else {
        ReplyGate::Blocked
    })
}

/// Holds the staged reply for a session whose queue was full.
///
/// A session has one slot. Init stops reading its requests while the slot
/// is taken, so a second reply can only be one it owed already -- to a
/// client with two replies unread and a third request sent, which is past
/// what the queue the protocol runs over allows.
pub(crate) fn hold_reply(
    jobs: &mut JobDispatcher,
    grant: EndpointGrant,
    now_ns: u64,
) -> Result<(), FaultCause> {
    let staged = jobs.staged_reply.take();
    let Ok(session) = jobs.session_mut(grant) else {
        // Nobody left to hold it for.
        return Ok(());
    };
    let Some(reply) = staged else {
        return Err(FaultCause::ReplyTooLargeToHold);
    };
    if session.held_reply.is_some() {
        return Err(FaultCause::ReplyUndeliverable(DW_STATUS_WOULD_BLOCK));
    }
    session.held_reply = Some(reply);
    session.blocked_since.get_or_insert(now_ns);
    Ok(())
}

/// Settles a reply to a session outside the dispatch of its own request:
/// delivered, held for a full queue, or -- `Ok(Some(_))` -- refused in a way
/// that costs the client its session, which the caller retires.
pub(crate) fn settle_reply(
    jobs: &mut JobDispatcher,
    grant: EndpointGrant,
    reply: Result<(), ReplyError>,
    now_ns: u64,
) -> Result<Option<FaultCause>, InitError> {
    match reply {
        Ok(()) => Ok(None),
        Err(ReplyError::Encode) => Err(InitError::Accounting),
        Err(ReplyError::Native(error)) => Err(InitError::Native(error)),
        Err(ReplyError::PeerClosed) => {
            Ok(Some(FaultCause::ReplyUndeliverable(DW_STATUS_PEER_CLOSED)))
        }
        Err(ReplyError::QueueFull) => Ok(hold_reply(jobs, grant, now_ns).err()),
    }
}

/// Retires one launch session and everything that depended on it being
/// there.
///
/// This is what the dispatcher has always done for a session whose peer
/// closed, and a session ended for its client's fault is retired the same
/// way: the launch it left parked is rolled back unannounced (R6C), its image
/// read is abandoned, its Channel and owner are released, the shell it was
/// the job session of is ended, and its running jobs become orphans, bounded
/// by F4 WYR1-F4-M1.
///
/// An `Err` here is a cleanup that did not complete or a job model that
/// contradicts itself. Both leave init holding resources it cannot name,
/// which is the one condition a client may not be blamed for.
pub(crate) fn retire_session<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    grant: EndpointGrant,
    scope: LaunchSessionScope,
) -> Result<(), InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    // R6C's cancel. The peer that asked for this launch is gone before it was
    // told the child exists, so nothing owns the child and nothing is owed a
    // reply. Rolling it back here rather than leaving it to its deadline
    // means the session's resources and its child's go in one step -- and
    // means the slot is not still holding a Channel this is about to close.
    cancel_parked_launch(system, waits, jobs, grant)?;
    let image_cleanup_failed = crate::image_launch::cancel_parked_image(system, jobs, Some(grant));
    let outer = if scope == LaunchSessionScope::ConsoleLauncher {
        jobs.jobs
            .loaded_job_for_owner(grant.endpoint_id, grant.endpoint_generation)
            .map_err(InitError::Jobs)?
    } else {
        None
    };
    let disconnected = jobs
        .disconnect_owned_session(grant)
        .map_err(InitError::Jobs)?;
    let mut failed = image_cleanup_failed
        | system.close_handle(disconnected.channel).is_err()
        | cleanup_session_owner(system, waits, disconnected.owner, true)
        | disconnected.outer_job.is_some_and(|job_id| {
            let loaded = jobs.jobs.loaded_job(job_id);
            loaded.map_or(true, |loaded| {
                force_cleanup_job(system, waits, jobs, loaded).is_err()
            })
        });
    if let Some(outer) = outer {
        failed |= cleanup_shell_before_publication(system, waits, jobs, outer).is_err();
    }
    failed |= retire_excess_orphans(system, jobs)?;
    if failed {
        return Err(InitError::Cleanup);
    }
    Ok(())
}

/// One session retired for its client's fault, and what the fault was.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SessionFault {
    pub(crate) grant: EndpointGrant,
    pub(crate) scope: LaunchSessionScope,
    pub(crate) cause: FaultCause,
}

/// What one poll of the dispatcher did to its sessions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JobDispatcherPoll {
    /// The retirement the caller reconciles its console state against.
    pub(crate) outcome: JobDispatcherPollOutcome,
    /// The first session this poll retired for its client's fault. A poll
    /// can retire more than one session and `outcome` names one; a fault is
    /// kept here whatever else happened, because with the registry poisoned
    /// a fault is a recovery and must not be lost behind a clean close.
    pub(crate) fault: Option<SessionFault>,
}

impl JobDispatcherPoll {
    pub(crate) const STABLE: Self = Self {
        outcome: JobDispatcherPollOutcome::Stable,
        fault: None,
    };

    /// Records a session closed by its peer.
    pub(crate) fn closed(&mut self, grant: EndpointGrant, scope: LaunchSessionScope) {
        self.retired(
            JobDispatcherPollOutcome::SessionClosed { grant, scope },
            scope,
        );
    }

    /// Records a session retired for its client's fault.
    pub(crate) fn faulted(&mut self, fault: SessionFault) {
        self.fault.get_or_insert(fault);
        self.retired(
            JobDispatcherPollOutcome::SessionFaulted {
                grant: fault.grant,
                scope: fault.scope,
                cause: fault.cause,
            },
            fault.scope,
        );
    }

    /// The console launcher's retirement is the one the caller acts on (it
    /// relaunches the console), so a shell's never displaces it; otherwise
    /// the first is kept.
    fn retired(&mut self, retired: JobDispatcherPollOutcome, scope: LaunchSessionScope) {
        let console_recorded = match self.outcome {
            JobDispatcherPollOutcome::Stable => {
                self.outcome = retired;
                return;
            }
            JobDispatcherPollOutcome::SessionClosed { scope, .. }
            | JobDispatcherPollOutcome::SessionFaulted { scope, .. } => {
                scope == LaunchSessionScope::ConsoleLauncher
            }
        };
        if !console_recorded && scope == LaunchSessionScope::ConsoleLauncher {
            self.outcome = retired;
        }
    }
}
