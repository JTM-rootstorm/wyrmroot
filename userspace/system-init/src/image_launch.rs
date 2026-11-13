//! LAUNCH_IMAGE: a shell job whose executable is a file (root
//! `STORAGE_PLAN.md` W6).
//!
//! The shell opens the file through vfsd and moves its WRFS Channel to init
//! with a three-stream LAUNCH_IMAGE, followed by a WRNS connection to vfsd
//! that init passes to the job untouched as its namespace (WRLP 1.13, root
//! `TOOLCHAIN_POSIX_LAYER_DESIGN.md` W5). Init never uses the namespace. Init
//! reads the whole file, at most [`MAX_IMAGE_BYTES`] and within
//! [`IMAGE_READ_TIMEOUT_NS`], into private memory no other process can reach,
//! constructs the job from those bytes exactly as it would a bootfs JobV2
//! payload, and drops the copy. The job gets the same TaskGroup limits and
//! stream contract as `bin/hello`.
//!
//! A file runs without a launch-policy identity: the recovery shell's
//! operator may run what the mounted filesystems hold. Bootfs payloads keep
//! their identity check.
//!
//! # The read never holds the supervisor
//!
//! The file Channel comes from the client, and nothing says who is at its
//! other end: a slow filesystem, a dead one, or the requester itself. So init
//! never waits on it. The request is parked in the dispatcher
//! ([`ParkedImageLaunch`]) and the read is a state machine the resident loop
//! advances between ticks ([`service_image_launch`]): one WRFS request is
//! outstanding at a time, each step is a non-blocking poll of the file
//! Channel, and the only clock is the loop's own. A peer that answers slowly
//! is read over as many ticks as it takes; one that never answers costs the
//! launch at its deadline and costs init nothing in between -- exits are
//! detected, recovery runs and every other session is served while it is
//! silent.
//!
//! One image is read at a time. A second LAUNCH_IMAGE while one is in flight
//! is refused with `ERROR` code 6, capacity
//! (`WYR1_B_REGISTRY_LAUNCH_CONTRACT.md` 9.5).
//!
//! # Where the bytes live
//!
//! Init has no allocator. The image is read into the scratch region the
//! resident loop maps for exactly this read
//! (`ResidentPlatform::with_private_memory`) and holds across the ticks the
//! read takes; the region is unmapped when the launch is constructed or
//! fails. The request itself -- path, argv, environment -- has to outlive
//! the dispatch frame that received it, and waits in a read-only memory
//! object only init holds a handle to.

use crate::job_sessions::{JobDispatcher, LaunchSessionScope};
use crate::jobs::{EndpointGrant, RequestTicket};
use crate::*;
use deepwyrm_syscall::{DW_RIGHT_MAP, DW_RIGHT_READ, DW_SIGNAL_READABLE};
use wyrmroot_fs_proto::node::{self, Body, Kind, MAX_IO_BYTES};
use wyrmroot_fs_proto::{Error as FsError, MAX_HANDLES as FS_MAX_HANDLES, Status};
use wyrmroot_launch_proto::{
    ErrorCode as LaunchErrorCode, LAUNCH_IMAGE_HANDLE_COUNT, Message as LaunchMessage,
    Reservation as LaunchReservation, parse_message as parse_launch_message,
};

/// The largest executable a file launch reads.
pub(crate) const MAX_IMAGE_BYTES: u64 = 8 * 1024 * 1024;
/// How long reading one image may take, in total, by the resident loop's
/// clock.
pub(crate) const IMAGE_READ_TIMEOUT_NS: u64 = 10_000_000_000;
/// The rights init keeps on the parked request's memory object: enough to
/// map it read-only again, and nothing that could pass it on.
const PARKED_REQUEST_RIGHTS: DwRights = DwRights(DW_RIGHT_READ.0 | DW_RIGHT_MAP.0);
/// Where the file and the namespace sit among a LAUNCH_IMAGE's handles.
const FILE_INDEX: usize = 3;

/// How far one image read has got.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ImageStage {
    /// GETATTR is outstanding.
    AwaitingAttr,
    /// The size is known and the read has no memory yet.
    AwaitingScratch { size: usize },
    /// A READ of `length` bytes at `offset` is outstanding.
    Reading {
        size: usize,
        offset: usize,
        length: usize,
    },
}

/// One LAUNCH_IMAGE between its request and its child.
///
/// Everything the launch still needs once the frame that read the request
/// has returned: the envelope its reply must repeat (9.5), the five handles
/// the request moved in, and where the read has got to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ParkedImageLaunch {
    grant: EndpointGrant,
    session: DwHandle,
    scope: LaunchSessionScope,
    reservation: LaunchReservation,
    ticket: RequestTicket,
    /// The three streams, the file, the namespace, as received.
    handles: [DwHandle; LAUNCH_IMAGE_HANDLE_COUNT],
    /// The request's bytes, in a read-only memory object only init can name.
    request: DwHandle,
    request_bytes: u64,
    /// When the read is given up, by the resident loop's clock.
    deadline_ns: u64,
    /// The WRFS transaction of the outstanding request.
    transaction: u64,
    stage: ImageStage,
}

impl ParkedImageLaunch {
    const fn file(&self) -> DwHandle {
        self.handles[FILE_INDEX]
    }

    /// The memory object holding the parked request, for tests that check
    /// it is released.
    #[cfg(test)]
    pub(crate) const fn request_handle(&self) -> DwHandle {
        self.request
    }

    /// Closes everything this launch holds. Returns whether a close failed.
    fn release<S: InitPlatform>(&self, system: &mut S) -> bool {
        let mut failed = system.close_handle(self.request).is_err();
        for handle in self.handles.iter().rev() {
            failed |= system.close_handle(*handle).is_err();
        }
        failed
    }
}

/// What the image read needs from the resident loop next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ImageService {
    /// No image is being read.
    Idle,
    /// A WRFS reply is outstanding on `file`. The loop may sleep on it, but
    /// no later than its own next tick. `holds_scratch` says whether the
    /// read is using the scratch region, which must then stay mapped.
    Waiting { file: DwHandle, holds_scratch: bool },
    /// The read needs `bytes` of private scratch memory before it can go on.
    NeedsScratch { bytes: u64 },
}

/// How a step on the image's file Channel failed.
///
/// The Channel is the client's, and so is everything its peer can do to it;
/// that costs the launch. What no peer can cause is init's own.
enum FileFault {
    Launch(LaunchErrorCode),
    Fatal(InitError),
}

fn file_fault(operation: ChannelOperation, error: NativeError) -> FileFault {
    match peer_cause(operation, error) {
        Some(PeerCause::Closed | PeerCause::QueueFull | PeerCause::MessageTooLarge) => {
            FileFault::Launch(LaunchErrorCode::LoaderFailure)
        }
        None => FileFault::Fatal(InitError::Native(error)),
    }
}

/// Sends one WRFS request on the image's file Channel.
fn send_file_request<S: ResidentPlatform>(
    system: &mut S,
    file: DwHandle,
    transaction_id: u64,
    body: Body<'_>,
) -> Result<(), FileFault> {
    let mut bytes = [0u8; 64];
    let size = match node::encode(
        &node::Message {
            transaction_id,
            body,
        },
        &mut bytes,
    ) {
        Ok(size) => size,
        // Init's own request did not fit init's own buffer.
        Err(
            FsError::WrongSize
            | FsError::WrongMagic
            | FsError::WrongVersion
            | FsError::UnknownMessage
            | FsError::WrongHandleCount
            | FsError::ZeroTransaction
            | FsError::NonzeroReserved
            | FsError::UnknownFlags
            | FsError::UnknownStatus
            | FsError::InvalidField
            | FsError::InvalidPath,
        ) => return Err(FileFault::Fatal(InitError::Accounting)),
    };
    system
        .send_channel(file, &bytes[..size])
        .map_err(|error| file_fault(ChannelOperation::Send, error))
}

/// Parks one LAUNCH_IMAGE and asks the file for its size.
///
/// `received` holds the three streams, the file and the namespace. On every
/// refusal all five are closed before the reply. Nothing here waits: the
/// reply to GETATTR is collected by [`service_image_launch`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn begin_image_launch<S: ResidentPlatform>(
    system: &mut S,
    authority: LoadAuthority,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    grant: EndpointGrant,
    scope: LaunchSessionScope,
    reservation: LaunchReservation,
    ticket: RequestTicket,
    request: &[u8],
    received: &[DwReceivedHandleInfoV1],
) -> Result<JobDispatchOutcome, DispatchError> {
    if received.len() != LAUNCH_IMAGE_HANDLE_COUNT {
        return Err(DispatchError::Fatal(InitError::Accounting));
    }
    let mut handles = [DwHandle(0); LAUNCH_IMAGE_HANDLE_COUNT];
    for (slot, info) in handles.iter_mut().zip(received) {
        *slot = info.handle;
    }
    let file = handles[FILE_INDEX];
    let refuse = |system: &mut S, jobs: &mut JobDispatcher, code: LaunchErrorCode| {
        if close_received_reverse(system, received, received.len()) {
            return Err(DispatchError::Fatal(InitError::Cleanup));
        }
        send_observed_job_error(system, jobs, session, reservation, code)?;
        Ok(JobDispatchOutcome::Responded)
    };
    if !scope.admits_image_launch() || validate_controller_channel(system, file).is_err() {
        return refuse(system, jobs, LaunchErrorCode::PolicyRejected);
    }
    // One image at a time: the scratch region is one mapping.
    if jobs.image.is_some() {
        return refuse(system, jobs, LaunchErrorCode::Capacity);
    }
    // WRLJ is request/response. A session whose bootfs launch is still
    // awaiting READY has no second launch to make; the arena would refuse it
    // once the image was read, and refusing it now costs no read.
    if jobs.launches.session_transaction(grant).is_some() {
        return refuse(system, jobs, LaunchErrorCode::InvalidState);
    }
    // Init's own clock failing is init's failure, not the launch's.
    let now_ns = match system.now() {
        Ok(now_ns) => now_ns,
        Err(error) => {
            let _ = close_received_reverse(system, received, received.len());
            return Err(DispatchError::Fatal(InitError::Native(error)));
        }
    };
    let Some(deadline_ns) = now_ns.checked_add(IMAGE_READ_TIMEOUT_NS) else {
        let _ = close_received_reverse(system, received, received.len());
        return Err(DispatchError::Fatal(InitError::Accounting));
    };
    let parked_request = match system.materialize_read_only_memory(
        authority.parent_root,
        request,
        PARKED_REQUEST_RIGHTS,
    ) {
        Ok(parked_request) => parked_request,
        Err(error) => return refuse(system, jobs, native_launch_error_code(error)),
    };
    let transaction = 1;
    if let Err(fault) = send_file_request(system, file, transaction, Body::GetAttr) {
        if system.close_handle(parked_request).is_err() {
            let _ = close_received_reverse(system, received, received.len());
            return Err(DispatchError::Fatal(InitError::Cleanup));
        }
        return match fault {
            FileFault::Launch(code) => refuse(system, jobs, code),
            FileFault::Fatal(error) => {
                let _ = close_received_reverse(system, received, received.len());
                Err(DispatchError::Fatal(error))
            }
        };
    }
    jobs.image = Some(ParkedImageLaunch {
        grant,
        session,
        scope,
        reservation,
        ticket,
        handles,
        request: parked_request,
        request_bytes: request.len() as u64,
        deadline_ns,
        transaction,
        stage: ImageStage::AwaitingAttr,
    });
    Ok(JobDispatchOutcome::ImageParked)
}

/// Abandons the image read `grant`'s session left parked -- or whichever is
/// parked, for `None` -- closing what it holds and replying to no one.
/// Returns whether a close failed.
pub(crate) fn cancel_parked_image<S: InitPlatform>(
    system: &mut S,
    jobs: &mut JobDispatcher,
    grant: Option<EndpointGrant>,
) -> bool {
    match jobs.image {
        Some(parked) if grant.is_none_or(|grant| grant == parked.grant) => {
            jobs.image = None;
            parked.release(system)
        }
        Some(_) | None => false,
    }
}

/// Fails the parked image launch back to its client with `code`.
///
/// Everything the launch held is closed first. A reply the session has no
/// room for is held for it; a client that cannot be told loses its session;
/// only a close that failed, or a kernel refusal no peer can cause, is
/// init's own.
pub(crate) fn fail_parked_image<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    code: LaunchErrorCode,
    now_ns: u64,
) -> Result<(), InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let Some(parked) = jobs.image.take() else {
        return Ok(());
    };
    if parked.release(system) {
        return Err(InitError::Cleanup);
    }
    let reply = send_observed_job_error(system, jobs, parked.session, parked.reservation, code);
    answer_or_retire(system, waits, jobs, &parked, reply, now_ns)
}

/// Settles a reply to the image launch's session: delivered, held for a
/// full queue, or the session that cannot be told is retired -- and the
/// fault left for the next poll to report.
fn answer_or_retire<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    parked: &ParkedImageLaunch,
    reply: Result<(), ReplyError>,
    now_ns: u64,
) -> Result<(), InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let Some(cause) = settle_reply(jobs, parked.grant, reply, now_ns)? else {
        return Ok(());
    };
    if jobs.session_handle(parked.grant) == Ok(parked.session) {
        retire_session(system, waits, jobs, parked.grant, parked.scope)?;
        jobs.image_fault.get_or_insert(SessionFault {
            grant: parked.grant,
            scope: parked.scope,
            cause,
        });
    }
    Ok(())
}

/// Where one step left the read.
enum ReadStep {
    /// Still in flight; this is what the loop needs next.
    InFlight(ImageService),
    /// It failed, for this reply to the client.
    Failed(LaunchErrorCode),
    /// The last byte is in the scratch region.
    Complete { size: usize },
}

/// Advances the parked image read by at most one WRFS reply, without
/// waiting.
///
/// `scratch` is the region the resident loop mapped for this read, once
/// [`ImageService::NeedsScratch`] asked for it. A failed read is answered
/// with the launch protocol's own codes and returns `Idle`; `Err` is only a
/// cleanup that did not happen, a kernel refusal no peer can cause, or
/// init's own bootfs failing.
#[allow(clippy::too_many_arguments)]
pub(crate) fn service_image_launch<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    jobs: &mut JobDispatcher,
    now_ns: u64,
    mut scratch: Option<&mut [u8]>,
) -> Result<ImageService, InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let Some(parked) = jobs.image else {
        return Ok(ImageService::Idle);
    };
    // The session went some other way than through `retire_session`. Nothing
    // is owed a reply.
    if jobs.session_handle(parked.grant) != Ok(parked.session) {
        return if cancel_parked_image(system, jobs, None) {
            Err(InitError::Cleanup)
        } else {
            Ok(ImageService::Idle)
        };
    }
    let step = if now_ns >= parked.deadline_ns {
        ReadStep::Failed(LaunchErrorCode::LoaderFailure)
    } else {
        advance_image_read(system, jobs, parked, now_ns, scratch.as_deref_mut())?
    };
    match step {
        ReadStep::InFlight(service) => Ok(service),
        ReadStep::Failed(code) => {
            fail_parked_image(system, waits, jobs, code, now_ns).map(|()| ImageService::Idle)
        }
        ReadStep::Complete { size } => match scratch.and_then(|scratch| scratch.get(..size)) {
            Some(image) => {
                jobs.image = None;
                launch_read_image(
                    system, loader, waits, authority, jobs, parked, image, now_ns,
                )
                .map(|()| ImageService::Idle)
            }
            None => fail_parked_image(system, waits, jobs, LaunchErrorCode::LoaderFailure, now_ns)
                .map(|()| ImageService::Idle),
        },
    }
}

/// One step of the read itself: at most one reply received and one request
/// sent.
///
/// Its own frame, deliberately. The WRFS reply buffer is 8 KiB and is dead
/// when this returns, so it is not on the stack beneath the launch's
/// construction -- the bootfs mapping, the policy and the loader -- which is
/// the deepest path the read has.
#[inline(never)]
fn advance_image_read<S: ResidentPlatform>(
    system: &mut S,
    jobs: &mut JobDispatcher,
    parked: ParkedImageLaunch,
    now_ns: u64,
    scratch: Option<&mut [u8]>,
) -> Result<ReadStep, InitError> {
    let file = parked.file();
    let waiting = |holds_scratch| {
        ReadStep::InFlight(ImageService::Waiting {
            file,
            holds_scratch,
        })
    };
    let request = |system: &mut S, jobs: &mut JobDispatcher, size: usize, offset: usize| {
        let length = (size - offset).min(MAX_IO_BYTES);
        let transaction = parked.transaction + 1;
        match send_file_request(
            system,
            file,
            transaction,
            Body::Read {
                offset: offset as u64,
                length: length as u32,
            },
        ) {
            Ok(()) => {
                jobs.image = Some(ParkedImageLaunch {
                    transaction,
                    stage: ImageStage::Reading {
                        size,
                        offset,
                        length,
                    },
                    ..parked
                });
                Ok(waiting(true))
            }
            Err(FileFault::Launch(code)) => Ok(ReadStep::Failed(code)),
            Err(FileFault::Fatal(error)) => Err(error),
        }
    };
    let (image, offset, length) = match (parked.stage, scratch) {
        (ImageStage::AwaitingAttr, _) => (None, 0, 0),
        (ImageStage::AwaitingScratch { size }, None) => {
            return Ok(ReadStep::InFlight(ImageService::NeedsScratch {
                bytes: (size as u64).next_multiple_of(wyrmroot_runtime::PAGE_SIZE),
            }));
        }
        (ImageStage::AwaitingScratch { size }, Some(scratch)) => {
            if scratch.len() < size {
                return Ok(ReadStep::Failed(LaunchErrorCode::LoaderFailure));
            }
            return request(system, jobs, size, 0);
        }
        // The region the bytes so far were read into is gone.
        (ImageStage::Reading { .. }, None) => {
            return Ok(ReadStep::Failed(LaunchErrorCode::LoaderFailure));
        }
        (
            ImageStage::Reading {
                size,
                offset,
                length,
            },
            Some(scratch),
        ) => match scratch.get_mut(..size) {
            Some(image) => (Some(image), offset, length),
            None => return Ok(ReadStep::Failed(LaunchErrorCode::LoaderFailure)),
        },
    };
    // A poll, not a wait: the deadline is already now.
    let item = DwWaitItemV1 {
        handle: file,
        signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
    };
    match system.wait_many(core::slice::from_ref(&item), DwDeadline(now_ns)) {
        Ok(observed) if observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 => {}
        // The peer closed with nothing left to read.
        Ok(_) => return Ok(ReadStep::Failed(LaunchErrorCode::LoaderFailure)),
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {
            return Ok(waiting(image.is_some()));
        }
        // A wait init cannot make on a Channel it validated is init's own.
        Err(error) => return Err(InitError::Native(error)),
    }
    let mut reply = [0u8; node::MAX_BYTES];
    let mut reply_handles = [DwReceivedHandleInfoV1::default(); FS_MAX_HANDLES];
    let counts = match system.receive_channel(file, &mut reply, &mut reply_handles) {
        Ok(counts) => counts,
        Err(error) => {
            return match file_fault(ChannelOperation::Receive, error) {
                FileFault::Launch(code) => Ok(ReadStep::Failed(code)),
                FileFault::Fatal(error) => Err(error),
            };
        }
    };
    if counts.handles != 0 {
        // A file reply carries no handle. These are init's now; close them.
        if close_received_reverse(system, &reply_handles, counts.handles) {
            return Err(InitError::Cleanup);
        }
        return Ok(ReadStep::Failed(LaunchErrorCode::LoaderFailure));
    }
    let body = match node::parse(&reply[..counts.bytes.min(reply.len())], 0) {
        Ok(message) if message.transaction_id == parked.transaction => message.body,
        // Another transaction's reply, or bytes that are no WRFS message:
        // the filesystem's doing either way.
        Ok(_)
        | Err(
            FsError::WrongSize
            | FsError::WrongMagic
            | FsError::WrongVersion
            | FsError::UnknownMessage
            | FsError::WrongHandleCount
            | FsError::ZeroTransaction
            | FsError::NonzeroReserved
            | FsError::UnknownFlags
            | FsError::UnknownStatus
            | FsError::InvalidField
            | FsError::InvalidPath,
        ) => return Ok(ReadStep::Failed(LaunchErrorCode::LoaderFailure)),
    };
    let Some(image) = image else {
        return Ok(match body {
            Body::Attr(attr)
                if attr.kind == Kind::File && (1..=MAX_IMAGE_BYTES).contains(&attr.size) =>
            {
                jobs.image = Some(ParkedImageLaunch {
                    stage: ImageStage::AwaitingScratch {
                        size: attr.size as usize,
                    },
                    ..parked
                });
                ReadStep::InFlight(ImageService::NeedsScratch {
                    bytes: attr.size.next_multiple_of(wyrmroot_runtime::PAGE_SIZE),
                })
            }
            // Not a regular file, empty, or too large.
            Body::Attr(_) | Body::Status { .. } => {
                ReadStep::Failed(LaunchErrorCode::PolicyRejected)
            }
            _ => ReadStep::Failed(LaunchErrorCode::LoaderFailure),
        });
    };
    let size = image.len();
    let read = match body {
        Body::Data(data) if !data.is_empty() && data.len() <= length => {
            image[offset..offset + data.len()].copy_from_slice(data);
            offset + data.len()
        }
        Body::Status {
            status: Status::IsDirectory,
            ..
        } => return Ok(ReadStep::Failed(LaunchErrorCode::PolicyRejected)),
        // Shorter than its size, an error, or a reply that is not data.
        _ => return Ok(ReadStep::Failed(LaunchErrorCode::LoaderFailure)),
    };
    if read < size {
        return request(system, jobs, size, read);
    }
    Ok(ReadStep::Complete { size })
}

/// Constructs the job from the image just read, and parks it for READY as
/// any bootfs launch is parked.
///
/// The file is always closed. The streams and the namespace go to the job,
/// or are closed with the refusal.
#[allow(clippy::too_many_arguments)]
fn launch_read_image<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    jobs: &mut JobDispatcher,
    parked: ParkedImageLaunch,
    image: &[u8],
    now_ns: u64,
) -> Result<(), InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let file_closed = system.close_handle(parked.file()).is_ok();
    // What the job receives: the streams, then the namespace.
    let mut moved = [DwReceivedHandleInfoV1::default(); LAUNCH_IMAGE_HANDLE_COUNT - 1];
    for (slot, handle) in moved.iter_mut().zip(
        parked
            .handles
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != FILE_INDEX)
            .map(|(_, handle)| *handle),
    ) {
        slot.handle = handle;
    }
    // Whether the launch got as far as the code that owns `moved`.
    let mut reached = false;
    let launched = match MappingPlan::for_bootfs(parked.request_bytes) {
        // Init's own record of a request it parsed once is no size at all.
        Err(
            MappingPlanError::EmptyArchive
            | MappingPlanError::ArchiveTooLarge
            | MappingPlanError::RoundingOverflow,
        ) => {
            let _ = close_received_reverse(system, &moved, moved.len());
            Err(DispatchError::Fatal(InitError::Accounting))
        }
        Ok(plan) => with_launch_policy(system, authority, |system, policy| {
            reached = true;
            let request = system.with_bootfs_bytes(
                authority.parent_root,
                parked.request,
                plan,
                // Init's own copy of bytes it parsed as a LAUNCH_IMAGE when
                // they arrived; why they would not parse again is not a
                // cause anything downstream can use.
                |system, request| match parse_launch_message(request, LAUNCH_IMAGE_HANDLE_COUNT)
                    .ok()
                    .map(|parsed| parsed.message)
                {
                    Some(LaunchMessage::LaunchImage(request)) => defer_reserved_launch(
                        system,
                        loader,
                        waits,
                        authority,
                        policy,
                        jobs,
                        parked.session,
                        parked.grant,
                        parked.scope,
                        parked.reservation,
                        parked.ticket,
                        request,
                        &moved,
                        moved.len(),
                        Some(image),
                    )
                    .map(|_| ()),
                    Some(_) | None => {
                        let _ = close_received_reverse(system, &moved, moved.len());
                        Err(DispatchError::Fatal(InitError::Accounting))
                    }
                },
            );
            match request {
                Ok(launched) => launched,
                // Init's own memory object could not be mapped back, or
                // could not be unmapped: init's address space, not the
                // client's doing.
                Err(error) => Err(DispatchError::Fatal(InitError::Native(error))),
            }
        })
        .unwrap_or_else(|error| {
            // Init's own bootfs or policy. If the launch never started, its
            // handles are still init's to close; the failure reported is the
            // one that happened.
            if !reached {
                let _ = close_received_reverse(system, &moved, moved.len());
            }
            Err(DispatchError::Fatal(error))
        }),
    };
    let request_closed = system.close_handle(parked.request).is_ok();
    let settled = match launched {
        Ok(()) => Ok(()),
        Err(DispatchError::Fatal(error)) => Err(error),
        // The launch was refused and its reply had no room: held.
        Err(DispatchError::ReplyHeld) => answer_or_retire(
            system,
            waits,
            jobs,
            &parked,
            Err(ReplyError::QueueFull),
            now_ns,
        ),
        // The only fault a finished read can still find is a client that
        // cannot be told how its launch ended.
        Err(DispatchError::Client(cause)) => {
            if jobs.session_handle(parked.grant) == Ok(parked.session) {
                retire_session(system, waits, jobs, parked.grant, parked.scope)?;
                jobs.image_fault.get_or_insert(SessionFault {
                    grant: parked.grant,
                    scope: parked.scope,
                    cause,
                });
            }
            Ok(())
        }
    };
    if file_closed && request_closed {
        settled
    } else {
        Err(InitError::Cleanup)
    }
}
