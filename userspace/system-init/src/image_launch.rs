//! LAUNCH_IMAGE: a shell job whose executable is a file (root
//! `STORAGE_PLAN.md` W6).
//!
//! The shell opens the file through vfsd and moves its WRFS Channel to init
//! with a three-stream LAUNCH_IMAGE, followed by a WRNS connection to vfsd
//! that init passes to the job untouched as its namespace (WRLP 1.13, root
//! `TOOLCHAIN_POSIX_LAYER_DESIGN.md` W5). Init never uses the namespace. Init reads the whole file, at most
//! [`MAX_IMAGE_BYTES`] and within [`IMAGE_READ_TIMEOUT_NS`], into private
//! memory no other process can reach, constructs the job from those bytes
//! exactly as it would a bootfs JobV2 payload, and drops the copy. The job
//! gets the same TaskGroup limits and stream contract as `bin/hello`.
//!
//! A file runs without a launch-policy identity: the recovery shell's
//! operator may run what the mounted filesystems hold. Bootfs payloads keep
//! their identity check. While init reads the file it waits on the filesystem
//! with that bounded deadline; a slow or hostile filesystem costs the launch,
//! never init.

use crate::job_sessions::{JobDispatcher, LaunchSessionScope};
use crate::jobs::{EndpointGrant, PolicyView, RequestTicket};
use crate::*;
use deepwyrm_syscall::DW_SIGNAL_READABLE;
use wyrmroot_fs_proto::node::{self, Body, Kind, MAX_IO_BYTES};
use wyrmroot_fs_proto::{MAX_HANDLES as FS_MAX_HANDLES, Status};
use wyrmroot_launch_proto::{ErrorCode as LaunchErrorCode, Reservation as LaunchReservation};

/// The largest executable a file launch reads.
pub(crate) const MAX_IMAGE_BYTES: u64 = 8 * 1024 * 1024;
/// How long reading one image may take, in total.
pub(crate) const IMAGE_READ_TIMEOUT_NS: u64 = 10_000_000_000;

/// Why an image could not be read; each maps to the shell's error code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ImageError {
    /// Not a regular file, empty, or too large.
    Unacceptable,
    /// The filesystem failed, went away, broke WRFS or ran out of time.
    Unreadable,
}

/// Sends one WRFS request on `file` and receives its reply into `reply`.
fn file_request<S: ResidentPlatform>(
    system: &mut S,
    file: DwHandle,
    transaction_id: u64,
    body: Body<'_>,
    reply: &mut [u8; node::MAX_BYTES],
    deadline: DwDeadline,
) -> Result<usize, ImageError> {
    let mut bytes = [0u8; 64];
    let size = node::encode(
        &node::Message {
            transaction_id,
            body,
        },
        &mut bytes,
    )
    .map_err(|_| ImageError::Unreadable)?;
    system
        .send_channel(file, &bytes[..size])
        .map_err(|_| ImageError::Unreadable)?;
    let item = DwWaitItemV1 {
        handle: file,
        signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
    };
    let observed = system
        .wait_many(core::slice::from_ref(&item), deadline)
        .map_err(|_| ImageError::Unreadable)?;
    if observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(ImageError::Unreadable);
    }
    let mut handles = [DwReceivedHandleInfoV1::default(); FS_MAX_HANDLES];
    let counts = system
        .receive_channel(file, reply, &mut handles)
        .map_err(|_| ImageError::Unreadable)?;
    if counts.handles != 0 {
        for info in &handles[..counts.handles.min(FS_MAX_HANDLES)] {
            let _ = system.close_handle(info.handle);
        }
        return Err(ImageError::Unreadable);
    }
    match node::parse(&reply[..counts.bytes.min(reply.len())], 0) {
        Ok(message) if message.transaction_id == transaction_id => Ok(counts.bytes),
        _ => Err(ImageError::Unreadable),
    }
}

/// The file's size, if it is a regular file the launch may read.
fn image_size<S: ResidentPlatform>(
    system: &mut S,
    file: DwHandle,
    deadline: DwDeadline,
) -> Result<u64, ImageError> {
    let mut reply = [0u8; node::MAX_BYTES];
    let used = file_request(system, file, 1, Body::GetAttr, &mut reply, deadline)?;
    match node::parse(&reply[..used], 0).map(|message| message.body) {
        Ok(Body::Attr(attr))
            if attr.kind == Kind::File && (1..=MAX_IMAGE_BYTES).contains(&attr.size) =>
        {
            Ok(attr.size)
        }
        Ok(Body::Attr(_)) | Ok(Body::Status { .. }) => Err(ImageError::Unacceptable),
        _ => Err(ImageError::Unreadable),
    }
}

/// Fills `image` from the start of `file`; the file must hold exactly that
/// many bytes.
fn read_image<S: ResidentPlatform>(
    system: &mut S,
    file: DwHandle,
    image: &mut [u8],
    deadline: DwDeadline,
) -> Result<(), ImageError> {
    let mut reply = [0u8; node::MAX_BYTES];
    let mut offset = 0usize;
    let mut transaction = 2u64;
    while offset < image.len() {
        let length = (image.len() - offset).min(MAX_IO_BYTES) as u32;
        let used = file_request(
            system,
            file,
            transaction,
            Body::Read {
                offset: offset as u64,
                length,
            },
            &mut reply,
            deadline,
        )?;
        transaction += 1;
        match node::parse(&reply[..used], 0).map(|message| message.body) {
            Ok(Body::Data(data)) if !data.is_empty() && data.len() <= length as usize => {
                image[offset..offset + data.len()].copy_from_slice(data);
                offset += data.len();
            }
            Ok(Body::Status {
                status: Status::IsDirectory,
                ..
            }) => return Err(ImageError::Unacceptable),
            // Shorter than its size, an error, or a malformed reply.
            _ => return Err(ImageError::Unreadable),
        }
    }
    Ok(())
}

/// Handles one LAUNCH_IMAGE: `received` holds the three streams, the file
/// and the namespace. The file is always closed; the streams and the
/// namespace go to the job or are closed with the refusal.
#[allow(clippy::too_many_arguments)]
pub(crate) fn defer_image_launch<S, L, W>(
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
    received: &[DwReceivedHandleInfoV1],
) -> Result<JobDispatchOutcome, InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let count = wyrmroot_launch_proto::LAUNCH_IMAGE_HANDLE_COUNT;
    if received.len() != count {
        return Err(InitError::Accounting);
    }
    let file = received[3].handle;
    // What the job receives: the streams, then the namespace.
    let moved = [received[0], received[1], received[2], received[4]];
    let refuse = |system: &mut S, code: LaunchErrorCode| {
        let failed = close_received_reverse(system, received, count);
        if failed {
            return Err(InitError::Cleanup);
        }
        send_observed_job_error(system, session, reservation, code)?;
        Ok(JobDispatchOutcome::Responded)
    };
    if !scope.admits_image_launch() || validate_controller_channel(system, file).is_err() {
        return refuse(system, LaunchErrorCode::PolicyRejected);
    }
    let deadline = match system
        .now()
        .map(|now| now.checked_add(IMAGE_READ_TIMEOUT_NS))
    {
        Ok(Some(deadline)) => DwDeadline(deadline),
        _ => return refuse(system, LaunchErrorCode::LoaderFailure),
    };
    let size = match image_size(system, file, deadline) {
        Ok(size) => size,
        Err(ImageError::Unacceptable) => return refuse(system, LaunchErrorCode::PolicyRejected),
        Err(ImageError::Unreadable) => return refuse(system, LaunchErrorCode::LoaderFailure),
    };
    let region = size.next_multiple_of(wyrmroot_runtime::PAGE_SIZE);
    let outcome = system.with_private_memory(authority.parent_root, region, |system, memory| {
        let image = &mut memory[..size as usize];
        match read_image(system, file, image, deadline) {
            Ok(()) => Ok(defer_reserved_launch(
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
                &moved,
                moved.len(),
                Some(&*image),
            )),
            Err(error) => Err(error),
        }
    });
    let file_closed = system.close_handle(file).is_ok();
    let result = match outcome {
        Ok(Ok(dispatched)) => dispatched,
        Ok(Err(ImageError::Unacceptable)) => {
            let failed = close_received_reverse(system, &moved, moved.len());
            if failed {
                return Err(InitError::Cleanup);
            }
            send_observed_job_error(
                system,
                session,
                reservation,
                LaunchErrorCode::PolicyRejected,
            )
            .map(|()| JobDispatchOutcome::Responded)
        }
        Ok(Err(ImageError::Unreadable)) | Err(_) => {
            let failed = close_received_reverse(system, &moved, moved.len());
            if failed {
                return Err(InitError::Cleanup);
            }
            send_observed_job_error(system, session, reservation, LaunchErrorCode::LoaderFailure)
                .map(|()| JobDispatchOutcome::Responded)
        }
    };
    if file_closed {
        result
    } else {
        Err(InitError::Cleanup)
    }
}
