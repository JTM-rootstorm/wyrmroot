//! Launching a job: stream pairs, the request and its replies.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) fn launch<System: WyrmshSystem>(
    system: &mut System,
    stdout: &NativeOutput,
    stderr: &NativeOutput,
    identity: ShellIdentity,
    controls: Controls,
    transactions: &mut TransactionIds,
    path: &str,
    argv: Arguments<'_>,
    transfers: &[DwHandleTransferV1],
) -> Result<u64, LaunchFailure> {
    let transaction = transactions.launch().map_err(|_| LaunchFailure {
        kind: LaunchFailureKind::Fatal(ShellError::TransactionExhausted),
        committed: false,
    })?;
    let reservation = reservation(identity, transaction);
    let mut arguments = [""; MAX_ARGV];
    let mut count = 0;
    for argument in argv.iter() {
        arguments[count] = argument;
        count += 1;
    }
    let mut request = [0_u8; MAX_LAUNCH_MESSAGE_BYTES];
    let size = encode_launch(
        reservation,
        path,
        &arguments[..count],
        &[],
        !transfers.is_empty(),
        &mut request,
    )
    .map_err(|_| LaunchFailure {
        kind: LaunchFailureKind::Fatal(ShellError::InspectionProtocol),
        committed: false,
    })?;
    send_progress_neutral(
        system,
        controls,
        stdout.endpoint().handle(),
        stderr.endpoint().handle(),
        &request[..size],
        transfers,
    )
    .map_err(|error| LaunchFailure {
        kind: LaunchFailureKind::Fatal(error),
        committed: false,
    })?;
    match receive_expected(system, identity, controls, stdout, stderr, transaction).map_err(
        |error| LaunchFailure {
            kind: LaunchFailureKind::Fatal(error),
            committed: true,
        },
    )? {
        Reply::LaunchAccepted(job_id) => Ok(job_id),
        Reply::Error(code) if recoverable_launch_error(code) => Err(LaunchFailure {
            kind: LaunchFailureKind::Expected(code),
            committed: true,
        }),
        _ => Err(LaunchFailure {
            kind: LaunchFailureKind::Fatal(ShellError::InspectionProtocol),
            committed: true,
        }),
    }
}

pub(crate) fn recoverable_launch_error(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::Capacity | ErrorCode::PolicyRejected | ErrorCode::LoaderFailure
    )
}

pub(crate) fn create_stream_pairs<System: WyrmshSystem>(
    system: &mut System,
    pairs: &mut [StreamPair; 3],
) -> Result<(), ShellError> {
    for pair in pairs {
        let (retained_broad, child) = system
            .create_channel(CHANNEL_CONSTRUCTION_RIGHTS)
            .map_err(|cause| native(NativeOperation::CreateChannel, cause))?;
        pair.retained = retained_broad;
        pair.child = child;
        let retained = match system.duplicate_handle(retained_broad, CHILD_CHANNEL_RIGHTS) {
            Ok(handle) => handle,
            Err(cause) => return Err(native(NativeOperation::DuplicateHandle, cause)),
        };
        if let Err(cause) = system.close_handle(retained_broad) {
            let _ = system.close_handle(retained);
            return Err(native(NativeOperation::Cleanup, cause));
        }
        pair.retained = retained;
        for (handle, rights) in [
            (pair.retained, CHILD_CHANNEL_RIGHTS),
            (pair.child, CHANNEL_CONSTRUCTION_RIGHTS),
        ] {
            let fresh = system
                .query_capability_info(handle)
                .map_err(|cause| native(NativeOperation::QueryRole, cause))?;
            if fresh.object_type != DW_OBJECT_TYPE_CHANNEL || fresh.rights != rights {
                return Err(ShellError::InspectionProtocol);
            }
        }
    }
    Ok(())
}

pub(crate) fn close_pairs<System: WyrmshSystem>(
    system: &mut System,
    pairs: &mut [StreamPair; 3],
    include_children: bool,
) -> Result<(), ShellError> {
    let mut failure = None;
    for pair in pairs.iter_mut().rev() {
        if include_children {
            close_record(system, &mut pair.child, &mut failure);
        }
        close_record(system, &mut pair.retained, &mut failure);
    }
    failure.map_or(Ok(()), |cause| Err(native(NativeOperation::Cleanup, cause)))
}

pub(crate) fn cleanup_then_error<System: WyrmshSystem>(
    system: &mut System,
    pairs: &mut [StreamPair; 3],
    original: ShellError,
) -> Result<(), ShellError> {
    match close_pairs(system, pairs, false) {
        Ok(()) => Err(original),
        Err(cleanup) => Err(cleanup),
    }
}

pub(crate) fn close_one<System: WyrmshSystem>(
    system: &mut System,
    handle: &mut DwHandle,
) -> Result<(), ShellError> {
    if handle.0 == 0 {
        return Ok(());
    }
    let local = *handle;
    system
        .close_handle(local)
        .map_err(|cause| native(NativeOperation::Cleanup, cause))?;
    *handle = DwHandle(0);
    Ok(())
}

pub(crate) fn close_record<System: WyrmshSystem>(
    system: &mut System,
    handle: &mut DwHandle,
    failure: &mut Option<NativeError>,
) {
    if handle.0 != 0 {
        let local = *handle;
        if let Err(error) = system.close_handle(local) {
            failure.get_or_insert(error);
        } else {
            *handle = DwHandle(0);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn start_job_request<System: WyrmshSystem>(
    system: &mut System,
    stdout: &NativeOutput,
    stderr: &NativeOutput,
    identity: ShellIdentity,
    controls: Controls,
    transactions: &mut TransactionIds,
    kind: MessageType,
    value: u64,
) -> Result<u64, ShellError> {
    let transaction = transactions
        .launch()
        .map_err(|_| ShellError::TransactionExhausted)?;
    let mut request = [0_u8; 56];
    let size = encode_job_message(
        reservation(identity, transaction),
        kind,
        value,
        &mut request,
    )
    .map_err(|_| ShellError::InspectionProtocol)?;
    send_progress_neutral(
        system,
        controls,
        stdout.endpoint().handle(),
        stderr.endpoint().handle(),
        &request[..size],
        &[],
    )?;
    Ok(transaction)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn send_progress_neutral<System: WyrmshSystem>(
    system: &mut System,
    controls: Controls,
    stdout: DwHandle,
    stderr: DwHandle,
    bytes: &[u8],
    transfers: &[DwHandleTransferV1],
) -> Result<(), ShellError> {
    let deadline = control_deadline(system)?;
    loop {
        poll_health(system, controls, stdout, stderr)?;
        ensure_before_control_deadline(system, deadline)?;
        match system.send_channel_with_handles(controls.shell_jobs, bytes, transfers) {
            Ok(()) => return Ok(()),
            Err(NativeError::Status(status)) if status == DW_STATUS_WOULD_BLOCK => {}
            Err(cause) => return Err(native(NativeOperation::ControlSend, cause)),
        }
        let mut items = health_items(controls, stdout, stderr);
        items[2] = wait_item(
            controls.shell_jobs,
            DwSignals(DW_SIGNAL_WRITABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        );
        match system.wait_many(&items, deadline) {
            Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {
                return Err(ShellError::InspectionTimeout);
            }
            Err(cause) => return Err(native(NativeOperation::Wait, cause)),
            Ok(result) if result.index == 2 => {
                if result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
                    return Err(ShellError::RequiredEndpointLost(EndpointRole::ShellJobs));
                }
                if result.observed.0 & DW_SIGNAL_WRITABLE.0 == 0 {
                    return Err(ShellError::InspectionProtocol);
                }
                ensure_before_control_deadline(system, deadline)?;
            }
            Ok(result) => classify_health(result)?,
        }
    }
}

pub(crate) fn progress_deadline<System: WyrmshSystem>(
    system: &mut System,
) -> Result<DwDeadline, ShellError> {
    let deadline = system
        .monotonic_active_now()
        .map_err(|cause| native(NativeOperation::MonotonicClock, cause))?
        .checked_add(STATUS_TIMEOUT_NS)
        .ok_or(ShellError::InspectionProtocol)?;
    if deadline == DW_DEADLINE_INFINITE.0 {
        return Err(ShellError::InspectionProtocol);
    }
    Ok(DwDeadline(deadline))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn receive_expected<System: WyrmshSystem>(
    system: &mut System,
    identity: ShellIdentity,
    controls: Controls,
    stdout: &NativeOutput,
    stderr: &NativeOutput,
    transaction: u64,
) -> Result<Reply, ShellError> {
    loop {
        if let Some((_, reply)) = receive_one(
            system,
            identity,
            controls,
            stdout,
            stderr,
            Some(transaction),
            None,
        )? {
            return Ok(reply);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn receive_one<System: WyrmshSystem>(
    system: &mut System,
    identity: ShellIdentity,
    controls: Controls,
    stdout: &NativeOutput,
    stderr: &NativeOutput,
    first: Option<u64>,
    second: Option<u64>,
) -> Result<Option<(u64, Reply)>, ShellError> {
    let deadline = progress_deadline(system)?;
    let mut items = health_items(
        controls,
        stdout.endpoint().handle(),
        stderr.endpoint().handle(),
    );
    items[2] = wait_item(
        controls.shell_jobs,
        DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
    );
    let result = match system.wait_many(&items, deadline) {
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => return Ok(None),
        Err(cause) => return Err(native(NativeOperation::Wait, cause)),
        Ok(result) => result,
    };
    if result.index != 2 {
        classify_health(result)?;
        return Err(ShellError::InspectionProtocol);
    }
    if result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
        return Err(ShellError::RequiredEndpointLost(EndpointRole::ShellJobs));
    }
    if result.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(ShellError::InspectionProtocol);
    }
    let mut bytes = [0_u8; 88];
    let mut handles = [DwReceivedHandleInfoV1::default(); 4];
    let counts = match system.receive_channel(controls.shell_jobs, &mut bytes, &mut handles) {
        Err(NativeError::Status(status)) if status == DW_STATUS_PEER_CLOSED => {
            return Err(ShellError::RequiredEndpointLost(EndpointRole::ShellJobs));
        }
        Err(cause) => return Err(native(NativeOperation::ControlReceive, cause)),
        Ok(counts) => counts,
    };
    if counts.handles != 0 {
        let mut failure = None;
        for received in handles.iter().take(counts.handles.min(handles.len())).rev() {
            if received.handle.0 != 0
                && let Err(error) = system.close_handle(received.handle)
            {
                failure.get_or_insert(error);
            }
        }
        if let Some(cause) = failure {
            return Err(native(NativeOperation::Cleanup, cause));
        }
        return Err(ShellError::InspectionProtocol);
    }
    if counts.bytes > bytes.len() {
        return Err(ShellError::InspectionProtocol);
    }
    let parsed = wyrmroot_launch_proto::parse_message(&bytes[..counts.bytes], 0)
        .map_err(|_| ShellError::InspectionProtocol)?;
    if parsed.reservation.connection_id != identity.launch_connection_id
        || parsed.reservation.generation != identity.launch_connection_generation
        || (Some(parsed.reservation.transaction_id) != first
            && Some(parsed.reservation.transaction_id) != second)
    {
        return Err(ShellError::InspectionProtocol);
    }
    let transaction = parsed.reservation.transaction_id;
    let reply = decode_reply(identity, transaction, &bytes[..counts.bytes], 0)
        .map_err(|_| ShellError::InspectionProtocol)?;
    Ok(Some((transaction, reply)))
}
