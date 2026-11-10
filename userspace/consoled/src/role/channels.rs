//! Launch and status channels, stream accounting and handle helpers.

use super::*;

pub(crate) fn receive_launch<P: ConsoledPlatform>(
    platform: &mut P,
    channel: DwHandle,
    expected: LaunchReservation,
) -> Result<LaunchReply, u32> {
    let (reservation, reply) = receive_launch_any(platform, channel)?;
    if reservation != expected {
        return Err(79);
    }
    Ok(reply)
}

// Only the Wyrmsh terminal drain waits for a launch result under a deadline.
pub(crate) fn receive_launch_before<P: ConsoledPlatform>(
    platform: &mut P,
    channel: DwHandle,
    expected: LaunchReservation,
    deadline: u64,
) -> Result<LaunchReply, u32> {
    let observed = platform
        .wait_one(
            channel,
            DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
            DwDeadline(deadline),
        )
        .map_err(|_| 64u32)?;
    if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0
        || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0
    {
        return Err(64);
    }
    let (reservation, reply) = receive_launch_ready(platform, channel)?;
    if reservation != expected {
        return Err(79);
    }
    Ok(reply)
}

pub(crate) fn receive_initial_launch<P: ConsoledPlatform>(
    platform: &mut P,
    channel: DwHandle,
    expected: LaunchReservation,
    policy: ChildPolicy,
) -> Result<LaunchReply, u32> {
    if policy == ChildPolicy::ConsoleEcho {
        return receive_launch(platform, channel, expected);
    }
    wait_readable(platform, channel).map_err(|_| 75u32)?;
    let mut bytes = [0u8; 128];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(channel, &mut bytes, &mut handles)
        .map_err(|_| 76u32)?;
    if counts.handles != 0 {
        close_received(platform, &handles, counts.handles);
        return Err(77);
    }
    let parsed = parse_shell_v1_reply(&bytes[..counts.bytes], 0).map_err(|_| 78u32)?;
    if parsed.reservation != expected {
        return Err(79);
    }
    match parsed.reply {
        ShellV1Reply::LaunchAccepted { job_id } => Ok(LaunchReply::LaunchAccepted(job_id)),
        ShellV1Reply::Error { code } => Ok(LaunchReply::Error(code)),
    }
}

pub(crate) fn serve_status<P: ConsoledPlatform>(
    platform: &mut P,
    endpoint: DwHandle,
    session: &mut wyrmroot_console_proto::StatusSession,
    model: &ConsoleModel,
) -> Result<(), u32> {
    let mut bytes = [0u8; wyrmroot_console_proto::MAX_MESSAGE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(endpoint, &mut bytes, &mut handles)
        .map_err(|_| 101u32)?;
    if counts.handles != 0 {
        close_received(platform, &handles, counts.handles);
        return Err(102);
    }
    let message = &bytes[..counts.bytes];
    let header = wyrmroot_console_proto::parse_header(message, 0).map_err(|_| 103u32)?;
    let decoded = wyrmroot_console_proto::decode(message, 0);
    let ticket = match session.admit(header) {
        Ok(ticket) => ticket,
        Err(code) => {
            let size = wyrmroot_console_proto::encode_error(header, code, &mut bytes)
                .map_err(|_| 104u32)?;
            return send_status_bounded(platform, endpoint, &bytes[..size], header);
        }
    };
    if decoded != Ok(wyrmroot_console_proto::Message::Query(header)) {
        let size = wyrmroot_console_proto::encode_error(
            header,
            wyrmroot_console_proto::ErrorCode::Malformed,
            &mut bytes,
        )
        .map_err(|_| 104u32)?;
        send_status_bounded(platform, endpoint, &bytes[..size], header)?;
        session.complete(ticket).map_err(|_| 105u32)?;
        return Ok(());
    }
    let snapshot = match model.status_snapshot() {
        Ok(snapshot) => snapshot,
        Err(_) => {
            let size = wyrmroot_console_proto::encode_error(
                header,
                wyrmroot_console_proto::ErrorCode::Unavailable,
                &mut bytes,
            )
            .map_err(|_| 106u32)?;
            send_status_bounded(platform, endpoint, &bytes[..size], header)?;
            session.complete(ticket).map_err(|_| 106u32)?;
            return Ok(());
        }
    };
    let relationship = session.relationship();
    if snapshot.flags & wyrmroot_console_proto::FLAG_CHILD_PRESENT != 0
        && (snapshot.child_generation != relationship.child_generation
            || snapshot.outer_launch_transaction != relationship.outer_launch_transaction)
    {
        return Err(107);
    }
    let size = wyrmroot_console_proto::encode_snapshot(header, snapshot, &mut bytes)
        .map_err(|_| 108u32)?;
    send_status_bounded(platform, endpoint, &bytes[..size], header)?;
    session.complete(ticket).map_err(|_| 109)
}

pub(crate) fn send_status_bounded<P: ConsoledPlatform>(
    platform: &mut P,
    endpoint: DwHandle,
    bytes: &[u8],
    header: wyrmroot_console_proto::Header,
) -> Result<(), u32> {
    match platform.send_channel(endpoint, bytes, &[]) {
        Ok(()) => return Ok(()),
        Err(NativeError::Status(status)) if status == DW_STATUS_WOULD_BLOCK => {}
        Err(_) => return Err(110),
    }
    let deadline = platform
        .monotonic_active_now()
        .map_err(|_| 110u32)?
        .checked_add(STATUS_SEND_TIMEOUT_NS)
        .ok_or(110u32)?;
    match platform.wait_one(
        endpoint,
        DwSignals(DW_SIGNAL_WRITABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        DwDeadline(deadline),
    ) {
        Ok(observed)
            if observed.observed.0 & DW_SIGNAL_WRITABLE.0 != 0
                && observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 == 0 =>
        {
            platform.send_channel(endpoint, bytes, &[]).map_err(|_| 111)
        }
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {
            let mut unavailable = [0u8; wyrmroot_console_proto::ERROR_BYTES];
            if let Ok(size) = wyrmroot_console_proto::encode_error(
                header,
                wyrmroot_console_proto::ErrorCode::Unavailable,
                &mut unavailable,
            ) {
                let _ = platform.send_channel(endpoint, &unavailable[..size], &[]);
            }
            Err(112)
        }
        _ => Err(113),
    }
}

pub(crate) fn receive_launch_any<P: ConsoledPlatform>(
    platform: &mut P,
    channel: DwHandle,
) -> Result<(LaunchReservation, LaunchReply), u32> {
    wait_readable(platform, channel).map_err(|_| 75u32)?;
    receive_launch_ready(platform, channel)
}

pub(crate) fn receive_launch_ready<P: ConsoledPlatform>(
    platform: &mut P,
    channel: DwHandle,
) -> Result<(LaunchReservation, LaunchReply), u32> {
    let mut bytes = [0u8; 128];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(channel, &mut bytes, &mut handles)
        .map_err(|_| 76u32)?;
    if counts.handles != 0 {
        close_received(platform, &handles, counts.handles);
        return Err(77);
    }
    let parsed = parse_launch_message(&bytes[..counts.bytes], 0).map_err(|_| 78u32)?;
    let reply = match parsed.message {
        LaunchMessage::LaunchAccepted { job_id } => LaunchReply::LaunchAccepted(job_id),
        LaunchMessage::TerminationAccepted { job_id } => LaunchReply::TerminationAccepted(job_id),
        LaunchMessage::JobResult { job_id, result } => LaunchReply::JobResult {
            job_id,
            session_shutdown: result.classification == TerminationClassification::NormalExit
                && result.application_code == SHELL_SESSION_SHUTDOWN_STATUS,
        },
        LaunchMessage::Cancelled {
            target_transaction_id,
        } => LaunchReply::Cancelled(target_transaction_id),
        LaunchMessage::Closed { job_id } => LaunchReply::Closed(job_id),
        LaunchMessage::Error { code } => LaunchReply::Error(code),
        _ => return Err(80),
    };
    Ok((parsed.reservation, reply))
}

pub(crate) fn reserve_input(model: &mut ConsoleModel, pending: &mut Pending) -> Result<(), u32> {
    if !pending.is_empty() {
        return Ok(());
    }
    let Some(reservation) = model
        .reserve_child_stdin(&mut pending.bytes)
        .map_err(|_| 81u32)?
    else {
        return Ok(());
    };
    pending.used = reservation.length();
    pending.reservation = Some(reservation);
    Ok(())
}

pub(crate) fn commit_input(model: &mut ConsoleModel, pending: &Pending) -> Result<(), u32> {
    let reservation = pending.reservation.ok_or(82u32)?;
    if reservation.length() != pending.used {
        return Err(83);
    }
    model.commit_child_stdin(reservation).map_err(|_| 84)
}

pub(crate) fn release_input(model: &mut ConsoleModel, pending: &Pending) -> Result<(), u32> {
    model
        .release_child_stdin(pending.reservation.ok_or(85u32)?)
        .map_err(|_| 86)
}

pub(crate) fn reserve_output(model: &mut ConsoleModel, pending: &mut Pending) -> Result<(), u32> {
    if !pending.is_empty() {
        return Ok(());
    }
    let Some(reservation) = model
        .reserve_serial_tx(&mut pending.bytes)
        .map_err(|_| 87u32)?
    else {
        return Ok(());
    };
    if reservation.output_source().is_none() {
        return Err(88);
    }
    pending.used = reservation.length();
    pending.reservation = Some(reservation);
    Ok(())
}

pub(crate) fn commit_output(model: &mut ConsoleModel, pending: &Pending) -> Result<(), u32> {
    let reservation = pending.reservation.ok_or(89u32)?;
    if reservation.length() != pending.used {
        return Err(90);
    }
    model.commit_serial_tx(reservation).map_err(|_| 91)
}

pub(crate) fn release_output(model: &mut ConsoleModel, pending: &Pending) -> Result<(), u32> {
    model
        .release_serial_tx(pending.reservation.ok_or(92u32)?)
        .map_err(|_| 93)
}

pub(crate) fn finish_launch_abort<P: ConsoledPlatform>(
    platform: &mut P,
    model: &mut ConsoleModel,
    transaction: LaunchTransaction,
    retained: &[DwHandle; 3],
    child: &[DwHandle; 3],
    moved_peers_revoked: bool,
) -> Result<(), u32> {
    let token = model.abort_child_launch(transaction).map_err(|_| 95u32)?;
    let cleanup = token.cleanup();
    let mut index = 0;
    while index < cleanup.entries.len() {
        if cleanup.entries[index].endpoint.0 == 0 {
            return Err(96);
        }
        let mut other = index + 1;
        while other < cleanup.entries.len() {
            if cleanup.entries[index].endpoint == cleanup.entries[other].endpoint {
                return Err(96);
            }
            other += 1;
        }
        index += 1;
    }
    if cleanup.entries[..3]
        .iter()
        .any(|entry| entry.disposition != CleanupDisposition::CloseConsoledPeer)
    {
        return Err(96);
    }
    for index in 0..3 {
        match cleanup.entries[index + 3].disposition {
            CleanupDisposition::CloseUnmovedChildPeer => {}
            CleanupDisposition::RevokeMovedChildPeerFromLaunch if moved_peers_revoked => {}
            _ => return Err(96),
        }
    }
    let mut close_failed = false;
    let mut evidence = LaunchCleanupEvidence {
        consoled_peers_closed: [false; 3],
        unmoved_child_peers_closed: [false; 3],
        moved_child_peers_revoked: [false; 3],
    };
    for index in (0..3).rev() {
        if cleanup.entries[index + 3].disposition == CleanupDisposition::CloseUnmovedChildPeer {
            let closed = platform.close_handle(child[index]).is_ok();
            close_failed |= !closed;
            evidence.unmoved_child_peers_closed[index] = closed;
        } else {
            evidence.moved_child_peers_revoked[index] = moved_peers_revoked;
        }
    }
    for index in (0..3).rev() {
        let closed = platform.close_handle(retained[index]).is_ok();
        close_failed |= !closed;
        evidence.consoled_peers_closed[index] = closed;
    }
    if close_failed {
        return Err(97);
    }
    model
        .complete_abort_child_launch(&token, evidence)
        .map(|_| ())
        .map_err(|_| 98)
}

pub(crate) fn close_attempt_handles<P: ConsoledPlatform>(
    platform: &mut P,
    handles: &[DwHandle],
) -> Result<(), u32> {
    let mut failed = false;
    for handle in handles.iter().rev() {
        if handle.0 != 0 {
            failed |= platform.close_handle(*handle).is_err();
        }
    }
    if failed {
        Err(FATAL_ATTACH_BASE | 99)
    } else {
        Ok(())
    }
}

pub(crate) fn finish_connect_abort<P: ConsoledPlatform>(
    platform: &mut P,
    model: &mut ConsoleModel,
    request: ConnectRequest,
    handles: &[DwHandle],
) -> Result<(), u32> {
    let handles_closed = close_attempt_handles(platform, handles).is_ok();
    let model_released = model.abort_connect(request).is_ok();
    if handles_closed && model_released {
        Ok(())
    } else {
        Err(FATAL_ATTACH_BASE | 100)
    }
}

pub(crate) fn create_reduced_stream_pair<P: ConsoledPlatform>(
    platform: &mut P,
) -> Result<(DwHandle, DwHandle), u32> {
    let (retained_broad, child_broad) = platform
        .create_channel(CHANNEL_CONSTRUCTION_RIGHTS)
        .map_err(|_| 82u32)?;
    let retained = match platform.duplicate_handle(retained_broad, CHILD_CHANNEL_RIGHTS) {
        Ok(handle) => handle,
        Err(_) => {
            let _ = platform.close_handle(child_broad);
            let _ = platform.close_handle(retained_broad);
            return Err(83);
        }
    };
    if platform.close_handle(retained_broad).is_err() {
        let _ = platform.close_handle(retained);
        let _ = platform.close_handle(child_broad);
        return Err(84);
    }
    if validate_exact_channel(platform, retained, CHILD_CHANNEL_RIGHTS).is_err() {
        let _ = platform.close_handle(child_broad);
        let _ = platform.close_handle(retained);
        return Err(85);
    }
    Ok((retained, child_broad))
}

pub(crate) fn validated_stream_endpoint(handle: DwHandle) -> Result<StreamEndpoint, StreamError> {
    StreamEndpoint::from_validated_handle(handle)
}

pub(crate) fn registry_header(
    authorities: StartupAuthorities,
    message_type: RegistryMessageType,
    transaction_id: u64,
) -> RegistryHeader {
    RegistryHeader {
        message_type,
        registry_generation: authorities.registry_generation,
        endpoint_id: authorities.registry_endpoint_id,
        endpoint_generation: authorities.registry_endpoint_generation,
        transaction_id,
    }
}

pub(crate) fn valid_connector_identity(
    identity: ConnectorIdentity,
    publication_generation: u64,
    client_transaction_id: u64,
) -> bool {
    identity.publication_generation == publication_generation
        && identity.client_transaction_id == client_transaction_id
        && identity.device_role_id == COM2_ROLE_ID.0
        && identity.bundle_generation != 0
        && identity.driver_attempt_generation != 0
        && identity.driver_control_endpoint_id != 0
        && identity.driver_control_endpoint_generation != 0
        && identity.attach_transaction_id != 0
        && identity.stream_generation != 0
}

pub(crate) fn serial_correlation(
    authorities: StartupAuthorities,
    identity: ConnectorIdentity,
) -> SerialCorrelation {
    SerialCorrelation {
        registry_generation: authorities.registry_generation,
        registry_endpoint_id: authorities.registry_endpoint_id,
        registry_endpoint_generation: authorities.registry_endpoint_generation,
        publication_generation: identity.publication_generation,
        connector_client_transaction: identity.client_transaction_id,
        device_role: identity.device_role_id,
        device_bundle: identity.bundle_generation,
        driver_attempt: identity.driver_attempt_generation,
        driver_control_endpoint_id: identity.driver_control_endpoint_id,
        driver_control_endpoint_generation: identity.driver_control_endpoint_generation,
        attach_transaction: identity.attach_transaction_id,
        stream_generation: identity.stream_generation,
    }
}

pub(crate) fn serial_correlates(serial: &SerialSession, event: EventGeneration) -> bool {
    serial.identity.publication_generation == event.serial.publication_generation
        && serial.identity.client_transaction_id == event.serial.connector_client_transaction
        && serial.identity.device_role_id == event.serial.device_role
        && serial.identity.bundle_generation == event.serial.device_bundle
        && serial.identity.driver_attempt_generation == event.serial.driver_attempt
        && serial.identity.driver_control_endpoint_id == event.serial.driver_control_endpoint_id
        && serial.identity.driver_control_endpoint_generation
            == event.serial.driver_control_endpoint_generation
        && serial.identity.attach_transaction_id == event.serial.attach_transaction
        && serial.identity.stream_generation == event.serial.stream_generation
}

pub(crate) fn observe_exact_ready<P: ConsoledPlatform>(
    platform: &mut P,
    model: &mut ConsoleModel,
    serial: &SerialSession,
    child: &ChildSession,
    error: u32,
) -> Result<(), u32> {
    if !serial_correlates(serial, child.event) {
        return Err(error);
    }
    observe_exact_ready_without_serial(platform, model, child, error)
}

pub(crate) fn observe_exact_ready_without_serial<P: ConsoledPlatform>(
    platform: &mut P,
    model: &mut ConsoleModel,
    child: &ChildSession,
    error: u32,
) -> Result<(), u32> {
    if !model.event_is_current(child.event)
        || child.stdin.endpoint().handle().0 == 0
        || child.stdout.endpoint().handle().0 == 0
        || child.stderr.endpoint().handle().0 == 0
    {
        return Err(error);
    }
    let token = model.ready_token().ok_or(error)?;
    if EventGeneration::from(token.ids) != child.event {
        return Err(error);
    }
    model
        .observe_ready(now_millis(platform)?, token)
        .map(|_| ())
        .map_err(|_| error)
}

pub(crate) fn valid_received_channel(info: DwReceivedHandleInfoV1, rights: DwRights) -> bool {
    info.handle.0 != 0
        && info.object_type == DW_OBJECT_TYPE_CHANNEL
        && info.rights == rights
        && info.reserved0 == 0
        && info.reserved == [0; 2]
}

pub(crate) fn validate_exact_channel<P: ConsoledPlatform>(
    platform: &mut P,
    handle: DwHandle,
    rights: DwRights,
) -> Result<(), NativeError> {
    let info = platform.query_capability_info(handle)?;
    if info.object_type == DW_OBJECT_TYPE_CHANNEL && info.rights == rights {
        Ok(())
    } else {
        Err(NativeError::Output(
            wyrmroot_runtime::NativeOutputError::InvalidObjectInfo,
        ))
    }
}

pub(crate) fn wait_readable<P: ConsoledPlatform>(
    platform: &mut P,
    handle: DwHandle,
) -> Result<(), NativeError> {
    let deadline = platform
        .monotonic_active_now()?
        .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .ok_or(NativeError::Output(
            wyrmroot_runtime::NativeOutputError::DeadlineOverflow,
        ))?;
    let observed = platform.wait_one(
        handle,
        DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        DwDeadline(deadline),
    )?;
    if observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 {
        Ok(())
    } else {
        Err(NativeError::Status(deepwyrm_syscall::DW_STATUS_PEER_CLOSED))
    }
}

pub(crate) fn wait_backoff<P: ConsoledPlatform>(
    platform: &mut P,
    registry: DwHandle,
    deadline_ms: u64,
) -> Result<(), u32> {
    let deadline_ns = deadline_ms.checked_mul(NANOS_PER_MILLI).ok_or(86u32)?;
    let item = wait_item(registry, DwSignals(DW_SIGNAL_PEER_CLOSED.0));
    match platform.wait_many(core::slice::from_ref(&item), DwDeadline(deadline_ns)) {
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => Ok(()),
        Ok(observed) if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 => Err(87),
        _ => Err(88),
    }
}

pub(crate) fn discard_one_record<P: ConsoledPlatform>(platform: &mut P, endpoint: DwHandle) {
    let mut bytes = [0u8; wyrmroot_stream_proto::MAX_RECORD_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    if let Ok(counts) = platform.receive_channel(endpoint, &mut bytes, &mut handles) {
        close_received(platform, &handles, counts.handles);
    }
}

pub(crate) fn close_child_streams<P: ConsoledPlatform>(
    platform: &mut P,
    child: &mut ChildSession,
) -> Result<(), u32> {
    let mut failed = close_child_status(platform, child).is_err();
    let handles = [
        child.stdin.endpoint().handle(),
        child.stdout.endpoint().handle(),
        child.stderr.endpoint().handle(),
    ];
    for handle in handles.into_iter().rev() {
        failed |= platform.close_handle(handle).is_err();
    }
    if failed { Err(93) } else { Ok(()) }
}

pub(crate) fn close_child_status<P: ConsoledPlatform>(
    platform: &mut P,
    child: &mut ChildSession,
) -> Result<(), u32> {
    let Some(mut status) = child.status.take() else {
        return Ok(());
    };
    status.session.close();
    platform.close_handle(status.endpoint).map_err(|_| 93)
}

pub(crate) fn close_status_retained<P: ConsoledPlatform>(
    platform: &mut P,
    endpoint: DwHandle,
    session: Option<&mut wyrmroot_console_proto::StatusSession>,
) -> Result<(), u32> {
    if let Some(session) = session {
        session.close();
    }
    if endpoint.0 != 0 && platform.close_handle(endpoint).is_err() {
        Err(93)
    } else {
        Ok(())
    }
}

pub(crate) fn close_status_pair<P: ConsoledPlatform>(
    platform: &mut P,
    retained: DwHandle,
    child: DwHandle,
) -> Result<(), u32> {
    let mut failed = false;
    if child.0 != 0 {
        failed |= platform.close_handle(child).is_err();
    }
    if retained.0 != 0 {
        failed |= platform.close_handle(retained).is_err();
    }
    if failed { Err(93) } else { Ok(()) }
}

pub(crate) fn close_received<P: ConsoledPlatform>(
    platform: &mut P,
    handles: &[DwReceivedHandleInfoV1],
    count: usize,
) {
    for info in handles[..count.min(handles.len())].iter().rev() {
        if info.handle.0 != 0 {
            let _ = platform.close_handle(info.handle);
        }
    }
}

pub(crate) fn close_handle_array_reverse<P: ConsoledPlatform>(
    platform: &mut P,
    handles: &[DwHandle],
) {
    for handle in handles.iter().rev() {
        if handle.0 != 0 {
            let _ = platform.close_handle(*handle);
        }
    }
}

pub(crate) fn close_authorities<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
) {
    let _ = platform.close_handle(authorities.launch);
    let _ = platform.close_handle(authorities.registry);
}

pub(crate) const fn wait_item(handle: DwHandle, signals: DwSignals) -> DwWaitItemV1 {
    DwWaitItemV1 { handle, signals }
}

pub(crate) const fn output_kind(source: OutputSource) -> StreamKind {
    match source {
        OutputSource::Stdout => StreamKind::Stdout,
        OutputSource::Stderr => StreamKind::Stderr,
    }
}

pub(crate) fn now_millis<P: ConsoledPlatform>(platform: &mut P) -> Result<u64, u32> {
    platform
        .monotonic_active_now()
        .map(|now| now / NANOS_PER_MILLI)
        .map_err(|_| 94)
}
