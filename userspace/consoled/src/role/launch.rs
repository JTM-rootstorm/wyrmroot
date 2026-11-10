//! Launching the console child and waiting for its readiness.

use super::*;

pub(crate) fn launch_child<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    model: &mut ConsoleModel,
    serial: &mut SerialSession,
) -> Result<ChildSession, u32> {
    loop {
        match launch_child_once(platform, authorities, transactions, model, serial)? {
            LaunchChildOutcome::Child(child) => return Ok(child),
            LaunchChildOutcome::SerialLost(deadline) => {
                *serial = attach_serial_bounded(
                    platform,
                    authorities,
                    transactions,
                    model,
                    Some(deadline),
                )?;
            }
        }
    }
}

pub(crate) fn launch_child_once<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    model: &mut ConsoleModel,
    serial: &mut SerialSession,
) -> Result<LaunchChildOutcome, u32> {
    let policy = ChildPolicy::selected();
    let transaction_id = transactions.take()?;
    let mut retained = [DwHandle(0); 3];
    let mut child = [DwHandle(0); 3];
    for index in 0..3 {
        match create_reduced_stream_pair(platform) {
            Ok((local, peer)) => {
                retained[index] = local;
                child[index] = peer;
            }
            Err(_) => {
                close_handle_array_reverse(platform, &retained);
                close_handle_array_reverse(platform, &child);
                return Err(42);
            }
        }
    }
    let mut model_launch = match model.begin_child_launch(transaction_id) {
        Ok(launch) => launch,
        Err(_) => {
            close_handle_array_reverse(platform, &retained);
            close_handle_array_reverse(platform, &child);
            return Err(41);
        }
    };

    let mut status_retained = DwHandle(0);
    let mut status_child = DwHandle(0);
    let mut status_generation = 0;
    let mut status_session = None;
    if policy == ChildPolicy::Wyrmsh {
        status_generation = match transactions.take() {
            Ok(value) => value,
            Err(error) => {
                finish_launch_abort(platform, model, model_launch, &retained, &child, false)?;
                return Err(error);
            }
        };
        match create_reduced_stream_pair(platform) {
            Ok((local, peer)) => {
                status_retained = local;
                status_child = peer;
            }
            Err(_) => {
                finish_launch_abort(platform, model, model_launch, &retained, &child, false)?;
                return Err(42);
            }
        }
        status_session =
            match wyrmroot_console_proto::StatusSession::new(wyrmroot_console_proto::Relationship {
                console_generation: model_launch.console_generation(),
                status_generation,
                child_generation: model_launch.child_generation(),
                outer_launch_transaction: model_launch.outer_launch_transaction(),
            }) {
                Ok(session) => Some(session),
                Err(_) => {
                    close_status_pair(platform, status_retained, status_child)?;
                    finish_launch_abort(platform, model, model_launch, &retained, &child, false)?;
                    return Err(42);
                }
            };
    }

    let reservation = LaunchReservation {
        connection_id: authorities.launch_connection_id,
        generation: authorities.launch_connection_generation,
        transaction_id,
    };
    let mut bytes = [0u8; MAX_LAUNCH_MESSAGE_BYTES];
    let encoded = match policy {
        ChildPolicy::ConsoleEcho => encode_console_echo_launch(reservation, &mut bytes),
        ChildPolicy::Wyrmsh => encode_shell_v1_request(
            reservation,
            ShellV1Request {
                console_generation: model_launch.console_generation(),
                status_generation,
                requested_child_generation: model_launch.child_generation(),
            },
            &mut bytes,
        ),
    };
    let size = match encoded {
        Ok(size) => size,
        Err(_) => {
            close_status_pair(platform, status_retained, status_child)?;
            finish_launch_abort(platform, model, model_launch, &retained, &child, false)?;
            return Err(43);
        }
    };
    let transfers = [
        move_transfer(child[0]),
        move_transfer(child[1]),
        move_transfer(child[2]),
        move_transfer(status_child),
    ];
    let transfer_count = if policy == ChildPolicy::Wyrmsh { 4 } else { 3 };
    if platform
        .send_channel(
            authorities.launch,
            &bytes[..size],
            &transfers[..transfer_count],
        )
        .is_err()
    {
        // Channel MOVE is atomic: a failed send leaves every child peer local.
        close_status_pair(platform, status_retained, status_child)?;
        finish_launch_abort(platform, model, model_launch, &retained, &child, false)?;
        return Err(44);
    }
    for kind in [StreamKind::Stdin, StreamKind::Stdout, StreamKind::Stderr] {
        if model_launch.move_child_peer(kind).is_err() {
            close_status_retained(platform, status_retained, status_session.as_mut())?;
            close_handle_array_reverse(platform, &retained);
            // The native MOVE already committed, but no correlated launch
            // response proves revocation. Closing the launch session on fatal
            // process exit is the only truthful cleanup remaining.
            return Err(48);
        }
    }
    let response = match wait_launch_with_serial(
        platform,
        authorities,
        serial,
        reservation,
        policy,
        model,
        status_retained,
        status_session.as_mut(),
    ) {
        Ok(LaunchWaitOutcome::Reply(response)) => response,
        Ok(LaunchWaitOutcome::SerialLost) => {
            let old_serial = serial_correlation(authorities, serial.identity);
            let old_console = model.snapshot().console_generation.ok_or(45u32)?;
            if model
                .serial_peer_closed(old_serial, old_console, now_millis(platform)?)
                .map_err(|_| 45u32)?
                != RecoveryAction::None
            {
                return Err(45);
            }
            close_serial_session(platform, serial)?;
            retire_publication_watch(platform, authorities, transactions, serial)?;
            let resolved =
                match receive_initial_launch(platform, authorities.launch, reservation, policy) {
                    Ok(reply) => reply,
                    Err(_) => {
                        close_status_retained(platform, status_retained, status_session.as_mut())?;
                        close_handle_array_reverse(platform, &retained);
                        return Err(45);
                    }
                };
            match resolved {
                LaunchReply::LaunchAccepted(job_id) => {
                    if cleanup_unmodeled_job(platform, authorities, transactions, job_id).is_err() {
                        close_status_retained(platform, status_retained, status_session.as_mut())?;
                        close_handle_array_reverse(platform, &retained);
                        return Err(45);
                    }
                }
                LaunchReply::Error(code) if code != LaunchErrorCode::CleanupFailure => {}
                _ => {
                    close_status_retained(platform, status_retained, status_session.as_mut())?;
                    close_handle_array_reverse(platform, &retained);
                    return Err(45);
                }
            }
            close_status_retained(platform, status_retained, status_session.as_mut())?;
            finish_launch_abort(platform, model, model_launch, &retained, &child, true)?;
            return match model.take_recovery_action() {
                Some(RecoveryAction::RetrySerialAt(deadline)) => {
                    Ok(LaunchChildOutcome::SerialLost(deadline))
                }
                _ => Err(45),
            };
        }
        Err(_) => {
            close_status_retained(platform, status_retained, status_session.as_mut())?;
            close_handle_array_reverse(platform, &retained);
            // Do not complete the model abort without proof that launchd
            // revoked the three moved peers.
            return Err(45);
        }
    };
    let job_id = match response {
        LaunchReply::LaunchAccepted(job_id) => job_id,
        LaunchReply::Error(code) if code != LaunchErrorCode::CleanupFailure => {
            // An exact correlated rejection is proof that launchd completed
            // cleanup for every moved child peer before replying.
            close_status_retained(platform, status_retained, status_session.as_mut())?;
            finish_launch_abort(platform, model, model_launch, &retained, &child, true)?;
            return Err(47);
        }
        _ => {
            close_status_retained(platform, status_retained, status_session.as_mut())?;
            close_handle_array_reverse(platform, &retained);
            return Err(47);
        }
    };

    let modeled = match model.commit_child_launch(&mut model_launch, job_id) {
        Ok(modeled) => modeled,
        Err(_) => {
            if cleanup_unmodeled_job(platform, authorities, transactions, job_id).is_err() {
                close_status_retained(platform, status_retained, status_session.as_mut())?;
                close_handle_array_reverse(platform, &retained);
                return Err(49);
            }
            close_status_retained(platform, status_retained, status_session.as_mut())?;
            finish_launch_abort(platform, model, model_launch, &retained, &child, true)?;
            return Err(49);
        }
    };
    let event: EventGeneration = modeled.ids.into();
    let endpoints = match (
        validated_stream_endpoint(retained[0]),
        validated_stream_endpoint(retained[1]),
        validated_stream_endpoint(retained[2]),
    ) {
        (Ok(stdin), Ok(stdout), Ok(stderr)) => (stdin, stdout, stderr),
        _ => {
            close_status_retained(platform, status_retained, status_session.as_mut())?;
            close_handle_array_reverse(platform, &retained);
            if let Ok(now) = now_millis(platform) {
                let _ = model.wrong_direction_data(event, now);
                let _ = model.child_streams_closed(event, now);
                let _ = cleanup_job(platform, authorities, transactions, model, event, job_id);
            } else {
                let _ = cleanup_unmodeled_job(platform, authorities, transactions, job_id);
            }
            return Err(50);
        }
    };
    let ready = match model.observe_child_ready(event, now_millis(platform)?) {
        Ok(ready) => ready,
        Err(_) => {
            close_status_retained(platform, status_retained, status_session.as_mut())?;
            close_handle_array_reverse(platform, &retained);
            let _ = cleanup_unmodeled_job(platform, authorities, transactions, job_id);
            return Err(51);
        }
    };
    if EventGeneration::from(ready.ids) != event {
        close_status_retained(platform, status_retained, status_session.as_mut())?;
        close_handle_array_reverse(platform, &retained);
        let _ = cleanup_unmodeled_job(platform, authorities, transactions, job_id);
        return Err(52);
    }
    let wait = match start_job_wait(platform, authorities, transactions, job_id) {
        Ok(wait) => wait,
        Err(_) => {
            close_status_retained(platform, status_retained, status_session.as_mut())?;
            close_handle_array_reverse(platform, &retained);
            let _ = cleanup_unmodeled_job(platform, authorities, transactions, job_id);
            return Err(52);
        }
    };
    Ok(LaunchChildOutcome::Child(ChildSession {
        job_id,
        event,
        wait: Some(wait),
        session_shutdown: false,
        stdin: NativeOutput::new(endpoints.0),
        stdout: NativeInput::new(endpoints.1),
        stderr: NativeInput::new(endpoints.2),
        status: status_session.map(|session| StatusChannel {
            endpoint: status_retained,
            session,
        }),
    }))
}

/// Encodes the historical console-echo child's launch: a plain launch of its
/// own path, argv0 only, no environment, with the three streams.
pub(crate) fn encode_console_echo_launch(
    reservation: LaunchReservation,
    bytes: &mut [u8],
) -> Result<usize, wyrmroot_launch_proto::Error> {
    let policy = ChildPolicy::ConsoleEcho;
    encode_launch(
        reservation,
        policy.path(),
        &[policy.path()],
        &[],
        true,
        bytes,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn wait_launch_with_serial<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    serial: &mut SerialSession,
    reservation: LaunchReservation,
    policy: ChildPolicy,
    model: &ConsoleModel,
    status_endpoint: DwHandle,
    mut status_session: Option<&mut wyrmroot_console_proto::StatusSession>,
) -> Result<LaunchWaitOutcome, u32> {
    let deadline = platform
        .monotonic_active_now()
        .map_err(|_| 45u32)?
        .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .ok_or(45u32)?;
    loop {
        let mut items = [DwWaitItemV1::default(); 5];
        items[0] = wait_item(
            authorities.registry,
            DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        );
        items[1] = wait_item(serial.endpoint(), DW_SIGNAL_PEER_CLOSED);
        items[2] = wait_item(
            authorities.launch,
            DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        );
        let mut used = 3;
        let witness_index = serial.release_witness.map(|witness| {
            let index = used;
            items[index] = wait_item(
                witness,
                DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
            );
            used += 1;
            index
        });
        let status_index = if let Some(session) = status_session.as_deref() {
            if !session.is_open() || status_endpoint.0 == 0 {
                return Err(45);
            }
            let index = used;
            items[index] = wait_item(
                status_endpoint,
                DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
            );
            used += 1;
            Some(index)
        } else {
            None
        };
        let observed = platform
            .wait_many(&items[..used], DwDeadline(deadline))
            .map_err(|_| 45u32)?;
        let index = usize::try_from(observed.index).map_err(|_| 45u32)?;
        if witness_index == Some(index) {
            observe_release_witness(platform, serial, observed.observed)?;
            drop_orphaned_witness(platform, serial)?;
            continue;
        }
        if status_index == Some(index) {
            if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
                return Err(45);
            }
            serve_status(
                platform,
                status_endpoint,
                status_session.as_deref_mut().ok_or(45u32)?,
                model,
            )?;
            continue;
        }
        match index {
            0 if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 => return Err(45),
            0 => {
                if publication_withdrawn(receive_publication_change(platform, authorities, serial)?)
                {
                    continue;
                }
                return Ok(LaunchWaitOutcome::SerialLost);
            }
            1 => return Ok(LaunchWaitOutcome::SerialLost),
            2 if observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 => {
                return receive_initial_launch(platform, authorities.launch, reservation, policy)
                    .map(LaunchWaitOutcome::Reply);
            }
            2 => return Err(45),
            _ => return Err(45),
        }
    }
}
