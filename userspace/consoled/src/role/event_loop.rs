//! The resident event loop and terminal output draining.

use super::*;

pub(crate) fn event_loop<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    model: &mut ConsoleModel,
    serial: &mut SerialSession,
    child: &mut ChildSession,
) -> Result<u32, u32> {
    let mut input_pending = Pending::new();
    let mut output_pending = Pending::new();
    let mut next_data = DataClass::Raw;
    loop {
        // Fill only an empty retry buffer. Queue removal is committed only
        // after the corresponding native DATA datagram commits.
        reserve_input(model, &mut input_pending)?;
        reserve_output(model, &mut output_pending)?;

        let now = platform.monotonic_active_now().map_err(|_| 53u32)?;
        // Stability is time-based, not idleness-based. Continuous serial or
        // child traffic must not prevent the exact READY tuple from clearing
        // an expired child-restart window.
        observe_exact_ready(platform, model, serial, child, 55)?;
        let deadline = now.checked_add(EVENT_TICK_NS).ok_or(54u32)?;
        let snapshot = model.snapshot();
        let mut items = [DwWaitItemV1::default(); 13];
        let mut data_classes = [DataClass::Raw; 4];
        // Control and every retirement signal precede rotating data work.
        items[0] = wait_item(
            authorities.registry,
            DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        );
        items[1] = wait_item(serial.endpoint(), DW_SIGNAL_PEER_CLOSED);
        items[2] = wait_item(
            authorities.launch,
            DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        );
        items[3] = wait_item(
            child.stdin.endpoint().handle(),
            DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        );
        items[4] = wait_item(child.stdout.endpoint().handle(), DW_SIGNAL_PEER_CLOSED);
        items[5] = wait_item(child.stderr.endpoint().handle(), DW_SIGNAL_PEER_CLOSED);
        let initial_data_base = if let Some(status) = child.status.as_ref() {
            items[6] = wait_item(
                status.endpoint,
                DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
            );
            7
        } else {
            6
        };
        let mut data_base = initial_data_base;
        let witness_index = serial.release_witness.map(|witness| {
            let index = data_base;
            items[index] = wait_item(
                witness,
                DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
            );
            data_base += 1;
            index
        });

        let raw_writable = if output_pending.is_empty() {
            0
        } else {
            DW_SIGNAL_WRITABLE.0
        };
        let accepting_raw_input = true;
        let raw_readable = if accepting_raw_input
            && snapshot.input_queued <= STAGING_CAPACITY.saturating_sub(FAIR_SOURCE_BYTES_PER_TURN)
        {
            DW_SIGNAL_READABLE.0
        } else {
            0
        };
        let stdin_writable = if input_pending.is_empty() {
            0
        } else {
            DW_SIGNAL_WRITABLE.0
        };
        let stdout_readable = snapshot.stdout_queued
            <= STAGING_CAPACITY.saturating_sub(2 * FAIR_SOURCE_BYTES_PER_TURN);
        let stderr_readable = snapshot.stderr_queued
            <= STAGING_CAPACITY.saturating_sub(2 * FAIR_SOURCE_BYTES_PER_TURN);
        let mut used = data_base;
        for class in next_data.order() {
            let (handle, signals) = match class {
                DataClass::Raw => (serial.endpoint(), DwSignals(raw_readable | raw_writable)),
                DataClass::Stdin => (child.stdin.endpoint().handle(), DwSignals(stdin_writable)),
                DataClass::Stdout => (
                    child.stdout.endpoint().handle(),
                    DwSignals(if stdout_readable {
                        DW_SIGNAL_READABLE.0
                    } else {
                        0
                    }),
                ),
                DataClass::Stderr => (
                    child.stderr.endpoint().handle(),
                    DwSignals(if stderr_readable {
                        DW_SIGNAL_READABLE.0
                    } else {
                        0
                    }),
                ),
            };
            if signals.0 != 0 {
                items[used] = wait_item(handle, signals);
                data_classes[used - data_base] = class;
                used += 1;
            }
        }

        let observed = match platform.wait_many(&items[..used], DwDeadline(deadline)) {
            Ok(observed) => observed,
            Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {
                observe_exact_ready(platform, model, serial, child, 55)?;
                continue;
            }
            Err(_) => return Err(56),
        };
        let signals = observed.observed.0;
        let observed_index = usize::try_from(observed.index).map_err(|_| 61u32)?;

        if witness_index == Some(observed_index) {
            observe_release_witness(platform, serial, observed.observed)?;
            drop_orphaned_witness(platform, serial)?;
            continue;
        }

        match observed.index {
            // Registry retirement and raw close invalidate the serial tuple
            // before a co-ready launch response may use it.
            0 => {
                if signals & DW_SIGNAL_PEER_CLOSED.0 != 0 {
                    return Err(57);
                }
                if publication_withdrawn(receive_publication_change(platform, authorities, serial)?)
                {
                    continue;
                }
                recover_serial(
                    platform,
                    authorities,
                    transactions,
                    model,
                    serial,
                    child,
                    &mut input_pending,
                    &mut output_pending,
                )?;
                next_data = DataClass::Raw;
                continue;
            }
            1 => {
                recover_serial(
                    platform,
                    authorities,
                    transactions,
                    model,
                    serial,
                    child,
                    &mut input_pending,
                    &mut output_pending,
                )?;
                next_data = DataClass::Raw;
                continue;
            }
            2 => {
                if signals & DW_SIGNAL_READABLE.0 == 0 {
                    return Err(57);
                }
                drain_clean_terminal_output(
                    platform,
                    authorities,
                    model,
                    serial,
                    child,
                    &mut output_pending,
                )?;
                if recover_terminal_child(
                    platform,
                    authorities,
                    transactions,
                    model,
                    serial,
                    child,
                    &mut input_pending,
                    &mut output_pending,
                )? == TerminalOutcome::SessionEnded
                {
                    return Ok(SESSION_ENDED);
                }
                next_data = DataClass::Raw;
                continue;
            }
            3 => {
                if signals & DW_SIGNAL_PEER_CLOSED.0 != 0 && child.wait.is_some() {
                    if recover_terminal_precursor(
                        platform,
                        authorities,
                        transactions,
                        model,
                        serial,
                        child,
                        &mut input_pending,
                        &mut output_pending,
                    )? == TerminalOutcome::SessionEnded
                    {
                        return Ok(SESSION_ENDED);
                    }
                    next_data = DataClass::Raw;
                    continue;
                }
                let fault = if signals & DW_SIGNAL_PEER_CLOSED.0 != 0 {
                    ChildFault::Peer(StreamKind::Stdin)
                } else {
                    discard_one_record(platform, child.stdin.endpoint().handle());
                    ChildFault::WrongDirection
                };
                recover_child(
                    platform,
                    authorities,
                    transactions,
                    model,
                    serial,
                    child,
                    &mut input_pending,
                    &mut output_pending,
                    fault,
                )?;
                next_data = DataClass::Raw;
                continue;
            }
            4 | 5 => {
                if child.wait.is_some() {
                    if recover_terminal_precursor(
                        platform,
                        authorities,
                        transactions,
                        model,
                        serial,
                        child,
                        &mut input_pending,
                        &mut output_pending,
                    )? == TerminalOutcome::SessionEnded
                    {
                        return Ok(SESSION_ENDED);
                    }
                    next_data = DataClass::Raw;
                    continue;
                }
                let kind = if observed.index == 4 {
                    StreamKind::Stdout
                } else {
                    StreamKind::Stderr
                };
                recover_child(
                    platform,
                    authorities,
                    transactions,
                    model,
                    serial,
                    child,
                    &mut input_pending,
                    &mut output_pending,
                    ChildFault::Peer(kind),
                )?;
                next_data = DataClass::Raw;
                continue;
            }
            6 if child.status.is_some() => {
                if signals & DW_SIGNAL_PEER_CLOSED.0 != 0 && child.wait.is_some() {
                    if recover_terminal_precursor(
                        platform,
                        authorities,
                        transactions,
                        model,
                        serial,
                        child,
                        &mut input_pending,
                        &mut output_pending,
                    )? == TerminalOutcome::SessionEnded
                    {
                        return Ok(SESSION_ENDED);
                    }
                    next_data = DataClass::Raw;
                    continue;
                }
                let failed = if signals & DW_SIGNAL_PEER_CLOSED.0 != 0 {
                    true
                } else if signals & DW_SIGNAL_READABLE.0 != 0 {
                    let status = child.status.as_mut().ok_or(61u32)?;
                    serve_status(platform, status.endpoint, &mut status.session, model).is_err()
                } else {
                    true
                };
                if failed {
                    recover_child(
                        platform,
                        authorities,
                        transactions,
                        model,
                        serial,
                        child,
                        &mut input_pending,
                        &mut output_pending,
                        ChildFault::Status,
                    )?;
                }
                next_data = DataClass::Raw;
                continue;
            }
            _ => {}
        }

        let class_index = usize::try_from(
            observed
                .index
                .checked_sub(u32::try_from(data_base).map_err(|_| 61u32)?)
                .ok_or(61u32)?,
        )
        .map_err(|_| 61u32)?;
        let class = *data_classes.get(class_index).ok_or(61u32)?;
        next_data = class.next();
        match class {
            DataClass::Raw => {
                if signals & DW_SIGNAL_READABLE.0 != 0 {
                    let input_signals =
                        DwSignals(signals & (DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0));
                    if serial.input.observe_wait(input_signals).is_err() {
                        recover_serial(
                            platform,
                            authorities,
                            transactions,
                            model,
                            serial,
                            child,
                            &mut input_pending,
                            &mut output_pending,
                        )?;
                        next_data = DataClass::Raw;
                        continue;
                    }
                    let mut payload = [0u8; FAIR_SOURCE_BYTES_PER_TURN];
                    match serial
                        .input
                        .read(&mut ConsoledStreams::new(platform), &mut payload)
                    {
                        Ok(count) => {
                            model
                                .stage_serial_input(child.event, &payload[..count])
                                .map_err(|_| 58u32)?;
                        }
                        Err(StreamError::WouldBlock) => {}
                        Err(_) => {
                            recover_serial(
                                platform,
                                authorities,
                                transactions,
                                model,
                                serial,
                                child,
                                &mut input_pending,
                                &mut output_pending,
                            )?;
                            next_data = DataClass::Raw;
                            continue;
                        }
                    }
                }
                if signals & DW_SIGNAL_WRITABLE.0 != 0 && !output_pending.is_empty() {
                    match serial.output.write(
                        &mut ConsoledStreams::new(platform),
                        &output_pending.bytes[..output_pending.used],
                    ) {
                        Ok(written) if written == output_pending.used => {
                            commit_output(model, &output_pending)?;
                            output_pending.clear();
                        }
                        Ok(_) => return Err(59),
                        Err(StreamError::WouldBlock) => {
                            release_output(model, &output_pending)?;
                            output_pending.clear();
                        }
                        Err(_) => {
                            recover_serial(
                                platform,
                                authorities,
                                transactions,
                                model,
                                serial,
                                child,
                                &mut input_pending,
                                &mut output_pending,
                            )?;
                            next_data = DataClass::Raw;
                        }
                    }
                }
            }
            DataClass::Stdin => {
                if signals & DW_SIGNAL_WRITABLE.0 != 0 && !input_pending.is_empty() {
                    match child.stdin.write(
                        &mut ConsoledStreams::new(platform),
                        &input_pending.bytes[..input_pending.used],
                    ) {
                        Ok(written) if written == input_pending.used => {
                            commit_input(model, &input_pending)?;
                            input_pending.clear();
                        }
                        Ok(_) => return Err(59),
                        Err(StreamError::WouldBlock) => {
                            release_input(model, &input_pending)?;
                            input_pending.clear();
                        }
                        Err(_) => {
                            recover_child(
                                platform,
                                authorities,
                                transactions,
                                model,
                                serial,
                                child,
                                &mut input_pending,
                                &mut output_pending,
                                ChildFault::Peer(StreamKind::Stdin),
                            )?;
                            next_data = DataClass::Raw;
                        }
                    }
                }
            }
            DataClass::Stdout | DataClass::Stderr => {
                let source = match class {
                    DataClass::Stdout => OutputSource::Stdout,
                    DataClass::Stderr => OutputSource::Stderr,
                    _ => return Err(61),
                };
                let input = match source {
                    OutputSource::Stdout => &mut child.stdout,
                    OutputSource::Stderr => &mut child.stderr,
                };
                if input.observe_wait(observed.observed).is_err() {
                    recover_child(
                        platform,
                        authorities,
                        transactions,
                        model,
                        serial,
                        child,
                        &mut input_pending,
                        &mut output_pending,
                        ChildFault::Peer(output_kind(source)),
                    )?;
                    next_data = DataClass::Raw;
                    continue;
                }
                let mut payload = [0u8; FAIR_SOURCE_BYTES_PER_TURN];
                match input.read(&mut ConsoledStreams::new(platform), &mut payload) {
                    Ok(count) => {
                        model
                            .stage_child_output(child.event, source, &payload[..count])
                            .map_err(|_| 60u32)?;
                    }
                    Err(StreamError::WouldBlock) => {}
                    Err(_) => {
                        recover_child(
                            platform,
                            authorities,
                            transactions,
                            model,
                            serial,
                            child,
                            &mut input_pending,
                            &mut output_pending,
                            ChildFault::Peer(output_kind(source)),
                        )?;
                        next_data = DataClass::Raw;
                    }
                }
            }
        }
    }
}

pub(crate) fn drain_clean_terminal_output<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    model: &mut ConsoleModel,
    serial: &mut SerialSession,
    child: &mut ChildSession,
    output_pending: &mut Pending,
) -> Result<(), u32> {
    let deadline = platform
        .monotonic_active_now()
        .map_err(|_| 53u32)?
        .checked_add(TERMINAL_DRAIN_TIMEOUT_NS)
        .ok_or(54u32)?;
    let wait = child.wait.take().ok_or(61u32)?;
    match receive_launch_before(platform, authorities.launch, wait, deadline)? {
        LaunchReply::JobResult {
            job_id,
            session_shutdown,
        } if job_id == child.job_id => child.session_shutdown = session_shutdown,
        _ => return Err(61),
    }
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    loop {
        reserve_output(model, output_pending)?;
        let snapshot = model.snapshot();
        if stdout_eof
            && stderr_eof
            && output_pending.is_empty()
            && snapshot.stdout_queued == 0
            && snapshot.stderr_queued == 0
        {
            break;
        }
        let mut items = [DwWaitItemV1::default(); 3];
        let mut count = 0;
        let output_index = if output_pending.is_empty() {
            None
        } else {
            let index = count;
            items[count] = wait_item(
                serial.endpoint(),
                DwSignals(DW_SIGNAL_WRITABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
            );
            count += 1;
            Some(index)
        };
        let stdout_index = if stdout_eof {
            None
        } else {
            let index = count;
            items[count] = wait_item(
                child.stdout.endpoint().handle(),
                DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
            );
            count += 1;
            Some(index)
        };
        let stderr_index = if stderr_eof {
            None
        } else {
            let index = count;
            items[count] = wait_item(
                child.stderr.endpoint().handle(),
                DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
            );
            count += 1;
            Some(index)
        };
        let observed = platform
            .wait_many(&items[..count], DwDeadline(deadline))
            .map_err(|_| 64u32)?;
        let index = usize::try_from(observed.index).map_err(|_| 64u32)?;
        if output_index == Some(index) {
            if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0
                || observed.observed.0 & DW_SIGNAL_WRITABLE.0 == 0
            {
                return Err(64);
            }
            match serial.output.write(
                &mut ConsoledStreams::new(platform),
                &output_pending.bytes[..output_pending.used],
            ) {
                Ok(written) if written == output_pending.used => {
                    commit_output(model, output_pending)?;
                    output_pending.clear();
                }
                Ok(_) => return Err(59),
                Err(StreamError::WouldBlock) => {
                    release_output(model, output_pending)?;
                    output_pending.clear();
                }
                Err(_) => return Err(64),
            }
            continue;
        }
        let (input, source, eof) = if stdout_index == Some(index) {
            (&mut child.stdout, OutputSource::Stdout, &mut stdout_eof)
        } else if stderr_index == Some(index) {
            (&mut child.stderr, OutputSource::Stderr, &mut stderr_eof)
        } else {
            return Err(64);
        };
        input.observe_wait(observed.observed).map_err(|_| 64u32)?;
        let mut payload = [0u8; FAIR_SOURCE_BYTES_PER_TURN];
        match input.read(&mut ConsoledStreams::new(platform), &mut payload) {
            Ok(count) => model
                .stage_child_output(child.event, source, &payload[..count])
                .map_err(|_| 60u32)?,
            Err(StreamError::WouldBlock) => {}
            Err(StreamError::Eof) => *eof = true,
            Err(_) => return Err(64),
        }
    }
    Ok(())
}
