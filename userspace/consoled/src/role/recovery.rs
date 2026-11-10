//! Child, terminal and serial recovery, and job cleanup.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) fn recover_terminal_precursor<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    model: &mut ConsoleModel,
    serial: &mut SerialSession,
    child: &mut ChildSession,
    input_pending: &mut Pending,
    output_pending: &mut Pending,
) -> Result<TerminalOutcome, u32> {
    if !matches!(
        model.child_terminal_precursor(child.event, now_millis(platform)?),
        Ok(RecoveryAction::None)
    ) {
        return Err(62);
    }
    drain_clean_terminal_output(platform, authorities, model, serial, child, output_pending)?;
    recover_terminal_child(
        platform,
        authorities,
        transactions,
        model,
        serial,
        child,
        input_pending,
        output_pending,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn recover_terminal_child<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    model: &mut ConsoleModel,
    serial: &mut SerialSession,
    child: &mut ChildSession,
    input_pending: &mut Pending,
    output_pending: &mut Pending,
) -> Result<TerminalOutcome, u32> {
    if !matches!(model.child_terminal(child.event, now_millis(platform)?), Ok(RecoveryAction::ReapChild(job)) if job == child.job_id)
    {
        return Err(62);
    }
    let stream_failed = close_child_streams(platform, child).is_err();
    let observed_failed = model
        .child_streams_closed(child.event, now_millis(platform)?)
        .is_err();
    input_pending.clear();
    output_pending.clear();
    if stream_failed || observed_failed {
        return Err(64);
    }
    match close_reaped_job(
        platform,
        authorities,
        transactions,
        model,
        child.event,
        child.job_id,
    )? {
        RecoveryAction::ReplaceChild => {
            // F3A.7g. The reap is identical either way -- the streams, the
            // status channel and the job are released above before anything
            // here looks at why the child stopped -- so a session that ends
            // leaves no more behind than one that restarts. The only thing
            // withheld is the replacement.
            if child.session_shutdown {
                return Ok(TerminalOutcome::SessionEnded);
            }
            *child = launch_child(platform, authorities, transactions, model, serial)?;
            observe_exact_ready_without_serial(platform, model, child, 65)?;
            Ok(TerminalOutcome::Replaced)
        }
        RecoveryAction::Escalate => Err(66),
        _ => Err(67),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn recover_child<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    model: &mut ConsoleModel,
    serial: &mut SerialSession,
    child: &mut ChildSession,
    input_pending: &mut Pending,
    output_pending: &mut Pending,
    fault: ChildFault,
) -> Result<(), u32> {
    let action = match fault {
        ChildFault::Peer(kind) => model.child_peer_closed(child.event, kind, now_millis(platform)?),
        ChildFault::Status => model.status_peer_closed(child.event, now_millis(platform)?),
        ChildFault::WrongDirection => {
            model.wrong_direction_data(child.event, now_millis(platform)?)
        }
    }
    .map_err(|_| 62u32)?;
    if !matches!(action, RecoveryAction::TerminateChild(job) if job == child.job_id) {
        return Err(63);
    }
    close_child_status(platform, child)?;
    let wait_resolution = cancel_child_wait(platform, authorities, transactions, child)?;
    let stream_failed = close_child_streams(platform, child).is_err();
    let observed_failed = model
        .child_streams_closed(child.event, now_millis(platform)?)
        .is_err();
    if stream_failed || observed_failed {
        return Err(64);
    }
    input_pending.clear();
    output_pending.clear();
    let cleanup = match wait_resolution {
        ChildWaitResolution::Cancelled => cleanup_job(
            platform,
            authorities,
            transactions,
            model,
            child.event,
            child.job_id,
        )?,
        ChildWaitResolution::Terminal => complete_terminal_reap(
            platform,
            authorities,
            transactions,
            model,
            child.event,
            child.job_id,
        )?,
    };
    match cleanup {
        RecoveryAction::ReplaceChild => {
            *child = launch_child(platform, authorities, transactions, model, serial)?;
            observe_exact_ready_without_serial(platform, model, child, 65)?;
            Ok(())
        }
        RecoveryAction::Escalate => Err(66),
        _ => Err(67),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn recover_serial<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    model: &mut ConsoleModel,
    serial: &mut SerialSession,
    child: &mut ChildSession,
    input_pending: &mut Pending,
    output_pending: &mut Pending,
) -> Result<(), u32> {
    let old_serial = child.event.serial;
    let old_console = child.event.console_generation;
    let action = model
        .serial_peer_closed(old_serial, old_console, now_millis(platform)?)
        .map_err(|_| 68u32)?;
    if !matches!(action, RecoveryAction::TerminateChild(job) if job == child.job_id) {
        return Err(69);
    }
    let raw_failed = close_serial_session(platform, serial).is_err();
    let watch_failed =
        retire_publication_watch(platform, authorities, transactions, serial).is_err();
    let wait_resolution = cancel_child_wait(platform, authorities, transactions, child)?;
    let streams_failed = close_child_streams(platform, child).is_err();
    let observed_failed = model
        .child_streams_closed(child.event, now_millis(platform)?)
        .is_err();
    input_pending.clear();
    output_pending.clear();
    if raw_failed || watch_failed || streams_failed || observed_failed {
        return Err(70);
    }
    let retired = match wait_resolution {
        ChildWaitResolution::Cancelled => cleanup_job(
            platform,
            authorities,
            transactions,
            model,
            child.event,
            child.job_id,
        )?,
        ChildWaitResolution::Terminal => complete_terminal_reap(
            platform,
            authorities,
            transactions,
            model,
            child.event,
            child.job_id,
        )?,
    };
    if retired != RecoveryAction::None {
        return Err(72);
    }
    match model
        .complete_serial_cleanup(old_serial, old_console, now_millis(platform)?)
        .map_err(|_| 72u32)?
    {
        RecoveryAction::RetrySerialAt(deadline_ms) => {
            *serial = attach_serial_bounded(
                platform,
                authorities,
                transactions,
                model,
                Some(deadline_ms),
            )?;
            *child = launch_child(platform, authorities, transactions, model, serial)?;
            observe_exact_ready(platform, model, serial, child, 67)?;
            Ok(())
        }
        RecoveryAction::Escalate => Err(71),
        _ => Err(72),
    }
}

pub(crate) fn cleanup_job<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    model: &mut ConsoleModel,
    event: EventGeneration,
    job_id: u64,
) -> Result<RecoveryAction, u32> {
    let terminate = job_request(
        platform,
        authorities,
        transactions,
        LaunchMessageType::Terminate,
        job_id,
    )?;
    match terminate {
        LaunchReply::TerminationAccepted(response) if response == job_id => {}
        // A child which exited before its stream close reached us is already
        // terminal; WAIT remains the authoritative reap/result operation.
        LaunchReply::Error(LaunchErrorCode::InvalidState) => {}
        _ => return Err(73),
    }
    let waited = job_request(
        platform,
        authorities,
        transactions,
        LaunchMessageType::Wait,
        job_id,
    )?;
    if !matches!(waited, LaunchReply::JobResult { job_id: response, .. } if response == job_id) {
        return Err(75);
    }
    if !matches!(model.child_terminated(event, now_millis(platform)?), Ok(RecoveryAction::ReapChild(job)) if job == job_id)
    {
        return Err(74);
    }
    let closed = job_request(
        platform,
        authorities,
        transactions,
        LaunchMessageType::CloseJob,
        job_id,
    )?;
    if !matches!(closed, LaunchReply::Closed(response) if response == job_id) {
        return Err(76);
    }
    model
        .child_reaped(event, now_millis(platform)?)
        .map_err(|_| 77)
}

pub(crate) fn complete_terminal_reap<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    model: &mut ConsoleModel,
    event: EventGeneration,
    job_id: u64,
) -> Result<RecoveryAction, u32> {
    if !matches!(model.child_terminated(event, now_millis(platform)?), Ok(RecoveryAction::ReapChild(job)) if job == job_id)
    {
        return Err(74);
    }
    close_reaped_job(platform, authorities, transactions, model, event, job_id)
}

pub(crate) fn close_reaped_job<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    model: &mut ConsoleModel,
    event: EventGeneration,
    job_id: u64,
) -> Result<RecoveryAction, u32> {
    let closed = job_request(
        platform,
        authorities,
        transactions,
        LaunchMessageType::CloseJob,
        job_id,
    )?;
    if !matches!(closed, LaunchReply::Closed(response) if response == job_id) {
        return Err(76);
    }
    model
        .child_reaped(event, now_millis(platform)?)
        .map_err(|_| 77)
}

pub(crate) fn cleanup_unmodeled_job<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    job_id: u64,
) -> Result<(), u32> {
    let terminate = job_request(
        platform,
        authorities,
        transactions,
        LaunchMessageType::Terminate,
        job_id,
    )?;
    if !matches!(
        terminate,
        LaunchReply::TerminationAccepted(response) if response == job_id
    ) && terminate != LaunchReply::Error(LaunchErrorCode::InvalidState)
    {
        return Err(78);
    }
    let waited = job_request(
        platform,
        authorities,
        transactions,
        LaunchMessageType::Wait,
        job_id,
    )?;
    if !matches!(waited, LaunchReply::JobResult { job_id: response, .. } if response == job_id) {
        return Err(79);
    }
    let closed = job_request(
        platform,
        authorities,
        transactions,
        LaunchMessageType::CloseJob,
        job_id,
    )?;
    if !matches!(closed, LaunchReply::Closed(response) if response == job_id) {
        return Err(80);
    }
    Ok(())
}

pub(crate) fn start_job_wait<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    job_id: u64,
) -> Result<LaunchReservation, u32> {
    let reservation = LaunchReservation {
        connection_id: authorities.launch_connection_id,
        generation: authorities.launch_connection_generation,
        transaction_id: transactions.take()?,
    };
    let mut bytes = [0u8; 64];
    let size = encode_job_message(reservation, LaunchMessageType::Wait, job_id, &mut bytes)
        .map_err(|_| 78u32)?;
    platform
        .send_channel(authorities.launch, &bytes[..size], &[])
        .map_err(|_| 79u32)?;
    Ok(reservation)
}

pub(crate) fn cancel_child_wait<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    child: &mut ChildSession,
) -> Result<ChildWaitResolution, u32> {
    let target = child.wait.ok_or(78u32)?;
    let cancellation = LaunchReservation {
        connection_id: authorities.launch_connection_id,
        generation: authorities.launch_connection_generation,
        transaction_id: transactions.take()?,
    };
    let mut bytes = [0u8; 64];
    let size = encode_job_message(
        cancellation,
        LaunchMessageType::Cancel,
        target.transaction_id,
        &mut bytes,
    )
    .map_err(|_| 79u32)?;
    platform
        .send_channel(authorities.launch, &bytes[..size], &[])
        .map_err(|_| 80u32)?;

    let mut terminal = false;
    let mut received = 0;
    while received < 2 {
        let (reservation, reply) = receive_launch_any(platform, authorities.launch)?;
        if reservation == target
            && matches!(reply, LaunchReply::JobResult { job_id, .. } if job_id == child.job_id)
        {
            terminal = true;
            received += 1;
            continue;
        }
        if reservation == cancellation
            && reply == LaunchReply::Cancelled(target.transaction_id)
            && !terminal
        {
            child.wait = None;
            return Ok(ChildWaitResolution::Cancelled);
        }
        if reservation == cancellation
            && reply == LaunchReply::Error(LaunchErrorCode::CancellationUnavailable)
            && terminal
        {
            child.wait = None;
            return Ok(ChildWaitResolution::Terminal);
        }
        return Err(81);
    }
    Err(81)
}

pub(crate) fn cleanup_child_for_exit<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    child: &mut ChildSession,
) -> Result<(), u32> {
    let resolution = cancel_child_wait(platform, authorities, transactions, child);
    let streams_closed = close_child_streams(platform, child);
    let result = match resolution? {
        ChildWaitResolution::Cancelled => {
            cleanup_unmodeled_job(platform, authorities, transactions, child.job_id)
        }
        ChildWaitResolution::Terminal => {
            let reply = job_request(
                platform,
                authorities,
                transactions,
                LaunchMessageType::CloseJob,
                child.job_id,
            )?;
            if reply == LaunchReply::Closed(child.job_id) {
                Ok(())
            } else {
                Err(80)
            }
        }
    };
    streams_closed?;
    result
}

pub(crate) fn job_request<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    kind: LaunchMessageType,
    job_id: u64,
) -> Result<LaunchReply, u32> {
    let reservation = LaunchReservation {
        connection_id: authorities.launch_connection_id,
        generation: authorities.launch_connection_generation,
        transaction_id: transactions.take()?,
    };
    let mut bytes = [0u8; 128];
    let size = encode_job_message(reservation, kind, job_id, &mut bytes).map_err(|_| 73u32)?;
    platform
        .send_channel(authorities.launch, &bytes[..size], &[])
        .map_err(|_| 74u32)?;
    receive_launch(platform, authorities.launch, reservation)
}
