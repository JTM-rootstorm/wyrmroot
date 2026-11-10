//! The foreground job: output draining, waits and cancellation.

use super::*;

#[derive(Debug)]
pub(crate) enum ForegroundError {
    /// A non-fatal foreground-stream disposition: this job's stdout/stderr
    /// write side or stdin read side broke down, but the shell itself
    /// survives — the caller cancels and closes just this job, then reports
    /// `run stream=<cause>` to the reader's channel (see the
    /// `Err(ForegroundError::Stream(cause))` arm below `drain_foreground`'s
    /// call site). That is a different action from `Fatal`, which unwinds
    /// `run` and tears the whole shell down, so F3A.6n keeps `Stream` as its
    /// own disposition rather than rerouting it into
    /// `Fatal(ShellError::Stream(_))` the way the write path's other
    /// `StreamError`s already are (DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md
    /// §3.1 only allows a collapse when the correct action is identical,
    /// and here it is not). Per §3.2, the collapse this disposition already
    /// makes (many causes, one action) still owes its discarded instance to
    /// the reader, so it carries a payload instead of erasing it.
    Stream(ForegroundStreamCause),
    Fatal(ShellError),
}

/// The cause carried by a non-fatal `ForegroundError::Stream`. `WriteExhausted`
/// and `ReadExhausted` name the two `Ok(0)` sites in `drain_foreground`: a
/// zero-length copy is a distinct cause from any `StreamError` and, before
/// F3A.6n, was silently the same bare word as every other stream failure.
/// `Read` carries the stdin `StreamError` itself, mirroring the write path's
/// `Err(error) => ... ShellError::Stream(error)` arm twenty lines above in
/// the same match ladder — the established pattern for "keep the value, do
/// not collapse it" — rather than inventing a new one.
#[derive(Debug)]
pub(crate) enum ForegroundStreamCause {
    WriteExhausted,
    ReadExhausted,
    Read(StreamError),
}

/// Names a `ForegroundStreamCause` for the reader's channel (the
/// `run stream=<name>` line). Exhaustive over both this type and, through
/// `stream_error_name`, over `StreamError` itself:
/// DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md §3.4 forbids a wildcard arm at a
/// diagnostic boundary because it would silently adopt every variant added
/// later.
pub(crate) fn foreground_stream_cause_name(cause: &ForegroundStreamCause) -> &'static [u8] {
    match cause {
        ForegroundStreamCause::WriteExhausted => b"write-exhausted",
        ForegroundStreamCause::ReadExhausted => b"read-exhausted",
        ForegroundStreamCause::Read(error) => stream_error_name(error),
    }
}

/// Exhaustive name table for `StreamError`. `WouldBlock` and `Eof` are
/// unreachable from the `ForegroundStreamCause::Read` site in practice (the
/// drain loop peels both off before building this cause), but no_std guest
/// code must not panic to assert that with `unreachable!()`, so they still
/// get a real static name rather than being folded into a wildcard.
pub(crate) fn stream_error_name(error: &StreamError) -> &'static [u8] {
    match error {
        StreamError::Native(_) => b"native",
        StreamError::WouldBlock => b"would-block",
        StreamError::Eof => b"eof",
        StreamError::Broken => b"broken",
        StreamError::Protocol => b"protocol",
        StreamError::ReceivedHandles => b"received-handles",
        StreamError::Failed => b"failed",
        StreamError::Launch(_) => b"launch",
    }
}

pub(crate) struct PendingOutput {
    pub(crate) bytes: [u8; 256],
    pub(crate) offset: usize,
    pub(crate) used: usize,
}

impl PendingOutput {
    pub(crate) const fn new() -> Self {
        Self {
            bytes: [0; 256],
            offset: 0,
            used: 0,
        }
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.offset == self.used
    }

    pub(crate) fn clear(&mut self) {
        self.offset = 0;
        self.used = 0;
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn drain_foreground<System: WyrmshSystem>(
    system: &mut System,
    stdout: &mut NativeOutput,
    stderr: &mut NativeOutput,
    identity: ShellIdentity,
    controls: Controls,
    wait_transaction: u64,
    job_id: u64,
    child_stdout: &mut NativeInput,
    child_stderr: &mut NativeInput,
) -> Result<TerminationResult, ForegroundError> {
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    let mut terminal = None;
    let mut first_stdout = true;
    let mut stdout_pending = PendingOutput::new();
    let mut stderr_pending = PendingOutput::new();
    loop {
        poll_health(
            system,
            controls,
            stdout.endpoint().handle(),
            stderr.endpoint().handle(),
        )
        .map_err(ForegroundError::Fatal)?;
        let mut progress = false;
        for offset in 0..2 {
            let use_stdout = (offset == 0) == first_stdout;
            let (input, output, eof, pending, output_role) = if use_stdout {
                (
                    &mut *child_stdout,
                    &mut *stdout,
                    &mut stdout_eof,
                    &mut stdout_pending,
                    EndpointRole::Stdout,
                )
            } else {
                (
                    &mut *child_stderr,
                    &mut *stderr,
                    &mut stderr_eof,
                    &mut stderr_pending,
                    EndpointRole::Stderr,
                )
            };
            if !pending.is_empty() {
                match output.write(system, &pending.bytes[pending.offset..pending.used]) {
                    Ok(0) => {
                        return Err(ForegroundError::Stream(
                            ForegroundStreamCause::WriteExhausted,
                        ));
                    }
                    Ok(written) => {
                        pending.offset += written;
                        if pending.is_empty() {
                            pending.clear();
                        }
                        progress = true;
                    }
                    Err(StreamError::WouldBlock) => {}
                    Err(StreamError::Broken) => {
                        return Err(ForegroundError::Fatal(ShellError::RequiredEndpointLost(
                            output_role,
                        )));
                    }
                    Err(error) => return Err(ForegroundError::Fatal(ShellError::Stream(error))),
                }
                continue;
            }
            if *eof {
                continue;
            }
            let mut bounded = ReceiveBudget::new(system);
            match input.read(&mut bounded, &mut pending.bytes) {
                Ok(0) => {
                    return Err(ForegroundError::Stream(
                        ForegroundStreamCause::ReadExhausted,
                    ));
                }
                Ok(used) => {
                    pending.offset = 0;
                    pending.used = used;
                    progress = true;
                }
                Err(StreamError::WouldBlock) => {}
                Err(StreamError::Eof) => {
                    *eof = true;
                    progress = true;
                }
                // F3A.6n: keep the cause instead of folding every remaining
                // `StreamError` (Native, Broken, Protocol, ReceivedHandles,
                // Failed, Launch) into the same bare disposition — see
                // `ForegroundStreamCause::Read` and
                // DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md §3.2/§3.4.
                Err(error) => {
                    return Err(ForegroundError::Stream(ForegroundStreamCause::Read(error)));
                }
            }
        }
        first_stdout = !first_stdout;
        if terminal.is_none() {
            match try_receive_job(system, identity, controls, stdout, stderr, wait_transaction)
                .map_err(ForegroundError::Fatal)?
            {
                Some(Reply::JobResult(actual, result)) if actual == job_id => {
                    terminal = Some(result);
                    progress = true;
                }
                Some(Reply::Error(code)) => {
                    return Err(ForegroundError::Fatal(job_error_fatal(code)));
                }
                Some(_) => return Err(ForegroundError::Fatal(ShellError::InspectionProtocol)),
                None => {}
            }
        }
        if let Some(result) = terminal
            && stdout_eof
            && stderr_eof
            && stdout_pending.is_empty()
            && stderr_pending.is_empty()
        {
            return Ok(result);
        }
        if !progress {
            wait_foreground(
                system,
                controls,
                stdout,
                stderr,
                child_stdout,
                child_stderr,
                stdout_eof,
                stderr_eof,
                !stdout_pending.is_empty(),
                !stderr_pending.is_empty(),
            )
            .map_err(ForegroundError::Fatal)?;
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn try_receive_job<System: WyrmshSystem>(
    system: &mut System,
    identity: ShellIdentity,
    controls: Controls,
    _stdout: &NativeOutput,
    _stderr: &NativeOutput,
    transaction: u64,
) -> Result<Option<Reply>, ShellError> {
    let mut bytes = [0_u8; 88];
    let mut handles = [DwReceivedHandleInfoV1::default(); 4];
    let counts = match system.receive_channel(controls.shell_jobs, &mut bytes, &mut handles) {
        Err(NativeError::Status(status)) if status == DW_STATUS_WOULD_BLOCK => return Ok(None),
        Err(NativeError::Status(status)) if status == DW_STATUS_PEER_CLOSED => {
            return Err(ShellError::RequiredEndpointLost(EndpointRole::ShellJobs));
        }
        Err(cause) => return Err(native(NativeOperation::ControlReceive, cause)),
        Ok(counts) => counts,
    };
    if counts.handles != 0 || counts.bytes > bytes.len() {
        for received in handles.iter().take(counts.handles.min(handles.len())).rev() {
            if received.handle.0 != 0 {
                system
                    .close_handle(received.handle)
                    .map_err(|cause| native(NativeOperation::Cleanup, cause))?;
            }
        }
        return Err(ShellError::InspectionProtocol);
    }
    decode_reply(identity, transaction, &bytes[..counts.bytes], 0)
        .map(Some)
        .map_err(|_| ShellError::InspectionProtocol)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn wait_foreground<System: WyrmshSystem>(
    system: &mut System,
    controls: Controls,
    stdout: &NativeOutput,
    stderr: &NativeOutput,
    child_stdout: &mut NativeInput,
    child_stderr: &mut NativeInput,
    stdout_eof: bool,
    stderr_eof: bool,
    stdout_pending: bool,
    stderr_pending: bool,
) -> Result<(), ShellError> {
    let health = health_items(
        controls,
        stdout.endpoint().handle(),
        stderr.endpoint().handle(),
    );
    let mut items = [wait_item(DwHandle(0), DwSignals(0)); 7];
    items[..5].copy_from_slice(&[
        health[0],
        health[1],
        wait_item(
            controls.shell_jobs,
            DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        ),
        health[3],
        health[4],
    ]);
    if stdout_pending {
        items[3] = wait_item(
            stdout.endpoint().handle(),
            DwSignals(DW_SIGNAL_WRITABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        );
    }
    if stderr_pending {
        items[4] = wait_item(
            stderr.endpoint().handle(),
            DwSignals(DW_SIGNAL_WRITABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        );
    }
    let mut count = 5;
    let stdout_index = if stdout_eof || stdout_pending {
        None
    } else {
        items[count] = wait_item(
            child_stdout.endpoint().handle(),
            DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        );
        count += 1;
        Some(count - 1)
    };
    let stderr_index = if stderr_eof || stderr_pending {
        None
    } else {
        items[count] = wait_item(
            child_stderr.endpoint().handle(),
            DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        );
        count += 1;
        Some(count - 1)
    };
    let deadline = progress_deadline(system)?;
    let result = match system.wait_many(&items[..count], deadline) {
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => return Ok(()),
        Err(cause) => return Err(native(NativeOperation::Wait, cause)),
        Ok(result) => result,
    };
    match result.index {
        0 | 1 => classify_health(result),
        3 if stdout_pending => {
            if result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
                classify_health(result)
            } else if result.observed.0 & DW_SIGNAL_WRITABLE.0 != 0 {
                Ok(())
            } else {
                Err(ShellError::InspectionProtocol)
            }
        }
        4 if stderr_pending => {
            if result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
                classify_health(result)
            } else if result.observed.0 & DW_SIGNAL_WRITABLE.0 != 0 {
                Ok(())
            } else {
                Err(ShellError::InspectionProtocol)
            }
        }
        3 | 4 => classify_health(result),
        2 => {
            if result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
                Err(ShellError::RequiredEndpointLost(EndpointRole::ShellJobs))
            } else if result.observed.0 & DW_SIGNAL_READABLE.0 != 0 {
                Ok(())
            } else {
                Err(ShellError::InspectionProtocol)
            }
        }
        index if usize::try_from(index).ok() == stdout_index => child_stdout
            .observe_wait(result.observed)
            .map_err(ShellError::Stream),
        index if usize::try_from(index).ok() == stderr_index => child_stderr
            .observe_wait(result.observed)
            .map_err(ShellError::Stream),
        _ => Err(ShellError::InspectionProtocol),
    }
}

pub(crate) fn job_error_fatal(_code: ErrorCode) -> ShellError {
    ShellError::InspectionProtocol
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cancel_wait<System: WyrmshSystem>(
    system: &mut System,
    stdout: &NativeOutput,
    stderr: &NativeOutput,
    identity: ShellIdentity,
    controls: Controls,
    transactions: &mut TransactionIds,
    wait_transaction: u64,
    job_id: u64,
) -> Result<CancelResolution, ShellError> {
    let cancel_transaction = transactions
        .launch()
        .map_err(|_| ShellError::TransactionExhausted)?;
    let mut request = [0_u8; 56];
    let size = encode_job_message(
        reservation(identity, cancel_transaction),
        MessageType::Cancel,
        wait_transaction,
        &mut request,
    )
    .map_err(|_| ShellError::InspectionProtocol)?;
    let deadline = control_deadline(system)?;
    send_control(
        system,
        controls.shell_jobs,
        EndpointRole::ShellJobs,
        controls,
        stdout.endpoint().handle(),
        stderr.endpoint().handle(),
        &request[..size],
        deadline,
    )?;
    let mut result = None;
    let mut unavailable = false;
    loop {
        if system
            .monotonic_active_now()
            .map_err(|cause| native(NativeOperation::MonotonicClock, cause))?
            >= deadline.0
        {
            return Err(ShellError::InspectionTimeout);
        }
        let Some((transaction, reply)) = receive_one_until(
            system,
            identity,
            controls,
            stdout,
            stderr,
            wait_transaction,
            cancel_transaction,
            deadline,
        )?
        else {
            return Err(ShellError::InspectionTimeout);
        };
        ensure_before_control_deadline(system, deadline)?;
        if transaction == cancel_transaction {
            match reply {
                Reply::Cancelled(target)
                    if target == wait_transaction && result.is_none() && !unavailable =>
                {
                    return Ok(CancelResolution::Cancelled);
                }
                Reply::Error(ErrorCode::CancellationUnavailable) if !unavailable => {
                    unavailable = true
                }
                _ => return Err(ShellError::InspectionProtocol),
            }
        } else {
            match reply {
                Reply::JobResult(actual, terminal) if actual == job_id && result.is_none() => {
                    result = Some(terminal)
                }
                _ => return Err(ShellError::InspectionProtocol),
            }
        }
        if let (Some(terminal), true) = (result, unavailable) {
            return Ok(CancelResolution::Terminal(terminal));
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn receive_one_until<System: WyrmshSystem>(
    system: &mut System,
    identity: ShellIdentity,
    controls: Controls,
    stdout: &NativeOutput,
    stderr: &NativeOutput,
    first: u64,
    second: u64,
    deadline: DwDeadline,
) -> Result<Option<(u64, Reply)>, ShellError> {
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
    receive_correlated_datagram(system, identity, controls, first, second)
}

pub(crate) fn receive_correlated_datagram<System: WyrmshSystem>(
    system: &mut System,
    identity: ShellIdentity,
    controls: Controls,
    first: u64,
    second: u64,
) -> Result<Option<(u64, Reply)>, ShellError> {
    let mut bytes = [0_u8; 88];
    let mut handles = [DwReceivedHandleInfoV1::default(); 4];
    let counts = match system.receive_channel(controls.shell_jobs, &mut bytes, &mut handles) {
        Err(NativeError::Status(status)) if status == DW_STATUS_PEER_CLOSED => {
            return Err(ShellError::RequiredEndpointLost(EndpointRole::ShellJobs));
        }
        Err(cause) => return Err(native(NativeOperation::ControlReceive, cause)),
        Ok(counts) => counts,
    };
    if counts.handles != 0 || counts.bytes > bytes.len() {
        for received in handles.iter().take(counts.handles.min(handles.len())).rev() {
            if received.handle.0 != 0 {
                system
                    .close_handle(received.handle)
                    .map_err(|cause| native(NativeOperation::Cleanup, cause))?;
            }
        }
        return Err(ShellError::InspectionProtocol);
    }
    let parsed = wyrmroot_launch_proto::parse_message(&bytes[..counts.bytes], 0)
        .map_err(|_| ShellError::InspectionProtocol)?;
    let transaction = parsed.reservation.transaction_id;
    if transaction != first && transaction != second {
        return Err(ShellError::InspectionProtocol);
    }
    let reply = decode_reply(identity, transaction, &bytes[..counts.bytes], 0)
        .map_err(|_| ShellError::InspectionProtocol)?;
    Ok(Some((transaction, reply)))
}
