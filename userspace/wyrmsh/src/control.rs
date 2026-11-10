//! The control transport to consoled.

use super::*;

pub(crate) fn control_deadline<System: WyrmshSystem>(
    system: &mut System,
) -> Result<DwDeadline, ShellError> {
    let deadline = system
        .monotonic_active_now()
        .map_err(|cause| native(NativeOperation::MonotonicClock, cause))?
        .checked_add(inspection::STATUS_TIMEOUT_NS)
        .ok_or(ShellError::InspectionProtocol)?;
    if deadline == DW_DEADLINE_INFINITE.0 {
        return Err(ShellError::InspectionProtocol);
    }
    Ok(DwDeadline(deadline))
}

pub(crate) fn ensure_before_control_deadline<System: WyrmshSystem>(
    system: &mut System,
    deadline: DwDeadline,
) -> Result<(), ShellError> {
    if system
        .monotonic_active_now()
        .map_err(|cause| native(NativeOperation::MonotonicClock, cause))?
        >= deadline.0
    {
        return Err(ShellError::InspectionTimeout);
    }
    Ok(())
}

pub(crate) fn status_state_name(state: wyrmroot_console_proto::State) -> &'static [u8] {
    match state {
        wyrmroot_console_proto::State::Active => b"active",
        wyrmroot_console_proto::State::RetiringChild => b"retiring-child",
        wyrmroot_console_proto::State::AwaitingReap => b"awaiting-reap",
        wyrmroot_console_proto::State::Reconnecting => b"reconnecting",
        wyrmroot_console_proto::State::Exhausted => b"exhausted",
        wyrmroot_console_proto::State::FailClosed => b"fail-closed",
    }
}

pub(crate) fn write_u64<System: WyrmshSystem>(
    system: &mut System,
    stdout: &mut NativeOutput,
    stderr_handle: DwHandle,
    controls: Controls,
    mut value: u64,
) -> Result<(), ShellError> {
    let mut bytes = [0_u8; 20];
    let mut cursor = bytes.len();
    loop {
        cursor -= 1;
        bytes[cursor] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            return write_stdout(system, stdout, stderr_handle, controls, &bytes[cursor..]);
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "explicit control and output peer custody"
)]
pub(crate) fn send_control<System: WyrmshSystem>(
    system: &mut System,
    target: DwHandle,
    role: EndpointRole,
    controls: Controls,
    stdout: DwHandle,
    stderr: DwHandle,
    bytes: &[u8],
    deadline: DwDeadline,
) -> Result<(), ShellError> {
    ensure_before_control_deadline(system, deadline)?;
    match system.send_channel(target, bytes) {
        Ok(()) => return Ok(()),
        Err(NativeError::Status(status)) if status == DW_STATUS_WOULD_BLOCK => {}
        Err(cause) => return Err(native(NativeOperation::ControlSend, cause)),
    }
    wait_for_control(
        system,
        target,
        role,
        controls,
        stdout,
        stderr,
        DW_SIGNAL_WRITABLE,
        deadline,
    )?;
    match system.send_channel(target, bytes) {
        Ok(()) => Ok(()),
        Err(NativeError::Status(status)) if status == DW_STATUS_WOULD_BLOCK => {
            ensure_before_control_deadline(system, deadline)?;
            Err(ShellError::InspectionProtocol)
        }
        Err(cause) => Err(native(NativeOperation::ControlSend, cause)),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "explicit control and output peer custody"
)]
pub(crate) fn receive_control<System: WyrmshSystem>(
    system: &mut System,
    target: DwHandle,
    role: EndpointRole,
    controls: Controls,
    stdout: DwHandle,
    stderr: DwHandle,
    bytes: &mut [u8],
    deadline: DwDeadline,
) -> Result<usize, ShellError> {
    wait_for_control(
        system,
        target,
        role,
        controls,
        stdout,
        stderr,
        DW_SIGNAL_READABLE,
        deadline,
    )?;
    let mut handles = [DwReceivedHandleInfoV1::default(); CONTROL_HANDLE_CAPACITY];
    let counts = system
        .receive_channel(target, bytes, &mut handles)
        .map_err(|cause| native(NativeOperation::ControlReceive, cause))?;
    if counts.handles != 0 {
        let cleanup = close_received(system, &handles, counts.handles.min(handles.len()));
        if let Some(cause) = cleanup {
            return Err(native(NativeOperation::Cleanup, cause));
        }
        return Err(ShellError::InspectionProtocol);
    }
    if counts.bytes > bytes.len() {
        return Err(ShellError::InspectionProtocol);
    }
    Ok(counts.bytes)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn wait_for_control<System: WyrmshSystem>(
    system: &mut System,
    target: DwHandle,
    role: EndpointRole,
    controls: Controls,
    stdout: DwHandle,
    stderr: DwHandle,
    signal: DwSignals,
    deadline: DwDeadline,
) -> Result<(), ShellError> {
    let mut items = health_items(controls, stdout, stderr);
    let target_index = match role {
        EndpointRole::ConsoleStatus if target == controls.console_status => 0,
        EndpointRole::Registry if target == controls.registry => 1,
        EndpointRole::ShellJobs if target == controls.shell_jobs => 2,
        _ => return Err(ShellError::InspectionProtocol),
    };
    items[target_index] = wait_item(target, DwSignals(signal.0 | DW_SIGNAL_PEER_CLOSED.0));
    let result = match system.wait_many(&items, deadline) {
        Ok(result) => result,
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {
            return Err(ShellError::InspectionTimeout);
        }
        Err(cause) => return Err(native(NativeOperation::Wait, cause)),
    };
    if usize::try_from(result.index).ok() != Some(target_index) {
        return classify_health(result);
    }
    if result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
        return Err(ShellError::RequiredEndpointLost(role));
    }
    if result.observed.0 & signal.0 == 0 {
        return Err(ShellError::InspectionProtocol);
    }
    ensure_before_control_deadline(system, deadline)
}
