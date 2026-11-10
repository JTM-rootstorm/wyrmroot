//! Terminal output, input and health waits.

use super::*;

pub(crate) fn present_edit_error<System: WyrmshSystem>(
    system: &mut System,
    stderr: &mut NativeOutput,
    stdout_handle: DwHandle,
    controls: Controls,
    error: EditError,
) -> Result<(), ShellError> {
    let message = match error {
        EditError::Input(_) => b"\nerror: invalid input\n".as_slice(),
        EditError::LineTooLong => b"\nerror: line too long\n".as_slice(),
        EditError::UnsupportedCharacter => b"\nerror: unsupported character\n".as_slice(),
    };
    write_stderr(system, stderr, stdout_handle, controls, message)
}

pub(crate) fn present_command_error<System: WyrmshSystem>(
    system: &mut System,
    stderr: &mut NativeOutput,
    stdout_handle: DwHandle,
    controls: Controls,
    error: CommandError,
) -> Result<(), ShellError> {
    let message = match error {
        CommandError::Parse(_) => b"error: parse\n".as_slice(),
        CommandError::Usage(UsageError::UnknownCommand) => b"error: unknown command\n".as_slice(),
        CommandError::Usage(_) => b"error: usage\n".as_slice(),
    };
    write_stderr(system, stderr, stdout_handle, controls, message)
}

pub(crate) fn write_stdout<System: WyrmshSystem>(
    system: &mut System,
    output: &mut NativeOutput,
    stderr_handle: DwHandle,
    controls: Controls,
    bytes: &[u8],
) -> Result<(), ShellError> {
    let stdout_handle = output.endpoint().handle();
    write_all(
        system,
        output,
        EndpointRole::Stdout,
        stdout_handle,
        stderr_handle,
        controls,
        bytes,
    )
}

pub(crate) fn write_stderr<System: WyrmshSystem>(
    system: &mut System,
    output: &mut NativeOutput,
    stdout_handle: DwHandle,
    controls: Controls,
    bytes: &[u8],
) -> Result<(), ShellError> {
    let stderr_handle = output.endpoint().handle();
    write_all(
        system,
        output,
        EndpointRole::Stderr,
        stdout_handle,
        stderr_handle,
        controls,
        bytes,
    )
}

pub(crate) fn write_all<System: WyrmshSystem>(
    system: &mut System,
    output: &mut NativeOutput,
    role: EndpointRole,
    stdout: DwHandle,
    stderr: DwHandle,
    controls: Controls,
    bytes: &[u8],
) -> Result<(), ShellError> {
    let mut committed = 0;
    while committed != bytes.len() {
        poll_health(system, controls, stdout, stderr)?;
        match output.write(system, &bytes[committed..]) {
            Ok(0) => return Err(ShellError::Stream(StreamError::Protocol)),
            Ok(written) => {
                committed += written;
                if committed != bytes.len() {
                    wait_for_output(system, output, role, stdout, stderr, controls)?;
                }
            }
            Err(StreamError::WouldBlock) => {
                wait_for_output(system, output, role, stdout, stderr, controls)?;
            }
            Err(StreamError::Broken) => {
                return Err(ShellError::RequiredEndpointLost(role));
            }
            Err(error) => return Err(ShellError::Stream(error)),
        }
    }
    Ok(())
}

pub(crate) fn poll_health<System: WyrmshSystem>(
    system: &mut System,
    controls: Controls,
    stdout: DwHandle,
    stderr: DwHandle,
) -> Result<(), ShellError> {
    let items = health_items(controls, stdout, stderr);
    match system.wait_many(&items, DW_DEADLINE_NOW) {
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => Ok(()),
        Err(cause) => Err(native(NativeOperation::Wait, cause)),
        Ok(result) => classify_health(result),
    }
}

pub(crate) fn wait_for_input<System: WyrmshSystem>(
    system: &mut System,
    input: &mut NativeInput,
    controls: Controls,
    stdout: DwHandle,
    stderr: DwHandle,
) -> Result<(), ShellError> {
    let health = health_items(controls, stdout, stderr);
    let items = [
        health[0],
        health[1],
        health[2],
        health[3],
        health[4],
        wait_item(input.endpoint().handle(), INPUT_WAIT_SIGNALS),
    ];
    let result = system
        .wait_many(&items, DW_DEADLINE_INFINITE)
        .map_err(|cause| native(NativeOperation::Wait, cause))?;
    if result.index < 5 {
        return classify_health(result);
    }
    if result.index != 5 {
        return Err(ShellError::Stream(StreamError::Protocol));
    }
    input
        .observe_wait(result.observed)
        .map_err(ShellError::Stream)
}

pub(crate) fn wait_for_output<System: WyrmshSystem>(
    system: &mut System,
    output: &NativeOutput,
    role: EndpointRole,
    stdout: DwHandle,
    stderr: DwHandle,
    controls: Controls,
) -> Result<(), ShellError> {
    let target = output.endpoint().handle();
    let mut items = health_items(controls, stdout, stderr);
    let target_index = match role {
        EndpointRole::Stdout if target == stdout => 3,
        EndpointRole::Stderr if target == stderr => 4,
        _ => return Err(ShellError::Stream(StreamError::Protocol)),
    };
    items[target_index] = wait_item(target, OUTPUT_WAIT_SIGNALS);
    let result = system
        .wait_many(&items, DW_DEADLINE_INFINITE)
        .map_err(|cause| native(NativeOperation::Wait, cause))?;
    if usize::try_from(result.index).ok() != Some(target_index) {
        return classify_health(result);
    }
    output
        .observe_wait(result.observed)
        .map_err(|error| match error {
            StreamError::Broken => ShellError::RequiredEndpointLost(role),
            other => ShellError::Stream(other),
        })
}

pub(crate) fn health_items(
    controls: Controls,
    stdout: DwHandle,
    stderr: DwHandle,
) -> [DwWaitItemV1; 5] {
    [
        wait_item(controls.console_status, DW_SIGNAL_PEER_CLOSED),
        wait_item(controls.registry, DW_SIGNAL_PEER_CLOSED),
        wait_item(controls.shell_jobs, DW_SIGNAL_PEER_CLOSED),
        wait_item(stdout, DW_SIGNAL_PEER_CLOSED),
        wait_item(stderr, DW_SIGNAL_PEER_CLOSED),
    ]
}

pub(crate) fn classify_health(result: DwWaitResultV1) -> Result<(), ShellError> {
    let role = match result.index {
        0 => EndpointRole::ConsoleStatus,
        1 => EndpointRole::Registry,
        2 => EndpointRole::ShellJobs,
        3 => EndpointRole::Stdout,
        4 => EndpointRole::Stderr,
        _ => return Err(ShellError::Stream(StreamError::Protocol)),
    };
    if result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 == 0 {
        return Err(ShellError::Stream(StreamError::Protocol));
    }
    Err(ShellError::RequiredEndpointLost(role))
}

pub(crate) const fn wait_item(handle: DwHandle, signals: DwSignals) -> DwWaitItemV1 {
    DwWaitItemV1 { handle, signals }
}

pub(crate) fn close_received<System: WyrmshSystem, const N: usize>(
    system: &mut System,
    handles: &[DwReceivedHandleInfoV1; N],
    count: usize,
) -> Option<NativeError> {
    let mut failure = None;
    let mut index = count;
    while index != 0 {
        index -= 1;
        let handle = handles[index].handle;
        if handle.0 != 0
            && let Err(error) = system.close_handle(handle)
        {
            failure.get_or_insert(error);
        }
    }
    failure
}

/// Limits the amount of native receive work one `NativeInput::read` call may
/// perform. In particular, an attacker cannot keep that call trapped forever
/// by supplying an always-readable sequence of empty WRST DATA records.
pub(crate) struct ReceiveBudget<'a, System> {
    pub(crate) inner: &'a mut System,
    pub(crate) remaining: usize,
}

impl<'a, System> ReceiveBudget<'a, System> {
    pub(crate) const fn new(inner: &'a mut System) -> Self {
        Self {
            inner,
            remaining: 8,
        }
    }
}

impl<System: StreamSystem> StreamSystem for ReceiveBudget<'_, System> {
    fn receive(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError> {
        if self.remaining == 0 {
            return Err(NativeError::Status(deepwyrm_syscall::DW_STATUS_WOULD_BLOCK));
        }
        self.remaining -= 1;
        self.inner.receive(channel, bytes, handles)
    }

    fn send(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
        self.inner.send(channel, bytes)
    }

    fn close(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        self.inner.close(handle)
    }

    fn wait(&mut self, channel: DwHandle, signals: DwSignals) -> Result<DwSignals, NativeError> {
        self.inner.wait(channel, signals)
    }
}

pub(crate) const fn native(operation: NativeOperation, cause: NativeError) -> ShellError {
    ShellError::Native { operation, cause }
}
