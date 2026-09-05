// SPDX-License-Identifier: GPL-3.0-or-later
#![no_std]
#![forbid(unsafe_code)]

//! Allocation-free WYR1-E shell startup and local-command runtime.

use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_DEADLINE_NOW, DW_OBJECT_TYPE_CHANNEL, DW_SIGNAL_PEER_CLOSED,
    DW_SIGNAL_READABLE, DW_STATUS_TIMED_OUT, DwDeadline, DwHandle, DwObjectType,
    DwReceivedHandleInfoV1, DwRights, DwSignals, DwWaitItemV1, DwWaitResultV1,
};
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, HEADER_BYTES, LaunchError, LaunchProfile, WYRMSH_BYTES,
    encode_ready_for_profile, parse_wyrmsh_init,
};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, CapabilityValidationError, INPUT_WAIT_SIGNALS,
    NativeError, NativeInput, NativeOutput, OUTPUT_WAIT_SIGNALS, ReceiveCounts, STARTUP_ABI_V2,
    StartupBlock, StreamEndpoint, StreamError, StreamSystem, native_error_code,
    validate_bootstrap_channel,
};
#[cfg(test)]
use wyrmroot_stream_proto as _;
use wyrmroot_wyrmsh_core::{
    COMMANDS, Command, CommandName, EditError, EditOutcome, Editor, InputDecoder, ParseError,
    Parser, UsageError,
};

const HANDLE_COUNT: usize = 6;
const CLEAR_DISPLAY: &[u8] = b"\x1b[2J\x1b[H";
const SUBMISSION_NEWLINE: &[u8] = b"\n";

/// Native operations that can fail before or during one shell generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum NativeOperation {
    QueryBootstrap = 1,
    ReceiveInit = 2,
    QueryRole = 3,
    SendReady = 4,
    AwaitRelease = 5,
    CloseBootstrap = 6,
    Wait = 7,
    Cleanup = 8,
}

/// The endpoint whose loss makes the shell generation unusable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointRole {
    Stdin,
    Stdout,
    Stderr,
    ConsoleStatus,
    Registry,
    ShellJobs,
}

/// Exact non-authoritative correlation tuple retained for later E4C/E5 requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShellIdentity {
    pub transaction_id: u64,
    pub registry_generation: u64,
    pub registry_endpoint_id: u64,
    pub registry_endpoint_generation: u64,
    pub launch_connection_id: u64,
    pub launch_connection_generation: u64,
    pub console_generation: u64,
    pub status_generation: u64,
    pub child_generation: u64,
    pub outer_launch_transaction: u64,
}

/// Bounded failures; only explicit `exit` and Ctrl-D on an empty line return success.
#[derive(Debug, Eq, PartialEq)]
pub enum ShellError {
    Startup,
    Native {
        operation: NativeOperation,
        cause: NativeError,
    },
    BootstrapChannel(CapabilityValidationError),
    ReceiveCounts(ReceiveCounts),
    Launch(LaunchError),
    FreshCapability {
        index: usize,
    },
    UnexpectedBootstrapRelease(DwSignals),
    RequiredEndpointLost(EndpointRole),
    Stream(StreamError),
}

impl ShellError {
    /// Returns a bounded process exit code suitable for native diagnostics.
    #[must_use]
    pub const fn exit_code(&self) -> u32 {
        const PREFIX: u32 = 0x5745_0000;
        match self {
            Self::Native { operation, cause } => {
                PREFIX | ((*operation as u32) << 12) | native_error_code(*cause)
            }
            Self::Startup => PREFIX | 1,
            Self::BootstrapChannel(_) => PREFIX | 2,
            Self::ReceiveCounts(_) => PREFIX | 3,
            Self::Launch(_) => PREFIX | 4,
            Self::FreshCapability { .. } => PREFIX | 5,
            Self::UnexpectedBootstrapRelease(_) => PREFIX | 6,
            Self::RequiredEndpointLost(role) => {
                PREFIX
                    | 0x100
                    | match role {
                        EndpointRole::Stdin => 1,
                        EndpointRole::Stdout => 2,
                        EndpointRole::Stderr => 3,
                        EndpointRole::ConsoleStatus => 4,
                        EndpointRole::Registry => 5,
                        EndpointRole::ShellJobs => 6,
                    }
            }
            Self::Stream(_) => PREFIX | 7,
        }
    }
}

/// Bootstrap, stream, and combined-wait operations used by the shell.
pub trait WyrmshSystem: StreamSystem {
    fn query_capability_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError>;
    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError>;
    fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError>;
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError>;
    fn wait_many(
        &mut self,
        items: &[DwWaitItemV1],
        deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, NativeError>;
}

/// Validates the native ABI and the exact canonical shell argv/environment.
pub fn validate_startup(startup: StartupBlock<'_>) -> Result<(), ShellError> {
    if startup.version() != STARTUP_ABI_V2
        || startup.argc() != 1
        || startup.envc() != 0
        || startup
            .arg(0)
            .is_none_or(|argument| argument.as_str() != "system/wyrmsh")
    {
        return Err(ShellError::Startup);
    }
    Ok(())
}

/// Runs one production shell generation over the six-capability Wyrmsh profile.
pub fn run_wyrmsh<System: WyrmshSystem>(
    system: &mut System,
    startup: StartupBlock<'_>,
) -> Result<(), ShellError> {
    validate_startup(startup)?;
    let bootstrap = startup.bootstrap_channel().as_abi();
    let queried = system
        .query_capability_info(bootstrap)
        .map_err(|cause| native(NativeOperation::QueryBootstrap, cause))?;
    validate_bootstrap_channel(queried, BOOTSTRAP_CHANNEL_EXPECTATION)
        .map_err(ShellError::BootstrapChannel)?;

    let mut bytes = [0_u8; WYRMSH_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); HANDLE_COUNT];
    let counts = system
        .receive_channel(bootstrap, &mut bytes, &mut handles)
        .map_err(|cause| native(NativeOperation::ReceiveInit, cause))?;
    if counts.bytes != bytes.len() || counts.handles != handles.len() {
        let _ = close_received(system, &handles, counts.handles.min(handles.len()));
        return Err(ShellError::ReceiveCounts(counts));
    }

    let identity = match validate_init(system, &bytes, &handles) {
        Ok(identity) => identity,
        Err(error) => {
            let _ = close_received(system, &handles, handles.len());
            return Err(error);
        }
    };

    // Construct all bounded state before READY. From this point, every exit
    // closes the received role handles in reverse order.
    let endpoints = match stream_endpoints(&handles) {
        Ok(endpoints) => endpoints,
        Err(error) => {
            let _ = close_received(system, &handles, handles.len());
            return Err(error);
        }
    };
    let controls = Controls {
        console_status: handles[3].handle,
        registry: handles[4].handle,
        shell_jobs: handles[5].handle,
    };
    let mut shell = Shell::new(identity, endpoints, controls);

    let mut bootstrap_open = true;
    let result = (|| {
        let mut ready = [0_u8; HEADER_BYTES];
        let ready_size = encode_ready_for_profile(
            LaunchProfile::Wyrmsh,
            shell.identity.transaction_id,
            &mut ready,
        )
        .map_err(ShellError::Launch)?;
        system
            .send_channel(bootstrap, &ready[..ready_size])
            .map_err(|cause| native(NativeOperation::SendReady, cause))?;

        await_clean_release(system, bootstrap)?;
        system
            .close_handle(bootstrap)
            .map_err(|cause| native(NativeOperation::CloseBootstrap, cause))?;
        bootstrap_open = false;
        shell.serve(system)
    })();

    let bootstrap_cleanup_error = if bootstrap_open {
        system.close_handle(bootstrap).err()
    } else {
        None
    };
    let cleanup_error = close_received(system, &handles, handles.len());
    if result.is_ok()
        && let Some(cause) = bootstrap_cleanup_error.or(cleanup_error)
    {
        Err(native(NativeOperation::Cleanup, cause))
    } else {
        result
    }
}

fn validate_init<System: WyrmshSystem>(
    system: &mut System,
    bytes: &[u8; WYRMSH_BYTES],
    handles: &[DwReceivedHandleInfoV1; HANDLE_COUNT],
) -> Result<ShellIdentity, ShellError> {
    let parsed = parse_wyrmsh_init(bytes, handles).map_err(ShellError::Launch)?;
    for (index, received) in handles.iter().enumerate() {
        let fresh = system
            .query_capability_info(received.handle)
            .map_err(|cause| native(NativeOperation::QueryRole, cause))?;
        if fresh.object_type != DW_OBJECT_TYPE_CHANNEL || fresh.rights != CHILD_CHANNEL_RIGHTS {
            return Err(ShellError::FreshCapability { index });
        }
    }
    Ok(ShellIdentity {
        transaction_id: parsed.transaction_id,
        registry_generation: parsed.registry_generation,
        registry_endpoint_id: parsed.registry_endpoint_id,
        registry_endpoint_generation: parsed.registry_endpoint_generation,
        launch_connection_id: parsed.launch_connection_id,
        launch_connection_generation: parsed.launch_connection_generation,
        console_generation: parsed.console_generation,
        status_generation: parsed.status_generation,
        child_generation: parsed.child_generation,
        outer_launch_transaction: parsed.outer_launch_transaction,
    })
}

fn stream_endpoints(
    handles: &[DwReceivedHandleInfoV1; HANDLE_COUNT],
) -> Result<[StreamEndpoint; 3], ShellError> {
    Ok([
        StreamEndpoint::from_validated_handle(handles[0].handle).map_err(ShellError::Stream)?,
        StreamEndpoint::from_validated_handle(handles[1].handle).map_err(ShellError::Stream)?,
        StreamEndpoint::from_validated_handle(handles[2].handle).map_err(ShellError::Stream)?,
    ])
}

fn await_clean_release<System: WyrmshSystem>(
    system: &mut System,
    bootstrap: DwHandle,
) -> Result<(), ShellError> {
    let item = wait_item(
        bootstrap,
        DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
    );
    let observed = system
        .wait_many(core::slice::from_ref(&item), DW_DEADLINE_INFINITE)
        .map_err(|cause| native(NativeOperation::AwaitRelease, cause))?;
    if observed.index != 0 || observed.observed != DW_SIGNAL_PEER_CLOSED {
        return Err(ShellError::UnexpectedBootstrapRelease(observed.observed));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Controls {
    console_status: DwHandle,
    registry: DwHandle,
    shell_jobs: DwHandle,
}

struct Shell {
    identity: ShellIdentity,
    decoder: InputDecoder,
    editor: Editor,
    parser: Parser,
    stdin: NativeInput,
    stdout: NativeOutput,
    stderr: NativeOutput,
    controls: Controls,
}

impl Shell {
    const fn new(
        identity: ShellIdentity,
        endpoints: [StreamEndpoint; 3],
        controls: Controls,
    ) -> Self {
        Self {
            identity,
            decoder: InputDecoder::new(),
            editor: Editor::new(),
            parser: Parser::new(),
            stdin: NativeInput::new(endpoints[0]),
            stdout: NativeOutput::new(endpoints[1]),
            stderr: NativeOutput::new(endpoints[2]),
            controls,
        }
    }

    fn serve<System: WyrmshSystem>(&mut self, system: &mut System) -> Result<(), ShellError> {
        self.redraw(system)?;
        loop {
            poll_health(
                system,
                self.controls,
                self.stdout.endpoint().handle(),
                self.stderr.endpoint().handle(),
            )?;
            let mut byte = [0_u8; 1];
            let mut bounded = ReceiveBudget::new(system);
            match self.stdin.read(&mut bounded, &mut byte) {
                Ok(1) => {
                    if self.apply_byte(system, byte[0])? {
                        return Ok(());
                    }
                }
                Ok(_) => return Err(ShellError::Stream(StreamError::Protocol)),
                Err(StreamError::WouldBlock) => {
                    wait_for_input(
                        system,
                        &mut self.stdin,
                        self.controls,
                        self.stdout.endpoint().handle(),
                        self.stderr.endpoint().handle(),
                    )?;
                }
                Err(StreamError::Eof) => {
                    let _ = self.decoder.finish();
                    return Err(ShellError::RequiredEndpointLost(EndpointRole::Stdin));
                }
                Err(error) => return Err(ShellError::Stream(error)),
            }
        }
    }

    fn apply_byte<System: WyrmshSystem>(
        &mut self,
        system: &mut System,
        byte: u8,
    ) -> Result<bool, ShellError> {
        match self.editor.apply(self.decoder.feed(byte)) {
            EditOutcome::Unchanged | EditOutcome::Busy => Ok(false),
            EditOutcome::Changed => {
                self.redraw(system)?;
                Ok(false)
            }
            EditOutcome::Cancelled => {
                write_stdout(
                    system,
                    &mut self.stdout,
                    self.stderr.endpoint().handle(),
                    self.controls,
                    SUBMISSION_NEWLINE,
                )?;
                self.redraw(system)?;
                Ok(false)
            }
            EditOutcome::Rejected(error) => {
                present_edit_error(
                    system,
                    &mut self.stderr,
                    self.stdout.endpoint().handle(),
                    self.controls,
                    error,
                )?;
                self.redraw(system)?;
                Ok(false)
            }
            EditOutcome::Eof => Ok(true),
            EditOutcome::Submitted => self.submit(system),
        }
    }

    fn submit<System: WyrmshSystem>(&mut self, system: &mut System) -> Result<bool, ShellError> {
        write_stdout(
            system,
            &mut self.stdout,
            self.stderr.endpoint().handle(),
            self.controls,
            SUBMISSION_NEWLINE,
        )?;
        let command = self
            .parser
            .parse(self.editor.line().as_bytes())
            .map_err(CommandError::Parse)
            .and_then(|arguments| arguments.command().map_err(CommandError::Usage));
        let exit = match command {
            Ok(command) => dispatch_local(
                system,
                &mut self.stdout,
                self.stderr.endpoint().handle(),
                self.controls,
                command,
            )?,
            Err(error) => {
                present_command_error(
                    system,
                    &mut self.stderr,
                    self.stdout.endpoint().handle(),
                    self.controls,
                    error,
                )?;
                false
            }
        };
        self.editor.accept_submission();
        if !exit {
            self.redraw(system)?;
        }
        Ok(exit)
    }

    fn redraw<System: WyrmshSystem>(&mut self, system: &mut System) -> Result<(), ShellError> {
        let mut redraw = self.editor.redraw();
        let mut chunk = [0_u8; 256];
        loop {
            let used = redraw.read(&mut chunk);
            if used == 0 {
                return Ok(());
            }
            write_stdout(
                system,
                &mut self.stdout,
                self.stderr.endpoint().handle(),
                self.controls,
                &chunk[..used],
            )?;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandError {
    Parse(ParseError),
    Usage(UsageError),
}

fn dispatch_local<System: WyrmshSystem>(
    system: &mut System,
    stdout: &mut NativeOutput,
    stderr_handle: DwHandle,
    controls: Controls,
    command: Command<'_>,
) -> Result<bool, ShellError> {
    match command {
        Command::Empty => {}
        Command::Help => {
            for spec in COMMANDS {
                write_stdout(
                    system,
                    stdout,
                    stderr_handle,
                    controls,
                    spec.usage.as_bytes(),
                )?;
                write_stdout(system, stdout, stderr_handle, controls, b"\n")?;
            }
        }
        Command::Echo(arguments) => {
            for (index, argument) in arguments.iter().enumerate() {
                if index != 0 {
                    write_stdout(system, stdout, stderr_handle, controls, b" ")?;
                }
                write_stdout(system, stdout, stderr_handle, controls, argument.as_bytes())?;
            }
            write_stdout(system, stdout, stderr_handle, controls, b"\n")?;
        }
        Command::Clear => {
            write_stdout(system, stdout, stderr_handle, controls, CLEAR_DISPLAY)?;
        }
        Command::Exit => return Ok(true),
        Command::Services
        | Command::Tasks
        | Command::Status
        | Command::Run { .. }
        | Command::Spawn { .. }
        | Command::Wait(_)
        | Command::Terminate(_) => {
            let name = command_name(command);
            write_stdout(system, stdout, stderr_handle, controls, b"unavailable: ")?;
            write_stdout(system, stdout, stderr_handle, controls, name.as_bytes())?;
            write_stdout(system, stdout, stderr_handle, controls, b"\n")?;
        }
    }
    Ok(false)
}

fn command_name(command: Command<'_>) -> &'static str {
    let name = match command {
        Command::Services => CommandName::Services,
        Command::Tasks => CommandName::Tasks,
        Command::Status => CommandName::Status,
        Command::Run { .. } => CommandName::Run,
        Command::Spawn { .. } => CommandName::Spawn,
        Command::Wait(_) => CommandName::Wait,
        Command::Terminate(_) => CommandName::Terminate,
        _ => return "command",
    };
    COMMANDS
        .iter()
        .find(|spec| spec.name == name)
        .map_or("command", |spec| spec.spelling)
}

fn present_edit_error<System: WyrmshSystem>(
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

fn present_command_error<System: WyrmshSystem>(
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

fn write_stdout<System: WyrmshSystem>(
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

fn write_stderr<System: WyrmshSystem>(
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

fn write_all<System: WyrmshSystem>(
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

fn poll_health<System: WyrmshSystem>(
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

fn wait_for_input<System: WyrmshSystem>(
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

fn wait_for_output<System: WyrmshSystem>(
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

fn health_items(controls: Controls, stdout: DwHandle, stderr: DwHandle) -> [DwWaitItemV1; 5] {
    [
        wait_item(controls.console_status, DW_SIGNAL_PEER_CLOSED),
        wait_item(controls.registry, DW_SIGNAL_PEER_CLOSED),
        wait_item(controls.shell_jobs, DW_SIGNAL_PEER_CLOSED),
        wait_item(stdout, DW_SIGNAL_PEER_CLOSED),
        wait_item(stderr, DW_SIGNAL_PEER_CLOSED),
    ]
}

fn classify_health(result: DwWaitResultV1) -> Result<(), ShellError> {
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

const fn wait_item(handle: DwHandle, signals: DwSignals) -> DwWaitItemV1 {
    DwWaitItemV1 { handle, signals }
}

fn close_received<System: WyrmshSystem>(
    system: &mut System,
    handles: &[DwReceivedHandleInfoV1; HANDLE_COUNT],
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
struct ReceiveBudget<'a, System> {
    inner: &'a mut System,
    remaining: usize,
}

impl<'a, System> ReceiveBudget<'a, System> {
    const fn new(inner: &'a mut System) -> Self {
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

const fn native(operation: NativeOperation, cause: NativeError) -> ShellError {
    ShellError::Native { operation, cause }
}
