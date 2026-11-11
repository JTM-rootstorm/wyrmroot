// SPDX-License-Identifier: GPL-3.0-or-later
#![no_std]
#![forbid(unsafe_code)]

//! Allocation-free WYR1-E shell startup and local-command runtime.

mod files;
mod inspection;
mod jobs;

use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_DEADLINE_NOW, DW_OBJECT_TYPE_CHANNEL, DW_SIGNAL_PEER_CLOSED,
    DW_SIGNAL_READABLE, DW_SIGNAL_WRITABLE, DW_STATUS_TIMED_OUT, DW_STATUS_WOULD_BLOCK, DwDeadline,
    DwHandle, DwHandleTransferV1, DwObjectType, DwReceivedHandleInfoV1, DwRights, DwSignals,
    DwWaitItemV1, DwWaitResultV1,
};
use inspection::{InspectionError, RegistrySequence, TransactionIds};
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, HEADER_BYTES, LaunchError, LaunchProfile, WYRMSH_BYTES,
    encode_ready_for_profile, parse_wyrmsh_init,
};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, CapabilityValidationError, ChannelPlatform,
    ClockPlatform, HandlePlatform, INPUT_WAIT_SIGNALS, NativeError, NativeInput, NativeOutput,
    OUTPUT_WAIT_SIGNALS, ReceiveCounts, STARTUP_ABI_V2, StartupBlock, StreamEndpoint, StreamError,
    StreamSystem, WaitPlatform, native_error_code, validate_bootstrap_channel,
};
#[cfg(test)]
use wyrmroot_stream_proto as _;
use wyrmroot_wyrmsh_core::{
    COMMANDS, Command, EditError, EditOutcome, Editor, InputDecoder, ParseError, Parser, UsageError,
};

mod control;
mod inspect_commands;
mod terminal_io;
use control::*;
use inspect_commands::*;
use terminal_io::*;

const HANDLE_COUNT: usize = 6;
const CLEAR_DISPLAY: &[u8] = b"\x1b[2J\x1b[H";
const SUBMISSION_NEWLINE: &[u8] = b"\n";
const CONTROL_HANDLE_CAPACITY: usize = 4;
const REGISTRY_REPLY_BYTES: usize = wyrmroot_registry_proto::SERVICE_LIST_PREFIX_BYTES
    + wyrmroot_registry_proto::MAX_SERVICE_LIST_RECORDS
        * wyrmroot_registry_proto::SERVICE_LIST_RECORD_BYTES;
const JOB_REPLY_BYTES: usize = 56 + wyrmroot_launch_proto::MAX_LIVE_JOBS * 8;

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
    ControlSend = 9,
    ControlReceive = 10,
    MonotonicClock = 11,
    CreateChannel = 12,
    DuplicateHandle = 13,
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
    InspectionProtocol,
    InspectionTimeout,
    TransactionExhausted,
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
            Self::InspectionProtocol => PREFIX | 8,
            Self::InspectionTimeout => PREFIX | 9,
            Self::TransactionExhausted => PREFIX | 10,
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
    fn send_channel_with_handles(
        &mut self,
        channel: DwHandle,
        bytes: &[u8],
        transfers: &[DwHandleTransferV1],
    ) -> Result<(), NativeError>;
    fn create_channel(&mut self, rights: DwRights) -> Result<(DwHandle, DwHandle), NativeError>;
    fn duplicate_handle(
        &mut self,
        handle: DwHandle,
        rights: DwRights,
    ) -> Result<DwHandle, NativeError>;
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError>;
    fn wait_many(
        &mut self,
        items: &[DwWaitItemV1],
        deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, NativeError>;
    fn monotonic_active_now(&mut self) -> Result<u64, NativeError>;
}

/// Every platform with the handle, Channel, wait, and clock families is a
/// shell system: each method is the family method of the same name, and
/// `send_channel` is a send with no transfers. Its [`StreamSystem`] half is
/// the runtime's infinite-wait stream adapter.
impl<P> WyrmshSystem for P
where
    P: HandlePlatform + ChannelPlatform + WaitPlatform + ClockPlatform + ?Sized,
{
    fn query_capability_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
        HandlePlatform::query_capability_info(self, handle)
    }

    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError> {
        ChannelPlatform::receive_channel(self, channel, bytes, handles)
    }

    fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
        ChannelPlatform::send_channel(self, channel, bytes, &[])
    }

    fn send_channel_with_handles(
        &mut self,
        channel: DwHandle,
        bytes: &[u8],
        transfers: &[DwHandleTransferV1],
    ) -> Result<(), NativeError> {
        ChannelPlatform::send_channel(self, channel, bytes, transfers)
    }

    fn create_channel(&mut self, rights: DwRights) -> Result<(DwHandle, DwHandle), NativeError> {
        ChannelPlatform::create_channel(self, rights)
    }

    fn duplicate_handle(
        &mut self,
        handle: DwHandle,
        rights: DwRights,
    ) -> Result<DwHandle, NativeError> {
        HandlePlatform::duplicate_handle(self, handle, rights)
    }

    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        HandlePlatform::close_handle(self, handle)
    }

    fn wait_many(
        &mut self,
        items: &[DwWaitItemV1],
        deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, NativeError> {
        WaitPlatform::wait_many(self, items, deadline)
    }

    fn monotonic_active_now(&mut self) -> Result<u64, NativeError> {
        ClockPlatform::monotonic_active_now(self)
    }
}

/// Validates the native ABI and the exact canonical shell argv/environment.
pub(crate) fn validate_startup(startup: StartupBlock<'_>) -> Result<(), ShellError> {
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
) -> Result<Termination, ShellError> {
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
    transactions: TransactionIds,
    jobs: jobs::JobTable,
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
            transactions: TransactionIds::new(),
            jobs: jobs::JobTable::new(),
        }
    }

    fn serve<System: WyrmshSystem>(
        &mut self,
        system: &mut System,
    ) -> Result<Termination, ShellError> {
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
                    if let Some(termination) = self.apply_byte(system, byte[0])? {
                        return Ok(termination);
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
    ) -> Result<Option<Termination>, ShellError> {
        match self.editor.apply(self.decoder.feed(byte)) {
            EditOutcome::Unchanged | EditOutcome::Busy => Ok(None),
            EditOutcome::Changed => {
                self.redraw(system)?;
                Ok(None)
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
                Ok(None)
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
                Ok(None)
            }
            // F3A.7d. End of input ends the *session*, not just this shell.
            //
            // It used to be `Ok(true)` -- identical to `exit` -- which is why
            // a supervised product had no terminator: Ctrl-D ended a shell the
            // supervisor then relaunched. `DW1F_WYR1F_F3A_VM_REQUEST.md` §5
            // row 13 already says `\x04` means shutdown; this is the product
            // agreeing with the row rather than the row being rewritten.
            EditOutcome::Eof => Ok(Some(Termination::Session)),
            EditOutcome::Submitted => self.submit(system),
        }
    }

    fn submit<System: WyrmshSystem>(
        &mut self,
        system: &mut System,
    ) -> Result<Option<Termination>, ShellError> {
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
        let stderr_handle = self.stderr.endpoint().handle();
        let exit = match command {
            Ok(command) => dispatch_local(
                system,
                &mut self.stdout,
                &mut self.stderr,
                stderr_handle,
                self.identity,
                self.controls,
                &mut self.transactions,
                &mut self.jobs,
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
                None
            }
        };
        self.editor.accept_submission();
        if exit.is_none() {
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

/// Why the shell's input loop stopped.
///
/// F3A.7d. This was a `bool`, which is exactly the collapse
/// `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` §3.4 is about: "stop" covered both
/// ending this shell and ending the session, and the supervisor cannot tell
/// them apart from a bool. Naming them is what lets `shutdown` exist without
/// changing what `exit` means.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Termination {
    /// The shell ended. The supervisor relaunches it at the next generation.
    Shell,
    /// The session ended. The supervisor retires the console.
    Session,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandError {
    Parse(ParseError),
    Usage(UsageError),
}

#[allow(
    clippy::too_many_arguments,
    reason = "explicit shell capability custody"
)]
fn dispatch_local<System: WyrmshSystem>(
    system: &mut System,
    stdout: &mut NativeOutput,
    stderr: &mut NativeOutput,
    stderr_handle: DwHandle,
    identity: ShellIdentity,
    controls: Controls,
    transactions: &mut TransactionIds,
    jobs: &mut jobs::JobTable,
    command: Command<'_>,
) -> Result<Option<Termination>, ShellError> {
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
        Command::Exit => return Ok(Some(Termination::Shell)),
        Command::Shutdown => return Ok(Some(Termination::Session)),
        Command::Services => {
            inspect_services(system, stdout, stderr, identity, controls, transactions)?
        }
        Command::Tasks => inspect_tasks(system, stdout, stderr, identity, controls, transactions)?,
        Command::Status => {
            inspect_status(system, stdout, stderr, identity, controls, transactions)?
        }
        Command::Run { path, argv } => jobs::run(
            system,
            stdout,
            stderr,
            identity,
            controls,
            transactions,
            jobs,
            path,
            argv,
            None,
        )?,
        Command::RunFile { path, argv } => {
            let mut canonical = [0u8; wyrmroot_wyrmsh_core::MAX_FS_PATH_BYTES];
            let console = files::Console {
                stdout: &mut *stdout,
                stderr: &mut *stderr,
                controls,
            };
            if let Some((node, length)) = files::open_for_run(
                system,
                console,
                identity,
                transactions,
                path,
                &mut canonical,
            )? {
                // `open_for_run` admitted only ASCII.
                let display = core::str::from_utf8(&canonical[1..length])
                    .map_err(|_| ShellError::InspectionProtocol)?;
                jobs::run(
                    system,
                    stdout,
                    stderr,
                    identity,
                    controls,
                    transactions,
                    jobs,
                    display,
                    argv,
                    Some(node),
                )?;
            }
        }
        Command::Spawn { path, argv } => jobs::spawn(
            system,
            stdout,
            stderr,
            identity,
            controls,
            transactions,
            jobs,
            path,
            argv,
        )?,
        Command::Wait(job) => jobs::wait(
            system,
            stdout,
            stderr,
            identity,
            controls,
            transactions,
            jobs,
            job.get(),
        )?,
        Command::Ls(path) | Command::Cat(path) => {
            let console = files::Console {
                stdout,
                stderr,
                controls,
            };
            if matches!(command, Command::Ls(_)) {
                files::list(system, console, identity, transactions, path)?;
            } else {
                files::cat(system, console, identity, transactions, path)?;
            }
        }
        Command::Terminate(job) => jobs::terminate(
            system,
            stdout,
            stderr,
            identity,
            controls,
            transactions,
            jobs,
            job.get(),
        )?,
    }
    Ok(None)
}

#[cfg(test)]
mod platform_adapter_tests {
    extern crate std;

    use deepwyrm_syscall::{DW_RIGHT_READ, DW_SIGNAL_READABLE, DwHandleTransferV1};
    use std::vec::Vec;
    use wyrmroot_runtime::platform::recording::{Call, RecordingPlatform, Reply};

    use super::*;

    /// The shell's two send methods are one family send, with and without
    /// transfers, and its stream wait is the family's infinite single wait.
    #[test]
    fn the_shell_system_is_the_platform_family() {
        let transfer = DwHandleTransferV1 {
            handle: DwHandle(8),
            requested_rights: DW_RIGHT_READ,
            ..DwHandleTransferV1::default()
        };
        let mut platform = RecordingPlatform::scripted([
            Reply::Unit(Ok(())),
            Reply::Unit(Ok(())),
            Reply::Wait(Ok(DwWaitResultV1::default())),
        ]);
        WyrmshSystem::send_channel(&mut platform, DwHandle(3), b"a").unwrap();
        WyrmshSystem::send_channel_with_handles(&mut platform, DwHandle(3), b"b", &[transfer])
            .unwrap();
        StreamSystem::wait(&mut platform, DwHandle(4), DW_SIGNAL_READABLE).unwrap();
        assert_eq!(
            platform.take_calls(),
            [
                Call::SendChannel {
                    channel: DwHandle(3),
                    bytes: b"a".to_vec(),
                    transfers: Vec::new(),
                },
                Call::SendChannel {
                    channel: DwHandle(3),
                    bytes: b"b".to_vec(),
                    transfers: std::vec![transfer],
                },
                Call::WaitOne {
                    handle: DwHandle(4),
                    signals: DW_SIGNAL_READABLE,
                    deadline: DW_DEADLINE_INFINITE,
                },
            ]
        );
        platform.assert_script_consumed();
    }
}
