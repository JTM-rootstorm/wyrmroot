#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

mod stream_transfer;
use stream_transfer::move_transfer;

use deepwyrm_syscall::{
    DW_HANDLE_TRANSFER_MOVE, DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT,
    DW_RIGHT_READ, DW_RIGHT_TRANSFER, DW_RIGHT_WAIT, DW_RIGHT_WRITE, DW_SIGNAL_PEER_CLOSED,
    DW_SIGNAL_READABLE, DW_SIGNAL_WRITABLE, DW_STATUS_TIMED_OUT, DW_STATUS_WOULD_BLOCK, DwDeadline,
    DwHandle, DwHandleTransferV1, DwReceivedHandleInfoV1, DwRights, DwSignals, DwWaitItemV1,
};
use wyrmroot_consoled::{
    ChildPolicy, CleanupDisposition, ConnectRequest, ConsoleModel, EventGeneration,
    FAIR_SOURCE_BYTES_PER_TURN, LaunchCleanupEvidence, LaunchTransaction, OutputSource,
    RecoveryAction, Reservation, STAGING_CAPACITY, SerialCorrelation, StreamKind,
    cleanup_after_event_loop_failure, release_raw_then_witness,
};
#[cfg(feature = "wyr1e-wyrmsh")]
use wyrmroot_consoled::{ReleaseWitnessEvent, classify_release_witness};
use wyrmroot_device_proto::connector::{ConnectorIdentity, ConnectorMessage, RECORD_BYTES};
use wyrmroot_device_proto::{
    COM2_ROLE_ID, SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY,
    connector::{encode as encode_connector, parse as parse_connector},
};
use wyrmroot_launch_proto::{
    ErrorCode as LaunchErrorCode, MAX_LAUNCH_MESSAGE_BYTES, Message as LaunchMessage,
    MessageType as LaunchMessageType, Reservation as LaunchReservation,
    SHELL_SESSION_SHUTDOWN_STATUS, ShellV1Reply, ShellV1Request, TerminationClassification,
    encode_job_message, encode_launch, encode_shell_v1_request,
    parse_message as parse_launch_message, parse_shell_v1_reply,
};
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, CONSOLED_BYTES, LaunchProfile, encode_ready_for_profile,
    parse_consoled_init,
};
use wyrmroot_registry_proto::{
    ErrorCode as RegistryErrorCode, Header as RegistryHeader, Lookup, Message as RegistryMessage,
    MessageType as RegistryMessageType, ProtocolVersion, Watch, encode_cancel, encode_lookup,
    encode_watch, parse as parse_registry,
};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, NativeError, NativeInput, NativeOutput, ReceiveCounts,
    StartupBlock, StreamEndpoint, StreamError, StreamSystem, WYR0_I_SUPERVISION_POLICY,
    close_handle, create_channel, duplicate_handle, monotonic_active_now, panic_abort,
    query_capability_info, receive_channel, send_channel, validate_bootstrap_channel, wait_many,
    wait_one,
};

const FAILURE_BASE: u32 = 0xD400_0000;
const EVENT_TICK_NS: u64 = 1_000_000_000;
const STATUS_SEND_TIMEOUT_NS: u64 = 1_000_000_000;
#[cfg(feature = "wyr1e-wyrmsh")]
const TERMINAL_DRAIN_TIMEOUT_NS: u64 = 4_000_000_000;
const NANOS_PER_MILLI: u64 = 1_000_000;
const FATAL_ATTACH_BASE: u32 = 0x0000_0100;
/// The application status consoled exits with when its child ended the
/// session.
///
/// F3A.7g. Zero, deliberately: consoled did what it was for and stopped
/// because there was nothing left to supervise, which is a normal exit and
/// not a supervision failure. `FAILURE_BASE` covers every other way out of
/// `run`, so nothing else in this process can produce this status.
const SESSION_ENDED: u32 = 0;

/// DUPLICATE stays local. The retained endpoint has final child-Channel rights;
/// the peer keeps TRANSFER through init until the loader's final child MOVE.
const CHANNEL_CONSTRUCTION_RIGHTS: DwRights =
    DwRights(CHILD_CHANNEL_RIGHTS.0 | DW_RIGHT_TRANSFER.0 | DW_RIGHT_DUPLICATE.0);
const CONNECTOR_PAIR_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_TRANSFER.0,
);

#[derive(Clone, Copy)]
struct StartupAuthorities {
    #[cfg(feature = "wyr1d-selector32")]
    selector_control: DwHandle,
    #[cfg(feature = "wyr1d-selector32")]
    selector_nonce: u64,
    #[cfg(feature = "wyr1e8-recovery")]
    recovery_control: DwHandle,
    registry: DwHandle,
    launch: DwHandle,
    registry_generation: u64,
    registry_endpoint_id: u64,
    registry_endpoint_generation: u64,
    launch_connection_id: u64,
    launch_connection_generation: u64,
    startup_transaction: u64,
}

struct SerialSession {
    identity: ConnectorIdentity,
    watch: Option<ActiveWatch>,
    raw_owned: bool,
    #[cfg(feature = "wyr1e-wyrmsh")]
    release_witness: Option<DwHandle>,
    input: NativeInput,
    output: NativeOutput,
}

impl SerialSession {
    const fn endpoint(&self) -> DwHandle {
        self.input.endpoint().handle()
    }
}

fn close_serial_session(serial: &mut SerialSession) -> Result<(), u32> {
    // The raw endpoint is always released first. The retained registry
    // CONNECT peer is the devmgr-observed certificate for this exact client
    // generation and therefore cannot be closed before raw custody ends.
    #[cfg(feature = "wyr1e-wyrmsh")]
    let witness = serial.release_witness.take();
    #[cfg(not(feature = "wyr1e-wyrmsh"))]
    let witness: Option<DwHandle> = None;
    let raw = serial.raw_owned.then(|| serial.endpoint());
    // A failed close leaves ownership ambiguous. Consume it before the
    // attempt so outer fatal cleanup cannot retry a possibly released handle.
    serial.raw_owned = false;
    let closed = match raw {
        Some(raw) => release_raw_then_witness(raw, witness, |handle| close_handle(handle).is_ok()),
        None => witness.is_none_or(|handle| close_handle(handle).is_ok()),
    };
    if !closed {
        Err(FATAL_ATTACH_BASE | 101)
    } else {
        Ok(())
    }
}

#[cfg(feature = "wyr1e-wyrmsh")]
fn observe_release_witness(serial: &SerialSession, signals: DwSignals) -> Result<(), u32> {
    let readable = signals.0 & DW_SIGNAL_READABLE.0 != 0;
    let peer_closed = signals.0 & DW_SIGNAL_PEER_CLOSED.0 != 0;
    if classify_release_witness(readable, peer_closed) == ReleaseWitnessEvent::Malformed {
        if !readable {
            return Err(FATAL_ATTACH_BASE | 103);
        }
        let witness = serial.release_witness.ok_or(FATAL_ATTACH_BASE | 102)?;
        let mut bytes = [0u8; 1];
        let mut handles = [DwReceivedHandleInfoV1::default(); 1];
        if let Ok(counts) = receive_channel(witness, &mut bytes, &mut handles) {
            close_received(&handles, counts.handles);
        }
        return Err(FATAL_ATTACH_BASE | 102);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ActiveWatch {
    transaction_id: u64,
    publication_generation: u64,
}

struct ChildSession {
    job_id: u64,
    event: EventGeneration,
    wait: Option<LaunchReservation>,
    /// F3A.7g. Whether this child's terminal result carried
    /// `SHELL_SESSION_SHUTDOWN_STATUS`. It is written exactly where the
    /// result is received and read exactly once, by the terminal recovery
    /// that would otherwise relaunch the shell at the next generation.
    ///
    /// A fresh `ChildSession` is always `false`, so the fact cannot outlive
    /// the generation that reported it.
    session_shutdown: bool,
    stdin: NativeOutput,
    stdout: NativeInput,
    stderr: NativeInput,
    status: Option<StatusChannel>,
}

struct StatusChannel {
    endpoint: DwHandle,
    session: wyrmroot_console_proto::StatusSession,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LaunchReply {
    LaunchAccepted(u64),
    TerminationAccepted(u64),
    /// A terminal job result.
    ///
    /// `session_shutdown` is the only thing consoled reads out of the result
    /// body: the child exited with `SHELL_SESSION_SHUTDOWN_STATUS`, which
    /// says it was asked to end the *session* and not merely to end itself.
    /// The classification, exception and cleanup fields belong to the shell's
    /// own `job result` line, for jobs the shell launched; consoled supervises
    /// one child and has no reader for them.
    JobResult {
        job_id: u64,
        session_shutdown: bool,
    },
    Cancelled(u64),
    Closed(u64),
    Error(LaunchErrorCode),
}

#[derive(Clone, Copy)]
enum ChildFault {
    Peer(StreamKind),
    Status,
    WrongDirection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildWaitResolution {
    Cancelled,
    Terminal,
}

/// What a cleanly terminated child leaves behind.
///
/// F3A.7g. Terminal recovery used to have one outcome -- replace the child --
/// because a shell that ended was always a shell to relaunch. Row 12 of
/// `DW1F_WYR1F_F3A_VM_REQUEST.md` §5 still wants exactly that. Row 13 does
/// not: `\x04` ends the session, and the difference reaches consoled as the
/// child's own application status, so it is read where the status is read and
/// named here rather than inferred from anything the child printed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminalOutcome {
    /// The next generation is running and holds the console.
    Replaced,
    /// The child asked for the session to end. Nothing replaced it, and the
    /// child's streams, status channel and job are already released.
    SessionEnded,
}

enum LaunchChildOutcome {
    Child(ChildSession),
    SerialLost(u64),
}

enum LaunchWaitOutcome {
    Reply(LaunchReply),
    SerialLost,
}

#[derive(Clone, Copy)]
enum DataClass {
    Raw,
    Stdin,
    Stdout,
    Stderr,
}

impl DataClass {
    const fn next(self) -> Self {
        match self {
            Self::Raw => Self::Stdin,
            Self::Stdin => Self::Stdout,
            Self::Stdout => Self::Stderr,
            Self::Stderr => Self::Raw,
        }
    }

    const fn order(self) -> [Self; 4] {
        [
            self,
            self.next(),
            self.next().next(),
            self.next().next().next(),
        ]
    }
}

#[derive(Clone, Copy)]
struct Pending {
    bytes: [u8; FAIR_SOURCE_BYTES_PER_TURN],
    used: usize,
    reservation: Option<Reservation>,
}

impl Pending {
    const fn new() -> Self {
        Self {
            bytes: [0; FAIR_SOURCE_BYTES_PER_TURN],
            used: 0,
            reservation: None,
        }
    }

    const fn is_empty(&self) -> bool {
        self.used == 0
    }

    fn clear(&mut self) {
        self.used = 0;
        self.reservation = None;
    }
}

struct TransactionIds {
    next: u64,
}

impl TransactionIds {
    fn after(startup: u64) -> Result<Self, u32> {
        let next = startup.checked_add(1).ok_or(1u32)?;
        if next == 0 {
            return Err(1);
        }
        Ok(Self { next })
    }

    fn take(&mut self) -> Result<u64, u32> {
        let value = self.next;
        self.next = value.checked_add(1).ok_or(2u32)?;
        if value == 0 {
            return Err(2);
        }
        Ok(value)
    }
}

struct NativeStreams;

impl StreamSystem for NativeStreams {
    fn receive(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError> {
        receive_channel(channel, bytes, handles)
    }

    fn send(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
        send_channel(channel, bytes, &[])
    }

    fn close(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        close_handle(handle)
    }

    fn wait(&mut self, channel: DwHandle, signals: DwSignals) -> Result<DwSignals, NativeError> {
        let deadline = monotonic_active_now()?
            .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .ok_or(NativeError::Output(
                wyrmroot_runtime::NativeOutputError::DeadlineOverflow,
            ))?;
        Ok(wait_one(channel, signals, DwDeadline(deadline))?.observed)
    }
}

fn main(startup: StartupBlock<'_>) -> u32 {
    run(startup).unwrap_or_else(|step| FAILURE_BASE | step)
}

fn run(startup: StartupBlock<'_>) -> Result<u32, u32> {
    let bootstrap = startup.bootstrap_channel().as_abi();
    validate_bootstrap_channel(
        query_capability_info(bootstrap).map_err(|_| 3u32)?,
        BOOTSTRAP_CHANNEL_EXPECTATION,
    )
    .map_err(|_| 4u32)?;

    let mut init_bytes = [0u8; CONSOLED_BYTES];
    let mut init_handles = [DwReceivedHandleInfoV1::default(); 3];
    let counts =
        receive_channel(bootstrap, &mut init_bytes, &mut init_handles).map_err(|_| 5u32)?;
    if counts.bytes != CONSOLED_BYTES || counts.handles != 3 {
        close_received(&init_handles, counts.handles);
        let _ = close_handle(bootstrap);
        return Err(6);
    }
    let init = match parse_consoled_init(&init_bytes, &init_handles) {
        Ok(init) => init,
        Err(_) => {
            close_received(&init_handles, 3);
            let _ = close_handle(bootstrap);
            return Err(7);
        }
    };
    let authorities = StartupAuthorities {
        #[cfg(feature = "wyr1d-selector32")]
        selector_control: bootstrap,
        #[cfg(feature = "wyr1d-selector32")]
        selector_nonce: selector_configure(bootstrap)?,
        #[cfg(feature = "wyr1e8-recovery")]
        recovery_control: bootstrap,
        registry: init_handles[1].handle,
        launch: init_handles[2].handle,
        registry_generation: init.registry_generation,
        registry_endpoint_id: init.registry_endpoint_id,
        registry_endpoint_generation: init.registry_endpoint_generation,
        launch_connection_id: init.launch_connection_id,
        launch_connection_generation: init.launch_connection_generation,
        startup_transaction: init.transaction_id,
    };
    if close_handle(init_handles[0].handle).is_err() {
        close_authorities(authorities);
        let _ = close_handle(bootstrap);
        return Err(8);
    }

    let mut transactions = TransactionIds::after(authorities.startup_transaction)?;
    let mut model = ConsoleModel::new();
    let mut serial = match attach_serial_bounded(authorities, &mut transactions, &mut model, None) {
        Ok(serial) => serial,
        Err(error) => {
            close_authorities(authorities);
            let _ = close_handle(bootstrap);
            return Err(error);
        }
    };
    let child = match launch_child(authorities, &mut transactions, &mut model, &mut serial) {
        Ok(child) => child,
        Err(error) => {
            let _ = close_serial_session(&mut serial);
            close_authorities(authorities);
            let _ = close_handle(bootstrap);
            return Err(error);
        }
    };
    let mut child = child;
    if observe_exact_ready(&mut model, &serial, &child, 9).is_err() {
        let _ = close_serial_session(&mut serial);
        let _ = cleanup_child_for_exit(authorities, &mut transactions, &mut child);
        close_authorities(authorities);
        let _ = close_handle(bootstrap);
        return Err(9);
    }

    let mut ready = [0u8; 64];
    let ready_size = match encode_ready_for_profile(
        LaunchProfile::Consoled,
        authorities.startup_transaction,
        &mut ready,
    ) {
        Ok(size) => size,
        Err(_) => {
            let _ = close_serial_session(&mut serial);
            let _ = cleanup_child_for_exit(authorities, &mut transactions, &mut child);
            close_authorities(authorities);
            let _ = close_handle(bootstrap);
            return Err(10);
        }
    };
    if send_channel(bootstrap, &ready[..ready_size], &[]).is_err() {
        let _ = close_serial_session(&mut serial);
        let _ = cleanup_child_for_exit(authorities, &mut transactions, &mut child);
        close_authorities(authorities);
        let _ = close_handle(bootstrap);
        return Err(11);
    }
    #[cfg(not(any(feature = "wyr1d-selector32", feature = "wyr1e8-recovery")))]
    if close_handle(bootstrap).is_err() {
        let _ = close_serial_session(&mut serial);
        let _ = cleanup_child_for_exit(authorities, &mut transactions, &mut child);
        close_authorities(authorities);
        return Err(12);
    }

    let result = event_loop(
        authorities,
        &mut transactions,
        &mut model,
        &mut serial,
        &mut child,
    );
    // F3A.7g. A session that ended releases the same things a failed event
    // loop does, in the same order, minus the child: terminal recovery
    // already closed its streams, its status channel and its job before it
    // declined to replace it, and closing a released handle would report a
    // cleanup failure over a clean shutdown.
    if result == Ok(SESSION_ENDED) {
        let serial_closed = close_serial_session(&mut serial).is_ok();
        let watch_retired =
            retire_publication_watch(authorities, &mut transactions, &mut serial).is_ok();
        close_authorities(authorities);
        return if serial_closed && watch_retired {
            Ok(SESSION_ENDED)
        } else {
            Err(FATAL_ATTACH_BASE | 105)
        };
    }
    if let Err(error) = result {
        // Event-loop failures still own the exact serial generation. Release
        // raw and witness first, then its watch and child stream custody.
        let cleaned = cleanup_after_event_loop_failure(
            &mut serial,
            &mut child,
            |serial| close_serial_session(serial).is_ok(),
            |serial| retire_publication_watch(authorities, &mut transactions, serial).is_ok(),
            |child| close_child_streams(child).is_ok(),
        );
        close_authorities(authorities);
        return if !cleaned {
            Err(FATAL_ATTACH_BASE | 104)
        } else {
            Err(error)
        };
    }
    result
}

fn attach_serial(
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    model: &mut ConsoleModel,
) -> Result<SerialSession, u32> {
    let publication_generation = watch_publication(authorities, transactions)?;
    if publication_generation == 0 {
        return Err(13);
    }
    let direct = lookup_connector(authorities, transactions)?;
    let connector_transaction = match transactions.take() {
        Ok(value) => value,
        Err(error) => {
            close_attempt_handles(core::slice::from_ref(&direct))?;
            return Err(error);
        }
    };
    let request = ConnectorMessage::ConnectStream {
        publication_generation,
        client_transaction_id: connector_transaction,
    };
    let connect_request = ConnectRequest {
        registry_generation: authorities.registry_generation,
        registry_endpoint_id: authorities.registry_endpoint_id,
        registry_endpoint_generation: authorities.registry_endpoint_generation,
        requested_publication_generation: publication_generation,
        connector_client_transaction: connector_transaction,
    };
    if model.begin_connect(connect_request).is_err() {
        close_attempt_handles(core::slice::from_ref(&direct))?;
        return Err(14);
    }
    let mut connector_bytes = [0u8; RECORD_BYTES];
    if encode_connector(request, &mut connector_bytes).is_err() {
        finish_connect_abort(model, connect_request, core::slice::from_ref(&direct))?;
        return Err(14);
    }
    if send_channel(direct, &connector_bytes, &[]).is_err() {
        finish_connect_abort(model, connect_request, core::slice::from_ref(&direct))?;
        return Err(15);
    }
    if wait_readable(direct).is_err() {
        finish_connect_abort(model, connect_request, core::slice::from_ref(&direct))?;
        return Err(16);
    }
    let mut received = [DwReceivedHandleInfoV1::default(); 1];
    let counts = match receive_channel(direct, &mut connector_bytes, &mut received) {
        Ok(counts) => counts,
        Err(_) => {
            finish_connect_abort(model, connect_request, core::slice::from_ref(&direct))?;
            return Err(17);
        }
    };
    if counts.bytes != RECORD_BYTES
        || counts.handles != 1
        || !valid_received_channel(received[0], CHILD_CHANNEL_RIGHTS)
    {
        let handles = [direct, received[0].handle];
        finish_connect_abort(model, connect_request, &handles)?;
        return Err(18);
    }
    let identity = match parse_connector(&connector_bytes) {
        Ok(ConnectorMessage::Connected { identity }) => identity,
        _ => {
            let handles = [direct, received[0].handle];
            finish_connect_abort(model, connect_request, &handles)?;
            return Err(20);
        }
    };
    if !valid_connector_identity(identity, publication_generation, connector_transaction) {
        let handles = [direct, received[0].handle];
        finish_connect_abort(model, connect_request, &handles)?;
        return Err(21);
    }
    if validate_exact_channel(received[0].handle, CHILD_CHANNEL_RIGHTS).is_err() {
        let handles = [direct, received[0].handle];
        finish_connect_abort(model, connect_request, &handles)?;
        return Err(22);
    }
    #[cfg(not(feature = "wyr1e-wyrmsh"))]
    if close_handle(direct).is_err() {
        let _ = close_handle(received[0].handle);
        let _ = model.abort_connect(connect_request);
        return Err(FATAL_ATTACH_BASE | 23);
    }
    let attached_at = match now_millis() {
        Ok(now) => now,
        Err(error) => {
            #[cfg(feature = "wyr1e-wyrmsh")]
            let cleanup = [direct, received[0].handle];
            #[cfg(not(feature = "wyr1e-wyrmsh"))]
            let cleanup = [received[0].handle, DwHandle(0)];
            finish_connect_abort(model, connect_request, &cleanup)?;
            return Err(error);
        }
    };
    let active_watch =
        match begin_publication_watch(authorities, transactions, publication_generation) {
            Ok(watch) => watch,
            Err(error) => {
                #[cfg(feature = "wyr1e-wyrmsh")]
                let cleanup = [direct, received[0].handle];
                #[cfg(not(feature = "wyr1e-wyrmsh"))]
                let cleanup = [received[0].handle, DwHandle(0)];
                finish_connect_abort(model, connect_request, &cleanup)?;
                return Err(error);
            }
        };
    let correlation = serial_correlation(authorities, identity);
    if model.attach_connected(correlation, attached_at).is_err() {
        if cancel_registry_watch(authorities, transactions, active_watch.transaction_id).is_err() {
            #[cfg(feature = "wyr1e-wyrmsh")]
            let cleanup = [direct, received[0].handle];
            #[cfg(not(feature = "wyr1e-wyrmsh"))]
            let cleanup = [received[0].handle, DwHandle(0)];
            let _ = finish_connect_abort(model, connect_request, &cleanup);
            return Err(FATAL_ATTACH_BASE | 24);
        }
        #[cfg(feature = "wyr1e-wyrmsh")]
        let cleanup = [direct, received[0].handle];
        #[cfg(not(feature = "wyr1e-wyrmsh"))]
        let cleanup = [received[0].handle, DwHandle(0)];
        finish_connect_abort(model, connect_request, &cleanup)?;
        return Err(24);
    }
    Ok(SerialSession {
        identity,
        watch: Some(active_watch),
        raw_owned: true,
        #[cfg(feature = "wyr1e-wyrmsh")]
        release_witness: Some(direct),
        input: NativeInput::new(validated_stream_endpoint(received[0].handle).map_err(|_| 24u32)?),
        output: NativeOutput::new(
            validated_stream_endpoint(received[0].handle).map_err(|_| 24u32)?,
        ),
    })
}

fn begin_publication_watch(
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    publication_generation: u64,
) -> Result<ActiveWatch, u32> {
    let transaction_id = transactions.take()?;
    let policy = SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY;
    let header = registry_header(authorities, RegistryMessageType::Watch, transaction_id);
    let mut bytes = [0u8; 256];
    let size = encode_watch(
        header,
        Watch {
            protocol_id: policy.protocol_id,
            last_observed_generation: publication_generation,
            service_name: policy.service_name,
        },
        &mut bytes,
    )
    .map_err(|_| 25u32)?;
    send_channel(authorities.registry, &bytes[..size], &[]).map_err(|_| 26u32)?;
    Ok(ActiveWatch {
        transaction_id,
        publication_generation,
    })
}

fn attach_serial_bounded(
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    model: &mut ConsoleModel,
    first_deadline_ms: Option<u64>,
) -> Result<SerialSession, u32> {
    if let Some(deadline) = first_deadline_ms {
        wait_backoff(authorities.registry, deadline)?;
    }
    loop {
        match attach_serial(authorities, transactions, model) {
            Ok(serial) => return Ok(serial),
            Err(error) if error & FATAL_ATTACH_BASE != 0 => return Err(error),
            Err(_) => match model
                .serial_reconnect_failed(now_millis()?)
                .map_err(|_| 25u32)?
            {
                RecoveryAction::RetrySerialAt(deadline) => {
                    wait_backoff(authorities.registry, deadline)?;
                }
                RecoveryAction::Escalate => return Err(26),
                _ => return Err(27),
            },
        }
    }
}

fn watch_publication(
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
) -> Result<u64, u32> {
    let transaction_id = transactions.take()?;
    let policy = SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY;
    let header = registry_header(authorities, RegistryMessageType::Watch, transaction_id);
    let mut bytes = [0u8; 256];
    let size = encode_watch(
        header,
        Watch {
            protocol_id: policy.protocol_id,
            // Zero requests an immediate exact observation when a publication
            // is present and becomes a blocking watch while it is absent.
            last_observed_generation: 0,
            service_name: policy.service_name,
        },
        &mut bytes,
    )
    .map_err(|_| 25u32)?;
    send_channel(authorities.registry, &bytes[..size], &[]).map_err(|_| 26u32)?;
    if wait_readable(authorities.registry).is_err() {
        return match cancel_registry_watch(authorities, transactions, transaction_id) {
            Ok(Some(generation)) if generation != 0 => Ok(generation),
            Ok(_) => Err(27),
            Err(_) => Err(FATAL_ATTACH_BASE | 27),
        };
    }
    let mut received = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(authorities.registry, &mut bytes, &mut received)
        .map_err(|_| FATAL_ATTACH_BASE | 28)?;
    if counts.handles != 0 {
        close_attempt_handles(core::slice::from_ref(&received[0].handle))?;
        return Err(FATAL_ATTACH_BASE | 29);
    }
    let reply = parse_registry(&bytes[..counts.bytes], 0).map_err(|_| FATAL_ATTACH_BASE | 30)?;
    if reply.header
        != (RegistryHeader {
            message_type: RegistryMessageType::GenerationChanged,
            ..header
        })
    {
        return Err(FATAL_ATTACH_BASE | 31);
    }
    match reply.message {
        RegistryMessage::GenerationChanged { service_generation } => Ok(service_generation),
        _ => Err(FATAL_ATTACH_BASE | 32),
    }
}

fn cancel_registry_watch(
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    target: u64,
) -> Result<Option<u64>, u32> {
    let transaction_id = transactions.take()?;
    let header = registry_header(authorities, RegistryMessageType::Cancel, transaction_id);
    let mut bytes = [0u8; 72];
    let size = encode_cancel(header, target, &mut bytes).map_err(|_| FATAL_ATTACH_BASE | 28)?;
    send_channel(authorities.registry, &bytes[..size], &[]).map_err(|_| FATAL_ATTACH_BASE | 29)?;
    let mut changed = None;
    let mut received_count = 0;
    while received_count < 2 {
        wait_readable(authorities.registry).map_err(|_| FATAL_ATTACH_BASE | 30)?;
        let mut handles = [DwReceivedHandleInfoV1::default(); 1];
        let counts = receive_channel(authorities.registry, &mut bytes, &mut handles)
            .map_err(|_| FATAL_ATTACH_BASE | 31)?;
        if counts.handles != 0 {
            close_attempt_handles(core::slice::from_ref(&handles[0].handle))?;
            return Err(FATAL_ATTACH_BASE | 32);
        }
        let reply =
            parse_registry(&bytes[..counts.bytes], 0).map_err(|_| FATAL_ATTACH_BASE | 33)?;
        let common = reply.header.registry_generation == authorities.registry_generation
            && reply.header.endpoint_id == authorities.registry_endpoint_id
            && reply.header.endpoint_generation == authorities.registry_endpoint_generation;
        if !common {
            return Err(FATAL_ATTACH_BASE | 34);
        }
        if reply.header.transaction_id == target
            && reply.header.message_type == RegistryMessageType::GenerationChanged
        {
            let RegistryMessage::GenerationChanged { service_generation } = reply.message else {
                return Err(FATAL_ATTACH_BASE | 34);
            };
            changed = Some(service_generation);
            received_count += 1;
            continue;
        }
        if reply.header
            == (RegistryHeader {
                message_type: RegistryMessageType::Cancelled,
                ..header
            })
            && reply.message
                == (RegistryMessage::Cancelled {
                    target_transaction_id: target,
                })
        {
            return Ok(changed);
        }
        if reply.header
            == (RegistryHeader {
                message_type: RegistryMessageType::Error,
                ..header
            })
            && reply.message
                == (RegistryMessage::Error {
                    code: RegistryErrorCode::UnknownTransaction,
                })
            && changed.is_some()
        {
            return Ok(changed);
        }
        return Err(FATAL_ATTACH_BASE | 34);
    }
    Err(FATAL_ATTACH_BASE | 34)
}

fn receive_publication_change(
    authorities: StartupAuthorities,
    serial: &mut SerialSession,
) -> Result<u64, u32> {
    let watch = serial.watch.ok_or(FATAL_ATTACH_BASE | 35)?;
    let mut bytes = [0u8; 256];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(authorities.registry, &mut bytes, &mut handles)
        .map_err(|_| FATAL_ATTACH_BASE | 35)?;
    if counts.handles != 0 {
        close_attempt_handles(core::slice::from_ref(&handles[0].handle))?;
        return Err(FATAL_ATTACH_BASE | 35);
    }
    let reply = parse_registry(&bytes[..counts.bytes], 0).map_err(|_| FATAL_ATTACH_BASE | 35)?;
    let expected = RegistryHeader {
        message_type: RegistryMessageType::GenerationChanged,
        registry_generation: authorities.registry_generation,
        endpoint_id: authorities.registry_endpoint_id,
        endpoint_generation: authorities.registry_endpoint_generation,
        transaction_id: watch.transaction_id,
    };
    let RegistryMessage::GenerationChanged { service_generation } = reply.message else {
        return Err(FATAL_ATTACH_BASE | 35);
    };
    if reply.header != expected || service_generation == watch.publication_generation {
        return Err(FATAL_ATTACH_BASE | 35);
    }
    serial.watch = None;
    Ok(service_generation)
}

fn retire_publication_watch(
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    serial: &mut SerialSession,
) -> Result<(), u32> {
    let Some(watch) = serial.watch else {
        return Ok(());
    };
    cancel_registry_watch(authorities, transactions, watch.transaction_id)?;
    serial.watch = None;
    Ok(())
}

fn lookup_connector(
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
) -> Result<DwHandle, u32> {
    let (direct, service) = create_channel(CONNECTOR_PAIR_RIGHTS).map_err(|_| 33u32)?;
    let transaction_id = transactions.take()?;
    let policy = SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY;
    let header = registry_header(
        authorities,
        RegistryMessageType::LookupConnect,
        transaction_id,
    );
    let mut bytes = [0u8; 256];
    let size = match encode_lookup(
        header,
        Lookup {
            protocol_id: policy.protocol_id,
            version: ProtocolVersion {
                major: policy.protocol_major,
                minor: policy.protocol_minor,
            },
            service_name: policy.service_name,
        },
        &mut bytes,
    ) {
        Ok(size) => size,
        Err(_) => {
            close_attempt_handles(&[direct, service])?;
            return Err(34);
        }
    };
    let transfer = DwHandleTransferV1 {
        handle: service,
        // Registryd must forward this endpoint once more; it receives the
        // exact broad intermediary rights and reduces them to child rights in
        // the CONNECT_OFFER MOVE.
        requested_rights: CONNECTOR_PAIR_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if send_channel(authorities.registry, &bytes[..size], &[transfer]).is_err() {
        close_attempt_handles(&[direct, service])?;
        return Err(35);
    }
    if wait_readable(authorities.registry).is_err() {
        close_attempt_handles(core::slice::from_ref(&direct))?;
        return Err(FATAL_ATTACH_BASE | 36);
    }
    let mut received = [DwReceivedHandleInfoV1::default(); 1];
    let counts = match receive_channel(authorities.registry, &mut bytes, &mut received) {
        Ok(counts) => counts,
        Err(_) => {
            close_attempt_handles(core::slice::from_ref(&direct))?;
            return Err(FATAL_ATTACH_BASE | 37);
        }
    };
    if counts.handles != 0 {
        close_attempt_handles(&[direct, received[0].handle])?;
        return Err(38);
    }
    let reply = match parse_registry(&bytes[..counts.bytes], 0) {
        Ok(reply) => reply,
        Err(_) => {
            close_attempt_handles(core::slice::from_ref(&direct))?;
            return Err(39);
        }
    };
    if reply.header
        != (RegistryHeader {
            message_type: RegistryMessageType::Connected,
            ..header
        })
        || reply.message != RegistryMessage::Connected
    {
        close_attempt_handles(core::slice::from_ref(&direct))?;
        return Err(40);
    }
    Ok(direct)
}

fn launch_child(
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    model: &mut ConsoleModel,
    serial: &mut SerialSession,
) -> Result<ChildSession, u32> {
    loop {
        match launch_child_once(authorities, transactions, model, serial)? {
            LaunchChildOutcome::Child(child) => return Ok(child),
            LaunchChildOutcome::SerialLost(deadline) => {
                *serial = attach_serial_bounded(authorities, transactions, model, Some(deadline))?;
            }
        }
    }
}

fn launch_child_once(
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
        match create_reduced_stream_pair() {
            Ok((local, peer)) => {
                retained[index] = local;
                child[index] = peer;
            }
            Err(_) => {
                close_handle_array_reverse(&retained);
                close_handle_array_reverse(&child);
                return Err(42);
            }
        }
    }
    let mut model_launch = match model.begin_child_launch(transaction_id) {
        Ok(launch) => launch,
        Err(_) => {
            close_handle_array_reverse(&retained);
            close_handle_array_reverse(&child);
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
                finish_launch_abort(model, model_launch, &retained, &child, false)?;
                return Err(error);
            }
        };
        match create_reduced_stream_pair() {
            Ok((local, peer)) => {
                status_retained = local;
                status_child = peer;
            }
            Err(_) => {
                finish_launch_abort(model, model_launch, &retained, &child, false)?;
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
                    close_status_pair(status_retained, status_child)?;
                    finish_launch_abort(model, model_launch, &retained, &child, false)?;
                    return Err(42);
                }
            };
    }

    #[cfg(feature = "wyr1e8-recovery")]
    if policy == ChildPolicy::Wyrmsh {
        let facts = wyrmroot_consoled::quiesce_control::ReadyFacts {
            console_generation: model_launch.console_generation(),
            status_generation,
            shell_generation: model_launch.child_generation(),
            attach_transaction: serial.identity.attach_transaction_id,
            stream_generation: serial.identity.stream_generation,
            bundle_generation: serial.identity.bundle_generation,
        };
        let bytes = wyrmroot_consoled::quiesce_control::encode(
            wyrmroot_consoled::quiesce_control::Message::ReadyFacts(facts),
        )
        .map_err(|_| 43u32)?;
        if send_channel(authorities.recovery_control, &bytes, &[]).is_err() {
            close_status_pair(status_retained, status_child)?;
            finish_launch_abort(model, model_launch, &retained, &child, false)?;
            return Err(43);
        }
    }

    let reservation = LaunchReservation {
        connection_id: authorities.launch_connection_id,
        generation: authorities.launch_connection_generation,
        transaction_id,
    };
    let mut bytes = [0u8; MAX_LAUNCH_MESSAGE_BYTES];
    let encoded = match policy {
        ChildPolicy::ConsoleEcho => encode_launch(
            reservation,
            policy.path(),
            &[policy.path()],
            &[],
            true,
            &mut bytes,
        ),
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
            close_status_pair(status_retained, status_child)?;
            finish_launch_abort(model, model_launch, &retained, &child, false)?;
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
    if send_channel(
        authorities.launch,
        &bytes[..size],
        &transfers[..transfer_count],
    )
    .is_err()
    {
        // Channel MOVE is atomic: a failed send leaves every child peer local.
        close_status_pair(status_retained, status_child)?;
        finish_launch_abort(model, model_launch, &retained, &child, false)?;
        return Err(44);
    }
    for kind in [StreamKind::Stdin, StreamKind::Stdout, StreamKind::Stderr] {
        if model_launch.move_child_peer(kind).is_err() {
            close_status_retained(status_retained, status_session.as_mut())?;
            close_handle_array_reverse(&retained);
            // The native MOVE already committed, but no correlated launch
            // response proves revocation. Closing the launch session on fatal
            // process exit is the only truthful cleanup remaining.
            return Err(48);
        }
    }
    let response = match wait_launch_with_serial(
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
                .serial_peer_closed(old_serial, old_console, now_millis()?)
                .map_err(|_| 45u32)?
                != RecoveryAction::None
            {
                return Err(45);
            }
            close_serial_session(serial)?;
            retire_publication_watch(authorities, transactions, serial)?;
            let resolved = match receive_initial_launch(authorities.launch, reservation, policy) {
                Ok(reply) => reply,
                Err(_) => {
                    close_status_retained(status_retained, status_session.as_mut())?;
                    close_handle_array_reverse(&retained);
                    return Err(45);
                }
            };
            match resolved {
                LaunchReply::LaunchAccepted(job_id) => {
                    if cleanup_unmodeled_job(authorities, transactions, job_id).is_err() {
                        close_status_retained(status_retained, status_session.as_mut())?;
                        close_handle_array_reverse(&retained);
                        return Err(45);
                    }
                }
                LaunchReply::Error(code) if code != LaunchErrorCode::CleanupFailure => {}
                _ => {
                    close_status_retained(status_retained, status_session.as_mut())?;
                    close_handle_array_reverse(&retained);
                    return Err(45);
                }
            }
            close_status_retained(status_retained, status_session.as_mut())?;
            finish_launch_abort(model, model_launch, &retained, &child, true)?;
            return match model.take_recovery_action() {
                Some(RecoveryAction::RetrySerialAt(deadline)) => {
                    Ok(LaunchChildOutcome::SerialLost(deadline))
                }
                _ => Err(45),
            };
        }
        Err(_) => {
            close_status_retained(status_retained, status_session.as_mut())?;
            close_handle_array_reverse(&retained);
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
            close_status_retained(status_retained, status_session.as_mut())?;
            finish_launch_abort(model, model_launch, &retained, &child, true)?;
            return Err(47);
        }
        _ => {
            close_status_retained(status_retained, status_session.as_mut())?;
            close_handle_array_reverse(&retained);
            return Err(47);
        }
    };

    let modeled = match model.commit_child_launch(&mut model_launch, job_id) {
        Ok(modeled) => modeled,
        Err(_) => {
            if cleanup_unmodeled_job(authorities, transactions, job_id).is_err() {
                close_status_retained(status_retained, status_session.as_mut())?;
                close_handle_array_reverse(&retained);
                return Err(49);
            }
            close_status_retained(status_retained, status_session.as_mut())?;
            finish_launch_abort(model, model_launch, &retained, &child, true)?;
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
            close_status_retained(status_retained, status_session.as_mut())?;
            close_handle_array_reverse(&retained);
            if let Ok(now) = now_millis() {
                let _ = model.wrong_direction_data(event, now);
                let _ = model.child_streams_closed(event, now);
                let _ = cleanup_job(authorities, transactions, model, event, job_id);
            } else {
                let _ = cleanup_unmodeled_job(authorities, transactions, job_id);
            }
            return Err(50);
        }
    };
    let ready = match model.observe_child_ready(event, now_millis()?) {
        Ok(ready) => ready,
        Err(_) => {
            close_status_retained(status_retained, status_session.as_mut())?;
            close_handle_array_reverse(&retained);
            let _ = cleanup_unmodeled_job(authorities, transactions, job_id);
            return Err(51);
        }
    };
    if EventGeneration::from(ready.ids) != event {
        close_status_retained(status_retained, status_session.as_mut())?;
        close_handle_array_reverse(&retained);
        let _ = cleanup_unmodeled_job(authorities, transactions, job_id);
        return Err(52);
    }
    let wait = match start_job_wait(authorities, transactions, job_id) {
        Ok(wait) => wait,
        Err(_) => {
            close_status_retained(status_retained, status_session.as_mut())?;
            close_handle_array_reverse(&retained);
            let _ = cleanup_unmodeled_job(authorities, transactions, job_id);
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

fn wait_launch_with_serial(
    authorities: StartupAuthorities,
    serial: &mut SerialSession,
    reservation: LaunchReservation,
    policy: ChildPolicy,
    model: &ConsoleModel,
    status_endpoint: DwHandle,
    mut status_session: Option<&mut wyrmroot_console_proto::StatusSession>,
) -> Result<LaunchWaitOutcome, u32> {
    let deadline = monotonic_active_now()
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
        #[cfg(feature = "wyr1e-wyrmsh")]
        let witness_index = {
            let index = used;
            items[index] = wait_item(
                serial.release_witness.ok_or(45u32)?,
                DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
            );
            used += 1;
            Some(index)
        };
        #[cfg(not(feature = "wyr1e-wyrmsh"))]
        let witness_index: Option<usize> = None;
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
        let observed = wait_many(&items[..used], DwDeadline(deadline)).map_err(|_| 45u32)?;
        let index = usize::try_from(observed.index).map_err(|_| 45u32)?;
        if witness_index == Some(index) {
            #[cfg(feature = "wyr1e-wyrmsh")]
            observe_release_witness(serial, observed.observed)?;
            return Ok(LaunchWaitOutcome::SerialLost);
        }
        if status_index == Some(index) {
            if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
                return Err(45);
            }
            serve_status(
                status_endpoint,
                status_session.as_deref_mut().ok_or(45u32)?,
                model,
            )?;
            continue;
        }
        match index {
            0 if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 => return Err(45),
            0 => {
                receive_publication_change(authorities, serial)?;
                return Ok(LaunchWaitOutcome::SerialLost);
            }
            1 => return Ok(LaunchWaitOutcome::SerialLost),
            2 if observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 => {
                return receive_initial_launch(authorities.launch, reservation, policy)
                    .map(LaunchWaitOutcome::Reply);
            }
            2 => return Err(45),
            _ => return Err(45),
        }
    }
}

fn event_loop(
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    model: &mut ConsoleModel,
    mut serial: &mut SerialSession,
    mut child: &mut ChildSession,
) -> Result<u32, u32> {
    #[cfg(feature = "wyr1d-selector32")]
    let mut capture = wyrmroot_consoled::selector32::Capture::new(authorities.selector_nonce)
        .map_err(|_| 120u32)?;
    let mut streams = NativeStreams;
    let mut input_pending = Pending::new();
    let mut output_pending = Pending::new();
    let mut next_data = DataClass::Raw;
    #[cfg(feature = "wyr1e8-recovery")]
    let mut recovery_request = None;
    #[cfg(feature = "wyr1e8-recovery")]
    let mut recovery_acknowledged = false;
    loop {
        #[cfg(feature = "wyr1d-selector32")]
        if let Some(status) = capture
            .ready(
                selector_tuple(child.event),
                child.job_id,
                child.event.serial.publication_generation,
                child.event.serial.connector_client_transaction,
            )
            .map_err(|_| 121u32)?
        {
            selector_report(authorities.selector_control, status)?;
        }
        // Fill only an empty retry buffer. Queue removal is committed only
        // after the corresponding native DATA datagram commits.
        reserve_input(model, &mut input_pending)?;
        reserve_output(model, &mut output_pending)?;

        #[cfg(feature = "wyr1e8-recovery")]
        if let Some(identity) = recovery_request
            && !recovery_acknowledged
            && input_pending.is_empty()
            && output_pending.is_empty()
        {
            let snapshot = model.snapshot();
            if snapshot.input_queued == 0
                && snapshot.stdout_queued == 0
                && snapshot.stderr_queued == 0
            {
                if !streams_freshly_quiet(&mut streams, child, model)? {
                    // The quiet poll staged more native output. Reserve it
                    // before waiting so it can immediately reach serial TX.
                    continue;
                }
                let ack = wyrmroot_consoled::quiesce_control::encode(
                    wyrmroot_consoled::quiesce_control::Message::Quiesced(identity),
                )
                .map_err(|_| 128u32)?;
                send_channel(authorities.recovery_control, &ack, &[]).map_err(|_| 128u32)?;
                recovery_acknowledged = true;
            }
        }

        let now = monotonic_active_now().map_err(|_| 53u32)?;
        // Stability is time-based, not idleness-based. Continuous serial or
        // child traffic must not prevent the exact READY tuple from clearing
        // an expired child-restart window.
        observe_exact_ready(model, &serial, &child, 55)?;
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
        #[cfg(feature = "wyr1e-wyrmsh")]
        let mut data_base = initial_data_base;
        #[cfg(not(feature = "wyr1e-wyrmsh"))]
        let data_base = initial_data_base;
        #[cfg(feature = "wyr1e-wyrmsh")]
        let witness_index = {
            let index = data_base;
            items[index] = wait_item(
                serial.release_witness.ok_or(61u32)?,
                DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
            );
            data_base += 1;
            Some(index)
        };
        #[cfg(not(feature = "wyr1e-wyrmsh"))]
        let witness_index: Option<usize> = None;
        #[cfg(feature = "wyr1e8-recovery")]
        let recovery_index = {
            let index = data_base;
            items[index] = wait_item(
                authorities.recovery_control,
                DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
            );
            data_base += 1;
            Some(index)
        };
        #[cfg(not(feature = "wyr1e8-recovery"))]
        let recovery_index: Option<usize> = None;

        let raw_writable = if output_pending.is_empty() {
            0
        } else {
            DW_SIGNAL_WRITABLE.0
        };
        // R7B-3 read this as the one place a build's console behaves
        // differently, and it is -- but it is not a choice. An outstanding
        // quiesce request is acknowledged only once the input, stdout and
        // stderr queues are all empty and one further poll finds nothing. Keep
        // admitting raw serial input across that window and fresh bytes can
        // refill the queue faster than it drains, so the acknowledgement need
        // never be reached. Suppressing raw input is what makes the handshake
        // terminate; it is entailed by having the handshake, not a policy
        // chosen alongside it.
        //
        // So the open question is not whether to unify these two arms. It is
        // whether the product has the handshake at all, and that is the far
        // end of init's held-wait barrier: nothing sends `Quiesce` except the
        // machinery R7A filed as class D1. Deciding it from this side would be
        // settling a supervision protocol from one end. It waits for R7B-4.
        #[cfg(feature = "wyr1e8-recovery")]
        let accepting_raw_input = recovery_request.is_none();
        #[cfg(not(feature = "wyr1e8-recovery"))]
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

        let observed = match wait_many(&items[..used], DwDeadline(deadline)) {
            Ok(observed) => observed,
            Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {
                observe_exact_ready(model, &serial, &child, 55)?;
                continue;
            }
            Err(_) => return Err(56),
        };
        let signals = observed.observed.0;
        let observed_index = usize::try_from(observed.index).map_err(|_| 61u32)?;

        if witness_index == Some(observed_index) {
            #[cfg(feature = "wyr1e-wyrmsh")]
            observe_release_witness(&serial, observed.observed)?;
            recover_serial(
                authorities,
                transactions,
                model,
                &mut serial,
                &mut child,
                &mut input_pending,
                &mut output_pending,
            )?;
            next_data = DataClass::Raw;
            continue;
        }

        if recovery_index == Some(observed_index) {
            #[cfg(feature = "wyr1e8-recovery")]
            {
                if signals & DW_SIGNAL_PEER_CLOSED.0 != 0 || recovery_request.is_some() {
                    return Err(127);
                }
                if signals & DW_SIGNAL_READABLE.0 == 0 {
                    return Err(127);
                }
                recovery_request = Some(receive_recovery_request(authorities, child)?);
                next_data = DataClass::Stdout;
                continue;
            }
        }

        match observed.index {
            // Registry retirement and raw close invalidate the serial tuple
            // before a co-ready launch response may use it.
            0 => {
                if signals & DW_SIGNAL_PEER_CLOSED.0 != 0 {
                    return Err(57);
                }
                receive_publication_change(authorities, &mut serial)?;
                recover_serial(
                    authorities,
                    transactions,
                    model,
                    &mut serial,
                    &mut child,
                    &mut input_pending,
                    &mut output_pending,
                )?;
                next_data = DataClass::Raw;
                continue;
            }
            1 => {
                recover_serial(
                    authorities,
                    transactions,
                    model,
                    &mut serial,
                    &mut child,
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
                #[cfg(feature = "wyr1e-wyrmsh")]
                drain_clean_terminal_output(
                    authorities,
                    model,
                    &mut streams,
                    &mut serial,
                    &mut child,
                    &mut output_pending,
                )?;
                if recover_terminal_child(
                    authorities,
                    transactions,
                    model,
                    &mut serial,
                    &mut child,
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
                #[cfg(feature = "wyr1e-wyrmsh")]
                if signals & DW_SIGNAL_PEER_CLOSED.0 != 0 && child.wait.is_some() {
                    if recover_terminal_precursor(
                        authorities,
                        transactions,
                        model,
                        &mut streams,
                        &mut serial,
                        &mut child,
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
                    discard_one_record(child.stdin.endpoint().handle());
                    ChildFault::WrongDirection
                };
                recover_child(
                    authorities,
                    transactions,
                    model,
                    &mut serial,
                    &mut child,
                    &mut input_pending,
                    &mut output_pending,
                    fault,
                )?;
                next_data = DataClass::Raw;
                continue;
            }
            4 | 5 => {
                #[cfg(feature = "wyr1e-wyrmsh")]
                if child.wait.is_some() {
                    if recover_terminal_precursor(
                        authorities,
                        transactions,
                        model,
                        &mut streams,
                        &mut serial,
                        &mut child,
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
                    authorities,
                    transactions,
                    model,
                    &mut serial,
                    &mut child,
                    &mut input_pending,
                    &mut output_pending,
                    ChildFault::Peer(kind),
                )?;
                next_data = DataClass::Raw;
                continue;
            }
            6 if child.status.is_some() => {
                #[cfg(feature = "wyr1e-wyrmsh")]
                if signals & DW_SIGNAL_PEER_CLOSED.0 != 0 && child.wait.is_some() {
                    if recover_terminal_precursor(
                        authorities,
                        transactions,
                        model,
                        &mut streams,
                        &mut serial,
                        &mut child,
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
                    serve_status(status.endpoint, &mut status.session, model).is_err()
                } else {
                    true
                };
                if failed {
                    recover_child(
                        authorities,
                        transactions,
                        model,
                        &mut serial,
                        &mut child,
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
                            authorities,
                            transactions,
                            model,
                            &mut serial,
                            &mut child,
                            &mut input_pending,
                            &mut output_pending,
                        )?;
                        next_data = DataClass::Raw;
                        continue;
                    }
                    let mut payload = [0u8; FAIR_SOURCE_BYTES_PER_TURN];
                    match serial.input.read(&mut streams, &mut payload) {
                        Ok(count) => {
                            #[cfg(feature = "wyr1d-selector32")]
                            if let Some(status) =
                                capture.raw_rx(&payload[..count]).map_err(|_| 122u32)?
                            {
                                selector_report(authorities.selector_control, status)?;
                            }
                            model
                                .stage_serial_input(child.event, &payload[..count])
                                .map_err(|_| 58u32)?;
                        }
                        Err(StreamError::WouldBlock) => {}
                        Err(_) => {
                            recover_serial(
                                authorities,
                                transactions,
                                model,
                                &mut serial,
                                &mut child,
                                &mut input_pending,
                                &mut output_pending,
                            )?;
                            next_data = DataClass::Raw;
                            continue;
                        }
                    }
                }
                if signals & DW_SIGNAL_WRITABLE.0 != 0 && !output_pending.is_empty() {
                    match serial
                        .output
                        .write(&mut streams, &output_pending.bytes[..output_pending.used])
                    {
                        Ok(written) if written == output_pending.used => {
                            commit_output(model, &output_pending)?;
                            #[cfg(feature = "wyr1d-selector32")]
                            if let Some(status) = capture
                                .raw_tx(&output_pending.bytes[..written])
                                .map_err(|_| 123u32)?
                            {
                                selector_report(authorities.selector_control, status)?;
                            }
                            output_pending.clear();
                        }
                        Ok(_) => return Err(59),
                        Err(StreamError::WouldBlock) => {
                            release_output(model, &output_pending)?;
                            output_pending.clear();
                        }
                        Err(_) => {
                            recover_serial(
                                authorities,
                                transactions,
                                model,
                                &mut serial,
                                &mut child,
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
                    match child
                        .stdin
                        .write(&mut streams, &input_pending.bytes[..input_pending.used])
                    {
                        Ok(written) if written == input_pending.used => {
                            commit_input(model, &input_pending)?;
                            #[cfg(feature = "wyr1d-selector32")]
                            if let Some(status) = capture
                                .stdin_commit(&input_pending.bytes[..written])
                                .map_err(|_| 125u32)?
                            {
                                selector_report(authorities.selector_control, status)?;
                            }
                            input_pending.clear();
                        }
                        Ok(_) => return Err(59),
                        Err(StreamError::WouldBlock) => {
                            release_input(model, &input_pending)?;
                            input_pending.clear();
                        }
                        Err(_) => {
                            recover_child(
                                authorities,
                                transactions,
                                model,
                                &mut serial,
                                &mut child,
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
                        authorities,
                        transactions,
                        model,
                        &mut serial,
                        &mut child,
                        &mut input_pending,
                        &mut output_pending,
                        ChildFault::Peer(output_kind(source)),
                    )?;
                    next_data = DataClass::Raw;
                    continue;
                }
                let mut payload = [0u8; FAIR_SOURCE_BYTES_PER_TURN];
                match input.read(&mut streams, &mut payload) {
                    Ok(count) => {
                        #[cfg(feature = "wyr1d-selector32")]
                        if let Some(status) = capture
                            .child_output(matches!(source, OutputSource::Stderr), &payload[..count])
                            .map_err(|_| 124u32)?
                        {
                            selector_report(authorities.selector_control, status)?;
                        }
                        model
                            .stage_child_output(child.event, source, &payload[..count])
                            .map_err(|_| 60u32)?;
                    }
                    Err(StreamError::WouldBlock) => {}
                    Err(_) => {
                        recover_child(
                            authorities,
                            transactions,
                            model,
                            &mut serial,
                            &mut child,
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

#[cfg(feature = "wyr1e-wyrmsh")]
fn drain_clean_terminal_output(
    authorities: StartupAuthorities,
    model: &mut ConsoleModel,
    streams: &mut NativeStreams,
    serial: &mut SerialSession,
    child: &mut ChildSession,
    output_pending: &mut Pending,
) -> Result<(), u32> {
    let deadline = monotonic_active_now()
        .map_err(|_| 53u32)?
        .checked_add(TERMINAL_DRAIN_TIMEOUT_NS)
        .ok_or(54u32)?;
    let wait = child.wait.take().ok_or(61u32)?;
    match receive_launch_before(authorities.launch, wait, deadline)? {
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
        let observed = wait_many(&items[..count], DwDeadline(deadline)).map_err(|_| 64u32)?;
        let index = usize::try_from(observed.index).map_err(|_| 64u32)?;
        if output_index == Some(index) {
            if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0
                || observed.observed.0 & DW_SIGNAL_WRITABLE.0 == 0
            {
                return Err(64);
            }
            match serial
                .output
                .write(streams, &output_pending.bytes[..output_pending.used])
            {
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
        match input.read(streams, &mut payload) {
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

#[cfg(feature = "wyr1e-wyrmsh")]
#[allow(clippy::too_many_arguments)]
fn recover_terminal_precursor(
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    model: &mut ConsoleModel,
    streams: &mut NativeStreams,
    serial: &mut SerialSession,
    child: &mut ChildSession,
    input_pending: &mut Pending,
    output_pending: &mut Pending,
) -> Result<TerminalOutcome, u32> {
    if !matches!(
        model.child_terminal_precursor(child.event, now_millis()?),
        Ok(RecoveryAction::None)
    ) {
        return Err(62);
    }
    drain_clean_terminal_output(authorities, model, streams, serial, child, output_pending)?;
    recover_terminal_child(
        authorities,
        transactions,
        model,
        serial,
        child,
        input_pending,
        output_pending,
    )
}

#[cfg(feature = "wyr1e8-recovery")]
fn receive_recovery_request(
    authorities: StartupAuthorities,
    child: &ChildSession,
) -> Result<wyrmroot_consoled::quiesce_control::Identity, u32> {
    let mut bytes = [0_u8; wyrmroot_consoled::quiesce_control::FRAME_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(authorities.recovery_control, &mut bytes, &mut handles)
        .map_err(|_| 127u32)?;
    if counts.bytes != bytes.len() || counts.handles != 0 {
        close_received(&handles, counts.handles);
        return Err(127);
    }
    let wyrmroot_consoled::quiesce_control::Message::Quiesce(identity) =
        wyrmroot_consoled::quiesce_control::parse(&bytes).map_err(|_| 127u32)?
    else {
        return Err(127);
    };
    let relationship = child.status.as_ref().ok_or(127u32)?.session.relationship();
    if identity.console_generation != child.event.console_generation
        || identity.status_generation != relationship.status_generation
        || identity.shell_generation != child.event.child_generation
        || identity.outer_shell_job != child.job_id
    {
        return Err(127);
    }
    Ok(identity)
}

#[cfg(feature = "wyr1e8-recovery")]
fn streams_freshly_quiet(
    streams: &mut NativeStreams,
    child: &mut ChildSession,
    model: &mut ConsoleModel,
) -> Result<bool, u32> {
    model
        .poll_output_quiescence(child.event, |source, payload| {
            let input = match source {
                OutputSource::Stdout => &mut child.stdout,
                OutputSource::Stderr => &mut child.stderr,
            };
            match input.read(streams, payload) {
                Ok(count) => Ok(Some(count)),
                Err(StreamError::WouldBlock) => Ok(None),
                Err(_) => Err(wyrmroot_consoled::ModelError::ChildDisconnected),
            }
        })
        .map_err(|_| 128u32)
}

#[cfg(feature = "wyr1d-selector32")]
fn selector_configure(channel: DwHandle) -> Result<u64, u32> {
    use wyrmroot_consoled::selector32::{CONFIGURE, STATUS_BYTES, Status};
    wait_readable(channel).map_err(|_| 120u32)?;
    let mut bytes = [0; STATUS_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(channel, &mut bytes, &mut handles).map_err(|_| 120u32)?;
    if counts.bytes != STATUS_BYTES || counts.handles != 0 {
        close_received(&handles, counts.handles);
        return Err(120);
    }
    let config = Status::parse(&bytes).map_err(|_| 120u32)?;
    if config.kind != CONFIGURE {
        return Err(120);
    }
    Ok(config.nonce)
}

#[cfg(feature = "wyr1d-selector32")]
fn selector_tuple(event: EventGeneration) -> wyrmroot_consoled::selector32::Tuple {
    wyrmroot_consoled::selector32::Tuple {
        role: event.serial.device_role,
        bundle: event.serial.device_bundle,
        attempt: event.serial.driver_attempt,
        endpoint: event.serial.driver_control_endpoint_id,
        endpoint_generation: event.serial.driver_control_endpoint_generation,
        transaction: event.serial.attach_transaction,
        stream: event.serial.stream_generation,
        console: event.console_generation,
        child: event.child_generation,
    }
}

#[cfg(feature = "wyr1d-selector32")]
fn selector_report(
    channel: DwHandle,
    status: wyrmroot_consoled::selector32::Status,
) -> Result<(), u32> {
    let bytes = status.encode().map_err(|_| 125u32)?;
    send_channel(channel, &bytes, &[]).map_err(|_| 125u32)
}

fn recover_terminal_child(
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    model: &mut ConsoleModel,
    serial: &mut SerialSession,
    child: &mut ChildSession,
    input_pending: &mut Pending,
    output_pending: &mut Pending,
) -> Result<TerminalOutcome, u32> {
    #[cfg(not(feature = "wyr1e-wyrmsh"))]
    {
        let wait = child.wait.take().ok_or(61u32)?;
        match receive_launch(authorities.launch, wait)? {
            LaunchReply::JobResult {
                job_id,
                session_shutdown,
            } if job_id == child.job_id => child.session_shutdown = session_shutdown,
            _ => return Err(61),
        }
    }
    if !matches!(model.child_terminal(child.event, now_millis()?), Ok(RecoveryAction::ReapChild(job)) if job == child.job_id)
    {
        return Err(62);
    }
    let stream_failed = close_child_streams(child).is_err();
    let observed_failed = model
        .child_streams_closed(child.event, now_millis()?)
        .is_err();
    input_pending.clear();
    output_pending.clear();
    if stream_failed || observed_failed {
        return Err(64);
    }
    match close_reaped_job(authorities, transactions, model, child.event, child.job_id)? {
        RecoveryAction::ReplaceChild => {
            // F3A.7g. The reap is identical either way -- the streams, the
            // status channel and the job are released above before anything
            // here looks at why the child stopped -- so a session that ends
            // leaves no more behind than one that restarts. The only thing
            // withheld is the replacement.
            if child.session_shutdown {
                return Ok(TerminalOutcome::SessionEnded);
            }
            *child = launch_child(authorities, transactions, model, serial)?;
            observe_exact_ready_without_serial(model, child, 65)?;
            Ok(TerminalOutcome::Replaced)
        }
        RecoveryAction::Escalate => Err(66),
        _ => Err(67),
    }
}

fn recover_child(
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
        ChildFault::Peer(kind) => model.child_peer_closed(child.event, kind, now_millis()?),
        ChildFault::Status => model.status_peer_closed(child.event, now_millis()?),
        ChildFault::WrongDirection => model.wrong_direction_data(child.event, now_millis()?),
    }
    .map_err(|_| 62u32)?;
    if !matches!(action, RecoveryAction::TerminateChild(job) if job == child.job_id) {
        return Err(63);
    }
    close_child_status(child)?;
    let wait_resolution = cancel_child_wait(authorities, transactions, child)?;
    let stream_failed = close_child_streams(child).is_err();
    let observed_failed = model
        .child_streams_closed(child.event, now_millis()?)
        .is_err();
    if stream_failed || observed_failed {
        return Err(64);
    }
    input_pending.clear();
    output_pending.clear();
    let cleanup = match wait_resolution {
        ChildWaitResolution::Cancelled => {
            cleanup_job(authorities, transactions, model, child.event, child.job_id)?
        }
        ChildWaitResolution::Terminal => {
            complete_terminal_reap(authorities, transactions, model, child.event, child.job_id)?
        }
    };
    match cleanup {
        RecoveryAction::ReplaceChild => {
            *child = launch_child(authorities, transactions, model, serial)?;
            observe_exact_ready_without_serial(model, child, 65)?;
            Ok(())
        }
        RecoveryAction::Escalate => Err(66),
        _ => Err(67),
    }
}

#[allow(clippy::too_many_arguments)]
fn recover_serial(
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
        .serial_peer_closed(old_serial, old_console, now_millis()?)
        .map_err(|_| 68u32)?;
    if !matches!(action, RecoveryAction::TerminateChild(job) if job == child.job_id) {
        return Err(69);
    }
    let raw_failed = close_serial_session(serial).is_err();
    let watch_failed = retire_publication_watch(authorities, transactions, serial).is_err();
    let wait_resolution = cancel_child_wait(authorities, transactions, child)?;
    let streams_failed = close_child_streams(child).is_err();
    let observed_failed = model
        .child_streams_closed(child.event, now_millis()?)
        .is_err();
    input_pending.clear();
    output_pending.clear();
    if raw_failed || watch_failed || streams_failed || observed_failed {
        return Err(70);
    }
    let retired = match wait_resolution {
        ChildWaitResolution::Cancelled => {
            cleanup_job(authorities, transactions, model, child.event, child.job_id)?
        }
        ChildWaitResolution::Terminal => {
            complete_terminal_reap(authorities, transactions, model, child.event, child.job_id)?
        }
    };
    if retired != RecoveryAction::None {
        return Err(72);
    }
    #[cfg(feature = "wyr1d-selector32")]
    selector_report(
        authorities.selector_control,
        wyrmroot_consoled::selector32::Status {
            kind: wyrmroot_consoled::selector32::RELEASED,
            sequence: 0,
            nonce: authorities.selector_nonce,
            tuple: selector_tuple(child.event),
            job: child.job_id,
            rx: 0,
            tx: 0,
            leg: 0,
            value: 0,
            publication: old_serial.publication_generation,
            client_transaction: old_serial.connector_client_transaction,
        },
    )?;
    match model
        .complete_serial_cleanup(old_serial, old_console, now_millis()?)
        .map_err(|_| 72u32)?
    {
        RecoveryAction::RetrySerialAt(deadline_ms) => {
            *serial = attach_serial_bounded(authorities, transactions, model, Some(deadline_ms))?;
            *child = launch_child(authorities, transactions, model, serial)?;
            observe_exact_ready(model, serial, child, 67)?;
            Ok(())
        }
        RecoveryAction::Escalate => Err(71),
        _ => Err(72),
    }
}

fn cleanup_job(
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    model: &mut ConsoleModel,
    event: EventGeneration,
    job_id: u64,
) -> Result<RecoveryAction, u32> {
    let terminate = job_request(
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
    let waited = job_request(authorities, transactions, LaunchMessageType::Wait, job_id)?;
    if !matches!(waited, LaunchReply::JobResult { job_id: response, .. } if response == job_id) {
        return Err(75);
    }
    if !matches!(model.child_terminated(event, now_millis()?), Ok(RecoveryAction::ReapChild(job)) if job == job_id)
    {
        return Err(74);
    }
    let closed = job_request(
        authorities,
        transactions,
        LaunchMessageType::CloseJob,
        job_id,
    )?;
    if !matches!(closed, LaunchReply::Closed(response) if response == job_id) {
        return Err(76);
    }
    model.child_reaped(event, now_millis()?).map_err(|_| 77)
}

fn complete_terminal_reap(
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    model: &mut ConsoleModel,
    event: EventGeneration,
    job_id: u64,
) -> Result<RecoveryAction, u32> {
    if !matches!(model.child_terminated(event, now_millis()?), Ok(RecoveryAction::ReapChild(job)) if job == job_id)
    {
        return Err(74);
    }
    close_reaped_job(authorities, transactions, model, event, job_id)
}

fn close_reaped_job(
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    model: &mut ConsoleModel,
    event: EventGeneration,
    job_id: u64,
) -> Result<RecoveryAction, u32> {
    let closed = job_request(
        authorities,
        transactions,
        LaunchMessageType::CloseJob,
        job_id,
    )?;
    if !matches!(closed, LaunchReply::Closed(response) if response == job_id) {
        return Err(76);
    }
    model.child_reaped(event, now_millis()?).map_err(|_| 77)
}

fn cleanup_unmodeled_job(
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    job_id: u64,
) -> Result<(), u32> {
    let terminate = job_request(
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
    let waited = job_request(authorities, transactions, LaunchMessageType::Wait, job_id)?;
    if !matches!(waited, LaunchReply::JobResult { job_id: response, .. } if response == job_id) {
        return Err(79);
    }
    let closed = job_request(
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

fn start_job_wait(
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
    send_channel(authorities.launch, &bytes[..size], &[]).map_err(|_| 79u32)?;
    Ok(reservation)
}

fn cancel_child_wait(
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
    send_channel(authorities.launch, &bytes[..size], &[]).map_err(|_| 80u32)?;

    let mut terminal = false;
    let mut received = 0;
    while received < 2 {
        let (reservation, reply) = receive_launch_any(authorities.launch)?;
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

fn cleanup_child_for_exit(
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    child: &mut ChildSession,
) -> Result<(), u32> {
    let resolution = cancel_child_wait(authorities, transactions, child);
    let streams_closed = close_child_streams(child);
    let result = match resolution? {
        ChildWaitResolution::Cancelled => {
            cleanup_unmodeled_job(authorities, transactions, child.job_id)
        }
        ChildWaitResolution::Terminal => {
            let reply = job_request(
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

fn job_request(
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
    send_channel(authorities.launch, &bytes[..size], &[]).map_err(|_| 74u32)?;
    receive_launch(authorities.launch, reservation)
}

fn receive_launch(channel: DwHandle, expected: LaunchReservation) -> Result<LaunchReply, u32> {
    let (reservation, reply) = receive_launch_any(channel)?;
    if reservation != expected {
        return Err(79);
    }
    Ok(reply)
}

// Only the Wyrmsh terminal drain waits for a launch result under a deadline.
#[cfg(feature = "wyr1e-wyrmsh")]
fn receive_launch_before(
    channel: DwHandle,
    expected: LaunchReservation,
    deadline: u64,
) -> Result<LaunchReply, u32> {
    let observed = wait_one(
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
    let (reservation, reply) = receive_launch_ready(channel)?;
    if reservation != expected {
        return Err(79);
    }
    Ok(reply)
}

fn receive_initial_launch(
    channel: DwHandle,
    expected: LaunchReservation,
    policy: ChildPolicy,
) -> Result<LaunchReply, u32> {
    if policy == ChildPolicy::ConsoleEcho {
        return receive_launch(channel, expected);
    }
    wait_readable(channel).map_err(|_| 75u32)?;
    let mut bytes = [0u8; 128];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(channel, &mut bytes, &mut handles).map_err(|_| 76u32)?;
    if counts.handles != 0 {
        close_received(&handles, counts.handles);
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

fn serve_status(
    endpoint: DwHandle,
    session: &mut wyrmroot_console_proto::StatusSession,
    model: &ConsoleModel,
) -> Result<(), u32> {
    let mut bytes = [0u8; wyrmroot_console_proto::MAX_MESSAGE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(endpoint, &mut bytes, &mut handles).map_err(|_| 101u32)?;
    if counts.handles != 0 {
        close_received(&handles, counts.handles);
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
            return send_status_bounded(endpoint, &bytes[..size], header);
        }
    };
    if decoded != Ok(wyrmroot_console_proto::Message::Query(header)) {
        let size = wyrmroot_console_proto::encode_error(
            header,
            wyrmroot_console_proto::ErrorCode::Malformed,
            &mut bytes,
        )
        .map_err(|_| 104u32)?;
        send_status_bounded(endpoint, &bytes[..size], header)?;
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
            send_status_bounded(endpoint, &bytes[..size], header)?;
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
    send_status_bounded(endpoint, &bytes[..size], header)?;
    session.complete(ticket).map_err(|_| 109)
}

fn send_status_bounded(
    endpoint: DwHandle,
    bytes: &[u8],
    header: wyrmroot_console_proto::Header,
) -> Result<(), u32> {
    match send_channel(endpoint, bytes, &[]) {
        Ok(()) => return Ok(()),
        Err(NativeError::Status(status)) if status == DW_STATUS_WOULD_BLOCK => {}
        Err(_) => return Err(110),
    }
    let deadline = monotonic_active_now()
        .map_err(|_| 110u32)?
        .checked_add(STATUS_SEND_TIMEOUT_NS)
        .ok_or(110u32)?;
    match wait_one(
        endpoint,
        DwSignals(DW_SIGNAL_WRITABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        DwDeadline(deadline),
    ) {
        Ok(observed)
            if observed.observed.0 & DW_SIGNAL_WRITABLE.0 != 0
                && observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 == 0 =>
        {
            send_channel(endpoint, bytes, &[]).map_err(|_| 111)
        }
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {
            let mut unavailable = [0u8; wyrmroot_console_proto::ERROR_BYTES];
            if let Ok(size) = wyrmroot_console_proto::encode_error(
                header,
                wyrmroot_console_proto::ErrorCode::Unavailable,
                &mut unavailable,
            ) {
                let _ = send_channel(endpoint, &unavailable[..size], &[]);
            }
            Err(112)
        }
        _ => Err(113),
    }
}

fn receive_launch_any(channel: DwHandle) -> Result<(LaunchReservation, LaunchReply), u32> {
    wait_readable(channel).map_err(|_| 75u32)?;
    receive_launch_ready(channel)
}

fn receive_launch_ready(channel: DwHandle) -> Result<(LaunchReservation, LaunchReply), u32> {
    let mut bytes = [0u8; 128];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(channel, &mut bytes, &mut handles).map_err(|_| 76u32)?;
    if counts.handles != 0 {
        close_received(&handles, counts.handles);
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

fn reserve_input(model: &mut ConsoleModel, pending: &mut Pending) -> Result<(), u32> {
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

fn commit_input(model: &mut ConsoleModel, pending: &Pending) -> Result<(), u32> {
    let reservation = pending.reservation.ok_or(82u32)?;
    if reservation.length() != pending.used {
        return Err(83);
    }
    model.commit_child_stdin(reservation).map_err(|_| 84)
}

fn release_input(model: &mut ConsoleModel, pending: &Pending) -> Result<(), u32> {
    model
        .release_child_stdin(pending.reservation.ok_or(85u32)?)
        .map_err(|_| 86)
}

fn reserve_output(model: &mut ConsoleModel, pending: &mut Pending) -> Result<(), u32> {
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

fn commit_output(model: &mut ConsoleModel, pending: &Pending) -> Result<(), u32> {
    let reservation = pending.reservation.ok_or(89u32)?;
    if reservation.length() != pending.used {
        return Err(90);
    }
    model.commit_serial_tx(reservation).map_err(|_| 91)
}

fn release_output(model: &mut ConsoleModel, pending: &Pending) -> Result<(), u32> {
    model
        .release_serial_tx(pending.reservation.ok_or(92u32)?)
        .map_err(|_| 93)
}

fn finish_launch_abort(
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
            let closed = close_handle(child[index]).is_ok();
            close_failed |= !closed;
            evidence.unmoved_child_peers_closed[index] = closed;
        } else {
            evidence.moved_child_peers_revoked[index] = moved_peers_revoked;
        }
    }
    for index in (0..3).rev() {
        let closed = close_handle(retained[index]).is_ok();
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

fn close_attempt_handles(handles: &[DwHandle]) -> Result<(), u32> {
    let mut failed = false;
    for handle in handles.iter().rev() {
        if handle.0 != 0 {
            failed |= close_handle(*handle).is_err();
        }
    }
    if failed {
        Err(FATAL_ATTACH_BASE | 99)
    } else {
        Ok(())
    }
}

fn finish_connect_abort(
    model: &mut ConsoleModel,
    request: ConnectRequest,
    handles: &[DwHandle],
) -> Result<(), u32> {
    let handles_closed = close_attempt_handles(handles).is_ok();
    let model_released = model.abort_connect(request).is_ok();
    if handles_closed && model_released {
        Ok(())
    } else {
        Err(FATAL_ATTACH_BASE | 100)
    }
}

fn create_reduced_stream_pair() -> Result<(DwHandle, DwHandle), u32> {
    let (retained_broad, child_broad) =
        create_channel(CHANNEL_CONSTRUCTION_RIGHTS).map_err(|_| 82u32)?;
    let retained = match duplicate_handle(retained_broad, CHILD_CHANNEL_RIGHTS) {
        Ok(handle) => handle,
        Err(_) => {
            let _ = close_handle(child_broad);
            let _ = close_handle(retained_broad);
            return Err(83);
        }
    };
    if close_handle(retained_broad).is_err() {
        let _ = close_handle(retained);
        let _ = close_handle(child_broad);
        return Err(84);
    }
    if validate_exact_channel(retained, CHILD_CHANNEL_RIGHTS).is_err() {
        let _ = close_handle(child_broad);
        let _ = close_handle(retained);
        return Err(85);
    }
    Ok((retained, child_broad))
}

fn validated_stream_endpoint(handle: DwHandle) -> Result<StreamEndpoint, StreamError> {
    StreamEndpoint::from_validated_handle(handle)
}

fn registry_header(
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

fn valid_connector_identity(
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

fn serial_correlation(
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

fn serial_correlates(serial: &SerialSession, event: EventGeneration) -> bool {
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

fn observe_exact_ready(
    model: &mut ConsoleModel,
    serial: &SerialSession,
    child: &ChildSession,
    error: u32,
) -> Result<(), u32> {
    if !serial_correlates(serial, child.event) {
        return Err(error);
    }
    observe_exact_ready_without_serial(model, child, error)
}

fn observe_exact_ready_without_serial(
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
        .observe_ready(now_millis()?, token)
        .map(|_| ())
        .map_err(|_| error)
}

fn valid_received_channel(info: DwReceivedHandleInfoV1, rights: DwRights) -> bool {
    info.handle.0 != 0
        && info.object_type == DW_OBJECT_TYPE_CHANNEL
        && info.rights == rights
        && info.reserved0 == 0
        && info.reserved == [0; 2]
}

fn validate_exact_channel(handle: DwHandle, rights: DwRights) -> Result<(), NativeError> {
    let info = query_capability_info(handle)?;
    if info.object_type == DW_OBJECT_TYPE_CHANNEL && info.rights == rights {
        Ok(())
    } else {
        Err(NativeError::Output(
            wyrmroot_runtime::NativeOutputError::InvalidObjectInfo,
        ))
    }
}

fn wait_readable(handle: DwHandle) -> Result<(), NativeError> {
    let deadline = monotonic_active_now()?
        .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .ok_or(NativeError::Output(
            wyrmroot_runtime::NativeOutputError::DeadlineOverflow,
        ))?;
    let observed = wait_one(
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

fn wait_backoff(registry: DwHandle, deadline_ms: u64) -> Result<(), u32> {
    let deadline_ns = deadline_ms.checked_mul(NANOS_PER_MILLI).ok_or(86u32)?;
    let item = wait_item(registry, DwSignals(DW_SIGNAL_PEER_CLOSED.0));
    match wait_many(core::slice::from_ref(&item), DwDeadline(deadline_ns)) {
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => Ok(()),
        Ok(observed) if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 => Err(87),
        _ => Err(88),
    }
}

fn discard_one_record(endpoint: DwHandle) {
    let mut bytes = [0u8; wyrmroot_stream_proto::MAX_RECORD_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    if let Ok(counts) = receive_channel(endpoint, &mut bytes, &mut handles) {
        close_received(&handles, counts.handles);
    }
}

fn close_child_streams(child: &mut ChildSession) -> Result<(), u32> {
    let mut failed = close_child_status(child).is_err();
    let handles = [
        child.stdin.endpoint().handle(),
        child.stdout.endpoint().handle(),
        child.stderr.endpoint().handle(),
    ];
    for handle in handles.into_iter().rev() {
        failed |= close_handle(handle).is_err();
    }
    if failed { Err(93) } else { Ok(()) }
}

fn close_child_status(child: &mut ChildSession) -> Result<(), u32> {
    let Some(mut status) = child.status.take() else {
        return Ok(());
    };
    status.session.close();
    close_handle(status.endpoint).map_err(|_| 93)
}

fn close_status_retained(
    endpoint: DwHandle,
    session: Option<&mut wyrmroot_console_proto::StatusSession>,
) -> Result<(), u32> {
    if let Some(session) = session {
        session.close();
    }
    if endpoint.0 != 0 && close_handle(endpoint).is_err() {
        Err(93)
    } else {
        Ok(())
    }
}

fn close_status_pair(retained: DwHandle, child: DwHandle) -> Result<(), u32> {
    let mut failed = false;
    if child.0 != 0 {
        failed |= close_handle(child).is_err();
    }
    if retained.0 != 0 {
        failed |= close_handle(retained).is_err();
    }
    if failed { Err(93) } else { Ok(()) }
}

fn close_received(handles: &[DwReceivedHandleInfoV1], count: usize) {
    for info in handles[..count.min(handles.len())].iter().rev() {
        if info.handle.0 != 0 {
            let _ = close_handle(info.handle);
        }
    }
}

fn close_handle_array_reverse(handles: &[DwHandle]) {
    for handle in handles.iter().rev() {
        if handle.0 != 0 {
            let _ = close_handle(*handle);
        }
    }
}

fn close_authorities(authorities: StartupAuthorities) {
    let _ = close_handle(authorities.launch);
    let _ = close_handle(authorities.registry);
}

const fn wait_item(handle: DwHandle, signals: DwSignals) -> DwWaitItemV1 {
    DwWaitItemV1 { handle, signals }
}

const fn output_kind(source: OutputSource) -> StreamKind {
    match source {
        OutputSource::Stdout => StreamKind::Stdout,
        OutputSource::Stderr => StreamKind::Stderr,
    }
}

fn now_millis() -> Result<u64, u32> {
    monotonic_active_now()
        .map(|now| now / NANOS_PER_MILLI)
        .map_err(|_| 94)
}

wyrmroot_runtime::native_entry!(crate::main);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    panic_abort()
}
