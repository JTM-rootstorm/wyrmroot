//! The consoled role: bootstrap, serial attach, child launch, the event loop
//! and recovery.
//!
//! This is the whole native role that `src/main.rs` used to hold. The binary
//! keeps only its freestanding entry, which hands [`run`] the bootstrap
//! Channel. It exists only with `native-consoled`, which every consoled binary
//! shape requires.

use crate::stream_transfer::move_transfer;

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
    BOOTSTRAP_CHANNEL_EXPECTATION, ChannelPlatform, ClockPlatform, HandlePlatform, NativeError,
    NativeInput, NativeOutput, ReceiveCounts, StreamEndpoint, StreamError, StreamSystem,
    WYR0_I_SUPERVISION_POLICY, WaitPlatform, validate_bootstrap_channel,
};

/// The base every failure step of [`run`] is reported under, as the
/// binary's exit status: `FAILURE_BASE | step`.
pub const FAILURE_BASE: u32 = 0xD400_0000;
const EVENT_TICK_NS: u64 = 1_000_000_000;
const STATUS_SEND_TIMEOUT_NS: u64 = 1_000_000_000;
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
    release_witness: Option<DwHandle>,
    input: NativeInput,
    output: NativeOutput,
}

impl SerialSession {
    const fn endpoint(&self) -> DwHandle {
        self.input.endpoint().handle()
    }
}

fn close_serial_session<P: ConsoledPlatform>(
    platform: &mut P,
    serial: &mut SerialSession,
) -> Result<(), u32> {
    // The raw endpoint is always released first. The retained registry
    // CONNECT peer is the devmgr-observed certificate for this exact client
    // generation and therefore cannot be closed before raw custody ends.
    let witness = serial.release_witness.take();
    let raw = serial.raw_owned.then(|| serial.endpoint());
    // A failed close leaves ownership ambiguous. Consume it before the
    // attempt so outer fatal cleanup cannot retry a possibly released handle.
    serial.raw_owned = false;
    let closed = match raw {
        Some(raw) => {
            release_raw_then_witness(raw, witness, |handle| platform.close_handle(handle).is_ok())
        }
        None => witness.is_none_or(|handle| platform.close_handle(handle).is_ok()),
    };
    if !closed {
        Err(FATAL_ATTACH_BASE | 101)
    } else {
        Ok(())
    }
}

fn observe_release_witness<P: ConsoledPlatform>(
    platform: &mut P,
    serial: &SerialSession,
    signals: DwSignals,
) -> Result<(), u32> {
    let readable = signals.0 & DW_SIGNAL_READABLE.0 != 0;
    let peer_closed = signals.0 & DW_SIGNAL_PEER_CLOSED.0 != 0;
    if classify_release_witness(readable, peer_closed) == ReleaseWitnessEvent::Malformed {
        if !readable {
            return Err(FATAL_ATTACH_BASE | 103);
        }
        let witness = serial.release_witness.ok_or(FATAL_ATTACH_BASE | 102)?;
        let mut bytes = [0u8; 1];
        let mut handles = [DwReceivedHandleInfoV1::default(); 1];
        if let Ok(counts) = platform.receive_channel(witness, &mut bytes, &mut handles) {
            close_received(platform, &handles, counts.handles);
        }
        return Err(FATAL_ATTACH_BASE | 102);
    }
    Ok(())
}

/// Releases a witness whose other end is gone while raw custody still holds.
///
/// F3A.7k. devmgr retains the witness's other end as the lifetime certificate
/// of this client generation, and never closes it while it lives: a driver
/// retirement waits for *this* side to release first. So a pure release seen
/// here, with the raw endpoint still open, means the certificate's observer
/// is gone -- devmgr exited -- and says nothing about the serial line the
/// driver serves. Closure contract §5.4 requires consoled and the live shell
/// to keep serving across that loss, and they used to be torn down instead:
/// `recover_serial` killed the shell and waited for a republication that a
/// degraded devmgr never makes. A real serial loss still arrives on the raw
/// endpoint, and a replacement devmgr retires the retained console stack
/// explicitly (`wyr1c_native::retire_retained_device_topology`).
fn drop_orphaned_witness<P: ConsoledPlatform>(
    platform: &mut P,
    serial: &mut SerialSession,
) -> Result<(), u32> {
    let witness = serial
        .release_witness
        .take()
        .ok_or(FATAL_ATTACH_BASE | 102)?;
    platform
        .close_handle(witness)
        .map_err(|_| FATAL_ATTACH_BASE | 106)
}

/// Whether a publication change is devmgr's publication being withdrawn
/// while consoled still serves the line, rather than a new publication.
///
/// F3A.7k, the second half of `drop_orphaned_witness`. The serial connector's
/// publication endpoint lives only in devmgr, so when devmgr dies registryd
/// withdraws `device.serial.console0` and completes consoled's watch with
/// generation 0 (`registryd` `RegistryState::peer_closed`). That is the same
/// fact the orphaned witness reports -- devmgr is gone -- seen through the
/// registry, and it says nothing about the serial line the driver still
/// serves. Treating it as serial loss closed the raw endpoint and silenced
/// the console in every degraded boot whose episode fired. A new generation
/// is a real republication and still rebuilds the session. The watch is
/// one-shot, so nothing further arrives on it.
const fn publication_withdrawn(service_generation: u64) -> bool {
    service_generation == 0
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

#[allow(
    clippy::large_enum_variant,
    reason = "the guest role has no allocator to box into; the outcome is built and consumed once per launch"
)]
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

/// The platform operations the consoled role uses.
/// [`wyrmroot_runtime::NativePlatform`] is the production implementation; host
/// tests use the runtime's recording platform.
pub trait ConsoledPlatform:
    HandlePlatform + ChannelPlatform + WaitPlatform + ClockPlatform
{
}

impl<P> ConsoledPlatform for P where
    P: HandlePlatform + ChannelPlatform + WaitPlatform + ClockPlatform
{
}

/// consoled's native stream adapter, over its platform.
///
/// Deliberately not the runtime's blanket [`StreamSystem`] impl for a
/// platform: that one waits on an endpoint forever, and consoled's stream wait
/// has always been bounded, at `WYR0_I_SUPERVISION_POLICY.ready_timeout_ns`
/// past the active clock. Pass `&mut ConsoledStreams::new(platform)`, never
/// the platform itself, wherever a [`StreamSystem`] is wanted. It holds
/// nothing but the borrow, so one built per call behaves exactly as the
/// stateless `NativeStreams` unit it replaced.
struct ConsoledStreams<'a, P>(&'a mut P);

impl<'a, P: ConsoledPlatform> ConsoledStreams<'a, P> {
    fn new(platform: &'a mut P) -> Self {
        Self(platform)
    }
}

impl<P: ConsoledPlatform> StreamSystem for ConsoledStreams<'_, P> {
    fn receive(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError> {
        self.0.receive_channel(channel, bytes, handles)
    }

    fn send(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
        self.0.send_channel(channel, bytes, &[])
    }

    fn close(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        self.0.close_handle(handle)
    }

    fn wait(&mut self, channel: DwHandle, signals: DwSignals) -> Result<DwSignals, NativeError> {
        let deadline = self
            .0
            .monotonic_active_now()?
            .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .ok_or(NativeError::Output(
                wyrmroot_runtime::NativeOutputError::DeadlineOverflow,
            ))?;
        Ok(self
            .0
            .wait_one(channel, signals, DwDeadline(deadline))?
            .observed)
    }
}

/// Runs one consoled generation over its bootstrap Channel, returning the
/// session's exit status or the failure step it stopped with.
pub fn run<P: ConsoledPlatform>(platform: &mut P, bootstrap: DwHandle) -> Result<u32, u32> {
    validate_bootstrap_channel(
        platform
            .query_capability_info(bootstrap)
            .map_err(|_| 3u32)?,
        BOOTSTRAP_CHANNEL_EXPECTATION,
    )
    .map_err(|_| 4u32)?;

    let mut init_bytes = [0u8; CONSOLED_BYTES];
    let mut init_handles = [DwReceivedHandleInfoV1::default(); 3];
    let counts = platform
        .receive_channel(bootstrap, &mut init_bytes, &mut init_handles)
        .map_err(|_| 5u32)?;
    if counts.bytes != CONSOLED_BYTES || counts.handles != 3 {
        close_received(platform, &init_handles, counts.handles);
        let _ = platform.close_handle(bootstrap);
        return Err(6);
    }
    let init = match parse_consoled_init(&init_bytes, &init_handles) {
        Ok(init) => init,
        Err(_) => {
            close_received(platform, &init_handles, 3);
            let _ = platform.close_handle(bootstrap);
            return Err(7);
        }
    };
    let authorities = StartupAuthorities {
        registry: init_handles[1].handle,
        launch: init_handles[2].handle,
        registry_generation: init.registry_generation,
        registry_endpoint_id: init.registry_endpoint_id,
        registry_endpoint_generation: init.registry_endpoint_generation,
        launch_connection_id: init.launch_connection_id,
        launch_connection_generation: init.launch_connection_generation,
        startup_transaction: init.transaction_id,
    };
    if platform.close_handle(init_handles[0].handle).is_err() {
        close_authorities(platform, authorities);
        let _ = platform.close_handle(bootstrap);
        return Err(8);
    }

    let mut transactions = TransactionIds::after(authorities.startup_transaction)?;
    let mut model = ConsoleModel::new();
    let mut serial =
        match attach_serial_bounded(platform, authorities, &mut transactions, &mut model, None) {
            Ok(serial) => serial,
            Err(error) => {
                close_authorities(platform, authorities);
                let _ = platform.close_handle(bootstrap);
                return Err(error);
            }
        };
    let child = match launch_child(
        platform,
        authorities,
        &mut transactions,
        &mut model,
        &mut serial,
    ) {
        Ok(child) => child,
        Err(error) => {
            let _ = close_serial_session(platform, &mut serial);
            close_authorities(platform, authorities);
            let _ = platform.close_handle(bootstrap);
            return Err(error);
        }
    };
    let mut child = child;
    if observe_exact_ready(platform, &mut model, &serial, &child, 9).is_err() {
        let _ = close_serial_session(platform, &mut serial);
        let _ = cleanup_child_for_exit(platform, authorities, &mut transactions, &mut child);
        close_authorities(platform, authorities);
        let _ = platform.close_handle(bootstrap);
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
            let _ = close_serial_session(platform, &mut serial);
            let _ = cleanup_child_for_exit(platform, authorities, &mut transactions, &mut child);
            close_authorities(platform, authorities);
            let _ = platform.close_handle(bootstrap);
            return Err(10);
        }
    };
    if platform
        .send_channel(bootstrap, &ready[..ready_size], &[])
        .is_err()
    {
        let _ = close_serial_session(platform, &mut serial);
        let _ = cleanup_child_for_exit(platform, authorities, &mut transactions, &mut child);
        close_authorities(platform, authorities);
        let _ = platform.close_handle(bootstrap);
        return Err(11);
    }
    if platform.close_handle(bootstrap).is_err() {
        let _ = close_serial_session(platform, &mut serial);
        let _ = cleanup_child_for_exit(platform, authorities, &mut transactions, &mut child);
        close_authorities(platform, authorities);
        return Err(12);
    }

    let result = event_loop(
        platform,
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
        let serial_closed = close_serial_session(platform, &mut serial).is_ok();
        let watch_retired =
            retire_publication_watch(platform, authorities, &mut transactions, &mut serial).is_ok();
        close_authorities(platform, authorities);
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
            platform,
            &mut serial,
            &mut child,
            |platform, serial| close_serial_session(platform, serial).is_ok(),
            |platform, serial| {
                retire_publication_watch(platform, authorities, &mut transactions, serial).is_ok()
            },
            |platform, child| close_child_streams(platform, child).is_ok(),
        );
        close_authorities(platform, authorities);
        return if !cleaned {
            Err(FATAL_ATTACH_BASE | 104)
        } else {
            Err(error)
        };
    }
    result
}

mod channels;
mod event_loop;
mod launch;
mod recovery;
mod serial;
use channels::*;
use event_loop::*;
use launch::*;
use recovery::*;
use serial::*;

#[cfg(test)]
mod tests;
