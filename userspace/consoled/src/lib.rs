//! Bounded, no-std lifecycle model for the WYR1-D serial console supervisor.
//!
//! The native process supplies handles and wait results. This core makes the
//! identity, queue, terminal-transform, and restart decisions explicit before
//! those effects occur. It does not model a shell or terminal emulator.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

#[cfg(feature = "native-consoled")]
use {
    deepwyrm_syscall as _, wyrmroot_device_proto as _, wyrmroot_launch_proto as _,
    wyrmroot_loader as _, wyrmroot_registry_proto as _, wyrmroot_runtime as _,
    wyrmroot_stream_proto as _,
};

pub const STAGING_CAPACITY: usize = 4096;
pub const FAIR_SOURCE_BYTES_PER_TURN: usize = 1024;
pub const RESTART_WINDOW_MILLIS: u64 = 60_000;
pub const STABLE_RUN_MILLIS: u64 = 60_000;
pub const SERIAL_RETRY_BACKOFF_MILLIS: u64 = 25;
pub const MAX_FAILURES_PER_WINDOW: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelError {
    ZeroCorrelation,
    StaleCorrelation,
    WrongConnectionState,
    NoChild,
    IncompleteCleanup,
    AlreadyReserved,
    UnknownReservation,
    Backpressure,
    TooLarge,
    MonotonicRegression,
    ArithmeticOverflow,
    RestartExhausted,
    WrongDirection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    Active,
    RetiringChild,
    AwaitingReap,
    Reconnecting,
    Exhausted,
    FailClosed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputSource {
    Stdout,
    Stderr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamKind {
    Stdin,
    Stdout,
    Stderr,
}

impl StreamKind {
    const fn index(self) -> usize {
        match self {
            Self::Stdin => 0,
            Self::Stdout => 1,
            Self::Stderr => 2,
        }
    }
}

/// The complete correlation carried from registry lookup through raw WRST
/// attachment. Every field is nonzero for an active connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SerialCorrelation {
    pub registry_generation: u64,
    pub registry_endpoint_id: u64,
    pub registry_endpoint_generation: u64,
    pub publication_generation: u64,
    pub connector_client_transaction: u64,
    pub device_role: u64,
    pub device_bundle: u64,
    pub driver_attempt: u64,
    pub driver_control_endpoint_id: u64,
    pub driver_control_endpoint_generation: u64,
    pub attach_transaction: u64,
    pub stream_generation: u64,
}

impl SerialCorrelation {
    pub const fn connected(self) -> bool {
        self.registry_generation != 0
            && self.registry_endpoint_id != 0
            && self.registry_endpoint_generation != 0
            && self.publication_generation != 0
            && self.connector_client_transaction != 0
            && self.device_role != 0
            && self.device_bundle != 0
            && self.driver_attempt != 0
            && self.driver_control_endpoint_id != 0
            && self.driver_control_endpoint_generation != 0
            && self.attach_transaction != 0
            && self.stream_generation != 0
    }

    fn valid_transition_from(self, previous: Self) -> bool {
        if self.registry_generation != previous.registry_generation
            || self.registry_endpoint_id != previous.registry_endpoint_id
            || self.registry_endpoint_generation != previous.registry_endpoint_generation
            || self.device_role != previous.device_role
            || self.connector_client_transaction <= previous.connector_client_transaction
        {
            return false;
        }
        if self.publication_generation == previous.publication_generation {
            return self.device_bundle == previous.device_bundle
                && self.driver_attempt == previous.driver_attempt
                && self.driver_control_endpoint_id == previous.driver_control_endpoint_id
                && self.driver_control_endpoint_generation
                    == previous.driver_control_endpoint_generation
                && self.attach_transaction > previous.attach_transaction
                && self.stream_generation > previous.stream_generation;
        }
        self.publication_generation > previous.publication_generation
            && self.driver_attempt > previous.driver_attempt
            && self.driver_control_endpoint_generation > previous.driver_control_endpoint_generation
            && self.attach_transaction > previous.attach_transaction
            && self.stream_generation > previous.stream_generation
            && self.device_bundle >= previous.device_bundle
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectRequest {
    pub registry_generation: u64,
    pub registry_endpoint_id: u64,
    pub registry_endpoint_generation: u64,
    pub requested_publication_generation: u64,
    pub connector_client_transaction: u64,
}

impl ConnectRequest {
    pub const fn valid(self) -> bool {
        self.registry_generation != 0
            && self.registry_endpoint_id != 0
            && self.registry_endpoint_generation != 0
            && self.requested_publication_generation != 0
            && self.connector_client_transaction != 0
    }
    const fn matches(self, connected: SerialCorrelation) -> bool {
        self.registry_generation == connected.registry_generation
            && self.registry_endpoint_id == connected.registry_endpoint_id
            && self.registry_endpoint_generation == connected.registry_endpoint_generation
            && self.requested_publication_generation == connected.publication_generation
            && self.connector_client_transaction == connected.connector_client_transaction
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionIds {
    pub serial: SerialCorrelation,
    pub console_generation: u64,
    pub child_generation: u64,
    pub child_job: u64,
    pub child_launch: u64,
}

impl SessionIds {
    pub const fn complete(self) -> bool {
        self.serial.connected()
            && self.console_generation != 0
            && self.child_generation != 0
            && self.child_job != 0
            && self.child_launch != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventGeneration {
    pub serial: SerialCorrelation,
    pub console_generation: u64,
    pub child_generation: u64,
    pub child_job: u64,
    pub child_launch: u64,
}

impl From<SessionIds> for EventGeneration {
    fn from(ids: SessionIds) -> Self {
        Self {
            serial: ids.serial,
            console_generation: ids.console_generation,
            child_generation: ids.child_generation,
            child_job: ids.child_job,
            child_launch: ids.child_launch,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Endpoint(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerState {
    pub endpoint: Endpoint,
    pub live: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildSession {
    pub ids: SessionIds,
    pub peers: [PeerState; 3],
}

impl ChildSession {
    pub const fn all_peers_live(self) -> bool {
        self.peers[0].live && self.peers[1].live && self.peers[2].live
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupDisposition {
    CloseConsoledPeer,
    CloseUnmovedChildPeer,
    RevokeMovedChildPeerFromLaunch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointCleanup {
    pub endpoint: Endpoint,
    pub disposition: CleanupDisposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaunchCleanup {
    /// Exactly six unique entries, with moved peers revoked rather than closed.
    pub entries: [EndpointCleanup; 6],
}

/// Non-copy proof that the caller completed the six explicit abort actions.
#[derive(Debug, Eq, PartialEq)]
pub struct LaunchCleanupToken {
    identity: LaunchIdentity,
    cleanup: LaunchCleanup,
}

impl LaunchCleanupToken {
    pub const fn cleanup(&self) -> &LaunchCleanup {
        &self.cleanup
    }
}

/// Not `Copy` or `Clone`: this is exactly one JobV2 MOVE transaction.
#[derive(Debug, Eq, PartialEq)]
pub struct LaunchTransaction {
    serial: SerialCorrelation,
    console_generation: u64,
    child_generation: u64,
    child_job: u64,
    child_launch: u64,
    consoled: [Endpoint; 3],
    child_peers: [Endpoint; 3],
    moved: [bool; 3],
    committed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LaunchIdentity {
    serial: SerialCorrelation,
    console_generation: u64,
    child_generation: u64,
    child_launch: u64,
}

impl LaunchTransaction {
    pub fn move_child_peer(&mut self, kind: StreamKind) -> Result<Endpoint, ModelError> {
        let index = kind.index();
        if self.committed || self.moved[index] {
            return Err(ModelError::WrongConnectionState);
        }
        self.moved[index] = true;
        Ok(self.child_peers[index])
    }

    pub const fn all_moved(&self) -> bool {
        self.moved[0] && self.moved[1] && self.moved[2]
    }

    pub fn abort_cleanup(self) -> Result<LaunchCleanup, ModelError> {
        if self.committed {
            return Err(ModelError::WrongConnectionState);
        }
        let moved = self.moved;
        Ok(LaunchCleanup {
            entries: [
                EndpointCleanup {
                    endpoint: self.consoled[0],
                    disposition: CleanupDisposition::CloseConsoledPeer,
                },
                EndpointCleanup {
                    endpoint: self.consoled[1],
                    disposition: CleanupDisposition::CloseConsoledPeer,
                },
                EndpointCleanup {
                    endpoint: self.consoled[2],
                    disposition: CleanupDisposition::CloseConsoledPeer,
                },
                EndpointCleanup {
                    endpoint: self.child_peers[0],
                    disposition: child_cleanup(moved[0]),
                },
                EndpointCleanup {
                    endpoint: self.child_peers[1],
                    disposition: child_cleanup(moved[1]),
                },
                EndpointCleanup {
                    endpoint: self.child_peers[2],
                    disposition: child_cleanup(moved[2]),
                },
            ],
        })
    }
}

const fn child_cleanup(moved: bool) -> CleanupDisposition {
    if moved {
        CleanupDisposition::RevokeMovedChildPeerFromLaunch
    } else {
        CleanupDisposition::CloseUnmovedChildPeer
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BoundedQueue {
    bytes: [u8; STAGING_CAPACITY],
    head: usize,
    len: usize,
}

impl BoundedQueue {
    const fn new() -> Self {
        Self {
            bytes: [0; STAGING_CAPACITY],
            head: 0,
            len: 0,
        }
    }
    const fn len(&self) -> usize {
        self.len
    }
    const fn is_empty(&self) -> bool {
        self.len == 0
    }
    const fn available(&self) -> usize {
        STAGING_CAPACITY - self.len
    }
    fn push(&mut self, source: &[u8]) {
        let mut index = 0;
        while index < source.len() {
            let tail = (self.head + self.len) % STAGING_CAPACITY;
            self.bytes[tail] = source[index];
            self.len += 1;
            index += 1;
        }
    }
    fn copy_prefix(&self, destination: &mut [u8], maximum: usize) -> usize {
        let count = core::cmp::min(core::cmp::min(destination.len(), maximum), self.len);
        let mut index = 0;
        while index < count {
            destination[index] = self.bytes[(self.head + index) % STAGING_CAPACITY];
            index += 1;
        }
        count
    }
    fn consume(&mut self, count: usize) {
        self.head = (self.head + count) % STAGING_CAPACITY;
        self.len -= count;
    }
    fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct InputNormalizer {
    suppress_lf_after_cr: bool,
}

impl InputNormalizer {
    fn output_len(&self, input: &[u8]) -> usize {
        let mut suppress = self.suppress_lf_after_cr;
        let mut length = 0;
        let mut index = 0;
        while index < input.len() {
            let byte = input[index];
            if suppress {
                suppress = false;
                if byte == b'\n' {
                    index += 1;
                    continue;
                }
            }
            length += 1;
            suppress = byte == b'\r';
            index += 1;
        }
        length
    }
    fn stage(&mut self, input: &[u8], queue: &mut BoundedQueue) -> Result<(), ModelError> {
        if input.len() > FAIR_SOURCE_BYTES_PER_TURN {
            return Err(ModelError::TooLarge);
        }
        if self.output_len(input) > queue.available() {
            return Err(ModelError::Backpressure);
        }
        let mut index = 0;
        while index < input.len() {
            let byte = input[index];
            if self.suppress_lf_after_cr {
                self.suppress_lf_after_cr = false;
                if byte == b'\n' {
                    index += 1;
                    continue;
                }
            }
            if byte == b'\r' {
                queue.push(&[b'\n']);
                self.suppress_lf_after_cr = true;
            } else {
                queue.push(&[byte]);
            }
            index += 1;
        }
        Ok(())
    }
    fn reset(&mut self) {
        self.suppress_lf_after_cr = false;
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct OutputNormalizer {
    previous_was_cr: bool,
}

impl OutputNormalizer {
    fn output_len(&self, input: &[u8]) -> usize {
        let mut previous = self.previous_was_cr;
        let mut length = 0;
        let mut index = 0;
        while index < input.len() {
            let byte = input[index];
            length += if byte == b'\n' && !previous { 2 } else { 1 };
            previous = byte == b'\r';
            index += 1;
        }
        length
    }
    fn stage(&mut self, input: &[u8], queue: &mut BoundedQueue) -> Result<(), ModelError> {
        if input.len() > FAIR_SOURCE_BYTES_PER_TURN {
            return Err(ModelError::TooLarge);
        }
        if self.output_len(input) > queue.available() {
            return Err(ModelError::Backpressure);
        }
        let mut index = 0;
        while index < input.len() {
            let byte = input[index];
            if byte == b'\n' && !self.previous_was_cr {
                queue.push(&[b'\r']);
            }
            queue.push(&[byte]);
            self.previous_was_cr = byte == b'\r';
            index += 1;
        }
        Ok(())
    }
    fn reset(&mut self) {
        self.previous_was_cr = false;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryAction {
    None,
    TerminateChild(u64),
    ReapChild(u64),
    ReplaceChild,
    RetrySerialAt(u64),
    Escalate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RestartWindow {
    times: [u64; MAX_FAILURES_PER_WINDOW],
    len: usize,
}

impl RestartWindow {
    const fn new() -> Self {
        Self {
            times: [0; MAX_FAILURES_PER_WINDOW],
            len: 0,
        }
    }
    const fn failures(&self) -> usize {
        self.len
    }
    fn add(&mut self, now: u64) -> bool {
        let mut kept = 0;
        let mut index = 0;
        while index < self.len {
            if now - self.times[index] < RESTART_WINDOW_MILLIS {
                self.times[kept] = self.times[index];
                kept += 1;
            }
            index += 1;
        }
        self.len = kept;
        if self.len < MAX_FAILURES_PER_WINDOW {
            self.times[self.len] = now;
            self.len += 1;
        }
        self.len >= MAX_FAILURES_PER_WINDOW
    }
    fn clear(&mut self) {
        self.len = 0;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadyToken {
    pub ids: SessionIds,
    pub peers: [Endpoint; 3],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reservation {
    token: u64,
    source: Option<OutputSource>,
    length: usize,
    event: EventGeneration,
}

impl Reservation {
    pub const fn length(self) -> usize {
        self.length
    }
    pub const fn output_source(self) -> Option<OutputSource> {
        self.source
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsoleSnapshot {
    pub state: ConnectionState,
    pub serial: Option<SerialCorrelation>,
    pub console_generation: Option<u64>,
    pub child_generation: Option<u64>,
    pub child_job: Option<u64>,
    pub child_launch: Option<u64>,
    pub peers_live: [bool; 3],
    pub input_queued: usize,
    pub stdout_queued: usize,
    pub stderr_queued: usize,
    pub child_failures: usize,
    pub serial_failures: usize,
    pub last_failure: Option<ModelError>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ConsoleModel {
    state: ConnectionState,
    serial: Option<SerialCorrelation>,
    last_serial: Option<SerialCorrelation>,
    console_generation: Option<u64>,
    child: Option<ChildSession>,
    input: BoundedQueue,
    stdout: BoundedQueue,
    stderr: BoundedQueue,
    input_normalizer: InputNormalizer,
    stdout_normalizer: OutputNormalizer,
    stderr_normalizer: OutputNormalizer,
    next_output: OutputSource,
    pending_stdin: Option<Reservation>,
    pending_tx: Option<Reservation>,
    pending_launch: Option<LaunchIdentity>,
    pending_connect: Option<ConnectRequest>,
    child_window: RestartWindow,
    serial_window: RestartWindow,
    stable: Option<(ReadyToken, u64)>,
    ready_observed: Option<EventGeneration>,
    serial_cleanup: bool,
    child_terminated: bool,
    child_reaped: bool,
    child_failure_at: Option<u64>,
    last_now: Option<u64>,
    next_generation: u64,
    next_endpoint: u64,
    next_reservation: u64,
    last_failure: Option<ModelError>,
}

impl Default for ConsoleModel {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsoleModel {
    pub const fn new() -> Self {
        Self {
            state: ConnectionState::Reconnecting,
            serial: None,
            last_serial: None,
            console_generation: None,
            child: None,
            input: BoundedQueue::new(),
            stdout: BoundedQueue::new(),
            stderr: BoundedQueue::new(),
            input_normalizer: InputNormalizer {
                suppress_lf_after_cr: false,
            },
            stdout_normalizer: OutputNormalizer {
                previous_was_cr: false,
            },
            stderr_normalizer: OutputNormalizer {
                previous_was_cr: false,
            },
            next_output: OutputSource::Stdout,
            pending_stdin: None,
            pending_tx: None,
            pending_launch: None,
            pending_connect: None,
            child_window: RestartWindow::new(),
            serial_window: RestartWindow::new(),
            stable: None,
            ready_observed: None,
            serial_cleanup: true,
            child_terminated: true,
            child_reaped: true,
            child_failure_at: None,
            last_now: None,
            next_generation: 1,
            next_endpoint: 1,
            next_reservation: 1,
            last_failure: None,
        }
    }
    pub const fn state(&self) -> ConnectionState {
        self.state
    }

    /// Binds the exact registry/connector correlation expected to echo in the
    /// CONNECTED reply. No later CONNECTED may substitute a merely newer tuple.
    pub fn begin_connect(&mut self, expected: ConnectRequest) -> Result<(), ModelError> {
        if self.state == ConnectionState::Exhausted {
            return Err(ModelError::RestartExhausted);
        }
        if self.state != ConnectionState::Reconnecting || self.pending_connect.is_some() {
            return Err(ModelError::WrongConnectionState);
        }
        if !expected.valid() {
            return Err(ModelError::ZeroCorrelation);
        }
        self.pending_connect = Some(expected);
        Ok(())
    }

    pub fn abort_connect(&mut self, request: ConnectRequest) -> Result<(), ModelError> {
        if self.state != ConnectionState::Reconnecting || self.pending_connect != Some(request) {
            return Err(ModelError::StaleCorrelation);
        }
        self.pending_connect = None;
        Ok(())
    }

    /// CONNECTED clears the serial reconnect budget only.
    pub fn attach_connected(
        &mut self,
        serial: SerialCorrelation,
        now: u64,
    ) -> Result<u64, ModelError> {
        self.time(now)?;
        if self.state == ConnectionState::Exhausted {
            return Err(ModelError::RestartExhausted);
        }
        if self.state != ConnectionState::Reconnecting || !self.serial_cleanup || !self.child_reaped
        {
            return Err(ModelError::WrongConnectionState);
        }
        let request = self.pending_connect.ok_or(ModelError::StaleCorrelation)?;
        if !serial.connected()
            || !request.matches(serial)
            || self
                .last_serial
                .map(|previous| !serial.valid_transition_from(previous))
                .unwrap_or(false)
        {
            return Err(ModelError::StaleCorrelation);
        }
        let console = self.allocate_generation()?;
        self.serial = Some(serial);
        self.last_serial = Some(serial);
        self.pending_connect = None;
        self.console_generation = Some(console);
        self.state = ConnectionState::Active;
        self.serial_window.clear();
        self.clear_volatile();
        Ok(console)
    }

    pub fn begin_child_launch(
        &mut self,
        child_launch: u64,
    ) -> Result<LaunchTransaction, ModelError> {
        if self.state == ConnectionState::Exhausted {
            return Err(ModelError::RestartExhausted);
        }
        if self.state != ConnectionState::Active || self.serial.is_none() || self.child.is_some() {
            return Err(ModelError::WrongConnectionState);
        }
        if self.pending_launch.is_some() {
            return Err(ModelError::WrongConnectionState);
        }
        if child_launch == 0 {
            return Err(ModelError::ZeroCorrelation);
        }
        let child_generation = self.allocate_generation()?;
        let transaction = LaunchTransaction {
            serial: self.serial.ok_or(ModelError::WrongConnectionState)?,
            console_generation: self
                .console_generation
                .ok_or(ModelError::WrongConnectionState)?,
            child_generation,
            child_job: 0,
            child_launch,
            consoled: [
                self.allocate_endpoint()?,
                self.allocate_endpoint()?,
                self.allocate_endpoint()?,
            ],
            child_peers: [
                self.allocate_endpoint()?,
                self.allocate_endpoint()?,
                self.allocate_endpoint()?,
            ],
            moved: [false; 3],
            committed: false,
        };
        self.pending_launch = Some(LaunchIdentity {
            serial: transaction.serial,
            console_generation: transaction.console_generation,
            child_generation: transaction.child_generation,
            child_launch: transaction.child_launch,
        });
        Ok(transaction)
    }

    pub fn commit_child_launch(
        &mut self,
        tx: &mut LaunchTransaction,
        child_job: u64,
    ) -> Result<ChildSession, ModelError> {
        if self.state == ConnectionState::Exhausted {
            return Err(ModelError::RestartExhausted);
        }
        if self.state != ConnectionState::Active
            || tx.committed
            || !tx.all_moved()
            || self.child.is_some()
            || self.serial != Some(tx.serial)
            || self.console_generation != Some(tx.console_generation)
            || child_job == 0
            || self.pending_launch
                != Some(LaunchIdentity {
                    serial: tx.serial,
                    console_generation: tx.console_generation,
                    child_generation: tx.child_generation,
                    child_launch: tx.child_launch,
                })
        {
            return Err(ModelError::StaleCorrelation);
        }
        tx.child_job = child_job;
        let ids = SessionIds {
            serial: tx.serial,
            console_generation: tx.console_generation,
            child_generation: tx.child_generation,
            child_job: tx.child_job,
            child_launch: tx.child_launch,
        };
        let child = ChildSession {
            ids,
            peers: [
                PeerState {
                    endpoint: tx.consoled[0],
                    live: true,
                },
                PeerState {
                    endpoint: tx.consoled[1],
                    live: true,
                },
                PeerState {
                    endpoint: tx.consoled[2],
                    live: true,
                },
            ],
        };
        tx.committed = true;
        self.child = Some(child);
        self.pending_launch = None;
        self.stable = None;
        Ok(child)
    }

    pub fn abort_child_launch(
        &mut self,
        transaction: LaunchTransaction,
    ) -> Result<LaunchCleanupToken, ModelError> {
        let identity = LaunchIdentity {
            serial: transaction.serial,
            console_generation: transaction.console_generation,
            child_generation: transaction.child_generation,
            child_launch: transaction.child_launch,
        };
        if self.state != ConnectionState::Active
            || self.child.is_some()
            || self.serial != Some(identity.serial)
            || self.console_generation != Some(identity.console_generation)
            || self.pending_launch != Some(identity)
        {
            return Err(ModelError::StaleCorrelation);
        }
        let cleanup = transaction.abort_cleanup()?;
        Ok(LaunchCleanupToken { identity, cleanup })
    }
    pub fn complete_abort_child_launch(
        &mut self,
        token: LaunchCleanupToken,
    ) -> Result<LaunchCleanup, ModelError> {
        if self.state != ConnectionState::Active || self.pending_launch != Some(token.identity) {
            return Err(ModelError::StaleCorrelation);
        }
        self.pending_launch = None;
        Ok(token.cleanup)
    }

    pub fn event_is_current(&self, event: EventGeneration) -> bool {
        self.state == ConnectionState::Active
            && self.child.map(|value| EventGeneration::from(value.ids)) == Some(event)
    }
    pub fn stage_serial_input(
        &mut self,
        event: EventGeneration,
        bytes: &[u8],
    ) -> Result<(), ModelError> {
        self.require_current(event)?;
        self.input_normalizer.stage(bytes, &mut self.input)
    }
    pub fn stage_child_output(
        &mut self,
        event: EventGeneration,
        source: OutputSource,
        bytes: &[u8],
    ) -> Result<(), ModelError> {
        self.require_current(event)?;
        match source {
            OutputSource::Stdout => self.stdout_normalizer.stage(bytes, &mut self.stdout),
            OutputSource::Stderr => self.stderr_normalizer.stage(bytes, &mut self.stderr),
        }
    }

    pub fn wrong_direction_data(
        &mut self,
        event: EventGeneration,
        now: u64,
    ) -> Result<RecoveryAction, ModelError> {
        self.time(now)?;
        self.require_current(event)?;
        self.last_failure = Some(ModelError::WrongDirection);
        self.start_child_retirement(false, true, now)
    }
    pub fn child_peer_closed(
        &mut self,
        event: EventGeneration,
        kind: StreamKind,
        now: u64,
    ) -> Result<RecoveryAction, ModelError> {
        self.time(now)?;
        self.require_current(event)?;
        self.mark_child_peer_closed(event, kind)?;
        self.start_child_retirement(false, true, now)
    }
    /// Cleanup evidence is accepted while a child is retiring, but remains
    /// bound to the exact child session rather than treated as fresh DATA.
    pub fn observe_child_peer_closed(
        &mut self,
        event: EventGeneration,
        kind: StreamKind,
        now: u64,
    ) -> Result<(), ModelError> {
        self.time(now)?;
        if !matches!(
            self.state,
            ConnectionState::RetiringChild | ConnectionState::AwaitingReap
        ) {
            return Err(ModelError::WrongConnectionState);
        }
        self.mark_child_peer_closed(event, kind)
    }
    /// Confirms local closure of the complete retained stream triple during
    /// teardown, before the JobV2 reap may be accepted.
    pub fn child_streams_closed(
        &mut self,
        event: EventGeneration,
        now: u64,
    ) -> Result<(), ModelError> {
        self.time(now)?;
        if !matches!(
            self.state,
            ConnectionState::RetiringChild | ConnectionState::AwaitingReap
        ) {
            return Err(ModelError::WrongConnectionState);
        }
        self.mark_child_peer_closed(event, StreamKind::Stdin)?;
        self.mark_child_peer_closed(event, StreamKind::Stdout)?;
        self.mark_child_peer_closed(event, StreamKind::Stderr)
    }
    /// A raw close consumes no restart budget. Reconnect failure does.
    pub fn serial_peer_closed(
        &mut self,
        serial: SerialCorrelation,
        console_generation: u64,
        now: u64,
    ) -> Result<RecoveryAction, ModelError> {
        self.time(now)?;
        if self.state != ConnectionState::Active
            || self.serial != Some(serial)
            || self.console_generation != Some(console_generation)
        {
            return Err(ModelError::WrongConnectionState);
        }
        self.serial_cleanup = false;
        self.stable = None;
        self.clear_reservations();
        if self.child.is_some() {
            self.start_child_retirement(true, false, now)
        } else {
            self.child_terminated = true;
            self.child_reaped = true;
            self.finish_serial_cleanup(now)
        }
    }
    pub fn child_terminated(
        &mut self,
        event: EventGeneration,
        now: u64,
    ) -> Result<RecoveryAction, ModelError> {
        self.time(now)?;
        if self.state != ConnectionState::RetiringChild || !self.event_matches_child(event) {
            return Err(ModelError::WrongConnectionState);
        }
        self.child_terminated = true;
        self.state = ConnectionState::AwaitingReap;
        Ok(RecoveryAction::ReapChild(
            self.child.map(|value| value.ids.child_job).unwrap_or(0),
        ))
    }
    pub fn child_reaped(
        &mut self,
        event: EventGeneration,
        now: u64,
    ) -> Result<RecoveryAction, ModelError> {
        self.time(now)?;
        if self.state != ConnectionState::AwaitingReap
            || !self.child_terminated
            || !self.event_matches_child(event)
        {
            return Err(ModelError::WrongConnectionState);
        }
        self.child_reaped = true;
        self.complete_retirement(now)
    }
    pub fn complete_serial_cleanup(
        &mut self,
        serial: SerialCorrelation,
        console_generation: u64,
        now: u64,
    ) -> Result<RecoveryAction, ModelError> {
        self.time(now)?;
        if self.state != ConnectionState::AwaitingReap
            || self.serial_cleanup
            || !self.child_reaped
            || self.serial != Some(serial)
            || self.console_generation != Some(console_generation)
        {
            return Err(ModelError::WrongConnectionState);
        }
        if self
            .child
            .map(|value| value.peers[0].live || value.peers[1].live || value.peers[2].live)
            .unwrap_or(false)
        {
            return Err(ModelError::IncompleteCleanup);
        }
        self.child = None;
        self.finish_serial_cleanup(now)
    }
    pub fn serial_reconnect_failed(&mut self, now: u64) -> Result<RecoveryAction, ModelError> {
        self.time(now)?;
        if self.state != ConnectionState::Reconnecting {
            return Err(ModelError::WrongConnectionState);
        }
        // Covers both a failed reserved connector attempt and an earlier
        // registry lookup/watch failure where no request existed yet.
        self.pending_connect = None;
        if self.serial_window.add(now) {
            self.state = ConnectionState::Exhausted;
            self.last_failure = Some(ModelError::RestartExhausted);
            return Ok(RecoveryAction::Escalate);
        }
        let retry = now
            .checked_add(SERIAL_RETRY_BACKOFF_MILLIS)
            .ok_or_else(|| self.fail(ModelError::ArithmeticOverflow))?;
        Ok(RecoveryAction::RetrySerialAt(retry))
    }

    pub fn reserve_child_stdin(
        &mut self,
        output: &mut [u8],
    ) -> Result<Option<Reservation>, ModelError> {
        if output.is_empty() {
            return Ok(None);
        }
        let event = self.live_event()?;
        if self.pending_stdin.is_some() {
            return Err(ModelError::AlreadyReserved);
        }
        if self.input.is_empty() {
            return Ok(None);
        }
        let length = self.input.copy_prefix(output, FAIR_SOURCE_BYTES_PER_TURN);
        let reservation = Reservation {
            token: self.allocate_reservation()?,
            source: None,
            length,
            event,
        };
        self.pending_stdin = Some(reservation);
        Ok(Some(reservation))
    }
    pub fn commit_child_stdin(&mut self, reservation: Reservation) -> Result<(), ModelError> {
        if self.pending_stdin != Some(reservation) || self.live_event()? != reservation.event {
            return Err(ModelError::UnknownReservation);
        }
        self.input.consume(reservation.length);
        self.pending_stdin = None;
        Ok(())
    }
    pub fn release_child_stdin(&mut self, reservation: Reservation) -> Result<(), ModelError> {
        if self.pending_stdin != Some(reservation) || self.live_event()? != reservation.event {
            return Err(ModelError::UnknownReservation);
        }
        self.pending_stdin = None;
        Ok(())
    }
    /// WOULD_BLOCK callers release this reservation; no byte or turn is lost.
    pub fn reserve_serial_tx(
        &mut self,
        output: &mut [u8],
    ) -> Result<Option<Reservation>, ModelError> {
        if output.is_empty() {
            return Ok(None);
        }
        let event = self.live_event()?;
        if self.pending_tx.is_some() {
            return Err(ModelError::AlreadyReserved);
        }
        let first = self.next_output;
        let source = if self.queue_for(first).is_empty() {
            other(first)
        } else {
            first
        };
        if self.queue_for(source).is_empty() {
            return Ok(None);
        }
        let length = self
            .queue_for(source)
            .copy_prefix(output, FAIR_SOURCE_BYTES_PER_TURN);
        let reservation = Reservation {
            token: self.allocate_reservation()?,
            source: Some(source),
            length,
            event,
        };
        self.pending_tx = Some(reservation);
        Ok(Some(reservation))
    }
    pub fn commit_serial_tx(&mut self, reservation: Reservation) -> Result<(), ModelError> {
        if self.pending_tx != Some(reservation) || self.live_event()? != reservation.event {
            return Err(ModelError::UnknownReservation);
        }
        let source = reservation.source.ok_or(ModelError::UnknownReservation)?;
        self.queue_for_mut(source).consume(reservation.length);
        self.next_output = other(source);
        self.pending_tx = None;
        Ok(())
    }
    pub fn release_serial_tx(&mut self, reservation: Reservation) -> Result<(), ModelError> {
        if self.pending_tx != Some(reservation) || self.live_event()? != reservation.event {
            return Err(ModelError::UnknownReservation);
        }
        self.pending_tx = None;
        Ok(())
    }

    pub fn ready_token(&self) -> Option<ReadyToken> {
        let child = self.child?;
        if self.state != ConnectionState::Active
            || !child.ids.complete()
            || !child.all_peers_live()
            || self.ready_observed != Some(EventGeneration::from(child.ids))
        {
            return None;
        }
        Some(ReadyToken {
            ids: child.ids,
            peers: [
                child.peers[0].endpoint,
                child.peers[1].endpoint,
                child.peers[2].endpoint,
            ],
        })
    }
    /// Exact child READY begins a stable interval; stale READY cannot alter a
    /// newer session's token or restart budget.
    pub fn observe_child_ready(
        &mut self,
        event: EventGeneration,
        now: u64,
    ) -> Result<ReadyToken, ModelError> {
        self.time(now)?;
        if !self.event_is_current(event) {
            return Err(ModelError::StaleCorrelation);
        }
        self.ready_observed = Some(event);
        let token = self.ready_token().ok_or(ModelError::WrongConnectionState)?;
        self.stable = Some((token, now));
        Ok(token)
    }
    /// Exact READY identity clears only child failures after 60 continuous seconds.
    pub fn observe_ready(&mut self, now: u64, token: ReadyToken) -> Result<bool, ModelError> {
        self.time(now)?;
        if self.ready_token() != Some(token) {
            return Err(ModelError::StaleCorrelation);
        }
        match self.stable {
            Some((old, since)) if old == token => {
                if now - since < STABLE_RUN_MILLIS {
                    Ok(false)
                } else {
                    self.child_window.clear();
                    self.stable = Some((token, now));
                    Ok(true)
                }
            }
            _ => {
                self.stable = Some((token, now));
                Ok(false)
            }
        }
    }
    pub fn snapshot(&self) -> ConsoleSnapshot {
        let child = self.child;
        ConsoleSnapshot {
            state: self.state,
            serial: self.serial,
            console_generation: self.console_generation,
            child_generation: child.map(|value| value.ids.child_generation),
            child_job: child.map(|value| value.ids.child_job),
            child_launch: child.map(|value| value.ids.child_launch),
            peers_live: child
                .map(|value| {
                    [
                        value.peers[0].live,
                        value.peers[1].live,
                        value.peers[2].live,
                    ]
                })
                .unwrap_or([false; 3]),
            input_queued: self.input.len(),
            stdout_queued: self.stdout.len(),
            stderr_queued: self.stderr.len(),
            child_failures: self.child_window.failures(),
            serial_failures: self.serial_window.failures(),
            last_failure: self.last_failure,
        }
    }

    fn require_current(&mut self, event: EventGeneration) -> Result<(), ModelError> {
        if self.event_is_current(event) {
            Ok(())
        } else {
            self.last_failure = Some(ModelError::StaleCorrelation);
            Err(ModelError::StaleCorrelation)
        }
    }
    fn event_matches_child(&self, event: EventGeneration) -> bool {
        self.child.map(|value| EventGeneration::from(value.ids)) == Some(event)
    }
    fn live_event(&self) -> Result<EventGeneration, ModelError> {
        let child = self.child.ok_or(ModelError::NoChild)?;
        let event = EventGeneration::from(child.ids);
        if self.state != ConnectionState::Active || !child.all_peers_live() {
            return Err(ModelError::WrongConnectionState);
        }
        Ok(event)
    }
    fn mark_child_peer_closed(
        &mut self,
        event: EventGeneration,
        kind: StreamKind,
    ) -> Result<(), ModelError> {
        if self.child.map(|value| EventGeneration::from(value.ids)) != Some(event) {
            return Err(ModelError::StaleCorrelation);
        }
        let mut child = self.child.ok_or(ModelError::NoChild)?;
        child.peers[kind.index()].live = false;
        self.child = Some(child);
        Ok(())
    }
    fn start_child_retirement(
        &mut self,
        serial_cleanup: bool,
        capture_child_failure: bool,
        now: u64,
    ) -> Result<RecoveryAction, ModelError> {
        self.clear_volatile();
        self.child_terminated = false;
        self.child_reaped = false;
        if capture_child_failure && self.child_failure_at.is_none() {
            self.child_failure_at = Some(now);
        }
        if serial_cleanup {
            self.serial_cleanup = false;
        }
        self.state = ConnectionState::RetiringChild;
        Ok(RecoveryAction::TerminateChild(
            self.child.map(|value| value.ids.child_job).unwrap_or(0),
        ))
    }
    fn complete_retirement(&mut self, now: u64) -> Result<RecoveryAction, ModelError> {
        let child = self.child.ok_or(ModelError::NoChild)?;
        if child.peers[0].live || child.peers[1].live || child.peers[2].live {
            return Err(ModelError::IncompleteCleanup);
        }
        if !self.serial_cleanup {
            return Ok(RecoveryAction::None);
        }
        self.child = None;
        self.clear_volatile();
        let failure_at = self.child_failure_at.take().unwrap_or(now);
        if self.child_window.add(failure_at) {
            self.state = ConnectionState::Exhausted;
            self.last_failure = Some(ModelError::RestartExhausted);
            Ok(RecoveryAction::Escalate)
        } else {
            self.state = ConnectionState::Active;
            Ok(RecoveryAction::ReplaceChild)
        }
    }
    fn finish_serial_cleanup(&mut self, now: u64) -> Result<RecoveryAction, ModelError> {
        let retry = now
            .checked_add(SERIAL_RETRY_BACKOFF_MILLIS)
            .ok_or_else(|| self.fail(ModelError::ArithmeticOverflow))?;
        self.serial = None;
        self.console_generation = None;
        self.serial_cleanup = true;
        self.state = ConnectionState::Reconnecting;
        self.clear_volatile();
        Ok(RecoveryAction::RetrySerialAt(retry))
    }
    fn clear_volatile(&mut self) {
        self.input.clear();
        self.stdout.clear();
        self.stderr.clear();
        self.input_normalizer.reset();
        self.stdout_normalizer.reset();
        self.stderr_normalizer.reset();
        self.next_output = OutputSource::Stdout;
        self.clear_reservations();
        self.stable = None;
        self.ready_observed = None;
    }
    fn clear_reservations(&mut self) {
        self.pending_stdin = None;
        self.pending_tx = None;
    }
    fn queue_for(&self, source: OutputSource) -> &BoundedQueue {
        match source {
            OutputSource::Stdout => &self.stdout,
            OutputSource::Stderr => &self.stderr,
        }
    }
    fn queue_for_mut(&mut self, source: OutputSource) -> &mut BoundedQueue {
        match source {
            OutputSource::Stdout => &mut self.stdout,
            OutputSource::Stderr => &mut self.stderr,
        }
    }
    fn allocate_generation(&mut self) -> Result<u64, ModelError> {
        let value = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or_else(|| self.fail(ModelError::ArithmeticOverflow))?;
        Ok(value)
    }
    fn allocate_endpoint(&mut self) -> Result<Endpoint, ModelError> {
        let value = self.next_endpoint;
        self.next_endpoint = self
            .next_endpoint
            .checked_add(1)
            .ok_or_else(|| self.fail(ModelError::ArithmeticOverflow))?;
        Ok(Endpoint(value))
    }
    fn allocate_reservation(&mut self) -> Result<u64, ModelError> {
        let value = self.next_reservation;
        self.next_reservation = self
            .next_reservation
            .checked_add(1)
            .ok_or_else(|| self.fail(ModelError::ArithmeticOverflow))?;
        Ok(value)
    }
    fn time(&mut self, now: u64) -> Result<(), ModelError> {
        if self
            .last_now
            .map(|previous| now < previous)
            .unwrap_or(false)
        {
            self.fail(ModelError::MonotonicRegression);
            return Err(ModelError::MonotonicRegression);
        }
        self.last_now = Some(now);
        Ok(())
    }
    fn fail(&mut self, error: ModelError) -> ModelError {
        self.state = ConnectionState::FailClosed;
        self.last_failure = Some(error);
        self.stable = None;
        error
    }
}

const fn other(source: OutputSource) -> OutputSource {
    match source {
        OutputSource::Stdout => OutputSource::Stderr,
        OutputSource::Stderr => OutputSource::Stdout,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn correlation(value: u64) -> SerialCorrelation {
        SerialCorrelation {
            registry_generation: 1,
            registry_endpoint_id: 1,
            registry_endpoint_generation: 1,
            publication_generation: value,
            connector_client_transaction: value,
            device_role: 1,
            device_bundle: value,
            driver_attempt: value,
            driver_control_endpoint_id: value,
            driver_control_endpoint_generation: value,
            attach_transaction: value,
            stream_generation: value,
        }
    }
    fn connect(model: &mut ConsoleModel, value: u64, now: u64) {
        let serial = correlation(value);
        model
            .begin_connect(ConnectRequest {
                registry_generation: serial.registry_generation,
                registry_endpoint_id: serial.registry_endpoint_id,
                registry_endpoint_generation: serial.registry_endpoint_generation,
                requested_publication_generation: serial.publication_generation,
                connector_client_transaction: serial.connector_client_transaction,
            })
            .unwrap();
        model.attach_connected(serial, now).unwrap();
    }
    fn close_serial(model: &mut ConsoleModel, now: u64) -> RecoveryAction {
        let snapshot = model.snapshot();
        model
            .serial_peer_closed(
                snapshot.serial.unwrap(),
                snapshot.console_generation.unwrap(),
                now,
            )
            .unwrap()
    }
    fn launch(model: &mut ConsoleModel) -> EventGeneration {
        let mut tx = model.begin_child_launch(100).unwrap();
        for kind in [StreamKind::Stdin, StreamKind::Stdout, StreamKind::Stderr] {
            tx.move_child_peer(kind).unwrap();
        }
        model.commit_child_launch(&mut tx, 200).unwrap().ids.into()
    }
    fn live() -> (ConsoleModel, EventGeneration) {
        let mut model = ConsoleModel::new();
        connect(&mut model, 1, 0);
        let event = launch(&mut model);
        (model, event)
    }

    #[test]
    fn cross_record_input_and_independent_output_transform() {
        let (mut model, event) = live();
        model.stage_serial_input(event, b"a\r").unwrap();
        model.stage_serial_input(event, b"\nb\rc").unwrap();
        let mut input = [0; 8];
        let r = model.reserve_child_stdin(&mut input).unwrap().unwrap();
        assert_eq!(&input[..r.length()], b"a\nb\nc");
        model.commit_child_stdin(r).unwrap();
        model
            .stage_child_output(event, OutputSource::Stdout, b"o\r")
            .unwrap();
        model
            .stage_child_output(event, OutputSource::Stderr, b"e\n")
            .unwrap();
        model
            .stage_child_output(event, OutputSource::Stdout, b"\n")
            .unwrap();
        let mut output = [0; 8];
        let r = model.reserve_serial_tx(&mut output).unwrap().unwrap();
        assert_eq!(&output[..r.length()], b"o\r\n");
        model.commit_serial_tx(r).unwrap();
        let r = model.reserve_serial_tx(&mut output).unwrap().unwrap();
        assert_eq!(&output[..r.length()], b"e\r\n");
    }
    #[test]
    fn launch_binds_caller_supplied_transaction_and_accepted_job() {
        let mut model = ConsoleModel::new();
        connect(&mut model, 1, 0);
        let mut transaction = model.begin_child_launch(91).unwrap();
        for kind in [StreamKind::Stdin, StreamKind::Stdout, StreamKind::Stderr] {
            transaction.move_child_peer(kind).unwrap();
        }
        let child = model.commit_child_launch(&mut transaction, 92).unwrap();
        assert_eq!(child.ids.child_launch, 91);
        assert_eq!(child.ids.child_job, 92);
    }
    #[test]
    fn exact_preflight_admits_normalized_one_byte_when_one_slot_remains() {
        let (mut model, event) = live();
        model.input.push(&[b'x'; STAGING_CAPACITY - 1]);
        model.stage_serial_input(event, b"\r").unwrap();
        assert_eq!(model.input.len(), STAGING_CAPACITY);
        model.input.clear();
        model.stdout.push(&[b'x'; STAGING_CAPACITY - 1]);
        model
            .stage_child_output(event, OutputSource::Stdout, b"x")
            .unwrap();
        assert_eq!(model.stdout.len(), STAGING_CAPACITY);
    }
    #[test]
    fn backpressure_never_partially_transforms() {
        let (mut model, event) = live();
        model.stdout.push(&[b'x'; STAGING_CAPACITY - 1]);
        let before = model.stdout.len();
        assert_eq!(
            model.stage_child_output(event, OutputSource::Stdout, b"\n"),
            Err(ModelError::Backpressure)
        );
        assert_eq!(model.stdout.len(), before);
        assert_eq!(
            model.stage_serial_input(event, &[b'x'; 1025]),
            Err(ModelError::TooLarge)
        );
    }
    #[test]
    fn would_block_reservations_preserve_bytes_and_fair_turn() {
        let (mut model, event) = live();
        model.stage_serial_input(event, b"in").unwrap();
        let mut bytes = [0; 8];
        let stdin = model.reserve_child_stdin(&mut bytes).unwrap().unwrap();
        model.release_child_stdin(stdin).unwrap();
        let again = model.reserve_child_stdin(&mut bytes).unwrap().unwrap();
        assert_eq!(&bytes[..again.length()], b"in");
        model.commit_child_stdin(again).unwrap();
        model
            .stage_child_output(event, OutputSource::Stdout, b"out")
            .unwrap();
        model
            .stage_child_output(event, OutputSource::Stderr, b"err")
            .unwrap();
        let tx = model.reserve_serial_tx(&mut bytes).unwrap().unwrap();
        assert_eq!(tx.output_source(), Some(OutputSource::Stdout));
        model.release_serial_tx(tx).unwrap();
        let same = model.reserve_serial_tx(&mut bytes).unwrap().unwrap();
        assert_eq!(same.output_source(), Some(OutputSource::Stdout));
        model.commit_serial_tx(same).unwrap();
        assert_eq!(
            model
                .reserve_serial_tx(&mut bytes)
                .unwrap()
                .unwrap()
                .output_source(),
            Some(OutputSource::Stderr)
        );
    }
    #[test]
    fn partial_move_cleanup_accounts_for_exactly_six_unique_endpoints() {
        let mut model = ConsoleModel::new();
        connect(&mut model, 1, 0);
        let mut tx = model.begin_child_launch(101).unwrap();
        tx.move_child_peer(StreamKind::Stdin).unwrap();
        let token = model.abort_child_launch(tx).unwrap();
        let cleanup = token.cleanup();
        let mut index = 0;
        while index < 6 {
            let mut other = index + 1;
            while other < 6 {
                assert_ne!(
                    cleanup.entries[index].endpoint,
                    cleanup.entries[other].endpoint
                );
                other += 1;
            }
            index += 1;
        }
        assert_eq!(
            cleanup.entries[3].disposition,
            CleanupDisposition::RevokeMovedChildPeerFromLaunch
        );
        assert_eq!(
            cleanup.entries[4].disposition,
            CleanupDisposition::CloseUnmovedChildPeer
        );
        assert_eq!(
            model.begin_child_launch(102),
            Err(ModelError::WrongConnectionState)
        );
        let _cleanup = model.complete_abort_child_launch(token).unwrap();
        let retry = model.begin_child_launch(102).unwrap();
        let token = model.abort_child_launch(retry).unwrap();
        assert!(model.complete_abort_child_launch(token).is_ok());
    }
    #[test]
    fn launch_correlation_rejects_drift_before_commit() {
        let mut model = ConsoleModel::new();
        connect(&mut model, 1, 0);
        let mut tx = model.begin_child_launch(102).unwrap();
        for kind in [StreamKind::Stdin, StreamKind::Stdout, StreamKind::Stderr] {
            tx.move_child_peer(kind).unwrap();
        }
        close_serial(&mut model, 1);
        assert_eq!(
            model.commit_child_launch(&mut tx, 202),
            Err(ModelError::StaleCorrelation)
        );
        assert!(tx.abort_cleanup().is_ok());
    }
    #[test]
    fn individual_peer_close_requires_termination_reap_and_all_peer_cleanup() {
        let (mut model, event) = live();
        let job = model.child.unwrap().ids.child_job;
        assert_eq!(
            model.child_peer_closed(event, StreamKind::Stdout, 1),
            Ok(RecoveryAction::TerminateChild(job))
        );
        assert_eq!(
            model.child_terminated(event, 1),
            Ok(RecoveryAction::ReapChild(job))
        );
        assert_eq!(
            model.child_reaped(event, 1),
            Err(ModelError::IncompleteCleanup)
        );
        model.child_streams_closed(event, 1).unwrap();
        assert_eq!(
            model.child_reaped(event, 1),
            Ok(RecoveryAction::ReplaceChild)
        );
        assert_eq!(model.state(), ConnectionState::Active);
    }
    #[test]
    fn wrong_direction_data_is_a_child_failure() {
        let (mut model, event) = live();
        assert!(matches!(
            model.wrong_direction_data(event, 1),
            Ok(RecoveryAction::TerminateChild(_))
        ));
        assert_eq!(
            model.snapshot().last_failure,
            Some(ModelError::WrongDirection)
        );
    }
    #[test]
    fn raw_loss_requires_complete_reap_before_fresh_attach_and_does_not_count() {
        let (mut model, event) = live();
        let serial = model.snapshot().serial.unwrap();
        let console = model.snapshot().console_generation.unwrap();
        close_serial(&mut model, 1);
        model.child_terminated(event, 1).unwrap();
        model.child_streams_closed(event, 1).unwrap();
        model.child_reaped(event, 1).unwrap();
        assert_eq!(model.state(), ConnectionState::AwaitingReap);
        assert_eq!(
            model.attach_connected(correlation(2), 1),
            Err(ModelError::WrongConnectionState)
        );
        assert_eq!(
            model.complete_serial_cleanup(serial, console, 1),
            Ok(RecoveryAction::RetrySerialAt(26))
        );
        assert_eq!(model.snapshot().serial_failures, 0);
        connect(&mut model, 2, 2);
    }
    #[test]
    fn reconnect_failure_budget_exhausts_and_blocks_fifth_attach_or_launch() {
        let mut model = ConsoleModel::new();
        for now in 0..4 {
            let expected = if now == 3 {
                RecoveryAction::Escalate
            } else {
                RecoveryAction::RetrySerialAt(now + 25)
            };
            assert_eq!(model.serial_reconnect_failed(now), Ok(expected));
        }
        assert_eq!(model.state(), ConnectionState::Exhausted);
        assert_eq!(
            model.attach_connected(correlation(1), 5),
            Err(ModelError::RestartExhausted)
        );
        assert_eq!(
            model.begin_child_launch(103),
            Err(ModelError::RestartExhausted)
        );
    }
    #[test]
    fn correlation_is_full_monotonic_and_rejects_a_b_a() {
        let mut model = ConsoleModel::new();
        connect(&mut model, 1, 0);
        close_serial(&mut model, 1);
        connect(&mut model, 2, 2);
        close_serial(&mut model, 3);
        assert_eq!(
            model.attach_connected(correlation(1), 4),
            Err(ModelError::StaleCorrelation)
        );
    }
    #[test]
    fn exact_ready_token_only_clears_child_window_after_sixty_seconds() {
        let (mut model, event) = live();
        model
            .child_peer_closed(event, StreamKind::Stdin, 1)
            .unwrap();
        model.child_terminated(event, 1).unwrap();
        model.child_streams_closed(event, 1).unwrap();
        model.child_reaped(event, 1).unwrap();
        let event = launch(&mut model);
        let token = model.observe_child_ready(event, 2).unwrap();
        assert!(!model.observe_ready(60_001, token).unwrap());
        assert!(model.observe_ready(60_002, token).unwrap());
        model
            .child_peer_closed(event, StreamKind::Stdin, 60_003)
            .unwrap();
        assert_eq!(
            model.observe_ready(60_004, token),
            Err(ModelError::StaleCorrelation)
        );
    }
    #[test]
    fn global_time_regression_fails_closed_before_state_mutation() {
        let (mut model, event) = live();
        model.stage_serial_input(event, b"x").unwrap();
        model
            .child_peer_closed(event, StreamKind::Stdin, 10)
            .unwrap();
        let before = model.snapshot();
        assert_eq!(
            model.child_terminated(event, 9),
            Err(ModelError::MonotonicRegression)
        );
        assert_eq!(model.state(), ConnectionState::FailClosed);
        assert_eq!(model.snapshot().input_queued, before.input_queued);
    }
    #[test]
    fn empty_transport_buffers_do_not_reserve_or_rotate_fairness() {
        let (mut model, event) = live();
        model
            .stage_child_output(event, OutputSource::Stdout, b"a")
            .unwrap();
        model
            .stage_child_output(event, OutputSource::Stderr, b"b")
            .unwrap();
        assert_eq!(model.reserve_serial_tx(&mut []), Ok(None));
        let mut bytes = [0; 8];
        assert_eq!(
            model
                .reserve_serial_tx(&mut bytes)
                .unwrap()
                .unwrap()
                .output_source(),
            Some(OutputSource::Stdout)
        );
        assert_eq!(model.reserve_child_stdin(&mut []), Ok(None));
    }
    #[test]
    fn failed_connect_attempt_releases_pending_request_for_retry() {
        let mut model = ConsoleModel::new();
        let request = ConnectRequest {
            registry_generation: 1,
            registry_endpoint_id: 1,
            registry_endpoint_generation: 1,
            requested_publication_generation: 1,
            connector_client_transaction: 1,
        };
        model.begin_connect(request).unwrap();
        assert_eq!(
            model.serial_reconnect_failed(0),
            Ok(RecoveryAction::RetrySerialAt(25))
        );
        let retry = ConnectRequest {
            connector_client_transaction: 2,
            ..request
        };
        model.begin_connect(retry).unwrap();
        model.abort_connect(retry).unwrap();
    }
    #[test]
    fn ready_requires_exact_ready_event_and_stale_ready_preserves_new_proof() {
        let (mut model, event) = live();
        assert_eq!(model.ready_token(), None);
        let token = model.observe_child_ready(event, 1).unwrap();
        assert_eq!(
            model.observe_child_ready(
                EventGeneration {
                    child_generation: event.child_generation + 1,
                    ..event
                },
                2
            ),
            Err(ModelError::StaleCorrelation)
        );
        assert!(!model.observe_ready(2, token).unwrap());
    }
}
