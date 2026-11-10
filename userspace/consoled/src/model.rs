//! The console model: bounded queues, input and output normalization, the restart window and the console state machine.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BoundedQueue {
    pub(crate) bytes: [u8; STAGING_CAPACITY],
    pub(crate) head: usize,
    pub(crate) len: usize,
}

impl BoundedQueue {
    pub(crate) const fn new() -> Self {
        Self {
            bytes: [0; STAGING_CAPACITY],
            head: 0,
            len: 0,
        }
    }
    pub(crate) const fn len(&self) -> usize {
        self.len
    }
    pub(crate) const fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub(crate) const fn available(&self) -> usize {
        STAGING_CAPACITY - self.len
    }
    pub(crate) fn push(&mut self, source: &[u8]) {
        let mut index = 0;
        while index < source.len() {
            let tail = (self.head + self.len) % STAGING_CAPACITY;
            self.bytes[tail] = source[index];
            self.len += 1;
            index += 1;
        }
    }
    pub(crate) fn copy_prefix(&self, destination: &mut [u8], maximum: usize) -> usize {
        let count = core::cmp::min(core::cmp::min(destination.len(), maximum), self.len);
        let mut index = 0;
        while index < count {
            destination[index] = self.bytes[(self.head + index) % STAGING_CAPACITY];
            index += 1;
        }
        count
    }
    pub(crate) fn consume(&mut self, count: usize) {
        self.head = (self.head + count) % STAGING_CAPACITY;
        self.len -= count;
    }
    pub(crate) fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct InputNormalizer {
    pub(crate) suppress_lf_after_cr: bool,
}

impl InputNormalizer {
    pub(crate) fn output_len(&self, input: &[u8]) -> usize {
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
    pub(crate) fn stage(
        &mut self,
        input: &[u8],
        queue: &mut BoundedQueue,
    ) -> Result<(), ModelError> {
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
                queue.push(b"\n");
                self.suppress_lf_after_cr = true;
            } else {
                queue.push(&[byte]);
            }
            index += 1;
        }
        Ok(())
    }
    pub(crate) fn reset(&mut self) {
        self.suppress_lf_after_cr = false;
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct OutputNormalizer {
    pub(crate) previous_was_cr: bool,
}

impl OutputNormalizer {
    pub(crate) fn output_len(&self, input: &[u8]) -> usize {
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
    pub(crate) fn stage(
        &mut self,
        input: &[u8],
        queue: &mut BoundedQueue,
    ) -> Result<(), ModelError> {
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
                queue.push(b"\r");
            }
            queue.push(&[byte]);
            self.previous_was_cr = byte == b'\r';
            index += 1;
        }
        Ok(())
    }
    pub(crate) fn reset(&mut self) {
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
pub(crate) struct RestartWindow {
    pub(crate) times: [u64; MAX_FAILURES_PER_WINDOW],
    pub(crate) len: usize,
}

impl RestartWindow {
    pub(crate) const fn new() -> Self {
        Self {
            times: [0; MAX_FAILURES_PER_WINDOW],
            len: 0,
        }
    }
    pub(crate) const fn failures(&self) -> usize {
        self.len
    }
    pub(crate) fn add(&mut self, now: u64) -> bool {
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
    pub(crate) fn clear(&mut self) {
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
    pub(crate) token: u64,
    pub(crate) source: Option<OutputSource>,
    pub(crate) length: usize,
    pub(crate) event: EventGeneration,
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
    pub serial_invalidated: bool,
    pub pending_launch: bool,
    pub pending_launch_cleanup: bool,
    pub pending_connect: bool,
    pub pending_stdin_reservation: bool,
    pub pending_tx_reservation: bool,
    pub child_restart_exhausted: bool,
    pub serial_restart_exhausted: bool,
    pub last_failure: Option<ModelError>,
    pub pending_recovery: Option<RecoveryAction>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ConsoleModel {
    pub(crate) state: ConnectionState,
    pub(crate) serial: Option<SerialCorrelation>,
    pub(crate) last_serial: Option<SerialCorrelation>,
    pub(crate) console_generation: Option<u64>,
    pub(crate) child: Option<ChildSession>,
    pub(crate) input: BoundedQueue,
    pub(crate) stdout: BoundedQueue,
    pub(crate) stderr: BoundedQueue,
    pub(crate) input_normalizer: InputNormalizer,
    pub(crate) stdout_normalizer: OutputNormalizer,
    pub(crate) stderr_normalizer: OutputNormalizer,
    pub(crate) next_output: OutputSource,
    pub(crate) pending_stdin: Option<Reservation>,
    pub(crate) pending_tx: Option<Reservation>,
    pub(crate) pending_launch: Option<LaunchIdentity>,
    pub(crate) pending_launch_cleanup: Option<LaunchIdentity>,
    pub(crate) pending_connect: Option<ConnectRequest>,
    pub(crate) child_window: RestartWindow,
    pub(crate) serial_window: RestartWindow,
    pub(crate) stable: Option<(ReadyToken, u64)>,
    pub(crate) ready_observed: Option<EventGeneration>,
    pub(crate) serial_cleanup: bool,
    pub(crate) serial_invalidated: bool,
    pub(crate) child_exhausted: bool,
    pub(crate) serial_exhausted: bool,
    pub(crate) child_terminated: bool,
    pub(crate) child_reaped: bool,
    pub(crate) child_failure_at: Option<u64>,
    pub(crate) last_now: Option<u64>,
    pub(crate) next_generation: u64,
    pub(crate) next_endpoint: u64,
    pub(crate) next_reservation: u64,
    pub(crate) last_failure: Option<ModelError>,
    pub(crate) pending_recovery: Option<RecoveryAction>,
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
            pending_launch_cleanup: None,
            pending_connect: None,
            child_window: RestartWindow::new(),
            serial_window: RestartWindow::new(),
            stable: None,
            ready_observed: None,
            serial_cleanup: true,
            serial_invalidated: false,
            child_exhausted: false,
            serial_exhausted: false,
            child_terminated: true,
            child_reaped: true,
            child_failure_at: None,
            last_now: None,
            next_generation: 1,
            next_endpoint: 1,
            next_reservation: 1,
            last_failure: None,
            pending_recovery: None,
        }
    }
    pub const fn state(&self) -> ConnectionState {
        self.state
    }

    /// Binds the exact registry/connector correlation expected to echo in the
    /// CONNECTED reply. No later CONNECTED may substitute a merely newer tuple.
    pub fn begin_connect(&mut self, expected: ConnectRequest) -> Result<(), ModelError> {
        if self.state == ConnectionState::Exhausted && self.serial_exhausted {
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
        if !matches!(
            self.state,
            ConnectionState::Reconnecting | ConnectionState::FailClosed
        ) || self.pending_connect != Some(request)
        {
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
        if self.state == ConnectionState::Exhausted && self.serial_exhausted {
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
        self.input_normalizer.reset();
        Ok(console)
    }

    pub fn begin_child_launch(
        &mut self,
        child_launch: u64,
    ) -> Result<LaunchTransaction, ModelError> {
        if self.state == ConnectionState::Exhausted || self.child_exhausted {
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
        if self.state == ConnectionState::Exhausted || self.child_exhausted {
            return Err(ModelError::RestartExhausted);
        }
        if self.state != ConnectionState::Active
            || tx.committed
            || !tx.all_moved()
            || self.child.is_some()
            || self.serial_invalidated
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
        if !matches!(
            self.state,
            ConnectionState::Active | ConnectionState::FailClosed
        ) || self.child.is_some()
            || self.serial != Some(identity.serial)
            || self.console_generation != Some(identity.console_generation)
            || self.pending_launch != Some(identity)
        {
            return Err(ModelError::StaleCorrelation);
        }
        let cleanup = transaction.abort_cleanup()?;
        self.pending_launch_cleanup = Some(identity);
        Ok(LaunchCleanupToken { identity, cleanup })
    }
    pub fn complete_abort_child_launch(
        &mut self,
        token: &LaunchCleanupToken,
        evidence: LaunchCleanupEvidence,
    ) -> Result<LaunchCleanup, ModelError> {
        if self.pending_launch != Some(token.identity)
            || self.pending_launch_cleanup != Some(token.identity)
        {
            return Err(ModelError::StaleCorrelation);
        }
        if !evidence_matches_cleanup(&token.cleanup, evidence) {
            return Err(ModelError::IncompleteCleanup);
        }
        self.pending_launch = None;
        self.pending_launch_cleanup = None;
        let cleanup = token.cleanup;
        self.maybe_finish_serial_invalidation()?;
        Ok(cleanup)
    }

    pub(crate) fn event_is_current(&self, event: EventGeneration) -> bool {
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

    /// Polls each live child output once after staged output has drained.
    /// The adapter returns `None` only for a real WOULD_BLOCK observation;
    /// peer closure and every other read failure remain errors. Data found
    /// during this check enters the ordinary staging/serial commit path.
    ///
    /// R7B-2 note, kept at R7B-3: nothing here is selector-specific. "Have the
    /// queues drained, and does one more read find nothing?" is an ordinary
    /// question about this model, so it is no longer gated on the one caller
    /// that asks it.
    pub fn poll_output_quiescence(
        &mut self,
        event: EventGeneration,
        mut read: impl FnMut(OutputSource, &mut [u8]) -> Result<Option<usize>, ModelError>,
    ) -> Result<bool, ModelError> {
        self.require_current(event)?;
        if !self.input.is_empty()
            || !self.stdout.is_empty()
            || !self.stderr.is_empty()
            || self.pending_stdin.is_some()
            || self.pending_tx.is_some()
        {
            return Ok(false);
        }
        let mut quiet = true;
        let mut payload = [0u8; FAIR_SOURCE_BYTES_PER_TURN];
        for source in [OutputSource::Stdout, OutputSource::Stderr] {
            if let Some(count) = read(source, &mut payload)? {
                if count == 0 || count > payload.len() {
                    return Err(ModelError::TooLarge);
                }
                self.stage_child_output(event, source, &payload[..count])?;
                quiet = false;
            }
        }
        Ok(quiet)
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
    /// A JobV2 terminal notification is an active-child failure even when all
    /// three stream peers remain open; retirement/reap owns the cleanup.
    pub fn child_terminal(
        &mut self,
        event: EventGeneration,
        now: u64,
    ) -> Result<RecoveryAction, ModelError> {
        self.time(now)?;
        self.require_current(event)?;
        self.last_failure = Some(ModelError::ChildDisconnected);
        self.clear_volatile();
        self.child_failure_at = Some(now);
        self.child_terminated = true;
        self.child_reaped = false;
        self.state = ConnectionState::AwaitingReap;
        Ok(RecoveryAction::ReapChild(event.child_job))
    }
    /// Records that a child role closed while its authoritative terminal WAIT
    /// is still pending. The native controller must consume that exact result
    /// and drain committed output before publishing retirement.
    pub fn child_terminal_precursor(
        &mut self,
        event: EventGeneration,
        now: u64,
    ) -> Result<RecoveryAction, ModelError> {
        self.time(now)?;
        self.require_current(event)?;
        Ok(RecoveryAction::None)
    }
    pub fn child_peer_closed(
        &mut self,
        event: EventGeneration,
        kind: StreamKind,
        now: u64,
    ) -> Result<RecoveryAction, ModelError> {
        self.time(now)?;
        self.require_current(event)?;
        self.last_failure = Some(ModelError::ChildDisconnected);
        self.mark_child_peer_closed(event, kind)?;
        self.start_child_retirement(false, true, now)
    }
    pub fn status_peer_closed(
        &mut self,
        event: EventGeneration,
        now: u64,
    ) -> Result<RecoveryAction, ModelError> {
        self.time(now)?;
        self.require_current(event)?;
        self.last_failure = Some(ModelError::ChildDisconnected);
        self.start_child_retirement(false, true, now)
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
        if !matches!(
            self.state,
            ConnectionState::Active
                | ConnectionState::RetiringChild
                | ConnectionState::AwaitingReap
                | ConnectionState::Exhausted
        ) || self.serial != Some(serial)
            || self.console_generation != Some(console_generation)
        {
            return Err(ModelError::WrongConnectionState);
        }
        self.last_failure = Some(ModelError::SerialDisconnected);
        // Once the serial generation is invalidated, its mandatory child
        // replacement dominates any child-only failure observed first in the
        // same retirement. Do not carry that timestamp into the next serial
        // generation's independent child restart window.
        self.child_failure_at = None;
        self.serial_cleanup = false;
        self.serial_invalidated = true;
        self.input_normalizer.reset();
        self.stable = None;
        self.clear_reservations();
        if self.child.is_some() && self.state == ConnectionState::Active {
            self.start_child_retirement(true, false, now)
        } else if self.child.is_none() && self.pending_launch.is_none() {
            self.child_terminated = true;
            self.child_reaped = true;
            self.finish_serial_cleanup(now)
        } else {
            Ok(RecoveryAction::None)
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
            self.serial_exhausted = true;
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
        if self.stable.map(|(existing, _)| existing) != Some(token) {
            self.stable = Some((token, now));
        }
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
            serial_invalidated: self.serial_invalidated,
            pending_launch: self.pending_launch.is_some(),
            pending_launch_cleanup: self.pending_launch_cleanup.is_some(),
            pending_connect: self.pending_connect.is_some(),
            pending_stdin_reservation: self.pending_stdin.is_some(),
            pending_tx_reservation: self.pending_tx.is_some(),
            child_restart_exhausted: self.child_exhausted,
            serial_restart_exhausted: self.serial_exhausted,
            last_failure: self.last_failure,
            pending_recovery: self.pending_recovery,
        }
    }

    pub fn status_snapshot(&self) -> Result<wyrmroot_console_proto::Snapshot, ModelError> {
        use wyrmroot_console_proto::{
            FLAG_CHILD_PRESENT, FLAG_CHILD_RESTART_EXHAUSTED, FLAG_PENDING_LAUNCH,
            FLAG_PENDING_LAUNCH_CLEANUP, FLAG_SERIAL_INVALIDATED, FLAG_SERIAL_PRESENT,
            FLAG_SERIAL_RESTART_EXHAUSTED,
        };

        let snapshot = self.snapshot();
        let mut flags = 0;
        if snapshot.serial.is_some() {
            flags |= FLAG_SERIAL_PRESENT;
        }
        if snapshot.child_generation.is_some() {
            flags |= FLAG_CHILD_PRESENT;
        }
        if snapshot.serial_invalidated {
            flags |= FLAG_SERIAL_INVALIDATED;
        }
        if snapshot.pending_launch {
            flags |= FLAG_PENDING_LAUNCH;
        }
        if snapshot.pending_launch_cleanup {
            flags |= FLAG_PENDING_LAUNCH_CLEANUP;
        }
        if snapshot.child_restart_exhausted {
            flags |= FLAG_CHILD_RESTART_EXHAUSTED;
        }
        if snapshot.serial_restart_exhausted {
            flags |= FLAG_SERIAL_RESTART_EXHAUSTED;
        }
        let serial = snapshot.serial;
        let wire = wyrmroot_console_proto::Snapshot {
            state: status_state(snapshot.state),
            flags,
            serial_registry_generation: serial.map_or(0, |value| value.registry_generation),
            publication_generation: serial.map_or(0, |value| value.publication_generation),
            device_bundle: serial.map_or(0, |value| value.device_bundle),
            driver_attempt: serial.map_or(0, |value| value.driver_attempt),
            raw_stream_generation: serial.map_or(0, |value| value.stream_generation),
            child_generation: snapshot.child_generation.unwrap_or(0),
            outer_job: snapshot.child_job.unwrap_or(0),
            outer_launch_transaction: snapshot.child_launch.unwrap_or(0),
            live_peer_mask: snapshot
                .peers_live
                .into_iter()
                .enumerate()
                .fold(0, |mask, (index, live)| mask | (u32::from(live) << index)),
            input_queue_bytes: u32::try_from(snapshot.input_queued)
                .map_err(|_| ModelError::TooLarge)?,
            stdout_queue_bytes: u32::try_from(snapshot.stdout_queued)
                .map_err(|_| ModelError::TooLarge)?,
            stderr_queue_bytes: u32::try_from(snapshot.stderr_queued)
                .map_err(|_| ModelError::TooLarge)?,
            child_failures: u32::try_from(snapshot.child_failures)
                .map_err(|_| ModelError::TooLarge)?,
            serial_failures: u32::try_from(snapshot.serial_failures)
                .map_err(|_| ModelError::TooLarge)?,
            last_failure: status_failure(snapshot.last_failure),
        };
        wire.validate()
            .map_err(|_| ModelError::WrongConnectionState)?;
        Ok(wire)
    }
    pub fn take_recovery_action(&mut self) -> Option<RecoveryAction> {
        self.pending_recovery.take()
    }

    pub(crate) fn require_current(&mut self, event: EventGeneration) -> Result<(), ModelError> {
        if self.event_is_current(event) {
            Ok(())
        } else {
            self.last_failure = Some(ModelError::StaleCorrelation);
            Err(ModelError::StaleCorrelation)
        }
    }
    pub(crate) fn event_matches_child(&self, event: EventGeneration) -> bool {
        self.child.map(|value| EventGeneration::from(value.ids)) == Some(event)
    }
    pub(crate) fn live_event(&self) -> Result<EventGeneration, ModelError> {
        let child = self.child.ok_or(ModelError::NoChild)?;
        let event = EventGeneration::from(child.ids);
        if self.state != ConnectionState::Active || !child.all_peers_live() {
            return Err(ModelError::WrongConnectionState);
        }
        Ok(event)
    }
    pub(crate) fn mark_child_peer_closed(
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
    pub(crate) fn start_child_retirement(
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
    pub(crate) fn complete_retirement(&mut self, now: u64) -> Result<RecoveryAction, ModelError> {
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
            self.child_exhausted = true;
            self.last_failure = Some(ModelError::RestartExhausted);
            Ok(RecoveryAction::Escalate)
        } else {
            self.state = ConnectionState::Active;
            Ok(RecoveryAction::ReplaceChild)
        }
    }
    pub(crate) fn maybe_finish_serial_invalidation(&mut self) -> Result<(), ModelError> {
        if self.serial_invalidated
            && self.child.is_none()
            && self.pending_launch.is_none()
            && self.pending_launch_cleanup.is_none()
        {
            let now = self
                .last_now
                .ok_or_else(|| self.fail(ModelError::MonotonicRegression))?;
            self.pending_recovery = Some(self.finish_serial_cleanup(now)?);
        }
        Ok(())
    }
    pub(crate) fn finish_serial_cleanup(&mut self, now: u64) -> Result<RecoveryAction, ModelError> {
        let retry = now
            .checked_add(SERIAL_RETRY_BACKOFF_MILLIS)
            .ok_or_else(|| self.fail(ModelError::ArithmeticOverflow))?;
        self.serial = None;
        self.console_generation = None;
        self.serial_cleanup = true;
        self.serial_invalidated = false;
        self.state = ConnectionState::Reconnecting;
        self.clear_volatile();
        self.input_normalizer.reset();
        Ok(RecoveryAction::RetrySerialAt(retry))
    }
    pub(crate) fn clear_volatile(&mut self) {
        self.input.clear();
        self.stdout.clear();
        self.stderr.clear();
        // Input CR/LF state belongs to the healthy serial/console generation.
        // Child replacement clears staged bytes and child-output transforms,
        // but a delayed LF must still pair with an already consumed raw CR.
        self.stdout_normalizer.reset();
        self.stderr_normalizer.reset();
        self.next_output = OutputSource::Stdout;
        self.clear_reservations();
        self.stable = None;
        self.ready_observed = None;
    }
    pub(crate) fn clear_reservations(&mut self) {
        self.pending_stdin = None;
        self.pending_tx = None;
    }
    pub(crate) fn queue_for(&self, source: OutputSource) -> &BoundedQueue {
        match source {
            OutputSource::Stdout => &self.stdout,
            OutputSource::Stderr => &self.stderr,
        }
    }
    pub(crate) fn queue_for_mut(&mut self, source: OutputSource) -> &mut BoundedQueue {
        match source {
            OutputSource::Stdout => &mut self.stdout,
            OutputSource::Stderr => &mut self.stderr,
        }
    }
    pub(crate) fn allocate_generation(&mut self) -> Result<u64, ModelError> {
        let value = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or_else(|| self.fail(ModelError::ArithmeticOverflow))?;
        Ok(value)
    }
    pub(crate) fn allocate_endpoint(&mut self) -> Result<Endpoint, ModelError> {
        let value = self.next_endpoint;
        self.next_endpoint = self
            .next_endpoint
            .checked_add(1)
            .ok_or_else(|| self.fail(ModelError::ArithmeticOverflow))?;
        Ok(Endpoint(value))
    }
    pub(crate) fn allocate_reservation(&mut self) -> Result<u64, ModelError> {
        let value = self.next_reservation;
        self.next_reservation = self
            .next_reservation
            .checked_add(1)
            .ok_or_else(|| self.fail(ModelError::ArithmeticOverflow))?;
        Ok(value)
    }
    pub(crate) fn time(&mut self, now: u64) -> Result<(), ModelError> {
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
    pub(crate) fn fail(&mut self, error: ModelError) -> ModelError {
        self.state = ConnectionState::FailClosed;
        self.last_failure = Some(error);
        self.stable = None;
        error
    }

    #[cfg(test)]
    pub(crate) fn validate_invariants(&self) -> bool {
        if self.pending_launch_cleanup.is_some()
            && self.pending_launch_cleanup != self.pending_launch
        {
            return false;
        }
        if self.pending_launch.is_some()
            && (self.serial.is_none()
                || self.console_generation.is_none()
                || self.child.is_some()
                || self.pending_connect.is_some())
        {
            return false;
        }
        if self.state == ConnectionState::Reconnecting
            && (self.serial.is_some()
                || self.console_generation.is_some()
                || self.child.is_some()
                || self.pending_launch.is_some()
                || self.serial_invalidated
                || !self.serial_cleanup)
        {
            return false;
        }
        if self.state == ConnectionState::Active && self.serial.is_none() {
            return false;
        }
        if self.pending_connect.is_some()
            && (!matches!(
                self.state,
                ConnectionState::Reconnecting | ConnectionState::FailClosed
            ) || self.serial.is_some()
                || self.console_generation.is_some()
                || self.child.is_some()
                || self.pending_launch.is_some())
        {
            return false;
        }
        if self.child.is_some()
            && (self.serial.is_none()
                || self.console_generation.is_none()
                || self.pending_connect.is_some()
                || self.pending_launch.is_some())
        {
            return false;
        }
        if self.serial.is_some() != self.console_generation.is_some() {
            return false;
        }
        if self.serial_invalidated && self.serial_cleanup {
            return false;
        }
        true
    }
}

pub(crate) const fn status_state(state: ConnectionState) -> wyrmroot_console_proto::State {
    match state {
        ConnectionState::Active => wyrmroot_console_proto::State::Active,
        ConnectionState::RetiringChild => wyrmroot_console_proto::State::RetiringChild,
        ConnectionState::AwaitingReap => wyrmroot_console_proto::State::AwaitingReap,
        ConnectionState::Reconnecting => wyrmroot_console_proto::State::Reconnecting,
        ConnectionState::Exhausted => wyrmroot_console_proto::State::Exhausted,
        ConnectionState::FailClosed => wyrmroot_console_proto::State::FailClosed,
    }
}

pub(crate) const fn status_failure(
    error: Option<ModelError>,
) -> wyrmroot_console_proto::LastFailure {
    use wyrmroot_console_proto::LastFailure;
    match error {
        None => LastFailure::None,
        Some(ModelError::ZeroCorrelation) => LastFailure::ZeroCorrelation,
        Some(ModelError::StaleCorrelation) => LastFailure::StaleCorrelation,
        Some(ModelError::WrongConnectionState) => LastFailure::WrongConnectionState,
        Some(ModelError::NoChild) => LastFailure::NoChild,
        Some(ModelError::IncompleteCleanup) => LastFailure::IncompleteCleanup,
        Some(ModelError::AlreadyReserved) => LastFailure::AlreadyReserved,
        Some(ModelError::UnknownReservation) => LastFailure::UnknownReservation,
        Some(ModelError::Backpressure) => LastFailure::Backpressure,
        Some(ModelError::TooLarge) => LastFailure::TooLarge,
        Some(ModelError::MonotonicRegression) => LastFailure::MonotonicRegression,
        Some(ModelError::ArithmeticOverflow) => LastFailure::ArithmeticOverflow,
        Some(ModelError::RestartExhausted) => LastFailure::RestartExhausted,
        Some(ModelError::SerialDisconnected) => LastFailure::SerialDisconnected,
        Some(ModelError::ChildDisconnected) => LastFailure::ChildDisconnected,
        Some(ModelError::WrongDirection) => LastFailure::WrongDirection,
    }
}

pub(crate) const fn other(source: OutputSource) -> OutputSource {
    match source {
        OutputSource::Stdout => OutputSource::Stderr,
        OutputSource::Stderr => OutputSource::Stdout,
    }
}
