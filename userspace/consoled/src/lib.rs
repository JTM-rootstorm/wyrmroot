//! Bounded, no-std state model for the WYR1-D serial console supervisor.
//!
//! The native entry point owns handles and waits.  This module owns the
//! generation, transform, queue, and restart rules that make those waits safe
//! to drive.  It intentionally does not model a shell or a terminal emulator.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub const STAGING_CAPACITY: usize = 4096;
pub const FAIR_SOURCE_BYTES_PER_TURN: usize = 1024;
pub const RESTART_WINDOW_MILLIS: u64 = 60_000;
pub const STABLE_RUN_MILLIS: u64 = 60_000;
pub const SERIAL_RETRY_BACKOFF_MILLIS: u64 = 25;
pub const MAX_FAILURES_PER_WINDOW: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelError {
    ZeroGeneration,
    StaleGeneration,
    NoSerial,
    NoChild,
    BadTransition,
    Backpressure,
    TooLarge,
    MonotonicRegression,
    RestartExhausted,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionIds {
    pub serial_publication: u64,
    pub serial_driver: u64,
    pub serial_stream: u64,
    pub console: u64,
    pub child: u64,
}

impl SessionIds {
    pub const fn has_nonzero_generations(self) -> bool {
        self.serial_publication != 0
            && self.serial_driver != 0
            && self.serial_stream != 0
            && self.console != 0
            && self.child != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventGeneration {
    pub serial_publication: u64,
    pub serial_driver: u64,
    pub serial_stream: u64,
    pub console: u64,
    pub child: u64,
}

impl From<SessionIds> for EventGeneration {
    fn from(ids: SessionIds) -> Self {
        Self {
            serial_publication: ids.serial_publication,
            serial_driver: ids.serial_driver,
            serial_stream: ids.serial_stream,
            console: ids.console,
            child: ids.child,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Endpoint(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildSession {
    pub ids: SessionIds,
    pub stdin: Endpoint,
    pub stdout: Endpoint,
    pub stderr: Endpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaunchCleanup {
    /// Peers retained by consoled and therefore explicitly closed on rollback.
    pub close_consoled: [Endpoint; 3],
    /// Child-side endpoints which have not been moved into the JobV2 request.
    pub close_unmoved_child: [Option<Endpoint>; 3],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaunchTransaction {
    child: u64,
    consoled: [Endpoint; 3],
    child_peers: [Endpoint; 3],
    moved: [bool; 3],
}

impl LaunchTransaction {
    pub const fn child_generation(self) -> u64 {
        self.child
    }

    pub const fn consoled_peer(self, kind: StreamKind) -> Endpoint {
        self.consoled[kind.index()]
    }

    /// Records one exact MOVE. Repeating a MOVE is a transaction error rather
    /// than an implicit duplicate-handle operation.
    pub fn move_child_peer(&mut self, kind: StreamKind) -> Result<Endpoint, ModelError> {
        let index = kind.index();
        if self.moved[index] {
            return Err(ModelError::BadTransition);
        }
        self.moved[index] = true;
        Ok(self.child_peers[index])
    }

    pub const fn all_moved(self) -> bool {
        self.moved[0] && self.moved[1] && self.moved[2]
    }

    /// Exact rollback ownership after a partial JobV2 construction failure.
    /// Moved endpoints are owned by the rejected request/launch transaction;
    /// unmoved endpoints remain locally closable.
    pub const fn abort_cleanup(self) -> LaunchCleanup {
        LaunchCleanup {
            close_consoled: self.consoled,
            close_unmoved_child: [
                if self.moved[0] {
                    None
                } else {
                    Some(self.child_peers[0])
                },
                if self.moved[1] {
                    None
                } else {
                    Some(self.child_peers[1])
                },
                if self.moved[2] {
                    None
                } else {
                    Some(self.child_peers[2])
                },
            ],
        }
    }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundedQueue {
    bytes: [u8; STAGING_CAPACITY],
    head: usize,
    len: usize,
}

impl Default for BoundedQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl BoundedQueue {
    pub const fn new() -> Self {
        Self {
            bytes: [0; STAGING_CAPACITY],
            head: 0,
            len: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub const fn available(&self) -> usize {
        STAGING_CAPACITY - self.len
    }

    pub fn push(&mut self, input: &[u8]) -> Result<(), ModelError> {
        if input.len() > self.available() {
            return Err(ModelError::Backpressure);
        }
        let mut offset = 0;
        while offset < input.len() {
            let tail = (self.head + self.len) % STAGING_CAPACITY;
            self.bytes[tail] = input[offset];
            self.len += 1;
            offset += 1;
        }
        Ok(())
    }

    pub fn pop_into(&mut self, output: &mut [u8], maximum: usize) -> usize {
        let count = core::cmp::min(core::cmp::min(output.len(), maximum), self.len);
        let mut offset = 0;
        while offset < count {
            output[offset] = self.bytes[self.head];
            self.head = (self.head + 1) % STAGING_CAPACITY;
            self.len -= 1;
            offset += 1;
        }
        count
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InputNormalizer {
    suppress_lf_after_cr: bool,
}

impl InputNormalizer {
    pub const fn suppressing_lf(self) -> bool {
        self.suppress_lf_after_cr
    }

    pub fn stage(
        &mut self,
        input: &[u8],
        destination: &mut BoundedQueue,
    ) -> Result<(), ModelError> {
        if input.len() > FAIR_SOURCE_BYTES_PER_TURN || input.len() > destination.available() {
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
                destination.push(&[b'\n'])?;
                self.suppress_lf_after_cr = true;
            } else {
                destination.push(&[byte])?;
            }
            index += 1;
        }
        Ok(())
    }

    pub fn reset(&mut self) {
        self.suppress_lf_after_cr = false;
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OutputNormalizer {
    previous_was_cr: bool,
}

impl OutputNormalizer {
    pub const fn previous_was_cr(self) -> bool {
        self.previous_was_cr
    }

    pub fn stage(
        &mut self,
        input: &[u8],
        destination: &mut BoundedQueue,
    ) -> Result<(), ModelError> {
        if input.len() > FAIR_SOURCE_BYTES_PER_TURN
            || input.len().saturating_mul(2) > destination.available()
        {
            return Err(ModelError::Backpressure);
        }
        let mut index = 0;
        while index < input.len() {
            let byte = input[index];
            if byte == b'\n' && !self.previous_was_cr {
                destination.push(&[b'\r'])?;
            }
            destination.push(&[byte])?;
            self.previous_was_cr = byte == b'\r';
            index += 1;
        }
        Ok(())
    }

    pub fn reset(&mut self) {
        self.previous_was_cr = false;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryAction {
    None,
    ReplaceChild,
    RetrySerialAt(u64),
    Escalate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestartWindow {
    times: [u64; MAX_FAILURES_PER_WINDOW],
    len: usize,
    last_now: Option<u64>,
    exhausted: bool,
}

impl Default for RestartWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl RestartWindow {
    pub const fn new() -> Self {
        Self {
            times: [0; MAX_FAILURES_PER_WINDOW],
            len: 0,
            last_now: None,
            exhausted: false,
        }
    }

    pub const fn failures(&self) -> usize {
        self.len
    }
    pub const fn exhausted(&self) -> bool {
        self.exhausted
    }

    pub fn record_failure(&mut self, now: u64) -> Result<bool, ModelError> {
        self.check_now(now)?;
        let mut retained = 0;
        let mut index = 0;
        while index < self.len {
            if now - self.times[index] < RESTART_WINDOW_MILLIS {
                self.times[retained] = self.times[index];
                retained += 1;
            }
            index += 1;
        }
        self.len = retained;
        if self.len < MAX_FAILURES_PER_WINDOW {
            self.times[self.len] = now;
            self.len += 1;
        }
        self.exhausted = self.len >= MAX_FAILURES_PER_WINDOW;
        Ok(self.exhausted)
    }

    pub fn clear(&mut self, now: u64) -> Result<(), ModelError> {
        self.check_now(now)?;
        self.len = 0;
        self.exhausted = false;
        Ok(())
    }

    fn check_now(&mut self, now: u64) -> Result<(), ModelError> {
        if let Some(last) = self.last_now {
            if now < last {
                return Err(ModelError::MonotonicRegression);
            }
        }
        self.last_now = Some(now);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsoleSnapshot {
    pub ids: Option<SessionIds>,
    pub serial_live: bool,
    pub child_live: bool,
    pub input_queued: usize,
    pub stdout_queued: usize,
    pub stderr_queued: usize,
    pub child_failures: usize,
    pub serial_failures: usize,
    pub last_failure: Option<ModelError>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsoleModel {
    ids: Option<SessionIds>,
    child: Option<ChildSession>,
    input: BoundedQueue,
    stdout: BoundedQueue,
    stderr: BoundedQueue,
    input_normalizer: InputNormalizer,
    stdout_normalizer: OutputNormalizer,
    stderr_normalizer: OutputNormalizer,
    next_output: OutputSource,
    child_window: RestartWindow,
    serial_window: RestartWindow,
    stable_since: Option<u64>,
    last_serial: Option<(u64, u64, u64)>,
    next_generation: u64,
    next_endpoint: u64,
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
            ids: None,
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
            child_window: RestartWindow::new(),
            serial_window: RestartWindow::new(),
            stable_since: None,
            last_serial: None,
            next_generation: 1,
            next_endpoint: 1,
            last_failure: None,
        }
    }

    pub const fn ids(&self) -> Option<SessionIds> {
        self.ids
    }
    pub const fn child(&self) -> Option<ChildSession> {
        self.child
    }
    pub const fn serial_live(&self) -> bool {
        self.ids.is_some()
    }
    pub const fn child_live(&self) -> bool {
        self.child.is_some()
    }
    pub const fn input(&self) -> &BoundedQueue {
        &self.input
    }
    pub const fn stdout(&self) -> &BoundedQueue {
        &self.stdout
    }
    pub const fn stderr(&self) -> &BoundedQueue {
        &self.stderr
    }

    /// Accepts a newly attached raw WRST stream. A publication/driver/stream
    /// tuple may never be reused for a replacement console generation.
    pub fn attach_serial(
        &mut self,
        publication: u64,
        driver: u64,
        stream: u64,
    ) -> Result<SessionIds, ModelError> {
        if publication == 0 || driver == 0 || stream == 0 {
            return Err(ModelError::ZeroGeneration);
        }
        if self.last_serial == Some((publication, driver, stream)) {
            return Err(ModelError::StaleGeneration);
        }
        let console = self.allocate_generation()?;
        let ids = SessionIds {
            serial_publication: publication,
            serial_driver: driver,
            serial_stream: stream,
            console,
            child: 0,
        };
        self.ids = Some(ids);
        self.last_serial = Some((publication, driver, stream));
        self.child = None;
        self.reset_stream_state();
        Ok(ids)
    }

    pub fn begin_child_launch(&mut self) -> Result<LaunchTransaction, ModelError> {
        let ids = self.ids.ok_or(ModelError::NoSerial)?;
        if self.child.is_some() {
            return Err(ModelError::BadTransition);
        }
        let child = self.allocate_generation()?;
        let transaction = LaunchTransaction {
            child,
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
        };
        let _ = ids;
        Ok(transaction)
    }

    pub fn commit_child_launch(
        &mut self,
        transaction: LaunchTransaction,
    ) -> Result<ChildSession, ModelError> {
        let mut ids = self.ids.ok_or(ModelError::NoSerial)?;
        if !transaction.all_moved() || self.child.is_some() {
            return Err(ModelError::BadTransition);
        }
        ids.child = transaction.child;
        let child = ChildSession {
            ids,
            stdin: transaction.consoled[0],
            stdout: transaction.consoled[1],
            stderr: transaction.consoled[2],
        };
        self.ids = Some(ids);
        self.child = Some(child);
        Ok(child)
    }

    pub fn accepts_event(&self, event: EventGeneration) -> bool {
        self.ids.map(EventGeneration::from) == Some(event) && self.child.is_some()
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

    /// Selects one bounded stdout/stderr service turn without starving an
    /// otherwise ready sibling. The native loop supplies the source bytes.
    pub fn next_output_turn(&mut self) -> Option<(OutputSource, usize)> {
        let first = self.next_output;
        let second = match first {
            OutputSource::Stdout => OutputSource::Stderr,
            OutputSource::Stderr => OutputSource::Stdout,
        };
        let selected = if self.queue_for(first).is_empty() {
            second
        } else {
            first
        };
        if self.queue_for(selected).is_empty() {
            return None;
        }
        self.next_output = match selected {
            OutputSource::Stdout => OutputSource::Stderr,
            OutputSource::Stderr => OutputSource::Stdout,
        };
        Some((
            selected,
            core::cmp::min(FAIR_SOURCE_BYTES_PER_TURN, self.queue_for(selected).len()),
        ))
    }

    pub fn drain_serial_tx(&mut self, output: &mut [u8]) -> Option<(OutputSource, usize)> {
        let (source, limit) = self.next_output_turn()?;
        let count = self.queue_for_mut(source).pop_into(output, limit);
        Some((source, count))
    }

    /// Serial driver/stream loss invalidates the entire console generation.
    pub fn serial_lost(&mut self, now: u64) -> Result<RecoveryAction, ModelError> {
        self.ids = None;
        self.child = None;
        self.reset_stream_state();
        self.stable_since = None;
        let exhausted = self.serial_window.record_failure(now)?;
        if exhausted {
            self.last_failure = Some(ModelError::RestartExhausted);
            Ok(RecoveryAction::Escalate)
        } else {
            Ok(RecoveryAction::RetrySerialAt(
                now + SERIAL_RETRY_BACKOFF_MILLIS,
            ))
        }
    }

    /// Child-only loss deliberately preserves the healthy raw serial tuple.
    pub fn child_lost(&mut self, now: u64) -> Result<RecoveryAction, ModelError> {
        if self.ids.is_none() || self.child.is_none() {
            return Err(ModelError::NoChild);
        }
        self.child = None;
        self.ids = self.ids.map(|mut ids| {
            ids.child = 0;
            ids
        });
        self.input.clear();
        self.stdout.clear();
        self.stderr.clear();
        self.input_normalizer.reset();
        self.stdout_normalizer.reset();
        self.stderr_normalizer.reset();
        self.stable_since = None;
        let exhausted = self.child_window.record_failure(now)?;
        if exhausted {
            self.last_failure = Some(ModelError::RestartExhausted);
            Ok(RecoveryAction::Escalate)
        } else {
            Ok(RecoveryAction::ReplaceChild)
        }
    }

    /// Clear restart budgets only after exactly sixty continuous seconds in
    /// READY with an exact current raw/console/child/three-peer session.
    pub fn observe_ready(&mut self, now: u64, exact_ready: bool) -> Result<bool, ModelError> {
        self.check_model_time(now)?;
        let ready = exact_ready && self.ids.is_some() && self.child.is_some();
        if !ready {
            self.stable_since = None;
            return Ok(false);
        }
        let since = match self.stable_since {
            Some(value) => value,
            None => {
                self.stable_since = Some(now);
                return Ok(false);
            }
        };
        if now - since < STABLE_RUN_MILLIS {
            return Ok(false);
        }
        self.child_window.clear(now)?;
        self.serial_window.clear(now)?;
        self.stable_since = Some(now);
        Ok(true)
    }

    pub fn snapshot(&self) -> ConsoleSnapshot {
        ConsoleSnapshot {
            ids: self.ids,
            serial_live: self.ids.is_some(),
            child_live: self.child.is_some(),
            input_queued: self.input.len(),
            stdout_queued: self.stdout.len(),
            stderr_queued: self.stderr.len(),
            child_failures: self.child_window.failures(),
            serial_failures: self.serial_window.failures(),
            last_failure: self.last_failure,
        }
    }

    fn require_current(&mut self, event: EventGeneration) -> Result<(), ModelError> {
        if self.accepts_event(event) {
            Ok(())
        } else {
            self.last_failure = Some(ModelError::StaleGeneration);
            Err(ModelError::StaleGeneration)
        }
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

    fn reset_stream_state(&mut self) {
        self.input.clear();
        self.stdout.clear();
        self.stderr.clear();
        self.input_normalizer.reset();
        self.stdout_normalizer.reset();
        self.stderr_normalizer.reset();
        self.next_output = OutputSource::Stdout;
    }

    fn allocate_generation(&mut self) -> Result<u64, ModelError> {
        let value = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(ModelError::BadTransition)?;
        if value == 0 {
            return Err(ModelError::BadTransition);
        }
        Ok(value)
    }
    fn allocate_endpoint(&mut self) -> Result<Endpoint, ModelError> {
        let value = self.next_endpoint;
        self.next_endpoint = self
            .next_endpoint
            .checked_add(1)
            .ok_or(ModelError::BadTransition)?;
        if value == 0 {
            return Err(ModelError::BadTransition);
        }
        Ok(Endpoint(value))
    }
    fn check_model_time(&mut self, now: u64) -> Result<(), ModelError> {
        // Both restart clocks observe this point; their independent histories
        // still make regression fatal even when one clock has no failures.
        if self
            .child_window
            .last_now
            .map(|last| now < last)
            .unwrap_or(false)
            || self
                .serial_window
                .last_now
                .map(|last| now < last)
                .unwrap_or(false)
        {
            self.last_failure = Some(ModelError::MonotonicRegression);
            return Err(ModelError::MonotonicRegression);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live() -> (ConsoleModel, EventGeneration) {
        let mut model = ConsoleModel::new();
        model.attach_serial(11, 12, 13).unwrap();
        let mut launch = model.begin_child_launch().unwrap();
        launch.move_child_peer(StreamKind::Stdin).unwrap();
        launch.move_child_peer(StreamKind::Stdout).unwrap();
        launch.move_child_peer(StreamKind::Stderr).unwrap();
        let child = model.commit_child_launch(launch).unwrap();
        (model, child.ids.into())
    }

    #[test]
    fn input_crlf_transform_crosses_record_boundary() {
        let (mut model, event) = live();
        model.stage_serial_input(event, b"a\r").unwrap();
        model.stage_serial_input(event, b"\nb\rc").unwrap();
        let mut got = [0; 16];
        assert_eq!(model.input.pop_into(&mut got, 16), 5);
        assert_eq!(&got[..5], b"a\nb\nc");
    }

    #[test]
    fn output_crlf_state_is_independent_per_stream() {
        let (mut model, event) = live();
        model
            .stage_child_output(event, OutputSource::Stdout, b"a\r")
            .unwrap();
        model
            .stage_child_output(event, OutputSource::Stderr, b"e\n")
            .unwrap();
        model
            .stage_child_output(event, OutputSource::Stdout, b"\nb\n")
            .unwrap();
        let mut bytes = [0; 16];
        assert_eq!(model.stdout.pop_into(&mut bytes, 16), 6);
        assert_eq!(&bytes[..6], b"a\r\nb\r\n");
        assert_eq!(model.stderr.pop_into(&mut bytes, 16), 3);
        assert_eq!(&bytes[..3], b"e\r\n");
    }

    #[test]
    fn output_service_is_bounded_and_round_robin() {
        let (mut model, event) = live();
        let data = [b'x'; FAIR_SOURCE_BYTES_PER_TURN];
        model
            .stage_child_output(event, OutputSource::Stdout, &data)
            .unwrap();
        model
            .stage_child_output(event, OutputSource::Stderr, &data)
            .unwrap();
        assert_eq!(model.next_output_turn(), Some((OutputSource::Stdout, 1024)));
        assert_eq!(model.next_output_turn(), Some((OutputSource::Stderr, 1024)));
    }

    #[test]
    fn backpressure_has_no_partial_transform_or_queue_growth() {
        let (mut model, event) = live();
        model.stdout.push(&[b'x'; STAGING_CAPACITY - 1]).unwrap();
        let before = model.stdout.len();
        assert_eq!(
            model.stage_child_output(event, OutputSource::Stdout, b"\n"),
            Err(ModelError::Backpressure)
        );
        assert_eq!(model.stdout.len(), before);
        assert_eq!(
            model.stage_serial_input(event, &[b'x'; 1025]),
            Err(ModelError::Backpressure)
        );
    }

    #[test]
    fn serial_loss_invalidates_everything_and_replacement_is_fresh() {
        let (mut model, old_event) = live();
        let old = model.ids().unwrap();
        assert_eq!(model.serial_lost(10), Ok(RecoveryAction::RetrySerialAt(35)));
        assert!(!model.serial_live());
        assert!(!model.child_live());
        assert_eq!(
            model.stage_serial_input(old_event, b"stale"),
            Err(ModelError::StaleGeneration)
        );
        assert_eq!(
            model.attach_serial(old.serial_publication, old.serial_driver, old.serial_stream),
            Err(ModelError::StaleGeneration)
        );
        let next = model.attach_serial(21, 22, 23).unwrap();
        assert!(next.console > old.console);
        let mut launch = model.begin_child_launch().unwrap();
        for kind in [StreamKind::Stdin, StreamKind::Stdout, StreamKind::Stderr] {
            launch.move_child_peer(kind).unwrap();
        }
        let replacement = model.commit_child_launch(launch).unwrap();
        assert_ne!(replacement.ids.child, old.child);
        assert_ne!(replacement.stdin, model.child().unwrap().stdout);
    }

    #[test]
    fn child_only_loss_preserves_raw_serial_and_replaces_child() {
        let (mut model, _) = live();
        let raw = model.ids().unwrap();
        assert_eq!(model.child_lost(9), Ok(RecoveryAction::ReplaceChild));
        assert!(model.serial_live());
        assert!(!model.child_live());
        assert_eq!(model.ids().unwrap().serial_stream, raw.serial_stream);
        let mut launch = model.begin_child_launch().unwrap();
        for kind in [StreamKind::Stdin, StreamKind::Stdout, StreamKind::Stderr] {
            launch.move_child_peer(kind).unwrap();
        }
        assert_ne!(
            model.commit_child_launch(launch).unwrap().ids.child,
            raw.child
        );
    }

    #[test]
    fn partial_move_cleanup_only_closes_locally_owned_child_endpoints() {
        let mut model = ConsoleModel::new();
        model.attach_serial(1, 2, 3).unwrap();
        let mut launch = model.begin_child_launch().unwrap();
        let moved = launch.move_child_peer(StreamKind::Stdin).unwrap();
        let cleanup = launch.abort_cleanup();
        assert_eq!(
            cleanup.close_unmoved_child,
            [
                None,
                Some(Endpoint(moved.0 + 1)),
                Some(Endpoint(moved.0 + 2))
            ]
        );
        assert_ne!(cleanup.close_consoled[0], moved);
    }

    #[test]
    fn fourth_failure_in_half_open_window_escalates_and_age_boundary_expires() {
        let (mut model, _) = live();
        assert_eq!(model.child_lost(0), Ok(RecoveryAction::ReplaceChild));
        for now in [1, 2] {
            let mut launch = model.begin_child_launch().unwrap();
            for kind in [StreamKind::Stdin, StreamKind::Stdout, StreamKind::Stderr] {
                launch.move_child_peer(kind).unwrap();
            }
            model.commit_child_launch(launch).unwrap();
            assert_eq!(model.child_lost(now), Ok(RecoveryAction::ReplaceChild));
        }
        let mut launch = model.begin_child_launch().unwrap();
        for kind in [StreamKind::Stdin, StreamKind::Stdout, StreamKind::Stderr] {
            launch.move_child_peer(kind).unwrap();
        }
        model.commit_child_launch(launch).unwrap();
        assert_eq!(model.child_lost(3), Ok(RecoveryAction::Escalate));

        let mut other = ConsoleModel::new();
        other.attach_serial(1, 2, 3).unwrap();
        assert_eq!(other.serial_lost(0), Ok(RecoveryAction::RetrySerialAt(25)));
        assert_eq!(other.attach_serial(4, 5, 6).unwrap().serial_stream, 6);
        assert_eq!(
            other.serial_lost(60_000),
            Ok(RecoveryAction::RetrySerialAt(60_025))
        );
        assert_eq!(other.snapshot().serial_failures, 1);
    }

    #[test]
    fn serial_retry_budget_escalates_on_its_own_fourth_loss() {
        let mut model = ConsoleModel::new();
        model.attach_serial(1, 2, 3).unwrap();
        for (index, now) in [0, 1, 2, 3].iter().copied().enumerate() {
            let expected = if index == 3 {
                RecoveryAction::Escalate
            } else {
                RecoveryAction::RetrySerialAt(now + SERIAL_RETRY_BACKOFF_MILLIS)
            };
            assert_eq!(model.serial_lost(now), Ok(expected));
            if index != 3 {
                let base = (index as u64 + 1) * 10;
                model.attach_serial(base + 1, base + 2, base + 3).unwrap();
            }
        }
        assert_eq!(model.snapshot().serial_failures, MAX_FAILURES_PER_WINDOW);
    }

    #[test]
    fn monotonic_regression_fails_closed_and_stability_resets_only_after_exact_minute() {
        let (mut model, _) = live();
        assert_eq!(model.child_lost(10), Ok(RecoveryAction::ReplaceChild));
        let mut launch = model.begin_child_launch().unwrap();
        for kind in [StreamKind::Stdin, StreamKind::Stdout, StreamKind::Stderr] {
            launch.move_child_peer(kind).unwrap();
        }
        model.commit_child_launch(launch).unwrap();
        assert!(!model.observe_ready(20, true).unwrap());
        assert!(!model.observe_ready(60_019, true).unwrap());
        assert!(model.observe_ready(60_020, true).unwrap());
        assert_eq!(model.snapshot().child_failures, 0);
        assert_eq!(
            model.observe_ready(60_019, true),
            Err(ModelError::MonotonicRegression)
        );
    }

    #[test]
    fn stale_events_are_rejected_after_child_replacement() {
        let (mut model, old_event) = live();
        model.child_lost(1).unwrap();
        let mut launch = model.begin_child_launch().unwrap();
        for kind in [StreamKind::Stdin, StreamKind::Stdout, StreamKind::Stderr] {
            launch.move_child_peer(kind).unwrap();
        }
        let new_event: EventGeneration = model.commit_child_launch(launch).unwrap().ids.into();
        assert_eq!(
            model.stage_child_output(old_event, OutputSource::Stdout, b"x"),
            Err(ModelError::StaleGeneration)
        );
        assert!(
            model
                .stage_child_output(new_event, OutputSource::Stdout, b"x")
                .is_ok()
        );
    }
}
