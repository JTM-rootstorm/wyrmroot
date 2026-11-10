//! Bounded, no-std lifecycle model for the WYR1-D serial console supervisor.
//!
//! The native process supplies handles and wait results. This core makes the
//! identity, queue, terminal-transform, and restart decisions explicit before
//! those effects occur. It does not model a shell or terminal emulator.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;
// The recording platform is a dev-dependency; only the native role's tests
// name it.
#[cfg(all(test, not(feature = "native-consoled")))]
use wyrmroot_runtime as _;

/// The native role, which `src/main.rs` held until S2U step 3. It exists only
/// with `native-consoled`, which every consoled binary shape requires.
#[cfg(feature = "native-consoled")]
pub mod role;
#[cfg(feature = "native-consoled")]
mod stream_transfer;

mod model;
pub use model::*;

// The role was moved out of the binary verbatim, and the binary named this
// library `wyrmroot_consoled`. Keeping that name resolvable here keeps the
// moved code, and the source-text tests that read it, byte-for-byte as they
// were.
#[cfg(feature = "native-consoled")]
extern crate self as wyrmroot_consoled;

pub const STAGING_CAPACITY: usize = 4096;
pub const FAIR_SOURCE_BYTES_PER_TURN: usize = 1024;
pub const RESTART_WINDOW_MILLIS: u64 = 60_000;
pub const STABLE_RUN_MILLIS: u64 = 60_000;
pub const SERIAL_RETRY_BACKOFF_MILLIS: u64 = 25;
pub const MAX_FAILURES_PER_WINDOW: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseWitnessEvent {
    Released,
    Malformed,
}

/// The retained direct CONNECT endpoint carries no messages. Only a pure
/// peer-close observation certifies release; data remains malformed even when
/// it is co-observed with peer close.
pub const fn classify_release_witness(readable: bool, peer_closed: bool) -> ReleaseWitnessEvent {
    if !readable && peer_closed {
        ReleaseWitnessEvent::Released
    } else {
        ReleaseWitnessEvent::Malformed
    }
}

/// Executes the mandatory post-CONNECTED cleanup order while still attempting
/// both releases when the raw endpoint close fails.
pub fn release_raw_then_witness<H: Copy>(
    raw: H,
    witness: Option<H>,
    mut close: impl FnMut(H) -> bool,
) -> bool {
    let raw_closed = close(raw);
    let witness_closed = witness.is_none_or(close);
    raw_closed && witness_closed
}

/// Runs fatal event-loop cleanup in the only safe ownership order. Callers
/// supply their native effects so the sequencing remains executable in the
/// allocation-free model and in host tests.
///
/// `effects` is lent to each step in turn: the three steps all act through
/// the same native platform, which no two of them can hold at once.
pub fn cleanup_after_event_loop_failure<X, S, C>(
    effects: &mut X,
    serial: &mut S,
    child: &mut C,
    close_serial: impl FnOnce(&mut X, &mut S) -> bool,
    retire_watch: impl FnOnce(&mut X, &mut S) -> bool,
    close_child: impl FnOnce(&mut X, &mut C) -> bool,
) -> bool {
    let serial_closed = close_serial(effects, serial);
    let watch_retired = retire_watch(effects, serial);
    let child_closed = close_child(effects, child);
    serial_closed && watch_retired && child_closed
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildPolicy {
    ConsoleEcho,
    Wyrmsh,
}

impl ChildPolicy {
    pub const fn selected() -> Self {
        if true {
            Self::Wyrmsh
        } else {
            Self::ConsoleEcho
        }
    }

    pub const fn path(self) -> &'static str {
        match self {
            Self::ConsoleEcho => "bin/console-echo",
            Self::Wyrmsh => wyrmroot_console_proto::SHELL_PATH,
        }
    }
}

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
    SerialDisconnected,
    ChildDisconnected,
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
            && (
                self.driver_control_endpoint_id,
                self.driver_control_endpoint_generation,
            ) != (
                previous.driver_control_endpoint_id,
                previous.driver_control_endpoint_generation,
            )
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
    pub(crate) const fn all_peers_live(self) -> bool {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaunchCleanupEvidence {
    pub consoled_peers_closed: [bool; 3],
    pub unmoved_child_peers_closed: [bool; 3],
    pub moved_child_peers_revoked: [bool; 3],
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
    pub const fn console_generation(&self) -> u64 {
        self.console_generation
    }

    pub const fn child_generation(&self) -> u64 {
        self.child_generation
    }

    pub const fn outer_launch_transaction(&self) -> u64 {
        self.child_launch
    }

    pub fn move_child_peer(&mut self, kind: StreamKind) -> Result<Endpoint, ModelError> {
        let index = kind.index();
        if self.committed || self.moved[index] {
            return Err(ModelError::WrongConnectionState);
        }
        self.moved[index] = true;
        Ok(self.child_peers[index])
    }

    pub(crate) const fn all_moved(&self) -> bool {
        self.moved[0] && self.moved[1] && self.moved[2]
    }

    fn abort_cleanup(self) -> Result<LaunchCleanup, ModelError> {
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

fn evidence_matches_cleanup(cleanup: &LaunchCleanup, evidence: LaunchCleanupEvidence) -> bool {
    let mut index = 0;
    while index < 6 {
        let entry = cleanup.entries[index];
        let satisfied = match entry.disposition {
            CleanupDisposition::CloseConsoledPeer => evidence.consoled_peers_closed[index],
            CleanupDisposition::CloseUnmovedChildPeer => {
                evidence.unmoved_child_peers_closed[index - 3]
            }
            CleanupDisposition::RevokeMovedChildPeerFromLaunch => {
                evidence.moved_child_peers_revoked[index - 3]
            }
        };
        if !satisfied {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests;
