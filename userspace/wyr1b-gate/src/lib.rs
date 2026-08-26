//! Fixed-state selector-27 publisher/client actor models.

#![no_std]
#![forbid(unsafe_code)]

use wyrmroot_launch_proto as _;
use wyrmroot_registry_proto::{
    Correlation, Header as RegistryHeader, MessageType as RegistryMessageType,
    parse_correlation_environment,
};
use wyrmroot_wyr1b_gate_proto::{Direction, Error as WireError, MessageType, Record, challenge};
#[cfg(feature = "native-gate")]
use {deepwyrm_syscall as _, wyrmroot_loader as _, wyrmroot_runtime as _};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Correlation,
    Wire(WireError),
    WrongState,
    WrongActor,
    WrongObject,
    WrongOperation,
    PeerNotClosed,
    NonzeroJobResult,
}

/// Tracks the one state-aware WRTG failure diagnostic a native peer may attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailureTracker {
    startup_registry_generation: Option<u64>,
    ready: bool,
    current: Option<Record>,
    attempted: bool,
}

impl FailureTracker {
    pub const fn new(startup_registry_generation: Option<u64>) -> Self {
        Self {
            startup_registry_generation,
            ready: false,
            current: None,
            attempted: false,
        }
    }

    /// Records that the exact profile-bound WRLP READY send completed.
    pub fn mark_ready(&mut self) -> Result<(), Error> {
        if self.ready {
            return Err(Error::WrongState);
        }
        self.ready = true;
        Ok(())
    }

    /// Updates the exact actor identity and current operation after actor acceptance.
    pub fn update(&mut self, record: Record) -> Result<(), Error> {
        if !self.ready
            || record.nonce == 0
            || record.registry_generation == 0
            || record.actor_id == 0
            || record.actor_generation == 0
            || !matches!(record.operation_id, 1..=5)
        {
            return Err(Error::WrongState);
        }
        if let Some(current) = self.current
            && (record.nonce != current.nonce
                || record.registry_generation != current.registry_generation
                || record.actor_id != current.actor_id
                || record.actor_generation != current.actor_generation
                || (record.operation_id != current.operation_id
                    && !(current.operation_id == 1 && record.operation_id == 2)))
        {
            return Err(Error::WrongActor);
        }
        self.current = Some(record);
        Ok(())
    }

    /// Returns the sole failure record this process may attempt to send.
    pub fn take(&mut self, code: u32) -> Option<Record> {
        if !self.ready || self.attempted {
            return None;
        }
        let (nonce, registry_generation, actor_id, actor_generation, operation_id) =
            if let Some(current) = self.current {
                (
                    current.nonce,
                    current.registry_generation,
                    current.actor_id,
                    current.actor_generation,
                    current.operation_id,
                )
            } else {
                (1, self.startup_registry_generation?, 0, 0, 1)
            };
        self.attempted = true;
        Some(Record {
            message_type: MessageType::Failure,
            nonce,
            registry_generation,
            actor_id,
            actor_generation,
            object_id: 0,
            object_generation: 0,
            operation_id,
            value: match u64::from(code & 0xFFFF) {
                0 => 1,
                value => value,
            },
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublisherAction {
    Publish,
    Retire,
    Echo { direct: Record, report: Record },
    Report(Record),
    Done,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublisherPhase {
    Configure,
    Publishing,
    Published,
    Connected,
    Exchanged,
    Retiring,
    Retired,
    StaleClosed,
    StaleReported,
    Done,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Publisher {
    correlation: Correlation,
    phase: PublisherPhase,
    nonce: u64,
    client_id: u64,
    client_generation: u64,
    operation: u64,
}

impl Publisher {
    pub fn from_environment(entries: &[&str]) -> Result<Self, Error> {
        Ok(Self {
            correlation: parse_correlation_environment(entries).map_err(|_| Error::Correlation)?,
            phase: PublisherPhase::Configure,
            nonce: 0,
            client_id: 0,
            client_generation: 0,
            operation: 0,
        })
    }

    pub fn parent(&mut self, record: Record) -> Result<PublisherAction, Error> {
        if record.direction() != Direction::InitToChild {
            return Err(Error::Wire(WireError::WrongDirection));
        }
        match (self.phase, record.message_type) {
            (PublisherPhase::Configure, MessageType::ConfigurePublisher) => {
                self.check_actor(record)?;
                self.nonce = record.nonce;
                self.client_id = record.object_id;
                self.client_generation = record.object_generation;
                self.operation = record.operation_id;
                self.phase = PublisherPhase::Publishing;
                Ok(PublisherAction::Publish)
            }
            (PublisherPhase::Exchanged, MessageType::Retire) if self.operation == 1 => {
                self.check_exact(record, 1)?;
                self.phase = PublisherPhase::Retiring;
                Ok(PublisherAction::Retire)
            }
            (PublisherPhase::StaleClosed, MessageType::ProbeStale) => {
                if record.nonce != self.nonce
                    || record.registry_generation != self.correlation.registry_generation
                    || record.actor_id != self.correlation.endpoint_id
                    || record.actor_generation != self.correlation.endpoint_generation
                    || (record.object_id == self.correlation.endpoint_id
                        && record.object_generation == self.correlation.endpoint_generation)
                    || record.operation_id != 2
                {
                    return Err(Error::WrongActor);
                }
                self.operation = 2;
                self.phase = PublisherPhase::StaleReported;
                Ok(PublisherAction::Report(Record {
                    message_type: MessageType::StaleRejected,
                    ..record
                }))
            }
            (PublisherPhase::Exchanged, MessageType::Done) if self.operation == 2 => {
                self.check_done(record)?;
                self.phase = PublisherPhase::Done;
                Ok(PublisherAction::Done)
            }
            (PublisherPhase::StaleReported, MessageType::Done) => {
                self.check_done(record)?;
                self.phase = PublisherPhase::Done;
                Ok(PublisherAction::Done)
            }
            _ => Err(Error::WrongState),
        }
    }

    pub fn published(&mut self) -> Result<Record, Error> {
        if self.phase != PublisherPhase::Publishing {
            return Err(Error::WrongState);
        }
        self.phase = PublisherPhase::Published;
        Ok(self.report(MessageType::Published, 0))
    }

    /// Constructs a WRRG header from the startup-v2 correlation values.
    pub fn registry_header(
        &self,
        message_type: RegistryMessageType,
    ) -> Result<RegistryHeader, Error> {
        if self.nonce == 0 || self.operation == 0 {
            return Err(Error::WrongState);
        }
        let transaction_id = match message_type {
            RegistryMessageType::Publish | RegistryMessageType::Published => self
                .operation
                .checked_mul(2)
                .and_then(|value| value.checked_sub(1))
                .ok_or(Error::WrongOperation)?,
            RegistryMessageType::Retire | RegistryMessageType::Retired if self.operation == 1 => 2,
            RegistryMessageType::ConnectOffer => self.operation,
            _ => return Err(Error::WrongOperation),
        };
        Ok(RegistryHeader {
            message_type,
            registry_generation: self.correlation.registry_generation,
            endpoint_id: self.correlation.endpoint_id,
            endpoint_generation: self.correlation.endpoint_generation,
            transaction_id,
        })
    }

    pub fn connected(&mut self) -> Result<(), Error> {
        if self.phase != PublisherPhase::Published {
            return Err(Error::WrongState);
        }
        self.phase = PublisherPhase::Connected;
        Ok(())
    }

    pub fn direct(&mut self, record: Record) -> Result<PublisherAction, Error> {
        if self.phase != PublisherPhase::Connected
            || record.message_type != MessageType::DirectChallenge
            || record.direction() != Direction::ClientToDirect
        {
            return Err(Error::WrongState);
        }
        if record.nonce != self.nonce
            || record.registry_generation != self.correlation.registry_generation
            || record.actor_id != self.client_id
            || record.actor_generation != self.client_generation
            || record.object_id != self.correlation.endpoint_id
            || record.object_generation != self.correlation.endpoint_generation
            || record.operation_id != self.operation
            || record.value != challenge(record)
        {
            return Err(Error::WrongObject);
        }
        self.phase = PublisherPhase::Exchanged;
        let direct = Record {
            message_type: MessageType::DirectEcho,
            actor_id: self.correlation.endpoint_id,
            actor_generation: self.correlation.endpoint_generation,
            object_id: self.client_id,
            object_generation: self.client_generation,
            ..record
        };
        Ok(PublisherAction::Echo {
            direct,
            report: self.report(MessageType::Echoed, record.value),
        })
    }

    pub fn retired(&mut self) -> Result<Record, Error> {
        if self.phase != PublisherPhase::Retiring {
            return Err(Error::WrongState);
        }
        self.phase = PublisherPhase::Retired;
        Ok(self.report(MessageType::Retired, 0))
    }

    pub fn publication_peer_closed(
        &mut self,
        exact_send_or_wait_failure: bool,
    ) -> Result<(), Error> {
        if self.phase != PublisherPhase::Retired || !exact_send_or_wait_failure {
            return Err(Error::PeerNotClosed);
        }
        self.phase = PublisherPhase::StaleClosed;
        Ok(())
    }

    fn report(self, message_type: MessageType, value: u64) -> Record {
        Record {
            message_type,
            nonce: self.nonce,
            registry_generation: self.correlation.registry_generation,
            actor_id: self.correlation.endpoint_id,
            actor_generation: self.correlation.endpoint_generation,
            object_id: self.client_id,
            object_generation: self.client_generation,
            operation_id: self.operation,
            value,
        }
    }
    fn check_actor(self, record: Record) -> Result<(), Error> {
        if record.registry_generation != self.correlation.registry_generation
            || record.actor_id != self.correlation.endpoint_id
            || record.actor_generation != self.correlation.endpoint_generation
        {
            Err(Error::WrongActor)
        } else {
            Ok(())
        }
    }
    fn check_exact(self, record: Record, operation: u64) -> Result<(), Error> {
        self.check_actor(record)?;
        if record.nonce != self.nonce
            || record.object_id != self.client_id
            || record.object_generation != self.client_generation
            || record.operation_id != operation
        {
            Err(Error::WrongObject)
        } else {
            Ok(())
        }
    }
    fn check_done(self, record: Record) -> Result<(), Error> {
        self.check_actor(record)?;
        if record.nonce == self.nonce
            && record.object_id == 0
            && record.object_generation == 0
            && record.operation_id == self.operation
        {
            Ok(())
        } else {
            Err(Error::WrongObject)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientMode {
    AwaitConfigure,
    Registry,
    LaunchOwner,
    LaunchForeign,
    Done,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientAction {
    Configured,
    Lookup,
    Launch,
    ProbeForeign,
    Challenge(Record),
    Report(Record),
    Disconnect(Record),
    Done,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientPhase {
    AwaitConfigure,
    RegistryConfigured,
    RegistryConnected,
    RegistryExchanged,
    LaunchOwnerConfigured,
    LaunchOwnerAccepted,
    LaunchOwnerReported,
    LaunchForeignConfigured,
    LaunchForeignProbing,
    LaunchForeignReported,
    OrphanConfigured,
    OrphanReported,
    Done,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Client {
    correlation: Option<Correlation>,
    mode: ClientMode,
    phase: ClientPhase,
    config: Option<Record>,
    job_id: u64,
}

impl Client {
    pub fn registry_from_environment(entries: &[&str]) -> Result<Self, Error> {
        Ok(Self {
            correlation: Some(
                parse_correlation_environment(entries).map_err(|_| Error::Correlation)?,
            ),
            mode: ClientMode::AwaitConfigure,
            phase: ClientPhase::AwaitConfigure,
            config: None,
            job_id: 0,
        })
    }
    pub const fn launch() -> Self {
        Self {
            correlation: None,
            mode: ClientMode::AwaitConfigure,
            phase: ClientPhase::AwaitConfigure,
            config: None,
            job_id: 0,
        }
    }
    pub const fn mode(&self) -> ClientMode {
        self.mode
    }

    pub fn configure(&mut self, record: Record) -> Result<ClientAction, Error> {
        let replacement = self.phase == ClientPhase::RegistryExchanged
            && record.message_type == MessageType::ConfigureRegistryClient
            && record.operation_id == 2
            && self.config.is_some_and(|prior| {
                prior.operation_id == 1
                    && record.nonce == prior.nonce
                    && record.registry_generation == prior.registry_generation
            });
        if record.direction() != Direction::InitToChild
            || (self.phase != ClientPhase::AwaitConfigure && !replacement)
        {
            return Err(Error::WrongState);
        }
        let (mode, phase, action) = match record.message_type {
            MessageType::ConfigureRegistryClient => {
                let correlation = self.correlation.ok_or(Error::Correlation)?;
                if record.registry_generation != correlation.registry_generation
                    || record.actor_id != correlation.endpoint_id
                    || record.actor_generation != correlation.endpoint_generation
                {
                    return Err(Error::WrongActor);
                }
                if !replacement && record.operation_id != 1 {
                    return Err(Error::WrongOperation);
                }
                (
                    ClientMode::Registry,
                    ClientPhase::RegistryConfigured,
                    ClientAction::Lookup,
                )
            }
            MessageType::ConfigureLaunchOwner
                if self.correlation.is_none() && record.operation_id == 3 =>
            {
                (
                    ClientMode::LaunchOwner,
                    ClientPhase::LaunchOwnerConfigured,
                    ClientAction::Launch,
                )
            }
            MessageType::ConfigureLaunchOwner
                if self.correlation.is_none() && record.operation_id == 5 =>
            {
                (
                    ClientMode::LaunchOwner,
                    ClientPhase::OrphanConfigured,
                    ClientAction::Launch,
                )
            }
            MessageType::ConfigureLaunchForeign if self.correlation.is_none() => (
                ClientMode::LaunchForeign,
                ClientPhase::LaunchForeignConfigured,
                ClientAction::Configured,
            ),
            _ => return Err(Error::WrongState),
        };
        self.mode = mode;
        self.phase = phase;
        self.config = Some(record);
        Ok(action)
    }

    pub fn connected(&mut self) -> Result<(Record, Record), Error> {
        let config = self.require(ClientMode::Registry)?;
        if self.phase != ClientPhase::RegistryConfigured {
            return Err(Error::WrongState);
        }
        let connected = Record {
            message_type: MessageType::Connected,
            ..config
        };
        let mut direct = Record {
            message_type: MessageType::DirectChallenge,
            ..config
        };
        direct.value = challenge(direct);
        self.phase = ClientPhase::RegistryConnected;
        Ok((connected, direct))
    }

    /// Constructs a WRRG header from the exact configured RegistryClient correlation.
    pub fn registry_header(
        &self,
        message_type: RegistryMessageType,
    ) -> Result<RegistryHeader, Error> {
        let config = self.require(ClientMode::Registry)?;
        let correlation = self.correlation.ok_or(Error::Correlation)?;
        Ok(RegistryHeader {
            message_type,
            registry_generation: correlation.registry_generation,
            endpoint_id: correlation.endpoint_id,
            endpoint_generation: correlation.endpoint_generation,
            transaction_id: config.operation_id,
        })
    }

    pub fn direct_echo(&mut self, record: Record) -> Result<Record, Error> {
        let config = self.require(ClientMode::Registry)?;
        if self.phase != ClientPhase::RegistryConnected {
            return Err(Error::WrongState);
        }
        let expected = Record {
            message_type: MessageType::DirectEcho,
            actor_id: config.object_id,
            actor_generation: config.object_generation,
            object_id: config.actor_id,
            object_generation: config.actor_generation,
            value: challenge(Record {
                message_type: MessageType::DirectChallenge,
                ..config
            }),
            ..config
        };
        if record != expected {
            return Err(Error::WrongObject);
        }
        self.phase = ClientPhase::RegistryExchanged;
        Ok(Record {
            message_type: MessageType::Exchanged,
            value: record.value,
            ..config
        })
    }

    pub fn job_accepted(&mut self, job_id: u64) -> Result<ClientAction, Error> {
        let config = self.require(ClientMode::LaunchOwner)?;
        if job_id == 0
            || self.job_id != 0
            || !matches!(
                self.phase,
                ClientPhase::LaunchOwnerConfigured | ClientPhase::OrphanConfigured
            )
        {
            return Err(Error::WrongObject);
        }
        self.job_id = job_id;
        let report = Record {
            message_type: if config.operation_id == 5 {
                MessageType::OrphanDisconnecting
            } else {
                MessageType::JobAccepted
            },
            object_id: job_id,
            object_generation: config.actor_generation,
            ..config
        };
        if config.operation_id == 5 {
            self.phase = ClientPhase::OrphanReported;
            Ok(ClientAction::Disconnect(report))
        } else {
            self.phase = ClientPhase::LaunchOwnerAccepted;
            Ok(ClientAction::Report(report))
        }
    }

    pub fn job_result(&mut self, normal_exit_zero_cleanup_zero: bool) -> Result<Record, Error> {
        let config = self.require(ClientMode::LaunchOwner)?;
        if self.phase != ClientPhase::LaunchOwnerAccepted
            || config.operation_id != 3
            || self.job_id == 0
            || !normal_exit_zero_cleanup_zero
        {
            return Err(Error::NonzeroJobResult);
        }
        self.phase = ClientPhase::LaunchOwnerReported;
        Ok(Record {
            message_type: MessageType::JobResult,
            object_id: self.job_id,
            object_generation: config.actor_generation,
            ..config
        })
    }

    pub fn probe_foreign(&mut self, record: Record) -> Result<ClientAction, Error> {
        let config = self.require(ClientMode::LaunchForeign)?;
        if self.phase != ClientPhase::LaunchForeignConfigured
            || record.message_type != MessageType::ProbeForeign
            || record.direction() != Direction::InitToChild
            || record.nonce != config.nonce
            || record.registry_generation != config.registry_generation
            || record.actor_id != config.actor_id
            || record.actor_generation != config.actor_generation
            || record.object_id == 0
            || record.object_generation != config.object_generation
            || record.operation_id != 4
        {
            return Err(Error::WrongObject);
        }
        self.job_id = record.object_id;
        self.phase = ClientPhase::LaunchForeignProbing;
        Ok(ClientAction::ProbeForeign)
    }

    pub fn foreign_error(
        &mut self,
        probed_job: u64,
        exact_foreign_error: bool,
    ) -> Result<Record, Error> {
        let config = self.require(ClientMode::LaunchForeign)?;
        if self.phase != ClientPhase::LaunchForeignProbing
            || !exact_foreign_error
            || probed_job == 0
            || probed_job != self.job_id
        {
            return Err(Error::WrongObject);
        }
        self.phase = ClientPhase::LaunchForeignReported;
        Ok(Record {
            message_type: MessageType::ForeignRejected,
            object_id: probed_job,
            object_generation: config.object_generation,
            ..config
        })
    }

    pub fn done(&mut self, record: Record) -> Result<ClientAction, Error> {
        let config = self.config.ok_or(Error::WrongState)?;
        let terminal = matches!(
            self.phase,
            ClientPhase::RegistryExchanged
                | ClientPhase::LaunchOwnerReported
                | ClientPhase::LaunchForeignReported
                | ClientPhase::OrphanReported
        );
        if !terminal
            || record.message_type != MessageType::Done
            || record.direction() != Direction::InitToChild
            || record.nonce != config.nonce
            || record.registry_generation != config.registry_generation
            || record.actor_id != config.actor_id
            || record.actor_generation != config.actor_generation
            || record.object_id != 0
            || record.object_generation != 0
            || record.operation_id != config.operation_id
        {
            return Err(Error::WrongActor);
        }
        self.mode = ClientMode::Done;
        self.phase = ClientPhase::Done;
        Ok(ClientAction::Done)
    }

    fn require(self, mode: ClientMode) -> Result<Record, Error> {
        if self.mode == mode {
            self.config.ok_or(Error::WrongState)
        } else {
            Err(Error::WrongState)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrmroot_wyr1b_gate_proto::{RECORD_BYTES, encode, parse_for};

    const ENV: [&str; 3] = [
        "WYR_REGISTRY_GENERATION=11",
        "WYR_REGISTRY_ENDPOINT_ID=21",
        "WYR_REGISTRY_ENDPOINT_GENERATION=31",
    ];

    fn record(message_type: MessageType, actor: (u64, u64), object: (u64, u64), op: u64) -> Record {
        Record {
            message_type,
            nonce: 7,
            registry_generation: 11,
            actor_id: actor.0,
            actor_generation: actor.1,
            object_id: object.0,
            object_generation: object.1,
            operation_id: op,
            value: 0,
        }
    }

    fn wire(record: Record, direction: Direction) -> Record {
        let mut bytes = [0; RECORD_BYTES];
        encode(record, &mut bytes).unwrap();
        parse_for(&bytes, direction).unwrap()
    }

    #[test]
    fn startup_and_parent_direction_fail_closed() {
        for bad in [
            &ENV[..2],
            &[ENV[0], ENV[1], ENV[2], "WYR_REGISTRY_GENERATION=11"][..],
            &[ENV[1], ENV[0], ENV[2]][..],
            &["WYR_REGISTRY_GENERATION=0", ENV[1], ENV[2]][..],
            &["WYR_REGISTRY_GENERATION=01", ENV[1], ENV[2]][..],
        ] {
            assert_eq!(Publisher::from_environment(bad), Err(Error::Correlation));
            assert_eq!(
                Client::registry_from_environment(bad),
                Err(Error::Correlation)
            );
        }

        let mut publisher = Publisher::from_environment(&ENV).unwrap();
        assert_eq!(
            publisher.parent(record(MessageType::Published, (21, 31), (41, 51), 1)),
            Err(Error::Wire(WireError::WrongDirection))
        );
        assert_eq!(
            publisher.parent(record(
                MessageType::ConfigurePublisher,
                (22, 31),
                (41, 51),
                1
            )),
            Err(Error::WrongActor)
        );
    }

    #[test]
    fn failure_tracker_requires_ready_and_preserves_current_exact_context_once() {
        let first = record(MessageType::ConfigureRegistryClient, (21, 31), (61, 71), 1);
        let second = record(MessageType::ConfigureRegistryClient, (21, 31), (62, 72), 2);

        let mut before_ready = FailureTracker::new(Some(11));
        assert_eq!(before_ready.take(9), None);
        before_ready.mark_ready().unwrap();
        let preconfigure = before_ready.take(0x1_0000).unwrap();
        assert_eq!((preconfigure.actor_id, preconfigure.operation_id), (0, 1));
        assert_eq!(preconfigure.value, 1);
        assert_eq!(before_ready.take(2), None);

        let mut configured = FailureTracker::new(Some(11));
        configured.mark_ready().unwrap();
        configured.update(first).unwrap();
        let op1 = configured.take(0x1234).unwrap();
        assert_eq!(
            (
                op1.actor_id,
                op1.actor_generation,
                op1.operation_id,
                op1.value
            ),
            (21, 31, 1, 0x1234)
        );
        assert_eq!(configured.take(3), None);

        let mut replacement = FailureTracker::new(Some(11));
        replacement.mark_ready().unwrap();
        replacement.update(first).unwrap();
        // While op2 is only awaited or rejected, op1 remains current.
        assert_eq!(replacement.current.unwrap().operation_id, 1);
        replacement.update(second).unwrap();
        let op2 = replacement.take(7).unwrap();
        assert_eq!(
            (op2.actor_id, op2.actor_generation, op2.operation_id),
            (21, 31, 2)
        );

        let mut stale = FailureTracker::new(Some(11));
        stale.mark_ready().unwrap();
        stale
            .update(record(
                MessageType::ConfigurePublisher,
                (21, 31),
                (41, 51),
                1,
            ))
            .unwrap();
        stale
            .update(record(MessageType::StaleRejected, (21, 31), (22, 32), 2))
            .unwrap();
        assert_eq!(stale.take(8).unwrap().operation_id, 2);
    }

    #[test]
    fn publisher_publish_echo_retire_and_peer_close_stale_sequence_is_exact() {
        let mut publisher = Publisher::from_environment(&ENV).unwrap();
        let configure = wire(
            record(MessageType::ConfigurePublisher, (21, 31), (41, 51), 1),
            Direction::InitToChild,
        );
        assert_eq!(publisher.parent(configure), Ok(PublisherAction::Publish));
        assert_eq!(
            publisher
                .registry_header(RegistryMessageType::Publish)
                .unwrap()
                .transaction_id,
            1
        );
        assert_eq!(
            publisher.published().unwrap().message_type,
            MessageType::Published
        );
        let early_retire = wire(
            record(MessageType::Retire, (21, 31), (41, 51), 1),
            Direction::InitToChild,
        );
        assert_eq!(publisher.parent(early_retire), Err(Error::WrongState));
        publisher.connected().unwrap();

        let mut direct = record(MessageType::DirectChallenge, (41, 51), (21, 31), 1);
        direct.value = challenge(direct);
        let direct = wire(direct, Direction::ClientToDirect);
        let PublisherAction::Echo {
            direct: echo,
            report,
        } = publisher.direct(direct).unwrap()
        else {
            panic!("expected exact echo action");
        };
        assert_eq!(echo.message_type, MessageType::DirectEcho);
        assert_eq!(report.message_type, MessageType::Echoed);
        assert_eq!(echo.value, direct.value);

        let retire = wire(
            record(MessageType::Retire, (21, 31), (41, 51), 1),
            Direction::InitToChild,
        );
        assert_eq!(
            publisher
                .registry_header(RegistryMessageType::Retire)
                .unwrap()
                .transaction_id,
            2
        );
        assert_eq!(publisher.parent(retire), Ok(PublisherAction::Retire));
        assert_eq!(
            publisher.retired().unwrap().message_type,
            MessageType::Retired
        );
        assert_eq!(
            publisher.publication_peer_closed(false),
            Err(Error::PeerNotClosed)
        );
        publisher.publication_peer_closed(true).unwrap();
        let stale = wire(
            record(MessageType::ProbeStale, (21, 31), (22, 32), 2),
            Direction::InitToChild,
        );
        let PublisherAction::Report(stale) = publisher.parent(stale).unwrap() else {
            panic!("expected stale report");
        };
        assert_eq!(stale.message_type, MessageType::StaleRejected);
        let done = wire(
            record(MessageType::Done, (21, 31), (0, 0), 2),
            Direction::InitToChild,
        );
        assert_eq!(publisher.parent(done), Ok(PublisherAction::Done));
    }

    #[test]
    fn replacement_publisher_finishes_without_retirement() {
        let mut publisher = Publisher::from_environment(&ENV).unwrap();
        let configure = wire(
            record(MessageType::ConfigurePublisher, (21, 31), (41, 51), 2),
            Direction::InitToChild,
        );
        assert_eq!(publisher.parent(configure), Ok(PublisherAction::Publish));
        assert_eq!(
            publisher
                .registry_header(RegistryMessageType::Publish)
                .unwrap()
                .transaction_id,
            3
        );
        publisher.published().unwrap();
        publisher.connected().unwrap();
        let mut direct = record(MessageType::DirectChallenge, (41, 51), (21, 31), 2);
        direct.value = challenge(direct);
        publisher
            .direct(wire(direct, Direction::ClientToDirect))
            .unwrap();
        let wrong_done = wire(
            record(MessageType::Done, (21, 31), (0, 0), 1),
            Direction::InitToChild,
        );
        assert_eq!(publisher.parent(wrong_done), Err(Error::WrongObject));
        let done = wire(
            record(MessageType::Done, (21, 31), (0, 0), 2),
            Direction::InitToChild,
        );
        assert_eq!(publisher.parent(done), Ok(PublisherAction::Done));
    }

    #[test]
    fn registry_client_connect_exchange_and_replacement_are_exact() {
        let mut client = Client::registry_from_environment(&ENV).unwrap();
        let initial_op2 = wire(
            record(MessageType::ConfigureRegistryClient, (21, 31), (61, 71), 2),
            Direction::InitToChild,
        );
        assert_eq!(client.configure(initial_op2), Err(Error::WrongOperation));
        let first = wire(
            record(MessageType::ConfigureRegistryClient, (21, 31), (61, 71), 1),
            Direction::InitToChild,
        );
        assert_eq!(client.configure(first), Ok(ClientAction::Lookup));
        let (connected, direct) = client.connected().unwrap();
        assert_eq!(connected.message_type, MessageType::Connected);
        assert_eq!(direct.message_type, MessageType::DirectChallenge);
        assert_eq!(direct.value, challenge(direct));
        assert_eq!(client.connected(), Err(Error::WrongState));

        let echo = wire(
            Record {
                message_type: MessageType::DirectEcho,
                actor_id: direct.object_id,
                actor_generation: direct.object_generation,
                object_id: direct.actor_id,
                object_generation: direct.actor_generation,
                ..direct
            },
            Direction::PublisherToDirect,
        );
        assert_eq!(
            client.direct_echo(echo).unwrap().message_type,
            MessageType::Exchanged
        );

        let mut wrong_nonce = record(MessageType::ConfigureRegistryClient, (21, 31), (62, 72), 2);
        wrong_nonce.nonce = 8;
        let wrong_nonce = wire(wrong_nonce, Direction::InitToChild);
        assert_eq!(client.configure(wrong_nonce), Err(Error::WrongState));
        let replacement = wire(
            record(MessageType::ConfigureRegistryClient, (21, 31), (62, 72), 2),
            Direction::InitToChild,
        );
        assert_eq!(client.configure(replacement), Ok(ClientAction::Lookup));
        assert_eq!(
            client
                .registry_header(RegistryMessageType::LookupConnect)
                .unwrap()
                .transaction_id,
            2
        );
        let (_, direct) = client.connected().unwrap();
        let echo = wire(
            Record {
                message_type: MessageType::DirectEcho,
                actor_id: direct.object_id,
                actor_generation: direct.object_generation,
                object_id: direct.actor_id,
                object_generation: direct.actor_generation,
                ..direct
            },
            Direction::PublisherToDirect,
        );
        client.direct_echo(echo).unwrap();
        let wrong_done = wire(
            record(MessageType::Done, (21, 31), (0, 0), 1),
            Direction::InitToChild,
        );
        assert_eq!(client.done(wrong_done), Err(Error::WrongActor));
        let done = wire(
            record(MessageType::Done, (21, 31), (0, 0), 2),
            Direction::InitToChild,
        );
        assert_eq!(client.done(done), Ok(ClientAction::Done));
    }

    #[test]
    fn launch_owner_foreign_and_orphan_transitions_are_bounded() {
        let mut owner = Client::launch();
        let owner_config = wire(
            record(MessageType::ConfigureLaunchOwner, (81, 91), (0, 0), 3),
            Direction::InitToChild,
        );
        assert_eq!(owner.configure(owner_config), Ok(ClientAction::Launch));
        let ClientAction::Report(accepted) = owner.job_accepted(101).unwrap() else {
            panic!("expected accepted report");
        };
        assert_eq!(accepted.message_type, MessageType::JobAccepted);
        assert_eq!(owner.job_result(false), Err(Error::NonzeroJobResult));
        assert_eq!(
            owner.job_result(true).unwrap().message_type,
            MessageType::JobResult
        );
        assert_eq!(owner.job_result(true), Err(Error::NonzeroJobResult));

        let mut foreign = Client::launch();
        let foreign_config = wire(
            record(MessageType::ConfigureLaunchForeign, (82, 92), (81, 91), 4),
            Direction::InitToChild,
        );
        assert_eq!(
            foreign.configure(foreign_config),
            Ok(ClientAction::Configured)
        );
        assert_eq!(foreign.foreign_error(101, true), Err(Error::WrongObject));
        let probe = wire(
            record(MessageType::ProbeForeign, (82, 92), (101, 91), 4),
            Direction::InitToChild,
        );
        assert_eq!(foreign.probe_foreign(probe), Ok(ClientAction::ProbeForeign));
        assert_eq!(foreign.probe_foreign(probe), Err(Error::WrongObject));
        assert_eq!(foreign.foreign_error(101, false), Err(Error::WrongObject));
        assert_eq!(
            foreign.foreign_error(101, true).unwrap().message_type,
            MessageType::ForeignRejected
        );
        assert_eq!(foreign.foreign_error(101, true), Err(Error::WrongObject));

        let mut orphan = Client::launch();
        let orphan_config = wire(
            record(MessageType::ConfigureLaunchOwner, (83, 93), (0, 0), 5),
            Direction::InitToChild,
        );
        assert_eq!(orphan.configure(orphan_config), Ok(ClientAction::Launch));
        let ClientAction::Disconnect(report) = orphan.job_accepted(102).unwrap() else {
            panic!("expected orphan disconnect report");
        };
        assert_eq!(report.message_type, MessageType::OrphanDisconnecting);
        assert_eq!(orphan.job_accepted(103), Err(Error::WrongObject));
    }
}
