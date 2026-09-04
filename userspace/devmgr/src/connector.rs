//! Devmgr-owned WYR1-D direct serial connector transaction model.
//!
//! Native code owns actual Channel handles. This module names every ownership
//! transition so the native adapter never infers cleanup from event order.

use wyrmroot_device_proto::connector::{ConnectorErrorCode, ConnectorIdentity, ConnectorMessage};
use wyrmroot_device_proto::control::FailureCode;
use wyrmroot_device_proto::control_v1_1::{ControlIdentityV1_1, ControlMessageV1_1};
#[cfg(feature = "wyr1d-selector32")]
use wyrmroot_device_proto::{D5DriverIdentity, D5StreamIdentity};
use wyrmroot_device_proto::{PublicationPolicy, SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishedDriver {
    pub publication_generation: u64,
    pub control: ControlIdentityV1_1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachCorrelation {
    pub driver: PublishedDriver,
    pub client_transaction_id: u64,
    pub attach_transaction_id: u64,
    pub stream_generation: u64,
}

impl AttachCorrelation {
    pub const fn connector_identity(self) -> ConnectorIdentity {
        ConnectorIdentity {
            publication_generation: self.driver.publication_generation,
            client_transaction_id: self.client_transaction_id,
            device_role_id: self.driver.control.role_id.0,
            bundle_generation: self.driver.control.bundle_generation.0,
            driver_attempt_generation: self.driver.control.attempt_generation.0,
            driver_control_endpoint_id: self.driver.control.endpoint.id.0,
            driver_control_endpoint_generation: self.driver.control.endpoint.generation.0,
            attach_transaction_id: self.attach_transaction_id,
            stream_generation: self.stream_generation,
        }
    }

    #[cfg(feature = "wyr1d-selector32")]
    pub const fn d5_stream_identity(self) -> D5StreamIdentity {
        D5StreamIdentity {
            driver: self.driver.d5_identity(),
            publication_generation: self.driver.publication_generation,
            client_transaction_id: self.client_transaction_id,
            attach_transaction_id: self.attach_transaction_id,
            stream_generation: self.stream_generation,
        }
    }

    pub const fn attach_message(self) -> ControlMessageV1_1 {
        ControlMessageV1_1::AttachStream {
            identity: ControlIdentityV1_1 {
                transaction_id: self.attach_transaction_id,
                ..self.driver.control
            },
            stream_generation: self.stream_generation,
            publication_generation: self.driver.publication_generation,
        }
    }

    const fn ready_message(self) -> ControlMessageV1_1 {
        ControlMessageV1_1::StreamReady {
            identity: ControlIdentityV1_1 {
                transaction_id: self.attach_transaction_id,
                ..self.driver.control
            },
            stream_generation: self.stream_generation,
            publication_generation: self.driver.publication_generation,
        }
    }

    const fn detached_message(self) -> ControlMessageV1_1 {
        ControlMessageV1_1::StreamDetached {
            identity: ControlIdentityV1_1 {
                transaction_id: self.attach_transaction_id,
                ..self.driver.control
            },
            stream_generation: self.stream_generation,
            publication_generation: self.driver.publication_generation,
        }
    }
}

#[cfg(feature = "wyr1d-selector32")]
impl PublishedDriver {
    pub const fn d5_identity(self) -> D5DriverIdentity {
        D5DriverIdentity {
            device_role_id: self.control.role_id.0,
            bundle_generation: self.control.bundle_generation.0,
            driver_attempt_generation: self.control.attempt_generation.0,
            driver_control_endpoint_id: self.control.endpoint.id.0,
            driver_control_endpoint_generation: self.control.endpoint.generation.0,
            launch_transaction_id: self.control.transaction_id,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointOwner {
    Devmgr,
    Driver,
    Client,
    Released,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairOwnership {
    pub client: EndpointOwner,
    pub driver: EndpointOwner,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorSlot {
    Empty,
    PreMove {
        attach: AttachCorrelation,
        pair: PairOwnership,
    },
    PostMovePending {
        attach: AttachCorrelation,
        pair: PairOwnership,
    },
    ReadyToConnect {
        attach: AttachCorrelation,
        pair: PairOwnership,
    },
    Active {
        attach: AttachCorrelation,
        pair: PairOwnership,
    },
    AwaitingDriverRelease {
        attach: AttachCorrelation,
        pair: PairOwnership,
    },
    AwaitingClientRelease {
        attach: AttachCorrelation,
        pair: PairOwnership,
    },
    RetiringActive {
        attach: AttachCorrelation,
        pair: PairOwnership,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorAction {
    /// Native code creates one broad Channel pair; devmgr owns both endpoints.
    AllocatePair {
        attach: AttachCorrelation,
        driver_message: ControlMessageV1_1,
    },
    /// Native code atomically MOVEs only the driver endpoint over direct WRDC.
    MoveDriverEndpoint { attach: AttachCorrelation },
    /// Native code atomically MOVEs only the retained client endpoint in WRSC.
    MoveClientEndpoint { response: ConnectorMessage },
    /// Both endpoints remain in devmgr custody and must be closed in reverse
    /// construction order; neither handle ever crossed a Channel.
    ClosePreMovePair { attach: AttachCorrelation },
    /// Close the endpoint still retained by devmgr and ask the driver to close
    /// its already-moved peer.
    CloseRetainedClientAndRequestDriverRelease { attach: AttachCorrelation },
    /// Exact driver-reap proof released the moved endpoint. Native code closes
    /// only the client endpoint that never left devmgr custody.
    CloseRetainedClient { attach: AttachCorrelation },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorModelError {
    Busy,
    NotReady,
    Stale,
    InternalFailure,
}

impl ConnectorModelError {
    pub const fn wire_code(self) -> ConnectorErrorCode {
        match self {
            Self::Busy => ConnectorErrorCode::Busy,
            Self::NotReady => ConnectorErrorCode::NotReady,
            Self::Stale => ConnectorErrorCode::Stale,
            Self::InternalFailure => ConnectorErrorCode::InternalFailure,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorBroker {
    current: Option<PublishedDriver>,
    next_attach_transaction: u64,
    next_stream_generation: u64,
    slot: ConnectorSlot,
}

impl ConnectorBroker {
    pub const fn new(
        current: Option<PublishedDriver>,
        first_attach_transaction: u64,
        first_stream_generation: u64,
    ) -> Result<Self, ConnectorModelError> {
        if first_attach_transaction == 0 || first_stream_generation == 0 {
            return Err(ConnectorModelError::InternalFailure);
        }
        Ok(Self {
            current,
            next_attach_transaction: first_attach_transaction,
            next_stream_generation: first_stream_generation,
            slot: ConnectorSlot::Empty,
        })
    }

    /// The only publication metadata native WYR1-D connector routing may use.
    /// Historical selector-29 continues to use the separate 1.0 constant.
    pub const fn publication_policy() -> PublicationPolicy {
        SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY
    }

    pub const fn slot(&self) -> ConnectorSlot {
        self.slot
    }

    pub const fn current(&self) -> Option<PublishedDriver> {
        self.current
    }

    pub fn replace_published_driver(
        &mut self,
        replacement: PublishedDriver,
    ) -> Result<(), ConnectorModelError> {
        if !matches!(self.slot, ConnectorSlot::Empty)
            || self.current.is_some_and(|current| {
                replacement.publication_generation <= current.publication_generation
            })
            || replacement.publication_generation == 0
        {
            return Err(ConnectorModelError::Stale);
        }
        self.current = Some(replacement);
        Ok(())
    }

    pub fn begin_connect(
        &mut self,
        request: ConnectorMessage,
    ) -> Result<ConnectorAction, ConnectorModelError> {
        let ConnectorMessage::ConnectStream {
            publication_generation,
            client_transaction_id,
        } = request
        else {
            return Err(ConnectorModelError::Stale);
        };
        let current = self.current.ok_or(ConnectorModelError::NotReady)?;
        if publication_generation != current.publication_generation || client_transaction_id == 0 {
            return Err(ConnectorModelError::Stale);
        }
        if !matches!(self.slot, ConnectorSlot::Empty) {
            return Err(ConnectorModelError::Busy);
        }
        let next_attach = self
            .next_attach_transaction
            .checked_add(1)
            .ok_or(ConnectorModelError::InternalFailure)?;
        let next_stream = self
            .next_stream_generation
            .checked_add(1)
            .ok_or(ConnectorModelError::InternalFailure)?;
        let attach = AttachCorrelation {
            driver: current,
            client_transaction_id,
            attach_transaction_id: self.next_attach_transaction,
            stream_generation: self.next_stream_generation,
        };
        self.next_attach_transaction = next_attach;
        self.next_stream_generation = next_stream;
        self.slot = ConnectorSlot::PreMove {
            attach,
            pair: PairOwnership {
                client: EndpointOwner::Devmgr,
                driver: EndpointOwner::Devmgr,
            },
        };
        Ok(ConnectorAction::AllocatePair {
            attach,
            driver_message: attach.attach_message(),
        })
    }

    /// Records the atomic WRDC MOVE only after native Channel send succeeds.
    pub fn driver_endpoint_moved(
        &mut self,
        observed: AttachCorrelation,
    ) -> Result<ConnectorAction, ConnectorModelError> {
        let ConnectorSlot::PreMove { attach, mut pair } = self.slot else {
            return Err(ConnectorModelError::Stale);
        };
        if observed != attach {
            return Err(ConnectorModelError::Stale);
        }
        pair.driver = EndpointOwner::Driver;
        self.slot = ConnectorSlot::PostMovePending { attach, pair };
        Ok(ConnectorAction::MoveDriverEndpoint { attach })
    }

    /// Failed pre-MOVE sends leave both endpoints in devmgr custody for close.
    pub fn attach_send_failed(
        &mut self,
        observed: AttachCorrelation,
    ) -> Result<ConnectorAction, ConnectorModelError> {
        let ConnectorSlot::PreMove { attach, .. } = self.slot else {
            return Err(ConnectorModelError::Stale);
        };
        if observed != attach {
            return Err(ConnectorModelError::Stale);
        }
        self.slot = ConnectorSlot::Empty;
        Ok(ConnectorAction::ClosePreMovePair { attach })
    }

    pub fn accept_stream_ready(
        &mut self,
        message: ControlMessageV1_1,
    ) -> Result<(), ConnectorModelError> {
        let ConnectorSlot::PostMovePending { attach, pair } = self.slot else {
            return Err(ConnectorModelError::Stale);
        };
        if message != attach.ready_message() {
            return Err(ConnectorModelError::Stale);
        }
        self.slot = ConnectorSlot::ReadyToConnect { attach, pair };
        Ok(())
    }

    /// A bounded wait for STREAM_READY expired after the driver endpoint MOVE.
    /// Devmgr closes only its retained client endpoint and keeps the slot until
    /// STREAM_DETACHED or exact terminal-and-reaped attempt evidence proves the
    /// driver-owned endpoint was released. Direct-control peer close starts
    /// cleanup but is not stream-release proof by itself.
    pub fn pending_attach_timed_out(
        &mut self,
        observed: AttachCorrelation,
    ) -> Result<ConnectorAction, ConnectorModelError> {
        self.abort_post_move_pending(observed)
    }

    /// Accepts only an exact DRIVER_REJECTED response for the pending attach.
    /// Other failure identities/codes cannot tear down the current slot.
    pub fn pending_attach_rejected(
        &mut self,
        message: ControlMessageV1_1,
    ) -> Result<ConnectorAction, ConnectorModelError> {
        let ConnectorSlot::PostMovePending { attach, .. } = self.slot else {
            return Err(ConnectorModelError::Stale);
        };
        let ControlMessageV1_1::Failure { identity, code } = message else {
            return Err(ConnectorModelError::Stale);
        };
        if identity
            != (ControlIdentityV1_1 {
                transaction_id: attach.attach_transaction_id,
                ..attach.driver.control
            })
            || code != FailureCode::DriverRejected
        {
            return Err(ConnectorModelError::Stale);
        }
        self.abort_post_move_pending(attach)
    }

    fn abort_post_move_pending(
        &mut self,
        observed: AttachCorrelation,
    ) -> Result<ConnectorAction, ConnectorModelError> {
        let ConnectorSlot::PostMovePending { attach, mut pair } = self.slot else {
            return Err(ConnectorModelError::Stale);
        };
        if observed != attach
            || pair.client != EndpointOwner::Devmgr
            || pair.driver != EndpointOwner::Driver
        {
            return Err(ConnectorModelError::Stale);
        }
        pair.client = EndpointOwner::Released;
        self.slot = ConnectorSlot::AwaitingDriverRelease { attach, pair };
        Ok(ConnectorAction::CloseRetainedClientAndRequestDriverRelease { attach })
    }

    pub fn connected_response(&self) -> Result<ConnectorMessage, ConnectorModelError> {
        let ConnectorSlot::ReadyToConnect { attach, .. } = self.slot else {
            return Err(ConnectorModelError::Stale);
        };
        Ok(ConnectorMessage::Connected {
            identity: attach.connector_identity(),
        })
    }

    /// Records the atomic WRSC client-endpoint MOVE only after send succeeds.
    pub fn client_endpoint_moved(&mut self) -> Result<ConnectorAction, ConnectorModelError> {
        let ConnectorSlot::ReadyToConnect { attach, mut pair } = self.slot else {
            return Err(ConnectorModelError::Stale);
        };
        pair.client = EndpointOwner::Client;
        self.slot = ConnectorSlot::Active { attach, pair };
        Ok(ConnectorAction::MoveClientEndpoint {
            response: ConnectorMessage::Connected {
                identity: attach.connector_identity(),
            },
        })
    }

    pub fn connected_send_failed(&mut self) -> Result<ConnectorAction, ConnectorModelError> {
        let ConnectorSlot::ReadyToConnect { attach, mut pair } = self.slot else {
            return Err(ConnectorModelError::Stale);
        };
        pair.client = EndpointOwner::Released;
        self.slot = ConnectorSlot::AwaitingDriverRelease { attach, pair };
        Ok(ConnectorAction::CloseRetainedClientAndRequestDriverRelease { attach })
    }

    pub fn active_client_released(
        &mut self,
        observed: AttachCorrelation,
    ) -> Result<(), ConnectorModelError> {
        let ConnectorSlot::Active { attach, mut pair } = self.slot else {
            return Err(ConnectorModelError::Stale);
        };
        if observed != attach {
            return Err(ConnectorModelError::Stale);
        }
        pair.client = EndpointOwner::Released;
        self.slot = ConnectorSlot::AwaitingDriverRelease { attach, pair };
        Ok(())
    }

    pub fn driver_detached(
        &mut self,
        message: ControlMessageV1_1,
    ) -> Result<(), ConnectorModelError> {
        let (attach, mut pair, retiring) = match self.slot {
            ConnectorSlot::Active { attach, pair } => (attach, pair, false),
            ConnectorSlot::AwaitingDriverRelease { attach, pair } => (attach, pair, false),
            ConnectorSlot::RetiringActive { attach, pair } => (attach, pair, true),
            _ => return Err(ConnectorModelError::Stale),
        };
        if message != attach.detached_message() || pair.driver != EndpointOwner::Driver {
            return Err(ConnectorModelError::Stale);
        }
        pair.driver = EndpointOwner::Released;
        if pair.client == EndpointOwner::Released {
            self.slot = ConnectorSlot::Empty;
        } else if retiring {
            self.slot = ConnectorSlot::RetiringActive { attach, pair };
        } else {
            self.slot = ConnectorSlot::AwaitingClientRelease { attach, pair };
        }
        Ok(())
    }

    pub fn client_release_observed(
        &mut self,
        observed: AttachCorrelation,
    ) -> Result<(), ConnectorModelError> {
        let (attach, mut pair, retiring) = match self.slot {
            ConnectorSlot::AwaitingClientRelease { attach, pair } => (attach, pair, false),
            ConnectorSlot::RetiringActive { attach, pair } => (attach, pair, true),
            _ => return Err(ConnectorModelError::Stale),
        };
        if observed != attach || pair.client != EndpointOwner::Client {
            return Err(ConnectorModelError::Stale);
        }
        pair.client = EndpointOwner::Released;
        if pair.driver == EndpointOwner::Released {
            self.slot = ConnectorSlot::Empty;
        } else if retiring {
            self.slot = ConnectorSlot::RetiringActive { attach, pair };
        } else {
            self.slot = ConnectorSlot::AwaitingDriverRelease { attach, pair };
        }
        Ok(())
    }

    /// Selector-31 type-7 FinalizeRetire is the controller's certificate that
    /// the externally-owned client endpoint was closed by the retained probe.
    /// It is valid only for the current active attach; validate everything
    /// before changing ownership so an early, stale, or duplicate certificate
    /// cannot make a replacement admissible.
    pub fn selector_finalize_client_release(
        &mut self,
        observed_driver: PublishedDriver,
        observed_stream_generation: u64,
    ) -> Result<AttachCorrelation, ConnectorModelError> {
        let ConnectorSlot::Active { attach, .. } = self.slot else {
            return Err(ConnectorModelError::Stale);
        };
        if self.current != Some(observed_driver)
            || attach.driver != observed_driver
            || attach.stream_generation != observed_stream_generation
        {
            return Err(ConnectorModelError::Stale);
        }
        let _ = self.retire_current();
        self.client_release_observed(attach)?;
        Ok(attach)
    }

    /// D5 accepts a consoled release certificate only after exact driver-reap
    /// proof has moved the active slot to `AwaitingClientRelease`. All fields
    /// are checked before ownership changes, so stale, wrong, early, and
    /// duplicate certificates are non-mutating.
    #[cfg(feature = "wyr1d-selector32")]
    pub fn selector32_certify_client_release(
        &mut self,
        observed: D5StreamIdentity,
    ) -> Result<AttachCorrelation, ConnectorModelError> {
        let ConnectorSlot::AwaitingClientRelease { attach, .. } = self.slot else {
            return Err(ConnectorModelError::Stale);
        };
        if attach.d5_stream_identity() != observed {
            return Err(ConnectorModelError::Stale);
        }
        self.client_release_observed(attach)?;
        Ok(attach)
    }

    /// Records supervisor/reaper proof that one exact driver attempt is
    /// terminal. Process teardown, not devmgr, releases any endpoint that was
    /// already MOVEd into the driver. Stale attempt evidence is non-mutating.
    pub fn driver_attempt_reaped(
        &mut self,
        observed: PublishedDriver,
    ) -> Result<Option<ConnectorAction>, ConnectorModelError> {
        let slot_before = self.slot;
        let slot_driver = match slot_before {
            ConnectorSlot::Empty => None,
            ConnectorSlot::PreMove { attach, .. }
            | ConnectorSlot::PostMovePending { attach, .. }
            | ConnectorSlot::ReadyToConnect { attach, .. }
            | ConnectorSlot::Active { attach, .. }
            | ConnectorSlot::AwaitingDriverRelease { attach, .. }
            | ConnectorSlot::AwaitingClientRelease { attach, .. }
            | ConnectorSlot::RetiringActive { attach, .. } => Some(attach.driver),
        };
        let exact_slot = slot_driver == Some(observed);
        let exact_current = self.current == Some(observed);
        if !exact_slot && !exact_current {
            return Err(ConnectorModelError::Stale);
        }

        if exact_current {
            self.current = None;
        }
        let action = match slot_before {
            ConnectorSlot::Empty => None,
            ConnectorSlot::PreMove { attach, .. } => {
                self.slot = ConnectorSlot::Empty;
                Some(ConnectorAction::ClosePreMovePair { attach })
            }
            ConnectorSlot::PostMovePending { attach, .. }
            | ConnectorSlot::ReadyToConnect { attach, .. } => {
                // Reaping proves the driver-owned endpoint is already gone.
                // Only the still-local client endpoint may be closed here.
                self.slot = ConnectorSlot::Empty;
                Some(ConnectorAction::CloseRetainedClient { attach })
            }
            ConnectorSlot::Active { attach, mut pair }
            | ConnectorSlot::AwaitingClientRelease { attach, mut pair } => {
                pair.driver = EndpointOwner::Released;
                self.slot = if pair.client == EndpointOwner::Released {
                    ConnectorSlot::Empty
                } else {
                    ConnectorSlot::AwaitingClientRelease { attach, pair }
                };
                None
            }
            ConnectorSlot::AwaitingDriverRelease { attach, mut pair } => {
                pair.driver = EndpointOwner::Released;
                self.slot = if pair.client == EndpointOwner::Released {
                    ConnectorSlot::Empty
                } else {
                    ConnectorSlot::AwaitingClientRelease { attach, pair }
                };
                None
            }
            ConnectorSlot::RetiringActive { attach, mut pair } => {
                pair.driver = EndpointOwner::Released;
                self.slot = if pair.client == EndpointOwner::Released {
                    ConnectorSlot::Empty
                } else {
                    ConnectorSlot::RetiringActive { attach, pair }
                };
                None
            }
        };
        Ok(action)
    }

    /// Prevents new connection attempts immediately. Moved endpoints remain
    /// attributed to their owners until exact release observations arrive.
    pub fn retire_current(&mut self) -> Option<ConnectorAction> {
        self.current = None;
        match self.slot {
            ConnectorSlot::PreMove { attach, .. } => {
                self.slot = ConnectorSlot::Empty;
                Some(ConnectorAction::ClosePreMovePair { attach })
            }
            ConnectorSlot::PostMovePending { attach, mut pair }
            | ConnectorSlot::ReadyToConnect { attach, mut pair } => {
                pair.client = EndpointOwner::Released;
                self.slot = ConnectorSlot::AwaitingDriverRelease { attach, pair };
                Some(ConnectorAction::CloseRetainedClientAndRequestDriverRelease { attach })
            }
            ConnectorSlot::Active { attach, pair }
            | ConnectorSlot::AwaitingClientRelease { attach, pair }
            | ConnectorSlot::AwaitingDriverRelease { attach, pair } => {
                self.slot = ConnectorSlot::RetiringActive { attach, pair };
                None
            }
            ConnectorSlot::RetiringActive { .. } | ConnectorSlot::Empty => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrmroot_device_proto::control::ControlEndpoint;
    use wyrmroot_device_proto::coordinator::{
        AttemptGeneration, BundleGeneration, EndpointGeneration, EndpointId,
    };
    use wyrmroot_device_proto::manifest::RoleId;

    fn driver(publication: u64, attempt: u64) -> PublishedDriver {
        PublishedDriver {
            publication_generation: publication,
            control: ControlIdentityV1_1 {
                role_id: RoleId(1),
                bundle_generation: BundleGeneration(2),
                attempt_generation: AttemptGeneration(attempt),
                endpoint: ControlEndpoint {
                    id: EndpointId(4),
                    generation: EndpointGeneration(attempt),
                },
                transaction_id: 5,
            },
        }
    }

    fn attach_once(broker: &mut ConnectorBroker, publication: u64, tx: u64) -> AttachCorrelation {
        let ConnectorAction::AllocatePair { attach, .. } = broker
            .begin_connect(ConnectorMessage::ConnectStream {
                publication_generation: publication,
                client_transaction_id: tx,
            })
            .unwrap()
        else {
            panic!("allocate pair");
        };
        broker.driver_endpoint_moved(attach).unwrap();
        broker.accept_stream_ready(attach.ready_message()).unwrap();
        assert_eq!(
            broker.connected_response().unwrap(),
            ConnectorMessage::Connected {
                identity: attach.connector_identity()
            }
        );
        broker.client_endpoint_moved().unwrap();
        attach
    }

    fn begin_moved(broker: &mut ConnectorBroker, publication: u64, tx: u64) -> AttachCorrelation {
        let ConnectorAction::AllocatePair { attach, .. } = broker
            .begin_connect(ConnectorMessage::ConnectStream {
                publication_generation: publication,
                client_transaction_id: tx,
            })
            .unwrap()
        else {
            panic!("allocate pair");
        };
        broker.driver_endpoint_moved(attach).unwrap();
        attach
    }

    #[test]
    fn minor_one_policy_and_one_direct_client_reconnect_are_explicit() {
        assert_eq!(ConnectorBroker::publication_policy().protocol_minor, 1);
        let mut broker = ConnectorBroker::new(Some(driver(10, 1)), 100, 200).unwrap();
        let first = attach_once(&mut broker, 10, 7);
        assert_eq!(
            broker.begin_connect(ConnectorMessage::ConnectStream {
                publication_generation: 10,
                client_transaction_id: 8,
            }),
            Err(ConnectorModelError::Busy)
        );
        broker.active_client_released(first).unwrap();
        broker.driver_detached(first.detached_message()).unwrap();
        assert_eq!(broker.slot(), ConnectorSlot::Empty);
        let second = attach_once(&mut broker, 10, 9);
        assert!(second.stream_generation > first.stream_generation);
        assert!(second.attach_transaction_id > first.attach_transaction_id);
    }

    #[test]
    fn stale_ready_and_post_move_failure_do_not_lose_ownership() {
        let mut broker = ConnectorBroker::new(Some(driver(10, 1)), 100, 200).unwrap();
        let ConnectorAction::AllocatePair { attach, .. } = broker
            .begin_connect(ConnectorMessage::ConnectStream {
                publication_generation: 10,
                client_transaction_id: 7,
            })
            .unwrap()
        else {
            panic!("allocate pair");
        };
        broker.driver_endpoint_moved(attach).unwrap();
        let stale = AttachCorrelation {
            stream_generation: attach.stream_generation + 1,
            ..attach
        };
        assert_eq!(
            broker.accept_stream_ready(stale.ready_message()),
            Err(ConnectorModelError::Stale)
        );
        broker.accept_stream_ready(attach.ready_message()).unwrap();
        let action = broker.connected_send_failed().unwrap();
        assert_eq!(
            action,
            ConnectorAction::CloseRetainedClientAndRequestDriverRelease { attach }
        );
        broker.driver_detached(attach.detached_message()).unwrap();
        assert_eq!(broker.slot(), ConnectorSlot::Empty);
    }

    #[test]
    fn replacement_requires_empty_cleanup_and_strictly_new_publication() {
        let mut broker = ConnectorBroker::new(Some(driver(10, 1)), 100, 200).unwrap();
        let active = attach_once(&mut broker, 10, 7);
        assert_eq!(
            broker.replace_published_driver(driver(11, 2)),
            Err(ConnectorModelError::Stale)
        );
        broker.retire_current();
        broker.driver_detached(active.detached_message()).unwrap();
        broker.client_release_observed(active).unwrap();
        broker.replace_published_driver(driver(11, 2)).unwrap();
        assert_eq!(broker.current(), Some(driver(11, 2)));
    }

    #[test]
    fn pending_timeout_closes_only_retained_client_until_exact_driver_release() {
        let mut broker = ConnectorBroker::new(Some(driver(10, 1)), 100, 200).unwrap();
        let attach = begin_moved(&mut broker, 10, 7);
        assert_eq!(
            broker.pending_attach_timed_out(attach).unwrap(),
            ConnectorAction::CloseRetainedClientAndRequestDriverRelease { attach }
        );
        assert!(matches!(
            broker.slot(),
            ConnectorSlot::AwaitingDriverRelease {
                pair: PairOwnership {
                    client: EndpointOwner::Released,
                    driver: EndpointOwner::Driver
                },
                ..
            }
        ));
        assert_eq!(
            broker.accept_stream_ready(attach.ready_message()),
            Err(ConnectorModelError::Stale)
        );
        assert_eq!(
            broker.begin_connect(ConnectorMessage::ConnectStream {
                publication_generation: 10,
                client_transaction_id: 8,
            }),
            Err(ConnectorModelError::Busy)
        );
        broker.driver_detached(attach.detached_message()).unwrap();
        assert_eq!(broker.slot(), ConnectorSlot::Empty);
        assert!(
            broker
                .begin_connect(ConnectorMessage::ConnectStream {
                    publication_generation: 10,
                    client_transaction_id: 8,
                })
                .is_ok()
        );
    }

    #[test]
    fn driver_rejection_requires_exact_identity_then_release_proof() {
        let mut broker = ConnectorBroker::new(Some(driver(10, 1)), 100, 200).unwrap();
        let attach = begin_moved(&mut broker, 10, 7);
        let wrong_code = ControlMessageV1_1::Failure {
            identity: ControlIdentityV1_1 {
                transaction_id: attach.attach_transaction_id,
                ..attach.driver.control
            },
            code: FailureCode::DriverExited,
        };
        assert_eq!(
            broker.pending_attach_rejected(wrong_code),
            Err(ConnectorModelError::Stale)
        );
        assert!(matches!(
            broker.slot(),
            ConnectorSlot::PostMovePending { .. }
        ));

        let rejection = ControlMessageV1_1::Failure {
            identity: ControlIdentityV1_1 {
                transaction_id: attach.attach_transaction_id,
                ..attach.driver.control
            },
            code: FailureCode::DriverRejected,
        };
        assert_eq!(
            broker.pending_attach_rejected(rejection).unwrap(),
            ConnectorAction::CloseRetainedClientAndRequestDriverRelease { attach }
        );
        assert!(matches!(
            broker.slot(),
            ConnectorSlot::AwaitingDriverRelease { .. }
        ));
        broker.driver_detached(attach.detached_message()).unwrap();
        assert_eq!(broker.slot(), ConnectorSlot::Empty);
    }

    #[test]
    fn exact_reaped_pending_attempt_closes_only_retained_client_and_clears() {
        let published = driver(10, 1);
        let mut broker = ConnectorBroker::new(Some(published), 100, 200).unwrap();
        let attach = begin_moved(&mut broker, 10, 7);
        assert_eq!(
            broker.driver_attempt_reaped(published).unwrap(),
            Some(ConnectorAction::CloseRetainedClient { attach })
        );
        assert_eq!(broker.current(), None);
        assert_eq!(broker.slot(), ConnectorSlot::Empty);
        broker.replace_published_driver(driver(11, 2)).unwrap();
    }

    #[test]
    fn exact_reaped_active_attempt_waits_for_client_peer_close_then_clears() {
        let published = driver(10, 1);
        let mut broker = ConnectorBroker::new(Some(published), 100, 200).unwrap();
        let attach = attach_once(&mut broker, 10, 7);
        assert_eq!(broker.driver_attempt_reaped(published).unwrap(), None);
        assert_eq!(broker.current(), None);
        assert!(matches!(
            broker.slot(),
            ConnectorSlot::AwaitingClientRelease {
                pair: PairOwnership {
                    client: EndpointOwner::Client,
                    driver: EndpointOwner::Released
                },
                ..
            }
        ));
        broker.client_release_observed(attach).unwrap();
        assert_eq!(broker.slot(), ConnectorSlot::Empty);
        broker.replace_published_driver(driver(11, 2)).unwrap();
    }

    #[test]
    fn selector_finalize_certifies_client_release_then_exact_reap_opens_replacement() {
        let published = driver(10, 1);
        let mut broker = ConnectorBroker::new(Some(published), 100, 200).unwrap();
        let attach = attach_once(&mut broker, 10, 7);
        assert_eq!(
            broker
                .selector_finalize_client_release(published, attach.stream_generation)
                .unwrap(),
            attach
        );
        assert!(matches!(
            broker.slot(),
            ConnectorSlot::RetiringActive { .. }
        ));
        assert_eq!(
            broker.begin_connect(ConnectorMessage::ConnectStream {
                publication_generation: 10,
                client_transaction_id: 8,
            }),
            Err(ConnectorModelError::NotReady)
        );
        assert_eq!(broker.driver_attempt_reaped(published).unwrap(), None);
        assert_eq!(broker.slot(), ConnectorSlot::Empty);
        broker.replace_published_driver(driver(11, 2)).unwrap();
    }

    #[test]
    fn selector_finalize_rejects_early_duplicate_and_mismatched_attach_without_mutation() {
        let published = driver(10, 1);
        let mut broker = ConnectorBroker::new(Some(published), 100, 200).unwrap();
        assert_eq!(
            broker.selector_finalize_client_release(published, 200),
            Err(ConnectorModelError::Stale)
        );
        let attach = attach_once(&mut broker, 10, 7);
        let before = broker.slot();
        assert_eq!(
            broker.selector_finalize_client_release(published, attach.stream_generation + 1),
            Err(ConnectorModelError::Stale)
        );
        assert_eq!(broker.slot(), before);
        broker
            .selector_finalize_client_release(published, attach.stream_generation)
            .unwrap();
        let after = broker.slot();
        assert_eq!(
            broker.selector_finalize_client_release(published, attach.stream_generation),
            Err(ConnectorModelError::Stale)
        );
        assert_eq!(broker.slot(), after);
    }

    #[test]
    fn selector_reap_before_client_certificate_keeps_u2_blocked() {
        let published = driver(10, 1);
        let mut broker = ConnectorBroker::new(Some(published), 100, 200).unwrap();
        let attach = attach_once(&mut broker, 10, 7);
        assert_eq!(broker.driver_attempt_reaped(published).unwrap(), None);
        let before = broker.slot();
        assert_eq!(
            broker.selector_finalize_client_release(published, attach.stream_generation),
            Err(ConnectorModelError::Stale)
        );
        assert_eq!(broker.slot(), before);
        assert_eq!(
            broker.replace_published_driver(driver(11, 2)),
            Err(ConnectorModelError::Stale)
        );
    }

    #[cfg(feature = "wyr1d-selector32")]
    #[test]
    fn selector32_release_requires_exact_post_reap_stream_identity() {
        let published = driver(10, 1);
        let mut broker = ConnectorBroker::new(Some(published), 100, 200).unwrap();
        let attach = attach_once(&mut broker, 10, 7);
        assert_eq!(
            broker.selector32_certify_client_release(attach.d5_stream_identity()),
            Err(ConnectorModelError::Stale)
        );
        assert_eq!(broker.driver_attempt_reaped(published), Ok(None));
        let before = broker.slot();
        let mut stale = attach.d5_stream_identity();
        stale.stream_generation += 1;
        assert_eq!(
            broker.selector32_certify_client_release(stale),
            Err(ConnectorModelError::Stale)
        );
        assert_eq!(broker.slot(), before);
        assert_eq!(
            broker.selector32_certify_client_release(attach.d5_stream_identity()),
            Ok(attach)
        );
        assert_eq!(broker.slot(), ConnectorSlot::Empty);
        assert_eq!(
            broker.selector32_certify_client_release(attach.d5_stream_identity()),
            Err(ConnectorModelError::Stale)
        );
        assert_eq!(broker.slot(), ConnectorSlot::Empty);
    }

    #[test]
    fn stale_reaped_attempt_cannot_mutate_current_or_active_slot() {
        let published = driver(10, 1);
        let mut broker = ConnectorBroker::new(Some(published), 100, 200).unwrap();
        attach_once(&mut broker, 10, 7);
        let before_slot = broker.slot();
        assert_eq!(
            broker.driver_attempt_reaped(driver(10, 2)),
            Err(ConnectorModelError::Stale)
        );
        assert_eq!(broker.current(), Some(published));
        assert_eq!(broker.slot(), before_slot);
    }
}
