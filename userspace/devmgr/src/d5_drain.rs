//! One outstanding selector-private drain relay, tied to the active connector.

use crate::connector::{ConnectorBroker, ConnectorSlot};
use wyrmroot_device_proto::d5_controller::D5DrainIdentity;

#[derive(Default)]
pub struct DrainRelay {
    pending: Option<D5DrainIdentity>,
    completed: Option<D5DrainIdentity>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidDrain;

impl DrainRelay {
    pub fn request(
        &mut self,
        identity: D5DrainIdentity,
        broker: &ConnectorBroker,
    ) -> Result<(), InvalidDrain> {
        if self.pending.is_some()
            || self
                .completed
                .is_some_and(|old| old.driver == identity.driver)
            || !matches!((identity.leg, identity.target_tx_bytes), (2, 45) | (4, 46))
            || !active_matches(identity, broker)
        {
            return Err(InvalidDrain);
        }
        self.pending = Some(identity);
        Ok(())
    }

    pub fn validate_completion(
        &self,
        identity: D5DrainIdentity,
        broker: &ConnectorBroker,
    ) -> Result<(), InvalidDrain> {
        if self.pending != Some(identity) || !active_matches(identity, broker) {
            return Err(InvalidDrain);
        }
        Ok(())
    }

    /// Commit only after forwarding TxDrained to the controller succeeds.
    pub fn forwarded(&mut self, identity: D5DrainIdentity) -> Result<(), InvalidDrain> {
        if self.pending != Some(identity) {
            return Err(InvalidDrain);
        }
        self.pending = None;
        self.completed = Some(identity);
        Ok(())
    }

    pub fn permits_retire(
        &self,
        driver: wyrmroot_device_proto::d5_controller::D5DriverIdentity,
    ) -> bool {
        self.pending.is_none()
            && self
                .completed
                .is_some_and(|p| p.driver == driver && p.leg == 2)
    }
}

fn active_matches(identity: D5DrainIdentity, broker: &ConnectorBroker) -> bool {
    matches!(broker.slot(), ConnectorSlot::Active { attach, .. }
        if broker.current() == Some(attach.driver)
            && identity.driver == attach.driver.d5_identity()
            && identity.attach_transaction_id == attach.attach_transaction_id
            && identity.stream_generation == attach.stream_generation)
}
