//! Selector-private byte accounting and one-shot transport completion.

use wyrmroot_device_proto::d5_controller::{D5DrainIdentity, D5DriverIdentity};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainError {
    WrongIdentity,
    Duplicate,
    OverTarget,
    Incomplete,
}

pub struct DrainFence {
    driver: D5DriverIdentity,
    accepted: u64,
    acknowledged: bool,
    pending: Option<D5DrainIdentity>,
    completed: bool,
}

impl DrainFence {
    pub const fn new(driver: D5DriverIdentity) -> Self {
        Self {
            driver,
            accepted: 0,
            acknowledged: false,
            pending: None,
            completed: false,
        }
    }

    pub fn request(
        &mut self,
        identity: D5DrainIdentity,
        stream: Option<(u64, u64)>,
    ) -> Result<(), DrainError> {
        if self.pending.is_some() || self.completed {
            return Err(DrainError::Duplicate);
        }
        if identity.driver != self.driver
            || stream != Some((identity.attach_transaction_id, identity.stream_generation))
            || !matches!((identity.leg, identity.target_tx_bytes), (2, 45) | (4, 46))
        {
            return Err(DrainError::WrongIdentity);
        }
        if self.accepted > identity.target_tx_bytes {
            return Err(DrainError::OverTarget);
        }
        self.pending = Some(identity);
        Ok(())
    }

    /// Called for every normal payload, including payloads preceding the fence.
    pub fn accept(&mut self, length: usize) -> Result<(), DrainError> {
        if length == 0 {
            return Ok(());
        }
        let total = self
            .accepted
            .checked_add(length as u64)
            .ok_or(DrainError::OverTarget)?;
        if self.completed || total > self.pending.map_or(46, |p| p.target_tx_bytes) {
            return Err(DrainError::OverTarget);
        }
        self.accepted = total;
        self.acknowledged = false;
        Ok(())
    }

    pub fn irq_acknowledged(&mut self) {
        self.acknowledged = true;
    }

    pub const fn pending(&self) -> Option<D5DrainIdentity> {
        self.pending
    }

    pub fn ready(
        &self,
        fresh_channel_empty: bool,
        software_empty: bool,
        temt: bool,
    ) -> Option<D5DrainIdentity> {
        self.pending.filter(|p| {
            self.accepted == p.target_tx_bytes
                && self.acknowledged
                && fresh_channel_empty
                && software_empty
                && temt
        })
    }

    /// Called only after the exact TxDrained record was successfully sent.
    pub fn sent(&mut self, identity: D5DrainIdentity) -> Result<(), DrainError> {
        if self.pending != Some(identity) {
            return Err(DrainError::Incomplete);
        }
        self.pending = None;
        self.completed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const DRIVER: D5DriverIdentity = D5DriverIdentity {
        device_role_id: 1,
        bundle_generation: 1,
        driver_attempt_generation: 1,
        driver_control_endpoint_id: 1,
        driver_control_endpoint_generation: 1,
        launch_transaction_id: 1,
    };
    const FENCE: D5DrainIdentity = D5DrainIdentity {
        driver: DRIVER,
        attach_transaction_id: 5,
        stream_generation: 6,
        target_tx_bytes: 45,
        leg: 2,
    };

    #[test]
    fn queued_partial_and_previously_accepted_bytes_require_all_drain_facts() {
        let mut fence = DrainFence::new(DRIVER);
        fence.accept(23).unwrap();
        fence.irq_acknowledged();
        fence.request(FENCE, Some((5, 6))).unwrap();
        assert_eq!(fence.ready(true, true, true), None);
        fence.accept(22).unwrap();
        assert_eq!(fence.ready(true, true, true), None);
        fence.irq_acknowledged();
        assert_eq!(fence.ready(false, true, true), None);
        assert_eq!(fence.ready(true, false, true), None);
        assert_eq!(fence.ready(true, true, false), None);
        assert_eq!(fence.ready(true, true, true), Some(FENCE));
        // An unsuccessful send leaves the one pending identity intact.
        assert_eq!(fence.ready(true, true, true), Some(FENCE));
        fence.sent(FENCE).unwrap();
        assert_eq!(fence.ready(true, true, true), None);
        assert_eq!(
            fence.request(FENCE, Some((5, 6))),
            Err(DrainError::Duplicate)
        );
        assert!(fence.sent(FENCE).is_err());
    }

    #[test]
    fn wrong_stale_duplicate_and_over_target_fail() {
        let mut fence = DrainFence::new(DRIVER);
        assert!(fence.request(FENCE, Some((4, 6))).is_err());
        assert!(
            fence
                .request(
                    D5DrainIdentity {
                        driver: D5DriverIdentity {
                            launch_transaction_id: 2,
                            ..DRIVER
                        },
                        ..FENCE
                    },
                    Some((5, 6))
                )
                .is_err()
        );
        fence.request(FENCE, Some((5, 6))).unwrap();
        assert!(fence.request(FENCE, Some((5, 6))).is_err());
        assert!(fence.accept(46).is_err());
        let mut late = DrainFence::new(DRIVER);
        late.accept(46).unwrap();
        assert_eq!(
            late.request(FENCE, Some((5, 6))),
            Err(DrainError::OverTarget)
        );
        assert!(late.accept(1).is_err());
    }
}
