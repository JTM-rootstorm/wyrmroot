//! Devmgr side of the D3A split DeviceResource handoff.

use wyrmroot_device_proto::control_v1_1::{ControlIdentityV1_1, ControlMessageV1_1};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceStageState {
    ReadyToStage,
    AwaitingQuiesced,
    Quiesced,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceStageError {
    ZeroIdentity,
    WrongState,
    StaleReply,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceStageCoordinator {
    driver: ControlIdentityV1_1,
    stage_generation: u64,
    device_transaction_id: u64,
    state: DeviceStageState,
}

impl DeviceStageCoordinator {
    pub const fn new(
        driver: ControlIdentityV1_1,
        stage_generation: u64,
        device_transaction_id: u64,
    ) -> Result<Self, DeviceStageError> {
        if driver.role_id.0 == 0
            || driver.bundle_generation.0 == 0
            || driver.attempt_generation.0 == 0
            || driver.endpoint.id.0 == 0
            || driver.endpoint.generation.0 == 0
            || driver.transaction_id == 0
            || stage_generation == 0
            || device_transaction_id == 0
            || device_transaction_id == driver.transaction_id
        {
            return Err(DeviceStageError::ZeroIdentity);
        }
        Ok(Self {
            driver,
            stage_generation,
            device_transaction_id,
            state: DeviceStageState::ReadyToStage,
        })
    }

    pub const fn state(&self) -> DeviceStageState {
        self.state
    }

    pub const fn stage_generation(&self) -> u64 {
        self.stage_generation
    }

    pub const fn device_stage_message(&self) -> Result<ControlMessageV1_1, DeviceStageError> {
        if !matches!(self.state, DeviceStageState::ReadyToStage) {
            return Err(DeviceStageError::WrongState);
        }
        Ok(ControlMessageV1_1::DeviceStage {
            identity: ControlIdentityV1_1 {
                transaction_id: self.device_transaction_id,
                ..self.driver
            },
            stage_generation: self.stage_generation,
            resource_id: 1,
            pio_base: 0x2f8,
            pio_length: 8,
            source: 3,
        })
    }

    /// Native code calls this only after the exact one-handle DEVICE_STAGE
    /// MOVE commits atomically.
    pub fn device_stage_moved(&mut self) -> Result<(), DeviceStageError> {
        if self.state != DeviceStageState::ReadyToStage {
            return Err(DeviceStageError::WrongState);
        }
        self.state = DeviceStageState::AwaitingQuiesced;
        Ok(())
    }

    pub fn accept_device_quiesced(
        &mut self,
        message: ControlMessageV1_1,
    ) -> Result<(), DeviceStageError> {
        if self.state != DeviceStageState::AwaitingQuiesced {
            return Err(DeviceStageError::WrongState);
        }
        let expected = ControlMessageV1_1::DeviceQuiesced {
            identity: ControlIdentityV1_1 {
                transaction_id: self.device_transaction_id,
                ..self.driver
            },
            stage_generation: self.stage_generation,
        };
        if message != expected {
            return Err(DeviceStageError::StaleReply);
        }
        self.state = DeviceStageState::Quiesced;
        Ok(())
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

    fn driver() -> ControlIdentityV1_1 {
        ControlIdentityV1_1 {
            role_id: RoleId(1),
            bundle_generation: BundleGeneration(2),
            attempt_generation: AttemptGeneration(3),
            endpoint: ControlEndpoint {
                id: EndpointId(4),
                generation: EndpointGeneration(5),
            },
            transaction_id: 6,
        }
    }

    #[test]
    fn device_stage_is_one_way_until_exact_quiesced_reply() {
        let mut stage = DeviceStageCoordinator::new(driver(), 7, 8).unwrap();
        let message = stage.device_stage_message().unwrap();
        assert_eq!(message.handle_count(), 1);
        stage.device_stage_moved().unwrap();
        let stale = ControlMessageV1_1::DeviceQuiesced {
            identity: ControlIdentityV1_1 {
                transaction_id: 9,
                ..driver()
            },
            stage_generation: 7,
        };
        assert_eq!(
            stage.accept_device_quiesced(stale),
            Err(DeviceStageError::StaleReply)
        );
        let ControlMessageV1_1::DeviceStage {
            identity,
            stage_generation,
            ..
        } = message
        else {
            panic!("device stage");
        };
        stage
            .accept_device_quiesced(ControlMessageV1_1::DeviceQuiesced {
                identity,
                stage_generation,
            })
            .unwrap();
        assert_eq!(stage.state(), DeviceStageState::Quiesced);
    }
}
