//! Devmgr side of the D3A split DeviceResource handoff.

use wyrmroot_device_proto::control_v1_1::{ControlIdentityV1_1, ControlMessageV1_1};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageGeneration(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D3StageCorrelations {
    pub stage_generation: StageGeneration,
    pub device_transaction_id: u64,
    pub interrupt_transaction_id: u64,
    pub ready_transaction_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceStageState {
    ReadyToStage,
    AwaitingQuiesced,
    Quiesced,
    InterruptOwned,
    AwaitingReady,
    DriverReady,
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
    interrupt_transaction_id: u64,
    state: DeviceStageState,
}

impl DeviceStageCoordinator {
    pub const fn new(
        driver: ControlIdentityV1_1,
        correlations: D3StageCorrelations,
    ) -> Result<Self, DeviceStageError> {
        let stage_generation = correlations.stage_generation.0;
        let device_transaction_id = correlations.device_transaction_id;
        let interrupt_transaction_id = correlations.interrupt_transaction_id;
        if driver.role_id.0 == 0
            || driver.bundle_generation.0 == 0
            || driver.attempt_generation.0 == 0
            || driver.endpoint.id.0 == 0
            || driver.endpoint.generation.0 == 0
            || driver.transaction_id == 0
            || stage_generation == 0
            || device_transaction_id == 0
            || device_transaction_id == driver.transaction_id
            || interrupt_transaction_id == 0
            || interrupt_transaction_id == driver.transaction_id
            || interrupt_transaction_id == device_transaction_id
            || correlations.ready_transaction_id != driver.transaction_id
        {
            return Err(DeviceStageError::ZeroIdentity);
        }
        Ok(Self {
            driver,
            stage_generation,
            device_transaction_id,
            interrupt_transaction_id,
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

    /// Records a freshly created, locally owned Interrupt. Native code may
    /// call this only after creation and exact object-info validation.
    pub fn interrupt_created(&mut self) -> Result<(), DeviceStageError> {
        if self.state != DeviceStageState::Quiesced {
            return Err(DeviceStageError::WrongState);
        }
        self.state = DeviceStageState::InterruptOwned;
        Ok(())
    }

    pub const fn interrupt_stage_message(&self) -> Result<ControlMessageV1_1, DeviceStageError> {
        if !matches!(self.state, DeviceStageState::InterruptOwned) {
            return Err(DeviceStageError::WrongState);
        }
        Ok(ControlMessageV1_1::InterruptStage {
            identity: ControlIdentityV1_1 {
                transaction_id: self.interrupt_transaction_id,
                ..self.driver
            },
            stage_generation: self.stage_generation,
            parent_resource_id: 1,
            source: 3,
        })
    }

    /// Native code calls this only after the exact one-handle Interrupt MOVE
    /// commits. A send failure leaves the fresh Interrupt owned by devmgr.
    pub fn interrupt_stage_moved(&mut self) -> Result<(), DeviceStageError> {
        if self.state != DeviceStageState::InterruptOwned {
            return Err(DeviceStageError::WrongState);
        }
        self.state = DeviceStageState::AwaitingReady;
        Ok(())
    }

    pub fn accept_driver_ready(
        &mut self,
        message: ControlMessageV1_1,
    ) -> Result<(), DeviceStageError> {
        if self.state != DeviceStageState::AwaitingReady {
            return Err(DeviceStageError::WrongState);
        }
        let expected = ControlMessageV1_1::Ready {
            identity: self.driver,
        };
        if message != expected {
            return Err(DeviceStageError::StaleReply);
        }
        self.state = DeviceStageState::DriverReady;
        Ok(())
    }

    pub const fn ready_identity(&self) -> ControlIdentityV1_1 {
        self.driver
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
        let correlations = D3StageCorrelations {
            stage_generation: StageGeneration(7),
            device_transaction_id: 8,
            interrupt_transaction_id: 9,
            ready_transaction_id: 6,
        };
        let mut stage = DeviceStageCoordinator::new(driver(), correlations).unwrap();
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

        assert_eq!(
            DeviceStageCoordinator::new(
                driver(),
                D3StageCorrelations {
                    interrupt_transaction_id: 8,
                    ..correlations
                }
            ),
            Err(DeviceStageError::ZeroIdentity)
        );
    }

    #[test]
    fn interrupt_is_created_and_moved_only_after_exact_quiescence() {
        let mut stage = DeviceStageCoordinator::new(
            driver(),
            D3StageCorrelations {
                stage_generation: StageGeneration(7),
                device_transaction_id: 8,
                interrupt_transaction_id: 9,
                ready_transaction_id: 6,
            },
        )
        .unwrap();
        assert_eq!(stage.interrupt_created(), Err(DeviceStageError::WrongState));
        stage.device_stage_moved().unwrap();
        stage
            .accept_device_quiesced(ControlMessageV1_1::DeviceQuiesced {
                identity: ControlIdentityV1_1 {
                    transaction_id: 8,
                    ..driver()
                },
                stage_generation: 7,
            })
            .unwrap();
        stage.interrupt_created().unwrap();
        assert_eq!(
            stage.interrupt_stage_message().unwrap(),
            ControlMessageV1_1::InterruptStage {
                identity: ControlIdentityV1_1 {
                    transaction_id: 9,
                    ..driver()
                },
                stage_generation: 7,
                parent_resource_id: 1,
                source: 3,
            }
        );
        stage.interrupt_stage_moved().unwrap();
        assert_eq!(
            stage.accept_driver_ready(ControlMessageV1_1::Ready {
                identity: ControlIdentityV1_1 {
                    transaction_id: 9,
                    ..driver()
                }
            }),
            Err(DeviceStageError::StaleReply)
        );
        stage
            .accept_driver_ready(ControlMessageV1_1::Ready {
                identity: stage.ready_identity(),
            })
            .unwrap();
        assert_eq!(stage.state(), DeviceStageState::DriverReady);
    }
}
