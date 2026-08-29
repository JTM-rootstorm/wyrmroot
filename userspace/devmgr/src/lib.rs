//! Hardware-independent WYR1-C `/system/devmgr` foundation.
//!
//! Operational readiness means only that the exact immutable role manifest
//! and the supervisor generation are valid. Hardware intake remains blocked on
//! the separately reached DW1-D seam.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "native-devmgr")]
use {deepwyrm_syscall as _, wyrmroot_loader as _, wyrmroot_runtime as _};

use wyrmroot_device_proto::controller::{
    ControllerMessage, ControllerParseError, StatusCode, validate_binding_transition,
};
use wyrmroot_device_proto::coordinator::{
    Coordinator, CoordinatorError, CoordinatorState, RegistryBinding, SupervisorGeneration,
};
use wyrmroot_device_proto::manifest::{
    ContentIdentity, Manifest, ManifestError, MetadataPolicyId, PioRange, ProfileId,
    ProfileVersion, RoleId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationalStatus {
    pub supervisor_generation: SupervisorGeneration,
    pub state: CoordinatorState,
    pub profile: ProfileId,
    pub profile_version: ProfileVersion,
    pub role_id: RoleId,
    pub pio: PioRange,
    pub irq: u32,
    pub driver_identity: ContentIdentity,
    pub metadata_policy: MetadataPolicyId,
}

impl OperationalStatus {
    /// C1 cannot truthfully reach any device-bound phase.
    pub const fn is_device_bound(self) -> bool {
        matches!(
            self.state,
            CoordinatorState::Matched
                | CoordinatorState::LaunchingDriver
                | CoordinatorState::AwaitingDriverReady
                | CoordinatorState::AwaitingPublication
                | CoordinatorState::Published
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevmgrError {
    Manifest(ManifestError),
    Coordinator(CoordinatorError),
    MissingRole,
    Controller(ControllerParseError),
    StartupCorrelation,
    StaleControllerTransaction,
    ControllerLifecycle,
}

impl From<ControllerParseError> for DevmgrError {
    fn from(error: ControllerParseError) -> Self {
        Self::Controller(error)
    }
}

impl From<ManifestError> for DevmgrError {
    fn from(error: ManifestError) -> Self {
        Self::Manifest(error)
    }
}

impl From<CoordinatorError> for DevmgrError {
    fn from(error: CoordinatorError) -> Self {
        Self::Coordinator(error)
    }
}

/// Validates the complete C1 manifest and constructs the bounded status copied
/// out before the read-only manifest mapping is released.
pub fn prepare_operational(
    manifest_bytes: &[u8],
    supervisor_generation: u64,
) -> Result<OperationalStatus, DevmgrError> {
    let manifest = Manifest::parse(manifest_bytes)?;
    let candidate = manifest.get(0).ok_or(DevmgrError::MissingRole)?;
    let mut coordinator = Coordinator::new(SupervisorGeneration(supervisor_generation))?;
    coordinator.intake_manifest(manifest, candidate.content_identity)?;
    let role = coordinator.role().ok_or(DevmgrError::MissingRole)?;
    Ok(OperationalStatus {
        supervisor_generation: coordinator.supervisor_generation(),
        state: coordinator.state(),
        profile: wyrmroot_device_proto::manifest::PROFILE_Q35,
        profile_version: wyrmroot_device_proto::manifest::PROFILE_Q35_VERSION,
        role_id: role.role_id,
        pio: role.pio,
        irq: role.irq,
        driver_identity: role.content_identity,
        metadata_policy: role.metadata_policy,
    })
}

/// The allocation-free resident C1 control state.  The immutable manifest is
/// checked before this is constructed; the resident state intentionally keeps
/// only copied metadata, never a mapping borrowed from startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResidentController {
    status: OperationalStatus,
    startup_transaction_id: u64,
    last_transaction_id: u64,
    last_binding: Option<RegistryBinding>,
    active_binding: Option<RegistryBinding>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerAction {
    InitialPublicationBound,
    PublicationRebound,
}

impl ResidentController {
    pub fn new(
        status: OperationalStatus,
        startup_transaction_id: u64,
    ) -> Result<Self, DevmgrError> {
        if startup_transaction_id == 0 {
            return Err(DevmgrError::StartupCorrelation);
        }
        if status.state != CoordinatorState::WaitingForRegistry {
            return Err(DevmgrError::ControllerLifecycle);
        }
        Ok(Self {
            status,
            startup_transaction_id,
            last_transaction_id: 0,
            last_binding: None,
            active_binding: None,
        })
    }

    pub const fn status(&self) -> OperationalStatus {
        self.status
    }

    pub const fn active_binding(&self) -> Option<RegistryBinding> {
        self.active_binding
    }

    pub const fn last_transaction_id(&self) -> u64 {
        self.last_transaction_id
    }

    /// Applies a syntactically validated WRCS controller message.  Handle
    /// count is checked here; native code separately validates the moved
    /// replacement Channel's type and exact rights before calling this.
    pub fn accept(
        &mut self,
        message: ControllerMessage,
        received_handles: u32,
    ) -> Result<ControllerAction, DevmgrError> {
        if received_handles != message.handle_count() {
            return Err(DevmgrError::Controller(
                ControllerParseError::WrongHandleCount,
            ));
        }
        match message {
            ControllerMessage::InstallPublication {
                supervisor_generation,
                binding,
                transaction_id,
            } => {
                if transaction_id != self.startup_transaction_id
                    || self.last_binding.is_some()
                    || self.status.supervisor_generation != supervisor_generation
                {
                    return Err(DevmgrError::StartupCorrelation);
                }
                let binding = validate_binding_transition(
                    self.status.supervisor_generation,
                    None,
                    ControllerMessage::InstallPublication {
                        supervisor_generation,
                        binding,
                        transaction_id,
                    },
                )?;
                self.last_transaction_id = transaction_id;
                self.last_binding = Some(binding);
                self.active_binding = Some(binding);
                self.status.state = CoordinatorState::WaitingForDeviceBundle;
                Ok(ControllerAction::InitialPublicationBound)
            }
            ControllerMessage::RebindPublication {
                supervisor_generation,
                binding,
                transaction_id,
            } => {
                if self.status.supervisor_generation != supervisor_generation
                    || self.last_binding.is_none()
                    || self.active_binding.is_some()
                    || transaction_id <= self.last_transaction_id
                {
                    return Err(DevmgrError::StaleControllerTransaction);
                }
                let binding = validate_binding_transition(
                    self.status.supervisor_generation,
                    self.last_binding,
                    ControllerMessage::RebindPublication {
                        supervisor_generation,
                        binding,
                        transaction_id,
                    },
                )?;
                self.last_transaction_id = transaction_id;
                self.last_binding = Some(binding);
                self.active_binding = Some(binding);
                self.status.state = CoordinatorState::WaitingForDeviceBundle;
                Ok(ControllerAction::PublicationRebound)
            }
            ControllerMessage::Status { .. } => Err(DevmgrError::ControllerLifecycle),
        }
    }

    /// The registry-side peer can disappear without replacing this devmgr
    /// generation.  Keep the historical binding solely to enforce a monotonic
    /// replacement later; it is no longer an active publication binding.
    pub fn publication_peer_closed(&mut self) -> Result<(), DevmgrError> {
        if self.active_binding.is_none() {
            return Err(DevmgrError::ControllerLifecycle);
        }
        self.active_binding = None;
        self.status.state = CoordinatorState::WaitingForRegistry;
        Ok(())
    }

    pub fn report(&self, status: StatusCode) -> Result<ControllerMessage, DevmgrError> {
        if status.is_device_bound() {
            return Err(DevmgrError::Controller(
                ControllerParseError::DeviceBoundStatus,
            ));
        }
        let binding = match status {
            StatusCode::OperationalWaitingForRegistry => None,
            StatusCode::OperationalWaitingForDeviceBundle => self.active_binding,
            StatusCode::CleaningUp | StatusCode::Backoff | StatusCode::PermanentFailure => {
                return Err(DevmgrError::ControllerLifecycle);
            }
        };
        if self.last_transaction_id == 0 {
            return Err(DevmgrError::ControllerLifecycle);
        }
        Ok(ControllerMessage::Status {
            supervisor_generation: self.status.supervisor_generation,
            binding,
            transaction_id: self.last_transaction_id,
            status,
            attempt_generation: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrmroot_device_proto::manifest::{
        HEADER_BYTES, MAGIC, MAJOR, MINOR, PROFILE_Q35, PROFILE_Q35_VERSION, RECORD_BYTES,
        UART16550D_PATH,
    };

    fn manifest() -> [u8; HEADER_BYTES + RECORD_BYTES] {
        let mut bytes = [0; HEADER_BYTES + RECORD_BYTES];
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4..6].copy_from_slice(&MAJOR.to_le_bytes());
        bytes[6..8].copy_from_slice(&MINOR.to_le_bytes());
        let total = bytes.len() as u32;
        bytes[8..12].copy_from_slice(&total.to_le_bytes());
        bytes[12..14].copy_from_slice(&1u16.to_le_bytes());
        bytes[16..20].copy_from_slice(&PROFILE_Q35.0.to_le_bytes());
        bytes[20..24].copy_from_slice(&PROFILE_Q35_VERSION.0.to_le_bytes());
        let record = HEADER_BYTES;
        bytes[record..record + 8].copy_from_slice(&1u64.to_le_bytes());
        bytes[record + 8..record + 12].copy_from_slice(&2u32.to_le_bytes());
        bytes[record + 12..record + 16].copy_from_slice(&1u32.to_le_bytes());
        bytes[record + 16..record + 18].copy_from_slice(&0x2f8u16.to_le_bytes());
        bytes[record + 18..record + 20].copy_from_slice(&8u16.to_le_bytes());
        bytes[record + 20..record + 24].copy_from_slice(&3u32.to_le_bytes());
        bytes[record + 24..record + 26]
            .copy_from_slice(&(UART16550D_PATH.len() as u16).to_le_bytes());
        bytes[record + 28..record + 60].copy_from_slice(&[0x5a; 32]);
        bytes[record + 60..record + 64].copy_from_slice(&1u32.to_le_bytes());
        bytes[record + 72..record + 72 + UART16550D_PATH.len()].copy_from_slice(UART16550D_PATH);
        bytes
    }

    #[test]
    fn exact_manifest_becomes_operational_but_not_device_bound() {
        let status = prepare_operational(&manifest(), 7).unwrap();
        assert_eq!(status.supervisor_generation, SupervisorGeneration(7));
        assert_eq!(status.state, CoordinatorState::WaitingForRegistry);
        assert_eq!(
            status.pio,
            PioRange {
                base: 0x2f8,
                length: 8
            }
        );
        assert_eq!(status.irq, 3);
        assert!(!status.is_device_bound());
    }

    #[test]
    fn malformed_or_com1_manifest_never_becomes_operational() {
        let mut bytes = manifest();
        bytes[0] = b'X';
        assert_eq!(
            prepare_operational(&bytes, 1),
            Err(DevmgrError::Manifest(ManifestError::WrongMagic))
        );
        bytes = manifest();
        bytes[HEADER_BYTES + 8..HEADER_BYTES + 12].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            prepare_operational(&bytes, 1),
            Err(DevmgrError::Coordinator(CoordinatorError::Manifest(
                ManifestError::Com1Rejected
            )))
        );
    }

    #[test]
    fn zero_supervisor_generation_is_rejected() {
        assert_eq!(
            prepare_operational(&manifest(), 0),
            Err(DevmgrError::Coordinator(
                CoordinatorError::InvalidSupervisorGeneration
            ))
        );
    }

    fn binding(generation: u64, endpoint: u64) -> RegistryBinding {
        RegistryBinding {
            generation: wyrmroot_device_proto::coordinator::RegistryGeneration(generation),
            endpoint: wyrmroot_device_proto::coordinator::RegistryEndpoint {
                id: wyrmroot_device_proto::coordinator::RegistryEndpointId(endpoint),
                generation: wyrmroot_device_proto::coordinator::RegistryEndpointGeneration(1),
            },
        }
    }

    fn install(binding: RegistryBinding, transaction_id: u64) -> ControllerMessage {
        ControllerMessage::InstallPublication {
            supervisor_generation: SupervisorGeneration(7),
            binding,
            transaction_id,
        }
    }

    fn rebind(binding: RegistryBinding, transaction_id: u64) -> ControllerMessage {
        ControllerMessage::RebindPublication {
            supervisor_generation: SupervisorGeneration(7),
            binding,
            transaction_id,
        }
    }

    #[test]
    fn controller_correlates_zero_handle_install_to_startup_then_reports_waiting() {
        let mut resident =
            ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
        let installed = binding(1, 7);
        assert_eq!(
            resident.accept(install(installed, 41), 0),
            Ok(ControllerAction::InitialPublicationBound)
        );
        assert_eq!(
            resident.status().state,
            CoordinatorState::WaitingForDeviceBundle
        );
        assert_eq!(
            resident.report(StatusCode::OperationalWaitingForDeviceBundle),
            Ok(ControllerMessage::Status {
                supervisor_generation: SupervisorGeneration(7),
                binding: Some(installed),
                transaction_id: 41,
                status: StatusCode::OperationalWaitingForDeviceBundle,
                attempt_generation: None,
            })
        );
    }

    #[test]
    fn controller_rejects_wrong_install_correlation_or_handle_count() {
        let mut resident =
            ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
        assert_eq!(
            resident.accept(install(binding(1, 7), 40), 0),
            Err(DevmgrError::StartupCorrelation)
        );
        assert_eq!(
            resident.accept(install(binding(1, 7), 41), 1),
            Err(DevmgrError::Controller(
                ControllerParseError::WrongHandleCount
            ))
        );
    }

    #[test]
    fn peer_close_keeps_generation_and_requires_monotonic_one_handle_rebind() {
        let mut resident =
            ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
        let first = binding(1, 7);
        resident.accept(install(first, 41), 0).unwrap();
        resident.publication_peer_closed().unwrap();
        assert_eq!(
            resident.status().supervisor_generation,
            SupervisorGeneration(7)
        );
        assert_eq!(
            resident.status().state,
            CoordinatorState::WaitingForRegistry
        );
        assert_eq!(resident.active_binding(), None);
        assert_eq!(
            resident.report(StatusCode::OperationalWaitingForRegistry),
            Ok(ControllerMessage::Status {
                supervisor_generation: SupervisorGeneration(7),
                binding: None,
                transaction_id: 41,
                status: StatusCode::OperationalWaitingForRegistry,
                attempt_generation: None,
            })
        );
        assert_eq!(
            resident.accept(rebind(first, 42), 1),
            Err(DevmgrError::Controller(ControllerParseError::StaleBinding))
        );
        let second = binding(2, 8);
        assert_eq!(
            resident.accept(rebind(second, 42), 1),
            Ok(ControllerAction::PublicationRebound)
        );
        assert_eq!(resident.active_binding(), Some(second));
        assert_eq!(
            resident.status().supervisor_generation,
            SupervisorGeneration(7)
        );
    }

    #[test]
    fn status_and_replay_messages_cannot_drive_the_resident() {
        let mut resident =
            ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
        let first = binding(1, 7);
        resident.accept(install(first, 41), 0).unwrap();
        assert_eq!(
            resident.accept(rebind(binding(2, 8), 41), 1),
            Err(DevmgrError::StaleControllerTransaction)
        );
        assert_eq!(
            resident.accept(
                ControllerMessage::Status {
                    supervisor_generation: SupervisorGeneration(7),
                    binding: Some(first),
                    transaction_id: 42,
                    status: StatusCode::OperationalWaitingForDeviceBundle,
                    attempt_generation: None,
                },
                0,
            ),
            Err(DevmgrError::ControllerLifecycle)
        );
    }
}
