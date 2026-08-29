//! Hardware-independent WYR1-C `/system/devmgr` foundation.
//!
//! Operational readiness means only that the exact immutable role manifest
//! and the supervisor generation are valid. Hardware intake remains blocked on
//! the separately reached DW1-D seam.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "native-devmgr")]
use {deepwyrm_syscall as _, wyrmroot_loader as _, wyrmroot_runtime as _};

use wyrmroot_device_proto::coordinator::{
    Coordinator, CoordinatorError, CoordinatorState, SupervisorGeneration,
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
}
