//! The boot-disk virtio block driver (root `STORAGE_PLAN.md` W2/W3).
//!
//! devmgr moves it the boot disk's PCI-function DeviceResource with one WRDP
//! STAGE; the driver admits it against its launch correlation, the kernel's
//! resource facts and the function's live vendor and device IDs, and answers
//! READY (W2). It then brings the modern virtio device up behind the IOMMU,
//! reads block 0 through its one polled split virtqueue, and only then
//! publishes `device.block.virtio0`, which it serves with the WRBD
//! BlockDevice protocol (W3; Wyrmroot `WYR1_C_DEVICE_COORDINATOR_CONTRACT.md`
//! §3.1 item 6).

#![no_std]
#![forbid(unsafe_code)]

// Also built for the library's own tests, which drive the role through the
// runtime's recording platform.
#[cfg(any(feature = "native-virtio-blkd", test))]
pub mod role;

#[cfg(test)]
extern crate std;
#[cfg(test)]
use wyrmroot_devmgr as _;

use wyrmroot_registry_proto as _;
#[cfg(feature = "native-virtio-blkd")]
use {wyrmroot_loader as _, wyrmroot_runtime as _};

use deepwyrm_syscall::{
    DW_DEVICE_RESOURCE_INFO_V1_SIZE, DW_DEVICE_RESOURCE_INFO_V1_VERSION,
    DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION, DW_OBJECT_TYPE_DEVICE_RESOURCE, DW_RIGHT_INSPECT,
    DW_RIGHT_MAP, DW_RIGHT_MODIFY, DW_RIGHT_READ, DW_RIGHT_WRITE, DwDeviceResourceInfoV1,
    DwReceivedHandleInfoV1, DwRights,
};
use wyrmroot_device_proto::control_v1_1::ControlIdentityV1_1;
use wyrmroot_device_proto::manifest::{BOOT_DISK_POLICY, PciFunction};
use wyrmroot_device_proto::pci_driver::PciDriverMessage;

/// The rights a PCI driver holds on its function: config reads and command
/// writes (READ, WRITE), BAR objects (MAP), DMA mappings (MODIFY) and info
/// queries (INSPECT). It can neither duplicate nor transfer the resource.
pub const PCI_DRIVER_RESOURCE_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MAP.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0,
);

/// The PCI config-space dword holding the vendor and device IDs.
pub const PCI_CONFIG_IDS: u32 = 0;

/// The launch correlation init gave this driver attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaunchCorrelation {
    pub role_id: u64,
    pub attempt_generation: u64,
    pub endpoint_id: u64,
    pub endpoint_generation: u64,
    pub transaction_id: u64,
}

/// Why a STAGE was refused. Each maps to one driver failure step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StageError {
    NotStage,
    WrongIdentity,
    WrongPolicy,
    WrongHandle,
    WrongResource,
    WrongIds,
}

impl StageError {
    pub const fn code(self) -> u32 {
        match self {
            Self::NotStage => 0x41,
            Self::WrongIdentity => 0x42,
            Self::WrongPolicy => 0x43,
            Self::WrongHandle => 0x44,
            Self::WrongResource => 0x45,
            Self::WrongIds => 0x46,
        }
    }
}

/// The admitted STAGE: the identity READY echoes and the function to drive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmittedStage {
    pub identity: ControlIdentityV1_1,
    pub resource_id: u64,
    pub function: PciFunction,
}

/// Checks a STAGE against this attempt's launch correlation and the fixed
/// boot-disk policy, before the handle it carries is trusted for anything.
///
/// The STAGE uses its own transaction, which must be later than the launch's;
/// every other identity must equal the launch's, and the bundle generation is
/// the resource lease, checked later against the kernel's facts.
pub fn admit_stage_message(
    launch: LaunchCorrelation,
    message: PciDriverMessage,
) -> Result<AdmittedStage, StageError> {
    let PciDriverMessage::Stage {
        identity,
        resource_id,
        function,
    } = message
    else {
        return Err(StageError::NotStage);
    };
    if identity.role_id.0 != launch.role_id
        || identity.attempt_generation.0 != launch.attempt_generation
        || identity.endpoint.id.0 != launch.endpoint_id
        || identity.endpoint.generation.0 != launch.endpoint_generation
        || identity.transaction_id <= launch.transaction_id
    {
        return Err(StageError::WrongIdentity);
    }
    if identity.role_id != BOOT_DISK_POLICY.role_id
        || resource_id != BOOT_DISK_POLICY.resource_id
        || function != BOOT_DISK_POLICY.pci
    {
        return Err(StageError::WrongPolicy);
    }
    Ok(AdmittedStage {
        identity,
        resource_id,
        function,
    })
}

/// Checks the received handle's metadata: one DeviceResource with exactly the
/// driver rights.
pub fn admit_stage_handle(info: DwReceivedHandleInfoV1) -> Result<(), StageError> {
    if info.handle.0 == 0
        || info.object_type != DW_OBJECT_TYPE_DEVICE_RESOURCE
        || info.rights != PCI_DRIVER_RESOURCE_RIGHTS
        || info.reserved0 != 0
        || info.reserved != [0; 2]
    {
        return Err(StageError::WrongHandle);
    }
    Ok(())
}

/// Checks the kernel's facts about the received resource against the STAGE.
pub fn admit_resource_info(
    stage: AdmittedStage,
    info: DwDeviceResourceInfoV1,
) -> Result<(), StageError> {
    if info.size != DW_DEVICE_RESOURCE_INFO_V1_SIZE
        || info.version != DW_DEVICE_RESOURCE_INFO_V1_VERSION
        || info.kind != DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION
        || info.flags != 0
        || info.resource_id != stage.resource_id
        || info.lease_generation != stage.identity.bundle_generation.0
        || info.pio_base != 0
        || info.pio_length != 0
        || info.interrupt_source != 0
        || info.reserved != 0
    {
        return Err(StageError::WrongResource);
    }
    Ok(())
}

/// Checks the function's live config-space IDs against the STAGE.
pub const fn admit_config_ids(stage: AdmittedStage, ids: u32) -> Result<(), StageError> {
    if ids != stage.function.ids {
        return Err(StageError::WrongIds);
    }
    Ok(())
}

pub mod block;
pub mod virtio;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod virtio_tests;
