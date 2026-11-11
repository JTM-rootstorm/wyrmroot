//! The boot-disk lane (root `STORAGE_PLAN.md` W2): claim the disk's PCI
//! function, have init construct `virtio-blkd`, stage the reduced resource to
//! it with one WRDP STAGE, and accept its READY.
//!
//! The lane is contained. A failure here closes the lane's handles and leaves
//! the console lane, and devmgr, running; the disk stays unserved until the
//! next devmgr generation. Restart policy for the lane is later work.

use super::*;
use deepwyrm_syscall::{DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION, DW_RIGHT_MAP};
use wyrmroot_device_proto::manifest::BOOT_DISK_POLICY;
use wyrmroot_device_proto::pci_driver::{
    self, PciDriverMessage, READY_BYTES as WRDP_READY_BYTES, STAGE_BYTES as WRDP_STAGE_BYTES,
};

/// devmgr's custody of the boot disk: everything a driver needs, plus the
/// right to duplicate and transfer it.
pub(crate) const PCI_RESOURCE_CUSTODY_RIGHTS: DwRights =
    DwRights(DEVICE_RESOURCE_CUSTODY_RIGHTS.0 | DW_RIGHT_MAP.0);
/// What the driver holds: config reads and command writes, BAR objects, DMA
/// mappings and info. It cannot duplicate or pass the resource on.
pub const PCI_DRIVER_RESOURCE_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MAP.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0,
);
const PCI_DRIVER_TRANSFER_RIGHTS: DwRights =
    DwRights(PCI_DRIVER_RESOURCE_RIGHTS.0 | DW_RIGHT_TRANSFER.0);

/// The live boot-disk lane: devmgr's custody handle and the driver's control
/// Channel. devmgr does not watch the Channel yet; dropping the lane at
/// generation end closes both.
pub(crate) struct StorageLane {
    pub(crate) resource: DwHandle,
    pub(crate) control: Option<DwHandle>,
}

/// Claims the boot disk's PCI function and checks the kernel's facts about
/// it. A product without the boot-disk role has no lane.
pub(crate) fn claim_boot_disk<P: DevmgrPlatform>(
    platform: &mut P,
    domain: DwHandle,
    resident: &crate::ResidentController,
) -> Result<Option<DwHandle>, u32> {
    if resident.status().boot_disk_identity.is_none() {
        return Ok(None);
    }
    let resource = platform
        .claim_device_resource(
            domain,
            BOOT_DISK_POLICY.resource_id,
            PCI_RESOURCE_CUSTODY_RIGHTS,
        )
        .map_err(|_| failure(400))?;
    let checked = (|| {
        validate_fresh(
            platform,
            resource,
            DW_OBJECT_TYPE_DEVICE_RESOURCE,
            PCI_RESOURCE_CUSTODY_RIGHTS,
        )
        .map_err(|_| failure(401))?;
        let info = platform
            .device_resource_info(resource)
            .map_err(|_| failure(402))?;
        admit_boot_disk_info(info).map_err(|()| failure(403))
    })();
    match checked {
        Ok(()) => Ok(Some(resource)),
        Err(code) => {
            let _ = platform.close_handle(resource);
            Err(code)
        }
    }
}

/// The kernel's facts about a claimed boot-disk resource.
pub(crate) fn admit_boot_disk_info(
    info: deepwyrm_syscall::DwDeviceResourceInfoV1,
) -> Result<(), ()> {
    if info.size != deepwyrm_syscall::DW_DEVICE_RESOURCE_INFO_V1_SIZE
        || info.version != deepwyrm_syscall::DW_DEVICE_RESOURCE_INFO_V1_VERSION
        || info.kind != DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION
        || info.flags != 0
        || info.resource_id != BOOT_DISK_POLICY.resource_id
        || info.lease_generation == 0
        || info.pio_base != 0
        || info.pio_length != 0
        || info.interrupt_source != 0
        || info.reserved != 0
    {
        return Err(());
    }
    Ok(())
}

/// Launches and stages the boot-disk driver over `resource`, returning its
/// control Channel once its READY is accepted.
pub(crate) fn launch_storage_driver<P: DevmgrPlatform>(
    platform: &mut P,
    bootstrap: DwHandle,
    resource: DwHandle,
    resident: &mut crate::ResidentController,
) -> Result<DwHandle, u32> {
    let mut owned = StagedLaunchHandles::new();
    let result = launch_storage_owned(platform, &mut owned, bootstrap, resource, resident);
    owned.close_live(platform);
    result
}

fn launch_storage_owned<P: DevmgrPlatform>(
    platform: &mut P,
    owned: &mut StagedLaunchHandles,
    bootstrap: DwHandle,
    resource: DwHandle,
    resident: &mut crate::ResidentController,
) -> Result<DwHandle, u32> {
    let (retained_raw, child_raw) = platform
        .create_channel(DIRECT_CONTROL_RIGHTS)
        .map_err(|_| failure(410))?;
    let retained = owned.retained.hold(retained_raw);
    let child = owned.child.hold(child_raw);
    let (request, stage_transaction) = resident.issue_storage_launch().map_err(|_| failure(411))?;
    let mut launch = [0u8; LAUNCH_REQUEST_BYTES];
    encode_request(request, &mut launch).map_err(|_| failure(412))?;
    let child_transfer = DwHandleTransferV1 {
        handle: child.raw(),
        requested_rights: CHILD_CHANNEL_TRANSFER_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    send_bootstrap_channel(
        platform,
        bootstrap,
        &launch,
        core::slice::from_ref(&child_transfer),
        413,
    )?;
    child.moved();
    let deadline = platform
        .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .map_err(|_| failure(414))?;
    wait_readable(platform, bootstrap, deadline, 415)?;
    let mut constructed = [0u8; LAUNCH_RESPONSE_BYTES];
    let mut constructed_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(bootstrap, &mut constructed, &mut constructed_handles)
        .map_err(|_| failure(416))?;
    if counts.bytes != constructed.len() || counts.handles != 0 {
        close_received(platform, &constructed_handles, counts.handles);
        return Err(failure(417));
    }
    parse_constructed(&constructed, request).map_err(|_| failure(418))?;

    let info = platform
        .device_resource_info(resource)
        .map_err(|_| failure(419))?;
    admit_boot_disk_info(info).map_err(|()| failure(420))?;
    let identity = ControlIdentityV1_1 {
        role_id: request.role_id,
        bundle_generation: wyrmroot_device_proto::coordinator::BundleGeneration(
            info.lease_generation,
        ),
        attempt_generation: request.attempt_generation,
        endpoint: request.endpoint,
        transaction_id: stage_transaction,
    };
    let reduced = owned.reduced.hold(
        platform
            .duplicate_handle(resource, PCI_DRIVER_TRANSFER_RIGHTS)
            .map_err(|_| failure(421))?,
    );
    validate_fresh(
        platform,
        reduced.raw(),
        DW_OBJECT_TYPE_DEVICE_RESOURCE,
        PCI_DRIVER_TRANSFER_RIGHTS,
    )
    .map_err(|_| failure(422))?;
    let mut stage = [0u8; WRDP_STAGE_BYTES];
    pci_driver::encode(
        PciDriverMessage::Stage {
            identity,
            resource_id: BOOT_DISK_POLICY.resource_id,
            function: BOOT_DISK_POLICY.pci,
        },
        &mut stage,
    )
    .map_err(|_| failure(423))?;
    let transfer = DwHandleTransferV1 {
        handle: reduced.raw(),
        requested_rights: PCI_DRIVER_RESOURCE_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    platform
        .send_channel(retained.raw(), &stage, core::slice::from_ref(&transfer))
        .map_err(|_| failure(424))?;
    reduced.moved();
    wait_readable(platform, retained.raw(), deadline, 425)?;
    let mut ready = [0u8; WRDP_READY_BYTES];
    let mut ready_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(retained.raw(), &mut ready, &mut ready_handles)
        .map_err(|_| failure(426))?;
    if counts.bytes != ready.len() || counts.handles != 0 {
        close_received(platform, &ready_handles, counts.handles);
        return Err(failure(427));
    }
    if pci_driver::parse(&ready) != Ok(PciDriverMessage::Ready { identity }) {
        return Err(failure(428));
    }
    Ok(retained.take_raw())
}

#[cfg(test)]
mod tests {
    use super::*;
    use deepwyrm_syscall::{
        DW_DEVICE_RESOURCE_INFO_V1_SIZE, DW_DEVICE_RESOURCE_INFO_V1_VERSION,
        DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT, DwDeviceResourceInfoV1,
    };

    fn info() -> DwDeviceResourceInfoV1 {
        DwDeviceResourceInfoV1 {
            size: DW_DEVICE_RESOURCE_INFO_V1_SIZE,
            version: DW_DEVICE_RESOURCE_INFO_V1_VERSION,
            kind: DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION,
            resource_id: BOOT_DISK_POLICY.resource_id,
            lease_generation: 9,
            ..DwDeviceResourceInfoV1::default()
        }
    }

    #[test]
    fn only_the_boot_disk_pci_resource_with_a_live_lease_is_admitted() {
        assert_eq!(admit_boot_disk_info(info()), Ok(()));
        let cases: [fn(&mut DwDeviceResourceInfoV1); 6] = [
            |info| info.kind = DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT,
            |info| info.resource_id = 1,
            |info| info.lease_generation = 0,
            |info| info.interrupt_source = 3,
            |info| info.reserved = 1,
            |info| info.size -= 1,
        ];
        for change in cases {
            let mut bad = info();
            change(&mut bad);
            assert_eq!(admit_boot_disk_info(bad), Err(()));
        }
    }

    #[test]
    fn the_driver_gets_a_strict_subset_of_custody_without_duplicate_or_transfer() {
        assert_eq!(
            PCI_DRIVER_RESOURCE_RIGHTS.0 & !PCI_RESOURCE_CUSTODY_RIGHTS.0,
            0
        );
        assert_eq!(PCI_DRIVER_RESOURCE_RIGHTS.0 & DW_RIGHT_TRANSFER.0, 0);
        assert_eq!(PCI_DRIVER_RESOURCE_RIGHTS.0 & DW_RIGHT_DUPLICATE.0, 0);
        assert_eq!(
            PCI_DRIVER_TRANSFER_RIGHTS.0,
            PCI_DRIVER_RESOURCE_RIGHTS.0 | DW_RIGHT_TRANSFER.0
        );
    }
}
