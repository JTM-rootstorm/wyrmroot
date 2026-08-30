#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;
use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL,
    DW_OBJECT_TYPE_MEMORY_OBJECT, DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT, DW_RIGHT_READ,
    DW_RIGHT_TRANSFER, DW_RIGHT_WRITE, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DwHandle,
    DwObjectType, DwReceivedHandleInfoV1, DwRights, DwWaitItemV1,
};
#[cfg(not(feature = "wyr1c4-production"))]
use deepwyrm_syscall::{DW_HANDLE_TRANSFER_MOVE, DW_RIGHT_WAIT, DwHandleTransferV1};
#[cfg(feature = "wyr1c4-production")]
use deepwyrm_syscall::{
    DW_OBJECT_TYPE_DEVICE_RESOURCE, DW_OBJECT_TYPE_TASK_GROUP, DW_RIGHT_MODIFY,
};
use wyrmroot_device_proto::{
    ControllerMessage, StatusCode,
    controller::{
        INSTALL_BYTES, STATUS_BYTES, encode as encode_controller, parse as parse_controller,
    },
};
#[cfg(not(feature = "wyr1c4-production"))]
use wyrmroot_device_proto::{
    DirectControlRights,
    control::{CONTROL_READY_BYTES, parse as parse_control},
    driver_launch::{
        LAUNCH_REQUEST_BYTES, LAUNCH_RESPONSE_BYTES, encode_request, parse_constructed,
    },
};
use wyrmroot_devmgr::ControllerAction;
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, DEVICE_MANIFEST_RIGHTS, HEADER_BYTES, LaunchProfile, SELF_ROOT_RIGHTS,
    encode_ready_for_profile,
};
#[cfg(not(feature = "wyr1c4-production"))]
use wyrmroot_loader::launch::{DEVICE_COORDINATOR_BYTES, parse_device_coordinator_init};
#[cfg(feature = "wyr1c4-production")]
use wyrmroot_loader::launch::{
    DEVICE_COORDINATOR_RESOURCE_BYTES, RESOURCE_DOMAIN_CLAIM_RIGHTS,
    parse_device_coordinator_resource_init,
};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, MappingPlan, StartupBlock, close_handle,
    map_bootfs_read_only, panic_abort, query_capability_info, query_memory_object_size,
    receive_channel, send_channel, unmap_bootfs, validate_bootstrap_channel, wait_many,
};
#[cfg(not(feature = "wyr1c4-production"))]
use wyrmroot_runtime::{WYR0_I_SUPERVISION_POLICY, create_channel, monotonic_deadline_after};
#[cfg(feature = "wyr1c4-production")]
use wyrmroot_runtime::{
    claim_device_resource, device_resource_info, require_device_resource_interrupt_feature,
};

const FAILURE_BASE: u32 = 0xC101_0000;
#[cfg(not(feature = "wyr1c4-production"))]
const DIRECT_CONTROL_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0
        | DW_RIGHT_WRITE.0
        | DW_RIGHT_WAIT.0
        | DW_RIGHT_INSPECT.0
        | DW_RIGHT_DUPLICATE.0
        | DW_RIGHT_TRANSFER.0,
);
#[cfg(feature = "wyr1c4-production")]
const DEVICE_RESOURCE_CUSTODY_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0
        | DW_RIGHT_WRITE.0
        | DW_RIGHT_MODIFY.0
        | DW_RIGHT_DUPLICATE.0
        | DW_RIGHT_TRANSFER.0
        | DW_RIGHT_INSPECT.0,
);

fn main(startup: StartupBlock<'_>) -> u32 {
    run(startup).unwrap_or_else(|code| code)
}

fn run(startup: StartupBlock<'_>) -> Result<u32, u32> {
    let bootstrap = startup.bootstrap_channel().as_abi();
    let bootstrap_info = query_capability_info(bootstrap).map_err(|_| failure(1))?;
    validate_bootstrap_channel(bootstrap_info, BOOTSTRAP_CHANNEL_EXPECTATION)
        .map_err(|_| failure(2))?;

    #[cfg(not(feature = "wyr1c4-production"))]
    let mut init = [0u8; DEVICE_COORDINATOR_BYTES];
    #[cfg(feature = "wyr1c4-production")]
    let mut init = [0u8; DEVICE_COORDINATOR_RESOURCE_BYTES];
    #[cfg(not(feature = "wyr1c4-production"))]
    let mut handles = [DwReceivedHandleInfoV1::default(); 3];
    #[cfg(feature = "wyr1c4-production")]
    let mut handles = [DwReceivedHandleInfoV1::default(); 4];
    let counts = receive_channel(bootstrap, &mut init, &mut handles).map_err(|_| failure(3))?;
    if counts.bytes > init.len() || counts.handles != handles.len() {
        close_received(&handles, counts.handles);
        return Err(failure(4));
    }
    #[cfg(not(feature = "wyr1c4-production"))]
    let parsed_result = parse_device_coordinator_init(&init[..counts.bytes], &handles);
    #[cfg(feature = "wyr1c4-production")]
    let parsed_result = parse_device_coordinator_resource_init(&init[..counts.bytes], &handles);
    let parsed = match parsed_result {
        Ok(parsed) => parsed,
        Err(_) => {
            close_received(&handles, counts.handles);
            return Err(failure(5));
        }
    };
    let invalid = validate_fresh(
        handles[0].handle,
        DW_OBJECT_TYPE_ADDRESS_REGION,
        SELF_ROOT_RIGHTS,
    )
    .is_err()
        || validate_fresh(
            handles[1].handle,
            DW_OBJECT_TYPE_CHANNEL,
            CHILD_CHANNEL_RIGHTS,
        )
        .is_err()
        || validate_fresh(
            handles[2].handle,
            DW_OBJECT_TYPE_MEMORY_OBJECT,
            DEVICE_MANIFEST_RIGHTS,
        )
        .is_err();
    #[cfg(feature = "wyr1c4-production")]
    let invalid = invalid
        || validate_fresh(
            handles[3].handle,
            DW_OBJECT_TYPE_TASK_GROUP,
            RESOURCE_DOMAIN_CLAIM_RIGHTS,
        )
        .is_err();
    if invalid {
        close_received(&handles, counts.handles);
        return Err(failure(6));
    }

    let self_root = handles[0].handle;
    let publication = handles[1].handle;
    let manifest = handles[2].handle;
    #[cfg(feature = "wyr1c4-production")]
    let mut resource_domain = Some(handles[3].handle);
    let size = query_memory_object_size(manifest).map_err(|_| failure(7))?;
    let plan = MappingPlan::for_bootfs(size).map_err(|_| failure(8))?;
    let mapping = map_bootfs_read_only(self_root, manifest, plan).map_err(|_| failure(9))?;
    let prepared = mapping.with_logical_bytes(|bytes| {
        wyrmroot_devmgr::prepare_operational(bytes, parsed.supervisor_generation)
    });
    unmap_bootfs(mapping).map_err(|_| failure(10))?;
    let mut resident = match prepared
        .and_then(|status| wyrmroot_devmgr::ResidentController::new(status, parsed.transaction_id))
    {
        Ok(resident) => resident,
        Err(_) => {
            close_received(&handles, handles.len());
            return Err(failure(11));
        }
    };
    close_handle(manifest).map_err(|_| failure(12))?;
    close_handle(self_root).map_err(|_| failure(13))?;

    let mut ready = [0u8; HEADER_BYTES];
    #[cfg(not(feature = "wyr1c4-production"))]
    let launch_profile = LaunchProfile::DeviceCoordinator;
    #[cfg(feature = "wyr1c4-production")]
    let launch_profile = LaunchProfile::DeviceCoordinatorResourceDomain;
    let ready_len = encode_ready_for_profile(launch_profile, parsed.transaction_id, &mut ready)
        .map_err(|_| failure(14))?;
    send_channel(bootstrap, &ready[..ready_len], &[]).map_err(|_| failure(15))?;

    let mut publication = Some(publication);
    let mut driver_control = None;
    #[cfg(feature = "wyr1c4-production")]
    let mut _device_resource = None;
    loop {
        let mut waits = [DwWaitItemV1::default(); 3];
        waits[0] = wait_item(bootstrap);
        let publication_index = publication.map(|handle| {
            waits[1] = wait_item(handle);
            1
        });
        let driver_index = driver_control.map(|handle| {
            let index = 1 + usize::from(publication.is_some());
            waits[index] = wait_item(handle);
            index
        });
        let wait_count =
            1 + usize::from(publication.is_some()) + usize::from(driver_control.is_some());
        let observed =
            wait_many(&waits[..wait_count], DW_DEADLINE_INFINITE).map_err(|_| failure(16))?;
        let index = usize::try_from(observed.index).map_err(|_| failure(17))?;
        if index >= wait_count
            || observed.observed.0 & (DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0) == 0
        {
            return Err(failure(18));
        }
        if index == 0 {
            if observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
                close_optional(publication);
                close_handle(bootstrap).map_err(|_| failure(19))?;
                return Err(failure(20));
            }
            let (replacement, action) = match receive_controller(bootstrap, &mut resident) {
                Ok(received) => received,
                Err(code) => {
                    close_optional(publication);
                    close_optional(driver_control);
                    let _ = close_handle(bootstrap);
                    return Err(code);
                }
            };
            if let Some(replacement) = replacement {
                if let Some(old) = publication.replace(replacement) {
                    let _ = close_handle(replacement);
                    let _ = close_handle(old);
                    let _ = close_handle(bootstrap);
                    return Err(failure(21));
                }
            }
            #[cfg(feature = "wyr1c4-production")]
            if action == ControllerAction::InitialPublicationBound {
                let domain = resource_domain.take().ok_or(failure(46))?;
                if require_device_resource_interrupt_feature().is_err() {
                    let _ = close_handle(domain);
                    return Err(failure(47));
                }
                let resource = match claim_device_resource(
                    domain,
                    wyrmroot_devmgr::COM2_RESOURCE_ID,
                    DEVICE_RESOURCE_CUSTODY_RIGHTS,
                ) {
                    Ok(resource) => resource,
                    Err(_) => {
                        let _ = close_handle(domain);
                        return Err(failure(48));
                    }
                };
                // Establish local ownership before any validation, admission,
                // status, or custodian-retirement step can fail.
                _device_resource = Some(resource);
                let claim = (|| {
                    validate_fresh(
                        resource,
                        DW_OBJECT_TYPE_DEVICE_RESOURCE,
                        DEVICE_RESOURCE_CUSTODY_RIGHTS,
                    )
                    .map_err(|_| failure(49))?;
                    let info = device_resource_info(resource).map_err(|_| failure(50))?;
                    resident
                        .admit_device_resource(info)
                        .map_err(|_| failure(51))?;
                    Ok::<_, u32>(())
                })();
                if let Err(code) = claim {
                    close_optional(_device_resource.take());
                    let _ = close_handle(domain);
                    close_optional(publication);
                    close_optional(driver_control);
                    let _ = close_handle(bootstrap);
                    return Err(code);
                }
                if close_handle(domain).is_err() {
                    close_optional(_device_resource.take());
                    close_optional(publication);
                    close_optional(driver_control);
                    let _ = close_handle(bootstrap);
                    return Err(failure(52));
                }
            }
            #[cfg(not(feature = "wyr1c4-production"))]
            let status = StatusCode::OperationalWaitingForDeviceBundle;
            #[cfg(feature = "wyr1c4-production")]
            let status = StatusCode::OperationalResourceOwned;
            if let Err(code) = send_resident_status(bootstrap, &resident, status) {
                close_optional(publication);
                close_optional(driver_control);
                #[cfg(feature = "wyr1c4-production")]
                close_optional(_device_resource.take());
                let _ = close_handle(bootstrap);
                return Err(code);
            }
            #[cfg(not(feature = "wyr1c4-production"))]
            if action == ControllerAction::InitialPublicationBound {
                if driver_control.is_some() {
                    return Err(failure(38));
                }
                driver_control = Some(launch_driver(bootstrap, &mut resident)?);
            }
            continue;
        }

        if Some(index) == driver_index {
            let control = driver_control.take().ok_or(failure(39))?;
            // The C3 acceptance actor may exit after its direct READY.  Peer
            // closure is the only reached notification path; no resource was
            // ever delegated, so reaping cannot lose future custody.
            if observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 {
                let _ = close_handle(control);
                return Err(failure(40));
            }
            close_handle(control).map_err(|_| failure(41))?;
            resident.reap_driver().map_err(|_| failure(42))?;
            continue;
        }

        if Some(index) != publication_index {
            return Err(failure(43));
        }
        if observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 {
            close_optional(publication);
            close_optional(driver_control);
            close_handle(bootstrap).map_err(|_| failure(22))?;
            return Err(failure(23));
        }
        // Registry replacement closes only the old publication binding.  The
        // coordinator generation remains resident; a later WRCS rebind moves
        // one exact child Channel over the still-open bootstrap relationship.
        let old = publication.take().ok_or(failure(24))?;
        close_handle(old).map_err(|_| failure(25))?;
        resident
            .publication_peer_closed()
            .map_err(|_| failure(26))?;
        send_resident_status(
            bootstrap,
            &resident,
            StatusCode::OperationalWaitingForRegistry,
        )?;
    }
}

fn receive_controller(
    bootstrap: DwHandle,
    resident: &mut wyrmroot_devmgr::ResidentController,
) -> Result<(Option<DwHandle>, ControllerAction), u32> {
    let mut bytes = [0u8; INSTALL_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(bootstrap, &mut bytes, &mut handles).map_err(|_| failure(27))?;
    if counts.bytes > bytes.len() || counts.handles > handles.len() {
        close_received(&handles, counts.handles);
        return Err(failure(28));
    }
    let message = match parse_controller(&bytes[..counts.bytes]) {
        Ok(message) => message,
        Err(_) => {
            close_received(&handles, counts.handles);
            return Err(failure(29));
        }
    };
    if counts.handles as u32 != message.handle_count() {
        close_received(&handles, counts.handles);
        return Err(failure(30));
    }
    let replacement = match message {
        ControllerMessage::InstallPublication { .. } => {
            if counts.handles != 0 {
                close_received(&handles, counts.handles);
                return Err(failure(31));
            }
            None
        }
        ControllerMessage::RebindPublication { .. } => {
            if counts.handles != 1
                || validate_fresh(
                    handles[0].handle,
                    DW_OBJECT_TYPE_CHANNEL,
                    CHILD_CHANNEL_RIGHTS,
                )
                .is_err()
            {
                close_received(&handles, counts.handles);
                return Err(failure(32));
            }
            Some(handles[0].handle)
        }
        ControllerMessage::Status { .. } => {
            close_received(&handles, counts.handles);
            return Err(failure(33));
        }
    };
    let action = match resident.accept(message, counts.handles as u32) {
        Ok(action) => action,
        Err(_) => {
            if counts.handles == 1 {
                if let Some(replacement) = replacement {
                    let _ = close_handle(replacement);
                }
            }
            return Err(failure(34));
        }
    };
    Ok((replacement, action))
}

#[cfg(not(feature = "wyr1c4-production"))]
fn launch_driver(
    bootstrap: DwHandle,
    resident: &mut wyrmroot_devmgr::ResidentController,
) -> Result<DwHandle, u32> {
    let (retained, child) = create_channel(DIRECT_CONTROL_RIGHTS).map_err(|_| failure(44))?;
    if validate_fresh(retained, DW_OBJECT_TYPE_CHANNEL, DIRECT_CONTROL_RIGHTS).is_err()
        || validate_fresh(child, DW_OBJECT_TYPE_CHANNEL, DIRECT_CONTROL_RIGHTS).is_err()
    {
        let _ = close_handle(child);
        let _ = close_handle(retained);
        return Err(failure(45));
    }
    let request = match resident.issue_driver_launch(true, DirectControlRights::ExactReduced) {
        Ok(request) => request,
        Err(_) => {
            let _ = close_handle(child);
            let _ = close_handle(retained);
            return Err(failure(46));
        }
    };
    let mut bytes = [0u8; LAUNCH_REQUEST_BYTES];
    if encode_request(request, &mut bytes).is_err() {
        let _ = close_handle(child);
        let _ = close_handle(retained);
        return Err(failure(47));
    }
    let transfer = DwHandleTransferV1 {
        handle: child,
        requested_rights: CHILD_CHANNEL_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if send_channel(bootstrap, &bytes, core::slice::from_ref(&transfer)).is_err() {
        let _ = close_handle(child);
        let _ = close_handle(retained);
        return Err(failure(48));
    }

    // Construction acknowledgement and direct CONTROL_READY share one
    // absolute checked deadline. A late first phase cannot mint a fresh
    // readiness budget for the second phase.
    let deadline = monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .map_err(|_| failure(49))?;
    wait_readable(bootstrap, deadline, 50)?;
    let mut response = [0u8; LAUNCH_RESPONSE_BYTES];
    let mut response_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(bootstrap, &mut response, &mut response_handles)
        .map_err(|_| failure(51))?;
    if counts.bytes != response.len() || counts.handles != 0 {
        close_received(&response_handles, counts.handles);
        let _ = close_handle(retained);
        return Err(failure(52));
    }
    if parse_constructed(&response, request).is_err() || resident.driver_constructed().is_err() {
        let _ = close_handle(retained);
        return Err(failure(53));
    }

    wait_readable(retained, deadline, 54)?;
    let mut control = [0u8; CONTROL_READY_BYTES];
    let mut control_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts =
        receive_channel(retained, &mut control, &mut control_handles).map_err(|_| failure(55))?;
    if counts.bytes != control.len() || counts.handles != 0 {
        close_received(&control_handles, counts.handles);
        let _ = close_handle(retained);
        return Err(failure(56));
    }
    let message = parse_control(&control).map_err(|_| failure(57))?;
    resident
        .accept_driver_control_ready(message)
        .map_err(|_| failure(58))?;
    Ok(retained)
}

#[cfg(not(feature = "wyr1c4-production"))]
fn wait_readable(
    handle: DwHandle,
    deadline: deepwyrm_syscall::DwDeadline,
    stage: u32,
) -> Result<(), u32> {
    let observed = wait_many(core::slice::from_ref(&wait_item(handle)), deadline)
        .map_err(|_| failure(stage))?;
    if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(failure(stage));
    }
    Ok(())
}

fn send_resident_status(
    bootstrap: DwHandle,
    resident: &wyrmroot_devmgr::ResidentController,
    status: StatusCode,
) -> Result<(), u32> {
    let message = resident.report(status).map_err(|_| failure(35))?;
    let mut bytes = [0u8; STATUS_BYTES];
    encode_controller(message, &mut bytes).map_err(|_| failure(36))?;
    send_channel(bootstrap, &bytes, &[]).map_err(|_| failure(37))
}

fn validate_fresh(handle: DwHandle, object_type: DwObjectType, rights: DwRights) -> Result<(), ()> {
    let actual: CapabilityInfo<DwObjectType, DwRights> =
        query_capability_info(handle).map_err(|_| ())?;
    if actual.object_type != object_type || actual.rights != rights {
        return Err(());
    }
    Ok(())
}

fn wait_item(handle: DwHandle) -> DwWaitItemV1 {
    DwWaitItemV1 {
        handle,
        signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
    }
}

fn close_received(handles: &[DwReceivedHandleInfoV1], count: usize) {
    for info in handles.iter().take(count.min(handles.len())) {
        let _ = close_handle(info.handle);
    }
}

fn close_optional(handle: Option<DwHandle>) {
    if let Some(handle) = handle {
        let _ = close_handle(handle);
    }
}

const fn failure(stage: u32) -> u32 {
    FAILURE_BASE | stage
}

wyrmroot_runtime::native_entry!(crate::main);

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    panic_abort()
}
