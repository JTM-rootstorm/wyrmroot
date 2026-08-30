#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;
#[cfg(feature = "wyr1c6-production")]
use deepwyrm_syscall::DW_STATUS_TIMED_OUT;
use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL,
    DW_OBJECT_TYPE_MEMORY_OBJECT, DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT, DW_RIGHT_READ,
    DW_RIGHT_TRANSFER, DW_RIGHT_WRITE, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DwHandle,
    DwObjectType, DwReceivedHandleInfoV1, DwRights, DwWaitItemV1,
};
#[cfg(any(
    not(any(feature = "wyr1c4-production", feature = "wyr1c5-production")),
    feature = "wyr1c5-production"
))]
use deepwyrm_syscall::{DW_HANDLE_TRANSFER_MOVE, DW_RIGHT_WAIT, DwHandleTransferV1};
#[cfg(feature = "wyr1c5-production")]
use deepwyrm_syscall::{
    DW_INTERRUPT_INFO_V1_SIZE, DW_INTERRUPT_INFO_V1_VERSION, DW_INTERRUPT_STATE_ARMED,
    DW_OBJECT_TYPE_INTERRUPT,
};
#[cfg(any(feature = "wyr1c4-production", feature = "wyr1c5-production"))]
use deepwyrm_syscall::{
    DW_OBJECT_TYPE_DEVICE_RESOURCE, DW_OBJECT_TYPE_TASK_GROUP, DW_RIGHT_MODIFY,
};
#[cfg(feature = "wyr1c6-selector29")]
use deepwyrm_syscall::{DW_SIGNAL_WRITABLE, DW_STATUS_WOULD_BLOCK};
#[cfg(feature = "wyr1c6-production")]
use wyrmroot_device_proto::driver_launch::{
    C6_FACT_BYTES, C6Fact, REAPED_RESPONSE_BYTES, encode_c6_fact, encode_driver_retired,
    parse_reaped,
};
#[cfg(feature = "wyr1c6-selector29")]
use wyrmroot_device_proto::selector29_should_fail;
#[cfg(feature = "wyr1c6-production")]
use wyrmroot_device_proto::{ControlMessage, FailureCode};
use wyrmroot_device_proto::{
    ControllerMessage, StatusCode,
    controller::{
        INSTALL_BYTES, STATUS_BYTES, encode as encode_controller, parse as parse_controller,
    },
};
#[cfg(not(any(feature = "wyr1c4-production", feature = "wyr1c5-production")))]
use wyrmroot_device_proto::{
    DirectControlRights,
    control::{CONTROL_READY_BYTES, parse as parse_control},
    driver_launch::{
        LAUNCH_REQUEST_BYTES, LAUNCH_RESPONSE_BYTES, encode_request, parse_constructed,
    },
};
#[cfg(feature = "wyr1c5-production")]
use wyrmroot_device_proto::{
    DirectControlRights,
    control::{
        READY_BYTES, RESOURCE_BUNDLE_BYTES, encode as encode_control, parse as parse_control,
    },
    driver_launch::{
        LAUNCH_REQUEST_BYTES, LAUNCH_RESPONSE_BYTES, encode_request, parse_constructed,
    },
};
use wyrmroot_devmgr::ControllerAction;
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, DEVICE_MANIFEST_RIGHTS, HEADER_BYTES, LaunchProfile, SELF_ROOT_RIGHTS,
    encode_ready_for_profile,
};
#[cfg(not(any(feature = "wyr1c4-production", feature = "wyr1c5-production")))]
use wyrmroot_loader::launch::{DEVICE_COORDINATOR_BYTES, parse_device_coordinator_init};
#[cfg(any(feature = "wyr1c4-production", feature = "wyr1c5-production"))]
use wyrmroot_loader::launch::{
    DEVICE_COORDINATOR_RESOURCE_BYTES, RESOURCE_DOMAIN_CLAIM_RIGHTS,
    parse_device_coordinator_resource_init,
};
#[cfg(feature = "wyr1c4-production")]
use wyrmroot_registry_proto as _;
#[cfg(feature = "wyr1c5-production")]
use wyrmroot_registry_proto::{
    HEADER_BYTES as REGISTRY_HEADER_BYTES, Header as RegistryHeader, Message as RegistryMessage,
    MessageType as RegistryMessageType, encode_empty as encode_registry_empty,
    parse as parse_registry,
};
#[cfg(feature = "wyr1c6-production")]
use wyrmroot_runtime::NativeError;
#[cfg(feature = "wyr1c6-production")]
use wyrmroot_runtime::monotonic_active_now;
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, MappingPlan, StartupBlock, close_handle,
    map_bootfs_read_only, panic_abort, query_capability_info, query_memory_object_size,
    receive_channel, send_channel, unmap_bootfs, validate_bootstrap_channel, wait_many,
};
#[cfg(any(
    not(any(feature = "wyr1c4-production", feature = "wyr1c5-production")),
    feature = "wyr1c5-production"
))]
use wyrmroot_runtime::{WYR0_I_SUPERVISION_POLICY, create_channel, monotonic_deadline_after};
#[cfg(any(feature = "wyr1c4-production", feature = "wyr1c5-production"))]
use wyrmroot_runtime::{
    claim_device_resource, device_resource_info, require_device_resource_interrupt_feature,
};
#[cfg(feature = "wyr1c5-production")]
use wyrmroot_runtime::{create_interrupt, duplicate_handle, interrupt_info};

const FAILURE_BASE: u32 = 0xC101_0000;
#[cfg(any(
    not(any(feature = "wyr1c4-production", feature = "wyr1c5-production")),
    feature = "wyr1c5-production"
))]
const DIRECT_CONTROL_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0
        | DW_RIGHT_WRITE.0
        | DW_RIGHT_WAIT.0
        | DW_RIGHT_INSPECT.0
        | DW_RIGHT_DUPLICATE.0
        | DW_RIGHT_TRANSFER.0,
);
#[cfg(any(feature = "wyr1c4-production", feature = "wyr1c5-production"))]
const DEVICE_RESOURCE_CUSTODY_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0
        | DW_RIGHT_WRITE.0
        | DW_RIGHT_MODIFY.0
        | DW_RIGHT_DUPLICATE.0
        | DW_RIGHT_TRANSFER.0
        | DW_RIGHT_INSPECT.0,
);
#[cfg(feature = "wyr1c5-production")]
const DEVICE_RESOURCE_DRIVER_RIGHTS: DwRights =
    DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_INSPECT.0);
#[cfg(feature = "wyr1c5-production")]
const INTERRUPT_CUSTODY_RIGHTS: DwRights =
    DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_TRANSFER.0 | DW_RIGHT_INSPECT.0);
#[cfg(feature = "wyr1c5-production")]
const INTERRUPT_DRIVER_RIGHTS: DwRights =
    DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0);

fn main(startup: StartupBlock<'_>) -> u32 {
    run(startup).unwrap_or_else(|code| code)
}

fn run(startup: StartupBlock<'_>) -> Result<u32, u32> {
    let bootstrap = startup.bootstrap_channel().as_abi();
    let bootstrap_info = query_capability_info(bootstrap).map_err(|_| failure(1))?;
    validate_bootstrap_channel(bootstrap_info, BOOTSTRAP_CHANNEL_EXPECTATION)
        .map_err(|_| failure(2))?;

    #[cfg(not(any(feature = "wyr1c4-production", feature = "wyr1c5-production")))]
    let mut init = [0u8; DEVICE_COORDINATOR_BYTES];
    #[cfg(any(feature = "wyr1c4-production", feature = "wyr1c5-production"))]
    let mut init = [0u8; DEVICE_COORDINATOR_RESOURCE_BYTES];
    #[cfg(not(any(feature = "wyr1c4-production", feature = "wyr1c5-production")))]
    let mut handles = [DwReceivedHandleInfoV1::default(); 3];
    #[cfg(any(feature = "wyr1c4-production", feature = "wyr1c5-production"))]
    let mut handles = [DwReceivedHandleInfoV1::default(); 4];
    let counts = receive_channel(bootstrap, &mut init, &mut handles).map_err(|_| failure(3))?;
    if counts.bytes > init.len() || counts.handles != handles.len() {
        close_received(&handles, counts.handles);
        return Err(failure(4));
    }
    #[cfg(not(any(feature = "wyr1c4-production", feature = "wyr1c5-production")))]
    let parsed_result = parse_device_coordinator_init(&init[..counts.bytes], &handles);
    #[cfg(any(feature = "wyr1c4-production", feature = "wyr1c5-production"))]
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
    #[cfg(any(feature = "wyr1c4-production", feature = "wyr1c5-production"))]
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
    #[cfg(any(feature = "wyr1c4-production", feature = "wyr1c5-production"))]
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
    #[cfg(not(any(feature = "wyr1c4-production", feature = "wyr1c5-production")))]
    let launch_profile = LaunchProfile::DeviceCoordinator;
    #[cfg(any(feature = "wyr1c4-production", feature = "wyr1c5-production"))]
    let launch_profile = LaunchProfile::DeviceCoordinatorResourceDomain;
    let ready_len = encode_ready_for_profile(launch_profile, parsed.transaction_id, &mut ready)
        .map_err(|_| failure(14))?;
    send_channel(bootstrap, &ready[..ready_len], &[]).map_err(|_| failure(15))?;

    let mut publication = Some(publication);
    let mut driver_control = None;
    #[cfg(feature = "wyr1c4-production")]
    let mut _device_resource = None;
    #[cfg(feature = "wyr1c5-production")]
    let mut device_resource = None;
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
                #[cfg(feature = "wyr1c5-production")]
                if let Some(control) = driver_control {
                    let _ = send_driver_retire(control, &mut resident);
                }
                close_optional(driver_control);
                #[cfg(feature = "wyr1c5-production")]
                close_optional(device_resource.take());
                close_handle(bootstrap).map_err(|_| failure(19))?;
                return Err(failure(20));
            }
            let (replacement, action) = match receive_controller(bootstrap, &mut resident) {
                Ok(received) => received,
                Err(code) => {
                    close_optional(publication);
                    close_optional(driver_control);
                    #[cfg(feature = "wyr1c5-production")]
                    close_optional(device_resource.take());
                    let _ = close_handle(bootstrap);
                    return Err(code);
                }
            };
            if let Some(replacement) = replacement {
                if let Some(old) = publication.replace(replacement) {
                    let _ = close_handle(replacement);
                    let _ = close_handle(old);
                    #[cfg(feature = "wyr1c5-production")]
                    close_optional(device_resource.take());
                    let _ = close_handle(bootstrap);
                    return Err(failure(21));
                }
            }
            #[cfg(any(feature = "wyr1c4-production", feature = "wyr1c5-production"))]
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
                #[cfg(feature = "wyr1c4-production")]
                {
                    _device_resource = Some(resource);
                }
                #[cfg(feature = "wyr1c5-production")]
                {
                    device_resource = Some(resource);
                }
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
                    #[cfg(feature = "wyr1c4-production")]
                    close_optional(_device_resource.take());
                    #[cfg(feature = "wyr1c5-production")]
                    close_optional(device_resource.take());
                    let _ = close_handle(domain);
                    close_optional(publication);
                    close_optional(driver_control);
                    let _ = close_handle(bootstrap);
                    return Err(code);
                }
                if close_handle(domain).is_err() {
                    #[cfg(feature = "wyr1c4-production")]
                    close_optional(_device_resource.take());
                    #[cfg(feature = "wyr1c5-production")]
                    close_optional(device_resource.take());
                    close_optional(publication);
                    close_optional(driver_control);
                    let _ = close_handle(bootstrap);
                    return Err(failure(52));
                }
            }
            #[cfg(not(any(feature = "wyr1c4-production", feature = "wyr1c5-production")))]
            let status = StatusCode::OperationalWaitingForDeviceBundle;
            #[cfg(any(feature = "wyr1c4-production", feature = "wyr1c5-production"))]
            let status = StatusCode::OperationalResourceOwned;
            if let Err(code) = send_resident_status(bootstrap, &resident, status) {
                close_optional(publication);
                close_optional(driver_control);
                #[cfg(feature = "wyr1c4-production")]
                close_optional(_device_resource.take());
                #[cfg(feature = "wyr1c5-production")]
                close_optional(device_resource.take());
                let _ = close_handle(bootstrap);
                return Err(code);
            }
            #[cfg(feature = "wyr1c6-selector29")]
            if action == ControllerAction::InitialPublicationBound
                && resident.status().supervisor_generation.0
                    == wyrmroot_device_proto::SELECTOR29_FAILURE_SUPERVISOR_GENERATION
            {
                let supervisor = resident.status().supervisor_generation.0;
                send_c6_fact(
                    bootstrap,
                    C6Fact {
                        event: 1,
                        lease: resident.bundle_generation().ok_or(failure(129))?.0,
                        binding: wyrmroot_devmgr::COM2_RESOURCE_ID,
                        value: supervisor,
                        aux: wyrmroot_device_proto::manifest::COM2_ROLE_ID.0,
                    },
                )?;
                send_c6_fact(
                    bootstrap,
                    C6Fact {
                        event: 2,
                        lease: resident.bundle_generation().ok_or(failure(130))?.0,
                        binding: wyrmroot_devmgr::COM2_RESOURCE_ID,
                        value: supervisor,
                        aux: wyrmroot_device_proto::manifest::COM2_ROLE_ID.0,
                    },
                )?;
            } else if action == ControllerAction::InitialPublicationBound {
                let supervisor = resident.status().supervisor_generation.0;
                let lease = resident.bundle_generation().ok_or(failure(131))?.0;
                send_c6_fact(
                    bootstrap,
                    C6Fact {
                        event: 19,
                        lease,
                        binding: wyrmroot_devmgr::COM2_RESOURCE_ID,
                        value: supervisor,
                        aux: wyrmroot_device_proto::manifest::COM2_ROLE_ID.0,
                    },
                )?;
                for event in [20, 21, 22] {
                    send_c6_fact(
                        bootstrap,
                        C6Fact {
                            event,
                            lease,
                            binding: wyrmroot_devmgr::COM2_RESOURCE_ID,
                            value: supervisor,
                            aux: wyrmroot_device_proto::manifest::COM2_ROLE_ID.0,
                        },
                    )?;
                }
            }
            #[cfg(not(any(feature = "wyr1c4-production", feature = "wyr1c5-production")))]
            if action == ControllerAction::InitialPublicationBound {
                if driver_control.is_some() {
                    return Err(failure(38));
                }
                driver_control = Some(launch_driver(bootstrap, &mut resident)?);
            }
            #[cfg(feature = "wyr1c5-production")]
            if action == ControllerAction::InitialPublicationBound
                && (cfg!(not(feature = "wyr1c6-selector29"))
                    || resident.status().supervisor_generation.0 == 1)
            {
                let parent = device_resource.ok_or(failure(53))?;
                let launched = launch_driver_with_bundle(
                    bootstrap,
                    publication.ok_or(failure(54))?,
                    parent,
                    &mut resident,
                );
                driver_control = match launched {
                    Ok(control) => Some(control),
                    Err(code) => {
                        close_optional(device_resource.take());
                        close_optional(publication.take());
                        let _ = close_handle(bootstrap);
                        return Err(code);
                    }
                };
            } else if resident.driver_ready() {
                let republished = publish_driver(
                    publication.ok_or(failure(55))?,
                    resident.active_driver_request().ok_or(failure(56))?,
                    &mut resident,
                );
                if let Err(code) = republished {
                    if let Some(control) = driver_control.take() {
                        let _ = send_driver_retire(control, &mut resident);
                        let _ = close_handle(control);
                    }
                    close_optional(device_resource.take());
                    close_optional(publication.take());
                    let _ = close_handle(bootstrap);
                    return Err(code);
                }
            }
            continue;
        }

        if Some(index) == driver_index {
            let control = driver_control.take().ok_or(failure(39))?;
            // The C3 acceptance actor may exit after its direct READY.  Peer
            // closure is the only reached notification path; no resource was
            // ever delegated, so reaping cannot lose future custody.
            #[cfg(feature = "wyr1c6-production")]
            if observed.observed.0 & (DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0) != 0 {
                let request = resident.active_driver_request().ok_or(failure(40))?;
                observe_driver_failure(
                    control,
                    request,
                    &mut resident,
                    observed.observed.0 & DW_SIGNAL_READABLE.0 != 0,
                    observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0,
                )?;
                #[cfg(feature = "wyr1c6-selector29")]
                let stale_control = control;
                #[cfg(feature = "wyr1c6-selector29")]
                send_c6_fact(
                    bootstrap,
                    C6Fact {
                        event: 6,
                        lease: resident.driver_lease_generation().ok_or(failure(132))?,
                        binding: resident.driver_irq_binding().ok_or(failure(133))?,
                        value: request.attempt_generation.0,
                        aux: request.endpoint.generation.0,
                    },
                )?;
                close_handle(control).map_err(|_| failure(41))?;
                let old_publication = publication.take().ok_or(failure(42))?;
                retire_driver_publication(old_publication, request, &resident)?;
                #[cfg(feature = "wyr1c6-selector29")]
                let stale_publication = old_publication;
                #[cfg(not(feature = "wyr1c6-selector29"))]
                close_handle(old_publication).map_err(|_| failure(149))?;
                #[cfg(feature = "wyr1c6-selector29")]
                close_handle(stale_publication).map_err(|_| failure(149))?;
                #[cfg(feature = "wyr1c6-selector29")]
                {
                    let binding = resident.active_binding().ok_or(failure(134))?;
                    send_c6_fact(
                        bootstrap,
                        C6Fact {
                            event: 7,
                            lease: resident.driver_lease_generation().ok_or(failure(135))?,
                            binding: binding.generation.0,
                            value: request.attempt_generation.0,
                            aux: binding.endpoint.generation.0,
                        },
                    )?;
                }
                resident.publication_retired().map_err(|_| failure(43))?;
                await_driver_reaped(bootstrap, request)?;
                resident.reap_driver().map_err(|_| failure(44))?;
                #[cfg(feature = "wyr1c6-selector29")]
                send_c6_fact(
                    bootstrap,
                    C6Fact {
                        event: 8,
                        lease: resident.driver_lease_generation().ok_or(failure(136))?,
                        binding: resident.driver_irq_binding().ok_or(failure(137))?,
                        value: request.attempt_generation.0,
                        aux: request.endpoint.generation.0,
                    },
                )?;
                #[cfg(feature = "wyr1c6-selector29")]
                send_c6_fact(
                    bootstrap,
                    C6Fact {
                        event: 9,
                        lease: resident.driver_lease_generation().ok_or(failure(138))?,
                        binding: resident.driver_irq_binding().ok_or(failure(139))?,
                        value: 1,
                        aux: 0,
                    },
                )?;
                send_driver_retired(bootstrap, request)?;
                let rebind_deadline =
                    monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
                        .map_err(|_| failure(45))?;
                wait_readable(bootstrap, rebind_deadline, 46)?;
                let (replacement, action) = receive_controller(bootstrap, &mut resident)?;
                if action != ControllerAction::PublicationRebound {
                    return Err(failure(47));
                }
                let replacement = replacement.ok_or(failure(48))?;
                if publication.replace(replacement).is_some() {
                    return Err(failure(49));
                }
                let now = monotonic_active_now().map_err(|_| failure(50))?;
                resident
                    .complete_driver_failure_cleanup(now)
                    .map_err(|_| failure(51))?;
                if resident.status().state
                    == wyrmroot_device_proto::CoordinatorState::PermanentFailure
                {
                    close_optional(device_resource.take());
                    close_optional(publication.take());
                    close_handle(bootstrap).map_err(|_| failure(52))?;
                    return Err(failure(96));
                }
                let retry_until = resident.retry_until_ns().ok_or(failure(53))?;
                match wait_many(
                    core::slice::from_ref(&wait_item(bootstrap)),
                    deepwyrm_syscall::DwDeadline(retry_until),
                ) {
                    Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {}
                    Ok(_) | Err(_) => return Err(failure(54)),
                }
                let now = monotonic_active_now().map_err(|_| failure(55))?;
                resident.driver_retry_ready(now).map_err(|_| failure(56))?;
                let parent = device_resource.ok_or(failure(57))?;
                let launched = launch_driver_with_bundle(
                    bootstrap,
                    publication.ok_or(failure(58))?,
                    parent,
                    &mut resident,
                )?;
                driver_control = Some(launched);
                #[cfg(feature = "wyr1c6-selector29")]
                if resident
                    .active_driver_request()
                    .is_some_and(|request| request.attempt_generation.0 > 1)
                {
                    probe_stale_driver_endpoint(stale_control, request, &resident)?;
                    probe_stale_publication(stale_publication, request, &resident)?;
                    #[cfg(feature = "wyr1c6-selector29")]
                    {
                        let old_binding = resident.retired_binding().ok_or(failure(145))?;
                        let binding = resident.active_binding().ok_or(failure(142))?;
                        send_c6_fact(
                            bootstrap,
                            C6Fact {
                                event: 13,
                                lease: resident.driver_lease_generation().ok_or(failure(143))?,
                                binding: old_binding.generation.0,
                                value: resident.retired_driver_attempt().ok_or(failure(146))?,
                                aux: 3,
                            },
                        )?;
                        send_c6_fact(
                            bootstrap,
                            C6Fact {
                                event: 14,
                                lease: resident.driver_lease_generation().ok_or(failure(143))?,
                                binding: binding.generation.0,
                                value: resident.status().supervisor_generation.0,
                                aux: 0,
                            },
                        )?;
                    }
                    // U2 has reached READY and P2 has been committed by
                    // launch_driver_with_bundle. Returning now lets init's
                    // existing RRC-A path reap U2 and replace D1.
                    return Err(failure(126));
                }
                continue;
            }
            #[cfg(not(feature = "wyr1c6-production"))]
            if observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 {
                let _ = close_handle(control);
                #[cfg(feature = "wyr1c5-production")]
                {
                    close_optional(device_resource.take());
                    close_optional(publication.take());
                    let _ = close_handle(bootstrap);
                }
                return Err(failure(40));
            }
            close_handle(control).map_err(|_| failure(41))?;
            resident.reap_driver().map_err(|_| failure(42))?;
            #[cfg(feature = "wyr1c5-production")]
            {
                close_optional(device_resource.take());
                close_optional(publication.take());
                let _ = close_handle(bootstrap);
                return Err(failure(96));
            }
            #[cfg(not(feature = "wyr1c5-production"))]
            continue;
        }

        if Some(index) != publication_index {
            return Err(failure(43));
        }
        if observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 {
            close_optional(publication);
            #[cfg(feature = "wyr1c5-production")]
            if let Some(control) = driver_control {
                let _ = send_driver_retire(control, &mut resident);
            }
            close_optional(driver_control);
            #[cfg(feature = "wyr1c5-production")]
            close_optional(device_resource.take());
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

#[cfg(feature = "wyr1c6-production")]
fn observe_driver_failure(
    control: DwHandle,
    request: wyrmroot_device_proto::DriverLaunchRequest,
    resident: &mut wyrmroot_devmgr::ResidentController,
    readable: bool,
    peer_closed: bool,
) -> Result<(), u32> {
    if !readable {
        return resident
            .driver_failed(request.endpoint)
            .map_err(|_| failure(105));
    }
    let mut bytes = [0u8; wyrmroot_device_proto::control::FAILURE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(control, &mut bytes, &mut handles).map_err(|_| failure(100))?;
    if counts.bytes != bytes.len() || counts.handles != 0 {
        close_received(&handles, counts.handles);
        if peer_closed && counts.bytes == 0 && counts.handles == 0 {
            return resident
                .driver_failed(request.endpoint)
                .map_err(|_| failure(105));
        }
        return Err(failure(101));
    }
    let message = wyrmroot_device_proto::control::parse(&bytes).map_err(|_| failure(102))?;
    #[cfg(feature = "wyr1c6-selector29")]
    let expected_code = FailureCode::IntentionalRestart;
    #[cfg(not(feature = "wyr1c6-selector29"))]
    let expected_code = FailureCode::DriverExited;
    let expected = ControlMessage::Failure {
        role_id: request.role_id,
        bundle_generation: resident.bundle_generation().ok_or(failure(103))?,
        attempt_generation: request.attempt_generation,
        endpoint: request.endpoint,
        transaction_id: request.transaction_id,
        code: expected_code,
    };
    if message != expected {
        return Err(failure(104));
    }
    #[cfg(feature = "wyr1c6-selector29")]
    if !selector29_should_fail(request.supervisor_generation, request.attempt_generation) {
        return Err(failure(104));
    }
    resident
        .driver_failed(request.endpoint)
        .map_err(|_| failure(105))
}

#[cfg(feature = "wyr1c6-production")]
fn retire_driver_publication(
    publication: DwHandle,
    request: wyrmroot_device_proto::DriverLaunchRequest,
    resident: &wyrmroot_devmgr::ResidentController,
) -> Result<(), u32> {
    let binding = resident.active_binding().ok_or(failure(106))?;
    let header = RegistryHeader {
        message_type: RegistryMessageType::Retire,
        registry_generation: binding.generation.0,
        endpoint_id: binding.endpoint.id.0,
        endpoint_generation: binding.endpoint.generation.0,
        transaction_id: request.transaction_id,
    };
    let mut bytes = [0u8; REGISTRY_HEADER_BYTES];
    let size = encode_registry_empty(header, &mut bytes).map_err(|_| failure(107))?;
    send_channel(publication, &bytes[..size], &[]).map_err(|_| failure(108))?;
    let deadline = monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .map_err(|_| failure(109))?;
    wait_readable(publication, deadline, 110)?;
    let mut response = [0u8; REGISTRY_HEADER_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts =
        receive_channel(publication, &mut response, &mut handles).map_err(|_| failure(111))?;
    if counts.bytes != response.len() || counts.handles != 0 {
        close_received(&handles, counts.handles);
        return Err(failure(112));
    }
    let parsed = parse_registry(&response, 0).map_err(|_| failure(113))?;
    if parsed.header
        != (RegistryHeader {
            message_type: RegistryMessageType::Retired,
            ..header
        })
        || parsed.message != RegistryMessage::Retired
    {
        return Err(failure(114));
    }
    Ok(())
}

#[cfg(feature = "wyr1c6-selector29")]
fn probe_stale_driver_endpoint(
    control: DwHandle,
    request: wyrmroot_device_proto::DriverLaunchRequest,
    resident: &wyrmroot_devmgr::ResidentController,
) -> Result<(), u32> {
    let message = ControlMessage::Retire {
        role_id: request.role_id,
        bundle_generation: resident.bundle_generation().ok_or(failure(117))?,
        attempt_generation: request.attempt_generation,
        endpoint: request.endpoint,
        transaction_id: request.transaction_id,
    };
    let mut bytes = [0u8; wyrmroot_device_proto::control::RETIRE_BYTES];
    wyrmroot_device_proto::control::encode(message, &mut bytes).map_err(|_| failure(118))?;
    if send_channel(control, &bytes, &[]).is_ok() {
        return Err(failure(119));
    }
    Ok(())
}

#[cfg(feature = "wyr1c6-selector29")]
fn probe_stale_publication(
    publication: DwHandle,
    request: wyrmroot_device_proto::DriverLaunchRequest,
    resident: &wyrmroot_devmgr::ResidentController,
) -> Result<(), u32> {
    let binding = resident.retired_binding().ok_or(failure(149))?;
    let header = RegistryHeader {
        message_type: RegistryMessageType::Publish,
        registry_generation: binding.generation.0,
        endpoint_id: binding.endpoint.id.0,
        endpoint_generation: binding.endpoint.generation.0,
        transaction_id: request.transaction_id,
    };
    let mut bytes = [0u8; REGISTRY_HEADER_BYTES];
    let size = encode_registry_empty(header, &mut bytes).map_err(|_| failure(150))?;
    if send_channel(publication, &bytes[..size], &[]).is_ok() {
        return Err(failure(151));
    }
    Ok(())
}

#[cfg(feature = "wyr1c6-production")]
fn await_driver_reaped(
    bootstrap: DwHandle,
    request: wyrmroot_device_proto::DriverLaunchRequest,
) -> Result<(), u32> {
    let deadline = monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns)
        .map_err(|_| failure(115))?;
    wait_readable(bootstrap, deadline, 116)?;
    let mut bytes = [0u8; REAPED_RESPONSE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(bootstrap, &mut bytes, &mut handles).map_err(|_| failure(117))?;
    if counts.bytes != bytes.len() || counts.handles != 0 {
        close_received(&handles, counts.handles);
        return Err(failure(118));
    }
    parse_reaped(&bytes, request).map_err(|_| failure(119))
}

#[cfg(feature = "wyr1c6-production")]
fn send_driver_retired(
    bootstrap: DwHandle,
    request: wyrmroot_device_proto::DriverLaunchRequest,
) -> Result<(), u32> {
    let mut bytes = [0u8; wyrmroot_device_proto::driver_launch::DRIVER_RETIRED_BYTES];
    encode_driver_retired(request, &mut bytes).map_err(|_| failure(120))?;
    send_channel(bootstrap, &bytes, &[]).map_err(|_| failure(121))
}

#[cfg(not(any(feature = "wyr1c4-production", feature = "wyr1c5-production")))]
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

#[cfg(feature = "wyr1c5-production")]
fn launch_driver_with_bundle(
    bootstrap: DwHandle,
    publication: DwHandle,
    parent_resource: DwHandle,
    resident: &mut wyrmroot_devmgr::ResidentController,
) -> Result<DwHandle, u32> {
    let (retained, child) = create_channel(DIRECT_CONTROL_RIGHTS).map_err(|_| failure(57))?;
    if validate_fresh(retained, DW_OBJECT_TYPE_CHANNEL, DIRECT_CONTROL_RIGHTS).is_err()
        || validate_fresh(child, DW_OBJECT_TYPE_CHANNEL, DIRECT_CONTROL_RIGHTS).is_err()
    {
        let _ = close_handle(child);
        let _ = close_handle(retained);
        return Err(failure(58));
    }
    let request =
        match resident.issue_driver_launch_with_bundle(true, DirectControlRights::ExactReduced) {
            Ok(request) => request,
            Err(_) => {
                let _ = close_handle(child);
                let _ = close_handle(retained);
                return Err(failure(59));
            }
        };
    let mut launch = [0u8; LAUNCH_REQUEST_BYTES];
    if encode_request(request, &mut launch).is_err() {
        let _ = close_handle(child);
        let _ = close_handle(retained);
        return Err(failure(60));
    }
    let child_transfer = DwHandleTransferV1 {
        handle: child,
        requested_rights: CHILD_CHANNEL_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if send_channel(bootstrap, &launch, core::slice::from_ref(&child_transfer)).is_err() {
        let _ = close_handle(child);
        let _ = close_handle(retained);
        return Err(failure(61));
    }

    let deadline = match monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns) {
        Ok(deadline) => deadline,
        Err(_) => {
            let _ = close_handle(retained);
            return Err(failure(62));
        }
    };
    if wait_readable(bootstrap, deadline, 63).is_err() {
        let _ = close_handle(retained);
        return Err(failure(63));
    }
    let mut constructed = [0u8; LAUNCH_RESPONSE_BYTES];
    let mut constructed_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = match receive_channel(bootstrap, &mut constructed, &mut constructed_handles) {
        Ok(counts) => counts,
        Err(_) => {
            let _ = close_handle(retained);
            return Err(failure(64));
        }
    };
    if counts.bytes != constructed.len() || counts.handles != 0 {
        close_received(&constructed_handles, counts.handles);
        let _ = close_handle(retained);
        return Err(failure(65));
    }
    if parse_constructed(&constructed, request).is_err() || resident.driver_constructed().is_err() {
        let _ = close_handle(retained);
        return Err(failure(66));
    }

    let reduced = match duplicate_handle(parent_resource, DEVICE_RESOURCE_DRIVER_RIGHTS) {
        Ok(handle) => handle,
        Err(_) => {
            let _ = close_handle(retained);
            return Err(failure(67));
        }
    };
    let interrupt = match create_interrupt(parent_resource, INTERRUPT_CUSTODY_RIGHTS) {
        Ok(handle) => handle,
        Err(_) => {
            let _ = close_handle(reduced);
            let _ = close_handle(retained);
            return Err(failure(68));
        }
    };
    let intake = (|| {
        validate_fresh(
            reduced,
            DW_OBJECT_TYPE_DEVICE_RESOURCE,
            DEVICE_RESOURCE_DRIVER_RIGHTS,
        )
        .map_err(|_| failure(69))?;
        validate_fresh(
            interrupt,
            DW_OBJECT_TYPE_INTERRUPT,
            INTERRUPT_CUSTODY_RIGHTS,
        )
        .map_err(|_| failure(70))?;
        let resource = device_resource_info(reduced).map_err(|_| failure(71))?;
        let interrupt_info = interrupt_info(interrupt).map_err(|_| failure(72))?;
        if resource.resource_id != wyrmroot_devmgr::COM2_RESOURCE_ID
            || Some(wyrmroot_device_proto::coordinator::BundleGeneration(
                resource.lease_generation,
            )) != resident.bundle_generation()
            || interrupt_info.size != DW_INTERRUPT_INFO_V1_SIZE
            || interrupt_info.version != DW_INTERRUPT_INFO_V1_VERSION
            || interrupt_info.source != resource.interrupt_source
            || interrupt_info.state != DW_INTERRUPT_STATE_ARMED
            || interrupt_info.object_generation == 0
            || interrupt_info.binding_generation == 0
            || interrupt_info.parent_resource_id != resource.resource_id
            || interrupt_info.parent_lease_generation != resource.lease_generation
            || interrupt_info.flags.0 != 0
            || interrupt_info.reserved0 != 0
            || interrupt_info.reserved != 0
        {
            return Err(failure(73));
        }
        Ok::<_, u32>((resource.lease_generation, interrupt_info.binding_generation))
    })();
    let (lease_generation, irq_binding) = match intake {
        Ok(value) => value,
        Err(code) => {
            let _ = close_handle(interrupt);
            let _ = close_handle(reduced);
            let _ = close_handle(retained);
            return Err(code);
        }
    };
    if resident
        .set_driver_bindings(lease_generation, irq_binding)
        .is_err()
    {
        let _ = close_handle(interrupt);
        let _ = close_handle(reduced);
        let _ = close_handle(retained);
        return Err(failure(74));
    }

    let bundle = match resident.resource_bundle_message() {
        Ok(message) => message,
        Err(_) => {
            let _ = close_handle(interrupt);
            let _ = close_handle(reduced);
            let _ = close_handle(retained);
            return Err(failure(74));
        }
    };
    let mut bundle_bytes = [0u8; RESOURCE_BUNDLE_BYTES];
    if encode_control(bundle, &mut bundle_bytes).is_err() {
        let _ = close_handle(interrupt);
        let _ = close_handle(reduced);
        let _ = close_handle(retained);
        return Err(failure(75));
    }
    let transfers = [
        DwHandleTransferV1 {
            handle: reduced,
            requested_rights: DEVICE_RESOURCE_DRIVER_RIGHTS,
            operation: DW_HANDLE_TRANSFER_MOVE,
            reserved0: 0,
            reserved: [0; 2],
        },
        DwHandleTransferV1 {
            handle: interrupt,
            requested_rights: INTERRUPT_DRIVER_RIGHTS,
            operation: DW_HANDLE_TRANSFER_MOVE,
            reserved0: 0,
            reserved: [0; 2],
        },
    ];
    if send_channel(retained, &bundle_bytes, &transfers).is_err() {
        let _ = close_handle(interrupt);
        let _ = close_handle(reduced);
        let _ = close_handle(retained);
        return Err(failure(76));
    }
    if resident.bundle_transferred().is_err() {
        let _ = close_handle(retained);
        return Err(failure(92));
    }

    #[cfg(feature = "wyr1c6-selector29")]
    if request.supervisor_generation.0 == 1 {
        send_c6_fact(
            bootstrap,
            C6Fact {
                event: if request.attempt_generation.0 == 1 {
                    3
                } else {
                    10
                },
                lease: lease_generation,
                binding: irq_binding,
                value: request.attempt_generation.0,
                aux: request.endpoint.generation.0,
            },
        )?;
    }

    if wait_readable(retained, deadline, 77).is_err() {
        let _ = close_handle(retained);
        return Err(failure(77));
    }
    let mut ready = [0u8; READY_BYTES];
    let mut ready_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = match receive_channel(retained, &mut ready, &mut ready_handles) {
        Ok(counts) => counts,
        Err(_) => {
            let _ = close_handle(retained);
            return Err(failure(78));
        }
    };
    if counts.bytes != ready.len() || counts.handles != 0 {
        close_received(&ready_handles, counts.handles);
        let _ = close_handle(retained);
        return Err(failure(79));
    }
    let ready = match parse_control(&ready) {
        Ok(ready) => ready,
        Err(_) => {
            let _ = close_handle(retained);
            return Err(failure(80));
        }
    };
    if resident.accept_driver_ready(ready).is_err() {
        let _ = close_handle(retained);
        return Err(failure(81));
    }
    #[cfg(feature = "wyr1c6-selector29")]
    if request.supervisor_generation.0 == 1 {
        send_c6_fact(
            bootstrap,
            C6Fact {
                event: if request.attempt_generation.0 == 1 {
                    4
                } else {
                    11
                },
                lease: lease_generation,
                binding: irq_binding,
                value: request.attempt_generation.0,
                aux: request.endpoint.generation.0,
            },
        )?;
    }
    #[cfg(feature = "wyr1c6-selector29")]
    let should_publish = request.supervisor_generation.0
        == wyrmroot_device_proto::SELECTOR29_FAILURE_SUPERVISOR_GENERATION;
    #[cfg(not(feature = "wyr1c6-selector29"))]
    let should_publish = true;
    if should_publish {
        if let Err(code) = publish_driver(publication, request, resident) {
            let _ = send_driver_retire(retained, resident);
            let _ = close_handle(retained);
            return Err(code);
        }
        #[cfg(feature = "wyr1c6-selector29")]
        {
            let publication_binding = resident.active_binding().ok_or(failure(131))?;
            send_c6_fact(
                bootstrap,
                C6Fact {
                    event: if request.attempt_generation.0 == 1 {
                        5
                    } else {
                        12
                    },
                    lease: lease_generation,
                    binding: publication_binding.generation.0,
                    value: request.attempt_generation.0,
                    aux: publication_binding.endpoint.generation.0,
                },
            )?;
        }
    }
    #[cfg(feature = "wyr1c6-selector29")]
    if selector29_should_fail(request.supervisor_generation, request.attempt_generation) {
        send_failure_trigger(retained, request, resident)?;
    }
    Ok(retained)
}

#[cfg(feature = "wyr1c6-selector29")]
fn send_failure_trigger(
    control: DwHandle,
    request: wyrmroot_device_proto::DriverLaunchRequest,
    resident: &wyrmroot_devmgr::ResidentController,
) -> Result<(), u32> {
    let message = ControlMessage::TriggerFailure {
        role_id: request.role_id,
        bundle_generation: resident.bundle_generation().ok_or(failure(97))?,
        attempt_generation: request.attempt_generation,
        endpoint: request.endpoint,
        transaction_id: request.transaction_id,
    };
    let mut bytes = [0u8; wyrmroot_device_proto::control::TRIGGER_FAILURE_BYTES];
    wyrmroot_device_proto::control::encode(message, &mut bytes).map_err(|_| failure(98))?;
    send_channel(control, &bytes, &[]).map_err(|_| failure(99))
}

#[cfg(feature = "wyr1c5-production")]
fn publish_driver(
    publication: DwHandle,
    request: wyrmroot_device_proto::DriverLaunchRequest,
    resident: &mut wyrmroot_devmgr::ResidentController,
) -> Result<(), u32> {
    let binding = resident.active_binding().ok_or(failure(82))?;
    let header = RegistryHeader {
        message_type: RegistryMessageType::Publish,
        registry_generation: binding.generation.0,
        endpoint_id: binding.endpoint.id.0,
        endpoint_generation: binding.endpoint.generation.0,
        transaction_id: request.transaction_id,
    };
    let mut bytes = [0u8; REGISTRY_HEADER_BYTES];
    let size = encode_registry_empty(header, &mut bytes).map_err(|_| failure(83))?;
    send_channel(publication, &bytes[..size], &[]).map_err(|_| failure(84))?;
    let deadline = monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .map_err(|_| failure(85))?;
    wait_readable(publication, deadline, 86)?;
    let mut response = [0u8; REGISTRY_HEADER_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts =
        receive_channel(publication, &mut response, &mut handles).map_err(|_| failure(87))?;
    if counts.bytes != response.len() || counts.handles != 0 {
        close_received(&handles, counts.handles);
        return Err(failure(88));
    }
    let parsed = parse_registry(&response, 0).map_err(|_| failure(89))?;
    if parsed.header
        != (RegistryHeader {
            message_type: RegistryMessageType::Published,
            ..header
        })
        || parsed.message != RegistryMessage::Published
    {
        return Err(failure(90));
    }
    resident.publication_committed().map_err(|_| failure(91))
}

#[cfg(feature = "wyr1c5-production")]
fn send_driver_retire(
    control: DwHandle,
    resident: &mut wyrmroot_devmgr::ResidentController,
) -> Result<(), u32> {
    let message = resident.retire_message().map_err(|_| failure(93))?;
    let mut bytes = [0u8; wyrmroot_device_proto::control::RETIRE_BYTES];
    encode_control(message, &mut bytes).map_err(|_| failure(94))?;
    send_channel(control, &bytes, &[]).map_err(|_| failure(95))
}

#[cfg(any(
    not(any(feature = "wyr1c4-production", feature = "wyr1c5-production")),
    feature = "wyr1c5-production"
))]
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

#[cfg(feature = "wyr1c6-selector29")]
fn send_c6_fact(bootstrap: DwHandle, fact: C6Fact) -> Result<(), u32> {
    let mut bytes = [0u8; C6_FACT_BYTES];
    encode_c6_fact(fact, &mut bytes).map_err(|_| failure(127))?;
    let deadline = monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .map_err(|_| failure(128))?;
    for _ in 0..4 {
        match send_channel(bootstrap, &bytes, &[]) {
            Ok(()) => return Ok(()),
            Err(NativeError::Status(status)) if status == DW_STATUS_WOULD_BLOCK => {
                let writable = DwWaitItemV1 {
                    handle: bootstrap,
                    signals: deepwyrm_syscall::DwSignals(
                        DW_SIGNAL_WRITABLE.0 | DW_SIGNAL_PEER_CLOSED.0,
                    ),
                };
                let observed = wait_many(core::slice::from_ref(&writable), deadline)
                    .map_err(|_| failure(128))?;
                if observed.index != 0
                    || observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0
                    || observed.observed.0 & DW_SIGNAL_WRITABLE.0 == 0
                {
                    return Err(failure(128));
                }
            }
            Err(_) => return Err(failure(128)),
        }
    }
    Err(failure(128))
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
