//! The devmgr role: bootstrap, the resident controller loop, driver launch,
//! connector brokering and driver supervision.
//!
//! This is the whole native role that `src/main.rs` used to hold. The binary
//! keeps only its freestanding entry, which hands [`run`] the bootstrap
//! Channel. It exists only with `native-devmgr`, which every devmgr binary
//! shape requires.

use crate::ControllerAction;
#[cfg(feature = "wyr1e-production")]
use crate::connector::{
    AttachCorrelation, DirectClientReleaseEvent, ProductionPublicationEvent, ProductionWaitSource,
    classify_direct_client_release, classify_production_publication, cleanup_deadline_live,
    production_cleanup_deadline, production_wait_plan,
};
#[cfg(feature = "wyr1e-production")]
use crate::connector::{ConnectorAction, ConnectorBroker, ConnectorSlot, PublishedDriver};
#[cfg(feature = "wyr1d-production")]
use crate::staging::DeviceStageCoordinator;
#[cfg(feature = "wyr1d-production")]
use deepwyrm_syscall::DW_HANDLE_INVALID;
#[cfg(feature = "wyr1c6-production")]
use deepwyrm_syscall::DW_STATUS_TIMED_OUT;
use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL,
    DW_OBJECT_TYPE_MEMORY_OBJECT, DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT, DW_RIGHT_READ,
    DW_RIGHT_TRANSFER, DW_RIGHT_WRITE, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DwHandle,
    DwHandleTransferV1, DwObjectType, DwReceivedHandleInfoV1, DwRights, DwWaitItemV1,
};
#[cfg(any(
    not(any(feature = "wyr1c4-production", feature = "wyr1c5-production")),
    feature = "wyr1c5-production"
))]
use deepwyrm_syscall::{DW_HANDLE_TRANSFER_MOVE, DW_RIGHT_WAIT};
#[cfg(feature = "wyr1c5-production")]
use deepwyrm_syscall::{
    DW_INTERRUPT_INFO_V1_SIZE, DW_INTERRUPT_INFO_V1_VERSION, DW_INTERRUPT_STATE_ARMED,
    DW_OBJECT_TYPE_INTERRUPT,
};
#[cfg(any(feature = "wyr1c4-production", feature = "wyr1c5-production"))]
use deepwyrm_syscall::{
    DW_OBJECT_TYPE_DEVICE_RESOURCE, DW_OBJECT_TYPE_TASK_GROUP, DW_RIGHT_MODIFY,
};
#[cfg(feature = "wyr1e-production")]
use wyrmroot_device_proto::ConnectorMessage;
#[cfg(any(feature = "wyr1c6-production", feature = "wyr1d-production"))]
use wyrmroot_device_proto::ControlMessage;
#[cfg(feature = "wyr1c6-production")]
use wyrmroot_device_proto::FailureCode;
#[cfg(feature = "wyr1e-production")]
use wyrmroot_device_proto::connector::{
    RECORD_BYTES as CONNECTOR_BYTES, encode as encode_connector, parse as parse_connector,
};
#[cfg(all(feature = "wyr1c5-production", not(feature = "wyr1d-production")))]
use wyrmroot_device_proto::control::{READY_BYTES, RESOURCE_BUNDLE_BYTES, parse as parse_control};
#[cfg(feature = "wyr1d-production")]
use wyrmroot_device_proto::control_v1_1::{
    ControlIdentityV1_1, DEVICE_QUIESCED_BYTES as D3_DEVICE_QUIESCED_BYTES,
    DEVICE_STAGE_BYTES as D3_DEVICE_STAGE_BYTES, INTERRUPT_STAGE_BYTES as D3_INTERRUPT_STAGE_BYTES,
    READY_BYTES as D3_READY_BYTES, encode as encode_control_v1_1, parse as parse_control_v1_1,
};
#[cfg(not(feature = "wyr1e-production"))]
use wyrmroot_device_proto::controller::INSTALL_BYTES;
#[cfg(not(feature = "wyr1e-production"))]
use wyrmroot_device_proto::controller::parse as parse_controller;
#[cfg(feature = "wyr1e8-production")]
use wyrmroot_device_proto::d5_controller::{
    D5ControllerMessage, RECORD_BYTES as D5_CONTROLLER_BYTES, parse as parse_d5_controller,
};
#[cfg(feature = "wyr1c6-production")]
use wyrmroot_device_proto::driver_launch::{
    REAPED_RESPONSE_BYTES, encode_driver_retired, parse_reaped,
};
use wyrmroot_device_proto::{
    ControllerMessage, StatusCode,
    controller::{STATUS_BYTES, encode as encode_controller},
};
#[cfg(feature = "wyr1c5-production")]
use wyrmroot_device_proto::{
    DirectControlRights,
    control::encode as encode_control,
    driver_launch::{
        LAUNCH_REQUEST_BYTES, LAUNCH_RESPONSE_BYTES, encode_request, parse_constructed,
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
use wyrmroot_loader::launch::CHILD_CHANNEL_TRANSFER_RIGHTS;
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
#[cfg(feature = "wyr1c5-production")]
use wyrmroot_registry_proto::{
    HEADER_BYTES as REGISTRY_HEADER_BYTES, Header as RegistryHeader, Message as RegistryMessage,
    MessageType as RegistryMessageType, encode_empty as encode_registry_empty,
    parse as parse_registry,
};
#[cfg(feature = "wyr1e-production")]
use wyrmroot_registry_proto::{Lookup, ProtocolVersion};
#[cfg(feature = "wyr1c6-production")]
use wyrmroot_runtime::NativeError;
#[cfg(any(
    not(any(feature = "wyr1c4-production", feature = "wyr1c5-production")),
    feature = "wyr1c5-production"
))]
use wyrmroot_runtime::WYR0_I_SUPERVISION_POLICY;
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, ChannelPlatform, ClockPlatform, DevicePlatform,
    EvidencePlatform, HandlePlatform, MappingPlan, MemoryPlatform, WaitPlatform,
    validate_bootstrap_channel,
};

/// The platform operations the devmgr role uses. [`wyrmroot_runtime::NativePlatform`]
/// is the production implementation; host tests use the runtime's recording
/// platform.
pub trait DevmgrPlatform:
    HandlePlatform
    + ChannelPlatform
    + WaitPlatform
    + ClockPlatform
    + MemoryPlatform
    + DevicePlatform
    + EvidencePlatform
{
}

impl<P> DevmgrPlatform for P where
    P: HandlePlatform
        + ChannelPlatform
        + WaitPlatform
        + ClockPlatform
        + MemoryPlatform
        + DevicePlatform
        + EvidencePlatform
{
}

const FAILURE_BASE: u32 = 0xC101_0000;

#[cfg(feature = "wyr1e-production")]
#[derive(Clone, Copy)]
struct ProductionClientWitness {
    handle: DwHandle,
    attach: AttachCorrelation,
}
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
const DEVICE_RESOURCE_TRANSFER_RIGHTS: DwRights =
    DwRights(DEVICE_RESOURCE_DRIVER_RIGHTS.0 | DW_RIGHT_TRANSFER.0);
#[cfg(feature = "wyr1c5-production")]
const INTERRUPT_CUSTODY_RIGHTS: DwRights =
    DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_TRANSFER.0 | DW_RIGHT_INSPECT.0);
#[cfg(feature = "wyr1c5-production")]
const INTERRUPT_DRIVER_RIGHTS: DwRights =
    DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0);
#[cfg(feature = "wyr1e-production")]
const STREAM_BROAD_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_TRANSFER.0,
);

/// Runs one devmgr generation over its bootstrap Channel on `platform`,
/// returning the resident status or the failure code the generation stopped
/// with.
pub fn run<P: DevmgrPlatform>(platform: &mut P, bootstrap: DwHandle) -> Result<u32, u32> {
    let bootstrap_info = platform
        .query_capability_info(bootstrap)
        .map_err(|_| failure(1))?;
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
    let counts = platform
        .receive_channel(bootstrap, &mut init, &mut handles)
        .map_err(|_| failure(3))?;
    if counts.bytes > init.len() || counts.handles != handles.len() {
        close_received(platform, &handles, counts.handles);
        return Err(failure(4));
    }
    #[cfg(not(any(feature = "wyr1c4-production", feature = "wyr1c5-production")))]
    let parsed_result = parse_device_coordinator_init(&init[..counts.bytes], &handles);
    #[cfg(any(feature = "wyr1c4-production", feature = "wyr1c5-production"))]
    let parsed_result = parse_device_coordinator_resource_init(&init[..counts.bytes], &handles);
    let parsed = match parsed_result {
        Ok(parsed) => parsed,
        Err(_) => {
            close_received(platform, &handles, counts.handles);
            return Err(failure(5));
        }
    };
    let invalid = validate_fresh(
        platform,
        handles[0].handle,
        DW_OBJECT_TYPE_ADDRESS_REGION,
        SELF_ROOT_RIGHTS,
    )
    .is_err()
        || validate_fresh(
            platform,
            handles[1].handle,
            DW_OBJECT_TYPE_CHANNEL,
            CHILD_CHANNEL_RIGHTS,
        )
        .is_err()
        || validate_fresh(
            platform,
            handles[2].handle,
            DW_OBJECT_TYPE_MEMORY_OBJECT,
            DEVICE_MANIFEST_RIGHTS,
        )
        .is_err();
    #[cfg(any(feature = "wyr1c4-production", feature = "wyr1c5-production"))]
    let invalid = invalid
        || validate_fresh(
            platform,
            handles[3].handle,
            DW_OBJECT_TYPE_TASK_GROUP,
            RESOURCE_DOMAIN_CLAIM_RIGHTS,
        )
        .is_err();
    if invalid {
        close_received(platform, &handles, counts.handles);
        return Err(failure(6));
    }

    let self_root = handles[0].handle;
    let publication = handles[1].handle;
    let manifest = handles[2].handle;
    #[cfg(any(feature = "wyr1c4-production", feature = "wyr1c5-production"))]
    let mut resource_domain = Some(handles[3].handle);
    let size = platform
        .query_memory_object_size(manifest)
        .map_err(|_| failure(7))?;
    let plan = MappingPlan::for_bootfs(size).map_err(|_| failure(8))?;
    let mapping = platform
        .map_bootfs_read_only(self_root, manifest, plan)
        .map_err(|_| failure(9))?;
    let prepared = mapping.with_logical_bytes(|bytes| {
        crate::prepare_operational(bytes, parsed.supervisor_generation)
    });
    platform.unmap_bootfs(mapping).map_err(|_| failure(10))?;
    let mut resident = match prepared
        .and_then(|status| crate::ResidentController::new(status, parsed.transaction_id))
    {
        Ok(resident) => resident,
        Err(_) => {
            close_received(platform, &handles, handles.len());
            return Err(failure(11));
        }
    };
    platform.close_handle(manifest).map_err(|_| failure(12))?;
    platform.close_handle(self_root).map_err(|_| failure(13))?;

    let mut ready = [0u8; HEADER_BYTES];
    #[cfg(not(any(feature = "wyr1c4-production", feature = "wyr1c5-production")))]
    let launch_profile = LaunchProfile::DeviceCoordinator;
    #[cfg(any(feature = "wyr1c4-production", feature = "wyr1c5-production"))]
    let launch_profile = LaunchProfile::DeviceCoordinatorResourceDomain;
    let ready_len = encode_ready_for_profile(launch_profile, parsed.transaction_id, &mut ready)
        .map_err(|_| failure(14))?;
    send_bootstrap_channel(platform, bootstrap, &ready[..ready_len], &[], 15)?;

    let mut publication = Some(publication);
    let mut driver_control = None;
    #[cfg(feature = "wyr1e-production")]
    let mut connector_broker: Option<ConnectorBroker> = None;
    #[cfg(feature = "wyr1e-production")]
    let mut production_witness: Option<ProductionClientWitness> = None;
    #[cfg(feature = "wyr1e-production")]
    let mut connector_cleanup_deadline: Option<u64> = None;
    #[cfg(feature = "wyr1e-production")]
    let mut waiting_registry_status_sent = false;
    #[cfg(feature = "wyr1e8-production")]
    let mut e8_retire_requested = false;
    #[cfg(all(not(feature = "wyr1e8-production"), feature = "wyr1c6-production"))]
    let e8_retire_requested = false;
    #[cfg(feature = "wyr1c4-production")]
    let mut _device_resource = None;
    #[cfg(feature = "wyr1c5-production")]
    let mut device_resource = None;
    loop {
        let mut waits = [DwWaitItemV1::default(); 4];
        waits[0] = wait_item(bootstrap);
        let mut wait_count = 1;
        #[cfg(feature = "wyr1e-production")]
        let plan = production_wait_plan(
            connector_broker
                .as_ref()
                .map_or(ConnectorSlot::Empty, ConnectorBroker::slot),
            production_witness.is_some(),
            driver_control.is_some(),
            publication.is_some(),
            connector_cleanup_deadline,
        )
        .map_err(|_| failure(308))?;
        #[cfg(feature = "wyr1e-production")]
        let mut witness_index = None;
        #[cfg(feature = "wyr1e-production")]
        let mut driver_index = None;
        #[cfg(feature = "wyr1e-production")]
        let mut publication_index = None;
        #[cfg(feature = "wyr1e-production")]
        for source in plan.sources()[..plan.len()].iter().flatten() {
            let index = wait_count;
            waits[index] = match source {
                ProductionWaitSource::Witness => {
                    witness_index = Some(index);
                    wait_item(production_witness.ok_or(failure(309))?.handle)
                }
                ProductionWaitSource::Driver => {
                    driver_index = Some(index);
                    wait_item(driver_control.ok_or(failure(310))?)
                }
                ProductionWaitSource::Publication => {
                    publication_index = Some(index);
                    wait_item(publication.ok_or(failure(311))?)
                }
            };
            wait_count += 1;
        }
        #[cfg(not(feature = "wyr1e-production"))]
        let driver_index = driver_control.map(|handle| {
            let index = wait_count;
            waits[index] = wait_item(handle);
            wait_count += 1;
            index
        });
        #[cfg(not(feature = "wyr1e-production"))]
        let publication_index = publication.map(|handle| {
            let index = wait_count;
            waits[index] = wait_item(handle);
            wait_count += 1;
            index
        });
        #[cfg(feature = "wyr1e-production")]
        let wait_deadline = plan
            .deadline()
            .map_or(DW_DEADLINE_INFINITE, deepwyrm_syscall::DwDeadline);
        #[cfg(not(feature = "wyr1e-production"))]
        let wait_deadline = DW_DEADLINE_INFINITE;
        let observed = platform
            .wait_many(&waits[..wait_count], wait_deadline)
            .map_err(|_error| {
                #[cfg(feature = "wyr1e-production")]
                if matches!(_error, NativeError::Status(status) if status == DW_STATUS_TIMED_OUT) {
                    return failure(276);
                }
                failure(16)
            })?;
        let index = usize::try_from(observed.index).map_err(|_| failure(17))?;
        if index >= wait_count
            || observed.observed.0 & (DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0) == 0
        {
            return Err(failure(18));
        }
        #[cfg(feature = "wyr1e-production")]
        if let Some(deadline) = connector_cleanup_deadline
            && !cleanup_deadline_live(
                platform.monotonic_active_now().map_err(|_| failure(277))?,
                deadline,
            )
        {
            return Err(failure(278));
        }
        #[cfg(feature = "wyr1e-production")]
        if Some(index) == witness_index {
            observe_production_client_release(
                platform,
                &mut production_witness,
                connector_broker.as_mut().ok_or(failure(279))?,
                observed.observed,
            )?;
            update_production_cleanup(
                platform,
                connector_broker.as_ref().ok_or(failure(280))?,
                &mut connector_cleanup_deadline,
            )?;
            maybe_send_waiting_for_registry(
                platform,
                bootstrap,
                &resident,
                publication,
                connector_broker.as_ref().ok_or(failure(281))?,
                &mut waiting_registry_status_sent,
            )?;
            continue;
        }
        if index == 0 {
            if observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
                close_optional(platform, publication);
                #[cfg(feature = "wyr1c5-production")]
                if let Some(control) = driver_control {
                    let _ = send_driver_retire(platform, control, &mut resident);
                }
                close_optional(platform, driver_control);
                #[cfg(feature = "wyr1c5-production")]
                close_optional(platform, device_resource.take());
                platform.close_handle(bootstrap).map_err(|_| failure(19))?;
                return Err(failure(20));
            }
            let input = match receive_controller(platform, bootstrap, &mut resident) {
                Ok(received) => received,
                Err(code) => {
                    close_optional(platform, publication);
                    close_optional(platform, driver_control);
                    #[cfg(feature = "wyr1c5-production")]
                    close_optional(platform, device_resource.take());
                    let _ = platform.close_handle(bootstrap);
                    return Err(code);
                }
            };
            #[cfg(feature = "wyr1e8-production")]
            let (replacement, action) = match input {
                #[cfg(feature = "wyr1e8-production")]
                ControllerInput::D5(D5ControllerMessage::RequestRetire(identity)) => {
                    let request = resident.active_driver_request().ok_or(failure(309))?;
                    let control = driver_control.ok_or(failure(310))?;
                    let broker = connector_broker.as_ref().ok_or(failure(311))?;
                    let current = published_driver(&resident, request)?;
                    if identity != current.d5_identity()
                        || broker.current() != Some(current)
                        || !matches!(
                            broker.slot(),
                            ConnectorSlot::Active { attach, .. } if attach.driver == current
                        )
                        || e8_retire_requested
                    {
                        return Err(failure(312));
                    }
                    send_driver_retire(platform, control, &mut resident)?;
                    e8_retire_requested = true;
                    continue;
                }
                #[cfg(feature = "wyr1e8-production")]
                ControllerInput::D5(_) => return Err(failure(313)),
                ControllerInput::Controller(received) => received,
            };
            #[cfg(not(feature = "wyr1e8-production"))]
            let (replacement, action) = input;
            if let Some(replacement) = replacement {
                if let Some(old) = publication.replace(replacement) {
                    let _ = platform.close_handle(replacement);
                    let _ = platform.close_handle(old);
                    #[cfg(feature = "wyr1c5-production")]
                    close_optional(platform, device_resource.take());
                    let _ = platform.close_handle(bootstrap);
                    return Err(failure(21));
                }
                #[cfg(feature = "wyr1e-production")]
                {
                    if action == ControllerAction::PublicationRebound {
                        if !waiting_registry_status_sent
                            || !matches!(
                                connector_broker.as_ref().map(ConnectorBroker::slot),
                                Some(ConnectorSlot::Empty)
                            )
                        {
                            return Err(failure(293));
                        }
                        waiting_registry_status_sent = false;
                    }
                }
            }
            #[cfg(any(feature = "wyr1c4-production", feature = "wyr1c5-production"))]
            if action == ControllerAction::InitialPublicationBound {
                let domain = resource_domain.take().ok_or(failure(46))?;
                if platform
                    .require_device_resource_interrupt_feature()
                    .is_err()
                {
                    let _ = platform.close_handle(domain);
                    return Err(failure(47));
                }
                let resource = match platform.claim_device_resource(
                    domain,
                    crate::COM2_RESOURCE_ID,
                    DEVICE_RESOURCE_CUSTODY_RIGHTS,
                ) {
                    Ok(resource) => resource,
                    Err(_) => {
                        let _ = platform.close_handle(domain);
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
                        platform,
                        resource,
                        DW_OBJECT_TYPE_DEVICE_RESOURCE,
                        DEVICE_RESOURCE_CUSTODY_RIGHTS,
                    )
                    .map_err(|_| failure(49))?;
                    let info = platform
                        .device_resource_info(resource)
                        .map_err(|_| failure(50))?;
                    resident
                        .admit_device_resource(info)
                        .map_err(|_| failure(51))?;
                    Ok::<_, u32>(())
                })();
                if let Err(code) = claim {
                    #[cfg(feature = "wyr1c4-production")]
                    close_optional(platform, _device_resource.take());
                    #[cfg(feature = "wyr1c5-production")]
                    close_optional(platform, device_resource.take());
                    let _ = platform.close_handle(domain);
                    close_optional(platform, publication);
                    close_optional(platform, driver_control);
                    let _ = platform.close_handle(bootstrap);
                    return Err(code);
                }
                if platform.close_handle(domain).is_err() {
                    #[cfg(feature = "wyr1c4-production")]
                    close_optional(platform, _device_resource.take());
                    #[cfg(feature = "wyr1c5-production")]
                    close_optional(platform, device_resource.take());
                    close_optional(platform, publication);
                    close_optional(platform, driver_control);
                    let _ = platform.close_handle(bootstrap);
                    return Err(failure(52));
                }
            }
            if let Err(code) = send_publication_acknowledgement(platform, bootstrap, &resident) {
                close_optional(platform, publication);
                close_optional(platform, driver_control);
                #[cfg(feature = "wyr1c4-production")]
                close_optional(platform, _device_resource.take());
                #[cfg(feature = "wyr1c5-production")]
                close_optional(platform, device_resource.take());
                let _ = platform.close_handle(bootstrap);
                return Err(code);
            }
            #[cfg(not(any(feature = "wyr1c4-production", feature = "wyr1c5-production")))]
            if action == ControllerAction::InitialPublicationBound {
                if driver_control.is_some() {
                    return Err(failure(38));
                }
                driver_control = Some(launch_driver(platform, bootstrap, &mut resident)?);
            }
            #[cfg(feature = "wyr1c5-production")]
            if action == ControllerAction::InitialPublicationBound
                && (true || resident.status().supervisor_generation.0 == 1)
            {
                let parent = device_resource.ok_or(failure(53))?;
                let launched = launch_driver_with_bundle(
                    platform,
                    bootstrap,
                    publication.ok_or(failure(54))?,
                    parent,
                    &mut resident,
                );
                driver_control = match launched {
                    Ok(control) => Some(control),
                    Err(code) => {
                        close_optional(platform, device_resource.take());
                        close_optional(platform, publication.take());
                        let _ = platform.close_handle(bootstrap);
                        return Err(code);
                    }
                };
                #[cfg(feature = "wyr1e-production")]
                activate_connector_broker(&mut resident, &mut connector_broker)?;
            } else if resident.driver_ready() {
                let republished = publish_driver(
                    platform,
                    publication.ok_or(failure(55))?,
                    resident.active_driver_request().ok_or(failure(56))?,
                    &mut resident,
                );
                if let Err(code) = republished {
                    if let Some(control) = driver_control.take() {
                        let _ = send_driver_retire(platform, control, &mut resident);
                        let _ = platform.close_handle(control);
                    }
                    close_optional(platform, device_resource.take());
                    close_optional(platform, publication.take());
                    let _ = platform.close_handle(bootstrap);
                    return Err(code);
                }
                #[cfg(feature = "wyr1e-production")]
                activate_connector_broker(&mut resident, &mut connector_broker)?;
            }
            continue;
        }

        if Some(index) == driver_index {
            let control = driver_control.take().ok_or(failure(39))?;
            #[cfg(feature = "wyr1e-production")]
            if observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 && connector_broker.is_some() {
                service_production_driver_control(
                    platform,
                    control,
                    connector_broker.as_mut().ok_or(failure(271))?,
                )?;
                update_production_cleanup(
                    platform,
                    connector_broker.as_ref().ok_or(failure(288))?,
                    &mut connector_cleanup_deadline,
                )?;
                maybe_send_waiting_for_registry(
                    platform,
                    bootstrap,
                    &resident,
                    publication,
                    connector_broker.as_ref().ok_or(failure(289))?,
                    &mut waiting_registry_status_sent,
                )?;
                driver_control = Some(control);
                continue;
            }
            // The C3 acceptance actor may exit after its direct READY.  Peer
            // closure is the only reached notification path; no resource was
            // ever delegated, so reaping cannot lose future custody.
            #[cfg(feature = "wyr1c6-production")]
            if observed.observed.0 & (DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0) != 0 {
                let request = resident.active_driver_request().ok_or(failure(40))?;
                #[cfg(feature = "wyr1e-production")]
                let production_retiring_driver = published_driver(&resident, request)?;
                observe_driver_failure(
                    platform,
                    control,
                    request,
                    &mut resident,
                    observed.observed.0 & DW_SIGNAL_READABLE.0 != 0,
                    observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0,
                    e8_retire_requested,
                )?;
                #[cfg(feature = "wyr1e-production")]
                {
                    let broker = connector_broker.as_mut().ok_or(failure(294))?;
                    if broker.current() != Some(production_retiring_driver)
                        || broker.retire_current().is_some()
                    {
                        return Err(failure(295));
                    }
                    update_production_cleanup(platform, broker, &mut connector_cleanup_deadline)?;
                }
                platform.close_handle(control).map_err(|_| failure(41))?;
                let old_publication = publication.take().ok_or(failure(42))?;
                retire_driver_publication(platform, old_publication, request, &resident)?;
                platform
                    .close_handle(old_publication)
                    .map_err(|_| failure(149))?;
                resident.publication_retired().map_err(|_| failure(43))?;
                await_driver_reaped(platform, bootstrap, request)?;
                resident.reap_driver().map_err(|_| failure(44))?;
                #[cfg(feature = "wyr1e-production")]
                {
                    let broker = connector_broker.as_mut().ok_or(failure(296))?;
                    if broker
                        .driver_attempt_reaped(production_retiring_driver)
                        .map_err(|_| failure(297))?
                        .is_some()
                    {
                        return Err(failure(298));
                    }
                    update_production_cleanup(platform, broker, &mut connector_cleanup_deadline)?;
                    await_production_witness_release(
                        platform,
                        &mut production_witness,
                        broker,
                        &mut connector_cleanup_deadline,
                    )?;
                    if !matches!(broker.slot(), ConnectorSlot::Empty) {
                        return Err(failure(299));
                    }
                }
                send_driver_retired(platform, bootstrap, request)?;
                #[cfg(feature = "wyr1e8-production")]
                {
                    // The exact retired attempt is now terminal and fully
                    // reaped.  A later replacement failure is ordinary unless
                    // init issues another exact RequestRetire.
                    e8_retire_requested = false;
                }
                let rebind_deadline = platform
                    .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
                    .map_err(|_| failure(45))?;
                wait_readable(platform, bootstrap, rebind_deadline, 46)?;
                let received = receive_controller(platform, bootstrap, &mut resident)?;
                #[cfg(feature = "wyr1e8-production")]
                let (replacement, action) = match received {
                    ControllerInput::Controller(received) => received,
                    #[cfg(feature = "wyr1e8-production")]
                    ControllerInput::D5(_) => return Err(failure(314)),
                };
                #[cfg(not(feature = "wyr1e8-production"))]
                let (replacement, action) = received;
                if action != ControllerAction::PublicationRebound {
                    return Err(failure(47));
                }
                let replacement = replacement.ok_or(failure(48))?;
                if publication.replace(replacement).is_some() {
                    return Err(failure(49));
                }
                // This cleanup path consumes the rebind synchronously instead
                // of returning to the outer controller loop.  Acknowledge the
                // committed binding here so init can finish the same WRCS
                // transaction before the bounded driver backoff begins.
                let acknowledged = send_publication_acknowledgement(platform, bootstrap, &resident);
                if let Err(code) = acknowledged {
                    close_optional(platform, device_resource.take());
                    close_optional(platform, publication.take());
                    let _ = platform.close_handle(bootstrap);
                    return Err(code);
                }
                let now = platform.monotonic_active_now().map_err(|_| failure(50))?;
                resident
                    .complete_driver_failure_cleanup(now)
                    .map_err(|_| failure(51))?;
                if resident.status().state
                    == wyrmroot_device_proto::CoordinatorState::PermanentFailure
                {
                    close_optional(platform, device_resource.take());
                    close_optional(platform, publication.take());
                    platform.close_handle(bootstrap).map_err(|_| failure(52))?;
                    return Err(failure(96));
                }
                let retry_until = resident.retry_until_ns().ok_or(failure(53))?;
                match platform.wait_many(
                    core::slice::from_ref(&wait_item(bootstrap)),
                    deepwyrm_syscall::DwDeadline(retry_until),
                ) {
                    Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {}
                    Ok(_) | Err(_) => return Err(failure(54)),
                }
                let now = platform.monotonic_active_now().map_err(|_| failure(55))?;
                resident.driver_retry_ready(now).map_err(|_| failure(56))?;
                let parent = device_resource.ok_or(failure(57))?;
                let launched = launch_driver_with_bundle(
                    platform,
                    bootstrap,
                    publication.ok_or(failure(58))?,
                    parent,
                    &mut resident,
                )?;
                driver_control = Some(launched);
                #[cfg(feature = "wyr1e-production")]
                activate_connector_broker(&mut resident, &mut connector_broker)?;
                continue;
            }
            #[cfg(not(feature = "wyr1c6-production"))]
            if observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 {
                let _ = platform.close_handle(control);
                #[cfg(feature = "wyr1c5-production")]
                {
                    close_optional(platform, device_resource.take());
                    close_optional(platform, publication.take());
                    let _ = platform.close_handle(bootstrap);
                }
                return Err(failure(40));
            }
            platform.close_handle(control).map_err(|_| failure(41))?;
            resident.reap_driver().map_err(|_| failure(42))?;
            #[cfg(feature = "wyr1c5-production")]
            {
                close_optional(platform, device_resource.take());
                close_optional(platform, publication.take());
                let _ = platform.close_handle(bootstrap);
                return Err(failure(96));
            }
            #[cfg(not(feature = "wyr1c5-production"))]
            continue;
        }

        if Some(index) != publication_index {
            return Err(failure(43));
        }
        #[cfg(feature = "wyr1e-production")]
        let service_offer = match classify_production_publication(
            observed.observed.0 & DW_SIGNAL_READABLE.0 != 0,
            observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0,
        ) {
            ProductionPublicationEvent::Offer => true,
            ProductionPublicationEvent::Retire => false,
            ProductionPublicationEvent::Malformed => return Err(failure(312)),
        };
        #[cfg(not(feature = "wyr1e-production"))]
        let service_offer = observed.observed.0 & DW_SIGNAL_READABLE.0 != 0;
        if service_offer {
            #[cfg(feature = "wyr1e-production")]
            {
                let broker = connector_broker.as_mut().ok_or(failure(170))?;
                let control = driver_control.ok_or(failure(171))?;
                service_connector_offer(
                    platform,
                    publication.ok_or(failure(172))?,
                    control,
                    &resident,
                    broker,
                    #[cfg(feature = "wyr1e-production")]
                    &mut production_witness,
                )?;
                continue;
            }
            #[cfg(not(feature = "wyr1e-production"))]
            {
                close_optional(platform, publication);
                #[cfg(feature = "wyr1c5-production")]
                if let Some(control) = driver_control {
                    let _ = send_driver_retire(platform, control, &mut resident);
                }
                close_optional(platform, driver_control);
                #[cfg(feature = "wyr1c5-production")]
                close_optional(platform, device_resource.take());
                platform.close_handle(bootstrap).map_err(|_| failure(22))?;
                return Err(failure(23));
            }
        }
        // Registry replacement closes only the old publication binding.  The
        // coordinator generation remains resident; a later WRCS rebind moves
        // one exact child Channel over the still-open bootstrap relationship.
        let old = publication.take().ok_or(failure(24))?;
        #[cfg(feature = "wyr1e-production")]
        {
            let broker = connector_broker.as_mut().ok_or(failure(290))?;
            if broker.retire_current().is_some() {
                return Err(failure(291));
            }
            update_production_cleanup(platform, broker, &mut connector_cleanup_deadline)?;
            waiting_registry_status_sent = false;
        }
        platform.close_handle(old).map_err(|_| failure(25))?;
        resident
            .publication_peer_closed()
            .map_err(|_| failure(26))?;
        #[cfg(feature = "wyr1e-production")]
        {
            maybe_send_waiting_for_registry(
                platform,
                bootstrap,
                &resident,
                publication,
                connector_broker.as_ref().ok_or(failure(292))?,
                &mut waiting_registry_status_sent,
            )?;
            continue;
        }
        #[cfg(not(feature = "wyr1e-production"))]
        send_resident_status(
            platform,
            bootstrap,
            &resident,
            StatusCode::OperationalWaitingForRegistry,
        )?;
    }
}

#[cfg(feature = "wyr1e8-production")]
enum ControllerInput {
    Controller((Option<DwHandle>, ControllerAction)),
    #[cfg(feature = "wyr1e8-production")]
    D5(D5ControllerMessage),
}

#[cfg(not(feature = "wyr1e8-production"))]
type ControllerInput = (Option<DwHandle>, ControllerAction);

fn receive_controller<P: DevmgrPlatform>(
    platform: &mut P,
    bootstrap: DwHandle,
    resident: &mut crate::ResidentController,
) -> Result<ControllerInput, u32> {
    #[cfg(feature = "wyr1e8-production")]
    let mut bytes = [0u8; D5_CONTROLLER_BYTES];
    #[cfg(all(not(feature = "wyr1e8-production"), feature = "wyr1e-production"))]
    let mut bytes = [0u8; wyrmroot_device_proto::controller_v1_1::RECORD_BYTES];
    #[cfg(not(feature = "wyr1e-production"))]
    let mut bytes = [0u8; INSTALL_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(bootstrap, &mut bytes, &mut handles)
        .map_err(|_| failure(27))?;
    if counts.bytes > bytes.len() || counts.handles > handles.len() {
        close_received(platform, &handles, counts.handles);
        return Err(failure(28));
    }
    #[cfg(feature = "wyr1e8-production")]
    if counts.bytes == D5_CONTROLLER_BYTES
        && bytes[..4] == wyrmroot_device_proto::d5_controller::MAGIC
    {
        if counts.handles != 0 {
            close_received(platform, &handles, counts.handles);
            return Err(failure(233));
        }
        return parse_d5_controller(&bytes[..counts.bytes])
            .map(ControllerInput::D5)
            .map_err(|_| failure(233));
    }
    #[cfg(feature = "wyr1e-production")]
    let publication = match wyrmroot_device_proto::controller_v1_1::parse(&bytes[..counts.bytes]) {
        Ok(publication) => publication,
        Err(_) => {
            close_received(platform, &handles, counts.handles);
            return Err(failure(29));
        }
    };
    #[cfg(feature = "wyr1e-production")]
    let message = publication.controller;
    #[cfg(not(feature = "wyr1e-production"))]
    let message = match parse_controller(&bytes[..counts.bytes]) {
        Ok(message) => message,
        Err(_) => {
            close_received(platform, &handles, counts.handles);
            return Err(failure(29));
        }
    };
    if counts.handles as u32 != message.handle_count() {
        close_received(platform, &handles, counts.handles);
        return Err(failure(30));
    }
    let replacement = match message {
        ControllerMessage::InstallPublication { .. } => {
            if counts.handles != 0 {
                close_received(platform, &handles, counts.handles);
                return Err(failure(31));
            }
            None
        }
        ControllerMessage::RebindPublication { .. } => {
            if counts.handles != 1
                || validate_fresh(
                    platform,
                    handles[0].handle,
                    DW_OBJECT_TYPE_CHANNEL,
                    CHILD_CHANNEL_RIGHTS,
                )
                .is_err()
            {
                close_received(platform, &handles, counts.handles);
                return Err(failure(32));
            }
            Some(handles[0].handle)
        }
        ControllerMessage::Status { .. } => {
            close_received(platform, &handles, counts.handles);
            return Err(failure(33));
        }
    };
    #[cfg(feature = "wyr1e-production")]
    let accepted = resident.accept_publication(publication, counts.handles as u32);
    #[cfg(not(feature = "wyr1e-production"))]
    let accepted = resident.accept(message, counts.handles as u32);
    let action = match accepted {
        Ok(action) => action,
        Err(_) => {
            if counts.handles == 1
                && let Some(replacement) = replacement
            {
                let _ = platform.close_handle(replacement);
            }
            return Err(failure(34));
        }
    };
    #[cfg(feature = "wyr1e8-production")]
    return Ok(ControllerInput::Controller((replacement, action)));
    #[cfg(not(feature = "wyr1e8-production"))]
    Ok((replacement, action))
}

#[cfg(feature = "wyr1e-production")]
fn published_driver(
    resident: &crate::ResidentController,
    request: wyrmroot_device_proto::DriverLaunchRequest,
) -> Result<PublishedDriver, u32> {
    if resident.active_driver_request() != Some(request) || !resident.driver_ready() {
        return Err(failure(242));
    }
    Ok(PublishedDriver {
        publication_generation: resident
            .publication_service_generation()
            .ok_or(failure(243))?,
        control: ControlIdentityV1_1 {
            role_id: request.role_id,
            bundle_generation: resident.bundle_generation().ok_or(failure(244))?,
            attempt_generation: request.attempt_generation,
            endpoint: request.endpoint,
            transaction_id: request.transaction_id,
        },
    })
}

#[cfg(feature = "wyr1e-production")]
pub(crate) fn activate_connector_broker(
    resident: &mut crate::ResidentController,
    broker: &mut Option<ConnectorBroker>,
) -> Result<PublishedDriver, u32> {
    let request = resident.active_driver_request().ok_or(failure(245))?;
    let current = published_driver(resident, request)?;
    if let Some(broker) = broker.as_mut() {
        if !matches!(broker.slot(), ConnectorSlot::Empty) || broker.current().is_some() {
            return Err(failure(246));
        }
        broker
            .replace_published_driver(current)
            .map_err(|_| failure(247))?;
    } else {
        let (attach_transaction, stream_generation) = resident
            .reserve_d3_connector_correlations(request)
            .map_err(|_| failure(248))?;
        *broker = Some(
            ConnectorBroker::new(Some(current), attach_transaction, stream_generation)
                .map_err(|_| failure(249))?,
        );
    }
    Ok(current)
}

#[cfg(feature = "wyr1e-production")]
fn service_connector_offer<P: DevmgrPlatform>(
    platform: &mut P,
    publication: DwHandle,
    driver_control: DwHandle,
    resident: &crate::ResidentController,
    broker: &mut ConnectorBroker,
    #[cfg(feature = "wyr1e-production")] witness: &mut Option<ProductionClientWitness>,
) -> Result<(), u32> {
    let mut offer_bytes = [0u8; 256];
    let mut offer_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(publication, &mut offer_bytes, &mut offer_handles)
        .map_err(|_| failure(174))?;
    if counts.bytes > offer_bytes.len() || counts.handles != 1 {
        close_received(platform, &offer_handles, counts.handles);
        return Err(failure(175));
    }
    let offered = offer_handles[0];
    if offered.handle.0 == 0
        || offered.object_type != DW_OBJECT_TYPE_CHANNEL
        || offered.rights != CHILD_CHANNEL_RIGHTS
        || offered.reserved0 != 0
        || offered.reserved != [0; 2]
        || validate_fresh(
            platform,
            offered.handle,
            DW_OBJECT_TYPE_CHANNEL,
            CHILD_CHANNEL_RIGHTS,
        )
        .is_err()
    {
        close_received(platform, &offer_handles, 1);
        return Err(failure(176));
    }
    let offer = match parse_registry(&offer_bytes[..counts.bytes], counts.handles) {
        Ok(offer) => offer,
        Err(_) => {
            close_received(platform, &offer_handles, 1);
            return Err(failure(177));
        }
    };
    let binding = resident.active_binding().ok_or(failure(178))?;
    let policy = ConnectorBroker::publication_policy();
    let RegistryMessage::ConnectOffer(lookup) = offer.message else {
        close_received(platform, &offer_handles, 1);
        return Err(failure(179));
    };
    if offer.header.message_type != RegistryMessageType::ConnectOffer
        || offer.header.registry_generation != binding.generation.0
        || offer.header.endpoint_id != binding.endpoint.id.0
        || offer.header.endpoint_generation != binding.endpoint.generation.0
        || offer.header.transaction_id == 0
        || lookup
            != (Lookup {
                protocol_id: policy.protocol_id,
                version: ProtocolVersion {
                    major: policy.protocol_major,
                    minor: policy.protocol_minor,
                },
                service_name: policy.service_name,
            })
    {
        close_received(platform, &offer_handles, 1);
        return Err(failure(180));
    }
    let direct = offer_handles[0].handle;
    let deadline = platform
        .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .map_err(|_| failure(181))?;
    wait_readable(platform, direct, deadline, 182)?;
    let mut request_bytes = [0u8; CONNECTOR_BYTES];
    let mut request_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(direct, &mut request_bytes, &mut request_handles)
        .map_err(|_| failure(183))?;
    if counts.bytes != request_bytes.len() || counts.handles != 0 {
        close_received(platform, &request_handles, counts.handles);
        let _ = platform.close_handle(direct);
        return Err(failure(184));
    }
    let request = match parse_connector(&request_bytes) {
        Ok(request @ ConnectorMessage::ConnectStream { .. }) => request,
        _ => {
            let _ = platform.close_handle(direct);
            return Err(failure(185));
        }
    };
    let action = match broker.begin_connect(request) {
        Ok(action) => action,
        Err(error) => {
            let reply = error.reply(request).ok_or(failure(186))?;
            let mut bytes = [0u8; CONNECTOR_BYTES];
            let encoded = encode_connector(reply, &mut bytes);
            if encoded.is_ok() {
                // A rejected request owns no raw pair. A disconnected client
                // cannot turn a normal negative response into driver loss.
                let _ = platform.send_channel(direct, &bytes, &[]);
            }
            platform.close_handle(direct).map_err(|_| failure(186))?;
            encoded.map_err(|_| failure(186))?;
            return Ok(());
        }
    };
    let ConnectorAction::AllocatePair {
        attach,
        driver_message,
    } = action
    else {
        let _ = platform.close_handle(direct);
        return Err(failure(187));
    };
    #[cfg(feature = "wyr1e-production")]
    if witness.is_some() {
        let _ = broker.attach_send_failed(attach);
        let _ = platform.close_handle(direct);
        return Err(failure(276));
    }
    let (client_endpoint, driver_endpoint) = platform
        .create_channel(STREAM_BROAD_RIGHTS)
        .map_err(|_| failure(188))?;
    let mut driver_bytes = [0u8; D3_DEVICE_STAGE_BYTES];
    let size = driver_message.wire_size();
    encode_control_v1_1(driver_message, &mut driver_bytes[..size]).map_err(|_| failure(189))?;
    let transfer = DwHandleTransferV1 {
        handle: driver_endpoint,
        requested_rights: CHILD_CHANNEL_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if platform
        .send_channel(driver_control, &driver_bytes[..size], &[transfer])
        .is_err()
    {
        let _ = broker.attach_send_failed(attach);
        let _ = platform.close_handle(driver_endpoint);
        let _ = platform.close_handle(client_endpoint);
        let _ = platform.close_handle(direct);
        return Err(failure(190));
    }
    broker
        .driver_endpoint_moved(attach)
        .map_err(|_| failure(191))?;
    wait_readable(platform, driver_control, deadline, 192)?;
    let mut ready_bytes = [0u8; D3_DEVICE_STAGE_BYTES];
    let mut ready_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(driver_control, &mut ready_bytes, &mut ready_handles)
        .map_err(|_| failure(193))?;
    if counts.bytes > ready_bytes.len() || counts.handles != 0 {
        close_received(platform, &ready_handles, counts.handles);
        let _ = platform.close_handle(client_endpoint);
        let _ = platform.close_handle(direct);
        return Err(failure(194));
    }
    let ready = parse_control_v1_1(&ready_bytes[..counts.bytes]).map_err(|_| failure(195))?;
    broker
        .accept_stream_ready(ready)
        .map_err(|_| failure(196))?;
    let response = broker.connected_response().map_err(|_| failure(197))?;
    let mut response_bytes = [0u8; CONNECTOR_BYTES];
    encode_connector(response, &mut response_bytes).map_err(|_| failure(198))?;
    let transfer = DwHandleTransferV1 {
        handle: client_endpoint,
        requested_rights: CHILD_CHANNEL_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if platform
        .send_channel(direct, &response_bytes, &[transfer])
        .is_err()
    {
        let _ = broker.connected_send_failed();
        let _ = platform.close_handle(client_endpoint);
        let _ = platform.close_handle(direct);
        return Err(failure(199));
    }
    broker.client_endpoint_moved().map_err(|_| failure(200))?;
    #[cfg(feature = "wyr1e-production")]
    {
        *witness = Some(ProductionClientWitness {
            handle: direct,
            attach,
        });
        Ok(())
    }
    #[cfg(not(feature = "wyr1e-production"))]
    platform.close_handle(direct).map_err(|_| failure(201))
}

#[cfg(feature = "wyr1e-production")]
fn observe_production_client_release<P: DevmgrPlatform>(
    platform: &mut P,
    witness: &mut Option<ProductionClientWitness>,
    broker: &mut ConnectorBroker,
    signals: deepwyrm_syscall::DwSignals,
) -> Result<(), u32> {
    let observed = (*witness).ok_or(failure(279))?;
    let readable = signals.0 & DW_SIGNAL_READABLE.0 != 0;
    let peer_closed = signals.0 & DW_SIGNAL_PEER_CLOSED.0 != 0;
    if classify_direct_client_release(readable, peer_closed) == DirectClientReleaseEvent::Malformed
    {
        if !readable {
            return Err(failure(281));
        }
        let mut bytes = [0u8; 1];
        let mut handles = [DwReceivedHandleInfoV1::default(); 1];
        if let Ok(counts) = platform.receive_channel(observed.handle, &mut bytes, &mut handles) {
            close_received(platform, &handles, counts.handles);
        }
        return Err(failure(280));
    }
    match broker.slot() {
        ConnectorSlot::Active { attach, .. } if attach == observed.attach => broker
            .active_client_released(observed.attach)
            .map_err(|_| failure(282))?,
        ConnectorSlot::AwaitingClientRelease { attach, .. }
        | ConnectorSlot::RetiringActive { attach, .. }
            if attach == observed.attach =>
        {
            broker
                .client_release_observed(observed.attach)
                .map_err(|_| failure(283))?
        }
        _ => return Err(failure(284)),
    }
    platform
        .close_handle(observed.handle)
        .map_err(|_| failure(285))?;
    *witness = None;
    Ok(())
}

#[cfg(feature = "wyr1e-production")]
fn update_production_cleanup<P: DevmgrPlatform>(
    platform: &mut P,
    broker: &ConnectorBroker,
    deadline: &mut Option<u64>,
) -> Result<(), u32> {
    if matches!(broker.slot(), ConnectorSlot::Empty) {
        *deadline = None;
        return Ok(());
    }
    if matches!(
        broker.slot(),
        ConnectorSlot::AwaitingDriverRelease { .. }
            | ConnectorSlot::AwaitingClientRelease { .. }
            | ConnectorSlot::RetiringActive { .. }
    ) && deadline.is_none()
    {
        *deadline = Some(
            production_cleanup_deadline(platform.monotonic_active_now().map_err(|_| failure(286))?)
                .map_err(|_| failure(287))?,
        );
    }
    Ok(())
}

#[cfg(feature = "wyr1e-production")]
fn maybe_send_waiting_for_registry<P: DevmgrPlatform>(
    platform: &mut P,
    bootstrap: DwHandle,
    resident: &crate::ResidentController,
    publication: Option<DwHandle>,
    broker: &ConnectorBroker,
    sent: &mut bool,
) -> Result<(), u32> {
    if publication.is_none() && matches!(broker.slot(), ConnectorSlot::Empty) && !*sent {
        send_resident_status(
            platform,
            bootstrap,
            resident,
            StatusCode::OperationalWaitingForRegistry,
        )?;
        *sent = true;
    }
    Ok(())
}

#[cfg(feature = "wyr1e-production")]
fn await_production_witness_release<P: DevmgrPlatform>(
    platform: &mut P,
    witness: &mut Option<ProductionClientWitness>,
    broker: &mut ConnectorBroker,
    deadline: &mut Option<u64>,
) -> Result<(), u32> {
    let Some(observed) = *witness else {
        return if matches!(broker.slot(), ConnectorSlot::Empty) {
            *deadline = None;
            Ok(())
        } else {
            Err(failure(300))
        };
    };
    update_production_cleanup(platform, broker, deadline)?;
    let absolute = (*deadline).ok_or(failure(301))?;
    if !cleanup_deadline_live(
        platform.monotonic_active_now().map_err(|_| failure(302))?,
        absolute,
    ) {
        return Err(failure(303));
    }
    let result = platform
        .wait_many(
            core::slice::from_ref(&wait_item(observed.handle)),
            deepwyrm_syscall::DwDeadline(absolute),
        )
        .map_err(|_| failure(304))?;
    if result.index != 0
        || !cleanup_deadline_live(
            platform.monotonic_active_now().map_err(|_| failure(305))?,
            absolute,
        )
    {
        return Err(failure(306));
    }
    observe_production_client_release(platform, witness, broker, result.observed)?;
    update_production_cleanup(platform, broker, deadline)
}

#[cfg(feature = "wyr1e-production")]
fn service_production_driver_control<P: DevmgrPlatform>(
    platform: &mut P,
    driver_control: DwHandle,
    broker: &mut ConnectorBroker,
) -> Result<(), u32> {
    let mut bytes = [0u8; D3_DEVICE_STAGE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(driver_control, &mut bytes, &mut handles)
        .map_err(|_| failure(272))?;
    if counts.bytes > bytes.len() || counts.handles != 0 {
        close_received(platform, &handles, counts.handles);
        return Err(failure(273));
    }
    let message = parse_control_v1_1(&bytes[..counts.bytes]).map_err(|_| failure(274))?;
    broker.driver_detached(message).map_err(|_| failure(275))
}

#[cfg(feature = "wyr1c6-production")]
fn observe_driver_failure<P: DevmgrPlatform>(
    platform: &mut P,
    control: DwHandle,
    request: wyrmroot_device_proto::DriverLaunchRequest,
    resident: &mut crate::ResidentController,
    readable: bool,
    peer_closed: bool,
    intentional_retirement: bool,
) -> Result<(), u32> {
    if !readable {
        return record_driver_terminal(resident, request, intentional_retirement);
    }
    let mut bytes = [0u8; wyrmroot_device_proto::control::FAILURE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(control, &mut bytes, &mut handles)
        .map_err(|_| failure(100))?;
    if counts.bytes != bytes.len() || counts.handles != 0 {
        close_received(platform, &handles, counts.handles);
        if peer_closed && counts.bytes == 0 && counts.handles == 0 {
            return record_driver_terminal(resident, request, intentional_retirement);
        }
        return Err(failure(101));
    }
    let message = wyrmroot_device_proto::control::parse(&bytes).map_err(|_| failure(102))?;
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
    record_driver_terminal(resident, request, intentional_retirement)
}

#[cfg(feature = "wyr1c6-production")]
fn record_driver_terminal(
    resident: &mut crate::ResidentController,
    request: wyrmroot_device_proto::DriverLaunchRequest,
    intentional_retirement: bool,
) -> Result<(), u32> {
    if intentional_retirement {
        return resident
            .accept_intentional_driver_terminal(request)
            .map_err(|_| failure(105));
    }
    resident
        .driver_failed(request.endpoint)
        .map_err(|_| failure(105))
}

#[cfg(feature = "wyr1c6-production")]
pub(crate) fn retire_driver_publication<P: DevmgrPlatform>(
    platform: &mut P,
    publication: DwHandle,
    request: wyrmroot_device_proto::DriverLaunchRequest,
    resident: &crate::ResidentController,
) -> Result<(), u32> {
    let binding = resident.active_binding().ok_or(failure(106))?;
    let retire_transaction = resident
        .publication_retire_transaction(request)
        .map_err(|_| failure(152))?;
    let header = RegistryHeader {
        message_type: RegistryMessageType::Retire,
        registry_generation: binding.generation.0,
        endpoint_id: binding.endpoint.id.0,
        endpoint_generation: binding.endpoint.generation.0,
        transaction_id: retire_transaction,
    };
    let mut bytes = [0u8; REGISTRY_HEADER_BYTES];
    let size = encode_registry_empty(header, &mut bytes).map_err(|_| failure(107))?;
    platform
        .send_channel(publication, &bytes[..size], &[])
        .map_err(|_| failure(108))?;
    let deadline = platform
        .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .map_err(|_| failure(109))?;
    wait_readable(platform, publication, deadline, 110)?;
    let mut response = [0u8; REGISTRY_HEADER_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(publication, &mut response, &mut handles)
        .map_err(|_| failure(111))?;
    if counts.bytes != response.len() || counts.handles != 0 {
        close_received(platform, &handles, counts.handles);
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

#[cfg(feature = "wyr1c6-production")]
fn await_driver_reaped<P: DevmgrPlatform>(
    platform: &mut P,
    bootstrap: DwHandle,
    request: wyrmroot_device_proto::DriverLaunchRequest,
) -> Result<(), u32> {
    let deadline = platform
        .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns)
        .map_err(|_| failure(115))?;
    wait_readable(platform, bootstrap, deadline, 116)?;
    let mut bytes = [0u8; REAPED_RESPONSE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(bootstrap, &mut bytes, &mut handles)
        .map_err(|_| failure(117))?;
    if counts.bytes != bytes.len() || counts.handles != 0 {
        close_received(platform, &handles, counts.handles);
        return Err(failure(118));
    }
    parse_reaped(&bytes, request).map_err(|_| failure(119))
}

#[cfg(feature = "wyr1c6-production")]
fn send_driver_retired<P: DevmgrPlatform>(
    platform: &mut P,
    bootstrap: DwHandle,
    request: wyrmroot_device_proto::DriverLaunchRequest,
) -> Result<(), u32> {
    let mut bytes = [0u8; wyrmroot_device_proto::driver_launch::DRIVER_RETIRED_BYTES];
    encode_driver_retired(request, &mut bytes).map_err(|_| failure(120))?;
    send_bootstrap_channel(platform, bootstrap, &bytes, &[], 121)
}

#[cfg(not(any(feature = "wyr1c4-production", feature = "wyr1c5-production")))]
fn launch_driver<P: DevmgrPlatform>(
    platform: &mut P,
    bootstrap: DwHandle,
    resident: &mut crate::ResidentController,
) -> Result<DwHandle, u32> {
    let (retained, child) = platform
        .create_channel(DIRECT_CONTROL_RIGHTS)
        .map_err(|_| failure(44))?;
    if validate_fresh(
        platform,
        retained,
        DW_OBJECT_TYPE_CHANNEL,
        DIRECT_CONTROL_RIGHTS,
    )
    .is_err()
        || validate_fresh(
            platform,
            child,
            DW_OBJECT_TYPE_CHANNEL,
            DIRECT_CONTROL_RIGHTS,
        )
        .is_err()
    {
        let _ = platform.close_handle(child);
        let _ = platform.close_handle(retained);
        return Err(failure(45));
    }
    let request = match resident.issue_driver_launch(true, DirectControlRights::ExactReduced) {
        Ok(request) => request,
        Err(_) => {
            let _ = platform.close_handle(child);
            let _ = platform.close_handle(retained);
            return Err(failure(46));
        }
    };
    let mut bytes = [0u8; LAUNCH_REQUEST_BYTES];
    if encode_request(request, &mut bytes).is_err() {
        let _ = platform.close_handle(child);
        let _ = platform.close_handle(retained);
        return Err(failure(47));
    }
    let transfer = DwHandleTransferV1 {
        handle: child,
        requested_rights: CHILD_CHANNEL_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if send_bootstrap_channel(
        platform,
        bootstrap,
        &bytes,
        core::slice::from_ref(&transfer),
        48,
    )
    .is_err()
    {
        let _ = platform.close_handle(child);
        let _ = platform.close_handle(retained);
        return Err(failure(48));
    }

    // Construction acknowledgement and direct CONTROL_READY share one
    // absolute checked deadline. A late first phase cannot mint a fresh
    // readiness budget for the second phase.
    let deadline = platform
        .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .map_err(|_| failure(49))?;
    wait_readable(platform, bootstrap, deadline, 50)?;
    let mut response = [0u8; LAUNCH_RESPONSE_BYTES];
    let mut response_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(bootstrap, &mut response, &mut response_handles)
        .map_err(|_| failure(51))?;
    if counts.bytes != response.len() || counts.handles != 0 {
        close_received(platform, &response_handles, counts.handles);
        let _ = platform.close_handle(retained);
        return Err(failure(52));
    }
    if parse_constructed(&response, request).is_err() || resident.driver_constructed().is_err() {
        let _ = platform.close_handle(retained);
        return Err(failure(53));
    }

    wait_readable(platform, retained, deadline, 54)?;
    let mut control = [0u8; CONTROL_READY_BYTES];
    let mut control_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(retained, &mut control, &mut control_handles)
        .map_err(|_| failure(55))?;
    if counts.bytes != control.len() || counts.handles != 0 {
        close_received(platform, &control_handles, counts.handles);
        let _ = platform.close_handle(retained);
        return Err(failure(56));
    }
    let message = parse_control(&control).map_err(|_| failure(57))?;
    resident
        .accept_driver_control_ready(message)
        .map_err(|_| failure(58))?;
    Ok(retained)
}

#[cfg(feature = "wyr1c5-production")]
fn launch_driver_with_bundle<P: DevmgrPlatform>(
    platform: &mut P,
    bootstrap: DwHandle,
    publication: DwHandle,
    parent_resource: DwHandle,
    resident: &mut crate::ResidentController,
) -> Result<DwHandle, u32> {
    #[cfg(feature = "wyr1d-production")]
    return launch_driver_staged(platform, bootstrap, publication, parent_resource, resident);
    #[cfg(not(feature = "wyr1d-production"))]
    return launch_driver_with_historical_bundle(
        platform,
        bootstrap,
        publication,
        parent_resource,
        resident,
    );
}

/// One handle the staged launch owns until it moves or returns it.
#[cfg(feature = "wyr1d-production")]
struct OwnedHandle(DwHandle);

#[cfg(feature = "wyr1d-production")]
impl OwnedHandle {
    const fn raw(&self) -> DwHandle {
        self.0
    }

    fn moved(&mut self) {
        self.0 = DW_HANDLE_INVALID;
    }

    fn take_raw(&mut self) -> DwHandle {
        let raw = self.0;
        self.moved();
        raw
    }

    fn hold(&mut self, raw: DwHandle) -> &mut Self {
        self.0 = raw;
        self
    }
}

/// The handles one staged launch owns, in creation order.
///
/// These were `Drop` guards local to `launch_driver_staged`, closed at every
/// return in reverse declaration order. A guard cannot reach the caller's
/// platform from `Drop`, so the slots live here instead: each starts
/// invalid, is filled where its guard used to be created, and
/// [`StagedLaunchHandles::close_live`] closes the live ones in the same
/// reverse order when the launch returns. An unfilled or moved slot is
/// skipped, exactly as a guard not yet created or already moved was.
#[cfg(feature = "wyr1d-production")]
struct StagedLaunchHandles {
    retained: OwnedHandle,
    child: OwnedHandle,
    reduced: OwnedHandle,
    interrupt: OwnedHandle,
}

#[cfg(feature = "wyr1d-production")]
impl StagedLaunchHandles {
    const fn new() -> Self {
        Self {
            retained: OwnedHandle(DW_HANDLE_INVALID),
            child: OwnedHandle(DW_HANDLE_INVALID),
            reduced: OwnedHandle(DW_HANDLE_INVALID),
            interrupt: OwnedHandle(DW_HANDLE_INVALID),
        }
    }

    fn close_live<P: DevmgrPlatform>(&mut self, platform: &mut P) {
        for slot in [
            &mut self.interrupt,
            &mut self.reduced,
            &mut self.child,
            &mut self.retained,
        ] {
            if slot.0 != DW_HANDLE_INVALID {
                let _ = platform.close_handle(slot.0);
            }
        }
    }
}

#[cfg(feature = "wyr1d-production")]
fn launch_driver_staged<P: DevmgrPlatform>(
    platform: &mut P,
    bootstrap: DwHandle,
    publication: DwHandle,
    parent_resource: DwHandle,
    resident: &mut crate::ResidentController,
) -> Result<DwHandle, u32> {
    let mut owned = StagedLaunchHandles::new();
    let result = launch_driver_staged_owned(
        platform,
        &mut owned,
        bootstrap,
        publication,
        parent_resource,
        resident,
    );
    owned.close_live(platform);
    result
}

#[cfg(feature = "wyr1d-production")]
fn launch_driver_staged_owned<P: DevmgrPlatform>(
    platform: &mut P,
    owned: &mut StagedLaunchHandles,
    bootstrap: DwHandle,
    publication: DwHandle,
    parent_resource: DwHandle,
    resident: &mut crate::ResidentController,
) -> Result<DwHandle, u32> {
    let (retained_raw, child_raw) = platform
        .create_channel(DIRECT_CONTROL_RIGHTS)
        .map_err(|_| failure(57))?;
    let retained = owned.retained.hold(retained_raw);
    let child = owned.child.hold(child_raw);
    if validate_fresh(
        platform,
        retained.raw(),
        DW_OBJECT_TYPE_CHANNEL,
        DIRECT_CONTROL_RIGHTS,
    )
    .is_err()
        || validate_fresh(
            platform,
            child.raw(),
            DW_OBJECT_TYPE_CHANNEL,
            DIRECT_CONTROL_RIGHTS,
        )
        .is_err()
    {
        return Err(failure(58));
    }
    let request = resident
        .issue_driver_launch_with_bundle(true, DirectControlRights::ExactReduced)
        .map_err(|_| failure(59))?;
    let mut launch = [0u8; LAUNCH_REQUEST_BYTES];
    encode_request(request, &mut launch).map_err(|_| failure(60))?;
    let child_transfer = DwHandleTransferV1 {
        handle: child.raw(),
        requested_rights: CHILD_CHANNEL_TRANSFER_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if send_bootstrap_channel(
        platform,
        bootstrap,
        &launch,
        core::slice::from_ref(&child_transfer),
        61,
    )
    .is_err()
    {
        return Err(failure(61));
    }
    child.moved();
    let deadline = platform
        .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .map_err(|_| failure(62))?;
    wait_readable(platform, bootstrap, deadline, 63)?;
    let mut constructed = [0u8; LAUNCH_RESPONSE_BYTES];
    let mut constructed_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(bootstrap, &mut constructed, &mut constructed_handles)
        .map_err(|_| failure(64))?;
    if counts.bytes != constructed.len() || counts.handles != 0 {
        close_received(platform, &constructed_handles, counts.handles);
        return Err(failure(65));
    }
    if parse_constructed(&constructed, request).is_err() || resident.driver_constructed().is_err() {
        return Err(failure(66));
    }

    let correlations = resident
        .reserve_d3_stage_correlations(request)
        .map_err(|_| failure(68))?;
    let ready_identity = ControlIdentityV1_1 {
        role_id: request.role_id,
        bundle_generation: resident.bundle_generation().ok_or(failure(67))?,
        attempt_generation: request.attempt_generation,
        endpoint: request.endpoint,
        transaction_id: correlations.ready_transaction_id,
    };
    let mut staging =
        DeviceStageCoordinator::new(ready_identity, correlations).map_err(|_| failure(68))?;

    let reduced = owned.reduced.hold(
        platform
            .duplicate_handle(parent_resource, DEVICE_RESOURCE_TRANSFER_RIGHTS)
            .map_err(|_| failure(69))?,
    );
    if validate_fresh(
        platform,
        reduced.raw(),
        DW_OBJECT_TYPE_DEVICE_RESOURCE,
        DEVICE_RESOURCE_TRANSFER_RIGHTS,
    )
    .is_err()
    {
        return Err(failure(70));
    }
    let resource = platform
        .device_resource_info(reduced.raw())
        .map_err(|_| failure(71))?;
    if resource.resource_id != crate::COM2_RESOURCE_ID
        || resource.lease_generation != ready_identity.bundle_generation.0
        || resource.pio_base != 0x2f8
        || resource.pio_length != 8
        || resource.interrupt_source != 3
        || resource.flags != 0
        || resource.reserved != 0
    {
        return Err(failure(72));
    }
    let device_message = staging.device_stage_message().map_err(|_| failure(73))?;
    let mut device_bytes = [0; D3_DEVICE_STAGE_BYTES];
    encode_control_v1_1(device_message, &mut device_bytes).map_err(|_| failure(73))?;
    let transfer = DwHandleTransferV1 {
        handle: reduced.raw(),
        requested_rights: DEVICE_RESOURCE_DRIVER_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if platform
        .send_channel(
            retained.raw(),
            &device_bytes,
            core::slice::from_ref(&transfer),
        )
        .is_err()
    {
        return Err(failure(74));
    }
    reduced.moved();
    staging.device_stage_moved().map_err(|_| failure(75))?;
    wait_readable(platform, retained.raw(), deadline, 76)?;
    let mut quiesced_bytes = [0; D3_DEVICE_QUIESCED_BYTES];
    let mut response_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(retained.raw(), &mut quiesced_bytes, &mut response_handles)
        .map_err(|_| failure(77))?;
    if counts.bytes != quiesced_bytes.len() || counts.handles != 0 {
        close_received(platform, &response_handles, counts.handles);
        return Err(failure(78));
    }
    let quiesced = parse_control_v1_1(&quiesced_bytes).map_err(|_| failure(79))?;
    staging
        .accept_device_quiesced(quiesced)
        .map_err(|_| failure(80))?;

    // Creating the route-committing Interrupt is deliberately after the exact
    // DEVICE_QUIESCED reply above.
    let interrupt = owned.interrupt.hold(
        platform
            .create_interrupt(parent_resource, INTERRUPT_CUSTODY_RIGHTS)
            .map_err(|_| failure(81))?,
    );
    if validate_fresh(
        platform,
        interrupt.raw(),
        DW_OBJECT_TYPE_INTERRUPT,
        INTERRUPT_CUSTODY_RIGHTS,
    )
    .is_err()
    {
        return Err(failure(82));
    }
    let interrupt_facts = platform
        .interrupt_info(interrupt.raw())
        .map_err(|_| failure(83))?;
    if interrupt_facts.size != DW_INTERRUPT_INFO_V1_SIZE
        || interrupt_facts.version != DW_INTERRUPT_INFO_V1_VERSION
        || interrupt_facts.source != resource.interrupt_source
        || interrupt_facts.state != DW_INTERRUPT_STATE_ARMED
        || interrupt_facts.object_generation == 0
        || interrupt_facts.binding_generation == 0
        || interrupt_facts.parent_resource_id != resource.resource_id
        || interrupt_facts.parent_lease_generation != resource.lease_generation
        || interrupt_facts.flags.0 != 0
        || interrupt_facts.reserved0 != 0
        || interrupt_facts.reserved != 0
    {
        return Err(failure(84));
    }
    resident
        .set_driver_bindings(
            resource.lease_generation,
            interrupt_facts.binding_generation,
        )
        .map_err(|_| failure(85))?;
    staging.interrupt_created().map_err(|_| failure(86))?;
    let interrupt_message = staging.interrupt_stage_message().map_err(|_| failure(87))?;
    let mut interrupt_bytes = [0; D3_INTERRUPT_STAGE_BYTES];
    encode_control_v1_1(interrupt_message, &mut interrupt_bytes).map_err(|_| failure(87))?;
    let transfer = DwHandleTransferV1 {
        handle: interrupt.raw(),
        requested_rights: INTERRUPT_DRIVER_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if platform
        .send_channel(
            retained.raw(),
            &interrupt_bytes,
            core::slice::from_ref(&transfer),
        )
        .is_err()
    {
        return Err(failure(88));
    }
    interrupt.moved();
    staging.interrupt_stage_moved().map_err(|_| failure(89))?;
    resident.bundle_transferred().map_err(|_| failure(90))?;
    wait_readable(platform, retained.raw(), deadline, 91)?;
    let mut ready_bytes = [0; D3_READY_BYTES];
    let mut ready_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(retained.raw(), &mut ready_bytes, &mut ready_handles)
        .map_err(|_| failure(92))?;
    if counts.bytes != ready_bytes.len() || counts.handles != 0 {
        close_received(platform, &ready_handles, counts.handles);
        return Err(failure(93));
    }
    let ready = parse_control_v1_1(&ready_bytes).map_err(|_| failure(94))?;
    staging
        .accept_driver_ready(ready)
        .map_err(|_| failure(95))?;
    resident
        .accept_driver_ready_for_transaction(
            ControlMessage::Ready {
                role_id: request.role_id,
                bundle_generation: ready_identity.bundle_generation,
                attempt_generation: request.attempt_generation,
                endpoint: request.endpoint,
                transaction_id: correlations.ready_transaction_id,
            },
            correlations.ready_transaction_id,
        )
        .map_err(|_| failure(96))?;
    publish_driver(platform, publication, request, resident)?;
    Ok(retained.take_raw())
}

#[cfg(all(feature = "wyr1c5-production", not(feature = "wyr1d-production")))]
fn launch_driver_with_historical_bundle<P: DevmgrPlatform>(
    platform: &mut P,
    bootstrap: DwHandle,
    publication: DwHandle,
    parent_resource: DwHandle,
    resident: &mut crate::ResidentController,
) -> Result<DwHandle, u32> {
    let (retained, child) = platform
        .create_channel(DIRECT_CONTROL_RIGHTS)
        .map_err(|_| failure(57))?;
    if validate_fresh(
        platform,
        retained,
        DW_OBJECT_TYPE_CHANNEL,
        DIRECT_CONTROL_RIGHTS,
    )
    .is_err()
        || validate_fresh(
            platform,
            child,
            DW_OBJECT_TYPE_CHANNEL,
            DIRECT_CONTROL_RIGHTS,
        )
        .is_err()
    {
        let _ = platform.close_handle(child);
        let _ = platform.close_handle(retained);
        return Err(failure(58));
    }
    let request =
        match resident.issue_driver_launch_with_bundle(true, DirectControlRights::ExactReduced) {
            Ok(request) => request,
            Err(_) => {
                let _ = platform.close_handle(child);
                let _ = platform.close_handle(retained);
                return Err(failure(59));
            }
        };
    let mut launch = [0u8; LAUNCH_REQUEST_BYTES];
    if encode_request(request, &mut launch).is_err() {
        let _ = platform.close_handle(child);
        let _ = platform.close_handle(retained);
        return Err(failure(60));
    }
    let child_transfer = DwHandleTransferV1 {
        handle: child,
        requested_rights: CHILD_CHANNEL_TRANSFER_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if send_bootstrap_channel(
        platform,
        bootstrap,
        &launch,
        core::slice::from_ref(&child_transfer),
        61,
    )
    .is_err()
    {
        let _ = platform.close_handle(child);
        let _ = platform.close_handle(retained);
        return Err(failure(61));
    }

    let deadline =
        match platform.monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns) {
            Ok(deadline) => deadline,
            Err(_) => {
                let _ = platform.close_handle(retained);
                return Err(failure(62));
            }
        };
    if wait_readable(platform, bootstrap, deadline, 63).is_err() {
        let _ = platform.close_handle(retained);
        return Err(failure(63));
    }
    let mut constructed = [0u8; LAUNCH_RESPONSE_BYTES];
    let mut constructed_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts =
        match platform.receive_channel(bootstrap, &mut constructed, &mut constructed_handles) {
            Ok(counts) => counts,
            Err(_) => {
                let _ = platform.close_handle(retained);
                return Err(failure(64));
            }
        };
    if counts.bytes != constructed.len() || counts.handles != 0 {
        close_received(platform, &constructed_handles, counts.handles);
        let _ = platform.close_handle(retained);
        return Err(failure(65));
    }
    if parse_constructed(&constructed, request).is_err() || resident.driver_constructed().is_err() {
        let _ = platform.close_handle(retained);
        return Err(failure(66));
    }

    let reduced = match platform.duplicate_handle(parent_resource, DEVICE_RESOURCE_TRANSFER_RIGHTS)
    {
        Ok(handle) => handle,
        Err(_) => {
            let _ = platform.close_handle(retained);
            return Err(failure(67));
        }
    };
    let interrupt = match platform.create_interrupt(parent_resource, INTERRUPT_CUSTODY_RIGHTS) {
        Ok(handle) => handle,
        Err(_) => {
            let _ = platform.close_handle(reduced);
            let _ = platform.close_handle(retained);
            return Err(failure(68));
        }
    };
    let intake = (|| {
        validate_fresh(
            platform,
            reduced,
            DW_OBJECT_TYPE_DEVICE_RESOURCE,
            DEVICE_RESOURCE_TRANSFER_RIGHTS,
        )
        .map_err(|_| failure(69))?;
        validate_fresh(
            platform,
            interrupt,
            DW_OBJECT_TYPE_INTERRUPT,
            INTERRUPT_CUSTODY_RIGHTS,
        )
        .map_err(|_| failure(70))?;
        let resource = platform
            .device_resource_info(reduced)
            .map_err(|_| failure(71))?;
        let interrupt_info = platform
            .interrupt_info(interrupt)
            .map_err(|_| failure(72))?;
        if resource.resource_id != crate::COM2_RESOURCE_ID
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
            let _ = platform.close_handle(interrupt);
            let _ = platform.close_handle(reduced);
            let _ = platform.close_handle(retained);
            return Err(code);
        }
    };
    if resident
        .set_driver_bindings(lease_generation, irq_binding)
        .is_err()
    {
        let _ = platform.close_handle(interrupt);
        let _ = platform.close_handle(reduced);
        let _ = platform.close_handle(retained);
        return Err(failure(74));
    }

    let bundle = match resident.resource_bundle_message() {
        Ok(message) => message,
        Err(_) => {
            let _ = platform.close_handle(interrupt);
            let _ = platform.close_handle(reduced);
            let _ = platform.close_handle(retained);
            return Err(failure(74));
        }
    };
    let mut bundle_bytes = [0u8; RESOURCE_BUNDLE_BYTES];
    if encode_control(bundle, &mut bundle_bytes).is_err() {
        let _ = platform.close_handle(interrupt);
        let _ = platform.close_handle(reduced);
        let _ = platform.close_handle(retained);
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
    if platform
        .send_channel(retained, &bundle_bytes, &transfers)
        .is_err()
    {
        let _ = platform.close_handle(interrupt);
        let _ = platform.close_handle(reduced);
        let _ = platform.close_handle(retained);
        return Err(failure(76));
    }
    if resident.bundle_transferred().is_err() {
        let _ = platform.close_handle(retained);
        return Err(failure(92));
    }

    if wait_readable(platform, retained, deadline, 77).is_err() {
        let _ = platform.close_handle(retained);
        return Err(failure(77));
    }
    let mut ready = [0u8; READY_BYTES];
    let mut ready_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = match platform.receive_channel(retained, &mut ready, &mut ready_handles) {
        Ok(counts) => counts,
        Err(_) => {
            let _ = platform.close_handle(retained);
            return Err(failure(78));
        }
    };
    if counts.bytes != ready.len() || counts.handles != 0 {
        close_received(platform, &ready_handles, counts.handles);
        let _ = platform.close_handle(retained);
        return Err(failure(79));
    }
    let ready = match parse_control(&ready) {
        Ok(ready) => ready,
        Err(_) => {
            let _ = platform.close_handle(retained);
            return Err(failure(80));
        }
    };
    if resident.accept_driver_ready(ready).is_err() {
        let _ = platform.close_handle(retained);
        return Err(failure(81));
    }
    let should_publish = true;
    if should_publish {
        if let Err(code) = publish_driver(platform, publication, request, resident) {
            let _ = send_driver_retire(platform, retained, resident);
            let _ = platform.close_handle(retained);
            return Err(code);
        }
    }
    Ok(retained)
}

#[cfg(feature = "wyr1c5-production")]
fn publish_driver<P: DevmgrPlatform>(
    platform: &mut P,
    publication: DwHandle,
    request: wyrmroot_device_proto::DriverLaunchRequest,
    resident: &mut crate::ResidentController,
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
    platform
        .send_channel(publication, &bytes[..size], &[])
        .map_err(|_| failure(84))?;
    let deadline = platform
        .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .map_err(|_| failure(85))?;
    wait_readable(platform, publication, deadline, 86)?;
    let mut response = [0u8; REGISTRY_HEADER_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(publication, &mut response, &mut handles)
        .map_err(|_| failure(87))?;
    if counts.bytes != response.len() || counts.handles != 0 {
        close_received(platform, &handles, counts.handles);
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
fn send_driver_retire<P: DevmgrPlatform>(
    platform: &mut P,
    control: DwHandle,
    resident: &mut crate::ResidentController,
) -> Result<(), u32> {
    let message = resident.retire_message().map_err(|_| failure(93))?;
    let mut bytes = [0u8; wyrmroot_device_proto::control::RETIRE_BYTES];
    encode_control(message, &mut bytes).map_err(|_| failure(94))?;
    platform
        .send_channel(control, &bytes, &[])
        .map_err(|_| failure(95))
}

#[cfg(any(
    not(any(feature = "wyr1c4-production", feature = "wyr1c5-production")),
    feature = "wyr1c5-production"
))]
fn wait_readable<P: DevmgrPlatform>(
    platform: &mut P,
    handle: DwHandle,
    deadline: deepwyrm_syscall::DwDeadline,
    stage: u32,
) -> Result<(), u32> {
    let observed = platform
        .wait_many(core::slice::from_ref(&wait_item(handle)), deadline)
        .map_err(|_| failure(stage))?;
    if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(failure(stage));
    }
    Ok(())
}

fn send_publication_acknowledgement<P: DevmgrPlatform>(
    platform: &mut P,
    bootstrap: DwHandle,
    resident: &crate::ResidentController,
) -> Result<(), u32> {
    let bytes = resident
        .publication_acknowledgement()
        .map_err(|error| match error {
            crate::PublicationAcknowledgementError::Lifecycle(_) => failure(35),
            crate::PublicationAcknowledgementError::Encoding(_) => failure(36),
        })?;
    send_bootstrap_channel(platform, bootstrap, &bytes, &[], 37)
}

fn send_resident_status<P: DevmgrPlatform>(
    platform: &mut P,
    bootstrap: DwHandle,
    resident: &crate::ResidentController,
    status: StatusCode,
) -> Result<(), u32> {
    let message = resident.report(status).map_err(|_| failure(35))?;
    let mut bytes = [0u8; STATUS_BYTES];
    encode_controller(message, &mut bytes).map_err(|_| failure(36))?;
    send_bootstrap_channel(platform, bootstrap, &bytes, &[], 37)
}

fn send_bootstrap_channel<P: DevmgrPlatform>(
    platform: &mut P,
    bootstrap: DwHandle,
    bytes: &[u8],
    transfers: &[DwHandleTransferV1],
    stage: u32,
) -> Result<(), u32> {
    platform
        .send_channel(bootstrap, bytes, transfers)
        .map_err(|_| failure(stage))
}

fn validate_fresh<P: DevmgrPlatform>(
    platform: &mut P,
    handle: DwHandle,
    object_type: DwObjectType,
    rights: DwRights,
) -> Result<(), ()> {
    let actual: CapabilityInfo<DwObjectType, DwRights> =
        platform.query_capability_info(handle).map_err(|_| ())?;
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

fn close_received<P: DevmgrPlatform>(
    platform: &mut P,
    handles: &[DwReceivedHandleInfoV1],
    count: usize,
) {
    for info in handles.iter().take(count.min(handles.len())) {
        let _ = platform.close_handle(info.handle);
    }
}

fn close_optional<P: DevmgrPlatform>(platform: &mut P, handle: Option<DwHandle>) {
    if let Some(handle) = handle {
        let _ = platform.close_handle(handle);
    }
}

const fn failure(stage: u32) -> u32 {
    FAILURE_BASE | stage
}
