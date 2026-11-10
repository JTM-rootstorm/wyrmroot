//! The devmgr role: bootstrap, the resident controller loop, driver launch,
//! connector brokering and driver supervision.
//!
//! This is the whole native role that `src/main.rs` used to hold. The binary
//! keeps only its freestanding entry, which hands [`run`] the bootstrap
//! Channel. It exists only with `native-devmgr`, which every devmgr binary
//! shape requires.

use crate::ControllerAction;
use crate::connector::{
    AttachCorrelation, DirectClientReleaseEvent, ProductionPublicationEvent, ProductionWaitSource,
    classify_direct_client_release, classify_production_publication, cleanup_deadline_live,
    production_cleanup_deadline, production_wait_plan,
};
use crate::connector::{ConnectorAction, ConnectorBroker, ConnectorSlot, PublishedDriver};
use crate::staging::DeviceStageCoordinator;
use deepwyrm_syscall::DW_HANDLE_INVALID;
use deepwyrm_syscall::DW_STATUS_TIMED_OUT;
use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL,
    DW_OBJECT_TYPE_MEMORY_OBJECT, DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT, DW_RIGHT_READ,
    DW_RIGHT_TRANSFER, DW_RIGHT_WRITE, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DwHandle,
    DwHandleTransferV1, DwObjectType, DwReceivedHandleInfoV1, DwRights, DwWaitItemV1,
};
use deepwyrm_syscall::{DW_HANDLE_TRANSFER_MOVE, DW_RIGHT_WAIT};
use deepwyrm_syscall::{
    DW_INTERRUPT_INFO_V1_SIZE, DW_INTERRUPT_INFO_V1_VERSION, DW_INTERRUPT_STATE_ARMED,
    DW_OBJECT_TYPE_INTERRUPT,
};
use deepwyrm_syscall::{
    DW_OBJECT_TYPE_DEVICE_RESOURCE, DW_OBJECT_TYPE_TASK_GROUP, DW_RIGHT_MODIFY,
};
use wyrmroot_device_proto::ConnectorMessage;
use wyrmroot_device_proto::ControlMessage;
use wyrmroot_device_proto::FailureCode;
use wyrmroot_device_proto::connector::{
    RECORD_BYTES as CONNECTOR_BYTES, encode as encode_connector, parse as parse_connector,
};
use wyrmroot_device_proto::control_v1_1::{
    ControlIdentityV1_1, DEVICE_QUIESCED_BYTES as D3_DEVICE_QUIESCED_BYTES,
    DEVICE_STAGE_BYTES as D3_DEVICE_STAGE_BYTES, INTERRUPT_STAGE_BYTES as D3_INTERRUPT_STAGE_BYTES,
    READY_BYTES as D3_READY_BYTES, encode as encode_control_v1_1, parse as parse_control_v1_1,
};
use wyrmroot_device_proto::driver_launch::{
    REAPED_RESPONSE_BYTES, encode_driver_retired, parse_reaped,
};
use wyrmroot_device_proto::{
    ControllerMessage, StatusCode,
    controller::{STATUS_BYTES, encode as encode_controller},
};
use wyrmroot_device_proto::{
    DirectControlRights,
    control::encode as encode_control,
    driver_launch::{
        LAUNCH_REQUEST_BYTES, LAUNCH_RESPONSE_BYTES, encode_request, parse_constructed,
    },
};
use wyrmroot_loader::launch::CHILD_CHANNEL_TRANSFER_RIGHTS;
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, DEVICE_MANIFEST_RIGHTS, HEADER_BYTES, LaunchProfile, SELF_ROOT_RIGHTS,
    encode_ready_for_profile,
};
use wyrmroot_loader::launch::{
    DEVICE_COORDINATOR_RESOURCE_BYTES, RESOURCE_DOMAIN_CLAIM_RIGHTS,
    parse_device_coordinator_resource_init,
};
use wyrmroot_registry_proto::{
    HEADER_BYTES as REGISTRY_HEADER_BYTES, Header as RegistryHeader, Message as RegistryMessage,
    MessageType as RegistryMessageType, encode_empty as encode_registry_empty,
    parse as parse_registry,
};
use wyrmroot_registry_proto::{Lookup, ProtocolVersion};
use wyrmroot_runtime::NativeError;
use wyrmroot_runtime::WYR0_I_SUPERVISION_POLICY;
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, ChannelPlatform, ClockPlatform, DevicePlatform,
    EvidencePlatform, HandlePlatform, MappingPlan, MemoryPlatform, WaitPlatform,
    validate_bootstrap_channel,
};

mod broker;
mod controller;
mod driver;
mod io;
pub(crate) use broker::*;
pub(crate) use controller::*;
pub(crate) use driver::*;
pub(crate) use io::*;

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

#[derive(Clone, Copy)]
pub(crate) struct ProductionClientWitness {
    handle: DwHandle,
    attach: AttachCorrelation,
}
const DIRECT_CONTROL_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0
        | DW_RIGHT_WRITE.0
        | DW_RIGHT_WAIT.0
        | DW_RIGHT_INSPECT.0
        | DW_RIGHT_DUPLICATE.0
        | DW_RIGHT_TRANSFER.0,
);
const DEVICE_RESOURCE_CUSTODY_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0
        | DW_RIGHT_WRITE.0
        | DW_RIGHT_MODIFY.0
        | DW_RIGHT_DUPLICATE.0
        | DW_RIGHT_TRANSFER.0
        | DW_RIGHT_INSPECT.0,
);
const DEVICE_RESOURCE_DRIVER_RIGHTS: DwRights =
    DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_INSPECT.0);
const DEVICE_RESOURCE_TRANSFER_RIGHTS: DwRights =
    DwRights(DEVICE_RESOURCE_DRIVER_RIGHTS.0 | DW_RIGHT_TRANSFER.0);
const INTERRUPT_CUSTODY_RIGHTS: DwRights =
    DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_TRANSFER.0 | DW_RIGHT_INSPECT.0);
const INTERRUPT_DRIVER_RIGHTS: DwRights =
    DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0);
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

    let mut init = [0u8; DEVICE_COORDINATOR_RESOURCE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 4];
    let counts = platform
        .receive_channel(bootstrap, &mut init, &mut handles)
        .map_err(|_| failure(3))?;
    if counts.bytes > init.len() || counts.handles != handles.len() {
        close_received(platform, &handles, counts.handles);
        return Err(failure(4));
    }
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
    let launch_profile = LaunchProfile::DeviceCoordinatorResourceDomain;
    let ready_len = encode_ready_for_profile(launch_profile, parsed.transaction_id, &mut ready)
        .map_err(|_| failure(14))?;
    send_bootstrap_channel(platform, bootstrap, &ready[..ready_len], &[], 15)?;

    let mut publication = Some(publication);
    let mut driver_control = None;
    let mut connector_broker: Option<ConnectorBroker> = None;
    let mut production_witness: Option<ProductionClientWitness> = None;
    let mut connector_cleanup_deadline: Option<u64> = None;
    let mut waiting_registry_status_sent = false;
    let mut device_resource = None;
    loop {
        let mut waits = [DwWaitItemV1::default(); 4];
        waits[0] = wait_item(bootstrap);
        let mut wait_count = 1;
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
        let mut witness_index = None;
        let mut driver_index = None;
        let mut publication_index = None;
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
        let wait_deadline = plan
            .deadline()
            .map_or(DW_DEADLINE_INFINITE, deepwyrm_syscall::DwDeadline);
        let observed = platform
            .wait_many(&waits[..wait_count], wait_deadline)
            .map_err(|_error| {
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
        if let Some(deadline) = connector_cleanup_deadline
            && !cleanup_deadline_live(
                platform.monotonic_active_now().map_err(|_| failure(277))?,
                deadline,
            )
        {
            return Err(failure(278));
        }
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
                if let Some(control) = driver_control {
                    let _ = send_driver_retire(platform, control, &mut resident);
                }
                close_optional(platform, driver_control);
                close_optional(platform, device_resource.take());
                platform.close_handle(bootstrap).map_err(|_| failure(19))?;
                return Err(failure(20));
            }
            let input = match receive_controller(platform, bootstrap, &mut resident) {
                Ok(received) => received,
                Err(code) => {
                    close_optional(platform, publication);
                    close_optional(platform, driver_control);
                    close_optional(platform, device_resource.take());
                    let _ = platform.close_handle(bootstrap);
                    return Err(code);
                }
            };
            let (replacement, action) = input;
            if let Some(replacement) = replacement {
                if let Some(old) = publication.replace(replacement) {
                    let _ = platform.close_handle(replacement);
                    let _ = platform.close_handle(old);
                    close_optional(platform, device_resource.take());
                    let _ = platform.close_handle(bootstrap);
                    return Err(failure(21));
                }
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
                    close_optional(platform, device_resource.take());
                    let _ = platform.close_handle(domain);
                    close_optional(platform, publication);
                    close_optional(platform, driver_control);
                    let _ = platform.close_handle(bootstrap);
                    return Err(code);
                }
                if platform.close_handle(domain).is_err() {
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
                close_optional(platform, device_resource.take());
                let _ = platform.close_handle(bootstrap);
                return Err(code);
            }
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
                activate_connector_broker(&mut resident, &mut connector_broker)?;
            }
            continue;
        }

        if Some(index) == driver_index {
            let control = driver_control.take().ok_or(failure(39))?;
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
            if observed.observed.0 & (DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0) != 0 {
                let request = resident.active_driver_request().ok_or(failure(40))?;
                let production_retiring_driver = published_driver(&resident, request)?;
                observe_driver_failure(
                    platform,
                    control,
                    request,
                    &mut resident,
                    observed.observed.0 & DW_SIGNAL_READABLE.0 != 0,
                    observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0,
                    false,
                )?;
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
                {
                    // The exact retired attempt is now terminal and fully
                    // reaped.  A later replacement failure is ordinary unless
                }
                let rebind_deadline = platform
                    .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
                    .map_err(|_| failure(45))?;
                wait_readable(platform, bootstrap, rebind_deadline, 46)?;
                let received = receive_controller(platform, bootstrap, &mut resident)?;
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
                activate_connector_broker(&mut resident, &mut connector_broker)?;
                continue;
            }
            platform.close_handle(control).map_err(|_| failure(41))?;
            resident.reap_driver().map_err(|_| failure(42))?;
            {
                close_optional(platform, device_resource.take());
                close_optional(platform, publication.take());
                let _ = platform.close_handle(bootstrap);
                return Err(failure(96));
            }
        }

        if Some(index) != publication_index {
            return Err(failure(43));
        }
        let service_offer = match classify_production_publication(
            observed.observed.0 & DW_SIGNAL_READABLE.0 != 0,
            observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0,
        ) {
            ProductionPublicationEvent::Offer => true,
            ProductionPublicationEvent::Retire => false,
            ProductionPublicationEvent::Malformed => return Err(failure(312)),
        };
        if service_offer {
            {
                let broker = connector_broker.as_mut().ok_or(failure(170))?;
                let control = driver_control.ok_or(failure(171))?;
                service_connector_offer(
                    platform,
                    publication.ok_or(failure(172))?,
                    control,
                    &resident,
                    broker,
                    &mut production_witness,
                )?;
                continue;
            }
        }
        // Registry replacement closes only the old publication binding.  The
        // coordinator generation remains resident; a later WRCS rebind moves
        // one exact child Channel over the still-open bootstrap relationship.
        let old = publication.take().ok_or(failure(24))?;
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
    }
}

type ControllerInput = (Option<DwHandle>, ControllerAction);
