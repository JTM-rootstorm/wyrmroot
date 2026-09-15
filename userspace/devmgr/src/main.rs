#![cfg_attr(target_os = "wyrmroot", no_std)]
#![cfg_attr(target_os = "wyrmroot", no_main)]
#![deny(unsafe_code)]

#[cfg(any(
    all(feature = "wyr1e-production", feature = "wyr1d-selector32"),
    all(feature = "wyr1e-production", feature = "dw1e3-selector31"),
    all(feature = "wyr1e-production", feature = "wyr1c6-selector29")
))]
compile_error!("WYR1-E production and selector-only devmgr policies are mutually exclusive");

#[cfg(target_os = "wyrmroot")]
use core::panic::PanicInfo;
#[cfg(feature = "wyr1d-production")]
use deepwyrm_syscall::DW_HANDLE_INVALID;
#[cfg(any(feature = "wyr1c6-production", feature = "dw1e3-selector31"))]
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
#[cfg(feature = "wyr1c6-selector29")]
use deepwyrm_syscall::{DW_SIGNAL_WRITABLE, DW_STATUS_WOULD_BLOCK};
#[cfg(any(
    feature = "dw1e3-selector31",
    feature = "wyr1d-selector32",
    feature = "wyr1e-production"
))]
use wyrmroot_device_proto::ConnectorMessage;
#[cfg(any(
    feature = "wyr1c6-production",
    feature = "wyr1d-production",
    feature = "dw1e3-selector31"
))]
use wyrmroot_device_proto::ControlMessage;
#[cfg(any(feature = "wyr1c6-production", feature = "dw1e3-selector31"))]
use wyrmroot_device_proto::FailureCode;
#[cfg(any(
    feature = "dw1e3-selector31",
    feature = "wyr1d-selector32",
    feature = "wyr1e-production"
))]
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
#[cfg(not(any(
    feature = "dw1e3-selector31",
    feature = "wyr1d-selector32",
    feature = "wyr1e-production"
)))]
use wyrmroot_device_proto::controller::INSTALL_BYTES;
#[cfg(not(any(feature = "wyr1d-selector32", feature = "wyr1e-production")))]
use wyrmroot_device_proto::controller::parse as parse_controller;
#[cfg(feature = "wyr1d-selector32")]
use wyrmroot_device_proto::d5_controller::encode as encode_d5_controller;
#[cfg(any(feature = "wyr1d-selector32", feature = "wyr1e8-production"))]
use wyrmroot_device_proto::d5_controller::{
    D5ControllerMessage, RECORD_BYTES as D5_CONTROLLER_BYTES, parse as parse_d5_controller,
};
#[cfg(feature = "wyr1c6-selector29")]
use wyrmroot_device_proto::driver_launch::{C6_FACT_BYTES, C6Fact, encode_c6_fact};
#[cfg(any(feature = "wyr1c6-production", feature = "dw1e3-selector31"))]
use wyrmroot_device_proto::driver_launch::{
    REAPED_RESPONSE_BYTES, encode_driver_retired, parse_reaped,
};
#[cfg(feature = "wyr1c6-selector29")]
use wyrmroot_device_proto::selector29_should_fail;
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
use wyrmroot_devmgr::ControllerAction;
#[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
use wyrmroot_devmgr::connector::{
    AttachCorrelation, DirectClientReleaseEvent, ProductionPublicationEvent, ProductionWaitSource,
    classify_direct_client_release, classify_production_publication, cleanup_deadline_live,
    production_cleanup_deadline, production_wait_plan,
};
#[cfg(any(
    feature = "dw1e3-selector31",
    feature = "wyr1d-selector32",
    feature = "wyr1e-production"
))]
use wyrmroot_devmgr::connector::{
    ConnectorAction, ConnectorBroker, ConnectorSlot, PublishedDriver,
};
#[cfg(feature = "wyr1d-production")]
use wyrmroot_devmgr::staging::DeviceStageCoordinator;
#[cfg(feature = "dw1e3-selector31")]
use wyrmroot_dw1e3_com2_test::{
    ChallengeBinding, DEVMGR_CONFIG_BYTES, DevmgrConfig, DevmgrReady, TRANSPORT_EMPTY_FACT_BYTES,
    encode_challenge_binding, encode_devmgr_ready, parse_begin_retire, parse_binding_ready,
    parse_challenge_binding, parse_devmgr_config, parse_finalize_retire, parse_retire_stage1_ready,
    parse_transport_empty_fact,
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
#[cfg(feature = "wyr1c4-production")]
use wyrmroot_registry_proto as _;
#[cfg(feature = "wyr1c5-production")]
use wyrmroot_registry_proto::{
    HEADER_BYTES as REGISTRY_HEADER_BYTES, Header as RegistryHeader, Message as RegistryMessage,
    MessageType as RegistryMessageType, encode_empty as encode_registry_empty,
    parse as parse_registry,
};
#[cfg(any(
    feature = "dw1e3-selector31",
    feature = "wyr1d-selector32",
    feature = "wyr1e-production"
))]
use wyrmroot_registry_proto::{Lookup, ProtocolVersion};
#[cfg(any(feature = "wyr1c6-production", feature = "dw1e3-selector31"))]
use wyrmroot_runtime::NativeError;
#[cfg(feature = "dw1e3-selector31")]
use wyrmroot_runtime::dw1e3_build_nonce;
#[cfg(any(feature = "wyr1c6-production", feature = "dw1e3-selector31"))]
use wyrmroot_runtime::monotonic_active_now;
#[cfg(target_os = "wyrmroot")]
use wyrmroot_runtime::panic_abort;
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, MappingPlan, StartupBlock, close_handle,
    map_bootfs_read_only, query_capability_info, query_memory_object_size, receive_channel,
    send_channel, unmap_bootfs, validate_bootstrap_channel, wait_many,
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

#[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
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
#[cfg(any(
    feature = "dw1e3-selector31",
    feature = "wyr1d-selector32",
    feature = "wyr1e-production"
))]
const STREAM_BROAD_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_TRANSFER.0,
);

fn native_main(startup: StartupBlock<'_>) -> u32 {
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
    send_bootstrap_channel(bootstrap, &ready[..ready_len], &[], 15)?;

    let mut publication = Some(publication);
    let mut driver_control = None;
    #[cfg(any(
        feature = "dw1e3-selector31",
        feature = "wyr1d-selector32",
        feature = "wyr1e-production"
    ))]
    let mut connector_broker: Option<ConnectorBroker> = None;
    #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
    let mut production_witness: Option<ProductionClientWitness> = None;
    #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
    let mut connector_cleanup_deadline: Option<u64> = None;
    #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
    let mut waiting_registry_status_sent = false;
    #[cfg(feature = "dw1e3-selector31")]
    let mut selector_binding = None;
    #[cfg(feature = "dw1e3-selector31")]
    let mut selector_binding_ready = false;
    #[cfg(feature = "dw1e3-selector31")]
    let mut selector_retiring_driver = None;
    #[cfg(feature = "wyr1d-selector32")]
    let mut selector32_retire_requested = None;
    #[cfg(feature = "wyr1d-selector32")]
    let mut selector32_drain = wyrmroot_devmgr::d5_drain::DrainRelay::default();
    #[cfg(feature = "wyr1e8-production")]
    let mut e8_retire_requested = false;
    #[cfg(all(
        not(feature = "wyr1e8-production"),
        any(feature = "wyr1c6-production", feature = "dw1e3-selector31")
    ))]
    let e8_retire_requested = false;
    #[cfg(feature = "wyr1c4-production")]
    let mut _device_resource = None;
    #[cfg(feature = "wyr1c5-production")]
    let mut device_resource = None;
    loop {
        let mut waits = [DwWaitItemV1::default(); 4];
        waits[0] = wait_item(bootstrap);
        let mut wait_count = 1;
        #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
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
        #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
        let mut witness_index = None;
        #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
        let mut driver_index = None;
        #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
        let mut publication_index = None;
        #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
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
        #[cfg(not(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32"))))]
        let driver_index = driver_control.map(|handle| {
            let index = wait_count;
            waits[index] = wait_item(handle);
            wait_count += 1;
            index
        });
        #[cfg(not(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32"))))]
        let publication_index = publication.map(|handle| {
            let index = wait_count;
            waits[index] = wait_item(handle);
            wait_count += 1;
            index
        });
        #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
        let wait_deadline = plan
            .deadline()
            .map_or(DW_DEADLINE_INFINITE, deepwyrm_syscall::DwDeadline);
        #[cfg(not(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32"))))]
        let wait_deadline = DW_DEADLINE_INFINITE;
        let observed = wait_many(&waits[..wait_count], wait_deadline).map_err(|_error| {
            #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
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
        #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
        if let Some(deadline) = connector_cleanup_deadline
            && !cleanup_deadline_live(monotonic_active_now().map_err(|_| failure(277))?, deadline)
        {
            return Err(failure(278));
        }
        #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
        if Some(index) == witness_index {
            observe_production_client_release(
                &mut production_witness,
                connector_broker.as_mut().ok_or(failure(279))?,
                observed.observed,
            )?;
            update_production_cleanup(
                connector_broker.as_ref().ok_or(failure(280))?,
                &mut connector_cleanup_deadline,
            )?;
            maybe_send_waiting_for_registry(
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
            let input = match receive_controller(bootstrap, &mut resident) {
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
            #[cfg(any(
                feature = "dw1e3-selector31",
                feature = "wyr1d-selector32",
                feature = "wyr1e8-production"
            ))]
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
                    send_driver_retire(control, &mut resident)?;
                    e8_retire_requested = true;
                    continue;
                }
                #[cfg(feature = "wyr1e8-production")]
                ControllerInput::D5(_) => return Err(failure(313)),
                #[cfg(feature = "wyr1d-selector32")]
                ControllerInput::D5(D5ControllerMessage::RequestRetire(identity)) => {
                    let request = resident.active_driver_request().ok_or(failure(226))?;
                    let control = driver_control.ok_or(failure(227))?;
                    let broker = connector_broker.as_ref().ok_or(failure(228))?;
                    let current = published_driver(&resident, request)?;
                    if identity != current.d5_identity()
                        || broker.current() != Some(current)
                        || !matches!(
                            broker.slot(),
                            ConnectorSlot::Active { attach, .. } if attach.driver == current
                        )
                        || selector32_retire_requested.is_some()
                        || !selector32_drain.permits_retire(identity)
                    {
                        return Err(failure(229));
                    }
                    send_selector32_driver_retire(control, &resident)?;
                    selector32_retire_requested = Some(current);
                    continue;
                }
                #[cfg(feature = "wyr1d-selector32")]
                ControllerInput::D5(D5ControllerMessage::ClientReleased(identity)) => {
                    connector_broker
                        .as_mut()
                        .ok_or(failure(230))?
                        .selector32_certify_client_release(identity)
                        .map_err(|_| failure(231))?;
                    continue;
                }
                #[cfg(feature = "wyr1d-selector32")]
                ControllerInput::D5(D5ControllerMessage::RequestDrain(identity)) => {
                    let control = driver_control.ok_or(failure(263))?;
                    let broker = connector_broker.as_ref().ok_or(failure(264))?;
                    if selector32_retire_requested.is_some() {
                        return Err(failure(265));
                    }
                    selector32_drain
                        .request(identity, broker)
                        .map_err(|_| failure(266))?;
                    send_d5_controller(control, D5ControllerMessage::RequestDrain(identity))?;
                    continue;
                }
                #[cfg(feature = "wyr1d-selector32")]
                ControllerInput::D5(
                    D5ControllerMessage::DriverReady(_) | D5ControllerMessage::TxDrained(_),
                ) => {
                    return Err(failure(232));
                }
                #[cfg(feature = "dw1e3-selector31")]
                ControllerInput::Dw1e3(config) => {
                    if config.nonce != dw1e3_build_nonce().map_err(|_| failure(164))?
                        || connector_broker.is_some()
                        || !resident.driver_ready()
                    {
                        return Err(failure(164));
                    }
                    let request = resident.active_driver_request().ok_or(failure(165))?;
                    let (attach, stream) = resident
                        .reserve_d3_connector_correlations(request)
                        .map_err(|_| failure(166))?;
                    let current = PublishedDriver {
                        publication_generation: config.publication_generation,
                        control: ControlIdentityV1_1 {
                            role_id: request.role_id,
                            bundle_generation: resident.bundle_generation().ok_or(failure(167))?,
                            attempt_generation: request.attempt_generation,
                            endpoint: request.endpoint,
                            transaction_id: request.transaction_id,
                        },
                    };
                    connector_broker = Some(
                        ConnectorBroker::new(Some(current), attach, stream)
                            .map_err(|_| failure(168))?,
                    );
                    let ready = DevmgrReady {
                        nonce: config.nonce,
                        publication_generation: config.publication_generation,
                    };
                    let mut ready_bytes = [0; DEVMGR_CONFIG_BYTES];
                    encode_devmgr_ready(ready, &mut ready_bytes).map_err(|_| failure(209))?;
                    send_channel(bootstrap, &ready_bytes, &[]).map_err(|_| failure(210))?;
                    continue;
                }
                #[cfg(feature = "dw1e3-selector31")]
                ControllerInput::Dw1e3Binding(binding) => {
                    let request = resident.active_driver_request().ok_or(failure(211))?;
                    let control = driver_control.ok_or(failure(212))?;
                    let broker = connector_broker.as_ref().ok_or(failure(213))?;
                    if binding.nonce != dw1e3_build_nonce().map_err(|_| failure(213))?
                        || binding.attempt_generation != request.attempt_generation.0
                        || selector_binding.is_some()
                        || broker.current().is_none()
                    {
                        return Err(failure(213));
                    }
                    let mut bytes = [0u8; TRANSPORT_EMPTY_FACT_BYTES];
                    encode_challenge_binding(binding, &mut bytes).map_err(|_| failure(214))?;
                    send_channel(control, &bytes, &[]).map_err(|_| failure(215))?;
                    selector_binding = Some(binding);
                    selector_binding_ready = false;
                    continue;
                }
                #[cfg(feature = "dw1e3-selector31")]
                ControllerInput::Dw1e3DriverCommand(binding, message_type) => {
                    let request = resident.active_driver_request().ok_or(failure(218))?;
                    let control = driver_control.ok_or(failure(219))?;
                    if binding.nonce != dw1e3_build_nonce().map_err(|_| failure(220))?
                        || binding.attempt_generation != request.attempt_generation.0
                        || selector_binding != Some(binding)
                        || !selector_binding_ready
                    {
                        return Err(failure(220));
                    }
                    let broker = connector_broker.as_mut().ok_or(failure(220))?;
                    let current = broker.current().ok_or(failure(220))?;
                    if current.control.attempt_generation != request.attempt_generation
                        || current.publication_generation != binding.publication_generation
                    {
                        return Err(failure(220));
                    }
                    if message_type == 7 {
                        broker
                            .selector_finalize_client_release(current, binding.stream_generation)
                            .map_err(|_| failure(221))?;
                        selector_retiring_driver = Some(current);
                    } else if message_type != 6 {
                        return Err(failure(221));
                    }
                    let mut bytes = [0u8; TRANSPORT_EMPTY_FACT_BYTES];
                    match message_type {
                        6 => wyrmroot_dw1e3_com2_test::encode_begin_retire(binding, &mut bytes),
                        7 => wyrmroot_dw1e3_com2_test::encode_finalize_retire(binding, &mut bytes),
                        _ => return Err(failure(221)),
                    }
                    .map_err(|_| failure(221))?;
                    send_channel(control, &bytes, &[]).map_err(|_| failure(222))?;
                    continue;
                }
                ControllerInput::Controller(received) => received,
            };
            #[cfg(not(any(
                feature = "dw1e3-selector31",
                feature = "wyr1d-selector32",
                feature = "wyr1e8-production"
            )))]
            let (replacement, action) = input;
            if let Some(replacement) = replacement {
                if let Some(old) = publication.replace(replacement) {
                    let _ = close_handle(replacement);
                    let _ = close_handle(old);
                    #[cfg(feature = "wyr1c5-production")]
                    close_optional(device_resource.take());
                    let _ = close_handle(bootstrap);
                    return Err(failure(21));
                }
                #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
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
            if let Err(code) = send_publication_acknowledgement(bootstrap, &resident) {
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
                #[cfg(feature = "wyr1d-selector32")]
                selector32_driver_ready(bootstrap, &mut resident, &mut connector_broker)?;
                #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
                activate_connector_broker(&mut resident, &mut connector_broker)?;
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
                #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
                activate_connector_broker(&mut resident, &mut connector_broker)?;
            }
            continue;
        }

        if Some(index) == driver_index {
            let control = driver_control.take().ok_or(failure(39))?;
            #[cfg(feature = "dw1e3-selector31")]
            if observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 && connector_broker.is_some() {
                service_selector31_driver_control(
                    control,
                    bootstrap,
                    connector_broker.as_mut().ok_or(failure(169))?,
                    selector_binding,
                    &mut selector_binding_ready,
                )?;
                driver_control = Some(control);
                continue;
            }
            #[cfg(feature = "wyr1d-selector32")]
            if observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 && connector_broker.is_some() {
                service_selector32_driver_control(
                    control,
                    bootstrap,
                    connector_broker.as_mut().ok_or(failure(252))?,
                    &mut selector32_drain,
                )?;
                driver_control = Some(control);
                continue;
            }
            #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
            if observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 && connector_broker.is_some() {
                service_production_driver_control(
                    control,
                    connector_broker.as_mut().ok_or(failure(271))?,
                )?;
                update_production_cleanup(
                    connector_broker.as_ref().ok_or(failure(288))?,
                    &mut connector_cleanup_deadline,
                )?;
                maybe_send_waiting_for_registry(
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
            #[cfg(any(feature = "wyr1c6-production", feature = "dw1e3-selector31"))]
            if observed.observed.0 & (DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0) != 0 {
                let request = resident.active_driver_request().ok_or(failure(40))?;
                #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
                let production_retiring_driver = published_driver(&resident, request)?;
                observe_driver_failure(
                    control,
                    request,
                    &mut resident,
                    observed.observed.0 & DW_SIGNAL_READABLE.0 != 0,
                    observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0,
                    e8_retire_requested,
                )?;
                #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
                {
                    let broker = connector_broker.as_mut().ok_or(failure(294))?;
                    if broker.current() != Some(production_retiring_driver)
                        || broker.retire_current().is_some()
                    {
                        return Err(failure(295));
                    }
                    update_production_cleanup(broker, &mut connector_cleanup_deadline)?;
                }
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
                #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
                {
                    let broker = connector_broker.as_mut().ok_or(failure(296))?;
                    if broker
                        .driver_attempt_reaped(production_retiring_driver)
                        .map_err(|_| failure(297))?
                        .is_some()
                    {
                        return Err(failure(298));
                    }
                    update_production_cleanup(broker, &mut connector_cleanup_deadline)?;
                    await_production_witness_release(
                        &mut production_witness,
                        broker,
                        &mut connector_cleanup_deadline,
                    )?;
                    if !matches!(broker.slot(), ConnectorSlot::Empty) {
                        return Err(failure(299));
                    }
                }
                #[cfg(feature = "dw1e3-selector31")]
                {
                    // The controller's type-7 certificate released the
                    // external client endpoint before FinalizeRetire.  The
                    // exact DriverReaped reply now proves the moved driver
                    // endpoint is gone; only an Empty broker may admit U2.
                    let reaped = selector_retiring_driver.take().ok_or(failure(224))?;
                    let broker = connector_broker.as_mut().ok_or(failure(224))?;
                    if reaped.control.attempt_generation != request.attempt_generation
                        || broker
                            .driver_attempt_reaped(reaped)
                            .map_err(|_| failure(225))?
                            .is_some()
                        || !matches!(broker.slot(), ConnectorSlot::Empty)
                    {
                        return Err(failure(225));
                    }
                    connector_broker = None;
                    selector_binding = None;
                    selector_binding_ready = false;
                }
                #[cfg(feature = "wyr1d-selector32")]
                {
                    let reaped = selector32_retire_requested.ok_or(failure(234))?;
                    let broker = connector_broker.as_mut().ok_or(failure(234))?;
                    if reaped.control.attempt_generation != request.attempt_generation
                        || broker
                            .driver_attempt_reaped(reaped)
                            .map_err(|_| failure(235))?
                            .is_some()
                        || !matches!(broker.slot(), ConnectorSlot::AwaitingClientRelease { .. })
                    {
                        return Err(failure(235));
                    }
                }
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
                #[cfg(feature = "wyr1e8-production")]
                {
                    // The exact retired attempt is now terminal and fully
                    // reaped.  A later replacement failure is ordinary unless
                    // init issues another exact RequestRetire.
                    e8_retire_requested = false;
                }
                #[cfg(feature = "wyr1d-selector32")]
                {
                    let release_deadline =
                        monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns)
                            .map_err(|_| failure(236))?;
                    wait_readable(bootstrap, release_deadline, 237)?;
                    let released = receive_controller(bootstrap, &mut resident)?;
                    let ControllerInput::D5(D5ControllerMessage::ClientReleased(identity)) =
                        released
                    else {
                        return Err(failure(238));
                    };
                    let broker = connector_broker.as_mut().ok_or(failure(239))?;
                    broker
                        .selector32_certify_client_release(identity)
                        .map_err(|_| failure(239))?;
                    if !matches!(broker.slot(), ConnectorSlot::Empty) {
                        return Err(failure(240));
                    }
                    selector32_retire_requested = None;
                }
                let rebind_deadline =
                    monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
                        .map_err(|_| failure(45))?;
                wait_readable(bootstrap, rebind_deadline, 46)?;
                let received = receive_controller(bootstrap, &mut resident)?;
                #[cfg(any(
                    feature = "dw1e3-selector31",
                    feature = "wyr1d-selector32",
                    feature = "wyr1e8-production"
                ))]
                let (replacement, action) = match received {
                    ControllerInput::Controller(received) => received,
                    #[cfg(feature = "wyr1e8-production")]
                    ControllerInput::D5(_) => return Err(failure(314)),
                    #[cfg(feature = "wyr1d-selector32")]
                    ControllerInput::D5(_) => return Err(failure(241)),
                    #[cfg(feature = "dw1e3-selector31")]
                    ControllerInput::Dw1e3(_) => return Err(failure(173)),
                    #[cfg(feature = "dw1e3-selector31")]
                    ControllerInput::Dw1e3Binding(_) => return Err(failure(217)),
                    #[cfg(feature = "dw1e3-selector31")]
                    ControllerInput::Dw1e3DriverCommand(_, _) => return Err(failure(223)),
                };
                #[cfg(not(any(
                    feature = "dw1e3-selector31",
                    feature = "wyr1d-selector32",
                    feature = "wyr1e8-production"
                )))]
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
                let acknowledged = send_publication_acknowledgement(bootstrap, &resident);
                if let Err(code) = acknowledged {
                    close_optional(device_resource.take());
                    close_optional(publication.take());
                    let _ = close_handle(bootstrap);
                    return Err(code);
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
                #[cfg(feature = "wyr1d-selector32")]
                selector32_driver_ready(bootstrap, &mut resident, &mut connector_broker)?;
                #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
                activate_connector_broker(&mut resident, &mut connector_broker)?;
                #[cfg(feature = "wyr1c6-selector29")]
                if resident.active_driver_request().is_some_and(|request| {
                    request.attempt_generation.0
                        > wyrmroot_device_proto::SELECTOR29_FAILURE_ATTEMPT_GENERATION
                }) {
                    let replacement = resident.active_driver_request().ok_or(failure(153))?;
                    probe_malformed_resource_mapping(launched, parent, replacement, &resident)?;
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
        #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
        let service_offer = match classify_production_publication(
            observed.observed.0 & DW_SIGNAL_READABLE.0 != 0,
            observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0,
        ) {
            ProductionPublicationEvent::Offer => true,
            ProductionPublicationEvent::Retire => false,
            ProductionPublicationEvent::Malformed => return Err(failure(312)),
        };
        #[cfg(not(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32"))))]
        let service_offer = observed.observed.0 & DW_SIGNAL_READABLE.0 != 0;
        if service_offer {
            #[cfg(any(
                feature = "dw1e3-selector31",
                feature = "wyr1d-selector32",
                feature = "wyr1e-production"
            ))]
            {
                let broker = connector_broker.as_mut().ok_or(failure(170))?;
                let control = driver_control.ok_or(failure(171))?;
                service_connector_offer(
                    publication.ok_or(failure(172))?,
                    control,
                    &resident,
                    broker,
                    #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
                    &mut production_witness,
                )?;
                continue;
            }
            #[cfg(not(any(
                feature = "dw1e3-selector31",
                feature = "wyr1d-selector32",
                feature = "wyr1e-production"
            )))]
            {
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
        }
        // Registry replacement closes only the old publication binding.  The
        // coordinator generation remains resident; a later WRCS rebind moves
        // one exact child Channel over the still-open bootstrap relationship.
        let old = publication.take().ok_or(failure(24))?;
        #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
        {
            let broker = connector_broker.as_mut().ok_or(failure(290))?;
            if broker.retire_current().is_some() {
                return Err(failure(291));
            }
            update_production_cleanup(broker, &mut connector_cleanup_deadline)?;
            waiting_registry_status_sent = false;
        }
        close_handle(old).map_err(|_| failure(25))?;
        resident
            .publication_peer_closed()
            .map_err(|_| failure(26))?;
        #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
        {
            maybe_send_waiting_for_registry(
                bootstrap,
                &resident,
                publication,
                connector_broker.as_ref().ok_or(failure(292))?,
                &mut waiting_registry_status_sent,
            )?;
            continue;
        }
        #[cfg(not(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32"))))]
        send_resident_status(
            bootstrap,
            &resident,
            StatusCode::OperationalWaitingForRegistry,
        )?;
    }
}

#[cfg(any(
    feature = "dw1e3-selector31",
    feature = "wyr1d-selector32",
    feature = "wyr1e8-production"
))]
enum ControllerInput {
    Controller((Option<DwHandle>, ControllerAction)),
    #[cfg(any(feature = "wyr1d-selector32", feature = "wyr1e8-production"))]
    D5(D5ControllerMessage),
    #[cfg(feature = "dw1e3-selector31")]
    Dw1e3(DevmgrConfig),
    #[cfg(feature = "dw1e3-selector31")]
    Dw1e3Binding(ChallengeBinding),
    #[cfg(feature = "dw1e3-selector31")]
    Dw1e3DriverCommand(ChallengeBinding, u16),
}

#[cfg(not(any(
    feature = "dw1e3-selector31",
    feature = "wyr1d-selector32",
    feature = "wyr1e8-production"
)))]
type ControllerInput = (Option<DwHandle>, ControllerAction);

fn receive_controller(
    bootstrap: DwHandle,
    resident: &mut wyrmroot_devmgr::ResidentController,
) -> Result<ControllerInput, u32> {
    #[cfg(feature = "dw1e3-selector31")]
    let mut bytes = [0u8; D3_DEVICE_STAGE_BYTES];
    #[cfg(all(
        not(feature = "dw1e3-selector31"),
        any(feature = "wyr1d-selector32", feature = "wyr1e8-production")
    ))]
    let mut bytes = [0u8; D5_CONTROLLER_BYTES];
    #[cfg(all(
        not(feature = "dw1e3-selector31"),
        not(feature = "wyr1d-selector32"),
        not(feature = "wyr1e8-production"),
        feature = "wyr1e-production"
    ))]
    let mut bytes = [0u8; wyrmroot_device_proto::controller_v1_1::RECORD_BYTES];
    #[cfg(not(any(
        feature = "dw1e3-selector31",
        feature = "wyr1d-selector32",
        feature = "wyr1e-production"
    )))]
    let mut bytes = [0u8; INSTALL_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(bootstrap, &mut bytes, &mut handles).map_err(|_| failure(27))?;
    if counts.bytes > bytes.len() || counts.handles > handles.len() {
        close_received(&handles, counts.handles);
        return Err(failure(28));
    }
    #[cfg(feature = "dw1e3-selector31")]
    if counts.bytes == DEVMGR_CONFIG_BYTES
        && bytes[..4] == wyrmroot_dw1e3_com2_test::DEVMGR_CONFIG_MAGIC
    {
        if counts.handles != 0 {
            close_received(&handles, counts.handles);
            return Err(failure(163));
        }
        let config = parse_devmgr_config(&bytes[..counts.bytes]).map_err(|_| failure(163))?;
        return Ok(ControllerInput::Dw1e3(config));
    }
    #[cfg(feature = "dw1e3-selector31")]
    if counts.bytes == TRANSPORT_EMPTY_FACT_BYTES
        && bytes[..4] == wyrmroot_dw1e3_com2_test::DEVMGR_CONFIG_MAGIC
    {
        if counts.handles != 0 {
            close_received(&handles, counts.handles);
            return Err(failure(216));
        }
        return match u16::from_le_bytes([bytes[6], bytes[7]]) {
            4 => parse_challenge_binding(&bytes[..counts.bytes])
                .map(ControllerInput::Dw1e3Binding)
                .map_err(|_| failure(216)),
            6 => parse_begin_retire(&bytes[..counts.bytes])
                .map(|binding| ControllerInput::Dw1e3DriverCommand(binding, 6))
                .map_err(|_| failure(216)),
            7 => parse_finalize_retire(&bytes[..counts.bytes])
                .map(|binding| ControllerInput::Dw1e3DriverCommand(binding, 7))
                .map_err(|_| failure(216)),
            _ => Err(failure(216)),
        };
    }
    #[cfg(any(feature = "wyr1d-selector32", feature = "wyr1e8-production"))]
    if counts.bytes == D5_CONTROLLER_BYTES
        && bytes[..4] == wyrmroot_device_proto::d5_controller::MAGIC
    {
        if counts.handles != 0 {
            close_received(&handles, counts.handles);
            return Err(failure(233));
        }
        return parse_d5_controller(&bytes[..counts.bytes])
            .map(ControllerInput::D5)
            .map_err(|_| failure(233));
    }
    #[cfg(any(feature = "wyr1d-selector32", feature = "wyr1e-production"))]
    let publication = match wyrmroot_device_proto::controller_v1_1::parse(&bytes[..counts.bytes]) {
        Ok(publication) => publication,
        Err(_) => {
            close_received(&handles, counts.handles);
            return Err(failure(29));
        }
    };
    #[cfg(any(feature = "wyr1d-selector32", feature = "wyr1e-production"))]
    let message = publication.controller;
    #[cfg(not(any(feature = "wyr1d-selector32", feature = "wyr1e-production")))]
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
    #[cfg(any(feature = "wyr1d-selector32", feature = "wyr1e-production"))]
    let accepted = resident.accept_publication(publication, counts.handles as u32);
    #[cfg(not(any(feature = "wyr1d-selector32", feature = "wyr1e-production")))]
    let accepted = resident.accept(message, counts.handles as u32);
    let action = match accepted {
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
    #[cfg(any(
        feature = "dw1e3-selector31",
        feature = "wyr1d-selector32",
        feature = "wyr1e8-production"
    ))]
    return Ok(ControllerInput::Controller((replacement, action)));
    #[cfg(not(any(
        feature = "dw1e3-selector31",
        feature = "wyr1d-selector32",
        feature = "wyr1e8-production"
    )))]
    Ok((replacement, action))
}

#[cfg(any(feature = "wyr1d-selector32", feature = "wyr1e-production"))]
fn published_driver(
    resident: &wyrmroot_devmgr::ResidentController,
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

#[cfg(feature = "wyr1d-selector32")]
fn selector32_driver_ready(
    bootstrap: DwHandle,
    resident: &mut wyrmroot_devmgr::ResidentController,
    broker: &mut Option<ConnectorBroker>,
) -> Result<(), u32> {
    let current = activate_connector_broker(resident, broker)?;
    send_d5_controller(
        bootstrap,
        D5ControllerMessage::DriverReady(current.d5_identity()),
    )
}

#[cfg(any(feature = "wyr1d-selector32", feature = "wyr1e-production"))]
fn activate_connector_broker(
    resident: &mut wyrmroot_devmgr::ResidentController,
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

#[cfg(feature = "wyr1d-selector32")]
fn send_d5_controller(bootstrap: DwHandle, message: D5ControllerMessage) -> Result<(), u32> {
    let mut bytes = [0u8; D5_CONTROLLER_BYTES];
    encode_d5_controller(message, &mut bytes).map_err(|_| failure(250))?;
    send_channel(bootstrap, &bytes, &[]).map_err(|_| failure(251))
}

#[cfg(feature = "wyr1d-selector32")]
fn send_selector32_driver_retire(
    control: DwHandle,
    resident: &wyrmroot_devmgr::ResidentController,
) -> Result<(), u32> {
    let request = resident.active_driver_request().ok_or(failure(257))?;
    // D3 uses the exact READY transaction reserved after launch,
    // device-stage, and interrupt-stage correlations: launch transaction + 3.
    // The resident remains Published until peer-close observation commits the
    // ordinary driver-failure cleanup transition.
    let ready_transaction = request.transaction_id.checked_add(3).ok_or(failure(260))?;
    let message = wyrmroot_device_proto::control_v1_1::ControlMessageV1_1::Retire {
        identity: ControlIdentityV1_1 {
            role_id: request.role_id,
            bundle_generation: resident.bundle_generation().ok_or(failure(258))?,
            attempt_generation: request.attempt_generation,
            endpoint: request.endpoint,
            transaction_id: ready_transaction,
        },
    };
    let mut bytes = [0u8; wyrmroot_device_proto::control_v1_1::RETIRE_BYTES];
    encode_control_v1_1(message, &mut bytes).map_err(|_| failure(261))?;
    send_channel(control, &bytes, &[]).map_err(|_| failure(262))
}

#[cfg(any(
    feature = "dw1e3-selector31",
    feature = "wyr1d-selector32",
    feature = "wyr1e-production"
))]
fn service_connector_offer(
    publication: DwHandle,
    driver_control: DwHandle,
    resident: &wyrmroot_devmgr::ResidentController,
    broker: &mut ConnectorBroker,
    #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
    witness: &mut Option<ProductionClientWitness>,
) -> Result<(), u32> {
    let mut offer_bytes = [0u8; 256];
    let mut offer_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(publication, &mut offer_bytes, &mut offer_handles)
        .map_err(|_| failure(174))?;
    if counts.bytes > offer_bytes.len() || counts.handles != 1 {
        close_received(&offer_handles, counts.handles);
        return Err(failure(175));
    }
    let offered = offer_handles[0];
    if offered.handle.0 == 0
        || offered.object_type != DW_OBJECT_TYPE_CHANNEL
        || offered.rights != CHILD_CHANNEL_RIGHTS
        || offered.reserved0 != 0
        || offered.reserved != [0; 2]
        || validate_fresh(offered.handle, DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS).is_err()
    {
        close_received(&offer_handles, 1);
        return Err(failure(176));
    }
    let offer = match parse_registry(&offer_bytes[..counts.bytes], counts.handles) {
        Ok(offer) => offer,
        Err(_) => {
            close_received(&offer_handles, 1);
            return Err(failure(177));
        }
    };
    let binding = resident.active_binding().ok_or(failure(178))?;
    let policy = ConnectorBroker::publication_policy();
    let RegistryMessage::ConnectOffer(lookup) = offer.message else {
        close_received(&offer_handles, 1);
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
        close_received(&offer_handles, 1);
        return Err(failure(180));
    }
    let direct = offer_handles[0].handle;
    let deadline = monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .map_err(|_| failure(181))?;
    wait_readable(direct, deadline, 182)?;
    let mut request_bytes = [0u8; CONNECTOR_BYTES];
    let mut request_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(direct, &mut request_bytes, &mut request_handles)
        .map_err(|_| failure(183))?;
    if counts.bytes != request_bytes.len() || counts.handles != 0 {
        close_received(&request_handles, counts.handles);
        let _ = close_handle(direct);
        return Err(failure(184));
    }
    let request = match parse_connector(&request_bytes) {
        Ok(request @ ConnectorMessage::ConnectStream { .. }) => request,
        _ => {
            let _ = close_handle(direct);
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
                let _ = send_channel(direct, &bytes, &[]);
            }
            close_handle(direct).map_err(|_| failure(186))?;
            encoded.map_err(|_| failure(186))?;
            return Ok(());
        }
    };
    let ConnectorAction::AllocatePair {
        attach,
        driver_message,
    } = action
    else {
        let _ = close_handle(direct);
        return Err(failure(187));
    };
    #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
    if witness.is_some() {
        let _ = broker.attach_send_failed(attach);
        let _ = close_handle(direct);
        return Err(failure(276));
    }
    let (client_endpoint, driver_endpoint) =
        create_channel(STREAM_BROAD_RIGHTS).map_err(|_| failure(188))?;
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
    if send_channel(driver_control, &driver_bytes[..size], &[transfer]).is_err() {
        let _ = broker.attach_send_failed(attach);
        let _ = close_handle(driver_endpoint);
        let _ = close_handle(client_endpoint);
        let _ = close_handle(direct);
        return Err(failure(190));
    }
    broker
        .driver_endpoint_moved(attach)
        .map_err(|_| failure(191))?;
    wait_readable(driver_control, deadline, 192)?;
    let mut ready_bytes = [0u8; D3_DEVICE_STAGE_BYTES];
    let mut ready_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(driver_control, &mut ready_bytes, &mut ready_handles)
        .map_err(|_| failure(193))?;
    if counts.bytes > ready_bytes.len() || counts.handles != 0 {
        close_received(&ready_handles, counts.handles);
        let _ = close_handle(client_endpoint);
        let _ = close_handle(direct);
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
    if send_channel(direct, &response_bytes, &[transfer]).is_err() {
        let _ = broker.connected_send_failed();
        let _ = close_handle(client_endpoint);
        let _ = close_handle(direct);
        return Err(failure(199));
    }
    broker.client_endpoint_moved().map_err(|_| failure(200))?;
    #[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
    {
        *witness = Some(ProductionClientWitness {
            handle: direct,
            attach,
        });
        Ok(())
    }
    #[cfg(not(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32"))))]
    close_handle(direct).map_err(|_| failure(201))
}

#[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
fn observe_production_client_release(
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
        if let Ok(counts) = receive_channel(observed.handle, &mut bytes, &mut handles) {
            close_received(&handles, counts.handles);
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
    close_handle(observed.handle).map_err(|_| failure(285))?;
    *witness = None;
    Ok(())
}

#[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
fn update_production_cleanup(
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
            production_cleanup_deadline(monotonic_active_now().map_err(|_| failure(286))?)
                .map_err(|_| failure(287))?,
        );
    }
    Ok(())
}

#[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
fn maybe_send_waiting_for_registry(
    bootstrap: DwHandle,
    resident: &wyrmroot_devmgr::ResidentController,
    publication: Option<DwHandle>,
    broker: &ConnectorBroker,
    sent: &mut bool,
) -> Result<(), u32> {
    if publication.is_none() && matches!(broker.slot(), ConnectorSlot::Empty) && !*sent {
        send_resident_status(
            bootstrap,
            resident,
            StatusCode::OperationalWaitingForRegistry,
        )?;
        *sent = true;
    }
    Ok(())
}

#[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
fn await_production_witness_release(
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
    update_production_cleanup(broker, deadline)?;
    let absolute = (*deadline).ok_or(failure(301))?;
    if !cleanup_deadline_live(monotonic_active_now().map_err(|_| failure(302))?, absolute) {
        return Err(failure(303));
    }
    let result = wait_many(
        core::slice::from_ref(&wait_item(observed.handle)),
        deepwyrm_syscall::DwDeadline(absolute),
    )
    .map_err(|_| failure(304))?;
    if result.index != 0
        || !cleanup_deadline_live(monotonic_active_now().map_err(|_| failure(305))?, absolute)
    {
        return Err(failure(306));
    }
    observe_production_client_release(witness, broker, result.observed)?;
    update_production_cleanup(broker, deadline)
}

#[cfg(all(feature = "wyr1e-production", not(feature = "wyr1d-selector32")))]
fn service_production_driver_control(
    driver_control: DwHandle,
    broker: &mut ConnectorBroker,
) -> Result<(), u32> {
    let mut bytes = [0u8; D3_DEVICE_STAGE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts =
        receive_channel(driver_control, &mut bytes, &mut handles).map_err(|_| failure(272))?;
    if counts.bytes > bytes.len() || counts.handles != 0 {
        close_received(&handles, counts.handles);
        return Err(failure(273));
    }
    let message = parse_control_v1_1(&bytes[..counts.bytes]).map_err(|_| failure(274))?;
    broker.driver_detached(message).map_err(|_| failure(275))
}

#[cfg(feature = "dw1e3-selector31")]
fn service_selector31_driver_control(
    driver_control: DwHandle,
    bootstrap: DwHandle,
    broker: &mut ConnectorBroker,
    binding: Option<ChallengeBinding>,
    binding_ready: &mut bool,
) -> Result<(), u32> {
    // This endpoint multiplexes selector-private WDE3 facts and ordinary
    // 112-byte D3 control. Never size the receive buffer to WDE3: doing so
    // would truncate STREAM_DETACHED and lose connector custody.
    let mut bytes = [0u8; D3_DEVICE_STAGE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts =
        receive_channel(driver_control, &mut bytes, &mut handles).map_err(|_| failure(203))?;
    if counts.bytes > bytes.len() || counts.handles != 0 {
        close_received(&handles, counts.handles);
        return Err(failure(204));
    }
    if counts.bytes == TRANSPORT_EMPTY_FACT_BYTES
        && bytes[..4] == wyrmroot_dw1e3_com2_test::DEVMGR_CONFIG_MAGIC
        && u16::from_le_bytes([bytes[6], bytes[7]]) == 3
    {
        // The current exact driver-control endpoint is authenticated by the
        // outer resident loop. Parse for framing only, then relay the same
        // bytes: devmgr does not construct or reinterpret a TEMT fact.
        parse_transport_empty_fact(&bytes[..counts.bytes]).map_err(|_| failure(205))?;
        send_channel(bootstrap, &bytes[..counts.bytes], &[]).map_err(|_| failure(206))?;
        return Ok(());
    }
    if counts.bytes == TRANSPORT_EMPTY_FACT_BYTES
        && bytes[..4] == wyrmroot_dw1e3_com2_test::DEVMGR_CONFIG_MAGIC
        && u16::from_le_bytes([bytes[6], bytes[7]]) == 8
    {
        parse_retire_stage1_ready(&bytes[..counts.bytes]).map_err(|_| failure(209))?;
        send_channel(bootstrap, &bytes[..counts.bytes], &[]).map_err(|_| failure(210))?;
        return Ok(());
    }
    if counts.bytes == TRANSPORT_EMPTY_FACT_BYTES
        && bytes[..4] == wyrmroot_dw1e3_com2_test::DEVMGR_CONFIG_MAGIC
        && u16::from_le_bytes([bytes[6], bytes[7]]) == 5
    {
        let ready = parse_binding_ready(&bytes[..counts.bytes]).map_err(|_| failure(207))?;
        if binding != Some(ready) || *binding_ready {
            return Err(failure(207));
        }
        *binding_ready = true;
        send_channel(bootstrap, &bytes[..counts.bytes], &[]).map_err(|_| failure(208))?;
        return Ok(());
    }
    let attach = match broker.slot() {
        ConnectorSlot::Active { attach, .. } => attach,
        _ => return Err(failure(202)),
    };
    let message = parse_control_v1_1(&bytes[..counts.bytes]).map_err(|_| failure(205))?;
    broker
        .active_client_released(attach)
        .map_err(|_| failure(206))?;
    broker.driver_detached(message).map_err(|_| failure(207))?;
    if !matches!(broker.slot(), ConnectorSlot::Empty) {
        return Err(failure(208));
    }
    Ok(())
}

#[cfg(feature = "wyr1d-selector32")]
fn service_selector32_driver_control(
    driver_control: DwHandle,
    bootstrap: DwHandle,
    broker: &mut ConnectorBroker,
    drain: &mut wyrmroot_devmgr::d5_drain::DrainRelay,
) -> Result<(), u32> {
    let mut bytes = [0u8; D3_DEVICE_STAGE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts =
        receive_channel(driver_control, &mut bytes, &mut handles).map_err(|_| failure(253))?;
    if counts.bytes > bytes.len() || counts.handles != 0 {
        close_received(&handles, counts.handles);
        return Err(failure(254));
    }
    if counts.bytes == D5_CONTROLLER_BYTES && bytes[..4] == *b"WDR5" {
        let D5ControllerMessage::TxDrained(identity) =
            parse_d5_controller(&bytes[..counts.bytes]).map_err(|_| failure(267))?
        else {
            return Err(failure(268));
        };
        drain
            .validate_completion(identity, broker)
            .map_err(|_| failure(269))?;
        send_d5_controller(bootstrap, D5ControllerMessage::TxDrained(identity))?;
        drain.forwarded(identity).map_err(|_| failure(270))?;
        return Ok(());
    }
    let message = parse_control_v1_1(&bytes[..counts.bytes]).map_err(|_| failure(255))?;
    broker.driver_detached(message).map_err(|_| failure(256))
}

#[cfg(any(feature = "wyr1c6-production", feature = "dw1e3-selector31"))]
fn observe_driver_failure(
    control: DwHandle,
    request: wyrmroot_device_proto::DriverLaunchRequest,
    resident: &mut wyrmroot_devmgr::ResidentController,
    readable: bool,
    peer_closed: bool,
    intentional_retirement: bool,
) -> Result<(), u32> {
    if !readable {
        return record_driver_terminal(resident, request, intentional_retirement);
    }
    let mut bytes = [0u8; wyrmroot_device_proto::control::FAILURE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(control, &mut bytes, &mut handles).map_err(|_| failure(100))?;
    if counts.bytes != bytes.len() || counts.handles != 0 {
        close_received(&handles, counts.handles);
        if peer_closed && counts.bytes == 0 && counts.handles == 0 {
            return record_driver_terminal(resident, request, intentional_retirement);
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
    record_driver_terminal(resident, request, intentional_retirement)
}

#[cfg(any(feature = "wyr1c6-production", feature = "dw1e3-selector31"))]
fn record_driver_terminal(
    resident: &mut wyrmroot_devmgr::ResidentController,
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

#[cfg(any(feature = "wyr1c6-production", feature = "dw1e3-selector31"))]
fn retire_driver_publication(
    publication: DwHandle,
    request: wyrmroot_device_proto::DriverLaunchRequest,
    resident: &wyrmroot_devmgr::ResidentController,
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

#[cfg(any(feature = "wyr1c6-production", feature = "dw1e3-selector31"))]
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

#[cfg(any(feature = "wyr1c6-production", feature = "dw1e3-selector31"))]
fn send_driver_retired(
    bootstrap: DwHandle,
    request: wyrmroot_device_proto::DriverLaunchRequest,
) -> Result<(), u32> {
    let mut bytes = [0u8; wyrmroot_device_proto::driver_launch::DRIVER_RETIRED_BYTES];
    encode_driver_retired(request, &mut bytes).map_err(|_| failure(120))?;
    send_bootstrap_channel(bootstrap, &bytes, &[], 121)
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
    if send_bootstrap_channel(bootstrap, &bytes, core::slice::from_ref(&transfer), 48).is_err() {
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
    #[cfg(feature = "wyr1d-production")]
    return launch_driver_staged(bootstrap, publication, parent_resource, resident);
    #[cfg(not(feature = "wyr1d-production"))]
    return launch_driver_with_historical_bundle(bootstrap, publication, parent_resource, resident);
}

#[cfg(feature = "wyr1d-production")]
fn launch_driver_staged(
    bootstrap: DwHandle,
    publication: DwHandle,
    parent_resource: DwHandle,
    resident: &mut wyrmroot_devmgr::ResidentController,
) -> Result<DwHandle, u32> {
    struct OwnedHandle(DwHandle);

    impl OwnedHandle {
        const fn raw(&self) -> DwHandle {
            self.0
        }

        fn moved(&mut self) {
            self.0 = DW_HANDLE_INVALID;
        }

        fn into_raw(mut self) -> DwHandle {
            let raw = self.0;
            self.moved();
            raw
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if self.0 != DW_HANDLE_INVALID {
                let _ = close_handle(self.0);
            }
        }
    }

    let (retained_raw, child_raw) =
        create_channel(DIRECT_CONTROL_RIGHTS).map_err(|_| failure(57))?;
    let retained = OwnedHandle(retained_raw);
    let mut child = OwnedHandle(child_raw);
    if validate_fresh(
        retained.raw(),
        DW_OBJECT_TYPE_CHANNEL,
        DIRECT_CONTROL_RIGHTS,
    )
    .is_err()
        || validate_fresh(child.raw(), DW_OBJECT_TYPE_CHANNEL, DIRECT_CONTROL_RIGHTS).is_err()
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
    let deadline = monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .map_err(|_| failure(62))?;
    wait_readable(bootstrap, deadline, 63)?;
    let mut constructed = [0u8; LAUNCH_RESPONSE_BYTES];
    let mut constructed_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(bootstrap, &mut constructed, &mut constructed_handles)
        .map_err(|_| failure(64))?;
    if counts.bytes != constructed.len() || counts.handles != 0 {
        close_received(&constructed_handles, counts.handles);
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

    let reduced = OwnedHandle(
        duplicate_handle(parent_resource, DEVICE_RESOURCE_TRANSFER_RIGHTS)
            .map_err(|_| failure(69))?,
    );
    if validate_fresh(
        reduced.raw(),
        DW_OBJECT_TYPE_DEVICE_RESOURCE,
        DEVICE_RESOURCE_TRANSFER_RIGHTS,
    )
    .is_err()
    {
        return Err(failure(70));
    }
    let resource = device_resource_info(reduced.raw()).map_err(|_| failure(71))?;
    if resource.resource_id != wyrmroot_devmgr::COM2_RESOURCE_ID
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
    if send_channel(
        retained.raw(),
        &device_bytes,
        core::slice::from_ref(&transfer),
    )
    .is_err()
    {
        return Err(failure(74));
    }
    let mut reduced = reduced;
    reduced.moved();
    staging.device_stage_moved().map_err(|_| failure(75))?;
    wait_readable(retained.raw(), deadline, 76)?;
    let mut quiesced_bytes = [0; D3_DEVICE_QUIESCED_BYTES];
    let mut response_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(retained.raw(), &mut quiesced_bytes, &mut response_handles)
        .map_err(|_| failure(77))?;
    if counts.bytes != quiesced_bytes.len() || counts.handles != 0 {
        close_received(&response_handles, counts.handles);
        return Err(failure(78));
    }
    let quiesced = parse_control_v1_1(&quiesced_bytes).map_err(|_| failure(79))?;
    staging
        .accept_device_quiesced(quiesced)
        .map_err(|_| failure(80))?;

    // Creating the route-committing Interrupt is deliberately after the exact
    // DEVICE_QUIESCED reply above.
    let interrupt = OwnedHandle(
        create_interrupt(parent_resource, INTERRUPT_CUSTODY_RIGHTS).map_err(|_| failure(81))?,
    );
    if validate_fresh(
        interrupt.raw(),
        DW_OBJECT_TYPE_INTERRUPT,
        INTERRUPT_CUSTODY_RIGHTS,
    )
    .is_err()
    {
        return Err(failure(82));
    }
    let interrupt_facts = interrupt_info(interrupt.raw()).map_err(|_| failure(83))?;
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
    if send_channel(
        retained.raw(),
        &interrupt_bytes,
        core::slice::from_ref(&transfer),
    )
    .is_err()
    {
        return Err(failure(88));
    }
    let mut interrupt = interrupt;
    interrupt.moved();
    staging.interrupt_stage_moved().map_err(|_| failure(89))?;
    resident.bundle_transferred().map_err(|_| failure(90))?;
    wait_readable(retained.raw(), deadline, 91)?;
    let mut ready_bytes = [0; D3_READY_BYTES];
    let mut ready_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(retained.raw(), &mut ready_bytes, &mut ready_handles)
        .map_err(|_| failure(92))?;
    if counts.bytes != ready_bytes.len() || counts.handles != 0 {
        close_received(&ready_handles, counts.handles);
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
    if let Err(code) = publish_driver(publication, request, resident) {
        return Err(code);
    }
    Ok(retained.into_raw())
}

#[cfg(all(feature = "wyr1c5-production", not(feature = "wyr1d-production")))]
fn launch_driver_with_historical_bundle(
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
        requested_rights: CHILD_CHANNEL_TRANSFER_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if send_bootstrap_channel(
        bootstrap,
        &launch,
        core::slice::from_ref(&child_transfer),
        61,
    )
    .is_err()
    {
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

    let reduced = match duplicate_handle(parent_resource, DEVICE_RESOURCE_TRANSFER_RIGHTS) {
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
            DEVICE_RESOURCE_TRANSFER_RIGHTS,
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
                event: if request.attempt_generation.0
                    == wyrmroot_device_proto::SELECTOR29_FAILURE_ATTEMPT_GENERATION
                {
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
                event: if request.attempt_generation.0
                    == wyrmroot_device_proto::SELECTOR29_FAILURE_ATTEMPT_GENERATION
                {
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
                    event: if request.attempt_generation.0
                        == wyrmroot_device_proto::SELECTOR29_FAILURE_ATTEMPT_GENERATION
                    {
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

#[cfg(feature = "wyr1c6-selector29")]
fn probe_malformed_resource_mapping(
    control: DwHandle,
    parent_resource: DwHandle,
    request: wyrmroot_device_proto::DriverLaunchRequest,
    resident: &wyrmroot_devmgr::ResidentController,
) -> Result<(), u32> {
    let active_generation = resident.bundle_generation().ok_or(failure(154))?;
    let first_resource = duplicate_handle(parent_resource, DEVICE_RESOURCE_TRANSFER_RIGHTS)
        .map_err(|_| failure(156))?;
    // U2 already owns the lease's exclusive Interrupt binding. Exercise the
    // typed bundle mapping instead by placing a second reduced DeviceResource
    // in the Interrupt slot; the actor must reject it without disturbing U2.
    let second_resource = match duplicate_handle(parent_resource, DEVICE_RESOURCE_TRANSFER_RIGHTS) {
        Ok(handle) => handle,
        Err(_) => {
            let _ = close_handle(first_resource);
            return Err(failure(157));
        }
    };
    let message = ControlMessage::ResourceBundle {
        role_id: request.role_id,
        bundle_generation: active_generation,
        attempt_generation: request.attempt_generation,
        endpoint: request.endpoint,
        transaction_id: request.transaction_id,
    };
    let mut bytes = [0u8; RESOURCE_BUNDLE_BYTES];
    if encode_control(message, &mut bytes).is_err() {
        let _ = close_handle(second_resource);
        let _ = close_handle(first_resource);
        return Err(failure(158));
    }
    let transfers = [
        DwHandleTransferV1 {
            handle: first_resource,
            requested_rights: DEVICE_RESOURCE_DRIVER_RIGHTS,
            operation: DW_HANDLE_TRANSFER_MOVE,
            reserved0: 0,
            reserved: [0; 2],
        },
        DwHandleTransferV1 {
            handle: second_resource,
            requested_rights: DEVICE_RESOURCE_DRIVER_RIGHTS,
            operation: DW_HANDLE_TRANSFER_MOVE,
            reserved0: 0,
            reserved: [0; 2],
        },
    ];
    if send_channel(control, &bytes, &transfers).is_err() {
        let _ = close_handle(second_resource);
        let _ = close_handle(first_resource);
        return Err(failure(159));
    }
    let deadline = monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .map_err(|_| failure(160))?;
    wait_readable(control, deadline, 161)?;
    let mut response = [0u8; wyrmroot_device_proto::control::FAILURE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(control, &mut response, &mut handles).map_err(|_| failure(162))?;
    if counts.bytes != response.len() || counts.handles != 0 {
        close_received(&handles, counts.handles);
        return Err(failure(163));
    }
    let expected = ControlMessage::Failure {
        role_id: request.role_id,
        bundle_generation: active_generation,
        attempt_generation: request.attempt_generation,
        endpoint: request.endpoint,
        transaction_id: request.transaction_id,
        code: FailureCode::MalformedResource,
    };
    if parse_control(&response) != Ok(expected) {
        return Err(failure(164));
    }
    Ok(())
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

fn send_publication_acknowledgement(
    bootstrap: DwHandle,
    resident: &wyrmroot_devmgr::ResidentController,
) -> Result<(), u32> {
    let bytes = resident
        .publication_acknowledgement()
        .map_err(|error| match error {
            wyrmroot_devmgr::PublicationAcknowledgementError::Lifecycle(_) => failure(35),
            wyrmroot_devmgr::PublicationAcknowledgementError::Encoding(_) => failure(36),
        })?;
    send_bootstrap_channel(bootstrap, &bytes, &[], 37)
}

fn send_resident_status(
    bootstrap: DwHandle,
    resident: &wyrmroot_devmgr::ResidentController,
    status: StatusCode,
) -> Result<(), u32> {
    let message = resident.report(status).map_err(|_| failure(35))?;
    let mut bytes = [0u8; STATUS_BYTES];
    encode_controller(message, &mut bytes).map_err(|_| failure(36))?;
    send_bootstrap_channel(bootstrap, &bytes, &[], 37)
}

fn send_bootstrap_channel(
    bootstrap: DwHandle,
    bytes: &[u8],
    transfers: &[DwHandleTransferV1],
    stage: u32,
) -> Result<(), u32> {
    #[cfg(not(feature = "wyr1c6-selector29"))]
    return send_channel(bootstrap, bytes, transfers).map_err(|_| failure(stage));

    #[cfg(feature = "wyr1c6-selector29")]
    let deadline = monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .map_err(|_| failure(stage))?;
    #[cfg(feature = "wyr1c6-selector29")]
    for _ in 0..4 {
        match send_channel(bootstrap, bytes, transfers) {
            Ok(()) => return Ok(()),
            Err(NativeError::Status(status)) if status == DW_STATUS_WOULD_BLOCK => {
                let writable = DwWaitItemV1 {
                    handle: bootstrap,
                    signals: deepwyrm_syscall::DwSignals(
                        DW_SIGNAL_WRITABLE.0 | DW_SIGNAL_PEER_CLOSED.0,
                    ),
                };
                let observed = wait_many(core::slice::from_ref(&writable), deadline)
                    .map_err(|_| failure(stage))?;
                if observed.index != 0
                    || observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0
                    || observed.observed.0 & DW_SIGNAL_WRITABLE.0 == 0
                {
                    return Err(failure(stage));
                }
            }
            Err(_) => return Err(failure(stage)),
        }
    }
    #[cfg(feature = "wyr1c6-selector29")]
    Err(failure(stage))
}

#[cfg(feature = "wyr1c6-selector29")]
fn send_c6_fact(bootstrap: DwHandle, fact: C6Fact) -> Result<(), u32> {
    let mut bytes = [0u8; C6_FACT_BYTES];
    encode_c6_fact(fact, &mut bytes).map_err(|_| failure(127))?;
    send_bootstrap_channel(bootstrap, &bytes, &[], 128)
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

#[cfg(target_os = "wyrmroot")]
wyrmroot_runtime::native_entry!(crate::native_main);

#[cfg(target_os = "wyrmroot")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    panic_abort()
}

// This is a guest binary for `x86_64-unknown-wyrmroot`. A host build exists
// only so a workspace-wide `cargo test` can build the target at all: `_start`
// and a `#[panic_handler]` would each collide with the std that the host test
// profile links. Naming the freestanding entry keeps it, and everything it
// reaches, live for host type-checking; nothing here ever runs on the host.
#[cfg(not(target_os = "wyrmroot"))]
fn main() {
    let _: fn(StartupBlock<'_>) -> u32 = native_main;
}
