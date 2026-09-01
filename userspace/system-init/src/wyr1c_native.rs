//! Native WYR1-C resident device-coordinator ownership and construction.
//!
//! Historical C3 keeps its direct, hardware-free construction path. The C4
//! profile instead parents each devmgr generation under retained resource-
//! domain custody and delegates only its reduced claim authority.

use super::*;
use crate::wyr1b::{EndpointKind, RegistryTopology};
#[cfg(feature = "dw1e3-selector31")]
use crate::wyr1b_native::{InstalledPeer, launch_registry_client_actor};
use crate::wyr1b_native::{
    RegistryNativeAttempt, create_controller_channel_pair, establish_registry_topology,
    launch_registry_until_ready, poison_registry_generation, restart_topology_or_poison,
};
use deepwyrm_syscall::{DW_HANDLE_TRANSFER_MOVE, DW_OBJECT_TYPE_CHANNEL, DwHandleTransferV1};
#[cfg(feature = "dw1e3-selector31")]
use wyrmroot_device_proto::SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY;
#[cfg(not(feature = "dw1e3-selector31"))]
use wyrmroot_device_proto::SERIAL_CONSOLE_PUBLICATION_POLICY;
use wyrmroot_device_proto::coordinator::{
    RegistryEndpoint, RegistryEndpointGeneration, RegistryEndpointId, RegistryGeneration,
    SupervisorGeneration,
};
#[cfg(feature = "wyr1c6-selector29")]
use wyrmroot_device_proto::driver_launch::{C6_FACT_BYTES, C6Fact, parse_c6_fact};
#[cfg(any(feature = "wyr1c6-production", feature = "dw1e3-selector31"))]
use wyrmroot_device_proto::driver_launch::{encode_reaped, parse_driver_retired};
use wyrmroot_device_proto::{
    DriverLaunchRequest,
    controller::{
        ControllerMessage, StatusCode, encode as encode_controller, parse as parse_controller,
    },
    driver_launch::{
        DRIVER_RETIRED_BYTES, LAUNCH_REQUEST_BYTES, LAUNCH_RESPONSE_BYTES, encode_constructed,
        parse_request,
    },
    manifest::{COM2_ROLE_ID, ContentIdentity, Manifest as DeviceManifest},
};
#[cfg(any(test, not(feature = "wyr1c5-production")))]
use wyrmroot_loader::launch::CHILD_CHANNEL_RIGHTS;
#[cfg(feature = "wyr1c5-production")]
use wyrmroot_loader::launch::CHILD_CHANNEL_TRANSFER_RIGHTS;
#[cfg(test)]
use wyrmroot_loader::launch::DEVICE_MANIFEST_RIGHTS;
use wyrmroot_loader::{
    launch::{DEVICE_MANIFEST_TRANSFER_RIGHTS, LaunchProfile},
    process::{
        DeviceCoordinatorLoadRequest, DeviceCoordinatorResourceLoadRequest,
        DeviceDriverLoadRequest, load_device_coordinator_process,
        load_device_coordinator_resource_process, load_device_driver_process,
    },
};

#[cfg(feature = "wyr1c5-production")]
const DRIVER_CONTROL_INGRESS_RIGHTS: DwRights = CHILD_CHANNEL_TRANSFER_RIGHTS;
#[cfg(not(feature = "wyr1c5-production"))]
const DRIVER_CONTROL_INGRESS_RIGHTS: DwRights = CHILD_CHANNEL_RIGHTS;
#[cfg(feature = "dw1e3-selector31")]
use wyrmroot_dw1e3_com2_test::{
    CHALLENGE_BYTES as E3A_CHALLENGE_BYTES, CHALLENGE_GENERATION as E3A_CHALLENGE_GENERATION,
    CONTROL_BYTES as E3A_CONTROL_BYTES, ChallengeBinding,
    ControllerMessage as E3AControllerMessage, DevmgrConfig, DevmgrReady,
    RESPONSE_BYTES as E3A_RESPONSE_BYTES, TRANSPORT_EMPTY_FACT_BYTES, TransportEmptyFact,
    challenge as e3a_challenge, encode as encode_e3a_controller, encode_begin_retire,
    encode_challenge_binding, encode_devmgr_config as encode_e3a_devmgr_config,
    encode_finalize_retire, fnv1a64 as e3a_fnv1a64, parse as parse_e3a_controller,
    parse_binding_ready, parse_devmgr_ready, parse_retire_stage1_ready, parse_transport_empty_fact,
    response as e3a_response,
};
use wyrmroot_registry_proto::{
    Header as RegistryHeader, MessageType as RegistryMessageType, ProtocolVersion,
    encode_install_publication,
};

pub(crate) const MARKER_BYTES: &[u8] = b"WYR1-C1";
pub(crate) const MARKER_PATH: &str = "system/bootstrap/wyr1-c-gate-v1";
pub(crate) const DEVICE_MANIFEST_PATH: &str = "system/bootstrap/wyr1-c-device-manifest-v1";
const DEVMGR_PATH: &str = "system/devmgr";
const PUBLICATION_ID_BASE: u64 = 0xC1_0000;
const SERVICE_GENERATION_BASE: u64 = 0xC1_0800;
const PUBLICATION_TRANSACTION_BASE: u64 = 0xC1_1000;
#[cfg(feature = "dw1e3-selector31")]
const E3A_PROBE_PATH: &str = "test/dw1e3/com2-probe";
#[cfg(feature = "dw1e3-selector31")]
const E3A_PROBE_TRANSACTION_ID: u64 = 0xE3A0_0001;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PublicationCorrelation {
    publication_id: u64,
    service_generation: u64,
    transaction_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PublicationAllocator {
    next: PublicationCorrelation,
}

impl PublicationAllocator {
    const fn new() -> Self {
        Self {
            next: PublicationCorrelation {
                publication_id: PUBLICATION_ID_BASE + 1,
                service_generation: SERVICE_GENERATION_BASE + 1,
                transaction_id: PUBLICATION_TRANSACTION_BASE + 1,
            },
        }
    }

    fn issue(&mut self) -> Result<PublicationCorrelation, InitError> {
        let issued = self.next;
        self.next = PublicationCorrelation {
            publication_id: issued
                .publication_id
                .checked_add(1)
                .ok_or(InitError::Accounting)?,
            service_generation: issued
                .service_generation
                .checked_add(1)
                .ok_or(InitError::Accounting)?,
            transaction_id: issued
                .transaction_id
                .checked_add(1)
                .ok_or(InitError::Accounting)?,
        };
        Ok(issued)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DriverNativeAttempt {
    loaded: LoadedProcess,
    task_group: DwHandle,
    request: DriverLaunchRequest,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ResidentState {
    resource_domain: Option<ResourceDomainCustody>,
    registry: Option<RegistryNativeAttempt>,
    topology: RegistryTopology,
    devmgr: Option<ActiveNativeRole>,
    binding: Option<wyrmroot_device_proto::RegistryBinding>,
    publication_service_generation: u64,
    waiting_registry_observed: bool,
    publication_allocator: PublicationAllocator,
    last_controller_transaction: u64,
    next_controller_transaction: u64,
    driver: Option<DriverNativeAttempt>,
    last_reaped_driver: Option<DriverLaunchRequest>,
    #[cfg(feature = "dw1e3-selector31")]
    e3a_probe: Option<InstalledPeer>,
    #[cfg(feature = "dw1e3-selector31")]
    e3a_stream_generation: Option<u64>,
    #[cfg(feature = "dw1e3-selector31")]
    e3a_binding: Option<ChallengeBinding>,
    #[cfg(feature = "dw1e3-selector31")]
    e3a_response_committed: bool,
    #[cfg(feature = "dw1e3-selector31")]
    e3a_transport_empty: Option<TransportEmptyFact>,
    #[cfg(feature = "dw1e3-selector31")]
    e3a_begin_retire_sent: bool,
    #[cfg(feature = "dw1e3-selector31")]
    e3a_stage1_ready: bool,
    #[cfg(feature = "dw1e3-selector31")]
    e3a_peer_closed: bool,
    #[cfg(feature = "dw1e3-selector31")]
    e3a_finalize_retire_sent: bool,
    #[cfg(feature = "dw1e3-selector31")]
    e3a_next_challenge_generation: u64,
    #[cfg(feature = "dw1e3-selector31")]
    e3a_terminal_claimed: bool,
    #[cfg(feature = "dw1e3-selector31")]
    e3a_u2_probe_reaped_successfully: bool,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_gate_config: crate::wyr1c6_gate::GateConfig,
    #[cfg(feature = "wyr1c6-selector29")]
    pub(crate) c6_evidence: Option<crate::wyr1c6_gate::EvidenceLog>,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_d1_lease: Option<u64>,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_d1_supervisor: Option<u64>,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_d1_cleanup_complete: bool,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_d1_driver_failures: u64,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_d2_lease: Option<u64>,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_d2_supervisor: Option<u64>,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_d2_role: Option<u64>,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_u1_irq: Option<u64>,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_u1_attempt: Option<u64>,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_u1_endpoint: Option<u64>,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_p1_service_generation: u64,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_p1_registry_generation: u64,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_p1_endpoint_generation: u64,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_u2_irq: Option<u64>,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_u2_attempt: Option<u64>,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_u2_endpoint: Option<u64>,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_p2_service_generation: u64,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_p2_registry_generation: u64,
    #[cfg(feature = "wyr1c6-selector29")]
    c6_p2_endpoint_generation: u64,
    last_driver_attempt: u64,
    last_driver_session: u64,
    last_driver_endpoint: u64,
    last_driver_transaction: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DevmgrNativeAttempt {
    active: ActiveNativeRole,
    binding: wyrmroot_device_proto::RegistryBinding,
    publication_service_generation: u64,
    last_controller_transaction: u64,
    next_controller_transaction: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResidentPollEvent {
    DevmgrExited,
    DevmgrControlLost,
    DevmgrControlReadable,
    RegistryLost,
    DriverExited,
    #[cfg(feature = "dw1e3-selector31")]
    ProbeControlReadable,
    #[cfg(feature = "dw1e3-selector31")]
    ProbeControlLost,
    #[cfg(feature = "dw1e3-selector31")]
    ProbeExited,
}

fn classify_resident_poll(
    result: DwWaitResultV1,
    registry_present: bool,
    driver_present: bool,
    #[cfg(feature = "dw1e3-selector31")] probe_present: bool,
) -> Result<ResidentPollEvent, InitError> {
    let item_count = 2 + usize::from(registry_present) * 2 + usize::from(driver_present) + {
        #[cfg(feature = "dw1e3-selector31")]
        {
            usize::from(probe_present) * 2
        }
        #[cfg(not(feature = "dw1e3-selector31"))]
        {
            0
        }
    };
    if result.index >= item_count as u32 {
        return Err(InitError::Supervision);
    }
    match result.index {
        0 if result.observed.0 & DW_SIGNAL_EXITED.0 != 0 => Ok(ResidentPollEvent::DevmgrExited),
        1 if result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 => {
            Ok(ResidentPollEvent::DevmgrControlLost)
        }
        1 if result.observed.0 & DW_SIGNAL_READABLE.0 != 0 => {
            Ok(ResidentPollEvent::DevmgrControlReadable)
        }
        2 if registry_present && result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 => {
            Ok(ResidentPollEvent::RegistryLost)
        }
        3 if registry_present && result.observed.0 & DW_SIGNAL_EXITED.0 != 0 => {
            Ok(ResidentPollEvent::RegistryLost)
        }
        index
            if driver_present
                && index == 2 + u32::from(registry_present) * 2
                && result.observed.0 & DW_SIGNAL_EXITED.0 != 0 =>
        {
            Ok(ResidentPollEvent::DriverExited)
        }
        #[cfg(feature = "dw1e3-selector31")]
        index
            if probe_present
                && index == 2 + u32::from(registry_present) * 2 + u32::from(driver_present)
                && result.observed.0 & DW_SIGNAL_READABLE.0 != 0 =>
        {
            // A probe may write ResponseCommitted and close immediately. On
            // a combined READABLE|PEER_CLOSED wake, consume that queued,
            // exact message first; a fresh close wake then classifies the
            // post-response lifetime normally.
            Ok(ResidentPollEvent::ProbeControlReadable)
        }
        #[cfg(feature = "dw1e3-selector31")]
        index
            if probe_present
                && index == 2 + u32::from(registry_present) * 2 + u32::from(driver_present)
                && result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 =>
        {
            Ok(ResidentPollEvent::ProbeControlLost)
        }
        #[cfg(feature = "dw1e3-selector31")]
        index
            if probe_present
                && index == 3 + u32::from(registry_present) * 2 + u32::from(driver_present)
                && result.observed.0 & DW_SIGNAL_EXITED.0 != 0 =>
        {
            Ok(ResidentPollEvent::ProbeExited)
        }
        _ => Err(InitError::Supervision),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegistryRecoveryStep {
    Degraded,
    AwaitStatus,
    Restart,
}

const fn registry_recovery_step(
    exhausted: bool,
    status_already_consumed: bool,
) -> RegistryRecoveryStep {
    if exhausted {
        RegistryRecoveryStep::Degraded
    } else if status_already_consumed {
        RegistryRecoveryStep::Restart
    } else {
        RegistryRecoveryStep::AwaitStatus
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn activate_in_place<'a, S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    slot: &'a mut MaybeUninit<ResidentSystemInit>,
    authority: LoadAuthority,
    resource_domain: Option<ResourceDomainCustody>,
    parent_profile: LaunchProfile,
    bootstrap_channel: DwHandle,
    parent_transaction: u64,
    bootfs: &[u8],
) -> Result<&'a mut ResidentSystemInit, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
    if archive
        .lookup(MARKER_PATH.as_bytes())
        .map_err(map_lookup)?
        .data()
        != MARKER_BYTES
    {
        return Err(InitError::WrongManifestProfile);
    }
    let manifest_entry = archive
        .lookup(DEVICE_MANIFEST_PATH.as_bytes())
        .map_err(map_lookup)?;
    if manifest_entry.is_executable() {
        return Err(InitError::WrongManifestProfile);
    }
    let device_manifest = DeviceManifest::parse(manifest_entry.data())
        .map_err(|_| InitError::WrongManifestProfile)?;
    let (manifest, uart_identity) = crate::wyr1b_native::validate_retained_bootfs_c1(bootfs)?;
    #[cfg(feature = "wyr1c6-selector29")]
    let (c6_gate_config, c6_evidence) = {
        let entry = archive
            .lookup(crate::wyr1c6_gate::GATE_PATH.as_bytes())
            .map_err(map_lookup)?;
        let config =
            crate::wyr1c6_gate::parse_config(entry.data()).map_err(InitError::Wyr1C6GateConfig)?;
        let evidence = Some(
            crate::wyr1c6_gate::EvidenceLog::new(config.nonce)
                .map_err(InitError::Wyr1C6GateConfig)?,
        );
        (config, evidence)
    };
    validate_device_identity(device_manifest, uart_identity)?;
    let resident = slot.write(ResidentSystemInit {
        controller: manifest,
        authority,
        result: RecoveryResult::Degraded,
        active: [None; EARLY_ROLE_COUNT],
        evidence_finalized: false,
        last_tick_ns: 0,
        wyr1b: None,
        wyr1b_evidence: None,
        wyr1c: None,
    });
    resident.controller.become_operational()?;
    let mut ready = [0u8; HEADER_BYTES];
    let ready_len = encode_ready_for_profile(parent_profile, parent_transaction, &mut ready)
        .map_err(InitError::Launch)?;
    system
        .send_channel(bootstrap_channel, &ready[..ready_len])
        .map_err(InitError::Native)?;
    resident
        .controller
        .begin_registry(system.now().map_err(InitError::Native)?, 1, 0xC1_0000)?;
    let registry = launch_registry_until_ready(
        system,
        loader,
        waits,
        &mut resident.controller,
        authority,
        bootfs,
    )?
    .ok_or(InitError::WrongActivationOrder)?;
    let (registry, mut topology) =
        establish_registry_topology(system, waits, &mut resident.controller, registry)?;
    let mut publication_allocator = PublicationAllocator::new();
    let devmgr = match launch_devmgr(
        system,
        loader,
        waits,
        &mut resident.controller,
        authority,
        resource_domain,
        bootfs,
        registry,
        &mut topology,
        &mut publication_allocator,
        manifest_entry.data(),
    ) {
        Ok(devmgr) => devmgr,
        Err(error) => {
            let poison = poison_registry_generation(
                system,
                waits,
                &mut resident.controller,
                registry,
                false,
            );
            return Err(poison.err().unwrap_or(error));
        }
    };
    let state = ResidentState {
        resource_domain,
        registry: Some(registry),
        topology,
        devmgr: Some(devmgr.active),
        binding: Some(devmgr.binding),
        publication_service_generation: devmgr.publication_service_generation,
        waiting_registry_observed: false,
        publication_allocator,
        last_controller_transaction: devmgr.last_controller_transaction,
        next_controller_transaction: devmgr.next_controller_transaction,
        driver: None,
        last_reaped_driver: None,
        #[cfg(feature = "dw1e3-selector31")]
        e3a_probe: None,
        #[cfg(feature = "dw1e3-selector31")]
        e3a_stream_generation: None,
        #[cfg(feature = "dw1e3-selector31")]
        e3a_binding: None,
        #[cfg(feature = "dw1e3-selector31")]
        e3a_response_committed: false,
        #[cfg(feature = "dw1e3-selector31")]
        e3a_transport_empty: None,
        #[cfg(feature = "dw1e3-selector31")]
        e3a_begin_retire_sent: false,
        #[cfg(feature = "dw1e3-selector31")]
        e3a_stage1_ready: false,
        #[cfg(feature = "dw1e3-selector31")]
        e3a_peer_closed: false,
        #[cfg(feature = "dw1e3-selector31")]
        e3a_finalize_retire_sent: false,
        #[cfg(feature = "dw1e3-selector31")]
        e3a_next_challenge_generation: E3A_CHALLENGE_GENERATION,
        #[cfg(feature = "dw1e3-selector31")]
        e3a_terminal_claimed: false,
        #[cfg(feature = "dw1e3-selector31")]
        e3a_u2_probe_reaped_successfully: false,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_gate_config,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_evidence,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_d1_lease: None,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_d1_supervisor: None,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_d1_cleanup_complete: false,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_d1_driver_failures: 0,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_d2_lease: None,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_d2_supervisor: None,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_d2_role: None,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_u1_irq: None,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_u1_attempt: None,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_u1_endpoint: None,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_p1_service_generation: 0,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_p1_registry_generation: 0,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_p1_endpoint_generation: 0,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_u2_irq: None,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_u2_attempt: None,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_u2_endpoint: None,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_p2_service_generation: 0,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_p2_registry_generation: 0,
        #[cfg(feature = "wyr1c6-selector29")]
        c6_p2_endpoint_generation: 0,
        last_driver_attempt: 0,
        last_driver_session: 0,
        last_driver_endpoint: 0,
        last_driver_transaction: 0,
    };
    resident.active = [Some(registry.active), Some(devmgr.active)];
    resident.result = RecoveryResult::Recovered;
    resident.wyr1c = Some(state);
    Ok(resident)
}

fn validate_device_identity(
    manifest: DeviceManifest<'_>,
    uart_identity: [u8; 32],
) -> Result<(), InitError> {
    manifest
        .match_com2(ContentIdentity(uart_identity))
        .map(|_| ())
        .map_err(|_| InitError::WrongManifestProfile)
}

#[allow(clippy::too_many_arguments)]
fn launch_devmgr<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    controller: &mut SystemInit,
    authority: LoadAuthority,
    resource_domain: Option<ResourceDomainCustody>,
    bootfs: &[u8],
    registry: RegistryNativeAttempt,
    topology: &mut RegistryTopology,
    publication_allocator: &mut PublicationAllocator,
    manifest_bytes: &[u8],
) -> Result<DevmgrNativeAttempt, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let RestartState::Starting {
        generation,
        transaction_id,
        ..
    } = controller
        .role_state(RoleId::Devmgr)
        .ok_or(InitError::WrongActivationOrder)?
    else {
        return Err(InitError::WrongActivationOrder);
    };
    let grant = topology
        .issue(generation, EndpointKind::Publication)
        .map_err(InitError::Wyr1BModel)?;
    let publication = publication_allocator.issue()?;
    let binding = wyrmroot_device_proto::RegistryBinding {
        generation: RegistryGeneration(grant.registry_generation),
        endpoint: RegistryEndpoint {
            id: RegistryEndpointId(grant.endpoint_id),
            generation: RegistryEndpointGeneration(grant.endpoint_generation),
        },
    };
    let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
    let image = archive.lookup(DEVMGR_PATH.as_bytes()).map_err(map_lookup)?;
    let identity = controller.executable_identity(RoleId::Devmgr)?;
    if !image.is_executable() || wyrmroot_runtime::sha256::digest(image.data()) != identity {
        return Err(InitError::ArtifactIdentityMismatch(RoleId::Devmgr));
    }
    let (registry_endpoint, devmgr_endpoint) = create_controller_channel_pair(system)?;
    let manifest = match system
        .materialize_read_only_memory(
            authority.parent_root,
            manifest_bytes,
            DEVICE_MANIFEST_TRANSFER_RIGHTS,
        )
        .map_err(InitError::Native)
    {
        Ok(manifest) => manifest,
        Err(error) => {
            let cleanup_failed = system.close_handle(registry_endpoint).is_err()
                | system.close_handle(devmgr_endpoint).is_err();
            return Err(if cleanup_failed {
                InitError::Cleanup
            } else {
                error
            });
        }
    };
    let task_group_parent = resource_domain
        .map(ResourceDomainCustody::handle)
        .unwrap_or(authority.task_group);
    let task_group = match system
        .create_attempt_task_group(task_group_parent)
        .map_err(InitError::Native)
    {
        Ok(task_group) => task_group,
        Err(error) => {
            let cleanup_failed = system.close_handle(registry_endpoint).is_err()
                | system.close_handle(devmgr_endpoint).is_err()
                | system.close_handle(manifest).is_err();
            return Err(if cleanup_failed {
                InitError::Cleanup
            } else {
                error
            });
        }
    };
    let reservation = match controller.reserve_attempt(RoleId::Devmgr, generation, transaction_id) {
        Ok(reservation) => reservation,
        Err(error) => {
            let cleanup_failed = system.close_handle(registry_endpoint).is_err()
                | system.close_handle(devmgr_endpoint).is_err()
                | system.close_handle(manifest).is_err()
                | system.close_handle(task_group).is_err();
            return Err(if cleanup_failed {
                InitError::Cleanup
            } else {
                error
            });
        }
    };
    if let Err(error) = install_publication(
        system,
        registry.control_channel,
        grant,
        publication,
        registry_endpoint,
    ) {
        let cleanup_failed = system.close_handle(registry_endpoint).is_err()
            | system.close_handle(devmgr_endpoint).is_err()
            | system.close_handle(manifest).is_err()
            | system.close_handle(task_group).is_err()
            | controller.abort_reservation(reservation).is_err();
        return Err(if cleanup_failed {
            InitError::Cleanup
        } else {
            error
        });
    }
    let generation_authority = LoadAuthority {
        task_group,
        ..authority
    };
    let loaded_result = if let Some(custody) = resource_domain {
        let reduced = custody
            .devmgr_claim_authority(ResourceDomainMembership::DevmgrGenerationDescendant)
            .map_err(|_| InitError::WrongActivationOrder)?;
        load_device_coordinator_resource_process(
            loader,
            generation_authority,
            DeviceCoordinatorResourceLoadRequest {
                image: image.data(),
                display_path: DEVMGR_PATH,
                publication_endpoint: devmgr_endpoint,
                manifest,
                resource_domain: reduced.handle(),
                supervisor_generation: generation,
                transaction_id,
            },
        )
    } else {
        load_device_coordinator_process(
            loader,
            generation_authority,
            DeviceCoordinatorLoadRequest {
                image: image.data(),
                display_path: DEVMGR_PATH,
                publication_endpoint: devmgr_endpoint,
                manifest,
                supervisor_generation: generation,
                transaction_id,
            },
        )
    };
    let loaded = match loaded_result {
        Ok(loaded) => loaded,
        Err(failure) => {
            let mut cleanup_failed = system.close_handle(task_group).is_err()
                | controller.abort_reservation(reservation).is_err();
            if !failure.publication_endpoint_consumed {
                cleanup_failed |= system.close_handle(devmgr_endpoint).is_err();
            }
            if !failure.manifest_consumed {
                cleanup_failed |= system.close_handle(manifest).is_err();
            }
            return Err(if cleanup_failed {
                InitError::Cleanup
            } else {
                InitError::Loader(failure.error)
            });
        }
    };
    let resources = AttemptResources {
        role: RoleId::Devmgr,
        generation,
        transaction_id,
        executable_identity: identity,
        startup_profile: StartupProfile::DeviceCoordinator,
        task_group,
        process: loaded.process,
        launch_channel: loaded.launch_channel,
        mappings: 0,
        reservation,
    };
    if let Err(error) = controller.install_attempt(resources) {
        let cleanup_failed = cleanup_loaded(system, waits, loaded, task_group, true).is_err();
        return Err(if cleanup_failed {
            InitError::Cleanup
        } else {
            error
        });
    }
    let started = match system.now().map_err(InitError::Native) {
        Ok(value) => value,
        Err(error) => {
            return fail_loaded_devmgr(
                system,
                waits,
                controller,
                loaded,
                task_group,
                generation,
                transaction_id,
                error,
            );
        }
    };
    if let Err(error) =
        controller.child_started(RoleId::Devmgr, generation, transaction_id, started)
    {
        return fail_loaded_devmgr(
            system,
            waits,
            controller,
            loaded,
            task_group,
            generation,
            transaction_id,
            error,
        );
    }
    let deadline = started
        .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .ok_or(InitError::Accounting)?;
    let launch_profile = if resource_domain.is_some() {
        LaunchProfile::DeviceCoordinatorResourceDomain
    } else {
        LaunchProfile::DeviceCoordinator
    };
    if await_child_ready_profile_observed(
        waits,
        loaded.process,
        loaded.launch_channel,
        launch_profile,
        transaction_id,
        DwDeadline(deadline),
    )
    .is_err()
    {
        return fail_loaded_devmgr(
            system,
            waits,
            controller,
            loaded,
            task_group,
            generation,
            transaction_id,
            InitError::Supervision,
        );
    }
    if let Err(error) = controller.ready(
        RoleId::Devmgr,
        generation,
        transaction_id,
        system.now().map_err(InitError::Native)?,
    ) {
        return fail_loaded_devmgr(
            system,
            waits,
            controller,
            loaded,
            task_group,
            generation,
            transaction_id,
            error,
        );
    }
    let request = ControllerMessage::InstallPublication {
        supervisor_generation: SupervisorGeneration(generation),
        binding,
        transaction_id,
    };
    let mut bytes = [0u8; wyrmroot_device_proto::controller::INSTALL_BYTES];
    if encode_controller(request, &mut bytes).is_err() {
        return fail_loaded_devmgr(
            system,
            waits,
            controller,
            loaded,
            task_group,
            generation,
            transaction_id,
            InitError::WrongManifestProfile,
        );
    }
    if let Err(error) = system
        .send_channel(loaded.launch_channel, &bytes)
        .map_err(InitError::Native)
    {
        return fail_loaded_devmgr(
            system,
            waits,
            controller,
            loaded,
            task_group,
            generation,
            transaction_id,
            error,
        );
    }
    let now = match system.now().map_err(InitError::Native) {
        Ok(value) => value,
        Err(error) => {
            return fail_loaded_devmgr(
                system,
                waits,
                controller,
                loaded,
                task_group,
                generation,
                transaction_id,
                error,
            );
        }
    };
    let status_deadline = match now.checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns) {
        Some(value) => value,
        None => {
            return fail_loaded_devmgr(
                system,
                waits,
                controller,
                loaded,
                task_group,
                generation,
                transaction_id,
                InitError::Accounting,
            );
        }
    };
    let observed = match system
        .wait_many(
            core::slice::from_ref(&DwWaitItemV1 {
                handle: loaded.launch_channel,
                signals: DW_SIGNAL_READABLE,
            }),
            DwDeadline(status_deadline),
        )
        .map_err(InitError::Native)
    {
        Ok(value) => value,
        Err(error) => {
            return fail_loaded_devmgr(
                system,
                waits,
                controller,
                loaded,
                task_group,
                generation,
                transaction_id,
                error,
            );
        }
    };
    if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return fail_loaded_devmgr(
            system,
            waits,
            controller,
            loaded,
            task_group,
            generation,
            transaction_id,
            InitError::Supervision,
        );
    }
    let response = match receive_controller_status(system, loaded.launch_channel) {
        Ok(value) => value,
        Err(error) => {
            return fail_loaded_devmgr(
                system,
                waits,
                controller,
                loaded,
                task_group,
                generation,
                transaction_id,
                error,
            );
        }
    };
    let expected_status = if resource_domain.is_some() {
        StatusCode::OperationalResourceOwned
    } else {
        StatusCode::OperationalWaitingForDeviceBundle
    };
    if response
        != (ControllerMessage::Status {
            supervisor_generation: SupervisorGeneration(generation),
            binding: Some(binding),
            transaction_id,
            status: expected_status,
            attempt_generation: None,
        })
    {
        return fail_loaded_devmgr(
            system,
            waits,
            controller,
            loaded,
            task_group,
            generation,
            transaction_id,
            InitError::WrongManifestProfile,
        );
    }
    Ok(DevmgrNativeAttempt {
        active: ActiveNativeRole {
            role: RoleId::Devmgr,
            generation,
            transaction_id,
            loaded,
            task_group,
        },
        binding,
        publication_service_generation: publication.service_generation,
        last_controller_transaction: transaction_id,
        next_controller_transaction: transaction_id.checked_add(1).ok_or(InitError::Accounting)?,
    })
}

fn install_publication<S: Wyr1BPlatform>(
    system: &mut S,
    control: DwHandle,
    grant: crate::wyr1b::EndpointGrant,
    correlation: PublicationCorrelation,
    endpoint: DwHandle,
) -> Result<(), InitError> {
    let mut bytes = [0u8; 256];
    #[cfg(feature = "dw1e3-selector31")]
    let policy = SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY;
    #[cfg(not(feature = "dw1e3-selector31"))]
    let policy = SERIAL_CONSOLE_PUBLICATION_POLICY;
    let size = encode_install_publication(
        RegistryHeader {
            message_type: RegistryMessageType::InstallPublication,
            registry_generation: grant.registry_generation,
            endpoint_id: 0,
            endpoint_generation: 0,
            transaction_id: correlation.transaction_id,
        },
        grant.endpoint_id,
        grant.endpoint_generation,
        policy.supervisor_role_id,
        correlation.publication_id,
        correlation.service_generation,
        policy.protocol_id,
        &[ProtocolVersion {
            major: policy.protocol_major,
            minor: policy.protocol_minor,
        }],
        policy.service_name,
        &mut bytes,
    )
    .map_err(InitError::RegistryProtocol)?;
    let transfer = DwHandleTransferV1 {
        handle: endpoint,
        requested_rights: wyrmroot_loader::launch::CHILD_CHANNEL_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    system
        .send_channel_with_handles(control, &bytes[..size], core::slice::from_ref(&transfer))
        .map_err(InitError::Native)
}

#[allow(clippy::too_many_arguments)]
fn fail_loaded_devmgr<S, W>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    loaded: LoadedProcess,
    task_group: DwHandle,
    generation: u64,
    transaction_id: u64,
    original: InitError,
) -> Result<DevmgrNativeAttempt, InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let now = system.now().unwrap_or(0);
    let transition_failed = controller
        .fail(
            RoleId::Devmgr,
            generation,
            transaction_id,
            now,
            AttemptFailure::WaitFailed,
        )
        .is_err();
    let cleanup_failed = cleanup_loaded(system, waits, loaded, task_group, true).is_err();
    let retired_at = now.checked_add(1).unwrap_or(now);
    let controller_cleanup_failed = transition_failed
        || retired_at == now
        || controller
            .cleanup_complete(RoleId::Devmgr, generation, transaction_id, retired_at)
            .is_err();
    Err(if cleanup_failed || controller_cleanup_failed {
        InitError::Cleanup
    } else {
        original
    })
}

fn await_waiting_for_registry<S, W>(
    system: &mut S,
    waits: &mut W,
    devmgr: ActiveNativeRole,
    supervisor_generation: u64,
    last_controller_transaction: u64,
) -> Result<(), InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let deadline = system
        .now()
        .map_err(InitError::Native)?
        .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .ok_or(InitError::Accounting)?;
    let observed = waits
        .wait_many(
            core::slice::from_ref(&DwWaitItemV1 {
                handle: devmgr.loaded.launch_channel,
                signals: DW_SIGNAL_READABLE,
            }),
            DwDeadline(deadline),
        )
        .map_err(InitError::Native)?;
    if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(InitError::Supervision);
    }
    receive_waiting_for_registry(
        system,
        devmgr,
        supervisor_generation,
        last_controller_transaction,
    )
}

fn receive_waiting_for_registry<S: InitPlatform>(
    system: &mut S,
    devmgr: ActiveNativeRole,
    supervisor_generation: u64,
    last_controller_transaction: u64,
) -> Result<(), InitError> {
    let message = receive_controller_status(system, devmgr.loaded.launch_channel)?;
    match message {
        ControllerMessage::Status {
            supervisor_generation: received,
            binding: None,
            transaction_id,
            status: StatusCode::OperationalWaitingForRegistry,
            attempt_generation: None,
        } if received == SupervisorGeneration(supervisor_generation)
            && transaction_id == last_controller_transaction =>
        {
            Ok(())
        }
        _ => Err(InitError::WrongManifestProfile),
    }
}

fn receive_controller_status<S: InitPlatform>(
    system: &mut S,
    channel: DwHandle,
) -> Result<ControllerMessage, InitError> {
    let mut bytes = [0u8; wyrmroot_device_proto::controller::STATUS_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = system
        .receive_channel(channel, &mut bytes, &mut handles)
        .map_err(InitError::Native)?;
    if counts.handles != 0 {
        let mut cleanup_failed = false;
        for info in handles.iter().take(counts.handles.min(handles.len())).rev() {
            cleanup_failed |= system.close_handle(info.handle).is_err();
        }
        return Err(if cleanup_failed {
            InitError::Cleanup
        } else {
            InitError::WrongManifestProfile
        });
    }
    if counts.bytes != bytes.len() {
        return Err(InitError::WrongManifestProfile);
    }
    parse_controller(&bytes).map_err(|_| InitError::WrongManifestProfile)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DevmgrControlInput {
    Status(ControllerMessage),
    #[cfg(feature = "wyr1c6-selector29")]
    C6Fact(C6Fact),
    #[cfg(feature = "dw1e3-selector31")]
    TransportEmpty(TransportEmptyFact),
    #[cfg(feature = "dw1e3-selector31")]
    BindingReady(ChallengeBinding),
    #[cfg(feature = "dw1e3-selector31")]
    RetireStage1Ready(ChallengeBinding),
    DriverLaunch {
        request: DriverLaunchRequest,
        child_endpoint: DwHandle,
    },
    DriverRetired {
        bytes: [u8; DRIVER_RETIRED_BYTES],
    },
}

fn receive_devmgr_control<S: InitPlatform>(
    system: &mut S,
    channel: DwHandle,
) -> Result<DevmgrControlInput, InitError> {
    let mut bytes = [0u8; LAUNCH_REQUEST_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = system
        .receive_channel(channel, &mut bytes, &mut handles)
        .map_err(InitError::Native)?;
    if counts.bytes < 4 || counts.bytes > bytes.len() || counts.handles > handles.len() {
        close_received_native(system, &handles, counts.handles)?;
        return Err(InitError::WrongManifestProfile);
    }
    match &bytes[..4] {
        #[cfg(feature = "dw1e3-selector31")]
        b"WDE3" => {
            if counts.handles != 0 || counts.bytes != TRANSPORT_EMPTY_FACT_BYTES {
                close_received_native(system, &handles, counts.handles)?;
                return Err(InitError::WrongManifestProfile);
            }
            match u16::from_le_bytes([bytes[6], bytes[7]]) {
                3 => parse_transport_empty_fact(&bytes[..counts.bytes])
                    .map(DevmgrControlInput::TransportEmpty)
                    .map_err(|_| InitError::WrongManifestProfile),
                5 => parse_binding_ready(&bytes[..counts.bytes])
                    .map(DevmgrControlInput::BindingReady)
                    .map_err(|_| InitError::WrongManifestProfile),
                8 => parse_retire_stage1_ready(&bytes[..counts.bytes])
                    .map(DevmgrControlInput::RetireStage1Ready)
                    .map_err(|_| InitError::WrongManifestProfile),
                _ => Err(InitError::WrongManifestProfile),
            }
        }
        #[cfg(feature = "wyr1c6-selector29")]
        b"WRCF" => {
            if counts.handles != 0 || counts.bytes != C6_FACT_BYTES {
                close_received_native(system, &handles, counts.handles)?;
                return Err(InitError::WrongManifestProfile);
            }
            let fact = parse_c6_fact(&bytes[..counts.bytes])
                .map_err(|_| InitError::WrongManifestProfile)?;
            Ok(DevmgrControlInput::C6Fact(fact))
        }
        b"WRCS" => {
            if counts.handles != 0 {
                close_received_native(system, &handles, counts.handles)?;
                return Err(InitError::WrongManifestProfile);
            }
            let message = parse_controller(&bytes[..counts.bytes])
                .map_err(|_| InitError::WrongManifestProfile)?;
            if !matches!(message, ControllerMessage::Status { .. }) {
                return Err(InitError::WrongManifestProfile);
            }
            Ok(DevmgrControlInput::Status(message))
        }
        b"WRDL" => {
            if counts.handles != 1 || counts.bytes != LAUNCH_REQUEST_BYTES {
                close_received_native(system, &handles, counts.handles)?;
                return Err(InitError::WrongManifestProfile);
            }
            let info = handles[0];
            let metadata_valid = info.handle.0 != 0
                && info.object_type == DW_OBJECT_TYPE_CHANNEL
                && info.rights == DRIVER_CONTROL_INGRESS_RIGHTS
                && info.reserved0 == 0
                && info.reserved == [0; 2];
            let queried = system.query_capability_info(info.handle);
            if !metadata_valid
                || !matches!(
                    queried,
                    Ok(actual)
                        if actual.object_type == DW_OBJECT_TYPE_CHANNEL
                            && actual.rights == DRIVER_CONTROL_INGRESS_RIGHTS
                )
            {
                system
                    .close_handle(info.handle)
                    .map_err(|_| InitError::Cleanup)?;
                return Err(InitError::ResourceIdentityMismatch);
            }
            let request = match parse_request(&bytes[..counts.bytes]) {
                Ok(request) => request,
                Err(_) => {
                    system
                        .close_handle(info.handle)
                        .map_err(|_| InitError::Cleanup)?;
                    return Err(InitError::WrongManifestProfile);
                }
            };
            Ok(DevmgrControlInput::DriverLaunch {
                request,
                child_endpoint: info.handle,
            })
        }
        b"WRDT" => {
            if counts.bytes != DRIVER_RETIRED_BYTES || counts.handles != 0 {
                close_received_native(system, &handles, counts.handles)?;
                return Err(InitError::WrongManifestProfile);
            }
            let mut retired = [0u8; DRIVER_RETIRED_BYTES];
            retired.copy_from_slice(&bytes[..DRIVER_RETIRED_BYTES]);
            Ok(DevmgrControlInput::DriverRetired { bytes: retired })
        }
        _ => {
            close_received_native(system, &handles, counts.handles)?;
            Err(InitError::WrongManifestProfile)
        }
    }
}

fn close_received_native<S: InitPlatform>(
    system: &mut S,
    handles: &[DwReceivedHandleInfoV1],
    count: usize,
) -> Result<(), InitError> {
    let mut failed = false;
    for info in handles.iter().take(count.min(handles.len())).rev() {
        failed |= system.close_handle(info.handle).is_err();
    }
    if failed {
        Err(InitError::Cleanup)
    } else {
        Ok(())
    }
}

#[cfg(feature = "wyr1c6-selector29")]
fn accept_c6_fact(resident: &mut ResidentSystemInit, fact: C6Fact) -> Result<(), InitError> {
    #[cfg(feature = "wyr1c6-selector29")]
    if fact.event == 19 {
        let (d1_lease, cleanup_complete) = resident
            .wyr1c
            .as_ref()
            .map(|state| (state.c6_d1_lease, state.c6_d1_cleanup_complete))
            .ok_or(InitError::WrongActivationOrder)?;
        let d1_lease = d1_lease.ok_or(InitError::WrongActivationOrder)?;
        if !cleanup_complete
            || fact.lease <= d1_lease
            || fact.binding != 1
            || fact.value == 0
            || fact.aux != COM2_ROLE_ID.0
        {
            return Err(InitError::WrongManifestProfile);
        }
        let state = resident
            .wyr1c
            .as_mut()
            .ok_or(InitError::WrongActivationOrder)?;
        state
            .c6_evidence
            .as_mut()
            .ok_or(InitError::WrongActivationOrder)?
            .record(
                crate::wyr1c6_gate::GateEvent::D1GrantAvailable,
                d1_lease,
                0,
                1,
                0,
            )
            .map_err(|_| InitError::WrongManifestProfile)?;
    }
    let state = resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?;
    let valid = match fact.event {
        1 => fact.lease != 0 && fact.binding == 1 && fact.value != 0 && fact.aux == COM2_ROLE_ID.0,
        2 => Some(fact.lease) == state.c6_d1_lease && fact.binding == 1,
        3 => {
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && fact.binding != 0
                && fact.value != 0
                && fact.aux != 0
        }
        4 | 6 | 8 => {
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && Some(fact.binding) == state.c6_u1_irq
                && Some(fact.value) == state.c6_u1_attempt
                && Some(fact.aux) == state.c6_u1_endpoint
        }
        5 => {
            let binding = state.binding;
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && binding.is_some_and(|binding| {
                    fact.binding == binding.generation.0
                        && fact.aux == binding.endpoint.generation.0
                })
                && fact.value == state.c6_u1_attempt.unwrap_or(0)
                && state.publication_service_generation != 0
        }
        7 => {
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && fact.binding == state.c6_p1_registry_generation
                && Some(fact.value) == state.c6_u1_attempt
                && fact.aux == state.c6_p1_endpoint_generation
        }
        9 => {
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && Some(fact.binding) == state.c6_u1_irq
                && fact.value == 1
                && fact.aux == 0
        }
        10 => {
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && fact.binding != 0
                && Some(fact.binding) != state.c6_u1_irq
                && fact.value > state.c6_u1_attempt.unwrap_or(0)
                && fact.aux != 0
        }
        11 => {
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && Some(fact.binding) == state.c6_u2_irq
                && Some(fact.value) == state.c6_u2_attempt
                && Some(fact.aux) == state.c6_u2_endpoint
        }
        12 => {
            let binding = state.binding;
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && binding.is_some_and(|binding| {
                    fact.binding == binding.generation.0
                        && fact.aux == binding.endpoint.generation.0
                })
                && Some(fact.value) == state.c6_u2_attempt
                && state.publication_service_generation > state.c6_p1_service_generation
        }
        13 => {
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && fact.binding == state.c6_p1_registry_generation
                && Some(fact.value) == state.c6_u1_attempt
                && fact.aux == 3
        }
        14 => {
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && fact.binding == state.c6_p2_registry_generation
                && Some(fact.value) == state.c6_d1_supervisor
                && fact.aux == 0
        }
        15 => {
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && fact.binding == state.c6_p2_service_generation
                && Some(fact.value) == state.c6_u2_attempt
                && fact.aux == state.c6_p2_endpoint_generation
        }
        16 => {
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && Some(fact.binding) == state.c6_u2_irq
                && Some(fact.value) == state.c6_u2_attempt
                && Some(fact.aux) == state.c6_u2_endpoint
        }
        17 => {
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && fact.binding == 0
                && Some(fact.value) == state.c6_d1_supervisor
                && fact.aux == 1
        }
        18 => {
            fact.lease == state.c6_d1_lease.unwrap_or(0)
                && fact.binding == 0
                && fact.value == 1
                && fact.aux == 0
        }
        19 => {
            let active = state.devmgr;
            fact.lease > state.c6_d1_lease.unwrap_or(0)
                && fact.binding == 1
                && fact.value != 0
                && fact.aux != 0
                && active.is_some_and(|active| {
                    active.role == RoleId::Devmgr && active.generation == fact.value
                })
        }
        20..=22 => {
            let active = state.devmgr;
            fact.lease == state.c6_d2_lease.unwrap_or(0)
                && fact.binding == 1
                && Some(fact.value) == state.c6_d2_supervisor
                && Some(fact.aux) == state.c6_d2_role
                && active.is_some_and(|active| {
                    active.role == RoleId::Devmgr && active.generation == fact.value
                })
        }
        23 => {
            fact.lease == state.c6_d2_lease.unwrap_or(0)
                && fact.binding == 0
                && fact.value == 3
                && fact.aux == 0
                && resident
                    .controller
                    .c6_startup_profiles_exclude_direct_device_authority()
                && state.resource_domain.is_some_and(|custody| {
                    custody
                        .devmgr_claim_authority(ResourceDomainMembership::InitOutsideDomain)
                        .is_err()
                })
                && state.driver.is_none()
        }
        24 => {
            fact.lease == state.c6_d2_lease.unwrap_or(0)
                && fact.binding == 0
                && fact.value == 0
                && fact.aux == 0
                && state.c6_gate_config.physical_io_not_performed
        }
        25 => {
            let devmgr_failures = resident
                .controller
                .role_failure_count(RoleId::Devmgr)
                .unwrap_or(usize::MAX);
            fact.lease == state.c6_d2_lease.unwrap_or(0)
                && fact.binding == 0
                && fact.value == state.c6_d1_driver_failures
                && fact.aux == devmgr_failures as u64
        }
        26 => {
            fact.lease == state.c6_d2_lease.unwrap_or(0)
                && fact.binding == 0
                && fact.value == u64::from(WYR0_I_SUPERVISION_POLICY.max_attempts)
                && fact.aux == WYR0_I_SUPERVISION_POLICY.backoff_ns
        }
        _ => false,
    };
    if !valid {
        return Err(InitError::WrongManifestProfile);
    }
    let event = match fact.event {
        1 => crate::wyr1c6_gate::GateEvent::D1Begin,
        2 => crate::wyr1c6_gate::GateEvent::D1Lease,
        3 => crate::wyr1c6_gate::GateEvent::U1Start,
        4 => crate::wyr1c6_gate::GateEvent::U1Ready,
        5 => crate::wyr1c6_gate::GateEvent::P1Publish,
        6 => crate::wyr1c6_gate::GateEvent::U1Failure,
        7 => crate::wyr1c6_gate::GateEvent::P1Retire,
        8 => crate::wyr1c6_gate::GateEvent::U1Reap,
        9 => crate::wyr1c6_gate::GateEvent::OldIrqReleased,
        10 => crate::wyr1c6_gate::GateEvent::U2Start,
        11 => crate::wyr1c6_gate::GateEvent::U2Ready,
        12 => crate::wyr1c6_gate::GateEvent::P2Publish,
        13 => crate::wyr1c6_gate::GateEvent::StaleReject,
        14 => crate::wyr1c6_gate::GateEvent::D1Failure,
        15 => crate::wyr1c6_gate::GateEvent::P2Retire,
        16 => crate::wyr1c6_gate::GateEvent::U2Reap,
        17 => crate::wyr1c6_gate::GateEvent::D1GenerationClean,
        18 => crate::wyr1c6_gate::GateEvent::D1GrantAvailable,
        19 => crate::wyr1c6_gate::GateEvent::D2Lease,
        20 => crate::wyr1c6_gate::GateEvent::D2Start,
        21 => crate::wyr1c6_gate::GateEvent::D2Claim,
        22 => crate::wyr1c6_gate::GateEvent::D2Ready,
        23 => crate::wyr1c6_gate::GateEvent::NoAuthority,
        24 => crate::wyr1c6_gate::GateEvent::NoIo,
        25 => crate::wyr1c6_gate::GateEvent::Accounting,
        26 => crate::wyr1c6_gate::GateEvent::Bounded,
        _ => return Err(InitError::WrongManifestProfile),
    };
    let evidence_binding = c6_evidence_binding(
        fact.event,
        fact.binding,
        state.publication_service_generation,
        state.c6_p1_service_generation,
        state.c6_p2_service_generation,
    );
    let log = state
        .c6_evidence
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?;
    log.record(event, fact.lease, evidence_binding, fact.value, fact.aux)
        .map_err(|_| InitError::WrongManifestProfile)?;
    match fact.event {
        1 => {
            state.c6_d1_lease = Some(fact.lease);
            state.c6_d1_supervisor = Some(fact.value);
        }
        3 => {
            state.c6_u1_irq = Some(fact.binding);
            state.c6_u1_attempt = Some(fact.value);
            state.c6_u1_endpoint = Some(fact.aux);
        }
        5 => {
            state.c6_p1_service_generation = state.publication_service_generation;
            state.c6_p1_registry_generation = fact.binding;
            state.c6_p1_endpoint_generation = fact.aux;
        }
        6 => {
            state.c6_d1_driver_failures = state
                .c6_d1_driver_failures
                .checked_add(1)
                .ok_or(InitError::Accounting)?;
        }
        10 => {
            state.c6_u2_irq = Some(fact.binding);
            state.c6_u2_attempt = Some(fact.value);
            state.c6_u2_endpoint = Some(fact.aux);
        }
        12 => {
            state.c6_p2_service_generation = state.publication_service_generation;
            state.c6_p2_registry_generation = fact.binding;
            state.c6_p2_endpoint_generation = fact.aux;
        }
        19 => {
            state.c6_d2_lease = Some(fact.lease);
            state.c6_d2_supervisor = Some(fact.value);
            state.c6_d2_role = Some(fact.aux);
        }
        17 => state.c6_d1_cleanup_complete = true,
        _ => {}
    }
    if fact.event == 22 {
        emit_c6_terminal_facts(resident)?;
    }
    Ok(())
}

#[cfg(feature = "wyr1c6-selector29")]
const fn c6_evidence_binding(
    event: u8,
    observed_registry_generation: u64,
    current_service_generation: u64,
    p1_service_generation: u64,
    p2_service_generation: u64,
) -> u64 {
    match event {
        5 | 12 => current_service_generation,
        7 | 13 => p1_service_generation,
        14 => p2_service_generation,
        _ => observed_registry_generation,
    }
}

#[cfg(feature = "wyr1c6-selector29")]
fn emit_c6_terminal_facts(resident: &mut ResidentSystemInit) -> Result<(), InitError> {
    let (lease, driver_failures, devmgr_failures, max_attempts, backoff_ns) = {
        let state = resident
            .wyr1c
            .as_ref()
            .ok_or(InitError::WrongActivationOrder)?;
        let devmgr = state.devmgr.ok_or(InitError::WrongActivationOrder)?;
        if devmgr.role != RoleId::Devmgr
            || state.driver.is_some()
            || state.c6_d2_lease.is_none()
            || state.c6_d2_supervisor != Some(devmgr.generation)
            || state.c6_d2_role != Some(COM2_ROLE_ID.0)
            || !state.c6_gate_config.physical_io_not_performed
            || !resident
                .controller
                .c6_startup_profiles_exclude_direct_device_authority()
            || !state.resource_domain.is_some_and(|custody| {
                custody
                    .devmgr_claim_authority(ResourceDomainMembership::InitOutsideDomain)
                    .is_err()
            })
        {
            return Err(InitError::WrongManifestProfile);
        }
        let lease = state.c6_d2_lease.ok_or(InitError::WrongActivationOrder)?;
        let driver_failures = state.c6_d1_driver_failures;
        let devmgr_failures = resident
            .controller
            .role_failure_count(RoleId::Devmgr)
            .ok_or(InitError::Accounting)?;
        if driver_failures == 0 || devmgr_failures == 0 {
            return Err(InitError::Accounting);
        }
        (
            lease,
            driver_failures,
            devmgr_failures as u64,
            WYR0_I_SUPERVISION_POLICY.max_attempts,
            WYR0_I_SUPERVISION_POLICY.backoff_ns,
        )
    };
    for (event, value, aux) in [
        (23, 3, 0),
        (24, 0, 0),
        (25, driver_failures, devmgr_failures),
        (26, u64::from(max_attempts), backoff_ns),
    ] {
        accept_c6_fact(
            resident,
            C6Fact {
                event,
                lease,
                binding: 0,
                value,
                aux,
            },
        )?;
    }
    Ok(())
}

#[cfg(feature = "wyr1c6-selector29")]
pub fn finish_c6_evidence(resident: &mut ResidentSystemInit) -> Result<bool, InitError> {
    let state = resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?;
    let log = state
        .c6_evidence
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?;
    if !log.ready_for_terminal() {
        return Ok(false);
    }
    log.finish().map_err(|_| InitError::WrongManifestProfile)?;
    Ok(true)
}

fn validate_driver_actor(bootfs: &[u8], request: DriverLaunchRequest) -> Result<&[u8], InitError> {
    // Re-run the complete retained WRRM/product validation at the construction
    // boundary, then join the request identity through WRDM to the exact
    // executable bytes actually supplied to the loader.
    let _ = crate::wyr1b_native::validate_retained_bootfs_c1(bootfs)?;
    let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
    let device_manifest = archive
        .lookup(DEVICE_MANIFEST_PATH.as_bytes())
        .map_err(map_lookup)?;
    if device_manifest.is_executable() {
        return Err(InitError::WrongManifestProfile);
    }
    let role = DeviceManifest::parse(device_manifest.data())
        .map_err(|_| InitError::WrongManifestProfile)?
        .match_com2(request.actor_identity)
        .map_err(|_| InitError::WrongManifestProfile)?;
    if request.role_id != COM2_ROLE_ID || role.role_id != request.role_id {
        return Err(InitError::WrongManifestProfile);
    }
    let actor = archive
        .lookup(wyrmroot_device_proto::manifest::UART16550D_PATH)
        .map_err(map_lookup)?;
    if !actor.is_executable()
        || wyrmroot_runtime::sha256::digest(actor.data()) != request.actor_identity.0
    {
        return Err(InitError::ArtifactIdentityMismatch(RoleId::Uart16550d));
    }
    Ok(actor.data())
}

fn driver_correlation_is_fresh(
    supervisor_generation: u64,
    last_attempt: u64,
    last_session: u64,
    last_endpoint: u64,
    last_transaction: u64,
    request: DriverLaunchRequest,
) -> bool {
    request.supervisor_generation == SupervisorGeneration(supervisor_generation)
        && request.attempt_generation.0 > last_attempt
        && request.launch_session.0 > last_session
        && request.endpoint.id.0 > last_endpoint
        && request.endpoint.generation.0 == 1
        && request.transaction_id > last_transaction
}

#[allow(clippy::too_many_arguments)]
fn construct_driver<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootfs: &[u8],
    devmgr: ActiveNativeRole,
    request: DriverLaunchRequest,
    child_endpoint: DwHandle,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let state = resident
        .wyr1c
        .as_ref()
        .ok_or(InitError::WrongActivationOrder)?;
    let correlation_valid = driver_correlation_is_fresh(
        devmgr.generation,
        state.last_driver_attempt,
        state.last_driver_session,
        state.last_driver_endpoint,
        state.last_driver_transaction,
        request,
    );
    if !correlation_valid || state.driver.is_some() {
        system
            .close_handle(child_endpoint)
            .map_err(|_| InitError::Cleanup)?;
        return Err(InitError::WrongManifestProfile);
    }
    let actor = match validate_driver_actor(bootfs, request) {
        Ok(actor) => actor,
        Err(error) => {
            system
                .close_handle(child_endpoint)
                .map_err(|_| InitError::Cleanup)?;
            return Err(error);
        }
    };
    #[cfg(feature = "wyr1c5-production")]
    let driver_parent = devmgr.task_group;
    #[cfg(not(feature = "wyr1c5-production"))]
    let driver_parent = resident.authority.task_group;
    let task_group = match system.create_attempt_task_group(driver_parent) {
        Ok(handle) => handle,
        Err(error) => {
            system
                .close_handle(child_endpoint)
                .map_err(|_| InitError::Cleanup)?;
            return Err(InitError::Native(error));
        }
    };
    let loaded = match load_device_driver_process(
        loader,
        LoadAuthority {
            task_group,
            ..resident.authority
        },
        DeviceDriverLoadRequest {
            image: actor,
            display_path: wyrmroot_device_proto::DEVICE_DRIVER_PATH,
            control_endpoint: child_endpoint,
            supervisor_generation: request.supervisor_generation.0,
            role_id: request.role_id.0,
            attempt_generation: request.attempt_generation.0,
            launch_session: request.launch_session.0,
            endpoint_id: request.endpoint.id.0,
            endpoint_generation: request.endpoint.generation.0,
            transaction_id: request.transaction_id,
        },
    ) {
        Ok(loaded) => loaded,
        Err(failure) => {
            let mut cleanup_failed = system.close_handle(task_group).is_err();
            if !failure.control_endpoint_consumed {
                cleanup_failed |= system.close_handle(child_endpoint).is_err();
            }
            return Err(if cleanup_failed {
                InitError::Cleanup
            } else {
                InitError::Loader(failure.error)
            });
        }
    };

    {
        let state = resident
            .wyr1c
            .as_mut()
            .ok_or(InitError::WrongActivationOrder)?;
        state.driver = Some(DriverNativeAttempt {
            loaded,
            task_group,
            request,
        });
        state.last_driver_attempt = request.attempt_generation.0;
        state.last_driver_session = request.launch_session.0;
        state.last_driver_endpoint = request.endpoint.id.0;
        state.last_driver_transaction = request.transaction_id;
    }
    let mut ack = [0u8; LAUNCH_RESPONSE_BYTES];
    encode_constructed(request, &mut ack).map_err(|_| InitError::WrongManifestProfile)?;
    if let Err(error) = system.send_channel(devmgr.loaded.launch_channel, &ack) {
        let attempt = resident
            .wyr1c
            .as_mut()
            .and_then(|state| state.driver.take())
            .ok_or(InitError::WrongActivationOrder)?;
        let cleanup_failed =
            cleanup_loaded(system, waits, attempt.loaded, attempt.task_group, true).is_err();
        return Err(if cleanup_failed {
            InitError::Cleanup
        } else {
            InitError::Native(error)
        });
    }
    Ok(())
}

#[cfg(feature = "dw1e3-selector31")]
fn start_e3a_probe<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootfs: &[u8],
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let (
        devmgr,
        registry_control,
        publication_generation,
        driver_attempt,
        challenge_generation,
        already_started,
    ) = {
        let state = resident
            .wyr1c
            .as_ref()
            .ok_or(InitError::WrongActivationOrder)?;
        (
            state.devmgr.ok_or(InitError::WrongActivationOrder)?,
            state
                .registry
                .ok_or(InitError::WrongActivationOrder)?
                .control_channel,
            state.publication_service_generation,
            state
                .driver
                .ok_or(InitError::WrongActivationOrder)?
                .request
                .attempt_generation
                .0,
            state.e3a_next_challenge_generation,
            state.e3a_probe.is_some(),
        )
    };
    if already_started || publication_generation == 0 || !matches!(challenge_generation, 1 | 2) {
        return Err(InitError::WrongActivationOrder);
    }
    let nonce = wyrmroot_runtime::dw1e3_build_nonce().map_err(InitError::Native)?;
    // E3A has no separate payload nonce. E3B supplies both frozen payload
    // nonces, which the runtime validates as distinct from this evidence key.
    let challenge = e3a_challenge(
        wyrmroot_runtime::dw1e3_challenge_nonce(challenge_generation).map_err(InitError::Native)?,
    );
    let expected_hash = e3a_fnv1a64(&challenge);

    // Constructing the process only unblocks devmgr's synchronous staging path;
    // it does not mean the Interrupt is bound or the registry publication is
    // committed. The selector-private ready reply is emitted by devmgr only
    // after both facts hold and its connector broker owns the exact generation.
    let mut devmgr_config = [0u8; wyrmroot_dw1e3_com2_test::DEVMGR_CONFIG_BYTES];
    encode_e3a_devmgr_config(
        DevmgrConfig {
            nonce,
            publication_generation,
        },
        &mut devmgr_config,
    )
    .map_err(|_| InitError::WrongManifestProfile)?;
    system
        .send_channel(devmgr.loaded.launch_channel, &devmgr_config)
        .map_err(InitError::Native)?;

    let now = system.now().map_err(InitError::Native)?;
    let deadline = now
        .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .ok_or(InitError::Accounting)?;
    let observed = waits
        .wait_many(
            &[
                DwWaitItemV1 {
                    handle: devmgr.loaded.launch_channel,
                    signals: DW_SIGNAL_READABLE,
                },
                DwWaitItemV1 {
                    handle: devmgr.loaded.process,
                    signals: DW_SIGNAL_EXITED,
                },
            ],
            DwDeadline(deadline),
        )
        .map_err(InitError::Native)?;
    if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(InitError::Supervision);
    }
    let mut devmgr_ready = [0u8; wyrmroot_dw1e3_com2_test::DEVMGR_CONFIG_BYTES];
    let mut ready_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = system
        .receive_channel(
            devmgr.loaded.launch_channel,
            &mut devmgr_ready,
            &mut ready_handles,
        )
        .map_err(InitError::Native)?;
    if counts.bytes != devmgr_ready.len() || counts.handles != 0 {
        close_received_native(system, &ready_handles, counts.handles)?;
        return Err(InitError::WrongManifestProfile);
    }
    let ready = parse_devmgr_ready(&devmgr_ready).map_err(|_| InitError::WrongManifestProfile)?;
    if ready
        != (DevmgrReady {
            nonce,
            publication_generation,
        })
    {
        return Err(InitError::WrongManifestProfile);
    }

    let authority = resident.authority;
    let probe = {
        let state = resident
            .wyr1c
            .as_mut()
            .ok_or(InitError::WrongActivationOrder)?;
        launch_registry_client_actor(
            system,
            loader,
            waits,
            authority,
            bootfs,
            registry_control,
            &mut state.topology,
            E3A_PROBE_PATH,
            publication_generation,
            E3A_PROBE_TRANSACTION_ID,
        )?
    };
    let result = (|| {
        // Bind both selector reporters from the controller's retained Process
        // custody. Deepwyrm resolves this handle in system-init's table, so
        // neither the probe nor a guessed primordial identity can claim the
        // controller role.
        wyrmroot_runtime::dw1e3_bind_probe(probe.loaded.process, nonce)
            .map_err(InitError::Native)?;
        let configure = E3AControllerMessage::Configure {
            nonce,
            publication_generation,
            challenge_generation,
            expected_length: E3A_CHALLENGE_BYTES as u64,
            expected_hash,
        };
        let mut bytes = [0u8; E3A_CONTROL_BYTES];
        encode_e3a_controller(configure, &mut bytes)
            .map_err(|_| InitError::WrongManifestProfile)?;
        system
            .send_channel(probe.loaded.launch_channel, &bytes)
            .map_err(InitError::Native)?;

        let now = system.now().map_err(InitError::Native)?;
        let deadline = now
            .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .ok_or(InitError::Accounting)?;
        let observed = waits
            .wait_many(
                &[
                    DwWaitItemV1 {
                        handle: probe.loaded.launch_channel,
                        signals: DW_SIGNAL_READABLE,
                    },
                    DwWaitItemV1 {
                        handle: probe.loaded.process,
                        signals: DW_SIGNAL_EXITED,
                    },
                ],
                DwDeadline(deadline),
            )
            .map_err(InitError::Native)?;
        if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
            return Err(InitError::Supervision);
        }
        let mut handles = [DwReceivedHandleInfoV1::default(); 1];
        let counts = system
            .receive_channel(probe.loaded.launch_channel, &mut bytes, &mut handles)
            .map_err(InitError::Native)?;
        if counts.bytes != bytes.len() || counts.handles != 0 {
            close_received_native(system, &handles, counts.handles)?;
            return Err(InitError::WrongManifestProfile);
        }
        let attached = parse_e3a_controller(&bytes).map_err(|_| InitError::WrongManifestProfile)?;
        let E3AControllerMessage::Attached {
            nonce: received_nonce,
            publication_generation: received_publication,
            stream_generation,
            challenge_generation: received_challenge_generation,
        } = attached
        else {
            return Err(InitError::WrongManifestProfile);
        };
        if received_nonce != nonce
            || received_publication != publication_generation
            || received_challenge_generation != challenge_generation
        {
            return Err(InitError::WrongManifestProfile);
        }

        let binding = ChallengeBinding {
            nonce,
            attempt_generation: driver_attempt,
            publication_generation,
            stream_generation,
            challenge_generation,
            expected_length: E3A_CHALLENGE_BYTES as u64,
            expected_hash,
        };
        let mut binding_bytes = [0u8; TRANSPORT_EMPTY_FACT_BYTES];
        encode_challenge_binding(binding, &mut binding_bytes)
            .map_err(|_| InitError::WrongManifestProfile)?;
        system
            .send_channel(devmgr.loaded.launch_channel, &binding_bytes)
            .map_err(InitError::Native)?;
        let now = system.now().map_err(InitError::Native)?;
        let deadline = now
            .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .ok_or(InitError::Accounting)?;
        let observed = waits
            .wait_many(
                core::slice::from_ref(&DwWaitItemV1 {
                    handle: devmgr.loaded.launch_channel,
                    signals: DW_SIGNAL_READABLE,
                }),
                DwDeadline(deadline),
            )
            .map_err(InitError::Native)?;
        if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
            return Err(InitError::Supervision);
        }
        if receive_devmgr_control(system, devmgr.loaded.launch_channel)?
            != DevmgrControlInput::BindingReady(binding)
        {
            return Err(InitError::WrongManifestProfile);
        }
        // Action 3 is the sole host-transmit readiness point, and only after
        // the current driver has returned its exact BindingReady correlation.
        wyrmroot_runtime::dw1e3_arm_challenge(
            stream_generation,
            challenge_generation,
            E3A_CHALLENGE_BYTES as u64,
            expected_hash,
            nonce,
        )
        .map_err(InitError::Native)?;
        let permit = E3AControllerMessage::ArmPermit {
            nonce,
            publication_generation,
            stream_generation,
            challenge_generation,
            expected_length: E3A_CHALLENGE_BYTES as u64,
            expected_hash,
        };
        encode_e3a_controller(permit, &mut bytes).map_err(|_| InitError::WrongManifestProfile)?;
        system
            .send_channel(probe.loaded.launch_channel, &bytes)
            .map_err(InitError::Native)?;
        Ok((stream_generation, binding))
    })();
    match result {
        Ok((stream_generation, binding)) => {
            let state = resident
                .wyr1c
                .as_mut()
                .ok_or(InitError::WrongActivationOrder)?;
            state.e3a_probe = Some(probe);
            state.e3a_stream_generation = Some(stream_generation);
            state.e3a_binding = Some(binding);
            state.e3a_response_committed = false;
            state.e3a_transport_empty = None;
            state.e3a_begin_retire_sent = false;
            state.e3a_stage1_ready = false;
            state.e3a_peer_closed = false;
            state.e3a_finalize_retire_sent = false;
            state.e3a_u2_probe_reaped_successfully = false;
            Ok(())
        }
        Err(error) => {
            let cleanup_failed =
                cleanup_loaded(system, waits, probe.loaded, probe.task_group, true).is_err();
            Err(if cleanup_failed {
                InitError::Cleanup
            } else {
                error
            })
        }
    }
}

fn reap_driver<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
    terminate: bool,
) -> Result<DriverLaunchRequest, InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let attempt = resident
        .wyr1c
        .as_mut()
        .and_then(|state| state.driver.take())
        .ok_or(InitError::WrongActivationOrder)?;
    let request = attempt.request;
    cleanup_loaded(system, waits, attempt.loaded, attempt.task_group, terminate)?;
    if let Some(state) = resident.wyr1c.as_mut() {
        state.last_reaped_driver = Some(request);
    }
    Ok(request)
}

#[cfg(feature = "dw1e3-selector31")]
fn exact_e3a_response(binding: ChallengeBinding) -> Result<(u64, u64), InitError> {
    let challenge = e3a_challenge(
        wyrmroot_runtime::dw1e3_challenge_nonce(binding.challenge_generation)
            .map_err(InitError::Native)?,
    );
    if binding.expected_length != E3A_CHALLENGE_BYTES as u64
        || binding.expected_hash != e3a_fnv1a64(&challenge)
    {
        return Err(InitError::WrongManifestProfile);
    }
    let response = e3a_response(&challenge);
    Ok((E3A_RESPONSE_BYTES as u64, e3a_fnv1a64(&response)))
}

#[cfg(feature = "dw1e3-selector31")]
fn exact_transport_empty(
    binding: ChallengeBinding,
    fact: TransportEmptyFact,
) -> Result<(), InitError> {
    let (response_length, response_hash) = exact_e3a_response(binding)?;
    if fact.nonce != binding.nonce
        || fact.attempt_generation != binding.attempt_generation
        || fact.publication_generation != binding.publication_generation
        || fact.stream_generation != binding.stream_generation
        || fact.challenge_generation != binding.challenge_generation
        || fact.response_length != response_length
        || fact.response_hash != response_hash
    {
        return Err(InitError::WrongManifestProfile);
    }
    Ok(())
}

#[cfg(feature = "dw1e3-selector31")]
fn maybe_begin_e3a_retire<S: InitPlatform>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
) -> Result<(), InitError> {
    let (
        devmgr,
        binding,
        response_committed,
        transport_empty,
        already_sent,
        u2_probe_reaped_successfully,
    ) = {
        let state = resident
            .wyr1c
            .as_ref()
            .ok_or(InitError::WrongActivationOrder)?;
        (
            state.devmgr.ok_or(InitError::WrongActivationOrder)?,
            state.e3a_binding.ok_or(InitError::WrongActivationOrder)?,
            state.e3a_response_committed,
            state.e3a_transport_empty,
            state.e3a_begin_retire_sent,
            state.e3a_u2_probe_reaped_successfully,
        )
    };
    if !response_committed || transport_empty.is_none() {
        return Ok(());
    }
    if binding.challenge_generation == 2 {
        if !u2_probe_reaped_successfully {
            // A TEMT wake can win the resident poll before a simultaneously
            // queued nonzero probe exit.  The exact normal-zero reap is a
            // controller-side causal join, not merely cleanup.
            return Ok(());
        }
        let terminal_claimed = resident
            .wyr1c
            .as_ref()
            .ok_or(InitError::WrongActivationOrder)?
            .e3a_terminal_claimed;
        if terminal_claimed {
            return Err(InitError::WrongManifestProfile);
        }
        exact_transport_empty(
            binding,
            transport_empty.ok_or(InitError::WrongActivationOrder)?,
        )?;
        // The probe cannot make this claim: both its committed response and
        // the current driver's post-ack TEMT fact have been rejoined here.
        wyrmroot_runtime::dw1e3_terminal_claim(binding.nonce).map_err(InitError::Native)?;
        resident
            .wyr1c
            .as_mut()
            .ok_or(InitError::WrongActivationOrder)?
            .e3a_terminal_claimed = true;
        return Ok(());
    }
    if binding.challenge_generation != 1 {
        return Err(InitError::WrongManifestProfile);
    }
    if already_sent {
        return Err(InitError::WrongManifestProfile);
    }
    exact_transport_empty(
        binding,
        transport_empty.ok_or(InitError::WrongActivationOrder)?,
    )?;
    let mut bytes = [0u8; TRANSPORT_EMPTY_FACT_BYTES];
    encode_begin_retire(binding, &mut bytes).map_err(|_| InitError::WrongManifestProfile)?;
    system
        .send_channel(devmgr.loaded.launch_channel, &bytes)
        .map_err(InitError::Native)?;
    resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?
        .e3a_begin_retire_sent = true;
    Ok(())
}

#[cfg(feature = "dw1e3-selector31")]
fn send_e3a_finalize_retire<S: InitPlatform>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
) -> Result<(), InitError> {
    let (devmgr, binding, stage1_ready, peer_closed, already_sent) = {
        let state = resident
            .wyr1c
            .as_ref()
            .ok_or(InitError::WrongActivationOrder)?;
        (
            state.devmgr.ok_or(InitError::WrongActivationOrder)?,
            state.e3a_binding.ok_or(InitError::WrongActivationOrder)?,
            state.e3a_stage1_ready,
            state.e3a_peer_closed,
            state.e3a_finalize_retire_sent,
        )
    };
    if !stage1_ready || !peer_closed {
        return Ok(());
    }
    if already_sent {
        return Err(InitError::WrongManifestProfile);
    }
    let mut bytes = [0u8; TRANSPORT_EMPTY_FACT_BYTES];
    encode_finalize_retire(binding, &mut bytes).map_err(|_| InitError::WrongManifestProfile)?;
    system
        .send_channel(devmgr.loaded.launch_channel, &bytes)
        .map_err(InitError::Native)?;
    resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?
        .e3a_finalize_retire_sent = true;
    Ok(())
}

#[cfg(feature = "dw1e3-selector31")]
fn receive_e3a_probe_message<S: InitPlatform>(
    resident: &ResidentSystemInit,
    system: &mut S,
) -> Result<E3AControllerMessage, InitError> {
    let probe = resident
        .wyr1c
        .as_ref()
        .and_then(|state| state.e3a_probe)
        .ok_or(InitError::WrongActivationOrder)?;
    let mut bytes = [0u8; E3A_CONTROL_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = system
        .receive_channel(probe.loaded.launch_channel, &mut bytes, &mut handles)
        .map_err(InitError::Native)?;
    if counts.bytes != bytes.len() || counts.handles != 0 {
        close_received_native(system, &handles, counts.handles)?;
        return Err(InitError::WrongManifestProfile);
    }
    parse_e3a_controller(&bytes).map_err(|_| InitError::WrongManifestProfile)
}

#[cfg(feature = "dw1e3-selector31")]
fn validate_e3a_u1_finalize_exit<W>(
    resident: &ResidentSystemInit,
    waits: &mut W,
) -> Result<(), InitError>
where
    W: SupervisionPlatform<Error = NativeError>,
{
    let state = resident
        .wyr1c
        .as_ref()
        .ok_or(InitError::WrongActivationOrder)?;
    let binding = state.e3a_binding.ok_or(InitError::WrongManifestProfile)?;
    let driver = state.driver.ok_or(InitError::WrongManifestProfile)?;
    if binding.challenge_generation != 1
        || !state.e3a_response_committed
        || !state.e3a_begin_retire_sent
        || !state.e3a_stage1_ready
        || !state.e3a_peer_closed
        || !state.e3a_finalize_retire_sent
        || state.e3a_terminal_claimed
    {
        return Err(InitError::WrongManifestProfile);
    }
    exact_transport_empty(
        binding,
        state
            .e3a_transport_empty
            .ok_or(InitError::WrongManifestProfile)?,
    )?;
    let exit = waits
        .query_task_termination(driver.loaded.process)
        .map_err(InitError::Native)?;
    wyrmroot_runtime::validate_successful_exit(&exit).map_err(|_| InitError::WrongManifestProfile)
}

#[cfg(feature = "dw1e3-selector31")]
fn reap_e3a_probe<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
    admit_u2: bool,
) -> Result<(), InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let probe = resident
        .wyr1c
        .as_mut()
        .and_then(|state| state.e3a_probe.take());
    let Some(probe) = probe else {
        return Ok(());
    };
    let deadline = system
        .now()
        .map_err(InitError::Native)?
        .checked_add(WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns)
        .ok_or(InitError::Accounting)?;
    // Closing only the controller endpoint asks the probe to take its normal
    // parent-peer-close exit. It has already supplied its close proof.
    let mut cleanup_failed = system.close_handle(probe.loaded.launch_channel).is_err();
    let observed_exit = matches!(
        waits.wait_many(
            core::slice::from_ref(&DwWaitItemV1 {
                handle: probe.loaded.process,
                signals: DW_SIGNAL_EXITED,
            }),
            DwDeadline(deadline),
        ),
        Ok(result) if result.index == 0 && result.observed.0 & DW_SIGNAL_EXITED.0 != 0
    ) && matches!(
        waits.query_task_termination(probe.loaded.process),
        Ok(info) if info.state == DW_TASK_STATE_EXITED
    );
    if !observed_exit {
        cleanup_failed |= system.terminate_task_group(probe.task_group).is_err();
        let fallback_deadline = system
            .now()
            .ok()
            .and_then(|now| now.checked_add(WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns));
        if let Some(fallback_deadline) = fallback_deadline {
            let _ = waits.wait_many(
                core::slice::from_ref(&DwWaitItemV1 {
                    handle: probe.loaded.process,
                    signals: DW_SIGNAL_EXITED,
                }),
                DwDeadline(fallback_deadline),
            );
        } else {
            cleanup_failed = true;
        }
    }
    cleanup_failed |= !matches!(
        waits.query_task_termination(probe.loaded.process),
        Ok(info)
            if info.state == DW_TASK_STATE_EXITED
                && (!admit_u2 || wyrmroot_runtime::validate_successful_exit(&info).is_ok())
    );
    for handle in [probe.loaded.process, probe.task_group] {
        cleanup_failed |= system.close_handle(handle).is_err();
    }
    if let Some(state) = resident.wyr1c.as_mut() {
        let retired_generation = state
            .e3a_binding
            .map(|binding| binding.challenge_generation)
            .unwrap_or(0);
        state.e3a_stream_generation = None;
        state.e3a_binding = None;
        state.e3a_response_committed = false;
        state.e3a_transport_empty = None;
        state.e3a_begin_retire_sent = false;
        state.e3a_stage1_ready = false;
        state.e3a_peer_closed = false;
        state.e3a_finalize_retire_sent = false;
        state.e3a_u2_probe_reaped_successfully = false;
        if cleanup_failed || !admit_u2 {
            // Any unexpected probe loss poisons the selector lifecycle.  A
            // failed cleanup must likewise never expose an intermediate U2
            // admission after a nonzero or incomplete U1 probe exit.
            state.e3a_next_challenge_generation = 0;
        } else if retired_generation == 1 {
            state.e3a_next_challenge_generation = 2;
        }
    }
    if cleanup_failed {
        Err(InitError::Cleanup)
    } else {
        Ok(())
    }
}

/// The fresh U2 probe exits normally after it has committed its response.  It
/// is no longer the active reporter, but its successful exit must be reaped
/// without clearing the U2 binding or a TEMT fact that is still in flight.
#[cfg(feature = "dw1e3-selector31")]
fn reap_e3a_u2_probe_after_response<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
) -> Result<(), InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let probe = {
        let state = resident
            .wyr1c
            .as_mut()
            .ok_or(InitError::WrongActivationOrder)?;
        let binding = state.e3a_binding.ok_or(InitError::WrongManifestProfile)?;
        if binding.challenge_generation != 2
            || !state.e3a_response_committed
            || state.e3a_terminal_claimed
        {
            return Err(InitError::WrongManifestProfile);
        }
        state
            .e3a_probe
            .take()
            .ok_or(InitError::WrongManifestProfile)?
    };
    let deadline = system
        .now()
        .map_err(InitError::Native)?
        .checked_add(WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns)
        .ok_or(InitError::Accounting)?;
    let mut cleanup_failed = system.close_handle(probe.loaded.launch_channel).is_err();
    let observed_exit = matches!(
        waits.wait_many(
            core::slice::from_ref(&DwWaitItemV1 {
                handle: probe.loaded.process,
                signals: DW_SIGNAL_EXITED,
            }),
            DwDeadline(deadline),
        ),
        Ok(result) if result.index == 0 && result.observed.0 & DW_SIGNAL_EXITED.0 != 0
    );
    let terminal_result = if observed_exit {
        match waits.query_task_termination(probe.loaded.process) {
            Ok(exit) => wyrmroot_runtime::validate_successful_exit(&exit)
                .map_err(|_| InitError::WrongManifestProfile),
            Err(error) => Err(InitError::Native(error)),
        }
    } else {
        // No exit by the bounded deadline is a selector failure.  Terminate
        // only in this timeout-cleanup case, then wait/requery so every owned
        // handle is reconciled before returning the original failure.
        cleanup_failed |= system.terminate_task_group(probe.task_group).is_err();
        let fallback_deadline = system
            .now()
            .ok()
            .and_then(|now| now.checked_add(WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns));
        let fallback_exited = if let Some(fallback_deadline) = fallback_deadline {
            matches!(
                waits.wait_many(
                core::slice::from_ref(&DwWaitItemV1 {
                    handle: probe.loaded.process,
                    signals: DW_SIGNAL_EXITED,
                }),
                DwDeadline(fallback_deadline),
            ),
                Ok(result) if result.index == 0 && result.observed.0 & DW_SIGNAL_EXITED.0 != 0
            ) && matches!(
                waits.query_task_termination(probe.loaded.process),
                Ok(info) if info.state == DW_TASK_STATE_EXITED
            )
        } else {
            false
        };
        if !fallback_exited {
            // We have already closed the controller endpoint, but process and
            // task-group ownership remain live until a later cleanup/reap can
            // prove EXITED. Do not forget them on a successful-but-ineffective
            // terminate request.
            resident
                .wyr1c
                .as_mut()
                .ok_or(InitError::WrongActivationOrder)?
                .e3a_probe = Some(probe);
            return Err(InitError::Cleanup);
        }
        Err(InitError::Supervision)
    };
    for handle in [probe.loaded.process, probe.task_group] {
        cleanup_failed |= system.close_handle(handle).is_err();
    }
    if cleanup_failed {
        return Err(InitError::Cleanup);
    }
    terminal_result?;
    resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?
        .e3a_u2_probe_reaped_successfully = true;
    // TEMT may already be present when the exit is observed. Re-run the
    // controller join only after this exact normal-zero reap has committed.
    maybe_begin_e3a_retire(resident, system)
}

#[cfg(feature = "dw1e3-selector31")]
fn e3a_u2_probe_may_exit(resident: &ResidentSystemInit) -> bool {
    resident.wyr1c.as_ref().is_some_and(|state| {
        state
            .e3a_binding
            .is_some_and(|binding| binding.challenge_generation == 2)
            && state.e3a_response_committed
            && !state.e3a_terminal_claimed
    })
}

#[cfg(feature = "dw1e3-selector31")]
fn poison_e3a_lifecycle(resident: &mut ResidentSystemInit) {
    if let Some(state) = resident.wyr1c.as_mut() {
        state.e3a_next_challenge_generation = 0;
        state.e3a_stream_generation = None;
        state.e3a_binding = None;
        state.e3a_response_committed = false;
        state.e3a_transport_empty = None;
        state.e3a_begin_retire_sent = false;
        state.e3a_stage1_ready = false;
        state.e3a_peer_closed = false;
        state.e3a_finalize_retire_sent = false;
        state.e3a_u2_probe_reaped_successfully = false;
    }
}

#[cfg(feature = "dw1e3-selector31")]
fn fail_e3a_u2_probe_exit<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
    error: InitError,
) -> Result<(), InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    // A timed-out U2 reap can retain the process/task-group for a second
    // bounded cleanup attempt. Consume that owner before poisoning its
    // correlations so a live probe is never orphaned by this failure path.
    let probe_cleanup = reap_e3a_probe(resident, system, waits, false);
    poison_e3a_lifecycle(resident);
    let driver_cleanup = if resident
        .wyr1c
        .as_ref()
        .is_some_and(|state| state.driver.is_some())
    {
        reap_driver(resident, system, waits, true).map(|_| ())
    } else {
        Ok(())
    };
    if probe_cleanup.is_err() || driver_cleanup.is_err() {
        Err(InitError::Cleanup)
    } else {
        Err(error)
    }
}

/// A devmgr or registry recovery cannot inherit an in-flight selector probe.
/// Consume its exact owners first and poison all selector correlations so a
/// delayed report cannot advance Q1/Q2 or make a terminal claim.
#[cfg(feature = "dw1e3-selector31")]
fn fail_closed_e3a_recovery<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
) -> bool
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let active = resident.wyr1c.as_ref().is_some_and(|state| {
        state.e3a_probe.is_some()
            || state.e3a_binding.is_some()
            || state.e3a_stream_generation.is_some()
    });
    if !active {
        return false;
    }
    let _probe_cleanup = reap_e3a_probe(resident, system, waits, false);
    let _driver_cleanup = if resident
        .wyr1c
        .as_ref()
        .is_some_and(|state| state.driver.is_some())
    {
        reap_driver(resident, system, waits, true).map(|_| ())
    } else {
        Ok(())
    };
    poison_e3a_lifecycle(resident);
    // The triggering registry/devmgr role is still owned by its recovery
    // caller. Leave a fatal-cleanup disposition for that caller to consume
    // both actor lifetimes before this resident can return.
    resident.result = RecoveryResult::Fatal;
    true
}

/// Selector-31 recovery is terminal when a Q1/Q2 correlation was active: no
/// replacement may inherit the poisoned state.  Consume both root actors even
/// if only one delivered the triggering failure, then permanently retire their
/// controller reservations without relaunching either role.
#[cfg(feature = "dw1e3-selector31")]
fn finish_e3a_fatal_recovery<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
) -> Result<(), InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let (registry, devmgr) = {
        let state = resident
            .wyr1c
            .as_mut()
            .ok_or(InitError::WrongActivationOrder)?;
        let registry = state.registry.take();
        let devmgr = state.devmgr.take();
        state.binding = None;
        state.waiting_registry_observed = false;
        (registry, devmgr)
    };
    resident.active[0] = None;
    resident.active[1] = None;
    let mut cleanup_failed = false;
    if let Some(devmgr) = devmgr {
        cleanup_failed |=
            cleanup_loaded(system, waits, devmgr.loaded, devmgr.task_group, true).is_err();
        cleanup_failed |= resident
            .controller
            .retire_attempt_after_fatal(RoleId::Devmgr)
            .is_err();
    }
    if let Some(registry) = registry {
        cleanup_failed |= cleanup_loaded(
            system,
            waits,
            registry.active.loaded,
            registry.active.task_group,
            true,
        )
        .is_err();
        cleanup_failed |= system.close_handle(registry.control_channel).is_err();
        cleanup_failed |= resident
            .controller
            .retire_attempt_after_fatal(RoleId::Registryd)
            .is_err();
    }
    resident.controller.fatal();
    resident.result = RecoveryResult::Fatal;
    if cleanup_failed {
        Err(InitError::Cleanup)
    } else {
        Ok(())
    }
}

/// A probe channel close or process exit is never a normal lifecycle edge.
/// Take both owned lifetimes down before returning failure so neither a stale
/// reporter nor a surviving driver can later advance the selector.
#[cfg(feature = "dw1e3-selector31")]
fn fail_e3a_probe_supervision<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
    validate_exit: bool,
) -> Result<(), InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let exit_error = if validate_exit {
        let probe = resident
            .wyr1c
            .as_ref()
            .and_then(|state| state.e3a_probe)
            .ok_or(InitError::WrongActivationOrder)?;
        match waits.query_task_termination(probe.loaded.process) {
            Ok(exit) => wyrmroot_runtime::validate_successful_exit(&exit)
                .map_err(|_| InitError::WrongManifestProfile)
                .err(),
            Err(error) => Some(InitError::Native(error)),
        }
    } else {
        None
    };
    let probe_cleanup = reap_e3a_probe(resident, system, waits, false);
    let driver_cleanup = reap_driver(resident, system, waits, true);
    if probe_cleanup.is_err() || driver_cleanup.is_err() {
        Err(InitError::Cleanup)
    } else {
        Err(exit_error.unwrap_or(InitError::WrongManifestProfile))
    }
}

#[cfg(any(feature = "wyr1c6-production", feature = "dw1e3-selector31"))]
fn acknowledge_driver_reaped<S: InitPlatform>(
    system: &mut S,
    devmgr: ActiveNativeRole,
    request: DriverLaunchRequest,
) -> Result<(), InitError> {
    let mut bytes = [0u8; wyrmroot_device_proto::driver_launch::REAPED_RESPONSE_BYTES];
    encode_reaped(request, &mut bytes).map_err(|_| InitError::WrongManifestProfile)?;
    system
        .send_channel(devmgr.loaded.launch_channel, &bytes)
        .map_err(InitError::Native)
}

fn expect_device_status<S, W>(
    system: &mut S,
    waits: &mut W,
    devmgr: ActiveNativeRole,
    binding: wyrmroot_device_proto::RegistryBinding,
    transaction_id: u64,
    expected_status: StatusCode,
) -> Result<(), InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let deadline = system
        .now()
        .map_err(InitError::Native)?
        .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .ok_or(InitError::Accounting)?;
    let observed = waits
        .wait_many(
            core::slice::from_ref(&DwWaitItemV1 {
                handle: devmgr.loaded.launch_channel,
                signals: DW_SIGNAL_READABLE,
            }),
            DwDeadline(deadline),
        )
        .map_err(InitError::Native)?;
    if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(InitError::Supervision);
    }
    let expected = ControllerMessage::Status {
        supervisor_generation: SupervisorGeneration(devmgr.generation),
        binding: Some(binding),
        transaction_id,
        status: expected_status,
        attempt_generation: None,
    };
    if receive_controller_status(system, devmgr.loaded.launch_channel)? != expected {
        return Err(InitError::WrongManifestProfile);
    }
    Ok(())
}

pub(crate) fn control_tick<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    now_ns: u64,
) -> Result<SystemMode, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    if now_ns < resident.last_tick_ns {
        resident.controller.fatal();
        resident.result = RecoveryResult::Fatal;
        return Err(InitError::WrongActivationOrder);
    }
    resident.last_tick_ns = now_ns;
    let state = resident
        .wyr1c
        .as_ref()
        .ok_or(InitError::WrongActivationOrder)?;
    let Some(devmgr) = state.devmgr else {
        resident.result = RecoveryResult::Degraded;
        return Ok(resident.controller.mode());
    };
    let mut items = [DwWaitItemV1::default(); 7];
    items[0] = DwWaitItemV1 {
        handle: devmgr.loaded.process,
        signals: DW_SIGNAL_EXITED,
    };
    items[1] = DwWaitItemV1 {
        handle: devmgr.loaded.launch_channel,
        signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
    };
    let registry_present = state.registry.is_some();
    let mut item_count = if let Some(registry) = state.registry {
        items[2] = DwWaitItemV1 {
            handle: registry.control_channel,
            signals: DW_SIGNAL_PEER_CLOSED,
        };
        items[3] = DwWaitItemV1 {
            handle: registry.active.loaded.process,
            signals: DW_SIGNAL_EXITED,
        };
        4
    } else {
        2
    };
    let driver_present = state.driver.is_some();
    if let Some(driver) = state.driver {
        items[item_count] = DwWaitItemV1 {
            handle: driver.loaded.process,
            signals: DW_SIGNAL_EXITED,
        };
        item_count += 1;
    }
    #[cfg(feature = "dw1e3-selector31")]
    if let Some(probe) = state.e3a_probe {
        items[item_count] = DwWaitItemV1 {
            handle: probe.loaded.launch_channel,
            signals: DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        };
        item_count += 1;
        items[item_count] = DwWaitItemV1 {
            handle: probe.loaded.process,
            signals: DW_SIGNAL_EXITED,
        };
        item_count += 1;
    }
    let observed = system.wait_many(&items[..item_count], DwDeadline(now_ns));
    match observed {
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {}
        Err(error) => return Err(InitError::Native(error)),
        Ok(result) => {
            let event = classify_resident_poll(
                result,
                registry_present,
                driver_present,
                #[cfg(feature = "dw1e3-selector31")]
                state.e3a_probe.is_some(),
            )?;
            let size = system
                .query_memory_object_size(resident.authority.bootfs)
                .map_err(InitError::Native)?;
            let plan = MappingPlan::for_bootfs(size).map_err(|error| {
                ordinary_mapping_error(MappingDiagnosticSite::RegistryReplacement, error, size)
            })?;
            system
                .with_bootfs_bytes(
                    resident.authority.parent_root,
                    resident.authority.bootfs,
                    plan,
                    |system, bootfs| match event {
                        ResidentPollEvent::DevmgrExited | ResidentPollEvent::DevmgrControlLost => {
                            recover_devmgr(resident, system, loader, waits, bootfs)
                        }
                        ResidentPollEvent::DevmgrControlReadable => {
                            let state = resident
                                .wyr1c
                                .as_ref()
                                .ok_or(InitError::WrongActivationOrder)?;
                            let devmgr = state.devmgr.ok_or(InitError::WrongActivationOrder)?;
                            match receive_devmgr_control(system, devmgr.loaded.launch_channel) {
                                #[cfg(feature = "dw1e3-selector31")]
                                Ok(DevmgrControlInput::TransportEmpty(fact)) => {
                                    let binding = resident
                                        .wyr1c
                                        .as_ref()
                                        .and_then(|state| state.e3a_binding)
                                        .ok_or(InitError::WrongActivationOrder)?;
                                    let duplicate = resident
                                        .wyr1c
                                        .as_ref()
                                        .ok_or(InitError::WrongActivationOrder)?
                                        .e3a_transport_empty
                                        .is_some();
                                    if duplicate {
                                        return Err(InitError::WrongManifestProfile);
                                    }
                                    exact_transport_empty(binding, fact)?;
                                    resident
                                        .wyr1c
                                        .as_mut()
                                        .ok_or(InitError::WrongActivationOrder)?
                                        .e3a_transport_empty = Some(fact);
                                    maybe_begin_e3a_retire(resident, system)
                                }
                                #[cfg(feature = "dw1e3-selector31")]
                                Ok(DevmgrControlInput::BindingReady(_binding)) => {
                                    Err(InitError::WrongManifestProfile)
                                }
                                #[cfg(feature = "dw1e3-selector31")]
                                Ok(DevmgrControlInput::RetireStage1Ready(binding)) => {
                                    let state = resident
                                        .wyr1c
                                        .as_mut()
                                        .ok_or(InitError::WrongActivationOrder)?;
                                    if !state.e3a_begin_retire_sent
                                        || state.e3a_stage1_ready
                                        || state.e3a_binding != Some(binding)
                                    {
                                        return Err(InitError::WrongManifestProfile);
                                    }
                                    state.e3a_stage1_ready = true;
                                    Ok(())
                                }
                                #[cfg(feature = "wyr1c6-selector29")]
                                Ok(DevmgrControlInput::C6Fact(fact)) => {
                                    accept_c6_fact(resident, fact)
                                }
                                Ok(DevmgrControlInput::Status(message)) => {
                                    let duplicate =
                                        state.registry.is_none() && state.waiting_registry_observed;
                                    let expected = ControllerMessage::Status {
                                        supervisor_generation: SupervisorGeneration(
                                            devmgr.generation,
                                        ),
                                        binding: None,
                                        transaction_id: state.last_controller_transaction,
                                        status: StatusCode::OperationalWaitingForRegistry,
                                        attempt_generation: None,
                                    };
                                    if duplicate || message != expected {
                                        return recover_devmgr_after_error(
                                            resident,
                                            system,
                                            loader,
                                            waits,
                                            bootfs,
                                            InitError::WrongManifestProfile,
                                        );
                                    }
                                    if state.registry.is_some() {
                                        recover_registry(
                                            resident, system, loader, waits, bootfs, true,
                                        )
                                    } else {
                                        resident
                                            .wyr1c
                                            .as_mut()
                                            .ok_or(InitError::WrongActivationOrder)?
                                            .waiting_registry_observed = true;
                                        Ok(())
                                    }
                                }
                                Ok(DevmgrControlInput::DriverLaunch {
                                    request,
                                    child_endpoint,
                                }) => {
                                    if let Err(error) = construct_driver(
                                        resident,
                                        system,
                                        loader,
                                        waits,
                                        bootfs,
                                        devmgr,
                                        request,
                                        child_endpoint,
                                    ) {
                                        recover_devmgr_after_error(
                                            resident, system, loader, waits, bootfs, error,
                                        )
                                    } else {
                                        #[cfg(feature = "dw1e3-selector31")]
                                        {
                                            start_e3a_probe(resident, system, loader, waits, bootfs)
                                        }
                                        #[cfg(not(feature = "dw1e3-selector31"))]
                                        {
                                            Ok(())
                                        }
                                    }
                                }
                                Ok(DevmgrControlInput::DriverRetired { bytes }) => {
                                    #[cfg(any(
                                        feature = "wyr1c6-production",
                                        feature = "dw1e3-selector31"
                                    ))]
                                    {
                                        let state = resident
                                            .wyr1c
                                            .as_ref()
                                            .ok_or(InitError::WrongActivationOrder)?;
                                        let request = state
                                            .last_reaped_driver
                                            .ok_or(InitError::WrongActivationOrder)?;
                                        parse_driver_retired(&bytes, request)
                                            .map_err(|_| InitError::WrongManifestProfile)?;
                                        rebind_publication(resident, system, waits)
                                    }
                                    #[cfg(not(any(
                                        feature = "wyr1c6-production",
                                        feature = "dw1e3-selector31"
                                    )))]
                                    {
                                        let _ = bytes;
                                        Err(InitError::WrongManifestProfile)
                                    }
                                }
                                Err(error) => recover_devmgr_after_error(
                                    resident, system, loader, waits, bootfs, error,
                                ),
                            }
                        }
                        ResidentPollEvent::RegistryLost => {
                            recover_registry(resident, system, loader, waits, bootfs, false)
                        }
                        ResidentPollEvent::DriverExited => {
                            #[cfg(feature = "dw1e3-selector31")]
                            if let Err(error) = validate_e3a_u1_finalize_exit(resident, waits) {
                                let driver_cleanup = reap_driver(resident, system, waits, false);
                                let probe_cleanup = reap_e3a_probe(resident, system, waits, false);
                                return Err(if driver_cleanup.is_err() || probe_cleanup.is_err() {
                                    InitError::Cleanup
                                } else {
                                    error
                                });
                            }
                            let _request = reap_driver(resident, system, waits, false)?;
                            #[cfg(feature = "dw1e3-selector31")]
                            reap_e3a_probe(resident, system, waits, true)?;
                            #[cfg(any(
                                feature = "wyr1c6-production",
                                feature = "dw1e3-selector31"
                            ))]
                            {
                                let state = resident
                                    .wyr1c
                                    .as_ref()
                                    .ok_or(InitError::WrongActivationOrder)?;
                                let devmgr = state.devmgr.ok_or(InitError::WrongActivationOrder)?;
                                acknowledge_driver_reaped(system, devmgr, _request)?;
                            }
                            Ok(())
                        }
                        #[cfg(feature = "dw1e3-selector31")]
                        ResidentPollEvent::ProbeControlReadable => {
                            let message = receive_e3a_probe_message(resident, system)?;
                            let binding = resident
                                .wyr1c
                                .as_ref()
                                .and_then(|state| state.e3a_binding)
                                .ok_or(InitError::WrongActivationOrder)?;
                            match message {
                                E3AControllerMessage::ResponseCommitted {
                                    nonce,
                                    publication_generation,
                                    stream_generation,
                                    challenge_generation,
                                    response_length,
                                    response_hash,
                                } => {
                                    let (expected_length, expected_hash) =
                                        exact_e3a_response(binding)?;
                                    let state = resident
                                        .wyr1c
                                        .as_mut()
                                        .ok_or(InitError::WrongActivationOrder)?;
                                    if state.e3a_response_committed
                                        || nonce != binding.nonce
                                        || publication_generation != binding.publication_generation
                                        || stream_generation != binding.stream_generation
                                        || challenge_generation != binding.challenge_generation
                                        || response_length != expected_length
                                        || response_hash != expected_hash
                                    {
                                        return Err(InitError::WrongManifestProfile);
                                    }
                                    state.e3a_response_committed = true;
                                    maybe_begin_e3a_retire(resident, system)
                                }
                                E3AControllerMessage::StreamPeerClosed {
                                    nonce,
                                    publication_generation,
                                    stream_generation,
                                    challenge_generation,
                                } => {
                                    let state = resident
                                        .wyr1c
                                        .as_ref()
                                        .ok_or(InitError::WrongActivationOrder)?;
                                    if !state.e3a_stage1_ready
                                        || !state.e3a_response_committed
                                        || state.e3a_peer_closed
                                        || nonce != binding.nonce
                                        || publication_generation != binding.publication_generation
                                        || stream_generation != binding.stream_generation
                                        || challenge_generation != binding.challenge_generation
                                    {
                                        return Err(InitError::WrongManifestProfile);
                                    }
                                    wyrmroot_runtime::dw1e3_report(
                                        wyrmroot_runtime::Dw1e3ReportEvent::Driver1PeerClosed,
                                        stream_generation,
                                        0,
                                        nonce,
                                    )
                                    .map_err(InitError::Native)?;
                                    resident
                                        .wyr1c
                                        .as_mut()
                                        .ok_or(InitError::WrongActivationOrder)?
                                        .e3a_peer_closed = true;
                                    send_e3a_finalize_retire(resident, system)
                                }
                                _ => Err(InitError::WrongManifestProfile),
                            }
                        }
                        #[cfg(feature = "dw1e3-selector31")]
                        ResidentPollEvent::ProbeControlLost => {
                            if e3a_u2_probe_may_exit(resident) {
                                match reap_e3a_u2_probe_after_response(resident, system, waits) {
                                    Ok(()) => Ok(()),
                                    Err(error) => {
                                        fail_e3a_u2_probe_exit(resident, system, waits, error)
                                    }
                                }
                            } else {
                                fail_e3a_probe_supervision(resident, system, waits, false)
                            }
                        }
                        #[cfg(feature = "dw1e3-selector31")]
                        ResidentPollEvent::ProbeExited => {
                            if e3a_u2_probe_may_exit(resident) {
                                match reap_e3a_u2_probe_after_response(resident, system, waits) {
                                    Ok(()) => Ok(()),
                                    Err(error) => {
                                        fail_e3a_u2_probe_exit(resident, system, waits, error)
                                    }
                                }
                            } else {
                                fail_e3a_probe_supervision(resident, system, waits, true)
                            }
                        }
                    },
                )
                .map_err(InitError::Native)??;
        }
    }
    Ok(resident.controller.mode())
}

fn recover_registry<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootfs: &[u8],
    status_already_consumed: bool,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    #[cfg(feature = "dw1e3-selector31")]
    if fail_closed_e3a_recovery(resident, system, waits) {
        return finish_e3a_fatal_recovery(resident, system, waits);
    }
    let registry = resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?
        .registry
        .take()
        .ok_or(InitError::WrongActivationOrder)?;
    resident.active[0] = None;
    resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?
        .binding = None;
    let exhausted =
        poison_registry_generation(system, waits, &mut resident.controller, registry, false)?;
    let step = registry_recovery_step(exhausted, status_already_consumed);
    match step {
        RegistryRecoveryStep::Degraded => {
            resident.result = RecoveryResult::Degraded;
            return Ok(());
        }
        RegistryRecoveryStep::Restart | RegistryRecoveryStep::AwaitStatus => {}
    }
    let replacement = launch_registry_until_ready(
        system,
        loader,
        waits,
        &mut resident.controller,
        resident.authority,
        bootfs,
    )?;
    let Some(replacement) = replacement else {
        resident.result = RecoveryResult::Degraded;
        return Ok(());
    };
    let replacement = restart_topology_or_poison(
        system,
        waits,
        &mut resident.controller,
        &mut resident
            .wyr1c
            .as_mut()
            .ok_or(InitError::WrongActivationOrder)?
            .topology,
        replacement,
    )?;
    resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?
        .registry = Some(replacement);
    resident.active[0] = Some(replacement.active);
    if step == RegistryRecoveryStep::AwaitStatus {
        let state = resident
            .wyr1c
            .as_ref()
            .ok_or(InitError::WrongActivationOrder)?;
        let devmgr = state.devmgr.ok_or(InitError::WrongActivationOrder)?;
        if let Err(error) = await_waiting_for_registry(
            system,
            waits,
            devmgr,
            devmgr.generation,
            state.last_controller_transaction,
        ) {
            return recover_devmgr_after_error(resident, system, loader, waits, bootfs, error);
        }
    }
    resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?
        .waiting_registry_observed = true;
    if let Err(error) = rebind_publication(resident, system, waits) {
        return recover_devmgr_after_error(resident, system, loader, waits, bootfs, error);
    }
    Ok(())
}

fn recover_devmgr_after_error<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootfs: &[u8],
    _error: InitError,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    recover_devmgr(resident, system, loader, waits, bootfs)
}

#[cfg(feature = "wyr1c6-selector29")]
fn selector29_restarting_d1(
    devmgr_generation: u64,
    active_driver: Option<DriverLaunchRequest>,
    last_reaped_driver: Option<DriverLaunchRequest>,
) -> bool {
    if devmgr_generation != wyrmroot_device_proto::SELECTOR29_FAILURE_SUPERVISOR_GENERATION {
        return false;
    }
    active_driver.or(last_reaped_driver).is_some_and(|request| {
        request.supervisor_generation.0
            == wyrmroot_device_proto::SELECTOR29_FAILURE_SUPERVISOR_GENERATION
            && request.attempt_generation.0
                > wyrmroot_device_proto::SELECTOR29_FAILURE_ATTEMPT_GENERATION
    })
}

#[cfg(feature = "wyr1c6-selector29")]
const fn selector29_terminal_fact_for_event(
    next: crate::wyr1c6_gate::GateEvent,
) -> Result<Option<u8>, InitError> {
    match next {
        crate::wyr1c6_gate::GateEvent::StaleReject => Ok(Some(13)),
        crate::wyr1c6_gate::GateEvent::D1Failure => Ok(Some(14)),
        crate::wyr1c6_gate::GateEvent::P2Retire => Ok(None),
        _ => Err(InitError::WrongManifestProfile),
    }
}

#[cfg(feature = "wyr1c6-selector29")]
fn selector29_next_d1_terminal_fact(
    resident: &ResidentSystemInit,
) -> Result<Option<u8>, InitError> {
    let next = resident
        .wyr1c
        .as_ref()
        .and_then(|state| state.c6_evidence.as_ref())
        .and_then(crate::wyr1c6_gate::EvidenceLog::next_expected_event)
        .ok_or(InitError::WrongActivationOrder)?;
    selector29_terminal_fact_for_event(next)
}

#[cfg(feature = "wyr1c6-selector29")]
fn drain_selector29_d1_terminal_facts<S: InitPlatform>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    devmgr: ActiveNativeRole,
) -> Result<(), InitError> {
    while let Some(expected) = selector29_next_d1_terminal_fact(resident)? {
        match receive_devmgr_control(system, devmgr.loaded.launch_channel)? {
            DevmgrControlInput::C6Fact(fact) if fact.event == expected => {
                accept_c6_fact(resident, fact)?;
            }
            _ => return Err(InitError::WrongManifestProfile),
        }
    }
    Ok(())
}

fn recover_devmgr<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootfs: &[u8],
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    #[cfg(feature = "dw1e3-selector31")]
    if fail_closed_e3a_recovery(resident, system, waits) {
        return finish_e3a_fatal_recovery(resident, system, waits);
    }
    #[cfg(feature = "wyr1c6-selector29")]
    let restarting_d1 = {
        let state = resident
            .wyr1c
            .as_ref()
            .ok_or(InitError::WrongActivationOrder)?;
        selector29_restarting_d1(
            state
                .devmgr
                .map(|devmgr| devmgr.generation)
                .unwrap_or_default(),
            state.driver.map(|driver| driver.request),
            state.last_reaped_driver,
        )
    };
    #[cfg(feature = "wyr1c6-selector29")]
    if restarting_d1 {
        let devmgr = resident
            .wyr1c
            .as_ref()
            .and_then(|state| state.devmgr)
            .ok_or(InitError::WrongActivationOrder)?;
        // D1 sends the final stale-rejection and failure facts immediately
        // before exiting. A process-exit wait may win over the readable launch
        // channel, so drain those already-buffered facts before synthesizing
        // P2 retirement and U2 reap evidence.
        drain_selector29_d1_terminal_facts(resident, system, devmgr)?;
    }
    if resident
        .wyr1c
        .as_ref()
        .is_some_and(|state| state.driver.is_some())
        && reap_driver(resident, system, waits, true).is_err()
    {
        resident.result = RecoveryResult::Degraded;
        return Err(InitError::Cleanup);
    }
    #[cfg(feature = "wyr1c6-selector29")]
    if restarting_d1 {
        let (lease, p2_binding, p2_attempt, p2_endpoint, irq, u2_attempt, u2_endpoint) = {
            let state = resident
                .wyr1c
                .as_ref()
                .ok_or(InitError::WrongActivationOrder)?;
            (
                state.c6_d1_lease.ok_or(InitError::WrongActivationOrder)?,
                if state.c6_p2_service_generation == 0 {
                    return Err(InitError::WrongActivationOrder);
                } else {
                    state.c6_p2_service_generation
                },
                state.c6_u2_attempt.ok_or(InitError::WrongActivationOrder)?,
                if state.c6_p2_endpoint_generation == 0 {
                    return Err(InitError::WrongActivationOrder);
                } else {
                    state.c6_p2_endpoint_generation
                },
                state.c6_u2_irq.ok_or(InitError::WrongActivationOrder)?,
                state.c6_u2_attempt.ok_or(InitError::WrongActivationOrder)?,
                state
                    .c6_u2_endpoint
                    .ok_or(InitError::WrongActivationOrder)?,
            )
        };
        accept_c6_fact(
            resident,
            C6Fact {
                event: 15,
                lease,
                binding: p2_binding,
                value: p2_attempt,
                aux: p2_endpoint,
            },
        )?;
        accept_c6_fact(
            resident,
            C6Fact {
                event: 16,
                lease,
                binding: irq,
                value: u2_attempt,
                aux: u2_endpoint,
            },
        )?;
    }
    let active = resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?
        .devmgr
        .take()
        .ok_or(InitError::WrongActivationOrder)?;
    resident.active[1] = None;
    {
        let state = resident
            .wyr1c
            .as_mut()
            .ok_or(InitError::WrongActivationOrder)?;
        state.binding = None;
        state.waiting_registry_observed = false;
    }
    let now = system.now().map_err(InitError::Native)?;
    let transition = resident.controller.fail(
        RoleId::Devmgr,
        active.generation,
        active.transaction_id,
        now,
        AttemptFailure::WaitFailed,
    );
    let cleanup_failed =
        cleanup_loaded(system, waits, active.loaded, active.task_group, true).is_err();
    if let Err(error) = transition {
        let disposition = if cleanup_failed {
            CleanupDisposition::Failed
        } else {
            CleanupDisposition::Complete
        };
        resident.controller.retire_active_fail_closed(
            RoleId::Devmgr,
            active.generation,
            active.transaction_id,
            now,
            AttemptFailure::WaitFailed,
            disposition,
        )?;
        resident.result = RecoveryResult::Degraded;
        return if cleanup_failed {
            Err(InitError::Cleanup)
        } else {
            Err(error)
        };
    }
    let retired_at = now.checked_add(1).ok_or(InitError::Accounting)?;
    if cleanup_failed {
        resident.controller.cleanup_failed(
            RoleId::Devmgr,
            active.generation,
            active.transaction_id,
            retired_at,
        )?;
        resident.result = RecoveryResult::Degraded;
        return Ok(());
    }
    resident.controller.cleanup_complete(
        RoleId::Devmgr,
        active.generation,
        active.transaction_id,
        retired_at,
    )?;
    #[cfg(feature = "wyr1c6-selector29")]
    if restarting_d1 {
        let lease = resident
            .wyr1c
            .as_ref()
            .and_then(|state| state.c6_d1_lease)
            .ok_or(InitError::WrongActivationOrder)?;
        accept_c6_fact(
            resident,
            C6Fact {
                event: 17,
                lease,
                binding: 0,
                value: active.generation,
                aux: 1,
            },
        )?;
    }
    if advance_or_degrade(
        system,
        &mut resident.controller,
        RoleId::Devmgr,
        active.transaction_id,
    )? {
        resident.result = RecoveryResult::Degraded;
        return Ok(());
    }
    launch_devmgr_replacement(resident, system, loader, waits, bootfs)
}

fn launch_devmgr_replacement<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootfs: &[u8],
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let manifest_entry = Archive::new(bootfs)
        .map_err(InitError::Bootfs)?
        .lookup(DEVICE_MANIFEST_PATH.as_bytes())
        .map_err(map_lookup)?;
    loop {
        let attempt_transaction = match resident
            .controller
            .role_state(RoleId::Devmgr)
            .ok_or(InitError::WrongActivationOrder)?
        {
            RestartState::Starting { transaction_id, .. } => transaction_id,
            _ => return Err(InitError::WrongActivationOrder),
        };
        let registry = resident.wyr1c.as_ref().and_then(|state| state.registry);
        let resource_domain = resident
            .wyr1c
            .as_ref()
            .and_then(|state| state.resource_domain);
        let Some(registry) = registry else {
            resident.result = RecoveryResult::Degraded;
            return Ok(());
        };
        let attempt = {
            let state = resident
                .wyr1c
                .as_mut()
                .ok_or(InitError::WrongActivationOrder)?;
            launch_devmgr(
                system,
                loader,
                waits,
                &mut resident.controller,
                resident.authority,
                resource_domain,
                bootfs,
                registry,
                &mut state.topology,
                &mut state.publication_allocator,
                manifest_entry.data(),
            )
        };
        match attempt {
            Ok(attempt) => {
                let state = resident
                    .wyr1c
                    .as_mut()
                    .ok_or(InitError::WrongActivationOrder)?;
                state.devmgr = Some(attempt.active);
                state.binding = Some(attempt.binding);
                state.publication_service_generation = attempt.publication_service_generation;
                state.last_controller_transaction = attempt.last_controller_transaction;
                state.next_controller_transaction = attempt.next_controller_transaction;
                state.waiting_registry_observed = false;
                resident.active[1] = Some(attempt.active);
                return Ok(());
            }
            Err(error) => {
                let (generation, transaction_id) = match resident
                    .controller
                    .role_state(RoleId::Devmgr)
                    .ok_or(InitError::WrongActivationOrder)?
                {
                    RestartState::Starting {
                        generation,
                        transaction_id,
                        ..
                    } => (generation, transaction_id),
                    RestartState::Backoff { .. } => {
                        if advance_or_degrade(
                            system,
                            &mut resident.controller,
                            RoleId::Devmgr,
                            attempt_transaction,
                        )? {
                            resident.result = RecoveryResult::Degraded;
                            return Ok(());
                        }
                        continue;
                    }
                    RestartState::PermanentFailure { .. } => {
                        resident.result = RecoveryResult::Degraded;
                        return Ok(());
                    }
                    _ => return Err(error),
                };
                let failed_at = system.now().map_err(InitError::Native)?;
                resident.controller.fail(
                    RoleId::Devmgr,
                    generation,
                    transaction_id,
                    failed_at,
                    AttemptFailure::CreationFailed,
                )?;
                resident.controller.cleanup_complete(
                    RoleId::Devmgr,
                    generation,
                    transaction_id,
                    failed_at.checked_add(1).ok_or(InitError::Accounting)?,
                )?;
                if advance_or_degrade(
                    system,
                    &mut resident.controller,
                    RoleId::Devmgr,
                    transaction_id,
                )? {
                    resident.result = RecoveryResult::Degraded;
                    return Ok(());
                }
            }
        }
    }
}

fn rebind_publication<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let state = resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?;
    let registry = state.registry.ok_or(InitError::WrongActivationOrder)?;
    let devmgr = state.devmgr.ok_or(InitError::WrongActivationOrder)?;
    let (binding, publication_service_generation, transaction_id) = perform_rebind(
        system,
        waits,
        &mut state.topology,
        &mut state.publication_allocator,
        registry.control_channel,
        devmgr,
        state.next_controller_transaction,
    )?;
    state.binding = Some(binding);
    state.publication_service_generation = publication_service_generation;
    state.waiting_registry_observed = false;
    state.last_controller_transaction = transaction_id;
    state.next_controller_transaction =
        transaction_id.checked_add(1).ok_or(InitError::Accounting)?;
    Ok(())
}

fn perform_rebind<S, W>(
    system: &mut S,
    waits: &mut W,
    topology: &mut RegistryTopology,
    publication_allocator: &mut PublicationAllocator,
    registry_control: DwHandle,
    devmgr: ActiveNativeRole,
    transaction_id: u64,
) -> Result<(wyrmroot_device_proto::RegistryBinding, u64, u64), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let grant = topology
        .issue(devmgr.generation, EndpointKind::Publication)
        .map_err(InitError::Wyr1BModel)?;
    let publication = publication_allocator.issue()?;
    let binding = wyrmroot_device_proto::RegistryBinding {
        generation: RegistryGeneration(grant.registry_generation),
        endpoint: RegistryEndpoint {
            id: RegistryEndpointId(grant.endpoint_id),
            generation: RegistryEndpointGeneration(grant.endpoint_generation),
        },
    };
    let (registry_endpoint, devmgr_endpoint) = create_controller_channel_pair(system)?;
    if let Err(error) = install_publication(
        system,
        registry_control,
        grant,
        publication,
        registry_endpoint,
    ) {
        let cleanup_failed = system.close_handle(devmgr_endpoint).is_err()
            | system.close_handle(registry_endpoint).is_err();
        return Err(if cleanup_failed {
            InitError::Cleanup
        } else {
            error
        });
    }
    let request = ControllerMessage::RebindPublication {
        supervisor_generation: SupervisorGeneration(devmgr.generation),
        binding,
        transaction_id,
    };
    let mut bytes = [0u8; wyrmroot_device_proto::controller::INSTALL_BYTES];
    if encode_controller(request, &mut bytes).is_err() {
        return Err(if system.close_handle(devmgr_endpoint).is_err() {
            InitError::Cleanup
        } else {
            InitError::WrongManifestProfile
        });
    }
    let transfer = DwHandleTransferV1 {
        handle: devmgr_endpoint,
        requested_rights: wyrmroot_loader::launch::CHILD_CHANNEL_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if let Err(error) = system
        .send_channel_with_handles(
            devmgr.loaded.launch_channel,
            &bytes,
            core::slice::from_ref(&transfer),
        )
        .map_err(InitError::Native)
    {
        let cleanup_failed = system.close_handle(devmgr_endpoint).is_err();
        return Err(if cleanup_failed {
            InitError::Cleanup
        } else {
            error
        });
    }
    expect_device_status(
        system,
        waits,
        devmgr,
        binding,
        transaction_id,
        StatusCode::OperationalWaitingForDeviceBundle,
    )?;
    Ok((binding, publication.service_generation, transaction_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use deepwyrm_syscall::{DW_SIGNAL_EXITED, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DwStatus};
    use wyrmroot_device_proto::manifest::{
        HEADER_BYTES as WRDM_HEADER_BYTES, MAGIC as WRDM_MAGIC, MAJOR as WRDM_MAJOR,
        MINOR as WRDM_MINOR, PROFILE_Q35, PROFILE_Q35_VERSION, RECORD_BYTES as WRDM_RECORD_BYTES,
        UART16550D_PATH,
    };

    const FAILURE: NativeError = NativeError::Status(DwStatus(-1));

    struct RebindPlatform {
        inbound: [u8; wyrmroot_device_proto::controller::STATUS_BYTES],
        inbound_len: usize,
        send_count: usize,
        fail_send_at: usize,
        closed: [DwHandle; 4],
        close_count: usize,
    }

    impl RebindPlatform {
        fn with_status(message: ControllerMessage) -> Self {
            let mut inbound = [0; wyrmroot_device_proto::controller::STATUS_BYTES];
            encode_controller(message, &mut inbound).unwrap();
            Self {
                inbound,
                inbound_len: wyrmroot_device_proto::controller::STATUS_BYTES,
                send_count: 0,
                fail_send_at: usize::MAX,
                closed: [DwHandle(0); 4],
                close_count: 0,
            }
        }
    }

    impl InitPlatform for RebindPlatform {
        fn query_capability_info(
            &mut self,
            _handle: DwHandle,
        ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
            Err(FAILURE)
        }

        fn receive_channel(
            &mut self,
            _channel: DwHandle,
            bytes: &mut [u8],
            _handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, NativeError> {
            if self.inbound_len == 0 {
                return Err(FAILURE);
            }
            bytes[..self.inbound_len].copy_from_slice(&self.inbound[..self.inbound_len]);
            let counts = ReceiveCounts {
                bytes: self.inbound_len,
                handles: 0,
            };
            self.inbound_len = 0;
            Ok(counts)
        }

        fn query_memory_object_size(&mut self, _handle: DwHandle) -> Result<u64, NativeError> {
            Err(FAILURE)
        }

        fn with_bootfs_bytes<R>(
            &mut self,
            _root: DwHandle,
            _bootfs: DwHandle,
            _plan: MappingPlan,
            _use_bytes: impl for<'a> FnOnce(&mut Self, &'a [u8]) -> R,
        ) -> Result<R, NativeError> {
            Err(FAILURE)
        }

        fn send_channel(&mut self, _channel: DwHandle, _bytes: &[u8]) -> Result<(), NativeError> {
            Err(FAILURE)
        }

        fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
            self.closed[self.close_count] = handle;
            self.close_count += 1;
            Ok(())
        }

        fn create_attempt_task_group(
            &mut self,
            _parent: DwHandle,
        ) -> Result<DwHandle, NativeError> {
            Err(FAILURE)
        }

        fn terminate_task_group(&mut self, _task_group: DwHandle) -> Result<(), NativeError> {
            Err(FAILURE)
        }

        fn now(&mut self) -> Result<u64, NativeError> {
            Ok(100)
        }

        fn wait_until(&mut self, _deadline_ns: u64) -> Result<(), NativeError> {
            Err(FAILURE)
        }
    }

    impl Wyr1BPlatform for RebindPlatform {
        fn channel_create(
            &mut self,
            _rights: DwRights,
        ) -> Result<(DwHandle, DwHandle), NativeError> {
            Ok((DwHandle(50), DwHandle(51)))
        }

        fn send_channel_with_handles(
            &mut self,
            _channel: DwHandle,
            _bytes: &[u8],
            _transfers: &[DwHandleTransferV1],
        ) -> Result<(), NativeError> {
            self.send_count += 1;
            if self.send_count == self.fail_send_at {
                Err(FAILURE)
            } else {
                Ok(())
            }
        }

        fn wait_many(
            &mut self,
            _items: &[DwWaitItemV1],
            _deadline: DwDeadline,
        ) -> Result<DwWaitResultV1, NativeError> {
            Err(FAILURE)
        }

        fn materialize_read_only_memory(
            &mut self,
            _root: DwHandle,
            _bytes: &[u8],
            _rights: DwRights,
        ) -> Result<DwHandle, NativeError> {
            Err(FAILURE)
        }
    }

    struct StatusWaits {
        fail: bool,
    }

    impl SupervisionPlatform for StatusWaits {
        type Error = NativeError;

        fn wait_many(
            &mut self,
            _items: &[DwWaitItemV1],
            _deadline: DwDeadline,
        ) -> Result<DwWaitResultV1, Self::Error> {
            if self.fail {
                Err(FAILURE)
            } else {
                Ok(DwWaitResultV1 {
                    index: 0,
                    observed: DW_SIGNAL_READABLE,
                    ..DwWaitResultV1::default()
                })
            }
        }

        fn receive_channel(
            &mut self,
            _channel: DwHandle,
            _bytes: &mut [u8],
            _handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, Self::Error> {
            Err(FAILURE)
        }

        fn query_task_termination(
            &mut self,
            _process: DwHandle,
        ) -> Result<DwTaskTerminationInfoV1, Self::Error> {
            Err(FAILURE)
        }
    }

    const fn devmgr() -> ActiveNativeRole {
        ActiveNativeRole {
            role: RoleId::Devmgr,
            generation: 7,
            transaction_id: 8,
            loaded: LoadedProcess {
                process: DwHandle(20),
                launch_channel: DwHandle(30),
            },
            task_group: DwHandle(10),
        }
    }

    fn binding() -> wyrmroot_device_proto::RegistryBinding {
        wyrmroot_device_proto::RegistryBinding {
            generation: RegistryGeneration(2),
            endpoint: RegistryEndpoint {
                id: RegistryEndpointId(1),
                generation: RegistryEndpointGeneration(1),
            },
        }
    }

    fn rebound_binding() -> wyrmroot_device_proto::RegistryBinding {
        wyrmroot_device_proto::RegistryBinding {
            generation: RegistryGeneration(2),
            endpoint: RegistryEndpoint {
                id: RegistryEndpointId(2),
                generation: RegistryEndpointGeneration(1),
            },
        }
    }

    fn waiting_device_status() -> ControllerMessage {
        ControllerMessage::Status {
            supervisor_generation: SupervisorGeneration(7),
            binding: Some(binding()),
            transaction_id: 9,
            status: StatusCode::OperationalWaitingForDeviceBundle,
            attempt_generation: None,
        }
    }

    #[test]
    fn successful_rebind_preserves_devmgr_generation_and_commits_correlation() {
        let status = ControllerMessage::Status {
            supervisor_generation: SupervisorGeneration(7),
            binding: Some(rebound_binding()),
            transaction_id: 9,
            status: StatusCode::OperationalWaitingForDeviceBundle,
            attempt_generation: None,
        };
        let mut platform = RebindPlatform::with_status(status);
        let mut waits = StatusWaits { fail: false };
        let mut topology = RegistryTopology::new(2).unwrap();
        let initial_grant = topology.issue(7, EndpointKind::Publication).unwrap();
        assert_eq!(initial_grant.endpoint_id, 1);
        let mut publications = PublicationAllocator::new();
        let initial_publication = publications.issue().unwrap();
        let result = perform_rebind(
            &mut platform,
            &mut waits,
            &mut topology,
            &mut publications,
            DwHandle(40),
            devmgr(),
            9,
        )
        .unwrap();
        assert_eq!(result.0, rebound_binding());
        assert!(result.1 > initial_publication.service_generation);
        assert_eq!(result.2, 9);
        assert_eq!(platform.send_count, 2);
        assert_eq!(platform.close_count, 0);
        assert_eq!(devmgr().generation, 7);
    }

    #[test]
    fn failed_rebind_send_closes_only_the_unmoved_devmgr_endpoint() {
        let mut platform = RebindPlatform::with_status(waiting_device_status());
        platform.fail_send_at = 2;
        let error = perform_rebind(
            &mut platform,
            &mut StatusWaits { fail: false },
            &mut RegistryTopology::new(2).unwrap(),
            &mut PublicationAllocator::new(),
            DwHandle(40),
            devmgr(),
            9,
        )
        .unwrap_err();
        assert_eq!(error, InitError::Native(FAILURE));
        assert_eq!(&platform.closed[..platform.close_count], &[DwHandle(51)]);
    }

    #[test]
    fn failed_rebind_status_is_reported_after_both_moves_commit() {
        let mut platform = RebindPlatform::with_status(waiting_device_status());
        let error = perform_rebind(
            &mut platform,
            &mut StatusWaits { fail: true },
            &mut RegistryTopology::new(2).unwrap(),
            &mut PublicationAllocator::new(),
            DwHandle(40),
            devmgr(),
            9,
        )
        .unwrap_err();
        assert_eq!(error, InitError::Native(FAILURE));
        assert_eq!(platform.send_count, 2);
        assert_eq!(platform.close_count, 0);
    }

    #[test]
    fn publication_peer_close_status_requires_exact_generation_and_transaction() {
        let message = ControllerMessage::Status {
            supervisor_generation: SupervisorGeneration(7),
            binding: None,
            transaction_id: 8,
            status: StatusCode::OperationalWaitingForRegistry,
            attempt_generation: None,
        };
        let mut platform = RebindPlatform::with_status(message);
        receive_waiting_for_registry(&mut platform, devmgr(), 7, 8).unwrap();

        let mut stale = RebindPlatform::with_status(message);
        assert_eq!(
            receive_waiting_for_registry(&mut stale, devmgr(), 7, 9),
            Err(InitError::WrongManifestProfile)
        );
    }

    #[test]
    fn resident_poll_distinguishes_devmgr_and_registry_failures() {
        let event = |index, observed| {
            classify_resident_poll(
                DwWaitResultV1 {
                    index,
                    observed,
                    ..DwWaitResultV1::default()
                },
                true,
                false,
            )
            .unwrap()
        };
        assert_eq!(event(0, DW_SIGNAL_EXITED), ResidentPollEvent::DevmgrExited);
        assert_eq!(
            event(1, DW_SIGNAL_PEER_CLOSED),
            ResidentPollEvent::DevmgrControlLost
        );
        assert_eq!(
            event(1, DW_SIGNAL_READABLE),
            ResidentPollEvent::DevmgrControlReadable
        );
        assert_eq!(
            event(2, DW_SIGNAL_PEER_CLOSED),
            ResidentPollEvent::RegistryLost
        );
        assert_eq!(event(3, DW_SIGNAL_EXITED), ResidentPollEvent::RegistryLost);
    }

    #[test]
    fn registry_exhaustion_enters_degraded_without_a_stale_status_wait() {
        assert_eq!(
            registry_recovery_step(true, false),
            RegistryRecoveryStep::Degraded
        );
        assert_eq!(
            registry_recovery_step(false, false),
            RegistryRecoveryStep::AwaitStatus
        );
        assert_eq!(
            registry_recovery_step(false, true),
            RegistryRecoveryStep::Restart
        );
    }

    #[test]
    fn publication_correlations_advance_across_devmgr_and_registry_recovery() {
        let mut allocator = PublicationAllocator::new();
        let initial = allocator.issue().unwrap();
        let after_devmgr_exit = allocator.issue().unwrap();
        let after_registry_exit = allocator.issue().unwrap();

        assert!(after_devmgr_exit.publication_id > initial.publication_id);
        assert!(after_devmgr_exit.service_generation > initial.service_generation);
        assert!(after_devmgr_exit.transaction_id > initial.transaction_id);
        assert!(after_registry_exit.publication_id > after_devmgr_exit.publication_id);
        assert!(after_registry_exit.service_generation > after_devmgr_exit.service_generation);
        assert!(after_registry_exit.transaction_id > after_devmgr_exit.transaction_id);
        assert_ne!(initial.publication_id, initial.service_generation);
        assert_ne!(initial.publication_id, initial.transaction_id);
        assert_ne!(initial.service_generation, initial.transaction_id);
    }

    #[cfg(feature = "wyr1c6-selector29")]
    #[test]
    fn c6_publication_records_use_service_generation_not_registry_generation() {
        let registry_generation = 7;
        let p1_service_generation = 0xC1_0801;
        let p2_service_generation = 0xC1_0802;

        assert_eq!(
            c6_evidence_binding(5, registry_generation, p1_service_generation, 0, 0),
            p1_service_generation
        );
        assert_eq!(
            c6_evidence_binding(
                7,
                registry_generation,
                p2_service_generation,
                p1_service_generation,
                0,
            ),
            p1_service_generation
        );
        assert_eq!(
            c6_evidence_binding(
                12,
                registry_generation,
                p2_service_generation,
                p1_service_generation,
                0,
            ),
            p2_service_generation
        );
        assert_eq!(
            c6_evidence_binding(
                14,
                registry_generation,
                p2_service_generation,
                p1_service_generation,
                p2_service_generation,
            ),
            p2_service_generation
        );
        assert!(p2_service_generation > p1_service_generation);
        assert_ne!(p1_service_generation, registry_generation);
    }

    fn wrdm(identity: [u8; 32]) -> [u8; WRDM_HEADER_BYTES + WRDM_RECORD_BYTES] {
        let mut out = [0; WRDM_HEADER_BYTES + WRDM_RECORD_BYTES];
        out[..4].copy_from_slice(&WRDM_MAGIC);
        out[4..6].copy_from_slice(&WRDM_MAJOR.to_le_bytes());
        out[6..8].copy_from_slice(&WRDM_MINOR.to_le_bytes());
        let total = out.len() as u32;
        out[8..12].copy_from_slice(&total.to_le_bytes());
        out[12..14].copy_from_slice(&1u16.to_le_bytes());
        out[16..20].copy_from_slice(&PROFILE_Q35.0.to_le_bytes());
        out[20..24].copy_from_slice(&PROFILE_Q35_VERSION.0.to_le_bytes());
        let base = WRDM_HEADER_BYTES;
        out[base..base + 8].copy_from_slice(&1u64.to_le_bytes());
        out[base + 8..base + 12].copy_from_slice(&2u32.to_le_bytes());
        out[base + 12..base + 16].copy_from_slice(&1u32.to_le_bytes());
        out[base + 16..base + 18].copy_from_slice(&0x2f8u16.to_le_bytes());
        out[base + 18..base + 20].copy_from_slice(&8u16.to_le_bytes());
        out[base + 20..base + 24].copy_from_slice(&3u32.to_le_bytes());
        out[base + 24..base + 26].copy_from_slice(&(UART16550D_PATH.len() as u16).to_le_bytes());
        out[base + 28..base + 60].copy_from_slice(&identity);
        out[base + 60..base + 64].copy_from_slice(&1u32.to_le_bytes());
        out[base + 72..base + 72 + UART16550D_PATH.len()].copy_from_slice(UART16550D_PATH);
        out
    }

    #[test]
    fn wrdm_uart_identity_must_match_the_independent_wrrm_identity() {
        let bytes = wrdm([7; 32]);
        let manifest = DeviceManifest::parse(&bytes).unwrap();
        validate_device_identity(manifest, [7; 32]).unwrap();
        assert_eq!(
            validate_device_identity(manifest, [8; 32]),
            Err(InitError::WrongManifestProfile)
        );
    }

    struct ControlInputPlatform {
        inbound: [u8; LAUNCH_REQUEST_BYTES],
        inbound_len: usize,
        received: DwReceivedHandleInfoV1,
        received_count: usize,
        queried: CapabilityInfo<DwObjectType, DwRights>,
        closed: Option<DwHandle>,
    }

    impl InitPlatform for ControlInputPlatform {
        fn query_capability_info(
            &mut self,
            _handle: DwHandle,
        ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
            Ok(self.queried)
        }
        fn receive_channel(
            &mut self,
            _channel: DwHandle,
            bytes: &mut [u8],
            handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, NativeError> {
            bytes[..self.inbound_len].copy_from_slice(&self.inbound[..self.inbound_len]);
            if self.received_count == 1 {
                handles[0] = self.received;
            }
            Ok(ReceiveCounts {
                bytes: self.inbound_len,
                handles: self.received_count,
            })
        }
        fn query_memory_object_size(&mut self, _handle: DwHandle) -> Result<u64, NativeError> {
            Err(FAILURE)
        }
        fn with_bootfs_bytes<R>(
            &mut self,
            _root: DwHandle,
            _bootfs: DwHandle,
            _plan: MappingPlan,
            _use_bytes: impl for<'a> FnOnce(&mut Self, &'a [u8]) -> R,
        ) -> Result<R, NativeError> {
            Err(FAILURE)
        }
        fn send_channel(&mut self, _channel: DwHandle, _bytes: &[u8]) -> Result<(), NativeError> {
            Err(FAILURE)
        }
        fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
            self.closed = Some(handle);
            Ok(())
        }
        fn create_attempt_task_group(
            &mut self,
            _parent: DwHandle,
        ) -> Result<DwHandle, NativeError> {
            Err(FAILURE)
        }
        fn terminate_task_group(&mut self, _task_group: DwHandle) -> Result<(), NativeError> {
            Err(FAILURE)
        }
        fn now(&mut self) -> Result<u64, NativeError> {
            Err(FAILURE)
        }
        fn wait_until(&mut self, _deadline_ns: u64) -> Result<(), NativeError> {
            Err(FAILURE)
        }
    }

    fn driver_request() -> DriverLaunchRequest {
        DriverLaunchRequest {
            supervisor_generation: SupervisorGeneration(7),
            role_id: COM2_ROLE_ID,
            attempt_generation: wyrmroot_device_proto::coordinator::AttemptGeneration(1),
            launch_session: wyrmroot_device_proto::coordinator::LaunchSessionGeneration(2),
            endpoint: wyrmroot_device_proto::ControlEndpoint {
                id: wyrmroot_device_proto::coordinator::EndpointId(3),
                generation: wyrmroot_device_proto::coordinator::EndpointGeneration(1),
            },
            transaction_id: 9,
            driver_path: wyrmroot_device_proto::DEVICE_DRIVER_PATH,
            actor_identity: ContentIdentity([0x5a; 32]),
            child_is_channel: true,
            child_rights: wyrmroot_device_proto::DirectControlRights::ExactReduced,
        }
    }

    fn control_input_platform(request: DriverLaunchRequest) -> ControlInputPlatform {
        let mut inbound = [0u8; LAUNCH_REQUEST_BYTES];
        wyrmroot_device_proto::encode_request(request, &mut inbound).unwrap();
        ControlInputPlatform {
            inbound,
            inbound_len: LAUNCH_REQUEST_BYTES,
            received: DwReceivedHandleInfoV1 {
                handle: DwHandle(91),
                object_type: DW_OBJECT_TYPE_CHANNEL,
                rights: DRIVER_CONTROL_INGRESS_RIGHTS,
                reserved0: 0,
                reserved: [0; 2],
            },
            received_count: 1,
            queried: CapabilityInfo {
                object_type: DW_OBJECT_TYPE_CHANNEL,
                rights: DRIVER_CONTROL_INGRESS_RIGHTS,
            },
            closed: None,
        }
    }

    #[test]
    fn native_driver_request_dispatch_moves_exactly_one_reduced_channel() {
        let request = driver_request();
        let mut platform = control_input_platform(request);
        assert_eq!(
            receive_devmgr_control(&mut platform, DwHandle(12)).unwrap(),
            DevmgrControlInput::DriverLaunch {
                request,
                child_endpoint: DwHandle(91),
            }
        );
        assert_eq!(platform.closed, None);
    }

    #[cfg(feature = "wyr1c5-production")]
    #[test]
    fn native_driver_request_requires_transfer_staging_before_actor_reduction() {
        assert_eq!(DRIVER_CONTROL_INGRESS_RIGHTS.0, 0x193);
        assert_eq!(CHILD_CHANNEL_RIGHTS.0, 0x113);
        assert_ne!(
            DRIVER_CONTROL_INGRESS_RIGHTS.0 & deepwyrm_syscall::DW_RIGHT_TRANSFER.0,
            0
        );

        let mut final_actor_rights_are_not_staging = control_input_platform(driver_request());
        final_actor_rights_are_not_staging.received.rights = CHILD_CHANNEL_RIGHTS;
        final_actor_rights_are_not_staging.queried.rights = CHILD_CHANNEL_RIGHTS;
        assert_eq!(
            receive_devmgr_control(&mut final_actor_rights_are_not_staging, DwHandle(12)),
            Err(InitError::ResourceIdentityMismatch)
        );
        assert_eq!(
            final_actor_rights_are_not_staging.closed,
            Some(DwHandle(91))
        );
    }

    #[test]
    fn native_driver_request_rejects_wrong_received_type_or_rights() {
        let mut wrong_rights = control_input_platform(driver_request());
        wrong_rights.received.rights = DEVICE_MANIFEST_RIGHTS;
        assert_eq!(
            receive_devmgr_control(&mut wrong_rights, DwHandle(12)),
            Err(InitError::ResourceIdentityMismatch)
        );
        assert_eq!(wrong_rights.closed, Some(DwHandle(91)));

        let mut wrong_type = control_input_platform(driver_request());
        wrong_type.received.object_type = deepwyrm_syscall::DW_OBJECT_TYPE_MEMORY_OBJECT;
        assert_eq!(
            receive_devmgr_control(&mut wrong_type, DwHandle(12)),
            Err(InitError::ResourceIdentityMismatch)
        );
        assert_eq!(wrong_type.closed, Some(DwHandle(91)));
    }

    #[test]
    fn native_driver_correlation_rejects_replay_and_supervisor_replacement() {
        let request = driver_request();
        assert!(driver_correlation_is_fresh(7, 0, 0, 0, 0, request));
        assert!(!driver_correlation_is_fresh(8, 0, 0, 0, 0, request));
        assert!(!driver_correlation_is_fresh(7, 1, 0, 0, 0, request));
        assert!(!driver_correlation_is_fresh(7, 0, 2, 0, 0, request));
        assert!(!driver_correlation_is_fresh(7, 0, 0, 3, 0, request));
        assert!(!driver_correlation_is_fresh(7, 0, 0, 0, 9, request));

        let mut stale_endpoint_generation = request;
        stale_endpoint_generation.endpoint.generation =
            wyrmroot_device_proto::coordinator::EndpointGeneration(2);
        assert!(!driver_correlation_is_fresh(
            7,
            0,
            0,
            0,
            0,
            stale_endpoint_generation,
        ));
    }

    #[test]
    fn native_replacement_accepts_first_fresh_namespace_and_rejects_old_endpoint() {
        let mut old = driver_request();
        let old_namespace = 7 * (1u64 << 32);
        old.attempt_generation.0 = old_namespace + 1;
        old.launch_session.0 = old_namespace + (1u64 << 30) + 1;
        old.endpoint.id.0 = old_namespace + (2u64 << 30) + 1;
        old.transaction_id = old_namespace + (3u64 << 30) + 1;

        let mut fresh = driver_request();
        let fresh_namespace = 8 * (1u64 << 32);
        fresh.supervisor_generation = SupervisorGeneration(8);
        fresh.attempt_generation.0 = fresh_namespace + 1;
        fresh.launch_session.0 = fresh_namespace + (1u64 << 30) + 1;
        fresh.endpoint.id.0 = fresh_namespace + (2u64 << 30) + 1;
        fresh.transaction_id = fresh_namespace + (3u64 << 30) + 1;

        assert!(driver_correlation_is_fresh(
            8,
            old.attempt_generation.0,
            old.launch_session.0,
            old.endpoint.id.0,
            old.transaction_id,
            fresh,
        ));
        assert!(!driver_correlation_is_fresh(
            8,
            old.attempt_generation.0,
            old.launch_session.0,
            old.endpoint.id.0,
            old.transaction_id,
            old,
        ));
    }

    #[test]
    fn resident_poll_observes_driver_exit_separately_from_registry_exit() {
        assert_eq!(
            classify_resident_poll(
                DwWaitResultV1 {
                    index: 4,
                    observed: DW_SIGNAL_EXITED,
                    ..DwWaitResultV1::default()
                },
                true,
                true,
            ),
            Ok(ResidentPollEvent::DriverExited)
        );
        assert_eq!(
            classify_resident_poll(
                DwWaitResultV1 {
                    index: 2,
                    observed: DW_SIGNAL_EXITED,
                    ..DwWaitResultV1::default()
                },
                false,
                true,
            ),
            Ok(ResidentPollEvent::DriverExited)
        );
    }

    #[cfg(feature = "wyr1c6-selector29")]
    #[test]
    fn selector29_d1_restart_survives_u2_reaping_but_not_d2_replacement() {
        let mut u1 = driver_request();
        u1.supervisor_generation = SupervisorGeneration(1);
        u1.attempt_generation = wyrmroot_device_proto::coordinator::AttemptGeneration(
            wyrmroot_device_proto::SELECTOR29_FAILURE_ATTEMPT_GENERATION,
        );
        let mut u2 = u1;
        u2.attempt_generation.0 += 1;

        assert!(selector29_restarting_d1(1, Some(u2), Some(u1)));
        assert!(selector29_restarting_d1(1, None, Some(u2)));
        assert!(!selector29_restarting_d1(1, None, Some(u1)));
        assert!(!selector29_restarting_d1(2, None, Some(u2)));
    }

    #[cfg(feature = "wyr1c6-selector29")]
    #[test]
    fn selector29_d1_exit_drains_stale_and_failure_before_p2_retirement() {
        assert_eq!(
            selector29_terminal_fact_for_event(crate::wyr1c6_gate::GateEvent::StaleReject),
            Ok(Some(13))
        );
        assert_eq!(
            selector29_terminal_fact_for_event(crate::wyr1c6_gate::GateEvent::D1Failure),
            Ok(Some(14))
        );
        assert_eq!(
            selector29_terminal_fact_for_event(crate::wyr1c6_gate::GateEvent::P2Retire),
            Ok(None)
        );
        assert_eq!(
            selector29_terminal_fact_for_event(crate::wyr1c6_gate::GateEvent::P2Publish),
            Err(InitError::WrongManifestProfile)
        );
    }
}
