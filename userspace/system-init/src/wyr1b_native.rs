//! Native selector-27 registry and dependent-peer controller.

use super::*;
use crate::wyr1b::{
    EndpointGrant, EndpointKind, JobError, JobResult as ControllerJobResult, LaunchEngineError,
    PolicyView, RegistryTopology, RequestTicket, commit_prepared_job, correlation_environment,
    observe_prepared_ready, prepare_reserved_job,
};
use crate::wyr1b_gate::{EvidenceLog, GATE_PATH, GateConfig, GateEvent, parse_config};
use crate::wyr1b_job::{JobDispatcher, SessionOwner};
use deepwyrm_syscall::{
    DW_HANDLE_TRANSFER_MOVE, DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_INSPECT, DW_RIGHT_READ,
    DW_RIGHT_TRANSFER, DW_RIGHT_WAIT, DW_RIGHT_WRITE, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE,
    DW_TASK_STATE_EXITED, DW_TERMINATION_AUTHORIZED, DW_TERMINATION_NORMAL_EXIT,
    DW_TERMINATION_RESOURCE_POLICY, DW_TERMINATION_TASK_GROUP_TEARDOWN,
    DW_TERMINATION_UNHANDLED_EXCEPTION, DwHandleTransferV1, DwRights,
};
use wyrmroot_launch_proto::{
    ErrorCode as LaunchErrorCode, Message as LaunchMessage, MessageType as LaunchMessageType,
    Reservation as LaunchReservation, TerminationClassification, TerminationResult,
    encode_error as encode_launch_error, encode_job_list, encode_job_message, encode_job_result,
    encode_job_state, parse_message as parse_launch_message, parse_reservation_prefix,
};
use wyrmroot_loader::launch::CHILD_CHANNEL_RIGHTS;
use wyrmroot_registry_proto::{
    EnumerationScope, Header as RegistryHeader, InstallClient, MessageType as RegistryMessageType,
    ProtocolVersion, encode_install_client, encode_install_publication,
};
use wyrmroot_wyr1b_gate_proto::{
    Direction, ECHO_PROTOCOL_ID, ECHO_SERVICE_NAME, ECHO_VERSION_MAJOR, ECHO_VERSION_MINOR,
    MessageType as GateMessageType, RECORD_BYTES as GATE_RECORD_BYTES, Record as GateRecord,
    TEST_PRIVATE_PUBLISHER_ROLE_ID, encode as encode_gate_record, parse_for as parse_gate_record,
};

const REGISTRY_PATH: &str = "system/registryd";
const PUBLISHER_PATH: &str = "test/wyr1-b/publisher";
const CLIENT_PATH: &str = "test/wyr1-b/client";
const FIRST_PUBLICATION_ID: u64 = 0x1_0001;
const SECOND_PUBLICATION_ID: u64 = 0x1_0002;
const CLIENT_ID: u64 = 0x2_0001;
const INSTALL_PUBLICATION_TRANSACTION: u64 = 1;
const INSTALL_CLIENT_TRANSACTION: u64 = 3;
const CONTROLLER_CHANNEL_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_TRANSFER.0,
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InstalledPeer {
    pub grant: EndpointGrant,
    pub loaded: LoadedProcess,
    pub task_group: DwHandle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RegistryNativeAttempt {
    pub active: ActiveNativeRole,
    pub control_channel: DwHandle,
    ready_at: u64,
}

#[derive(Debug, Eq, PartialEq)]
enum PeerLaunchError {
    PreInstall(InitError),
    InstallCommitted(InitError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeerLaunchStage {
    Archive,
    ArtifactLookup,
    ArtifactValidation,
    Grant,
    Correlation,
    TaskGroup,
    ChannelPair,
    InstallMove,
    PeerCapability,
    Load,
    Clock,
    Deadline,
    Ready,
}

const fn peer_launch_error(stage: PeerLaunchStage, error: InitError) -> PeerLaunchError {
    match stage {
        PeerLaunchStage::Archive
        | PeerLaunchStage::ArtifactLookup
        | PeerLaunchStage::ArtifactValidation
        | PeerLaunchStage::Grant
        | PeerLaunchStage::Correlation
        | PeerLaunchStage::TaskGroup
        | PeerLaunchStage::ChannelPair
        | PeerLaunchStage::InstallMove => PeerLaunchError::PreInstall(error),
        PeerLaunchStage::PeerCapability
        | PeerLaunchStage::Load
        | PeerLaunchStage::Clock
        | PeerLaunchStage::Deadline
        | PeerLaunchStage::Ready => PeerLaunchError::InstallCommitted(error),
    }
}

fn retry_preinstall_once<T>(
    mut attempt: impl FnMut() -> Result<T, PeerLaunchError>,
) -> Result<T, PeerLaunchError> {
    match attempt() {
        Err(PeerLaunchError::PreInstall(InitError::Cleanup)) => {
            Err(PeerLaunchError::PreInstall(InitError::Cleanup))
        }
        Err(PeerLaunchError::PreInstall(_)) => attempt(),
        result => result,
    }
}

#[derive(Debug, Eq, PartialEq)]
enum GateRunError {
    PreInstall(InitError),
    CleanupFailed(InitError),
    InstallCommitted {
        error: InitError,
        cleanup_failed: bool,
    },
}

fn classify_gate_run_error(
    install_committed: bool,
    cleanup_failed: bool,
    error: InitError,
) -> GateRunError {
    if install_committed {
        GateRunError::InstallCommitted {
            error,
            cleanup_failed,
        }
    } else if cleanup_failed {
        GateRunError::CleanupFailed(InitError::Cleanup)
    } else {
        GateRunError::PreInstall(error)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct StagedChannelPair {
    first: Option<DwHandle>,
    second: Option<DwHandle>,
}

impl StagedChannelPair {
    const fn new(first: DwHandle, second: DwHandle) -> Self {
        Self {
            first: Some(first),
            second: Some(second),
        }
    }

    fn first(&self) -> Result<DwHandle, InitError> {
        self.first.ok_or(InitError::Accounting)
    }

    fn second(&self) -> Result<DwHandle, InitError> {
        self.second.ok_or(InitError::Accounting)
    }

    fn commit_first_move(&mut self) -> Result<(), InitError> {
        self.first.take().map(|_| ()).ok_or(InitError::Accounting)
    }

    fn commit_second_move(&mut self) -> Result<(), InitError> {
        self.second.take().map(|_| ()).ok_or(InitError::Accounting)
    }

    fn take_first(&mut self) -> Result<DwHandle, InitError> {
        self.first.take().ok_or(InitError::Accounting)
    }

    fn cleanup<S: InitPlatform>(&mut self, system: &mut S) -> bool {
        let mut failed = false;
        for slot in [&mut self.second, &mut self.first] {
            if let Some(handle) = slot.take() {
                failed |= system.close_handle(handle).is_err();
            }
        }
        !failed
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ResidentState {
    pub registry_control: DwHandle,
    pub topology: Option<RegistryTopology>,
    pub gate: GateConfig,
    pub jobs: JobDispatcher,
}

/// Validates the selector-27 retained product without weakening the selector-25
/// profile parser.
pub(crate) fn validate_retained_bootfs(
    bytes: &[u8],
) -> Result<(SystemInit, GateConfig), InitError> {
    let archive = Archive::new(bytes).map_err(InitError::Bootfs)?;
    let manifest_entry = archive
        .lookup(MANIFEST_PATH.as_bytes())
        .map_err(map_lookup)?;
    let manifest_bytes = manifest_entry.data();
    let encoded_generation: [u8; 32] = manifest_bytes
        .get(48..80)
        .ok_or(InitError::Manifest(ManifestParseError::TruncatedHeader))?
        .try_into()
        .expect("checked WRRM generation slice");
    if encoded_generation == [0; 32] {
        return Err(InitError::ZeroBootGeneration);
    }
    let manifest = Manifest::parse_structural(manifest_bytes, &encoded_generation)
        .map_err(InitError::Manifest)?;
    let controller = SystemInit::from_wyr1b_manifest(manifest)?;
    for role in manifest.roles() {
        let entry = archive.lookup(role.path().as_bytes()).map_err(map_lookup)?;
        if !entry.is_executable() || entry.data().is_empty() {
            return Err(InitError::NonExecutableRole);
        }
        if wyrmroot_runtime::sha256::digest(entry.data()) != *role.executable_identity() {
            return Err(InitError::ArtifactIdentityMismatch(role.id()));
        }
    }
    let init = archive
        .lookup(SYSTEM_INIT_PATH.as_bytes())
        .map_err(map_lookup)?;
    if !init.is_executable() || init.data().is_empty() {
        return Err(InitError::NonExecutableRole);
    }
    for edge in manifest.edges() {
        if let Some(path) = edge.target_path() {
            archive.lookup(path.as_bytes()).map_err(map_lookup)?;
        }
    }
    let gate = archive.lookup(GATE_PATH.as_bytes()).map_err(map_lookup)?;
    let gate = parse_config(gate.data()).map_err(InitError::Wyr1BGateConfig)?;
    Ok((controller, gate))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn activate_in_place<'a, S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    slot: &'a mut MaybeUninit<ResidentSystemInit>,
    authority: LoadAuthority,
    bootstrap_channel: DwHandle,
    parent_transaction: u64,
    bootfs: &[u8],
) -> Result<&'a mut ResidentSystemInit, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let resident = initialize_resident_in_place(slot, authority, bootfs)?;
    activate_resident(
        system,
        loader,
        waits,
        resident,
        authority,
        bootstrap_channel,
        parent_transaction,
        bootfs,
    )?;
    Ok(resident)
}

fn initialize_resident_in_place<'a>(
    slot: &'a mut MaybeUninit<ResidentSystemInit>,
    authority: LoadAuthority,
    bootfs: &[u8],
) -> Result<&'a mut ResidentSystemInit, InitError> {
    let (controller, gate) = validate_retained_bootfs(bootfs)?;
    Ok(slot.write(ResidentSystemInit {
        controller,
        authority,
        result: RecoveryResult::Degraded,
        active: [None; EARLY_ROLE_COUNT],
        evidence_finalized: false,
        last_tick_ns: 0,
        wyr1b: Some(ResidentState {
            registry_control: DwHandle(0),
            topology: None,
            gate,
            jobs: JobDispatcher::new(),
        }),
        wyr1b_evidence: None,
    }))
}

#[allow(clippy::too_many_arguments)]
fn activate_resident<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    resident: &mut ResidentSystemInit,
    authority: LoadAuthority,
    bootstrap_channel: DwHandle,
    parent_transaction: u64,
    bootfs: &[u8],
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let ResidentSystemInit {
        controller,
        result,
        active,
        wyr1b,
        wyr1b_evidence,
        ..
    } = resident;
    let state = wyr1b.as_mut().ok_or(InitError::Accounting)?;
    let gate = state.gate;
    controller.become_operational()?;
    let mut ready = [0u8; HEADER_BYTES];
    let ready_len =
        encode_ready_for_profile(LaunchProfile::Supervisor, parent_transaction, &mut ready)
            .map_err(InitError::Launch)?;
    system
        .send_channel(bootstrap_channel, &ready[..ready_len])
        .map_err(InitError::Native)?;
    let retire_deadline = system
        .now()
        .map_err(InitError::Native)?
        .checked_add(WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns)
        .ok_or(InitError::Accounting)?;
    let retired = waits
        .wait_many(
            core::slice::from_ref(&DwWaitItemV1 {
                handle: bootstrap_channel,
                signals: DW_SIGNAL_PEER_CLOSED,
            }),
            DwDeadline(retire_deadline),
        )
        .map_err(|_| InitError::Supervision)?;
    if retired.index != 0 || retired.observed.0 & DW_SIGNAL_PEER_CLOSED.0 == 0 {
        return Err(InitError::Supervision);
    }
    controller.begin_registry(system.now().map_err(InitError::Native)?, 1, 0x1001)?;
    let Some(registry) =
        launch_registry_until_ready(system, loader, waits, controller, authority, bootfs)?
    else {
        return Ok(());
    };
    let (mut registry, mut topology) =
        establish_registry_topology(system, waits, controller, registry)?;
    let (devmgr, activation_result) = match activate_role_until_ready(
        system,
        controller,
        loader,
        waits,
        authority,
        bootfs,
        RoleId::Devmgr,
    )? {
        RoleActivation::Ready(active) => (Some(active), RecoveryResult::Recovered),
        RoleActivation::Degraded => (None, RecoveryResult::Degraded),
    };
    *result = activation_result;
    loop {
        match run_registry_gate(
            system,
            loader,
            waits,
            authority,
            bootfs,
            registry,
            &mut topology,
            gate,
            &mut state.jobs,
        ) {
            Ok(evidence) => {
                *active = [Some(registry.active), devmgr];
                state.registry_control = registry.control_channel;
                state.topology = Some(topology);
                *wyr1b_evidence = Some(evidence);
                return Ok(());
            }
            Err(GateRunError::PreInstall(_error)) => {
                *result = RecoveryResult::Degraded;
                *active = [Some(registry.active), devmgr];
                state.registry_control = registry.control_channel;
                state.topology = Some(topology);
                return Ok(());
            }
            Err(GateRunError::CleanupFailed(_)) => {
                let _ = poison_registry_generation(system, waits, controller, registry, true)?;
                *result = RecoveryResult::Degraded;
                *active = [None, devmgr];
                state.topology = Some(topology);
                return Ok(());
            }
            Err(GateRunError::InstallCommitted {
                error: _,
                cleanup_failed,
            }) => {
                if poison_registry_generation(system, waits, controller, registry, cleanup_failed)?
                {
                    *result = RecoveryResult::Degraded;
                    *active = [None, devmgr];
                    state.topology = Some(topology);
                    return Ok(());
                }
                let Some(replacement) = launch_registry_until_ready(
                    system, loader, waits, controller, authority, bootfs,
                )?
                else {
                    *result = RecoveryResult::Degraded;
                    *active = [None, devmgr];
                    state.topology = Some(topology);
                    return Ok(());
                };
                registry = restart_topology_or_poison(
                    system,
                    waits,
                    controller,
                    &mut topology,
                    replacement,
                )?;
            }
        }
    }
}

fn gate_record(
    message_type: GateMessageType,
    gate: GateConfig,
    grant: EndpointGrant,
    object: EndpointGrant,
    operation_id: u64,
) -> GateRecord {
    GateRecord {
        message_type,
        nonce: gate.nonce,
        registry_generation: grant.registry_generation,
        actor_id: grant.endpoint_id,
        actor_generation: grant.endpoint_generation,
        object_id: object.endpoint_id,
        object_generation: object.endpoint_generation,
        operation_id,
        value: 0,
    }
}

fn send_gate<S: InitPlatform>(
    system: &mut S,
    channel: DwHandle,
    record: GateRecord,
) -> Result<(), InitError> {
    let mut bytes = [0u8; GATE_RECORD_BYTES];
    encode_gate_record(record, &mut bytes).map_err(InitError::Wyr1BGateProtocol)?;
    system
        .send_channel(channel, &bytes)
        .map_err(InitError::Native)
}

fn receive_gate<S: Wyr1BPlatform>(
    system: &mut S,
    channel: DwHandle,
    deadline: DwDeadline,
) -> Result<GateRecord, InitError> {
    let item = DwWaitItemV1 {
        handle: channel,
        signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
    };
    let observed = system
        .wait_many(core::slice::from_ref(&item), deadline)
        .map_err(InitError::Native)?;
    if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(InitError::Supervision);
    }
    let mut bytes = [0u8; GATE_RECORD_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = system
        .receive_channel(channel, &mut bytes, &mut handles)
        .map_err(InitError::Native)?;
    if counts.bytes != GATE_RECORD_BYTES || counts.handles != 0 {
        if counts.handles != 0 && handles[0].handle.0 != 0 {
            system
                .close_handle(handles[0].handle)
                .map_err(|_| InitError::Cleanup)?;
        }
        return Err(InitError::Wyr1BGateProtocol(
            wyrmroot_wyr1b_gate_proto::Error::WrongSize,
        ));
    }
    parse_gate_record(&bytes, Direction::ChildToInit).map_err(InitError::Wyr1BGateProtocol)
}

fn expect_gate(actual: GateRecord, expected: GateRecord) -> Result<(), InitError> {
    if actual == expected {
        Ok(())
    } else {
        Err(InitError::Wyr1BGateMismatch)
    }
}

fn install_publication<S: Wyr1BPlatform>(
    system: &mut S,
    control: DwHandle,
    grant: EndpointGrant,
    registry_endpoint: DwHandle,
    operation: u64,
) -> Result<(), InitError> {
    let mut bytes = [0u8; 256];
    let publication_id = match operation {
        1 => FIRST_PUBLICATION_ID,
        2 => SECOND_PUBLICATION_ID,
        _ => return Err(InitError::Wyr1BGateMismatch),
    };
    let transaction_id = INSTALL_PUBLICATION_TRANSACTION
        .checked_add(operation - 1)
        .ok_or(InitError::Accounting)?;
    let size = encode_install_publication(
        RegistryHeader {
            message_type: RegistryMessageType::InstallPublication,
            registry_generation: grant.registry_generation,
            endpoint_id: 0,
            endpoint_generation: 0,
            transaction_id,
        },
        grant.endpoint_id,
        grant.endpoint_generation,
        TEST_PRIVATE_PUBLISHER_ROLE_ID,
        publication_id,
        operation,
        ECHO_PROTOCOL_ID,
        &[ProtocolVersion {
            major: ECHO_VERSION_MAJOR,
            minor: ECHO_VERSION_MINOR,
        }],
        ECHO_SERVICE_NAME,
        &mut bytes,
    )
    .map_err(InitError::RegistryProtocol)?;
    move_endpoint(system, control, &bytes[..size], registry_endpoint)
}

fn install_client<S: Wyr1BPlatform>(
    system: &mut S,
    control: DwHandle,
    grant: EndpointGrant,
    registry_endpoint: DwHandle,
) -> Result<(), InitError> {
    let mut bytes = [0u8; 104];
    let size = encode_install_client(
        RegistryHeader {
            message_type: RegistryMessageType::InstallClient,
            registry_generation: grant.registry_generation,
            endpoint_id: 0,
            endpoint_generation: 0,
            transaction_id: INSTALL_CLIENT_TRANSACTION,
        },
        InstallClient {
            endpoint_id: grant.endpoint_id,
            endpoint_generation: grant.endpoint_generation,
            client_id: CLIENT_ID,
            client_generation: grant.role_generation,
            scope: EnumerationScope::None,
        },
        &mut bytes,
    )
    .map_err(InitError::RegistryProtocol)?;
    move_endpoint(system, control, &bytes[..size], registry_endpoint)
}

fn move_endpoint<S: Wyr1BPlatform>(
    system: &mut S,
    control: DwHandle,
    bytes: &[u8],
    endpoint: DwHandle,
) -> Result<(), InitError> {
    validate_controller_channel(system, endpoint)?;
    let transfer = DwHandleTransferV1 {
        handle: endpoint,
        requested_rights: CHILD_CHANNEL_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    system
        .send_channel_with_handles(control, bytes, core::slice::from_ref(&transfer))
        .map_err(InitError::Native)
}

fn validate_controller_channel<S: InitPlatform>(
    system: &mut S,
    handle: DwHandle,
) -> Result<(), InitError> {
    let info = system
        .query_capability_info(handle)
        .map_err(InitError::Native)?;
    if info.object_type != DW_OBJECT_TYPE_CHANNEL || info.rights != CONTROLLER_CHANNEL_RIGHTS {
        return Err(InitError::ResourceIdentityMismatch);
    }
    Ok(())
}

fn create_controller_channel_pair<S: Wyr1BPlatform>(
    system: &mut S,
) -> Result<(DwHandle, DwHandle), InitError> {
    system
        .channel_create(CONTROLLER_CHANNEL_RIGHTS)
        .map_err(InitError::Native)
}

fn launch_registry<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    controller: &mut SystemInit,
    authority: LoadAuthority,
    bootfs: &[u8],
) -> Result<RegistryNativeAttempt, InitError>
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
        .role_state(RoleId::Registryd)
        .ok_or(InitError::WrongActivationOrder)?
    else {
        return Err(InitError::WrongActivationOrder);
    };
    let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
    let image = archive
        .lookup(REGISTRY_PATH.as_bytes())
        .map_err(map_lookup)?;
    let executable_identity = controller.executable_identity(RoleId::Registryd)?;
    if !image.is_executable()
        || wyrmroot_runtime::sha256::digest(image.data()) != executable_identity
    {
        return Err(InitError::ArtifactIdentityMismatch(RoleId::Registryd));
    }
    let task_group = system
        .create_attempt_task_group(authority.task_group)
        .map_err(InitError::Native)?;
    let reservation =
        match controller.reserve_attempt(RoleId::Registryd, generation, transaction_id) {
            Ok(reservation) => reservation,
            Err(error) => {
                return Err(if system.close_handle(task_group).is_err() {
                    InitError::Cleanup
                } else {
                    error
                });
            }
        };
    let mut channels = match create_controller_channel_pair(system) {
        Ok((first, second)) => StagedChannelPair::new(first, second),
        Err(error) => {
            let close_failed = system.close_handle(task_group).is_err();
            let release_failed = controller.abort_reservation(reservation).is_err();
            return Err(if close_failed || release_failed {
                InitError::Cleanup
            } else {
                error
            });
        }
    };
    let child_control = channels.second()?;
    if let Err(error) = validate_controller_channel(system, child_control) {
        let mut failed = !channels.cleanup(system);
        failed |= system.close_handle(task_group).is_err();
        failed |= controller.abort_reservation(reservation).is_err();
        return Err(if failed { InitError::Cleanup } else { error });
    }
    let loaded = match load_service_process(
        loader,
        LoadAuthority {
            task_group,
            ..authority
        },
        ServiceLoadRequest {
            image: image.data(),
            display_path: REGISTRY_PATH,
            profile: LaunchProfile::BootstrapRegistry,
            service_channel: child_control,
            correlation: None,
            transaction_id,
        },
    ) {
        Ok(loaded) => loaded,
        Err(failure) => {
            if failure.service_channel_consumed {
                channels.commit_second_move()?;
            }
            let control_failed = !channels.cleanup(system);
            let group_failed = system.close_handle(task_group).is_err();
            let release_failed = controller.abort_reservation(reservation).is_err();
            return Err(if control_failed || group_failed || release_failed {
                InitError::Cleanup
            } else {
                InitError::Loader(failure.error)
            });
        }
    };
    channels.commit_second_move()?;
    let started_at = match system.now().map_err(InitError::Native) {
        Ok(now) => now,
        Err(error) => {
            let mut failed = cleanup_loaded(system, waits, loaded, task_group, true).is_err();
            failed |= !channels.cleanup(system);
            failed |= controller.abort_reservation(reservation).is_err();
            return Err(if failed { InitError::Cleanup } else { error });
        }
    };
    let deadline = match started_at.checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns) {
        Some(deadline) => deadline,
        None => {
            let mut failed = cleanup_loaded(system, waits, loaded, task_group, true).is_err();
            failed |= !channels.cleanup(system);
            failed |= controller.abort_reservation(reservation).is_err();
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Accounting
            });
        }
    };
    let resources = AttemptResources {
        role: RoleId::Registryd,
        generation,
        transaction_id,
        executable_identity,
        startup_profile: StartupProfile::BootstrapRegistry,
        task_group,
        process: loaded.process,
        launch_channel: loaded.launch_channel,
        mappings: 0,
        reservation,
    };
    if let Err(error) = controller.install_attempt(resources) {
        let cleanup = cleanup_loaded(system, waits, loaded, task_group, true);
        let control_failed = !channels.cleanup(system);
        return Err(if cleanup.is_err() || control_failed {
            InitError::Cleanup
        } else {
            error
        });
    }
    let control_channel = channels.take_first()?;
    if let Err(error) =
        controller.child_started(RoleId::Registryd, generation, transaction_id, started_at)
    {
        return Err(reconcile_failed_registry_launch(
            system,
            waits,
            controller,
            loaded,
            task_group,
            control_channel,
            generation,
            transaction_id,
            started_at,
            AttemptFailure::CreationFailed,
            error,
        ));
    }
    if let Err(_error) = await_child_ready_profile_observed(
        waits,
        loaded.process,
        loaded.launch_channel,
        LaunchProfile::BootstrapRegistry,
        transaction_id,
        DwDeadline(deadline),
    ) {
        return Err(reconcile_failed_registry_launch(
            system,
            waits,
            controller,
            loaded,
            task_group,
            control_channel,
            generation,
            transaction_id,
            started_at,
            AttemptFailure::WaitFailed,
            InitError::Supervision,
        ));
    }
    let ready_at = match system.now().map_err(InitError::Native) {
        Ok(now) => now,
        Err(error) => {
            return Err(reconcile_failed_registry_launch(
                system,
                waits,
                controller,
                loaded,
                task_group,
                control_channel,
                generation,
                transaction_id,
                started_at,
                AttemptFailure::WaitFailed,
                error,
            ));
        }
    };
    if let Err(error) = controller.ready(RoleId::Registryd, generation, transaction_id, ready_at) {
        return Err(reconcile_failed_registry_launch(
            system,
            waits,
            controller,
            loaded,
            task_group,
            control_channel,
            generation,
            transaction_id,
            ready_at,
            AttemptFailure::WaitFailed,
            error,
        ));
    }
    let installed_generation = match controller
        .resources(RoleId::Registryd)
        .map(|resources| resources.generation)
    {
        Some(generation) => generation,
        None => {
            return Err(reconcile_failed_registry_launch(
                system,
                waits,
                controller,
                loaded,
                task_group,
                control_channel,
                generation,
                transaction_id,
                ready_at,
                AttemptFailure::WaitFailed,
                InitError::MissingAttemptResources,
            ));
        }
    };
    if installed_generation != generation {
        return Err(reconcile_failed_registry_launch(
            system,
            waits,
            controller,
            loaded,
            task_group,
            control_channel,
            generation,
            transaction_id,
            ready_at,
            AttemptFailure::WaitFailed,
            InitError::ResourceIdentityMismatch,
        ));
    }
    Ok(RegistryNativeAttempt {
        active: ActiveNativeRole {
            role: RoleId::Registryd,
            generation,
            transaction_id,
            loaded,
            task_group,
        },
        control_channel,
        ready_at,
    })
}

fn establish_registry_topology<S, W>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    registry: RegistryNativeAttempt,
) -> Result<(RegistryNativeAttempt, RegistryTopology), InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    match RegistryTopology::new(registry.active.generation).map_err(InitError::Wyr1BModel) {
        Ok(topology) => Ok((registry, topology)),
        Err(error) => Err(reconcile_failed_registry_launch(
            system,
            waits,
            controller,
            registry.active.loaded,
            registry.active.task_group,
            registry.control_channel,
            registry.active.generation,
            registry.active.transaction_id,
            registry.ready_at,
            AttemptFailure::WaitFailed,
            error,
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn reconcile_failed_registry_launch<
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    loaded: LoadedProcess,
    task_group: DwHandle,
    control_channel: DwHandle,
    generation: u64,
    transaction_id: u64,
    classified_at: u64,
    failure: AttemptFailure,
    original: InitError,
) -> InitError {
    let transition = match controller.role_state(RoleId::Registryd) {
        Some(RestartState::Starting { .. }) | Some(RestartState::Ready { .. }) => controller.fail(
            RoleId::Registryd,
            generation,
            transaction_id,
            classified_at,
            failure,
        ),
        Some(RestartState::AwaitingReady { .. }) => controller.ready_wait_failed(
            RoleId::Registryd,
            generation,
            transaction_id,
            classified_at,
            failure,
        ),
        _ => Err(InitError::WrongActivationOrder),
    };
    if transition.is_err() {
        let _ = cleanup_loaded(system, waits, loaded, task_group, true);
        let _ = system.close_handle(control_channel);
        controller.fatal();
        return InitError::Cleanup;
    }
    let cleanup_failed = cleanup_loaded(system, waits, loaded, task_group, true).is_err()
        | system.close_handle(control_channel).is_err();
    let retired_at = match classified_at.checked_add(1) {
        Some(value) => value,
        None => {
            controller.fatal();
            return InitError::Accounting;
        }
    };
    if cleanup_failed {
        let _ =
            controller.cleanup_failed(RoleId::Registryd, generation, transaction_id, retired_at);
        return InitError::Cleanup;
    }
    match controller.cleanup_complete(RoleId::Registryd, generation, transaction_id, retired_at) {
        Ok(()) => original,
        Err(_) => {
            controller.fatal();
            InitError::Cleanup
        }
    }
}

fn launch_registry_until_ready<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    controller: &mut SystemInit,
    authority: LoadAuthority,
    bootfs: &[u8],
) -> Result<Option<RegistryNativeAttempt>, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    loop {
        let attempt_transaction = match controller
            .role_state(RoleId::Registryd)
            .ok_or(InitError::WrongActivationOrder)?
        {
            RestartState::Starting { transaction_id, .. } => transaction_id,
            _ => return Err(InitError::WrongActivationOrder),
        };
        let attempt_time = system.now().map_err(InitError::Native)?;
        match launch_registry(system, loader, waits, controller, authority, bootfs) {
            Ok(value) => return Ok(Some(value)),
            Err(error) => {
                let now = attempt_time;
                let state = controller
                    .role_state(RoleId::Registryd)
                    .ok_or(InitError::WrongActivationOrder)?;
                let (generation, transaction_id) = match state {
                    RestartState::Starting {
                        generation,
                        transaction_id,
                        ..
                    } => (generation, transaction_id),
                    RestartState::Backoff { .. } => {
                        if advance_registry_or_exhausted(system, controller, attempt_transaction)? {
                            return Ok(None);
                        }
                        continue;
                    }
                    RestartState::PermanentFailure { .. } => return Ok(None),
                    _ => return Err(InitError::WrongActivationOrder),
                };
                controller.fail(
                    RoleId::Registryd,
                    generation,
                    transaction_id,
                    now,
                    AttemptFailure::CreationFailed,
                )?;
                let retired_at = now.checked_add(1).ok_or(InitError::Accounting)?;
                if error == InitError::Cleanup {
                    controller.cleanup_failed(
                        RoleId::Registryd,
                        generation,
                        transaction_id,
                        retired_at,
                    )?;
                    return Ok(None);
                }
                controller.cleanup_complete(
                    RoleId::Registryd,
                    generation,
                    transaction_id,
                    retired_at,
                )?;
                if advance_registry_or_exhausted(system, controller, transaction_id)? {
                    return Ok(None);
                }
            }
        }
    }
}

fn poison_registry_generation<S, W>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    registry: RegistryNativeAttempt,
    dependent_cleanup_failed: bool,
) -> Result<bool, InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let observed_now = system.now().map_err(InitError::Native);
    let (transition_now, transition) = match observed_now {
        Ok(now) => (
            Some(now),
            controller.fail(
                RoleId::Registryd,
                registry.active.generation,
                registry.active.transaction_id,
                now,
                AttemptFailure::WaitFailed,
            ),
        ),
        Err(error) => (None, Err(error)),
    };
    let native_cleanup_failed = cleanup_loaded(
        system,
        waits,
        registry.active.loaded,
        registry.active.task_group,
        true,
    )
    .is_err()
        | system.close_handle(registry.control_channel).is_err()
        | dependent_cleanup_failed;

    let now = match transition {
        Ok(()) => transition_now.ok_or(InitError::Accounting)?,
        Err(error) => {
            let identity_mismatch = matches!(
                error,
                InitError::Restart(RestartTransitionError::StaleGeneration)
                    | InitError::Restart(RestartTransitionError::TransactionMismatch)
            );
            let retirement = if identity_mismatch || transition_now.is_none() {
                controller.retire_attempt_after_fatal(RoleId::Registryd)
            } else {
                controller.retire_active_fail_closed(
                    RoleId::Registryd,
                    registry.active.generation,
                    registry.active.transaction_id,
                    transition_now.ok_or(InitError::Accounting)?,
                    AttemptFailure::WaitFailed,
                    if native_cleanup_failed {
                        CleanupDisposition::Failed
                    } else {
                        CleanupDisposition::Complete
                    },
                )
            };
            if retirement.is_err() {
                let _ = controller.retire_attempt_after_fatal(RoleId::Registryd);
            }
            return Err(if native_cleanup_failed || retirement.is_err() {
                InitError::Cleanup
            } else {
                // Preserve the original transition error after complete native
                // cleanup; its exact type explains why fail()->CleaningUp did
                // not commit while the role is now truthfully permanent.
                error
            });
        }
    };
    let retired_at = now.checked_add(1).unwrap_or(now);
    let cleanup_must_fail = native_cleanup_failed || retired_at == now;
    if cleanup_must_fail {
        if controller
            .cleanup_failed(
                RoleId::Registryd,
                registry.active.generation,
                registry.active.transaction_id,
                retired_at,
            )
            .is_err()
        {
            let _ = controller.retire_attempt_after_fatal(RoleId::Registryd);
            return Err(InitError::Cleanup);
        }
        return if retired_at == now && !native_cleanup_failed {
            Err(InitError::Accounting)
        } else {
            Ok(true)
        };
    }
    if let Err(error) = controller.cleanup_complete(
        RoleId::Registryd,
        registry.active.generation,
        registry.active.transaction_id,
        retired_at,
    ) {
        let _ = controller.retire_attempt_after_fatal(RoleId::Registryd);
        return Err(error);
    }
    advance_registry_or_exhausted(system, controller, registry.active.transaction_id)
}

fn restart_topology_or_poison<S, W>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    topology: &mut RegistryTopology,
    registry: RegistryNativeAttempt,
) -> Result<RegistryNativeAttempt, InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    if let Err(error) = topology
        .restart(registry.active.generation)
        .map_err(InitError::Wyr1BModel)
    {
        let _ = poison_registry_generation(system, waits, controller, registry, false)?;
        return Err(error);
    }
    Ok(registry)
}

fn advance_registry_or_exhausted<S: InitPlatform>(
    system: &mut S,
    controller: &mut SystemInit,
    transaction_id: u64,
) -> Result<bool, InitError> {
    let _ = advance_or_degrade(system, controller, RoleId::Registryd, transaction_id)?;
    Ok(matches!(
        controller
            .role_state(RoleId::Registryd)
            .ok_or(InitError::WrongActivationOrder)?,
        RestartState::PermanentFailure { .. }
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeerKind {
    Publisher { operation: u64 },
    Client,
}

#[allow(clippy::too_many_arguments)]
fn launch_peer<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    bootfs: &[u8],
    registry_control: DwHandle,
    topology: &mut RegistryTopology,
    kind: PeerKind,
) -> Result<InstalledPeer, PeerLaunchError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let (endpoint_kind, role_generation, path, profile, transaction_id) = match kind {
        PeerKind::Publisher { operation } => (
            EndpointKind::Publication,
            operation,
            PUBLISHER_PATH,
            LaunchProfile::BootstrapService,
            0x2000 + operation,
        ),
        PeerKind::Client => (
            EndpointKind::RegistryClient,
            1,
            CLIENT_PATH,
            LaunchProfile::RegistryClient,
            0x3001,
        ),
    };
    let archive = Archive::new(bootfs)
        .map_err(|error| peer_launch_error(PeerLaunchStage::Archive, InitError::Bootfs(error)))?;
    let image = archive
        .lookup(path.as_bytes())
        .map_err(|error| peer_launch_error(PeerLaunchStage::ArtifactLookup, map_lookup(error)))?;
    if !image.is_executable() || image.data().is_empty() {
        return Err(peer_launch_error(
            PeerLaunchStage::ArtifactValidation,
            InitError::NonExecutableRole,
        ));
    }
    let grant = topology
        .issue(role_generation, endpoint_kind)
        .map_err(|error| peer_launch_error(PeerLaunchStage::Grant, InitError::Wyr1BModel(error)))?;
    let correlation = correlation_environment(grant).map_err(|error| {
        peer_launch_error(PeerLaunchStage::Correlation, InitError::Wyr1BModel(error))
    })?;
    let task_group = system
        .create_attempt_task_group(authority.task_group)
        .map_err(|error| peer_launch_error(PeerLaunchStage::TaskGroup, InitError::Native(error)))?;
    let mut channels = match create_controller_channel_pair(system) {
        Ok((first, second)) => StagedChannelPair::new(first, second),
        Err(error) => {
            return Err(peer_launch_error(
                PeerLaunchStage::ChannelPair,
                if system.close_handle(task_group).is_err() {
                    InitError::Cleanup
                } else {
                    error
                },
            ));
        }
    };
    let registry_endpoint = channels.first().map_err(PeerLaunchError::PreInstall)?;
    let install = match kind {
        PeerKind::Publisher { operation } => install_publication(
            system,
            registry_control,
            grant,
            registry_endpoint,
            operation,
        ),
        PeerKind::Client => install_client(system, registry_control, grant, registry_endpoint),
    };
    if let Err(error) = install {
        let mut failed = !channels.cleanup(system);
        failed |= system.close_handle(task_group).is_err();
        return Err(peer_launch_error(
            PeerLaunchStage::InstallMove,
            if failed { InitError::Cleanup } else { error },
        ));
    }
    channels
        .commit_first_move()
        .map_err(PeerLaunchError::InstallCommitted)?;
    // A successful install MOVE transfers the registry endpoint. Any later
    // failure poisons this registry generation; init must not retry against it.
    let peer_endpoint = channels
        .second()
        .map_err(PeerLaunchError::InstallCommitted)?;
    if let Err(error) = validate_controller_channel(system, peer_endpoint) {
        let failed = !channels.cleanup(system) | system.close_handle(task_group).is_err();
        return Err(peer_launch_error(
            PeerLaunchStage::PeerCapability,
            if failed { InitError::Cleanup } else { error },
        ));
    }
    let loaded = match load_service_process(
        loader,
        LoadAuthority {
            task_group,
            ..authority
        },
        ServiceLoadRequest {
            image: image.data(),
            display_path: path,
            profile,
            service_channel: peer_endpoint,
            correlation: Some(&correlation),
            transaction_id,
        },
    ) {
        Ok(loaded) => loaded,
        Err(failure) => {
            if failure.service_channel_consumed {
                channels
                    .commit_second_move()
                    .map_err(PeerLaunchError::InstallCommitted)?;
            }
            let close_failed = !channels.cleanup(system) | system.close_handle(task_group).is_err();
            return Err(peer_launch_error(
                PeerLaunchStage::Load,
                if close_failed {
                    InitError::Cleanup
                } else {
                    InitError::Loader(failure.error)
                },
            ));
        }
    };
    channels
        .commit_second_move()
        .map_err(PeerLaunchError::InstallCommitted)?;
    let now = match system.now().map_err(InitError::Native) {
        Ok(now) => now,
        Err(error) => {
            let cleanup = cleanup_loaded(system, waits, loaded, task_group, true);
            return Err(peer_launch_error(
                PeerLaunchStage::Clock,
                if cleanup.is_err() {
                    InitError::Cleanup
                } else {
                    error
                },
            ));
        }
    };
    let deadline = match now.checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns) {
        Some(deadline) => deadline,
        None => {
            let cleanup = cleanup_loaded(system, waits, loaded, task_group, true);
            return Err(peer_launch_error(
                PeerLaunchStage::Deadline,
                if cleanup.is_err() {
                    InitError::Cleanup
                } else {
                    InitError::Accounting
                },
            ));
        }
    };
    if await_child_ready_profile_observed(
        waits,
        loaded.process,
        loaded.launch_channel,
        profile,
        transaction_id,
        DwDeadline(deadline),
    )
    .is_err()
    {
        return Err(peer_launch_error(
            PeerLaunchStage::Ready,
            if cleanup_loaded(system, waits, loaded, task_group, true).is_err() {
                InitError::Cleanup
            } else {
                InitError::Supervision
            },
        ));
    }
    Ok(InstalledPeer {
        grant,
        loaded,
        task_group,
    })
}

fn configure_publisher<S: InitPlatform>(
    system: &mut S,
    gate: GateConfig,
    publisher: InstalledPeer,
    client: InstalledPeer,
    operation: u64,
) -> Result<GateRecord, InitError> {
    let record = gate_record(
        GateMessageType::ConfigurePublisher,
        gate,
        publisher.grant,
        client.grant,
        operation,
    );
    send_gate(system, publisher.loaded.launch_channel, record)?;
    Ok(record)
}

fn configure_client<S: InitPlatform>(
    system: &mut S,
    gate: GateConfig,
    client: InstalledPeer,
    publisher: InstalledPeer,
    operation: u64,
) -> Result<GateRecord, InitError> {
    let record = gate_record(
        GateMessageType::ConfigureRegistryClient,
        gate,
        client.grant,
        publisher.grant,
        operation,
    );
    send_gate(system, client.loaded.launch_channel, record)?;
    Ok(record)
}

fn report_deadline<S: InitPlatform>(system: &mut S) -> Result<DwDeadline, InitError> {
    Ok(DwDeadline(
        system
            .now()
            .map_err(InitError::Native)?
            .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .ok_or(InitError::Accounting)?,
    ))
}

fn expect_report<S: Wyr1BPlatform>(
    system: &mut S,
    peer: InstalledPeer,
    configured: GateRecord,
    message_type: GateMessageType,
) -> Result<GateRecord, InitError> {
    let expected = GateRecord {
        message_type,
        ..configured
    };
    let deadline = report_deadline(system)?;
    let actual = receive_gate(system, peer.loaded.launch_channel, deadline)?;
    expect_gate(actual, expected)?;
    Ok(actual)
}

fn expect_challenge_report<S: Wyr1BPlatform>(
    system: &mut S,
    peer: InstalledPeer,
    configured: GateRecord,
    message_type: GateMessageType,
) -> Result<GateRecord, InitError> {
    let deadline = report_deadline(system)?;
    let actual = receive_gate(system, peer.loaded.launch_channel, deadline)?;
    if actual.message_type != message_type
        || actual.nonce != configured.nonce
        || actual.registry_generation != configured.registry_generation
        || actual.actor_id != configured.actor_id
        || actual.actor_generation != configured.actor_generation
        || actual.object_id != configured.object_id
        || actual.object_generation != configured.object_generation
        || actual.operation_id != configured.operation_id
    {
        return Err(InitError::Wyr1BGateMismatch);
    }
    Ok(actual)
}

fn done_record(gate: GateConfig, peer: InstalledPeer, operation_id: u64) -> GateRecord {
    GateRecord {
        message_type: GateMessageType::Done,
        nonce: gate.nonce,
        registry_generation: peer.grant.registry_generation,
        actor_id: peer.grant.endpoint_id,
        actor_generation: peer.grant.endpoint_generation,
        object_id: 0,
        object_generation: 0,
        operation_id,
        value: 0,
    }
}

fn complete_direct_exchange<S: Wyr1BPlatform>(
    system: &mut S,
    publisher: InstalledPeer,
    client: InstalledPeer,
    publisher_config: GateRecord,
    client_config: GateRecord,
) -> Result<u64, InitError> {
    let echoed =
        expect_challenge_report(system, publisher, publisher_config, GateMessageType::Echoed)?;
    let exchanged =
        expect_challenge_report(system, client, client_config, GateMessageType::Exchanged)?;
    if echoed.value != exchanged.value {
        return Err(InitError::Wyr1BGateMismatch);
    }
    Ok(echoed.value)
}

#[allow(clippy::too_many_arguments)]
fn launch_launch_client<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    bootfs: &[u8],
    topology: &mut RegistryTopology,
    jobs: &mut JobDispatcher,
    operation: u64,
) -> Result<InstalledPeer, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
    let image = archive.lookup(CLIENT_PATH.as_bytes()).map_err(map_lookup)?;
    if !image.is_executable() || image.data().is_empty() {
        return Err(InitError::NonExecutableRole);
    }
    let grant = topology
        .issue(operation, EndpointKind::LaunchSession)
        .map_err(InitError::Wyr1BModel)?;
    let task_group = system
        .create_attempt_task_group(authority.task_group)
        .map_err(InitError::Native)?;
    let mut channels = match create_controller_channel_pair(system) {
        Ok((controller, child)) => StagedChannelPair::new(controller, child),
        Err(error) => {
            return Err(if system.close_handle(task_group).is_err() {
                InitError::Cleanup
            } else {
                error
            });
        }
    };
    let child = channels.second()?;
    let transaction_id = 0x4000_u64
        .checked_add(grant.endpoint_id)
        .ok_or(InitError::Accounting)?;
    let loaded = match load_service_process(
        loader,
        LoadAuthority {
            task_group,
            ..authority
        },
        ServiceLoadRequest {
            image: image.data(),
            display_path: CLIENT_PATH,
            profile: LaunchProfile::LaunchClient,
            service_channel: child,
            correlation: None,
            transaction_id,
        },
    ) {
        Ok(loaded) => loaded,
        Err(failure) => {
            if failure.service_channel_consumed {
                channels.commit_second_move()?;
            }
            let failed = !channels.cleanup(system) | system.close_handle(task_group).is_err();
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Loader(failure.error)
            });
        }
    };
    channels.commit_second_move()?;
    let deadline = report_deadline(system)?;
    if await_child_ready_profile_observed(
        waits,
        loaded.process,
        loaded.launch_channel,
        LaunchProfile::LaunchClient,
        transaction_id,
        deadline,
    )
    .is_err()
    {
        let failed = cleanup_loaded(system, waits, loaded, task_group, true).is_err()
            | !channels.cleanup(system);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Supervision
        });
    }
    let session = channels.take_first()?;
    if let Err(error) = jobs.install_session(grant, session) {
        let failed = system.close_handle(session).is_err()
            | cleanup_loaded(system, waits, loaded, task_group, true).is_err();
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Wyr1BModel(error)
        });
    }
    if let Err(error) = jobs.attach_session_owner(
        grant,
        SessionOwner {
            process: loaded.process,
            launch_channel: loaded.launch_channel,
            task_group,
        },
    ) {
        let disconnected = jobs.disconnect_session(grant);
        let failed = disconnected.map_or(true, |channel| system.close_handle(channel).is_err())
            | cleanup_loaded(system, waits, loaded, task_group, true).is_err();
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Wyr1BModel(error)
        });
    }
    Ok(InstalledPeer {
        grant,
        loaded,
        task_group,
    })
}

fn wait_session_readable<S: Wyr1BPlatform>(
    system: &mut S,
    session: DwHandle,
) -> Result<(), InitError> {
    let deadline = report_deadline(system)?;
    let result = system
        .wait_many(
            core::slice::from_ref(&DwWaitItemV1 {
                handle: session,
                signals: deepwyrm_syscall::DwSignals(
                    DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0,
                ),
            }),
            deadline,
        )
        .map_err(InitError::Native)?;
    if result.index != 0 || result.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(InitError::Supervision);
    }
    Ok(())
}

fn close_received_reverse<S: InitPlatform>(
    system: &mut S,
    handles: &[DwReceivedHandleInfoV1],
    count: usize,
) -> bool {
    let mut failed = false;
    for handle in handles[..count.min(handles.len())].iter().rev() {
        failed |= system.close_handle(handle.handle).is_err();
    }
    failed
}

fn launch_engine_error(error: LaunchEngineError<NativeError>) -> InitError {
    match error {
        LaunchEngineError::Job(error) => InitError::Wyr1BModel(error),
        LaunchEngineError::Validation {
            error,
            abort_failed,
            cleanup_failed,
        } => {
            if abort_failed || cleanup_failed {
                InitError::Cleanup
            } else {
                InitError::Wyr1BModel(error)
            }
        }
        LaunchEngineError::Loader {
            error,
            abort_failed,
            cleanup_failed,
            ..
        } => {
            if abort_failed || cleanup_failed {
                InitError::Cleanup
            } else {
                InitError::Loader(error)
            }
        }
        LaunchEngineError::Publication { error, .. } => InitError::Wyr1BModel(error),
    }
}

fn publish_launch_accepted<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    reservation: LaunchReservation,
    loaded: crate::wyr1b::LoadedJob,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut response = [0_u8; 88];
    let size = encode_job_message(
        reservation,
        LaunchMessageType::LaunchAccepted,
        loaded.job_id,
        &mut response,
    )
    .map_err(|_| InitError::Accounting)?;
    if let Err(error) = system.send_channel(session, &response[..size]) {
        let cleanup_failed = force_cleanup_job(system, waits, jobs, loaded).is_err();
        return Err(if cleanup_failed {
            InitError::Cleanup
        } else {
            InitError::Native(error)
        });
    }
    Ok(())
}

fn force_cleanup_job<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    loaded: crate::wyr1b::LoadedJob,
) -> Result<TerminationResult, InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    if let Some(resources) = jobs
        .jobs
        .forced_termination_resources(loaded.job_id)
        .map_err(InitError::Wyr1BModel)?
    {
        if system
            .terminate_task_group(DwHandle(resources.task_group))
            .is_err()
        {
            jobs.jobs
                .record_cleanup_bits(loaded.job_id, 1 << 0)
                .map_err(InitError::Wyr1BModel)?;
        } else {
            jobs.jobs
                .commit_forced_termination(loaded.job_id, resources)
                .map_err(InitError::Wyr1BModel)?;
        }
    }
    let result = reap_job(system, waits, jobs, loaded)?;
    if result.cleanup_result != 0 {
        Err(InitError::Cleanup)
    } else {
        Ok(result)
    }
}

fn rollback_prepared_job<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    prepared: crate::wyr1b::PreparedJob,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    force_cleanup_job(
        system,
        waits,
        jobs,
        crate::wyr1b::LoadedJob {
            job_id: prepared.job_id(),
            loaded: prepared.loaded,
            task_group: prepared.task_group,
        },
    )
    .map(|_| ())
}

#[allow(clippy::too_many_arguments)]
fn accept_reserved_launch<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: &PolicyView<'_>,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    reservation: LaunchReservation,
    request_ticket: RequestTicket,
    request: wyrmroot_launch_proto::LaunchRequest<'_>,
    received: &[DwReceivedHandleInfoV1; 16],
    handle_count: usize,
) -> Result<crate::wyr1b::LoadedJob, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    for info in &received[..handle_count] {
        if let Err(error) = validate_controller_channel(system, info.handle) {
            let failed = close_received_reverse(system, received, handle_count);
            return Err(if failed { InitError::Cleanup } else { error });
        }
    }
    let ticket = match jobs.jobs.begin_reserved_launch(request_ticket) {
        Ok(ticket) => ticket,
        Err(error) => {
            let failed = close_received_reverse(system, received, handle_count);
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Wyr1BModel(error)
            });
        }
    };
    let streams = [received[0].handle, received[1].handle, received[2].handle];
    let streams = &streams[..handle_count];
    let task_group = match system.create_attempt_task_group(authority.task_group) {
        Ok(task_group) => task_group,
        Err(error) => {
            return Err(
                if close_received_reverse(system, received, handle_count)
                    | jobs.jobs.abort_launch(ticket).is_err()
                {
                    InitError::Cleanup
                } else {
                    InitError::Native(error)
                },
            );
        }
    };
    let prepared = match prepare_reserved_job(
        &mut jobs.jobs,
        policy,
        loader,
        authority,
        task_group.0,
        reservation,
        ticket,
        request,
        streams,
    ) {
        Ok(prepared) => prepared,
        Err(LaunchEngineError::Publication {
            error,
            ticket,
            loaded,
            task_group,
        }) => {
            let cleanup_failed =
                cleanup_loaded(system, waits, loaded, DwHandle(task_group), true).is_err();
            let abort_failed = jobs.jobs.abort_launch(ticket).is_err();
            return Err(if cleanup_failed || abort_failed {
                InitError::Cleanup
            } else {
                InitError::Wyr1BModel(error)
            });
        }
        Err(error) => {
            let mapped = launch_engine_error(error);
            return Err(if system.close_handle(task_group).is_err() {
                InitError::Cleanup
            } else {
                mapped
            });
        }
    };
    let deadline = match report_deadline(system) {
        Ok(deadline) => deadline,
        Err(error) => {
            return Err(
                if rollback_prepared_job(system, waits, jobs, prepared).is_err() {
                    InitError::Cleanup
                } else {
                    error
                },
            );
        }
    };
    let observation = observe_prepared_ready(waits, &prepared, deadline);
    if observation.is_err() {
        return Err(
            if rollback_prepared_job(system, waits, jobs, prepared).is_err() {
                InitError::Cleanup
            } else {
                InitError::Supervision
            },
        );
    }
    let observation = observation.expect("checked exact READY observation");
    let loaded = match commit_prepared_job(&mut jobs.jobs, prepared, observation) {
        Ok(loaded) => loaded,
        Err(error) => {
            return Err(
                if rollback_prepared_job(system, waits, jobs, prepared).is_err() {
                    InitError::Cleanup
                } else {
                    InitError::Wyr1BModel(error)
                },
            );
        }
    };
    publish_launch_accepted(system, waits, jobs, session, reservation, loaded)?;
    Ok(loaded)
}

#[allow(clippy::too_many_arguments)]
fn receive_and_accept_job<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: &PolicyView<'_>,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    grant: EndpointGrant,
) -> Result<crate::wyr1b::LoadedJob, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    wait_session_readable(system, session)?;
    match dispatch_one_job_request(
        system,
        loader,
        waits,
        authority,
        Some(policy),
        jobs,
        session,
        grant,
    )? {
        JobDispatchOutcome::Launched(loaded) => Ok(loaded),
        JobDispatchOutcome::Responded => Err(InitError::Wyr1BModel(JobError::WrongState)),
    }
}

fn classify_termination(
    info: &DwTaskTerminationInfoV1,
) -> Result<TerminationClassification, InitError> {
    Ok(if info.reason == DW_TERMINATION_NORMAL_EXIT {
        TerminationClassification::NormalExit
    } else if info.reason == DW_TERMINATION_AUTHORIZED {
        TerminationClassification::Authorized
    } else if info.reason == DW_TERMINATION_UNHANDLED_EXCEPTION {
        TerminationClassification::UnhandledException
    } else if info.reason == DW_TERMINATION_RESOURCE_POLICY {
        TerminationClassification::ResourcePolicy
    } else if info.reason == DW_TERMINATION_TASK_GROUP_TEARDOWN {
        TerminationClassification::TaskGroupTeardown
    } else {
        return Err(InitError::Supervision);
    })
}

fn reap_job<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    loaded: crate::wyr1b::LoadedJob,
) -> Result<TerminationResult, InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let terminal = match jobs
        .jobs
        .terminal_result(loaded.job_id)
        .map_err(InitError::Wyr1BModel)?
    {
        Some(terminal) => terminal,
        None => {
            if loaded.loaded.process.0 == 0 {
                return Err(InitError::Accounting);
            }
            let mut info = match waits.query_task_termination(loaded.loaded.process) {
                Ok(info) => info,
                Err(_) => {
                    jobs.jobs
                        .record_cleanup_bits(loaded.job_id, 1 << 1)
                        .map_err(InitError::Wyr1BModel)?;
                    return Err(InitError::Cleanup);
                }
            };
            if info.state != DW_TASK_STATE_EXITED {
                let deadline = match report_deadline(system) {
                    Ok(deadline) => deadline,
                    Err(_) => {
                        jobs.jobs
                            .record_cleanup_bits(loaded.job_id, 1 << 1)
                            .map_err(InitError::Wyr1BModel)?;
                        return Err(InitError::Cleanup);
                    }
                };
                if waits
                    .wait_many(
                        core::slice::from_ref(&DwWaitItemV1 {
                            handle: loaded.loaded.process,
                            signals: DW_SIGNAL_EXITED,
                        }),
                        deadline,
                    )
                    .is_err()
                {
                    jobs.jobs
                        .record_cleanup_bits(loaded.job_id, 1 << 1)
                        .map_err(InitError::Wyr1BModel)?;
                    return Err(InitError::Cleanup);
                }
                info = match waits.query_task_termination(loaded.loaded.process) {
                    Ok(info) => info,
                    Err(_) => {
                        jobs.jobs
                            .record_cleanup_bits(loaded.job_id, 1 << 1)
                            .map_err(InitError::Wyr1BModel)?;
                        return Err(InitError::Cleanup);
                    }
                };
            }
            if info.state != DW_TASK_STATE_EXITED {
                jobs.jobs
                    .record_cleanup_bits(loaded.job_id, 1 << 1)
                    .map_err(InitError::Wyr1BModel)?;
                return Err(InitError::Cleanup);
            }
            ControllerJobResult {
                classification: classify_termination(&info)?.as_u32(),
                application_code: info.application_code,
                exception_class: info.exception_type.0,
                exception_detail: info.detail,
                exception_address: info.fault_address,
                cleanup_result: 0,
            }
        }
    };
    let mut closed_mask = 0_u32;
    let mut failed_bits = 0_u32;
    if loaded.loaded.launch_channel.0 != 0 {
        if system.close_handle(loaded.loaded.launch_channel).is_err() {
            failed_bits |= 1 << 2;
        } else {
            closed_mask |= 1 << 2;
        }
    }
    if loaded.loaded.process.0 != 0 {
        if system.close_handle(loaded.loaded.process).is_err() {
            failed_bits |= 1 << 3;
        } else {
            closed_mask |= 1 << 3;
        }
    }
    if loaded.task_group != 0 {
        if system.close_handle(DwHandle(loaded.task_group)).is_err() {
            failed_bits |= 1 << 4;
        } else {
            closed_mask |= 1 << 4;
        }
    }
    let completed = jobs
        .jobs
        .apply_cleanup_progress(loaded.job_id, terminal, closed_mask, failed_bits)
        .map_err(InitError::Wyr1BModel)?;
    let Some(completed) = completed else {
        return Err(InitError::Cleanup);
    };
    jobs.jobs.reclaim_closed_sessions();
    controller_result_to_wire(completed)
}

const fn job_error_code(error: JobError) -> LaunchErrorCode {
    match error {
        JobError::TransactionReplay => LaunchErrorCode::TransactionReplay,
        JobError::UnknownConnection
        | JobError::ClosedConnection
        | JobError::StaleGeneration
        | JobError::DuplicateConnection
        | JobError::ZeroIdentity => LaunchErrorCode::StaleOrUnknownSession,
        JobError::ForeignJob | JobError::UnknownJob => LaunchErrorCode::ForeignOrUnknownJob,
        JobError::Capacity | JobError::ArithmeticOverflow => LaunchErrorCode::Capacity,
        JobError::Policy(_)
        | JobError::PolicyMissing
        | JobError::PolicyExecutable
        | JobError::Bootfs(_)
        | JobError::BootGenerationMismatch
        | JobError::ArtifactNotExecutable
        | JobError::ArtifactIdentityMismatch
        | JobError::StreamPolicy => LaunchErrorCode::PolicyRejected,
        JobError::WrongState | JobError::ResourceIdentity => LaunchErrorCode::InvalidState,
    }
}

const fn launch_error_code(error: &InitError) -> LaunchErrorCode {
    match error {
        InitError::Wyr1BModel(error) => job_error_code(*error),
        InitError::Loader(_) | InitError::Native(_) | InitError::Supervision => {
            LaunchErrorCode::LoaderFailure
        }
        InitError::Cleanup | InitError::Accounting => LaunchErrorCode::CleanupFailure,
        _ => LaunchErrorCode::PolicyRejected,
    }
}

fn send_job_error<S: InitPlatform>(
    system: &mut S,
    session: DwHandle,
    reservation: LaunchReservation,
    code: LaunchErrorCode,
) -> Result<(), InitError> {
    let mut response = [0_u8; 88];
    let size =
        encode_launch_error(reservation, code, &mut response).map_err(|_| InitError::Accounting)?;
    system
        .send_channel(session, &response[..size])
        .map_err(InitError::Native)
}

fn controller_result_to_wire(result: ControllerJobResult) -> Result<TerminationResult, InitError> {
    let classification = match result.classification {
        1 => TerminationClassification::NormalExit,
        2 => TerminationClassification::Authorized,
        3 => TerminationClassification::UnhandledException,
        4 => TerminationClassification::ResourcePolicy,
        5 => TerminationClassification::TaskGroupTeardown,
        _ => return Err(InitError::Accounting),
    };
    Ok(TerminationResult {
        classification,
        application_code: result.application_code,
        exception_class: result.exception_class,
        exception_detail: result.exception_detail,
        exception_address: result.exception_address,
        cleanup_result: result.cleanup_result,
    })
}

#[allow(clippy::too_many_arguments)]
fn dispatch_reserved_operation<S, W>(
    system: &mut S,
    _waits: &mut W,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    grant: EndpointGrant,
    reservation: LaunchReservation,
    ticket: RequestTicket,
    message: LaunchMessage<'_>,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut response = [0_u8; 320];
    let result: Result<Option<usize>, JobError> = match message {
        LaunchMessage::Query { job_id } => {
            jobs.jobs
                .query_reserved(ticket, job_id)
                .and_then(|snapshot| {
                    let phase = match snapshot.phase {
                        crate::wyr1b::JobPhase::Running => wyrmroot_launch_proto::JobPhase::Running,
                        crate::wyr1b::JobPhase::Terminating => {
                            wyrmroot_launch_proto::JobPhase::Terminating
                        }
                        crate::wyr1b::JobPhase::Reserved => return Err(JobError::WrongState),
                    };
                    encode_job_state(reservation, job_id, phase, &mut response)
                        .map(Some)
                        .map_err(|_| JobError::WrongState)
                })
        }
        LaunchMessage::Wait { job_id } => (|| -> Result<Option<usize>, JobError> {
            match jobs.jobs.result_reserved(ticket, job_id) {
                Ok(controller) => {
                    let terminal =
                        controller_result_to_wire(controller).map_err(|_| JobError::WrongState)?;
                    encode_job_result(reservation, job_id, terminal, &mut response)
                        .map(Some)
                        .map_err(|_| JobError::WrongState)
                }
                Err(JobError::UnknownJob) => {
                    jobs.jobs.query_reserved(ticket, job_id)?;
                    jobs.install_pending_wait(grant, reservation, job_id)?;
                    Ok(None)
                }
                Err(error) => Err(error),
            }
        })(),
        LaunchMessage::Terminate { job_id } => {
            let resources = match jobs.jobs.authorize_terminate_reserved(ticket, job_id) {
                Ok(resources) => resources,
                Err(error) => {
                    return send_job_error(system, session, reservation, job_error_code(error));
                }
            };
            if system
                .terminate_task_group(DwHandle(resources.task_group))
                .is_err()
            {
                jobs.jobs
                    .record_cleanup_bits(job_id, 1 << 0)
                    .map_err(InitError::Wyr1BModel)?;
                return send_job_error(
                    system,
                    session,
                    reservation,
                    LaunchErrorCode::CleanupFailure,
                );
            }
            jobs.jobs
                .commit_terminate(job_id, resources)
                .and_then(|()| {
                    encode_job_message(
                        reservation,
                        LaunchMessageType::TerminationAccepted,
                        job_id,
                        &mut response,
                    )
                    .map(Some)
                    .map_err(|_| JobError::WrongState)
                })
        }
        LaunchMessage::ListJobs => {
            let mut ids = [0_u64; wyrmroot_launch_proto::MAX_LIVE_JOBS];
            jobs.jobs.list_reserved(ticket, &mut ids).and_then(|count| {
                encode_job_list(reservation, &ids[..count], &mut response)
                    .map(Some)
                    .map_err(|_| JobError::WrongState)
            })
        }
        LaunchMessage::CloseJob { job_id } => {
            jobs.jobs.close_job_reserved(ticket, job_id).and_then(|()| {
                jobs.drop_job_waits(grant, job_id);
                encode_job_message(
                    reservation,
                    LaunchMessageType::Closed,
                    job_id,
                    &mut response,
                )
                .map(Some)
                .map_err(|_| JobError::WrongState)
            })
        }
        LaunchMessage::Cancel {
            target_transaction_id,
        } => {
            if jobs
                .cancel_pending_wait(grant, target_transaction_id)
                .is_none()
            {
                return send_job_error(
                    system,
                    session,
                    reservation,
                    LaunchErrorCode::CancellationUnavailable,
                );
            }
            encode_job_message(
                reservation,
                LaunchMessageType::Cancelled,
                target_transaction_id,
                &mut response,
            )
            .map(Some)
            .map_err(|_| JobError::WrongState)
        }
        _ => Err(JobError::WrongState),
    };
    match result {
        Ok(Some(size)) => system
            .send_channel(session, &response[..size])
            .map_err(InitError::Native),
        Ok(None) => Ok(()),
        Err(error) => send_job_error(system, session, reservation, job_error_code(error)),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JobDispatchOutcome {
    Responded,
    Launched(crate::wyr1b::LoadedJob),
}

#[allow(clippy::too_many_arguments)]
fn dispatch_one_job_request<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: Option<&PolicyView<'_>>,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    grant: EndpointGrant,
) -> Result<JobDispatchOutcome, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut bytes = [0_u8; wyrmroot_launch_proto::MAX_STRING_BYTES + 2048];
    let mut received = [DwReceivedHandleInfoV1::default(); 16];
    let counts = system
        .receive_channel(session, &mut bytes, &mut received)
        .map_err(InitError::Native)?;
    if counts.bytes > bytes.len() || counts.handles > received.len() {
        let failed = close_received_reverse(system, &received, counts.handles);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Wyr1BModel(JobError::StreamPolicy)
        });
    }
    let reservation = match parse_reservation_prefix(&bytes[..counts.bytes]) {
        Ok(reservation) => reservation,
        Err(_) => {
            let failed = close_received_reverse(system, &received, counts.handles);
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Wyr1BModel(JobError::WrongState)
            });
        }
    };
    if reservation.connection_id != grant.endpoint_id
        || reservation.generation != grant.endpoint_generation
    {
        let failed = close_received_reverse(system, &received, counts.handles);
        if failed {
            return Err(InitError::Cleanup);
        }
        send_job_error(
            system,
            session,
            reservation,
            LaunchErrorCode::StaleOrUnknownSession,
        )?;
        return Ok(JobDispatchOutcome::Responded);
    }
    let request_ticket = match jobs.jobs.reserve_request(reservation) {
        Ok(ticket) => ticket,
        Err(error) => {
            let failed = close_received_reverse(system, &received, counts.handles);
            if failed {
                return Err(InitError::Cleanup);
            }
            send_job_error(system, session, reservation, job_error_code(error))?;
            return Ok(JobDispatchOutcome::Responded);
        }
    };
    let parsed = match parse_launch_message(&bytes[..counts.bytes], counts.handles) {
        Ok(parsed) => parsed,
        Err(_) => {
            let failed = close_received_reverse(system, &received, counts.handles);
            if failed {
                return Err(InitError::Cleanup);
            }
            send_job_error(
                system,
                session,
                reservation,
                LaunchErrorCode::MalformedRequest,
            )?;
            return Ok(JobDispatchOutcome::Responded);
        }
    };
    match parsed.message {
        LaunchMessage::Launch(request) => {
            let Some(policy) = policy else {
                if close_received_reverse(system, &received, counts.handles) {
                    return Err(InitError::Cleanup);
                }
                send_job_error(
                    system,
                    session,
                    reservation,
                    LaunchErrorCode::PolicyRejected,
                )?;
                return Ok(JobDispatchOutcome::Responded);
            };
            match accept_reserved_launch(
                system,
                loader,
                waits,
                authority,
                policy,
                jobs,
                session,
                reservation,
                request_ticket,
                request,
                &received,
                counts.handles,
            ) {
                Ok(loaded) => Ok(JobDispatchOutcome::Launched(loaded)),
                Err(error) => {
                    send_job_error(system, session, reservation, launch_error_code(&error))?;
                    if error == InitError::Cleanup {
                        Err(error)
                    } else {
                        Ok(JobDispatchOutcome::Responded)
                    }
                }
            }
        }
        message => {
            if close_received_reverse(system, &received, counts.handles) {
                return Err(InitError::Cleanup);
            }
            dispatch_reserved_operation(
                system,
                waits,
                jobs,
                session,
                grant,
                reservation,
                request_ticket,
                message,
            )?;
            Ok(JobDispatchOutcome::Responded)
        }
    }
}

fn poll_job_dispatcher<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    jobs: &mut JobDispatcher,
    now_ns: u64,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    if let Some((grant, session)) = jobs.next_session() {
        let item = DwWaitItemV1 {
            handle: session,
            signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        };
        match system.wait_many(core::slice::from_ref(&item), DwDeadline(now_ns)) {
            Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {}
            Err(error) => return Err(InitError::Native(error)),
            Ok(observed) if observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 => {
                let size = system
                    .query_memory_object_size(authority.bootfs)
                    .map_err(InitError::Native)?;
                let plan = MappingPlan::for_bootfs(size).map_err(|error| {
                    ordinary_mapping_error(MappingDiagnosticSite::JobDispatcher, error, size)
                })?;
                let dispatched = system
                    .with_bootfs_bytes(
                        authority.parent_root,
                        authority.bootfs,
                        plan,
                        |system, bootfs| {
                            let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
                            let manifest = archive
                                .lookup(MANIFEST_PATH.as_bytes())
                                .map_err(map_lookup)?;
                            let boot_generation: [u8; 32] = manifest
                                .data()
                                .get(48..80)
                                .ok_or(InitError::Accounting)?
                                .try_into()
                                .map_err(|_| InitError::Accounting)?;
                            let policy = PolicyView::from_bootfs(archive, boot_generation)
                                .map_err(InitError::Wyr1BModel)?;
                            dispatch_one_job_request(
                                system,
                                loader,
                                waits,
                                authority,
                                Some(&policy),
                                jobs,
                                session,
                                grant,
                            )
                        },
                    )
                    .map_err(InitError::Native)?;
                if let Err(dispatch_error) = dispatched {
                    let disconnected = jobs.disconnect_owned_session(grant);
                    let close_failed = disconnected.map_or(true, |session| {
                        system.close_handle(session.channel).is_err()
                            | cleanup_session_owner(system, waits, session.owner, true)
                    });
                    if close_failed {
                        return Err(InitError::Cleanup);
                    }
                    return Err(dispatch_error);
                }
            }
            Ok(observed) if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 => {
                let disconnected = jobs
                    .disconnect_owned_session(grant)
                    .map_err(InitError::Wyr1BModel)?;
                if system.close_handle(disconnected.channel).is_err()
                    | cleanup_session_owner(system, waits, disconnected.owner, true)
                {
                    return Err(InitError::Cleanup);
                }
            }
            Ok(_) => return Err(InitError::Supervision),
        }
    }
    if let Some(loaded) = jobs.next_cleanup_job() {
        let terminal_staged = jobs
            .jobs
            .terminal_result(loaded.job_id)
            .map_err(InitError::Wyr1BModel)?
            .is_some();
        let exited = if terminal_staged {
            true
        } else if loaded.loaded.process.0 == 0 {
            return Err(InitError::Accounting);
        } else {
            match waits.query_task_termination(loaded.loaded.process) {
                Ok(info) => info.state == DW_TASK_STATE_EXITED,
                Err(_) => {
                    jobs.jobs
                        .record_cleanup_bits(loaded.job_id, 1 << 1)
                        .map_err(InitError::Wyr1BModel)?;
                    return Err(InitError::Cleanup);
                }
            }
        };
        if exited {
            let result = reap_job(system, waits, jobs, loaded)?;
            if result.cleanup_result != 0 {
                return Err(InitError::Cleanup);
            }
        }
    }
    service_pending_wait(system, waits, jobs)?;
    Ok(())
}

fn service_pending_wait<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let Some(pending) = jobs.next_pending_wait() else {
        return Ok(());
    };
    let result = match jobs.jobs.result_for_owner(
        pending.reservation.connection_id,
        pending.reservation.generation,
        pending.job_id,
    ) {
        Ok(result) => result,
        Err(JobError::UnknownJob) => return Ok(()),
        Err(error) => return Err(InitError::Wyr1BModel(error)),
    };
    let session = jobs
        .session_handle(pending.grant)
        .map_err(InitError::Wyr1BModel)?;
    let terminal = controller_result_to_wire(result)?;
    let mut response = [0_u8; 88];
    let size = encode_job_result(pending.reservation, pending.job_id, terminal, &mut response)
        .map_err(|_| InitError::Accounting)?;
    if let Err(error) = system.send_channel(session, &response[..size]) {
        jobs.finish_pending_wait(pending)
            .map_err(InitError::Wyr1BModel)?;
        let disconnected = jobs
            .disconnect_owned_session(pending.grant)
            .map_err(InitError::Wyr1BModel)?;
        let failed = system.close_handle(disconnected.channel).is_err()
            | cleanup_session_owner(system, waits, disconnected.owner, true);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Native(error)
        });
    }
    jobs.finish_pending_wait(pending)
        .map_err(InitError::Wyr1BModel)
}

fn cleanup_session_owner<S, W>(
    system: &mut S,
    waits: &mut W,
    owner: Option<SessionOwner>,
    terminate: bool,
) -> bool
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    owner.is_some_and(|owner| {
        cleanup_loaded(
            system,
            waits,
            LoadedProcess {
                process: owner.process,
                launch_channel: owner.launch_channel,
            },
            owner.task_group,
            terminate,
        )
        .is_err()
    })
}

fn drain_job_dispatcher<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut sessions = [None; crate::wyr1b_job::MAX_SESSIONS];
    let session_count = jobs.drain_sessions(&mut sessions);
    let mut failed = false;
    for session in sessions[..session_count].iter().rev().flatten().copied() {
        failed |= system.close_handle(session.channel).is_err()
            | cleanup_session_owner(system, waits, session.owner, true);
    }
    let job_count = jobs.jobs.live_jobs();
    for _ in 0..job_count {
        let Some(loaded) = jobs.next_cleanup_job() else {
            break;
        };
        if let Some(resources) = jobs
            .jobs
            .forced_termination_resources(loaded.job_id)
            .map_err(InitError::Wyr1BModel)?
        {
            if system
                .terminate_task_group(DwHandle(resources.task_group))
                .is_err()
            {
                jobs.jobs
                    .record_cleanup_bits(loaded.job_id, 1 << 0)
                    .map_err(InitError::Wyr1BModel)?;
                failed = true;
            } else {
                jobs.jobs
                    .commit_forced_termination(loaded.job_id, resources)
                    .map_err(InitError::Wyr1BModel)?;
            }
        }
        match reap_job(system, waits, jobs, loaded) {
            Ok(result) => failed |= result.cleanup_result != 0,
            Err(_) => failed = true,
        }
    }
    if jobs.jobs.live_jobs() != 0 || failed {
        Err(InitError::Cleanup)
    } else {
        Ok(())
    }
}

fn close_launch_client<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    peer: InstalledPeer,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let session = jobs
        .session_handle(peer.grant)
        .map_err(InitError::Wyr1BModel)?;
    let deadline = report_deadline(system)?;
    let result = system
        .wait_many(
            core::slice::from_ref(&DwWaitItemV1 {
                handle: session,
                signals: DW_SIGNAL_PEER_CLOSED,
            }),
            deadline,
        )
        .map_err(InitError::Native)?;
    if result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 == 0 {
        return Err(InitError::Supervision);
    }
    let disconnected = jobs
        .disconnect_owned_session(peer.grant)
        .map_err(InitError::Wyr1BModel)?;
    let expected_owner = SessionOwner {
        process: peer.loaded.process,
        launch_channel: peer.loaded.launch_channel,
        task_group: peer.task_group,
    };
    if disconnected.owner != Some(expected_owner) {
        return Err(InitError::Accounting);
    }
    let failed = system.close_handle(disconnected.channel).is_err()
        | cleanup_session_owner(system, waits, disconnected.owner, false);
    if failed {
        Err(InitError::Cleanup)
    } else {
        Ok(())
    }
}

fn launch_gate_record(
    message_type: GateMessageType,
    gate: GateConfig,
    actor: EndpointGrant,
    object_id: u64,
    object_generation: u64,
    operation_id: u64,
) -> GateRecord {
    GateRecord {
        message_type,
        nonce: gate.nonce,
        registry_generation: actor.registry_generation,
        actor_id: actor.endpoint_id,
        actor_generation: actor.endpoint_generation,
        object_id,
        object_generation,
        operation_id,
        value: 0,
    }
}

fn expect_launch_report<S: Wyr1BPlatform>(
    system: &mut S,
    peer: InstalledPeer,
    expected: GateRecord,
) -> Result<(), InitError> {
    let deadline = report_deadline(system)?;
    let actual = receive_gate(system, peer.loaded.launch_channel, deadline)?;
    expect_gate(actual, expected)
}

#[allow(clippy::too_many_arguments)]
fn dispatch_owner_wait_then_poll<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: Option<&PolicyView<'_>>,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    grant: EndpointGrant,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    if dispatch_one_job_request(
        system, loader, waits, authority, policy, jobs, session, grant,
    )? != JobDispatchOutcome::Responded
    {
        return Err(InitError::Wyr1BModel(JobError::WrongState));
    }
    let poll_now = system.now().map_err(InitError::Native)?;
    poll_job_dispatcher(system, loader, waits, authority, jobs, poll_now)
}

fn record_owner_job_reap(
    evidence: &mut EvidenceLog,
    owner: EndpointGrant,
    job_id: u64,
    result: ControllerJobResult,
) -> Result<(), InitError> {
    if result.classification != TerminationClassification::NormalExit.as_u32()
        || result.application_code != 0
        || result.cleanup_result != 0
    {
        return Err(InitError::Wyr1BGateMismatch);
    }
    evidence
        .record(GateEvent::JobExitZero, job_id, owner.endpoint_generation, 0)
        .map_err(InitError::Wyr1BEvidence)?;
    evidence
        .record(
            GateEvent::JobReaped,
            job_id,
            owner.endpoint_generation,
            owner.endpoint_id,
        )
        .map_err(InitError::Wyr1BEvidence)
}

#[allow(clippy::too_many_arguments)]
fn run_job_gate<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    bootfs: &[u8],
    topology: &mut RegistryTopology,
    gate: GateConfig,
    jobs: &mut JobDispatcher,
    evidence: &mut EvidenceLog,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
    let manifest = archive
        .lookup(MANIFEST_PATH.as_bytes())
        .map_err(map_lookup)?;
    let boot_generation: [u8; 32] = manifest
        .data()
        .get(48..80)
        .ok_or(InitError::Accounting)?
        .try_into()
        .map_err(|_| InitError::Accounting)?;
    let policy =
        PolicyView::from_bootfs(archive, boot_generation).map_err(InitError::Wyr1BModel)?;

    let owner = launch_launch_client(system, loader, waits, authority, bootfs, topology, jobs, 3)?;
    let (_, owner_session) = jobs.next_session().ok_or(InitError::Accounting)?;
    let owner_config = launch_gate_record(
        GateMessageType::ConfigureLaunchOwner,
        gate,
        owner.grant,
        0,
        0,
        3,
    );
    send_gate(system, owner.loaded.launch_channel, owner_config)?;
    let owner_job = receive_and_accept_job(
        system,
        loader,
        waits,
        authority,
        &policy,
        jobs,
        owner_session,
        owner.grant,
    )?;
    expect_launch_report(
        system,
        owner,
        launch_gate_record(
            GateMessageType::JobAccepted,
            gate,
            owner.grant,
            owner_job.job_id,
            owner.grant.endpoint_generation,
            3,
        ),
    )?;
    evidence
        .record(
            GateEvent::JobAccepted,
            owner_job.job_id,
            owner.grant.endpoint_generation,
            owner.grant.endpoint_id,
        )
        .map_err(InitError::Wyr1BEvidence)?;
    wait_session_readable(system, owner_session)?;
    dispatch_owner_wait_then_poll(
        system,
        loader,
        waits,
        authority,
        Some(&policy),
        jobs,
        owner_session,
        owner.grant,
    )?;
    let job_id = owner_job.job_id;
    expect_launch_report(
        system,
        owner,
        launch_gate_record(
            GateMessageType::JobResult,
            gate,
            owner.grant,
            job_id,
            owner.grant.endpoint_generation,
            3,
        ),
    )?;
    let owner_result = jobs
        .jobs
        .result_for_owner(
            owner.grant.endpoint_id,
            owner.grant.endpoint_generation,
            job_id,
        )
        .map_err(InitError::Wyr1BModel)?;
    record_owner_job_reap(&mut *evidence, owner.grant, job_id, owner_result)?;
    close_launch_client(system, waits, jobs, owner)?;

    let foreign =
        launch_launch_client(system, loader, waits, authority, bootfs, topology, jobs, 4)?;
    let (_, foreign_session) = jobs.next_session().ok_or(InitError::Accounting)?;
    let foreign_config = launch_gate_record(
        GateMessageType::ConfigureLaunchForeign,
        gate,
        foreign.grant,
        owner.grant.endpoint_id,
        owner.grant.endpoint_generation,
        4,
    );
    send_gate(system, foreign.loaded.launch_channel, foreign_config)?;
    let probe = launch_gate_record(
        GateMessageType::ProbeForeign,
        gate,
        foreign.grant,
        job_id,
        owner.grant.endpoint_generation,
        4,
    );
    send_gate(system, foreign.loaded.launch_channel, probe)?;
    wait_session_readable(system, foreign_session)?;
    if dispatch_one_job_request(
        system,
        loader,
        waits,
        authority,
        Some(&policy),
        jobs,
        foreign_session,
        foreign.grant,
    )? != JobDispatchOutcome::Responded
    {
        return Err(InitError::Wyr1BModel(JobError::WrongState));
    }
    expect_launch_report(
        system,
        foreign,
        launch_gate_record(
            GateMessageType::ForeignRejected,
            gate,
            foreign.grant,
            job_id,
            owner.grant.endpoint_generation,
            4,
        ),
    )?;
    evidence
        .record(
            GateEvent::ForeignRejected,
            foreign.grant.endpoint_id,
            foreign.grant.endpoint_generation,
            job_id,
        )
        .map_err(InitError::Wyr1BEvidence)?;
    close_launch_client(system, waits, jobs, foreign)?;

    let orphan = launch_launch_client(system, loader, waits, authority, bootfs, topology, jobs, 5)?;
    let (_, orphan_session) = jobs.next_session().ok_or(InitError::Accounting)?;
    let orphan_config = launch_gate_record(
        GateMessageType::ConfigureLaunchOwner,
        gate,
        orphan.grant,
        0,
        0,
        5,
    );
    send_gate(system, orphan.loaded.launch_channel, orphan_config)?;
    let orphan_job = receive_and_accept_job(
        system,
        loader,
        waits,
        authority,
        &policy,
        jobs,
        orphan_session,
        orphan.grant,
    )?;
    expect_launch_report(
        system,
        orphan,
        launch_gate_record(
            GateMessageType::OrphanDisconnecting,
            gate,
            orphan.grant,
            orphan_job.job_id,
            orphan.grant.endpoint_generation,
            5,
        ),
    )?;
    close_launch_client(system, waits, jobs, orphan)?;
    let orphan_result = reap_job(system, waits, jobs, orphan_job)?;
    if orphan_result.cleanup_result != 0 {
        return Err(InitError::Cleanup);
    }
    evidence
        .record(
            GateEvent::OrphanReaped,
            orphan_job.job_id,
            orphan.grant.endpoint_generation,
            orphan.grant.endpoint_id,
        )
        .map_err(InitError::Wyr1BEvidence)?;
    jobs.jobs.reclaim_closed_sessions();
    if jobs.session_count() != 0 || jobs.jobs.live_jobs() != 0 || jobs.jobs.orphan_jobs() != 0 {
        return Err(InitError::Accounting);
    }
    evidence.finish().map_err(InitError::Wyr1BEvidence)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_registry_gate<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    bootfs: &[u8],
    registry: RegistryNativeAttempt,
    topology: &mut RegistryTopology,
    gate: GateConfig,
    jobs: &mut JobDispatcher,
) -> Result<EvidenceLog, GateRunError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut publisher1 = None;
    let mut publisher2 = None;
    let mut client = None;
    let mut install_committed = false;
    let mut evidence = EvidenceLog::new(gate.nonce)
        .map_err(|error| GateRunError::PreInstall(InitError::Wyr1BEvidence(error)))?;
    let outcome: Result<(), InitError> = (|| {
        if registry.active.role != RoleId::Registryd || registry.active.generation == 0 {
            return Err(InitError::Wyr1BGateMismatch);
        }
        evidence
            .record(
                GateEvent::RegistryReady,
                RoleId::Registryd as u64,
                registry.active.generation,
                registry.active.transaction_id,
            )
            .map_err(InitError::Wyr1BEvidence)?;
        macro_rules! launch {
            ($slot:ident, $kind:expr) => {{
                match retry_preinstall_once(|| {
                    launch_peer(
                        system,
                        loader,
                        waits,
                        authority,
                        bootfs,
                        registry.control_channel,
                        topology,
                        $kind,
                    )
                }) {
                    Ok(peer) => {
                        install_committed = true;
                        $slot = Some(peer);
                    }
                    Err(PeerLaunchError::PreInstall(error)) => return Err(error),
                    Err(PeerLaunchError::InstallCommitted(error)) => {
                        install_committed = true;
                        return Err(error);
                    }
                }
            }};
        }

        launch!(publisher1, PeerKind::Publisher { operation: 1 });
        launch!(client, PeerKind::Client);
        let first = publisher1.ok_or(InitError::Accounting)?;
        let client_peer = client.ok_or(InitError::Accounting)?;
        let publisher1_config = configure_publisher(system, gate, first, client_peer, 1)?;
        if first.grant.registry_generation != registry.active.generation {
            return Err(InitError::Wyr1BGateMismatch);
        }
        evidence
            .record(
                GateEvent::PublisherReady,
                first.grant.endpoint_id,
                first.grant.endpoint_generation,
                first.grant.role_generation,
            )
            .map_err(InitError::Wyr1BEvidence)?;
        expect_report(system, first, publisher1_config, GateMessageType::Published)?;
        let client1_config = configure_client(system, gate, client_peer, first, 1)?;
        if client_peer.grant.registry_generation != registry.active.generation {
            return Err(InitError::Wyr1BGateMismatch);
        }
        evidence
            .record(
                GateEvent::ClientReady,
                client_peer.grant.endpoint_id,
                client_peer.grant.endpoint_generation,
                client_peer.grant.role_generation,
            )
            .map_err(InitError::Wyr1BEvidence)?;
        evidence
            .record(
                GateEvent::Published,
                first.grant.endpoint_id,
                first.grant.endpoint_generation,
                first.grant.role_generation,
            )
            .map_err(InitError::Wyr1BEvidence)?;
        expect_report(
            system,
            client_peer,
            client1_config,
            GateMessageType::Connected,
        )?;
        evidence
            .record(
                GateEvent::Connected,
                client_peer.grant.endpoint_id,
                client_peer.grant.endpoint_generation,
                first.grant.endpoint_id,
            )
            .map_err(InitError::Wyr1BEvidence)?;
        let challenge = complete_direct_exchange(
            system,
            first,
            client_peer,
            publisher1_config,
            client1_config,
        )?;
        evidence
            .record(
                GateEvent::DirectExchange,
                client_peer.grant.endpoint_id,
                client_peer.grant.endpoint_generation,
                challenge,
            )
            .map_err(InitError::Wyr1BEvidence)?;

        let retire = gate_record(
            GateMessageType::Retire,
            gate,
            first.grant,
            client_peer.grant,
            1,
        );
        send_gate(system, first.loaded.launch_channel, retire)?;
        expect_report(system, first, retire, GateMessageType::Retired)?;
        evidence
            .record(
                GateEvent::Retired,
                first.grant.endpoint_id,
                first.grant.endpoint_generation,
                first.grant.role_generation,
            )
            .map_err(InitError::Wyr1BEvidence)?;

        launch!(publisher2, PeerKind::Publisher { operation: 2 });
        let second = publisher2.ok_or(InitError::Accounting)?;
        let publisher2_config = configure_publisher(system, gate, second, client_peer, 2)?;
        expect_report(
            system,
            second,
            publisher2_config,
            GateMessageType::Published,
        )?;
        let client2_config = configure_client(system, gate, client_peer, second, 2)?;
        expect_report(
            system,
            client_peer,
            client2_config,
            GateMessageType::Connected,
        )?;
        let _ = complete_direct_exchange(
            system,
            second,
            client_peer,
            publisher2_config,
            client2_config,
        )?;

        let stale = gate_record(
            GateMessageType::ProbeStale,
            gate,
            first.grant,
            second.grant,
            2,
        );
        send_gate(system, first.loaded.launch_channel, stale)?;
        expect_report(system, first, stale, GateMessageType::StaleRejected)?;
        evidence
            .record(
                GateEvent::StaleRejected,
                first.grant.endpoint_id,
                first.grant.endpoint_generation,
                second.grant.endpoint_id,
            )
            .map_err(InitError::Wyr1BEvidence)?;
        send_gate(
            system,
            first.loaded.launch_channel,
            done_record(gate, first, 2),
        )?;
        send_gate(
            system,
            second.loaded.launch_channel,
            done_record(gate, second, 2),
        )?;
        send_gate(
            system,
            client_peer.loaded.launch_channel,
            done_record(gate, client_peer, 2),
        )?;

        let first = publisher1.take().ok_or(InitError::Accounting)?;
        cleanup_loaded(system, waits, first.loaded, first.task_group, false)?;
        let second = publisher2.take().ok_or(InitError::Accounting)?;
        cleanup_loaded(system, waits, second.loaded, second.task_group, false)?;
        let client_peer = client.take().ok_or(InitError::Accounting)?;
        cleanup_loaded(
            system,
            waits,
            client_peer.loaded,
            client_peer.task_group,
            false,
        )?;
        run_job_gate(
            system,
            loader,
            waits,
            authority,
            bootfs,
            topology,
            gate,
            jobs,
            &mut evidence,
        )?;
        Ok(())
    })();
    if let Err(error) = outcome {
        let mut cleanup_failed =
            error == InitError::Cleanup || drain_job_dispatcher(system, waits, jobs).is_err();
        for slot in [&mut publisher2, &mut client, &mut publisher1] {
            if let Some(peer) = slot.take() {
                cleanup_failed |=
                    cleanup_loaded(system, waits, peer.loaded, peer.task_group, true).is_err();
            }
        }
        return Err(classify_gate_run_error(
            install_committed,
            cleanup_failed,
            error,
        ));
    }
    Ok(evidence)
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn run_registry_replacement_gate<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    bootfs: &[u8],
    registry: RegistryNativeAttempt,
    topology: &mut RegistryTopology,
    gate: GateConfig,
    jobs: &mut JobDispatcher,
) -> ReplacementGateOutcome
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    match run_registry_gate(
        system, loader, waits, authority, bootfs, registry, topology, gate, jobs,
    ) {
        Ok(_) => ReplacementGateOutcome::Complete,
        Err(GateRunError::PreInstall(_)) => ReplacementGateOutcome::PreInstall,
        Err(GateRunError::CleanupFailed(_)) => ReplacementGateOutcome::CleanupFailed,
        Err(GateRunError::InstallCommitted {
            error: _,
            cleanup_failed,
        }) => ReplacementGateOutcome::InstallCommitted { cleanup_failed },
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplacementGateOutcome {
    Complete,
    PreInstall,
    CleanupFailed,
    InstallCommitted { cleanup_failed: bool },
}

#[allow(clippy::too_many_arguments)]
fn launch_registry_replacement_with_gate<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    controller: &mut SystemInit,
    authority: LoadAuthority,
    bootfs: &[u8],
    topology: &mut RegistryTopology,
    gate: GateConfig,
    jobs: &mut JobDispatcher,
) -> Result<Option<(RegistryNativeAttempt, bool)>, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    loop {
        let Some(registry) =
            launch_registry_until_ready(system, loader, waits, controller, authority, bootfs)?
        else {
            return Ok(None);
        };
        let registry = restart_topology_or_poison(system, waits, controller, topology, registry)?;
        match run_registry_replacement_gate(
            system, loader, waits, authority, bootfs, registry, topology, gate, jobs,
        ) {
            ReplacementGateOutcome::Complete => return Ok(Some((registry, true))),
            ReplacementGateOutcome::PreInstall => return Ok(Some((registry, false))),
            ReplacementGateOutcome::CleanupFailed => {
                let _ = poison_registry_generation(system, waits, controller, registry, true)?;
                return Ok(None);
            }
            ReplacementGateOutcome::InstallCommitted { cleanup_failed } => {
                if poison_registry_generation(system, waits, controller, registry, cleanup_failed)?
                {
                    return Ok(None);
                }
            }
        }
    }
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
    let ResidentSystemInit {
        controller,
        authority,
        result,
        active: active_roles,
        wyr1b,
        ..
    } = resident;
    let state = wyr1b.as_mut().ok_or(InitError::WrongActivationOrder)?;
    for active_slot in active_roles.iter_mut() {
        let Some(active) = *active_slot else {
            continue;
        };
        let poll_items = [
            DwWaitItemV1 {
                handle: active.loaded.launch_channel,
                signals: deepwyrm_syscall::DwSignals(
                    DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0,
                ),
            },
            DwWaitItemV1 {
                handle: active.loaded.process,
                signals: DW_SIGNAL_EXITED,
            },
        ];
        let profile = if active.role == RoleId::Registryd {
            LaunchProfile::BootstrapRegistry
        } else {
            LaunchProfile::EarlyBootStub
        };
        let observed = match waits.wait_many(&poll_items, DwDeadline(now_ns)) {
            Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => continue,
            Err(error) => Err(ObservedSupervisionError::Supervision(
                SupervisionError::Platform(error),
            )),
            Ok(_) => {
                let deadline = now_ns
                    .checked_add(WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns)
                    .ok_or(InitError::Accounting)?;
                supervise_ready_child_profile(
                    waits,
                    active.loaded.process,
                    active.loaded.launch_channel,
                    profile,
                    active.transaction_id,
                    DwDeadline(deadline),
                )
            }
        };
        let (transition, terminate) = match observed {
            Ok(info) => (
                AfterReadyTransition::Terminal(terminal_disposition(&info)),
                false,
            ),
            Err(error) => (
                classify_after_ready_observation(&error),
                !error.process_exit_observed(),
            ),
        };
        match transition {
            AfterReadyTransition::Terminal(disposition) => controller.terminal(
                active.role,
                active.generation,
                active.transaction_id,
                now_ns,
                disposition,
            )?,
            AfterReadyTransition::Failure(failure) => controller.fail(
                active.role,
                active.generation,
                active.transaction_id,
                now_ns,
                failure,
            )?,
        }
        if active.role == RoleId::Devmgr {
            complete_native_cleanup(
                system,
                waits,
                controller,
                active.loaded,
                active.task_group,
                terminate,
                active.role,
                active.generation,
                active.transaction_id,
                now_ns,
            )?;
            *active_slot = None;
            if transition == AfterReadyTransition::Terminal(TerminalDisposition::NormalExit(0)) {
                continue;
            }
            if advance_or_degrade(system, controller, active.role, active.transaction_id)? {
                *result = RecoveryResult::Degraded;
                continue;
            }
            match remap_and_activate_role(
                system,
                loader,
                waits,
                *authority,
                controller,
                active.role,
            )? {
                RoleActivation::Ready(replacement) => *active_slot = Some(replacement),
                RoleActivation::Degraded => *result = RecoveryResult::Degraded,
            }
            continue;
        }

        let cleanup_failed = drain_job_dispatcher(system, waits, &mut state.jobs).is_err()
            | cleanup_loaded(system, waits, active.loaded, active.task_group, terminate).is_err()
            | system.close_handle(state.registry_control).is_err();
        *active_slot = None;
        state.registry_control = DwHandle(0);
        let retired_at = now_ns.checked_add(1).ok_or(InitError::Accounting)?;
        if cleanup_failed {
            controller.cleanup_failed(
                RoleId::Registryd,
                active.generation,
                active.transaction_id,
                retired_at,
            )?;
            *result = RecoveryResult::Degraded;
            continue;
        }
        controller.cleanup_complete(
            RoleId::Registryd,
            active.generation,
            active.transaction_id,
            retired_at,
        )?;
        if advance_registry_or_exhausted(system, controller, active.transaction_id)? {
            *result = RecoveryResult::Degraded;
            continue;
        }
        let size = system
            .query_memory_object_size(authority.bootfs)
            .map_err(InitError::Native)?;
        let plan = MappingPlan::for_bootfs(size).map_err(|error| {
            ordinary_mapping_error(MappingDiagnosticSite::RegistryReplacement, error, size)
        })?;
        let replacement = system
            .with_bootfs_bytes(
                authority.parent_root,
                authority.bootfs,
                plan,
                |system, bootfs| {
                    launch_registry_replacement_with_gate(
                        system,
                        loader,
                        waits,
                        controller,
                        *authority,
                        bootfs,
                        state
                            .topology
                            .as_mut()
                            .ok_or(InitError::WrongActivationOrder)?,
                        state.gate,
                        &mut state.jobs,
                    )
                },
            )
            .map_err(InitError::Native)??;
        if let Some((replacement, gate_complete)) = replacement {
            state.registry_control = replacement.control_channel;
            *active_slot = Some(replacement.active);
            if !gate_complete {
                *result = RecoveryResult::Degraded;
            }
        } else {
            *result = RecoveryResult::Degraded;
        }
    }
    poll_job_dispatcher(system, loader, waits, *authority, &mut state.jobs, now_ns)?;
    if controller.mode() == SystemMode::Degraded {
        *result = RecoveryResult::Degraded;
    }
    Ok(controller.mode())
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use alloc::{vec, vec::Vec};
    use deepwyrm_syscall::{DwMemoryProtection, DwStatus, DwWaitResultV1};
    use wyrmroot_bootfs::builder::{Builder as BootfsBuilder, FileMode};
    use wyrmroot_bootfs::launch_policy::{
        LAUNCH_POLICY_PATH, LaunchPolicyEntry, encode as encode_launch_policy,
    };
    use wyrmroot_loader::process::{ParentMapping, ProcessCreateRequest, ProcessCreateResult};
    use wyrmroot_registry_proto::{Message, parse};

    const FAILURE: NativeError = NativeError::Status(DwStatus(-1));

    struct MockPlatform {
        sent: [u8; 256],
        sent_len: usize,
        transfer: DwHandleTransferV1,
        fresh_rights: DwRights,
        queried: [DwHandle; 4],
        query_count: usize,
        created_rights: DwRights,
        closed: [DwHandle; 8],
        close_count: usize,
        fail_close: Option<DwHandle>,
        now: Option<u64>,
        terminate_count: usize,
        fail_terminate: bool,
        allow_wait: bool,
        session_poll_timeout: bool,
        task_group: Option<DwHandle>,
        fail_send: bool,
        inbound: [u8; 256],
        inbound_len: usize,
        inbound_handles: [DwReceivedHandleInfoV1; 16],
        inbound_handle_count: usize,
        bootfs: Option<Vec<u8>>,
        session_poll_readable: bool,
    }

    impl MockPlatform {
        fn new() -> Self {
            Self {
                sent: [0; 256],
                sent_len: 0,
                transfer: DwHandleTransferV1::default(),
                fresh_rights: CONTROLLER_CHANNEL_RIGHTS,
                queried: [DwHandle(0); 4],
                query_count: 0,
                created_rights: DwRights(0),
                closed: [DwHandle(0); 8],
                close_count: 0,
                fail_close: None,
                now: None,
                terminate_count: 0,
                fail_terminate: false,
                allow_wait: false,
                session_poll_timeout: false,
                task_group: None,
                fail_send: true,
                inbound: [0; 256],
                inbound_len: 0,
                inbound_handles: [DwReceivedHandleInfoV1::default(); 16],
                inbound_handle_count: 0,
                bootfs: None,
                session_poll_readable: false,
            }
        }
    }

    struct InitSendLoader {
        next: u64,
        closed: [DwHandle; 32],
        close_count: usize,
        transferred_service: Option<DwHandle>,
        fail_init: bool,
    }

    impl InitSendLoader {
        const fn new() -> Self {
            Self {
                next: 0x1000,
                closed: [DwHandle(0); 32],
                close_count: 0,
                transferred_service: None,
                fail_init: true,
            }
        }

        fn handle(&mut self) -> DwHandle {
            let handle = DwHandle(self.next);
            self.next += 1;
            handle
        }

        fn close_count(&self, handle: DwHandle) -> usize {
            self.closed[..self.close_count]
                .iter()
                .filter(|closed| **closed == handle)
                .count()
        }
    }

    impl LoaderPlatform for InitSendLoader {
        type Error = NativeError;

        fn channel_create(
            &mut self,
            _rights: DwRights,
        ) -> Result<(DwHandle, DwHandle), Self::Error> {
            Ok((self.handle(), self.handle()))
        }

        fn duplicate(
            &mut self,
            _handle: DwHandle,
            _rights: DwRights,
        ) -> Result<DwHandle, Self::Error> {
            Ok(self.handle())
        }

        fn close(&mut self, handle: DwHandle) -> Result<(), Self::Error> {
            self.closed[self.close_count] = handle;
            self.close_count += 1;
            Ok(())
        }

        fn process_create(
            &mut self,
            _request: ProcessCreateRequest,
        ) -> Result<ProcessCreateResult, Self::Error> {
            Ok(ProcessCreateResult {
                process: self.handle(),
                root: self.handle(),
                child_bootstrap: self.handle(),
            })
        }

        fn memory_create(
            &mut self,
            _bytes: u64,
            _rights: DwRights,
        ) -> Result<DwHandle, Self::Error> {
            Ok(self.handle())
        }

        fn materialize_parent(
            &mut self,
            _parent_root: DwHandle,
            memory: DwHandle,
            object_size: u64,
            _destination_offset: u64,
            _source: &[u8],
        ) -> Result<ParentMapping, Self::Error> {
            Ok(ParentMapping {
                address: 0x6000_0000 + memory.0 * 0x10_0000,
                bytes: object_size,
            })
        }

        fn materialize_parent_with(
            &mut self,
            _parent_root: DwHandle,
            memory: DwHandle,
            object_size: u64,
            _destination_offset: u64,
            destination_size: usize,
            materialize: impl FnOnce(&mut [u8]),
        ) -> Result<ParentMapping, Self::Error> {
            let mut destination = vec![0; destination_size];
            materialize(&mut destination);
            Ok(ParentMapping {
                address: 0x6000_0000 + memory.0 * 0x10_0000,
                bytes: object_size,
            })
        }

        fn unmap_parent(
            &mut self,
            _parent_root: DwHandle,
            _mapping: ParentMapping,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn map_child(
            &mut self,
            _child_root: DwHandle,
            _memory: DwHandle,
            _address: u64,
            _bytes: u64,
            _protection: DwMemoryProtection,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn unmap_child(
            &mut self,
            _child_root: DwHandle,
            _address: u64,
            _bytes: u64,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn thread_create(
            &mut self,
            _process: DwHandle,
            _rights: DwRights,
        ) -> Result<DwHandle, Self::Error> {
            Ok(self.handle())
        }

        fn send_init(
            &mut self,
            _channel: DwHandle,
            _bytes: &[u8],
            transfers: &[DwHandleTransferV1],
        ) -> Result<(), Self::Error> {
            self.transferred_service = transfers.last().map(|transfer| transfer.handle);
            if self.fail_init { Err(FAILURE) } else { Ok(()) }
        }

        fn thread_start(
            &mut self,
            _thread: DwHandle,
            _entry: u64,
            _stack_pointer: u64,
            _child_bootstrap: DwHandle,
            _startup_abi: u64,
        ) -> Result<(), Self::Error> {
            if self.fail_init {
                panic!("failed INIT must prevent thread start")
            }
            Ok(())
        }

        fn thread_terminate(&mut self, _thread: DwHandle) -> Result<(), Self::Error> {
            Ok(())
        }

        fn process_terminate(&mut self, _process: DwHandle) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn executable() -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x2000];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x400000_u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&0x1000_u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&0x400000_u64.to_le_bytes());
        bytes[88..96].copy_from_slice(&0x400000_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&16_u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&32_u64.to_le_bytes());
        bytes[112..120].copy_from_slice(&4096_u64.to_le_bytes());
        bytes
    }

    fn service_bootfs(path: &str, image: &[u8]) -> Vec<u8> {
        let mut builder = BootfsBuilder::new();
        builder
            .add(path.as_bytes(), image, FileMode::Executable)
            .unwrap();
        builder.build().unwrap()
    }

    fn job_policy_bootfs(image: &[u8]) -> (Vec<u8>, [u8; 32]) {
        let generation = [0x44; 32];
        let mut manifest = [0_u8; 80];
        manifest[48..80].copy_from_slice(&generation);
        let entry = LaunchPolicyEntry {
            path: "bin/hello",
            content_sha256: wyrmroot_runtime::sha256::digest(image),
            startup_abi: 2,
            profile_id: 1,
            allow_no_streams: true,
            allow_three_streams: true,
        };
        let mut policy = [0_u8; 512];
        let policy_size = encode_launch_policy(generation, &[entry], &mut policy).unwrap();
        let mut builder = BootfsBuilder::new();
        builder
            .add(b"bin/hello", image, FileMode::Executable)
            .unwrap();
        builder
            .add(
                LAUNCH_POLICY_PATH.as_bytes(),
                &policy[..policy_size],
                FileMode::ReadOnly,
            )
            .unwrap();
        builder
            .add(MANIFEST_PATH.as_bytes(), &manifest, FileMode::ReadOnly)
            .unwrap();
        (builder.build().unwrap(), generation)
    }

    fn starting_registry(image: &[u8]) -> SystemInit {
        let mut controller = SystemInit {
            mode: SystemMode::Bootstrap,
            roles: [
                RoleController::new(RoleId::Registryd, wyrmroot_runtime::sha256::digest(image))
                    .unwrap(),
                RoleController::new(RoleId::Devmgr, [2; 32]).unwrap(),
            ],
            degraded_transitions: 0,
            activated: [false; EARLY_ROLE_COUNT],
            accounting: AttemptLedger::new(),
            gate: None,
            evidence: None,
            registry_startup_profile: StartupProfile::BootstrapRegistry,
        };
        controller.become_operational().unwrap();
        controller.begin_registry(0, 1, 0x1001).unwrap();
        controller
    }

    impl InitPlatform for MockPlatform {
        fn query_capability_info(
            &mut self,
            handle: DwHandle,
        ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
            self.queried[self.query_count] = handle;
            self.query_count += 1;
            Ok(CapabilityInfo {
                object_type: DW_OBJECT_TYPE_CHANNEL,
                rights: self.fresh_rights,
            })
        }
        fn receive_channel(
            &mut self,
            _channel: DwHandle,
            bytes: &mut [u8],
            handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, NativeError> {
            if self.inbound_len == 0 {
                return Err(FAILURE);
            }
            bytes[..self.inbound_len].copy_from_slice(&self.inbound[..self.inbound_len]);
            handles[..self.inbound_handle_count]
                .copy_from_slice(&self.inbound_handles[..self.inbound_handle_count]);
            let bytes = self.inbound_len;
            let handles = self.inbound_handle_count;
            self.inbound_len = 0;
            self.inbound_handle_count = 0;
            Ok(ReceiveCounts { bytes, handles })
        }
        fn query_memory_object_size(&mut self, _handle: DwHandle) -> Result<u64, NativeError> {
            self.bootfs
                .as_ref()
                .map(|bootfs| bootfs.len() as u64)
                .ok_or(FAILURE)
        }
        fn with_bootfs_bytes<R>(
            &mut self,
            _root: DwHandle,
            _bootfs: DwHandle,
            _plan: MappingPlan,
            use_bytes: impl for<'a> FnOnce(&mut Self, &'a [u8]) -> R,
        ) -> Result<R, NativeError> {
            let bootfs = self.bootfs.take().ok_or(FAILURE)?;
            let result = use_bytes(self, &bootfs);
            self.bootfs = Some(bootfs);
            Ok(result)
        }
        fn send_channel(&mut self, _channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
            if self.fail_send {
                return Err(FAILURE);
            }
            self.sent[..bytes.len()].copy_from_slice(bytes);
            self.sent_len = bytes.len();
            Ok(())
        }
        fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
            self.closed[self.close_count] = handle;
            self.close_count += 1;
            if self.fail_close == Some(handle) {
                Err(FAILURE)
            } else {
                Ok(())
            }
        }
        fn create_attempt_task_group(
            &mut self,
            _parent: DwHandle,
        ) -> Result<DwHandle, NativeError> {
            self.task_group.ok_or(FAILURE)
        }
        fn terminate_task_group(&mut self, _task_group: DwHandle) -> Result<(), NativeError> {
            self.terminate_count += 1;
            if self.fail_terminate {
                Err(FAILURE)
            } else {
                Ok(())
            }
        }
        fn now(&mut self) -> Result<u64, NativeError> {
            self.now.ok_or(FAILURE)
        }
        fn wait_until(&mut self, deadline_ns: u64) -> Result<(), NativeError> {
            if self.allow_wait {
                self.now = Some(deadline_ns);
                Ok(())
            } else {
                Err(FAILURE)
            }
        }
    }

    struct TerminalWaits;

    impl SupervisionPlatform for TerminalWaits {
        type Error = NativeError;

        fn wait_many(
            &mut self,
            _items: &[DwWaitItemV1],
            _deadline: DwDeadline,
        ) -> Result<DwWaitResultV1, Self::Error> {
            Err(FAILURE)
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
            Ok(DwTaskTerminationInfoV1 {
                state: DW_TASK_STATE_EXITED,
                reason: DW_TERMINATION_NORMAL_EXIT,
                ..DwTaskTerminationInfoV1::default()
            })
        }
    }

    struct WaitFailureThenTerminal {
        query_count: usize,
    }

    impl SupervisionPlatform for WaitFailureThenTerminal {
        type Error = NativeError;

        fn wait_many(
            &mut self,
            _items: &[DwWaitItemV1],
            _deadline: DwDeadline,
        ) -> Result<DwWaitResultV1, Self::Error> {
            Err(FAILURE)
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
            self.query_count += 1;
            Ok(DwTaskTerminationInfoV1 {
                state: if self.query_count == 1 {
                    deepwyrm_syscall::DW_TASK_STATE_RUNNING
                } else {
                    DW_TASK_STATE_EXITED
                },
                reason: DW_TERMINATION_NORMAL_EXIT,
                ..DwTaskTerminationInfoV1::default()
            })
        }
    }

    impl Wyr1BPlatform for MockPlatform {
        fn channel_create(
            &mut self,
            rights: DwRights,
        ) -> Result<(DwHandle, DwHandle), NativeError> {
            self.created_rights = rights;
            Ok((DwHandle(20), DwHandle(21)))
        }
        fn send_channel_with_handles(
            &mut self,
            _channel: DwHandle,
            bytes: &[u8],
            transfers: &[DwHandleTransferV1],
        ) -> Result<(), NativeError> {
            assert_eq!(transfers.len(), 1);
            self.sent[..bytes.len()].copy_from_slice(bytes);
            self.sent_len = bytes.len();
            self.transfer = transfers[0];
            Ok(())
        }
        fn wait_many(
            &mut self,
            _items: &[DwWaitItemV1],
            _deadline: DwDeadline,
        ) -> Result<DwWaitResultV1, NativeError> {
            if self.session_poll_readable {
                Ok(DwWaitResultV1 {
                    index: 0,
                    observed: DW_SIGNAL_READABLE,
                    ..DwWaitResultV1::default()
                })
            } else if self.session_poll_timeout {
                Err(NativeError::Status(DW_STATUS_TIMED_OUT))
            } else {
                Err(FAILURE)
            }
        }
    }

    fn grant(kind: EndpointKind, endpoint_id: u64, role_generation: u64) -> EndpointGrant {
        EndpointGrant {
            registry_generation: 7,
            endpoint_id,
            endpoint_generation: 3,
            role_generation,
            kind,
        }
    }

    fn reservation(transaction_id: u64) -> LaunchReservation {
        LaunchReservation {
            connection_id: 1,
            generation: 3,
            transaction_id,
        }
    }

    fn evidence_through_job_accepted(
        gate: GateConfig,
        owner: EndpointGrant,
        job_id: u64,
    ) -> EvidenceLog {
        let publisher1 = grant(EndpointKind::Publication, 10, 1);
        let client = grant(EndpointKind::RegistryClient, 11, 1);
        let publisher2 = grant(EndpointKind::Publication, 12, 2);
        let mut evidence = EvidenceLog::new(gate.nonce).unwrap();
        for (event, subject, generation, value) in [
            (GateEvent::RegistryReady, RoleId::Registryd as u64, 7, 1),
            (
                GateEvent::PublisherReady,
                publisher1.endpoint_id,
                publisher1.endpoint_generation,
                publisher1.role_generation,
            ),
            (
                GateEvent::ClientReady,
                client.endpoint_id,
                client.endpoint_generation,
                client.role_generation,
            ),
            (
                GateEvent::Published,
                publisher1.endpoint_id,
                publisher1.endpoint_generation,
                publisher1.role_generation,
            ),
            (
                GateEvent::Connected,
                client.endpoint_id,
                client.endpoint_generation,
                publisher1.endpoint_id,
            ),
            (
                GateEvent::DirectExchange,
                client.endpoint_id,
                client.endpoint_generation,
                gate.nonce,
            ),
            (
                GateEvent::Retired,
                publisher1.endpoint_id,
                publisher1.endpoint_generation,
                publisher1.role_generation,
            ),
            (
                GateEvent::StaleRejected,
                publisher1.endpoint_id,
                publisher1.endpoint_generation,
                publisher2.endpoint_id,
            ),
            (
                GateEvent::JobAccepted,
                job_id,
                owner.endpoint_generation,
                owner.endpoint_id,
            ),
        ] {
            evidence.record(event, subject, generation, value).unwrap();
        }
        evidence
    }

    fn resident_with_wyr1b_evidence(evidence: EvidenceLog) -> ResidentSystemInit {
        let (controller, _) = ready_registry();
        ResidentSystemInit {
            controller,
            authority: LoadAuthority {
                parent_root: DwHandle(1),
                bootfs: DwHandle(2),
                task_group: DwHandle(3),
            },
            result: RecoveryResult::Recovered,
            active: [None; EARLY_ROLE_COUNT],
            evidence_finalized: false,
            last_tick_ns: 0,
            wyr1b: None,
            wyr1b_evidence: Some(evidence),
        }
    }

    #[test]
    fn native_gate_report_failure_exposes_no_partial_evidence() {
        let gate = GateConfig { nonce: 0x27 };
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        let mut evidence = EvidenceLog::new(gate.nonce).unwrap();
        evidence
            .record(GateEvent::RegistryReady, RoleId::Registryd as u64, 7, 1)
            .unwrap();
        let expected = launch_gate_record(
            GateMessageType::JobResult,
            gate,
            owner,
            1,
            owner.endpoint_generation,
            3,
        );
        let mut mismatched = expected;
        mismatched.value = 1;

        assert_eq!(
            expect_gate(mismatched, expected),
            Err(InitError::Wyr1BGateMismatch)
        );
        assert_eq!(evidence.recorded_events(), 1);
        let resident = resident_with_wyr1b_evidence(evidence);
        for index in 0..crate::wyr1b_gate::EVIDENCE_RECORDS {
            assert_eq!(resident.wyr1b_evidence_record(index), None);
        }
    }

    #[test]
    fn native_gate_mock_exposes_only_complete_clean_reap_transcript() {
        let gate = GateConfig { nonce: 0x27 };
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        let mut jobs = JobDispatcher::new();
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();
        let loaded = jobs.jobs.loaded_job(launch.job_id).unwrap();
        let mut platform = MockPlatform::new();
        let mut waits = TerminalWaits;
        let result = reap_job(&mut platform, &mut waits, &mut jobs, loaded).unwrap();
        assert_eq!(result.classification, TerminationClassification::NormalExit);
        assert_eq!(result.application_code, 0);
        assert_eq!(result.cleanup_result, 0);

        let mut evidence = evidence_through_job_accepted(gate, owner, launch.job_id);
        let owner_result = jobs
            .jobs
            .result_for_owner(owner.endpoint_id, owner.endpoint_generation, launch.job_id)
            .unwrap();
        record_owner_job_reap(&mut evidence, owner, launch.job_id, owner_result).unwrap();
        evidence
            .record(
                GateEvent::ForeignRejected,
                launch.job_id,
                owner.endpoint_generation,
                2,
            )
            .unwrap();
        evidence
            .record(
                GateEvent::OrphanReaped,
                launch.job_id + 1,
                owner.endpoint_generation,
                3,
            )
            .unwrap();
        evidence.finish().unwrap();

        let resident = resident_with_wyr1b_evidence(evidence);
        let expected_events = [
            GateEvent::RegistryReady,
            GateEvent::PublisherReady,
            GateEvent::ClientReady,
            GateEvent::Published,
            GateEvent::Connected,
            GateEvent::DirectExchange,
            GateEvent::Retired,
            GateEvent::StaleRejected,
            GateEvent::JobAccepted,
            GateEvent::JobExitZero,
            GateEvent::JobReaped,
            GateEvent::ForeignRejected,
            GateEvent::OrphanReaped,
            GateEvent::Terminal,
        ];
        for (sequence, event) in expected_events.into_iter().enumerate() {
            let record = resident.wyr1b_evidence_record(sequence).unwrap();
            assert_eq!(
                u64::from_str_radix(core::str::from_utf8(&record[25..33]).unwrap(), 16),
                Ok(sequence as u64)
            );
            assert_eq!(
                u64::from_str_radix(core::str::from_utf8(&record[34..36]).unwrap(), 16),
                Ok(event as u64)
            );
        }
        assert_eq!(resident.wyr1b_evidence_record(expected_events.len()), None);
    }

    #[test]
    fn native_gate_cleanup_failure_records_neither_job_terminal_event() {
        let gate = GateConfig { nonce: 0x27 };
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        let mut jobs = JobDispatcher::new();
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();
        let loaded = jobs.jobs.loaded_job(launch.job_id).unwrap();
        let mut platform = MockPlatform::new();
        platform.fail_close = Some(DwHandle(103));
        let mut waits = TerminalWaits;
        let mut evidence = evidence_through_job_accepted(gate, owner, launch.job_id);

        assert_eq!(
            reap_job(&mut platform, &mut waits, &mut jobs, loaded),
            Err(InitError::Cleanup)
        );
        assert_eq!(evidence.recorded_events(), 9);
        assert_eq!(
            resident_with_wyr1b_evidence(evidence).wyr1b_evidence_record(0),
            None
        );

        platform.fail_close = None;
        let retained = jobs.jobs.loaded_job(launch.job_id).unwrap();
        let result = reap_job(&mut platform, &mut waits, &mut jobs, retained).unwrap();
        assert_ne!(result.cleanup_result, 0);
        let owner_result = jobs
            .jobs
            .result_for_owner(owner.endpoint_id, owner.endpoint_generation, launch.job_id)
            .unwrap();
        assert_eq!(
            record_owner_job_reap(&mut evidence, owner, launch.job_id, owner_result),
            Err(InitError::Wyr1BGateMismatch)
        );
        assert_eq!(evidence.recorded_events(), 9);
        let resident = resident_with_wyr1b_evidence(evidence);
        for index in 0..crate::wyr1b_gate::EVIDENCE_RECORDS {
            assert_eq!(resident.wyr1b_evidence_record(index), None);
        }
    }

    #[test]
    fn native_dispatcher_executes_every_nonlaunch_operation_and_rejects_replay() {
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        let mut waits = TerminalWaits;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();

        let query_ticket = jobs.jobs.reserve_request(reservation(2)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(90),
            owner,
            reservation(2),
            query_ticket,
            LaunchMessage::Query {
                job_id: launch.job_id,
            },
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::JobState {
                phase: wyrmroot_launch_proto::JobPhase::Running,
                ..
            }
        ));

        let list_ticket = jobs.jobs.reserve_request(reservation(3)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(90),
            owner,
            reservation(3),
            list_ticket,
            LaunchMessage::ListJobs,
        )
        .unwrap();
        let listed = parse_launch_message(&platform.sent[..platform.sent_len], 0).unwrap();
        assert!(
            matches!(listed.message, LaunchMessage::JobList(ids) if ids.get(0) == Some(launch.job_id))
        );

        let terminate_ticket = jobs.jobs.reserve_request(reservation(4)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(90),
            owner,
            reservation(4),
            terminate_ticket,
            LaunchMessage::Terminate {
                job_id: launch.job_id,
            },
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::TerminationAccepted { job_id } if job_id == launch.job_id
        ));
        assert_eq!(platform.terminate_count, 1);

        let sent_before_wait = platform.sent_len;
        let wait_ticket = jobs.jobs.reserve_request(reservation(5)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(90),
            owner,
            reservation(5),
            wait_ticket,
            LaunchMessage::Wait {
                job_id: launch.job_id,
            },
        )
        .unwrap();
        assert_eq!(platform.sent_len, sent_before_wait);
        let loaded = jobs.jobs.loaded_job(launch.job_id).unwrap();
        reap_job(&mut platform, &mut waits, &mut jobs, loaded).unwrap();
        service_pending_wait(&mut platform, &mut waits, &mut jobs).unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::JobResult { job_id, .. } if job_id == launch.job_id
        ));

        let close_ticket = jobs.jobs.reserve_request(reservation(6)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(90),
            owner,
            reservation(6),
            close_ticket,
            LaunchMessage::CloseJob {
                job_id: launch.job_id,
            },
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Closed { job_id } if job_id == launch.job_id
        ));

        let cancel_ticket = jobs.jobs.reserve_request(reservation(7)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(90),
            owner,
            reservation(7),
            cancel_ticket,
            LaunchMessage::Cancel {
                target_transaction_id: 1,
            },
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Error {
                code: LaunchErrorCode::CancellationUnavailable
            }
        ));
        assert_eq!(
            jobs.jobs.reserve_request(reservation(7)),
            Err(JobError::TransactionReplay)
        );

        let foreign_grant = grant(EndpointKind::LaunchSession, 2, 1);
        jobs.install_session(foreign_grant, DwHandle(91)).unwrap();
        let foreign = LaunchReservation {
            connection_id: 2,
            generation: 3,
            transaction_id: 1,
        };
        let foreign_ticket = jobs.jobs.reserve_request(foreign).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(91),
            foreign_grant,
            foreign,
            foreign_ticket,
            LaunchMessage::Query {
                job_id: launch.job_id,
            },
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Error {
                code: LaunchErrorCode::ForeignOrUnknownJob
            }
        ));
    }

    #[test]
    fn production_owner_wait_tick_emits_result_before_gate_report_can_continue() {
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        platform.now = Some(10);
        platform.session_poll_timeout = true;
        let mut waits = TerminalWaits;
        let mut loader = InitSendLoader::new();
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();
        platform.inbound_len = encode_job_message(
            reservation(2),
            LaunchMessageType::Wait,
            launch.job_id,
            &mut platform.inbound,
        )
        .unwrap();

        dispatch_owner_wait_then_poll(
            &mut platform,
            &mut loader,
            &mut waits,
            LoadAuthority {
                parent_root: DwHandle(1),
                bootfs: DwHandle(2),
                task_group: DwHandle(3),
            },
            None,
            &mut jobs,
            DwHandle(90),
            owner,
        )
        .unwrap();

        let response = parse_launch_message(&platform.sent[..platform.sent_len], 0).unwrap();
        assert_eq!(response.reservation, reservation(2));
        assert!(matches!(
            response.message,
            LaunchMessage::JobResult { job_id, .. } if job_id == launch.job_id
        ));
    }

    #[test]
    fn resident_poll_disconnects_but_preserves_received_move_cleanup_failure() {
        let image = executable();
        let (bootfs, _) = job_policy_bootfs(&image);
        let mut platform = MockPlatform::new();
        platform.bootfs = Some(bootfs);
        platform.fail_close = Some(DwHandle(500));
        platform.session_poll_readable = true;
        platform.inbound_len = encode_job_message(
            reservation(1),
            LaunchMessageType::Query,
            7,
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_handles[0] = DwReceivedHandleInfoV1 {
            handle: DwHandle(500),
            ..DwReceivedHandleInfoV1::default()
        };
        platform.inbound_handle_count = 1;
        let mut loader = InitSendLoader::new();
        let mut waits = TerminalWaits;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();

        assert_eq!(
            poll_job_dispatcher(
                &mut platform,
                &mut loader,
                &mut waits,
                LoadAuthority {
                    parent_root: DwHandle(1),
                    bootfs: DwHandle(2),
                    task_group: DwHandle(3),
                },
                &mut jobs,
                10,
            ),
            Err(InitError::Cleanup)
        );
        assert_eq!(jobs.session_count(), 0);
        assert_eq!(
            &platform.closed[..platform.close_count],
            &[DwHandle(500), DwHandle(90)]
        );
    }

    #[test]
    fn native_receive_reserves_before_malformed_and_replay_responses() {
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        let mut waits = TerminalWaits;
        let mut loader = InitSendLoader::new();
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };

        let size = encode_job_message(
            reservation(2),
            LaunchMessageType::Query,
            launch.job_id,
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_len = size;
        assert_eq!(
            dispatch_one_job_request(
                &mut platform,
                &mut loader,
                &mut waits,
                authority,
                None,
                &mut jobs,
                DwHandle(90),
                owner,
            ),
            Ok(JobDispatchOutcome::Responded)
        );
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::JobState { job_id, .. } if job_id == launch.job_id
        ));

        let replay = encode_job_message(
            reservation(2),
            LaunchMessageType::Query,
            launch.job_id,
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_len = replay;
        dispatch_one_job_request(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            None,
            &mut jobs,
            DwHandle(90),
            owner,
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Error {
                code: LaunchErrorCode::TransactionReplay
            }
        ));

        encode_job_message(
            reservation(3),
            LaunchMessageType::Query,
            launch.job_id,
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_len = wyrmroot_launch_proto::HEADER_BYTES;
        dispatch_one_job_request(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            None,
            &mut jobs,
            DwHandle(90),
            owner,
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Error {
                code: LaunchErrorCode::MalformedRequest
            }
        ));
        assert_eq!(
            jobs.jobs.reserve_request(reservation(3)),
            Err(JobError::TransactionReplay)
        );
    }

    #[test]
    fn rejected_launch_emits_stable_error_keeps_session_and_replays() {
        let image = executable();
        let (bootfs, generation) = job_policy_bootfs(&image);
        let archive = Archive::new(&bootfs).unwrap();
        let policy = PolicyView::from_bootfs(archive, generation).unwrap();
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        platform.task_group = Some(DwHandle(77));
        let mut waits = TerminalWaits;
        let mut loader = InitSendLoader::new();
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };
        let size = wyrmroot_launch_proto::encode_launch(
            reservation(1),
            "bin/missing",
            &["bin/missing"],
            &[],
            false,
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_len = size;
        assert_eq!(
            dispatch_one_job_request(
                &mut platform,
                &mut loader,
                &mut waits,
                authority,
                Some(&policy),
                &mut jobs,
                DwHandle(90),
                owner,
            ),
            Ok(JobDispatchOutcome::Responded)
        );
        let rejected = parse_launch_message(&platform.sent[..platform.sent_len], 0).unwrap();
        assert_eq!(
            rejected.message,
            LaunchMessage::Error {
                code: LaunchErrorCode::PolicyRejected,
            }
        );
        assert_eq!(jobs.session_count(), 1);
        assert_eq!(jobs.jobs.live_jobs(), 0);

        let replay = wyrmroot_launch_proto::encode_launch(
            reservation(1),
            "bin/missing",
            &["bin/missing"],
            &[],
            false,
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_len = replay;
        dispatch_one_job_request(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            Some(&policy),
            &mut jobs,
            DwHandle(90),
            owner,
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Error {
                code: LaunchErrorCode::TransactionReplay
            }
        ));
        assert_eq!(jobs.session_count(), 1);

        platform.inbound_len = wyrmroot_launch_proto::encode_launch(
            reservation(2),
            "bin/hello",
            &["bin/hello"],
            &[],
            false,
            &mut platform.inbound,
        )
        .unwrap();
        dispatch_one_job_request(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            None,
            &mut jobs,
            DwHandle(90),
            owner,
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Error {
                code: LaunchErrorCode::PolicyRejected
            }
        ));
        platform.inbound_len = wyrmroot_launch_proto::encode_launch(
            reservation(2),
            "bin/hello",
            &["bin/hello"],
            &[],
            false,
            &mut platform.inbound,
        )
        .unwrap();
        dispatch_one_job_request(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            Some(&policy),
            &mut jobs,
            DwHandle(90),
            owner,
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Error {
                code: LaunchErrorCode::TransactionReplay
            }
        ));
        assert_eq!(jobs.jobs.live_jobs(), 0);
        assert_eq!(jobs.session_count(), 1);
    }

    #[test]
    fn post_load_deadline_failure_rolls_back_invisibly_and_keeps_session() {
        let image = executable();
        let (bootfs, generation) = job_policy_bootfs(&image);
        let archive = Archive::new(&bootfs).unwrap();
        let policy = PolicyView::from_bootfs(archive, generation).unwrap();
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        platform.task_group = Some(DwHandle(77));
        let mut waits = TerminalWaits;
        let mut loader = InitSendLoader::new();
        loader.fail_init = false;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };
        let size = wyrmroot_launch_proto::encode_launch(
            reservation(1),
            "bin/hello",
            &["bin/hello"],
            &[],
            false,
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_len = size;
        assert_eq!(
            dispatch_one_job_request(
                &mut platform,
                &mut loader,
                &mut waits,
                authority,
                Some(&policy),
                &mut jobs,
                DwHandle(90),
                owner,
            ),
            Ok(JobDispatchOutcome::Responded)
        );
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Error {
                code: LaunchErrorCode::LoaderFailure
            }
        ));
        assert_eq!(platform.terminate_count, 1);
        assert_eq!(jobs.jobs.live_jobs(), 0);
        assert_eq!(jobs.jobs.completed_results(), 0);
        assert_eq!(jobs.session_count(), 1);
        assert_eq!(
            jobs.jobs.result(reservation(2), 1),
            Err(JobError::UnknownJob)
        );
    }

    #[test]
    fn failed_launch_accepted_send_terminates_reaps_and_closes_once() {
        let mut platform = MockPlatform::new();
        let mut waits = TerminalWaits;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let ticket = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(ticket, 101, 102, 103).unwrap();
        let loaded = jobs.jobs.loaded_job(ticket.job_id).unwrap();

        assert_eq!(
            publish_launch_accepted(
                &mut platform,
                &mut waits,
                &mut jobs,
                DwHandle(90),
                reservation(1),
                loaded,
            ),
            Err(InitError::Native(FAILURE))
        );
        assert_eq!(platform.terminate_count, 1);
        assert_eq!(jobs.jobs.live_jobs(), 0);
        assert_eq!(
            &platform.closed[..platform.close_count],
            &[DwHandle(103), DwHandle(101), DwHandle(102)]
        );
    }

    #[test]
    fn pending_wait_cancel_succeeds_and_never_emits_a_late_result() {
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        let mut waits = TerminalWaits;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();

        let wait_ticket = jobs.jobs.reserve_request(reservation(2)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(90),
            owner,
            reservation(2),
            wait_ticket,
            LaunchMessage::Wait {
                job_id: launch.job_id,
            },
        )
        .unwrap();
        assert_eq!(platform.sent_len, 0);

        let cancel_ticket = jobs.jobs.reserve_request(reservation(3)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(90),
            owner,
            reservation(3),
            cancel_ticket,
            LaunchMessage::Cancel {
                target_transaction_id: 2,
            },
        )
        .unwrap();
        let cancelled = platform.sent;
        let cancelled_len = platform.sent_len;
        assert!(matches!(
            parse_launch_message(&cancelled[..cancelled_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Cancelled {
                target_transaction_id: 2
            }
        ));

        let loaded = jobs.jobs.loaded_job(launch.job_id).unwrap();
        reap_job(&mut platform, &mut waits, &mut jobs, loaded).unwrap();
        service_pending_wait(&mut platform, &mut waits, &mut jobs).unwrap();
        assert_eq!(platform.sent_len, cancelled_len);
        assert_eq!(&platform.sent[..cancelled_len], &cancelled[..cancelled_len]);
    }

    #[test]
    fn close_and_disconnect_drop_waits_but_jobs_reap_naturally() {
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        let mut waits = TerminalWaits;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();
        let wait_ticket = jobs.jobs.reserve_request(reservation(2)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(90),
            owner,
            reservation(2),
            wait_ticket,
            LaunchMessage::Wait {
                job_id: launch.job_id,
            },
        )
        .unwrap();
        let close_ticket = jobs.jobs.reserve_request(reservation(3)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(90),
            owner,
            reservation(3),
            close_ticket,
            LaunchMessage::CloseJob {
                job_id: launch.job_id,
            },
        )
        .unwrap();
        let closed = platform.sent;
        let closed_len = platform.sent_len;
        let loaded = jobs.jobs.loaded_job(launch.job_id).unwrap();
        reap_job(&mut platform, &mut waits, &mut jobs, loaded).unwrap();
        service_pending_wait(&mut platform, &mut waits, &mut jobs).unwrap();
        assert_eq!(&platform.sent[..closed_len], &closed[..closed_len]);
        assert_eq!(platform.terminate_count, 0);

        let second = grant(EndpointKind::LaunchSession, 2, 1);
        jobs.install_session(second, DwHandle(91)).unwrap();
        let second_reservation = |transaction_id| LaunchReservation {
            connection_id: 2,
            generation: 3,
            transaction_id,
        };
        let launch2 = jobs.jobs.begin_launch(second_reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch2, 201, 202, 203).unwrap();
        let wait2 = jobs.jobs.reserve_request(second_reservation(2)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(91),
            second,
            second_reservation(2),
            wait2,
            LaunchMessage::Wait {
                job_id: launch2.job_id,
            },
        )
        .unwrap();
        jobs.disconnect_owned_session(second).unwrap();
        let sent_before_reap = platform.sent;
        let sent_before_reap_len = platform.sent_len;
        let loaded2 = jobs.jobs.loaded_job(launch2.job_id).unwrap();
        reap_job(&mut platform, &mut waits, &mut jobs, loaded2).unwrap();
        service_pending_wait(&mut platform, &mut waits, &mut jobs).unwrap();
        assert_eq!(platform.sent_len, sent_before_reap_len);
        assert_eq!(
            &platform.sent[..sent_before_reap_len],
            &sent_before_reap[..sent_before_reap_len]
        );
        assert_eq!(platform.terminate_count, 0);
    }

    #[test]
    fn close_failure_retries_only_retained_handle_and_keeps_sticky_result_bit() {
        let mut platform = MockPlatform::new();
        platform.fail_close = Some(DwHandle(103));
        let mut waits = TerminalWaits;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();
        let loaded = jobs.jobs.loaded_job(launch.job_id).unwrap();
        assert_eq!(
            reap_job(&mut platform, &mut waits, &mut jobs, loaded),
            Err(InitError::Cleanup)
        );
        assert_eq!(jobs.jobs.live_jobs(), 1);
        assert_eq!(jobs.jobs.completed_results(), 0);
        assert_eq!(
            &platform.closed[..platform.close_count],
            &[DwHandle(103), DwHandle(101), DwHandle(102)]
        );

        platform.fail_close = None;
        let retained = jobs.jobs.loaded_job(launch.job_id).unwrap();
        assert_eq!(retained.loaded.process, DwHandle(0));
        assert_eq!(retained.task_group, 0);
        assert_eq!(retained.loaded.launch_channel, DwHandle(103));
        let result = reap_job(&mut platform, &mut waits, &mut jobs, retained).unwrap();
        assert_eq!(result.cleanup_result, 1 << 2);
        assert_eq!(jobs.jobs.live_jobs(), 0);
        assert_eq!(platform.closed[platform.close_count - 1], DwHandle(103));
    }

    #[test]
    fn terminate_failure_keeps_running_phase_and_records_cleanup_bit_zero() {
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        platform.fail_terminate = true;
        let mut waits = TerminalWaits;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();

        let terminate = jobs.jobs.reserve_request(reservation(2)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(90),
            owner,
            reservation(2),
            terminate,
            LaunchMessage::Terminate {
                job_id: launch.job_id,
            },
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Error {
                code: LaunchErrorCode::CleanupFailure
            }
        ));
        assert_eq!(platform.terminate_count, 1);
        assert_eq!(
            jobs.jobs
                .query(reservation(3), launch.job_id)
                .unwrap()
                .phase,
            crate::wyr1b::JobPhase::Running
        );

        let loaded = jobs.jobs.loaded_job(launch.job_id).unwrap();
        let result = reap_job(&mut platform, &mut waits, &mut jobs, loaded).unwrap();
        assert_eq!(result.cleanup_result, 1 << 0);
    }

    #[test]
    fn wait_failure_records_cleanup_bit_one_without_closing_before_terminal() {
        let mut platform = MockPlatform::new();
        platform.now = Some(1);
        let mut waits = WaitFailureThenTerminal { query_count: 0 };
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();
        let loaded = jobs.jobs.loaded_job(launch.job_id).unwrap();

        assert_eq!(
            reap_job(&mut platform, &mut waits, &mut jobs, loaded),
            Err(InitError::Cleanup)
        );
        assert_eq!(platform.close_count, 0);
        assert_eq!(jobs.jobs.live_jobs(), 1);

        let retained = jobs.jobs.loaded_job(launch.job_id).unwrap();
        let result = reap_job(&mut platform, &mut waits, &mut jobs, retained).unwrap();
        assert_eq!(result.cleanup_result, 1 << 1);
        assert_eq!(jobs.jobs.live_jobs(), 0);
    }

    #[test]
    fn registry_drain_propagates_sticky_cleanup_and_retries_only_once_per_tick() {
        let mut platform = MockPlatform::new();
        platform.fail_close = Some(DwHandle(103));
        let mut waits = TerminalWaits;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();

        assert_eq!(
            drain_job_dispatcher(&mut platform, &mut waits, &mut jobs),
            Err(InitError::Cleanup)
        );
        assert_eq!(jobs.jobs.live_jobs(), 1);
        assert_eq!(
            &platform.closed[..platform.close_count],
            &[DwHandle(90), DwHandle(103), DwHandle(101), DwHandle(102)]
        );

        platform.fail_close = None;
        assert_eq!(
            drain_job_dispatcher(&mut platform, &mut waits, &mut jobs),
            Err(InitError::Cleanup)
        );
        assert_eq!(jobs.jobs.live_jobs(), 0);
        assert_eq!(platform.closed[platform.close_count - 1], DwHandle(103));
    }

    fn ready_registry() -> (SystemInit, RegistryNativeAttempt) {
        let mut controller = SystemInit {
            mode: SystemMode::Bootstrap,
            roles: [
                RoleController::new(RoleId::Registryd, [1; 32]).unwrap(),
                RoleController::new(RoleId::Devmgr, [2; 32]).unwrap(),
            ],
            degraded_transitions: 0,
            activated: [false; EARLY_ROLE_COUNT],
            accounting: AttemptLedger::new(),
            gate: None,
            evidence: None,
            registry_startup_profile: StartupProfile::BootstrapRegistry,
        };
        controller.become_operational().unwrap();
        controller.begin_registry(0, 1, 0x1001).unwrap();
        let reservation = controller
            .reserve_attempt(RoleId::Registryd, 1, 0x1001)
            .unwrap();
        let loaded = LoadedProcess {
            process: DwHandle(31),
            launch_channel: DwHandle(32),
        };
        let task_group = DwHandle(30);
        controller
            .install_attempt(AttemptResources {
                role: RoleId::Registryd,
                generation: 1,
                transaction_id: 0x1001,
                executable_identity: [1; 32],
                startup_profile: StartupProfile::BootstrapRegistry,
                task_group,
                process: loaded.process,
                launch_channel: loaded.launch_channel,
                mappings: 0,
                reservation,
            })
            .unwrap();
        controller
            .child_started(RoleId::Registryd, 1, 0x1001, 1)
            .unwrap();
        controller.ready(RoleId::Registryd, 1, 0x1001, 2).unwrap();
        (
            controller,
            RegistryNativeAttempt {
                active: ActiveNativeRole {
                    role: RoleId::Registryd,
                    generation: 1,
                    transaction_id: 0x1001,
                    loaded,
                    task_group,
                },
                control_channel: DwHandle(33),
                ready_at: 2,
            },
        )
    }

    #[test]
    fn registry_init_send_failure_is_closed_once_by_controller() {
        let image = executable();
        let bootfs = service_bootfs(REGISTRY_PATH, &image);
        let mut controller = starting_registry(&image);
        let mut platform = MockPlatform::new();
        platform.task_group = Some(DwHandle(22));
        let mut loader = InitSendLoader::new();
        let mut waits = TerminalWaits;
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };

        assert!(matches!(
            launch_registry(
                &mut platform,
                &mut loader,
                &mut waits,
                &mut controller,
                authority,
                &bootfs,
            ),
            Err(InitError::Loader(LoadError::Platform {
                stage: wyrmroot_loader::process::LoadStage::InitSend,
                rollback_failed: false,
                ..
            }))
        ));
        assert_eq!(loader.transferred_service, Some(DwHandle(21)));
        assert_eq!(loader.close_count(DwHandle(21)), 0);
        assert_eq!(
            platform.closed[..platform.close_count]
                .iter()
                .filter(|handle| **handle == DwHandle(21))
                .count(),
            1
        );
        assert_eq!(
            platform.closed[..platform.close_count],
            [DwHandle(21), DwHandle(20), DwHandle(22)]
        );
        assert_eq!(controller.outstanding_reservations(), 0);
    }

    #[test]
    fn peer_init_send_failure_is_closed_once_after_registry_install() {
        let image = executable();
        let bootfs = service_bootfs(PUBLISHER_PATH, &image);
        let mut topology = RegistryTopology::new(7).unwrap();
        let mut platform = MockPlatform::new();
        platform.task_group = Some(DwHandle(22));
        let mut loader = InitSendLoader::new();
        let mut waits = TerminalWaits;
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };

        assert!(matches!(
            launch_peer(
                &mut platform,
                &mut loader,
                &mut waits,
                authority,
                &bootfs,
                DwHandle(10),
                &mut topology,
                PeerKind::Publisher { operation: 1 },
            ),
            Err(PeerLaunchError::InstallCommitted(InitError::Loader(
                LoadError::Platform {
                    stage: wyrmroot_loader::process::LoadStage::InitSend,
                    rollback_failed: false,
                    ..
                }
            )))
        ));
        assert_eq!(loader.transferred_service, Some(DwHandle(21)));
        assert_eq!(loader.close_count(DwHandle(21)), 0);
        assert_eq!(
            platform.closed[..platform.close_count]
                .iter()
                .filter(|handle| **handle == DwHandle(21))
                .count(),
            1
        );
        assert_eq!(
            platform.closed[..platform.close_count],
            [DwHandle(21), DwHandle(22)]
        );
        assert!(!platform.closed[..platform.close_count].contains(&DwHandle(20)));
    }

    #[test]
    fn poison_consumes_every_native_owner_when_clock_transition_cannot_start() {
        let (mut controller, registry) = ready_registry();
        let mut platform = MockPlatform::new();
        let mut waits = TerminalWaits;

        assert_eq!(
            poison_registry_generation(&mut platform, &mut waits, &mut controller, registry, false,),
            Err(InitError::Native(FAILURE))
        );
        assert_eq!(platform.terminate_count, 1);
        assert_eq!(
            platform.closed[..platform.close_count],
            [DwHandle(32), DwHandle(31), DwHandle(30), DwHandle(33)]
        );
        assert!(controller.resources(RoleId::Registryd).is_none());
        assert_eq!(controller.mode(), SystemMode::Fatal);
    }

    #[test]
    fn poison_transition_rejection_still_consumes_native_owners_and_retires_fatal() {
        let (mut controller, mut registry) = ready_registry();
        registry.active.transaction_id += 1;
        let mut platform = MockPlatform::new();
        platform.now = Some(3);
        let mut waits = TerminalWaits;

        assert_eq!(
            poison_registry_generation(&mut platform, &mut waits, &mut controller, registry, false,),
            Err(InitError::Restart(
                RestartTransitionError::TransactionMismatch
            ))
        );
        assert_eq!(platform.terminate_count, 1);
        assert_eq!(
            platform.closed[..platform.close_count],
            [DwHandle(32), DwHandle(31), DwHandle(30), DwHandle(33)]
        );
        assert!(controller.resources(RoleId::Registryd).is_none());
        assert_eq!(controller.mode(), SystemMode::Fatal);
        assert!(!matches!(
            controller.role_state(RoleId::Registryd),
            Some(RestartState::CleaningUp { .. })
        ));
    }

    #[test]
    fn poison_timestamp_overflow_records_failure_without_stranding_cleanup() {
        let (mut controller, registry) = ready_registry();
        let mut platform = MockPlatform::new();
        platform.now = Some(u64::MAX);
        let mut waits = TerminalWaits;

        assert_eq!(
            poison_registry_generation(&mut platform, &mut waits, &mut controller, registry, false,),
            Err(InitError::Restart(
                RestartTransitionError::ArithmeticOverflow
            ))
        );
        assert_eq!(platform.terminate_count, 1);
        assert_eq!(
            platform.closed[..platform.close_count],
            [DwHandle(32), DwHandle(31), DwHandle(30), DwHandle(33)]
        );
        assert_eq!(controller.outstanding_reservations(), 0);
        assert!(controller.resources(RoleId::Registryd).is_none());
        assert_eq!(
            controller.role_state(RoleId::Registryd),
            Some(RestartState::PermanentFailure {
                final_failure: AttemptFailure::WaitFailed,
                cleanup: CleanupDisposition::Complete,
            })
        );
        assert_eq!(controller.mode(), SystemMode::Degraded);
        assert!(!matches!(
            controller.role_state(RoleId::Registryd),
            Some(RestartState::CleaningUp { .. })
        ));
    }

    #[test]
    fn poison_timestamp_overflow_preserves_cleanup_failure_precedence() {
        let (mut controller, registry) = ready_registry();
        let mut platform = MockPlatform::new();
        platform.now = Some(u64::MAX);
        platform.fail_close = Some(registry.control_channel);
        let mut waits = TerminalWaits;

        assert_eq!(
            poison_registry_generation(&mut platform, &mut waits, &mut controller, registry, false,),
            Err(InitError::Cleanup)
        );
        assert_eq!(platform.terminate_count, 1);
        assert_eq!(
            platform.closed[..platform.close_count],
            [DwHandle(32), DwHandle(31), DwHandle(30), DwHandle(33)]
        );
        assert!(controller.resources(RoleId::Registryd).is_some());
        assert_eq!(controller.outstanding_reservations(), 1);
        assert_eq!(controller.mode(), SystemMode::Degraded);
        assert_eq!(
            controller.role_state(RoleId::Registryd),
            Some(RestartState::PermanentFailure {
                final_failure: AttemptFailure::WaitFailed,
                cleanup: CleanupDisposition::Failed,
            })
        );
    }

    #[test]
    fn poison_cleanup_failure_is_permanent_and_blocks_replacement() {
        let (mut controller, registry) = ready_registry();
        let mut platform = MockPlatform::new();
        platform.now = Some(3);
        platform.fail_close = Some(registry.control_channel);
        let mut waits = TerminalWaits;

        assert_eq!(
            poison_registry_generation(&mut platform, &mut waits, &mut controller, registry, true,),
            Ok(true)
        );
        assert!(matches!(
            controller.role_state(RoleId::Registryd),
            Some(RestartState::PermanentFailure { .. })
        ));
        assert_eq!(controller.mode(), SystemMode::Degraded);
        assert!(
            controller
                .start_replacement(RoleId::Registryd, 4, 2, 0x1002)
                .is_err()
        );
    }

    #[test]
    fn poison_complete_cleanup_admits_exact_next_registry_generation() {
        let (mut controller, registry) = ready_registry();
        let mut platform = MockPlatform::new();
        platform.now = Some(3);
        platform.allow_wait = true;
        let mut waits = TerminalWaits;

        assert_eq!(
            poison_registry_generation(&mut platform, &mut waits, &mut controller, registry, false,),
            Ok(false)
        );
        assert!(matches!(
            controller.role_state(RoleId::Registryd),
            Some(RestartState::Starting {
                generation: 2,
                transaction_id: 0x1002,
                ..
            })
        ));
    }

    #[test]
    fn rejected_topology_restart_cleans_the_newly_ready_registry() {
        let (mut controller, registry) = ready_registry();
        let mut topology = RegistryTopology::new(2).unwrap();
        let mut platform = MockPlatform::new();
        platform.now = Some(3);
        platform.allow_wait = true;
        let mut waits = TerminalWaits;

        assert_eq!(
            restart_topology_or_poison(
                &mut platform,
                &mut waits,
                &mut controller,
                &mut topology,
                registry,
            ),
            Err(InitError::Wyr1BModel(
                crate::wyr1b::JobError::StaleGeneration
            ))
        );
        assert_eq!(platform.terminate_count, 1);
        assert_eq!(
            platform.closed[..platform.close_count],
            [DwHandle(32), DwHandle(31), DwHandle(30), DwHandle(33)]
        );
        assert!(controller.resources(RoleId::Registryd).is_none());
    }

    #[test]
    fn publication_install_moves_exact_endpoint_and_keeps_logical_id_distinct() {
        let publication = grant(EndpointKind::Publication, 41, 9);
        let mut platform = MockPlatform::new();
        install_publication(&mut platform, DwHandle(10), publication, DwHandle(11), 1).unwrap();
        assert_eq!(platform.transfer.handle, DwHandle(11));
        assert_eq!(platform.transfer.operation, DW_HANDLE_TRANSFER_MOVE);
        assert_eq!(platform.transfer.requested_rights, CHILD_CHANNEL_RIGHTS);
        assert_eq!(platform.queried[..platform.query_count], [DwHandle(11)]);
        let parsed = parse(&platform.sent[..platform.sent_len], 1).unwrap();
        let Message::InstallPublication(install) = parsed.message else {
            panic!("wrong install type")
        };
        assert_eq!(install.endpoint_id, publication.endpoint_id);
        assert_eq!(install.endpoint_generation, publication.endpoint_generation);
        assert_eq!(install.publication_id, FIRST_PUBLICATION_ID);
        assert_ne!(install.publication_id, install.endpoint_id);
    }

    #[test]
    fn controller_pairs_are_broad_and_move_reduces_only_in_descriptor() {
        let mut platform = MockPlatform::new();
        assert_eq!(
            create_controller_channel_pair(&mut platform),
            Ok((DwHandle(20), DwHandle(21)))
        );
        assert_eq!(platform.created_rights, CONTROLLER_CHANNEL_RIGHTS);

        let client = grant(EndpointKind::RegistryClient, 44, 5);
        install_client(&mut platform, DwHandle(10), client, DwHandle(20)).unwrap();
        assert_eq!(platform.queried[0], DwHandle(20));
        assert_eq!(platform.transfer.requested_rights, CHILD_CHANNEL_RIGHTS);
        assert_ne!(CONTROLLER_CHANNEL_RIGHTS, CHILD_CHANNEL_RIGHTS);
    }

    #[test]
    fn staged_channel_cleanup_is_affine_and_reverse_ordered() {
        let mut platform = MockPlatform::new();
        let mut owner = StagedChannelPair::new(DwHandle(20), DwHandle(21));
        assert!(owner.cleanup(&mut platform));
        assert!(owner.cleanup(&mut platform));
        assert_eq!(
            platform.closed[..platform.close_count],
            [DwHandle(21), DwHandle(20)]
        );
    }

    #[test]
    fn committed_move_is_never_closed_by_local_rollback() {
        let mut platform = MockPlatform::new();
        let mut owner = StagedChannelPair::new(DwHandle(20), DwHandle(21));
        owner.commit_first_move().unwrap();
        assert!(owner.cleanup(&mut platform));
        assert_eq!(platform.closed[..platform.close_count], [DwHandle(21)]);
    }

    #[test]
    fn install_boundary_classification_is_exact_and_cleanup_sticky() {
        assert_eq!(
            classify_gate_run_error(false, false, InitError::Native(FAILURE)),
            GateRunError::PreInstall(InitError::Native(FAILURE))
        );
        assert_eq!(
            classify_gate_run_error(false, true, InitError::Native(FAILURE)),
            GateRunError::CleanupFailed(InitError::Cleanup)
        );
        assert_eq!(
            classify_gate_run_error(true, true, InitError::Native(FAILURE)),
            GateRunError::InstallCommitted {
                error: InitError::Native(FAILURE),
                cleanup_failed: true,
            }
        );
    }

    #[test]
    fn every_peer_fault_stage_stays_on_its_exact_install_side() {
        for stage in [
            PeerLaunchStage::Archive,
            PeerLaunchStage::ArtifactLookup,
            PeerLaunchStage::ArtifactValidation,
            PeerLaunchStage::Grant,
            PeerLaunchStage::Correlation,
            PeerLaunchStage::TaskGroup,
            PeerLaunchStage::ChannelPair,
            PeerLaunchStage::InstallMove,
        ] {
            assert!(matches!(
                peer_launch_error(stage, InitError::Native(FAILURE)),
                PeerLaunchError::PreInstall(InitError::Native(FAILURE))
            ));
        }
        for stage in [
            PeerLaunchStage::PeerCapability,
            PeerLaunchStage::Load,
            PeerLaunchStage::Clock,
            PeerLaunchStage::Deadline,
            PeerLaunchStage::Ready,
        ] {
            assert!(matches!(
                peer_launch_error(stage, InitError::Native(FAILURE)),
                PeerLaunchError::InstallCommitted(InitError::Native(FAILURE))
            ));
        }
    }

    #[test]
    fn preinstall_retry_executes_once_but_cleanup_failure_is_sticky() {
        let mut recoverable_calls = 0;
        let recovered = retry_preinstall_once(|| {
            recoverable_calls += 1;
            if recoverable_calls == 1 {
                Err(PeerLaunchError::PreInstall(InitError::Native(FAILURE)))
            } else {
                Ok(7_u8)
            }
        });
        assert_eq!(recovered, Ok(7));
        assert_eq!(recoverable_calls, 2);

        let mut cleanup_calls = 0;
        let blocked = retry_preinstall_once(|| {
            cleanup_calls += 1;
            Err::<u8, _>(PeerLaunchError::PreInstall(InitError::Cleanup))
        });
        assert_eq!(
            blocked,
            Err(PeerLaunchError::PreInstall(InitError::Cleanup))
        );
        assert_eq!(cleanup_calls, 1);
    }

    #[test]
    fn move_rejects_stale_source_rights_before_atomic_send() {
        let mut platform = MockPlatform::new();
        platform.fresh_rights = CHILD_CHANNEL_RIGHTS;
        let client = grant(EndpointKind::RegistryClient, 44, 5);
        assert_eq!(
            install_client(&mut platform, DwHandle(10), client, DwHandle(20)),
            Err(InitError::ResourceIdentityMismatch)
        );
        assert_eq!(platform.sent_len, 0);
        assert_eq!(platform.queried[..platform.query_count], [DwHandle(20)]);
    }

    #[test]
    fn gate_actor_uses_installed_endpoint_generation_not_role_generation() {
        let publisher = grant(EndpointKind::Publication, 41, 99);
        let client = grant(EndpointKind::RegistryClient, 42, 77);
        let record = gate_record(
            GateMessageType::ConfigurePublisher,
            GateConfig { nonce: 1 },
            publisher,
            client,
            1,
        );
        assert_eq!((record.actor_id, record.actor_generation), (41, 3));
        assert_ne!(record.actor_generation, publisher.role_generation);
    }

    #[test]
    fn stale_gate_report_is_rejected_without_advancing_state() {
        let publisher = grant(EndpointKind::Publication, 41, 99);
        let client = grant(EndpointKind::RegistryClient, 42, 77);
        let expected = gate_record(
            GateMessageType::Published,
            GateConfig { nonce: 1 },
            publisher,
            client,
            2,
        );
        let stale = GateRecord {
            operation_id: 1,
            ..expected
        };
        assert_eq!(
            expect_gate(stale, expected),
            Err(InitError::Wyr1BGateMismatch)
        );
    }

    #[test]
    fn selector_27_controller_owns_the_native_wrlj_dispatch() {
        let source = include_str!("wyr1b_native.rs");
        assert!(source.contains(concat!("run_", "job_gate")));
        assert!(source.contains(concat!("parse_launch_", "message")));
        assert!(!source.contains(concat!("launch_", "authorized_job")));
    }
}
