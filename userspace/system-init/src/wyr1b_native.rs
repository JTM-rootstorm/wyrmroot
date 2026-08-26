//! Native selector-27 registry and dependent-peer controller.

use super::*;
use crate::wyr1b::{EndpointGrant, EndpointKind, RegistryTopology, correlation_environment};
use crate::wyr1b_gate::{GATE_PATH, GateConfig, parse_config};
use deepwyrm_syscall::{
    DW_HANDLE_TRANSFER_MOVE, DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_INSPECT, DW_RIGHT_READ,
    DW_RIGHT_TRANSFER, DW_RIGHT_WAIT, DW_RIGHT_WRITE, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE,
    DwHandleTransferV1, DwRights,
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
pub(crate) struct Activation {
    pub controller: SystemInit,
    pub result: RecoveryResult,
    pub active: [Option<ActiveNativeRole>; EARLY_ROLE_COUNT],
    pub registry_control: DwHandle,
    pub topology: Option<RegistryTopology>,
    pub gate: GateConfig,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResidentState {
    pub registry_control: DwHandle,
    pub topology: Option<RegistryTopology>,
    pub gate: GateConfig,
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

pub(crate) fn activate<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    bootstrap_channel: DwHandle,
    parent_transaction: u64,
    bootfs: &[u8],
) -> Result<Activation, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let (mut controller, gate) = validate_retained_bootfs(bootfs)?;
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
    let Some((mut registry, mut topology)) =
        launch_registry_until_ready(system, loader, waits, &mut controller, authority, bootfs)?
    else {
        return Ok(Activation {
            controller,
            result: RecoveryResult::Degraded,
            active: [None, None],
            registry_control: DwHandle(0),
            topology: None,
            gate,
        });
    };
    let (devmgr, result) = match activate_role_until_ready(
        system,
        &mut controller,
        loader,
        waits,
        authority,
        bootfs,
        RoleId::Devmgr,
    )? {
        RoleActivation::Ready(active) => (Some(active), RecoveryResult::Recovered),
        RoleActivation::Degraded => (None, RecoveryResult::Degraded),
    };
    loop {
        match run_registry_gate(
            system,
            loader,
            waits,
            authority,
            bootfs,
            registry.control_channel,
            &mut topology,
            gate,
        ) {
            Ok(()) => break,
            Err(GateRunError::PreInstall(_error)) => {
                return Ok(Activation {
                    controller,
                    result: RecoveryResult::Degraded,
                    active: [Some(registry.active), devmgr],
                    registry_control: registry.control_channel,
                    topology: Some(topology),
                    gate,
                });
            }
            Err(GateRunError::CleanupFailed(_)) => {
                let _ = poison_registry_generation(system, waits, &mut controller, registry, true)?;
                return Ok(Activation {
                    controller,
                    result: RecoveryResult::Degraded,
                    active: [None, devmgr],
                    registry_control: DwHandle(0),
                    topology: Some(topology),
                    gate,
                });
            }
            Err(GateRunError::InstallCommitted {
                error: _,
                cleanup_failed,
            }) => {
                if poison_registry_generation(
                    system,
                    waits,
                    &mut controller,
                    registry,
                    cleanup_failed,
                )? {
                    return Ok(Activation {
                        controller,
                        result: RecoveryResult::Degraded,
                        active: [None, devmgr],
                        registry_control: DwHandle(0),
                        topology: Some(topology),
                        gate,
                    });
                }
                let Some((replacement, _)) = launch_registry_until_ready(
                    system,
                    loader,
                    waits,
                    &mut controller,
                    authority,
                    bootfs,
                )?
                else {
                    return Ok(Activation {
                        controller,
                        result: RecoveryResult::Degraded,
                        active: [None, devmgr],
                        registry_control: DwHandle(0),
                        topology: Some(topology),
                        gate,
                    });
                };
                registry = restart_topology_or_poison(
                    system,
                    waits,
                    &mut controller,
                    &mut topology,
                    replacement,
                )?;
            }
        }
    }
    Ok(Activation {
        controller,
        result,
        active: [Some(registry.active), devmgr],
        registry_control: registry.control_channel,
        topology: Some(topology),
        gate,
    })
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
) -> Result<(RegistryNativeAttempt, RegistryTopology), InitError>
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
    let topology = match RegistryTopology::new(installed_generation).map_err(InitError::Wyr1BModel)
    {
        Ok(topology) => topology,
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
                ready_at,
                AttemptFailure::WaitFailed,
                error,
            ));
        }
    };
    Ok((
        RegistryNativeAttempt {
            active: ActiveNativeRole {
                role: RoleId::Registryd,
                generation,
                transaction_id,
                loaded,
                task_group,
            },
            control_channel,
        },
        topology,
    ))
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
) -> Result<Option<(RegistryNativeAttempt, RegistryTopology)>, InitError>
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

fn complete_exchange<S: Wyr1BPlatform>(
    system: &mut S,
    publisher: InstalledPeer,
    client: InstalledPeer,
    publisher_config: GateRecord,
    client_config: GateRecord,
) -> Result<(), InitError> {
    expect_report(system, client, client_config, GateMessageType::Connected)?;
    let echoed =
        expect_challenge_report(system, publisher, publisher_config, GateMessageType::Echoed)?;
    let exchanged =
        expect_challenge_report(system, client, client_config, GateMessageType::Exchanged)?;
    if echoed.value != exchanged.value {
        return Err(InitError::Wyr1BGateMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_registry_gate<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    bootfs: &[u8],
    registry_control: DwHandle,
    topology: &mut RegistryTopology,
    gate: GateConfig,
) -> Result<(), GateRunError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut publisher1 = None;
    let mut publisher2 = None;
    let mut client = None;
    let mut install_committed = false;
    let outcome: Result<(), InitError> = (|| {
        macro_rules! launch {
            ($slot:ident, $kind:expr) => {{
                match retry_preinstall_once(|| {
                    launch_peer(
                        system,
                        loader,
                        waits,
                        authority,
                        bootfs,
                        registry_control,
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
        expect_report(system, first, publisher1_config, GateMessageType::Published)?;
        let client1_config = configure_client(system, gate, client_peer, first, 1)?;
        complete_exchange(
            system,
            first,
            client_peer,
            publisher1_config,
            client1_config,
        )?;

        let retire = gate_record(
            GateMessageType::Retire,
            gate,
            first.grant,
            client_peer.grant,
            1,
        );
        send_gate(system, first.loaded.launch_channel, retire)?;
        expect_report(system, first, retire, GateMessageType::Retired)?;

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
        complete_exchange(
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
        Ok(())
    })();
    if let Err(error) = outcome {
        let mut cleanup_failed = error == InitError::Cleanup;
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
    Ok(())
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
) -> Result<Option<(RegistryNativeAttempt, bool)>, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    loop {
        let Some((registry, _)) =
            launch_registry_until_ready(system, loader, waits, controller, authority, bootfs)?
        else {
            return Ok(None);
        };
        let registry = restart_topology_or_poison(system, waits, controller, topology, registry)?;
        match run_registry_gate(
            system,
            loader,
            waits,
            authority,
            bootfs,
            registry.control_channel,
            topology,
            gate,
        ) {
            Ok(()) => return Ok(Some((registry, true))),
            Err(GateRunError::PreInstall(_)) => return Ok(Some((registry, false))),
            Err(GateRunError::CleanupFailed(_)) => {
                let _ = poison_registry_generation(system, waits, controller, registry, true)?;
                return Ok(None);
            }
            Err(GateRunError::InstallCommitted {
                error: _,
                cleanup_failed,
            }) => {
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
    let mut state = resident
        .wyr1b
        .take()
        .ok_or(InitError::WrongActivationOrder)?;
    let result = (|| {
        for index in 0..resident.active.len() {
            let Some(active) = resident.active[index] else {
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
                AfterReadyTransition::Terminal(disposition) => resident.controller.terminal(
                    active.role,
                    active.generation,
                    active.transaction_id,
                    now_ns,
                    disposition,
                )?,
                AfterReadyTransition::Failure(failure) => resident.controller.fail(
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
                    &mut resident.controller,
                    active.loaded,
                    active.task_group,
                    terminate,
                    active.role,
                    active.generation,
                    active.transaction_id,
                    now_ns,
                )?;
                resident.active[index] = None;
                if transition == AfterReadyTransition::Terminal(TerminalDisposition::NormalExit(0))
                {
                    continue;
                }
                if advance_or_degrade(
                    system,
                    &mut resident.controller,
                    active.role,
                    active.transaction_id,
                )? {
                    resident.result = RecoveryResult::Degraded;
                    continue;
                }
                match remap_and_activate_role(
                    system,
                    loader,
                    waits,
                    resident.authority,
                    &mut resident.controller,
                    active.role,
                )? {
                    RoleActivation::Ready(replacement) => {
                        resident.active[index] = Some(replacement)
                    }
                    RoleActivation::Degraded => resident.result = RecoveryResult::Degraded,
                }
                continue;
            }

            let cleanup_failed =
                cleanup_loaded(system, waits, active.loaded, active.task_group, terminate).is_err()
                    | system.close_handle(state.registry_control).is_err();
            resident.active[index] = None;
            state.registry_control = DwHandle(0);
            let retired_at = now_ns.checked_add(1).ok_or(InitError::Accounting)?;
            if cleanup_failed {
                resident.controller.cleanup_failed(
                    RoleId::Registryd,
                    active.generation,
                    active.transaction_id,
                    retired_at,
                )?;
                resident.result = RecoveryResult::Degraded;
                continue;
            }
            resident.controller.cleanup_complete(
                RoleId::Registryd,
                active.generation,
                active.transaction_id,
                retired_at,
            )?;
            if advance_registry_or_exhausted(
                system,
                &mut resident.controller,
                active.transaction_id,
            )? {
                resident.result = RecoveryResult::Degraded;
                continue;
            }
            let size = system
                .query_memory_object_size(resident.authority.bootfs)
                .map_err(InitError::Native)?;
            let plan = MappingPlan::for_bootfs(size).map_err(InitError::Mapping)?;
            let replacement = system
                .with_bootfs_bytes(
                    resident.authority.parent_root,
                    resident.authority.bootfs,
                    plan,
                    |system, bootfs| {
                        launch_registry_replacement_with_gate(
                            system,
                            loader,
                            waits,
                            &mut resident.controller,
                            resident.authority,
                            bootfs,
                            state
                                .topology
                                .as_mut()
                                .ok_or(InitError::WrongActivationOrder)?,
                            state.gate,
                        )
                    },
                )
                .map_err(InitError::Native)??;
            if let Some((replacement, gate_complete)) = replacement {
                state.registry_control = replacement.control_channel;
                resident.active[index] = Some(replacement.active);
                if !gate_complete {
                    resident.result = RecoveryResult::Degraded;
                }
            } else {
                resident.result = RecoveryResult::Degraded;
            }
        }
        if resident.controller.mode() == SystemMode::Degraded {
            resident.result = RecoveryResult::Degraded;
        }
        Ok(resident.controller.mode())
    })();
    resident.wyr1b = Some(state);
    result
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use alloc::{vec, vec::Vec};
    use deepwyrm_syscall::{DwMemoryProtection, DwStatus, DwWaitResultV1};
    use wyrmroot_bootfs::builder::{Builder as BootfsBuilder, FileMode};
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
        allow_wait: bool,
        task_group: Option<DwHandle>,
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
                allow_wait: false,
                task_group: None,
            }
        }
    }

    struct InitSendLoader {
        next: u64,
        closed: [DwHandle; 32],
        close_count: usize,
        transferred_service: Option<DwHandle>,
    }

    impl InitSendLoader {
        const fn new() -> Self {
            Self {
                next: 0x1000,
                closed: [DwHandle(0); 32],
                close_count: 0,
                transferred_service: None,
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
            Err(FAILURE)
        }

        fn thread_start(
            &mut self,
            _thread: DwHandle,
            _entry: u64,
            _stack_pointer: u64,
            _child_bootstrap: DwHandle,
            _startup_abi: u64,
        ) -> Result<(), Self::Error> {
            panic!("failed INIT must prevent thread start")
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
            _bytes: &mut [u8],
            _handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, NativeError> {
            Err(FAILURE)
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
            Ok(())
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
            Err(FAILURE)
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
    fn selector_27_controller_does_not_embed_wrlj_dispatch() {
        let source = include_str!("wyr1b_native.rs");
        assert!(!source.contains(concat!("launch_", "authorized_job")));
        assert!(!source.contains(concat!("wyrmroot_launch_", "proto")));
    }
}
