//! Native selector-27 registry and dependent-peer controller.

use super::*;
use crate::wyr1b::{EndpointGrant, EndpointKind, RegistryTopology, correlation_environment};
use crate::wyr1b_gate::{GATE_PATH, GateConfig, parse_config};
use deepwyrm_syscall::{
    DW_HANDLE_TRANSFER_MOVE, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DwHandleTransferV1,
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

fn loader_caller_retains_service_channel(error: &LoadError<NativeError>) -> bool {
    match error {
        LoadError::Elf(_) | LoadError::Startup(_) | LoadError::Launch(_) => true,
        LoadError::Platform { stage, .. } => matches!(
            stage,
            LoadStage::ChannelCreate
                | LoadStage::ChannelReduce
                | LoadStage::ProcessCreate
                | LoadStage::MemoryCreate
                | LoadStage::ParentMaterialize
                | LoadStage::ParentUnmap
                | LoadStage::ChildMap
                | LoadStage::ThreadCreate
        ),
    }
}

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
            Err(_error) => {
                if poison_registry_generation(system, waits, &mut controller, registry)? {
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
                topology
                    .restart(replacement.active.generation)
                    .map_err(InitError::Wyr1BModel)?;
                registry = replacement;
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
    let task_group = system
        .create_attempt_task_group(authority.task_group)
        .map_err(InitError::Native)?;
    let reservation = controller.reserve_attempt(RoleId::Registryd, generation, transaction_id)?;
    let (control_channel, child_control) = match system.channel_create(CHILD_CHANNEL_RIGHTS) {
        Ok(pair) => pair,
        Err(error) => {
            let close_failed = system.close_handle(task_group).is_err();
            controller.abort_reservation(reservation)?;
            return Err(if close_failed {
                InitError::Cleanup
            } else {
                InitError::Native(error)
            });
        }
    };
    let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
    let image = archive
        .lookup(REGISTRY_PATH.as_bytes())
        .map_err(map_lookup)?;
    if !image.is_executable()
        || wyrmroot_runtime::sha256::digest(image.data())
            != controller.executable_identity(RoleId::Registryd)?
    {
        return Err(InitError::ArtifactIdentityMismatch(RoleId::Registryd));
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
        Err(error) => {
            let mut control_failed = system.close_handle(control_channel).is_err();
            if loader_caller_retains_service_channel(&error) {
                control_failed |= system.close_handle(child_control).is_err();
            }
            let group_failed = system.close_handle(task_group).is_err();
            controller.abort_reservation(reservation)?;
            return Err(if control_failed || group_failed {
                InitError::Cleanup
            } else {
                InitError::Loader(error)
            });
        }
    };
    let resources = AttemptResources {
        role: RoleId::Registryd,
        generation,
        transaction_id,
        executable_identity: controller.executable_identity(RoleId::Registryd)?,
        startup_profile: StartupProfile::BootstrapRegistry,
        task_group,
        process: loaded.process,
        launch_channel: loaded.launch_channel,
        mappings: 0,
        reservation,
    };
    if let Err(error) = controller.install_attempt(resources) {
        let cleanup = cleanup_loaded(system, waits, loaded, task_group, true);
        let control_failed = system.close_handle(control_channel).is_err();
        return Err(if cleanup.is_err() || control_failed {
            InitError::Cleanup
        } else {
            error
        });
    }
    let now = system.now().map_err(InitError::Native)?;
    controller.child_started(RoleId::Registryd, generation, transaction_id, now)?;
    let deadline = now
        .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .ok_or(InitError::Accounting)?;
    if let Err(_error) = await_child_ready_profile_observed(
        waits,
        loaded.process,
        loaded.launch_channel,
        LaunchProfile::BootstrapRegistry,
        transaction_id,
        DwDeadline(deadline),
    ) {
        let cleanup = cleanup_loaded(system, waits, loaded, task_group, true);
        let control_failed = system.close_handle(control_channel).is_err();
        return Err(if cleanup.is_err() || control_failed {
            InitError::Cleanup
        } else {
            InitError::Supervision
        });
    }
    controller.ready(
        RoleId::Registryd,
        generation,
        transaction_id,
        system.now().map_err(InitError::Native)?,
    )?;
    let installed_generation = controller
        .resources(RoleId::Registryd)
        .ok_or(InitError::MissingAttemptResources)?
        .generation;
    if installed_generation != generation {
        return Err(InitError::ResourceIdentityMismatch);
    }
    let topology = RegistryTopology::new(installed_generation).map_err(InitError::Wyr1BModel)?;
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
        match launch_registry(system, loader, waits, controller, authority, bootfs) {
            Ok(value) => return Ok(Some(value)),
            Err(_error) => {
                let now = system.now().map_err(InitError::Native)?;
                let state = controller
                    .role_state(RoleId::Registryd)
                    .ok_or(InitError::WrongActivationOrder)?;
                let (generation, transaction_id, failure) = match state {
                    RestartState::Starting {
                        generation,
                        transaction_id,
                        ..
                    } => (generation, transaction_id, AttemptFailure::CreationFailed),
                    RestartState::AwaitingReady {
                        generation,
                        transaction_id,
                        ..
                    } => (generation, transaction_id, AttemptFailure::WaitFailed),
                    _ => return Err(InitError::WrongActivationOrder),
                };
                match state {
                    RestartState::Starting { .. } => controller.fail(
                        RoleId::Registryd,
                        generation,
                        transaction_id,
                        now,
                        failure,
                    )?,
                    RestartState::AwaitingReady { .. } => controller.ready_wait_failed(
                        RoleId::Registryd,
                        generation,
                        transaction_id,
                        now,
                        failure,
                    )?,
                    _ => unreachable!(),
                }
                controller.cleanup_complete(
                    RoleId::Registryd,
                    generation,
                    transaction_id,
                    now.checked_add(1).ok_or(InitError::Accounting)?,
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
) -> Result<bool, InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let now = system.now().map_err(InitError::Native)?;
    controller.fail(
        RoleId::Registryd,
        registry.active.generation,
        registry.active.transaction_id,
        now,
        AttemptFailure::Cancelled,
    )?;
    complete_native_cleanup(
        system,
        waits,
        controller,
        registry.active.loaded,
        registry.active.task_group,
        true,
        RoleId::Registryd,
        registry.active.generation,
        registry.active.transaction_id,
        now,
    )?;
    system
        .close_handle(registry.control_channel)
        .map_err(|_| InitError::Cleanup)?;
    advance_registry_or_exhausted(system, controller, registry.active.transaction_id)
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
) -> Result<InstalledPeer, InitError>
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
    let grant = topology
        .issue(role_generation, endpoint_kind)
        .map_err(InitError::Wyr1BModel)?;
    let task_group = system
        .create_attempt_task_group(authority.task_group)
        .map_err(InitError::Native)?;
    let (registry_endpoint, peer_endpoint) = match system.channel_create(CHILD_CHANNEL_RIGHTS) {
        Ok(pair) => pair,
        Err(error) => {
            return Err(if system.close_handle(task_group).is_err() {
                InitError::Cleanup
            } else {
                InitError::Native(error)
            });
        }
    };
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
        let mut failed = system.close_handle(registry_endpoint).is_err();
        failed |= system.close_handle(peer_endpoint).is_err();
        failed |= system.close_handle(task_group).is_err();
        return Err(if failed { InitError::Cleanup } else { error });
    }
    // A successful install MOVE transfers the registry endpoint. Any later
    // failure poisons this registry generation; init must not retry against it.
    let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
    let image = archive.lookup(path.as_bytes()).map_err(map_lookup)?;
    if !image.is_executable() || image.data().is_empty() {
        let _ = system.close_handle(peer_endpoint);
        let _ = system.close_handle(task_group);
        return Err(InitError::NonExecutableRole);
    }
    let correlation = correlation_environment(grant).map_err(InitError::Wyr1BModel)?;
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
        Err(error) => {
            let mut close_failed = system.close_handle(task_group).is_err();
            if loader_caller_retains_service_channel(&error) {
                close_failed |= system.close_handle(peer_endpoint).is_err();
            }
            return Err(if close_failed {
                InitError::Cleanup
            } else {
                InitError::Loader(error)
            });
        }
    };
    let now = system.now().map_err(InitError::Native)?;
    let deadline = now
        .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .ok_or(InitError::Accounting)?;
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
        cleanup_loaded(system, waits, loaded, task_group, true)?;
        return Err(InitError::Supervision);
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
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut publisher1 = None;
    let mut publisher2 = None;
    let mut client = None;
    let outcome = (|| {
        publisher1 = Some(launch_peer(
            system,
            loader,
            waits,
            authority,
            bootfs,
            registry_control,
            topology,
            PeerKind::Publisher { operation: 1 },
        )?);
        client = Some(launch_peer(
            system,
            loader,
            waits,
            authority,
            bootfs,
            registry_control,
            topology,
            PeerKind::Client,
        )?);
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

        publisher2 = Some(launch_peer(
            system,
            loader,
            waits,
            authority,
            bootfs,
            registry_control,
            topology,
            PeerKind::Publisher { operation: 2 },
        )?);
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

        cleanup_loaded(system, waits, first.loaded, first.task_group, false)?;
        publisher1 = None;
        cleanup_loaded(system, waits, second.loaded, second.task_group, false)?;
        publisher2 = None;
        cleanup_loaded(
            system,
            waits,
            client_peer.loaded,
            client_peer.task_group,
            false,
        )?;
        client = None;
        Ok(())
    })();
    if let Err(error) = outcome {
        // Any post-install failure poisons the generation. Dependents are
        // terminated and reaped before the caller closes/restarts registryd.
        let mut failed = false;
        for peer in [publisher2, client, publisher1].into_iter().flatten() {
            failed |= cleanup_loaded(system, waits, peer.loaded, peer.task_group, true).is_err();
        }
        return Err(if failed { InitError::Cleanup } else { error });
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

            if active.role == RoleId::Devmgr {
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

            // Registry teardown owns the controller endpoint after every
            // dependent peer has been reaped. A failed close is fatal because
            // the old generation could remain reachable.
            system
                .close_handle(state.registry_control)
                .map_err(|_| InitError::Cleanup)?;
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
                        let Some((registry, _)) = launch_registry_until_ready(
                            system,
                            loader,
                            waits,
                            &mut resident.controller,
                            resident.authority,
                            bootfs,
                        )?
                        else {
                            return Err(InitError::WrongActivationOrder);
                        };
                        state
                            .topology
                            .as_mut()
                            .ok_or(InitError::WrongActivationOrder)?
                            .restart(registry.active.generation)
                            .map_err(InitError::Wyr1BModel)?;
                        run_registry_gate(
                            system,
                            loader,
                            waits,
                            resident.authority,
                            bootfs,
                            registry.control_channel,
                            state
                                .topology
                                .as_mut()
                                .ok_or(InitError::WrongActivationOrder)?,
                            state.gate,
                        )?;
                        Ok::<_, InitError>(registry)
                    },
                )
                .map_err(InitError::Native)??;
            state.registry_control = replacement.control_channel;
            resident.active[index] = Some(replacement.active);
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
    use super::*;
    use deepwyrm_syscall::{DwStatus, DwWaitResultV1};
    use wyrmroot_registry_proto::{Message, parse};

    const FAILURE: NativeError = NativeError::Status(DwStatus(-1));

    struct MockPlatform {
        sent: [u8; 256],
        sent_len: usize,
        transfer: DwHandleTransferV1,
    }

    impl MockPlatform {
        fn new() -> Self {
            Self {
                sent: [0; 256],
                sent_len: 0,
                transfer: DwHandleTransferV1::default(),
            }
        }
    }

    impl InitPlatform for MockPlatform {
        fn query_capability_info(
            &mut self,
            _handle: DwHandle,
        ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
            Err(FAILURE)
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
        fn close_handle(&mut self, _handle: DwHandle) -> Result<(), NativeError> {
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

    impl Wyr1BPlatform for MockPlatform {
        fn channel_create(
            &mut self,
            _rights: DwRights,
        ) -> Result<(DwHandle, DwHandle), NativeError> {
            Err(FAILURE)
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

    #[test]
    fn publication_install_moves_exact_endpoint_and_keeps_logical_id_distinct() {
        let publication = grant(EndpointKind::Publication, 41, 9);
        let mut platform = MockPlatform::new();
        install_publication(&mut platform, DwHandle(10), publication, DwHandle(11), 1).unwrap();
        assert_eq!(platform.transfer.handle, DwHandle(11));
        assert_eq!(platform.transfer.operation, DW_HANDLE_TRANSFER_MOVE);
        assert_eq!(platform.transfer.requested_rights, CHILD_CHANNEL_RIGHTS);
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
    fn loader_service_channel_ownership_changes_at_init_send() {
        let before = LoadError::Platform {
            stage: LoadStage::ThreadCreate,
            cause: FAILURE,
            rollback_failed: false,
        };
        let moved_boundary = LoadError::Platform {
            stage: LoadStage::InitSend,
            cause: FAILURE,
            rollback_failed: false,
        };
        assert!(loader_caller_retains_service_channel(&before));
        assert!(!loader_caller_retains_service_channel(&moved_boundary));
    }
}
