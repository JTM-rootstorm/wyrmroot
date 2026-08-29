//! Native WYR1-C1 resident device-coordinator activation.
//!
//! This deliberately stops after controller/publication installation.  It
//! does not discover or bind hardware; that belongs to later WYR1-C phases.

use super::*;
use crate::wyr1b::{EndpointKind, RegistryTopology};
use crate::wyr1b_native::{
    RegistryNativeAttempt, create_controller_channel_pair, establish_registry_topology,
    launch_registry_until_ready, poison_registry_generation, restart_topology_or_poison,
};
use deepwyrm_syscall::{DW_HANDLE_TRANSFER_MOVE, DwHandleTransferV1};
use wyrmroot_device_proto::coordinator::{
    RegistryEndpoint, RegistryEndpointGeneration, RegistryEndpointId, RegistryGeneration,
    SupervisorGeneration,
};
use wyrmroot_device_proto::{
    controller::{
        ControllerMessage, StatusCode, encode as encode_controller, parse as parse_controller,
    },
    manifest::{ContentIdentity, Manifest as DeviceManifest, SERIAL_CONSOLE_PUBLICATION_POLICY},
};
use wyrmroot_loader::{
    launch::{DEVICE_MANIFEST_RIGHTS, LaunchProfile},
    process::{DeviceCoordinatorLoadRequest, load_device_coordinator_process},
};
use wyrmroot_registry_proto::{
    Header as RegistryHeader, MessageType as RegistryMessageType, ProtocolVersion,
    encode_install_publication,
};

pub(crate) const MARKER_BYTES: &[u8] = b"WYR1-C1";
pub(crate) const MARKER_PATH: &str = "system/bootstrap/wyr1-c-gate-v1";
pub(crate) const DEVICE_MANIFEST_PATH: &str = "system/bootstrap/wyr1-c-device-manifest-v1";
const DEVMGR_PATH: &str = "system/devmgr";
const PUBLICATION_ID: u64 = 0xC1_0001;
const PUBLICATION_TRANSACTION: u64 = 0xC1_1001;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ResidentState {
    registry: Option<RegistryNativeAttempt>,
    topology: RegistryTopology,
    devmgr: Option<ActiveNativeRole>,
    binding: Option<wyrmroot_device_proto::RegistryBinding>,
    waiting_registry_observed: bool,
    last_controller_transaction: u64,
    next_controller_transaction: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DevmgrNativeAttempt {
    active: ActiveNativeRole,
    binding: wyrmroot_device_proto::RegistryBinding,
    last_controller_transaction: u64,
    next_controller_transaction: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResidentPollEvent {
    DevmgrExited,
    DevmgrControlLost,
    WaitingForRegistry,
    RegistryLost,
}

fn classify_resident_poll(
    result: DwWaitResultV1,
    item_count: usize,
) -> Result<ResidentPollEvent, InitError> {
    if result.index >= item_count as u32 {
        return Err(InitError::Supervision);
    }
    match result.index {
        0 if result.observed.0 & DW_SIGNAL_EXITED.0 != 0 => Ok(ResidentPollEvent::DevmgrExited),
        1 if result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 => {
            Ok(ResidentPollEvent::DevmgrControlLost)
        }
        1 if result.observed.0 & DW_SIGNAL_READABLE.0 != 0 => {
            Ok(ResidentPollEvent::WaitingForRegistry)
        }
        2 if item_count == 4 && result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 => {
            Ok(ResidentPollEvent::RegistryLost)
        }
        3 if item_count == 4 && result.observed.0 & DW_SIGNAL_EXITED.0 != 0 => {
            Ok(ResidentPollEvent::RegistryLost)
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
    let manifest = crate::wyr1b_native::validate_retained_bootfs_c1(bootfs)?;
    validate_device_identity(
        device_manifest,
        manifest.executable_identity(RoleId::Uart16550d)?,
    )?;
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
    let ready_len =
        encode_ready_for_profile(LaunchProfile::Supervisor, parent_transaction, &mut ready)
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
    let devmgr = match launch_devmgr(
        system,
        loader,
        waits,
        &mut resident.controller,
        authority,
        bootfs,
        registry,
        &mut topology,
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
        registry: Some(registry),
        topology,
        devmgr: Some(devmgr.active),
        binding: Some(devmgr.binding),
        waiting_registry_observed: false,
        last_controller_transaction: devmgr.last_controller_transaction,
        next_controller_transaction: devmgr.next_controller_transaction,
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
    bootfs: &[u8],
    registry: RegistryNativeAttempt,
    topology: &mut RegistryTopology,
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
            DEVICE_MANIFEST_RIGHTS,
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
    let task_group = match system
        .create_attempt_task_group(authority.task_group)
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
    if let Err(error) =
        install_publication(system, registry.control_channel, grant, registry_endpoint)
    {
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
    let loaded = match load_device_coordinator_process(
        loader,
        LoadAuthority {
            task_group,
            ..authority
        },
        DeviceCoordinatorLoadRequest {
            image: image.data(),
            display_path: DEVMGR_PATH,
            publication_endpoint: devmgr_endpoint,
            manifest,
            supervisor_generation: generation,
            transaction_id,
        },
    ) {
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
    if await_child_ready_profile_observed(
        waits,
        loaded.process,
        loaded.launch_channel,
        LaunchProfile::DeviceCoordinator,
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
    if response
        != (ControllerMessage::Status {
            supervisor_generation: SupervisorGeneration(generation),
            binding: Some(binding),
            transaction_id,
            status: StatusCode::OperationalWaitingForDeviceBundle,
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
        last_controller_transaction: transaction_id,
        next_controller_transaction: transaction_id.checked_add(1).ok_or(InitError::Accounting)?,
    })
}

fn install_publication<S: Wyr1BPlatform>(
    system: &mut S,
    control: DwHandle,
    grant: crate::wyr1b::EndpointGrant,
    endpoint: DwHandle,
) -> Result<(), InitError> {
    let mut bytes = [0u8; 256];
    let policy = SERIAL_CONSOLE_PUBLICATION_POLICY;
    let size = encode_install_publication(
        RegistryHeader {
            message_type: RegistryMessageType::InstallPublication,
            registry_generation: grant.registry_generation,
            endpoint_id: 0,
            endpoint_generation: 0,
            transaction_id: PUBLICATION_TRANSACTION,
        },
        grant.endpoint_id,
        grant.endpoint_generation,
        policy.supervisor_role_id,
        PUBLICATION_ID,
        1,
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
    let mut items = [DwWaitItemV1::default(); 4];
    items[0] = DwWaitItemV1 {
        handle: devmgr.loaded.process,
        signals: DW_SIGNAL_EXITED,
    };
    items[1] = DwWaitItemV1 {
        handle: devmgr.loaded.launch_channel,
        signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
    };
    let item_count = if let Some(registry) = state.registry {
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
    let observed = system.wait_many(&items[..item_count], DwDeadline(now_ns));
    match observed {
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {}
        Err(error) => return Err(InitError::Native(error)),
        Ok(result) => {
            let event = classify_resident_poll(result, item_count)?;
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
                        ResidentPollEvent::WaitingForRegistry => {
                            let state = resident
                                .wyr1c
                                .as_ref()
                                .ok_or(InitError::WrongActivationOrder)?;
                            let devmgr = state.devmgr.ok_or(InitError::WrongActivationOrder)?;
                            let duplicate =
                                state.registry.is_none() && state.waiting_registry_observed;
                            let status = receive_waiting_for_registry(
                                system,
                                devmgr,
                                devmgr.generation,
                                state.last_controller_transaction,
                            );
                            if duplicate || status.is_err() {
                                return recover_devmgr_after_error(
                                    resident,
                                    system,
                                    loader,
                                    waits,
                                    bootfs,
                                    status.err().unwrap_or(InitError::WrongManifestProfile),
                                );
                            }
                            if state.registry.is_some() {
                                recover_registry(resident, system, loader, waits, bootfs, true)
                            } else {
                                resident
                                    .wyr1c
                                    .as_mut()
                                    .ok_or(InitError::WrongActivationOrder)?
                                    .waiting_registry_observed = true;
                                Ok(())
                            }
                        }
                        ResidentPollEvent::RegistryLost => {
                            recover_registry(resident, system, loader, waits, bootfs, false)
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
                bootfs,
                registry,
                &mut state.topology,
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
    let (binding, transaction_id) = perform_rebind(
        system,
        waits,
        &mut state.topology,
        registry.control_channel,
        devmgr,
        state.next_controller_transaction,
    )?;
    state.binding = Some(binding);
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
    registry_control: DwHandle,
    devmgr: ActiveNativeRole,
    transaction_id: u64,
) -> Result<(wyrmroot_device_proto::RegistryBinding, u64), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let grant = topology
        .issue(devmgr.generation, EndpointKind::Publication)
        .map_err(InitError::Wyr1BModel)?;
    let binding = wyrmroot_device_proto::RegistryBinding {
        generation: RegistryGeneration(grant.registry_generation),
        endpoint: RegistryEndpoint {
            id: RegistryEndpointId(grant.endpoint_id),
            generation: RegistryEndpointGeneration(grant.endpoint_generation),
        },
    };
    let (registry_endpoint, devmgr_endpoint) = create_controller_channel_pair(system)?;
    if let Err(error) = install_publication(system, registry_control, grant, registry_endpoint) {
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
    Ok((binding, transaction_id))
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
        let mut platform = RebindPlatform::with_status(waiting_device_status());
        let mut waits = StatusWaits { fail: false };
        let mut topology = RegistryTopology::new(2).unwrap();
        let result = perform_rebind(
            &mut platform,
            &mut waits,
            &mut topology,
            DwHandle(40),
            devmgr(),
            9,
        )
        .unwrap();
        assert_eq!(result, (binding(), 9));
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
                4,
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
            ResidentPollEvent::WaitingForRegistry
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
}
