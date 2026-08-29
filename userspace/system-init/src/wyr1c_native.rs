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
    manifest::{Manifest as DeviceManifest, SERIAL_CONSOLE_PUBLICATION_POLICY},
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
    registry: RegistryNativeAttempt,
    _topology: RegistryTopology,
    devmgr: ActiveNativeRole,
    binding: wyrmroot_device_proto::RegistryBinding,
    last_controller_transaction: u64,
    next_controller_transaction: u64,
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
    DeviceManifest::parse(manifest_entry.data()).map_err(|_| InitError::WrongManifestProfile)?;
    let manifest = crate::wyr1b_native::validate_retained_bootfs_c1(bootfs)?;
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
    let state = launch_devmgr(
        system,
        loader,
        waits,
        &mut resident.controller,
        authority,
        bootfs,
        registry,
        &mut topology,
        manifest_entry.data(),
    )?;
    resident.active = [Some(state.registry.active), Some(state.devmgr)];
    resident.result = RecoveryResult::Recovered;
    resident.wyr1c = Some(state);
    Ok(resident)
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
) -> Result<ResidentState, InitError>
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
            let poison =
                poison_registry_generation(system, waits, controller, registry, cleanup_failed);
            return Err(poison.err().unwrap_or(if cleanup_failed {
                InitError::Cleanup
            } else {
                InitError::Loader(failure.error)
            }));
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
        let poison =
            poison_registry_generation(system, waits, controller, registry, cleanup_failed);
        return Err(poison.err().unwrap_or(if cleanup_failed {
            InitError::Cleanup
        } else {
            error
        }));
    }
    let started = match system.now().map_err(InitError::Native) {
        Ok(value) => value,
        Err(error) => {
            return fail_loaded_devmgr(
                system,
                waits,
                controller,
                registry,
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
            registry,
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
            registry,
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
            registry,
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
            registry,
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
            registry,
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
                registry,
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
                registry,
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
                registry,
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
            registry,
            loaded,
            task_group,
            generation,
            transaction_id,
            InitError::Supervision,
        );
    }
    let mut status = [0u8; wyrmroot_device_proto::controller::STATUS_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = match system
        .receive_channel(loaded.launch_channel, &mut status, &mut handles)
        .map_err(InitError::Native)
    {
        Ok(value) => value,
        Err(error) => {
            return fail_loaded_devmgr(
                system,
                waits,
                controller,
                registry,
                loaded,
                task_group,
                generation,
                transaction_id,
                error,
            );
        }
    };
    if counts.bytes != status.len() || counts.handles != 0 {
        return fail_loaded_devmgr(
            system,
            waits,
            controller,
            registry,
            loaded,
            task_group,
            generation,
            transaction_id,
            InitError::WrongManifestProfile,
        );
    }
    let response = match parse_controller(&status) {
        Ok(value) => value,
        Err(_) => {
            return fail_loaded_devmgr(
                system,
                waits,
                controller,
                registry,
                loaded,
                task_group,
                generation,
                transaction_id,
                InitError::WrongManifestProfile,
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
            registry,
            loaded,
            task_group,
            generation,
            transaction_id,
            InitError::WrongManifestProfile,
        );
    }
    Ok(ResidentState {
        registry,
        _topology: *topology,
        devmgr: ActiveNativeRole {
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
    registry: RegistryNativeAttempt,
    loaded: LoadedProcess,
    task_group: DwHandle,
    generation: u64,
    transaction_id: u64,
    original: InitError,
) -> Result<ResidentState, InitError>
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
    let poison = poison_registry_generation(
        system,
        waits,
        controller,
        registry,
        cleanup_failed || controller_cleanup_failed,
    );
    Err(poison
        .err()
        .unwrap_or(if cleanup_failed || controller_cleanup_failed {
            InitError::Cleanup
        } else {
            original
        }))
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
    let mut bytes = [0u8; wyrmroot_device_proto::controller::STATUS_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = system
        .receive_channel(devmgr.loaded.launch_channel, &mut bytes, &mut handles)
        .map_err(InitError::Native)?;
    if counts.bytes != bytes.len() || counts.handles != 0 {
        return Err(InitError::WrongManifestProfile);
    }
    match parse_controller(&bytes).map_err(|_| InitError::WrongManifestProfile)? {
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
    let mut bytes = [0u8; wyrmroot_device_proto::controller::STATUS_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = system
        .receive_channel(devmgr.loaded.launch_channel, &mut bytes, &mut handles)
        .map_err(InitError::Native)?;
    if counts.bytes != bytes.len() || counts.handles != 0 {
        return Err(InitError::WrongManifestProfile);
    }
    let expected = ControllerMessage::Status {
        supervisor_generation: SupervisorGeneration(devmgr.generation),
        binding: Some(binding),
        transaction_id,
        status: expected_status,
        attempt_generation: None,
    };
    if parse_controller(&bytes).map_err(|_| InitError::WrongManifestProfile)? != expected {
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
    let observed = system.wait_many(
        &[
            DwWaitItemV1 {
                handle: state.registry.control_channel,
                signals: DW_SIGNAL_PEER_CLOSED,
            },
            DwWaitItemV1 {
                handle: state.registry.active.loaded.process,
                signals: DW_SIGNAL_EXITED,
            },
        ],
        DwDeadline(now_ns),
    );
    match observed {
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {}
        Err(error) => return Err(InitError::Native(error)),
        Ok(result) if result.index > 1 => return Err(InitError::Supervision),
        Ok(_) => {
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
                    |system, bootfs| {
                        rebind_after_registry_restart(resident, system, loader, waits, bootfs)
                    },
                )
                .map_err(InitError::Native)??;
        }
    }
    Ok(resident.controller.mode())
}

fn rebind_after_registry_restart<S, L, W>(
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
    let state = resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?;
    if poison_registry_generation(
        system,
        waits,
        &mut resident.controller,
        state.registry,
        false,
    )? {
        resident.result = RecoveryResult::Degraded;
        return Ok(());
    }
    let replacement = launch_registry_until_ready(
        system,
        loader,
        waits,
        &mut resident.controller,
        resident.authority,
        bootfs,
    )?
    .ok_or(InitError::WrongActivationOrder)?;
    state.registry = restart_topology_or_poison(
        system,
        waits,
        &mut resident.controller,
        &mut state._topology,
        replacement,
    )?;
    await_waiting_for_registry(
        system,
        waits,
        state.devmgr,
        state.devmgr.generation,
        state.last_controller_transaction,
    )?;
    let grant = state
        ._topology
        .issue(state.devmgr.generation, EndpointKind::Publication)
        .map_err(InitError::Wyr1BModel)?;
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
        state.registry.control_channel,
        grant,
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
        supervisor_generation: SupervisorGeneration(state.devmgr.generation),
        binding,
        transaction_id: state.next_controller_transaction,
    };
    let mut bytes = [0u8; wyrmroot_device_proto::controller::INSTALL_BYTES];
    encode_controller(request, &mut bytes).map_err(|_| InitError::WrongManifestProfile)?;
    let transfer = DwHandleTransferV1 {
        handle: devmgr_endpoint,
        requested_rights: wyrmroot_loader::launch::CHILD_CHANNEL_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if let Err(error) = system
        .send_channel_with_handles(
            state.devmgr.loaded.launch_channel,
            &bytes,
            core::slice::from_ref(&transfer),
        )
        .map_err(InitError::Native)
    {
        let cleanup_failed = system.close_handle(devmgr_endpoint).is_err();
        let poison = poison_registry_generation(
            system,
            waits,
            &mut resident.controller,
            state.registry,
            cleanup_failed,
        );
        return Err(poison.err().unwrap_or(if cleanup_failed {
            InitError::Cleanup
        } else {
            error
        }));
    }
    if let Err(error) = expect_device_status(
        system,
        waits,
        state.devmgr,
        binding,
        state.next_controller_transaction,
        StatusCode::OperationalWaitingForDeviceBundle,
    ) {
        let poison = poison_registry_generation(
            system,
            waits,
            &mut resident.controller,
            state.registry,
            false,
        );
        return Err(poison.err().unwrap_or(error));
    }
    state.binding = binding;
    state.last_controller_transaction = state.next_controller_transaction;
    state.next_controller_transaction = state
        .next_controller_transaction
        .checked_add(1)
        .ok_or(InitError::Accounting)?;
    resident.active = [Some(state.registry.active), Some(state.devmgr)];
    Ok(())
}
