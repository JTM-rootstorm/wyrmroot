//! Native WYR1-C resident device-coordinator and C3 driver construction.
//!
//! C3 constructs and reaps the synthetic acceptance driver using one direct
//! child Channel. It still does not discover, receive, or bind hardware.

use super::*;
use crate::wyr1b::{EndpointKind, RegistryTopology};
use crate::wyr1b_native::{
    RegistryNativeAttempt, create_controller_channel_pair, establish_registry_topology,
    launch_registry_until_ready, poison_registry_generation, restart_topology_or_poison,
};
use deepwyrm_syscall::{DW_HANDLE_TRANSFER_MOVE, DW_OBJECT_TYPE_CHANNEL, DwHandleTransferV1};
use wyrmroot_device_proto::coordinator::{
    RegistryEndpoint, RegistryEndpointGeneration, RegistryEndpointId, RegistryGeneration,
    SupervisorGeneration,
};
use wyrmroot_device_proto::{
    DriverLaunchRequest,
    controller::{
        ControllerMessage, StatusCode, encode as encode_controller, parse as parse_controller,
    },
    driver_launch::{
        LAUNCH_REQUEST_BYTES, LAUNCH_RESPONSE_BYTES, encode_constructed, parse_request,
    },
    manifest::{
        COM2_ROLE_ID, ContentIdentity, Manifest as DeviceManifest,
        SERIAL_CONSOLE_PUBLICATION_POLICY,
    },
};
use wyrmroot_loader::{
    launch::{CHILD_CHANNEL_RIGHTS, DEVICE_MANIFEST_RIGHTS, LaunchProfile},
    process::{
        DeviceCoordinatorLoadRequest, DeviceDriverLoadRequest, load_device_coordinator_process,
        load_device_driver_process,
    },
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
    registry: Option<RegistryNativeAttempt>,
    topology: RegistryTopology,
    devmgr: Option<ActiveNativeRole>,
    binding: Option<wyrmroot_device_proto::RegistryBinding>,
    waiting_registry_observed: bool,
    publication_allocator: PublicationAllocator,
    last_controller_transaction: u64,
    next_controller_transaction: u64,
    driver: Option<DriverNativeAttempt>,
    last_driver_attempt: u64,
    last_driver_session: u64,
    last_driver_endpoint: u64,
    last_driver_transaction: u64,
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
    DevmgrControlReadable,
    RegistryLost,
    DriverExited,
}

fn classify_resident_poll(
    result: DwWaitResultV1,
    registry_present: bool,
    driver_present: bool,
) -> Result<ResidentPollEvent, InitError> {
    let item_count = 2 + usize::from(registry_present) * 2 + usize::from(driver_present);
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
    let mut publication_allocator = PublicationAllocator::new();
    let devmgr = match launch_devmgr(
        system,
        loader,
        waits,
        &mut resident.controller,
        authority,
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
        registry: Some(registry),
        topology,
        devmgr: Some(devmgr.active),
        binding: Some(devmgr.binding),
        waiting_registry_observed: false,
        publication_allocator,
        last_controller_transaction: devmgr.last_controller_transaction,
        next_controller_transaction: devmgr.next_controller_transaction,
        driver: None,
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
    correlation: PublicationCorrelation,
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
    DriverLaunch {
        request: DriverLaunchRequest,
        child_endpoint: DwHandle,
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
                && info.rights == CHILD_CHANNEL_RIGHTS
                && info.reserved0 == 0
                && info.reserved == [0; 2];
            let queried = system.query_capability_info(info.handle);
            if !metadata_valid
                || !matches!(
                    queried,
                    Ok(actual)
                        if actual.object_type == DW_OBJECT_TYPE_CHANNEL
                            && actual.rights == CHILD_CHANNEL_RIGHTS
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

fn validate_driver_actor(bootfs: &[u8], request: DriverLaunchRequest) -> Result<&[u8], InitError> {
    // Re-run the complete retained WRRM/product validation at the construction
    // boundary, then join the request identity through WRDM to the exact
    // executable bytes actually supplied to the loader.
    crate::wyr1b_native::validate_retained_bootfs_c1(bootfs)?;
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
    let task_group = match system.create_attempt_task_group(resident.authority.task_group) {
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

fn reap_driver<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
    terminate: bool,
) -> Result<(), InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let attempt = resident
        .wyr1c
        .as_mut()
        .and_then(|state| state.driver.take())
        .ok_or(InitError::WrongActivationOrder)?;
    cleanup_loaded(system, waits, attempt.loaded, attempt.task_group, terminate)
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
    let mut items = [DwWaitItemV1::default(); 5];
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
    let observed = system.wait_many(&items[..item_count], DwDeadline(now_ns));
    match observed {
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {}
        Err(error) => return Err(InitError::Native(error)),
        Ok(result) => {
            let event = classify_resident_poll(result, registry_present, driver_present)?;
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
                                        Ok(())
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
                            reap_driver(resident, system, waits, false)
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
    if resident
        .wyr1c
        .as_ref()
        .is_some_and(|state| state.driver.is_some())
        && reap_driver(resident, system, waits, true).is_err()
    {
        resident.result = RecoveryResult::Degraded;
        return Err(InitError::Cleanup);
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
        &mut state.publication_allocator,
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
    publication_allocator: &mut PublicationAllocator,
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
            &mut PublicationAllocator::new(),
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
                rights: CHILD_CHANNEL_RIGHTS,
                reserved0: 0,
                reserved: [0; 2],
            },
            received_count: 1,
            queried: CapabilityInfo {
                object_type: DW_OBJECT_TYPE_CHANNEL,
                rights: CHILD_CHANNEL_RIGHTS,
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
}
