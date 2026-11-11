//! Product activation: the marker, the registry, devmgr and its drivers.

use crate::jobs::{EndpointKind, RegistryTopology};
use crate::*;
use crate::{
    RegistryNativeAttempt, create_controller_channel_pair, establish_registry_topology,
    launch_registry_until_ready, poison_registry_generation,
};
use deepwyrm_syscall::{DW_HANDLE_TRANSFER_MOVE, DW_OBJECT_TYPE_CHANNEL, DwHandleTransferV1};
use wyrmroot_device_proto::SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY;
use wyrmroot_device_proto::coordinator::{
    RegistryEndpoint, RegistryEndpointGeneration, RegistryEndpointId, RegistryGeneration,
    SupervisorGeneration,
};
use wyrmroot_device_proto::driver_launch::encode_reaped;
use wyrmroot_device_proto::{
    DriverLaunchRequest,
    controller::{ControllerMessage, StatusCode, parse as parse_controller},
    driver_launch::{
        DRIVER_RETIRED_BYTES, LAUNCH_REQUEST_BYTES, LAUNCH_RESPONSE_BYTES, encode_constructed,
        parse_request,
    },
    manifest::{
        BOOT_DISK_PUBLICATION_POLICY, BOOT_DISK_ROLE_ID, COM2_ROLE_ID, ContentIdentity,
        Manifest as DeviceManifest, PublicationPolicy,
    },
    pci_driver::{GRANT_BYTES, PublicationGrant, encode_grant},
};
use wyrmroot_loader::launch::CHILD_CHANNEL_TRANSFER_RIGHTS;
use wyrmroot_loader::{
    launch::{DEVICE_MANIFEST_TRANSFER_RIGHTS, LaunchProfile},
    process::{
        DeviceCoordinatorLoadRequest, DeviceCoordinatorResourceLoadRequest,
        DeviceDriverLoadRequest, load_device_coordinator_process,
        load_device_coordinator_resource_process, load_device_driver_process,
    },
};

pub(crate) const DRIVER_CONTROL_INGRESS_RIGHTS: DwRights = CHILD_CHANNEL_TRANSFER_RIGHTS;
use wyrmroot_registry_proto::{
    Header as RegistryHeader, MessageType as RegistryMessageType, ProtocolVersion,
    encode_install_publication,
};

pub(crate) use wyrmroot_bootfs::paths::DEVMGR_PATH;
pub(crate) use wyrmroot_bootfs::paths::{
    DEVICE_MANIFEST_PATH, MARKER as MARKER_BYTES, MARKER_PATH,
};
pub(crate) const PUBLICATION_ID_BASE: u64 = 0xC1_0000;
pub(crate) const SERVICE_GENERATION_BASE: u64 = 0xC1_0800;
pub(crate) const PUBLICATION_TRANSACTION_BASE: u64 = 0xC1_1000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PublicationCorrelation {
    pub(crate) publication_id: u64,
    pub(crate) service_generation: u64,
    pub(crate) transaction_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PublicationAllocator {
    pub(crate) next: PublicationCorrelation,
}

impl PublicationAllocator {
    pub(crate) const fn new() -> Self {
        Self {
            next: PublicationCorrelation {
                publication_id: PUBLICATION_ID_BASE + 1,
                service_generation: SERVICE_GENERATION_BASE + 1,
                transaction_id: PUBLICATION_TRANSACTION_BASE + 1,
            },
        }
    }

    pub(crate) fn issue(&mut self) -> Result<PublicationCorrelation, InitError> {
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
pub(crate) struct DriverNativeAttempt {
    pub(crate) loaded: LoadedProcess,
    pub(crate) task_group: DwHandle,
    pub(crate) request: DriverLaunchRequest,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ResidentState {
    pub(crate) session: Option<ConsoleState>,
    pub(crate) resource_domain: Option<ResourceDomainCustody>,
    pub(crate) registry: Option<RegistryNativeAttempt>,
    pub(crate) topology: RegistryTopology,
    pub(crate) devmgr: Option<ActiveNativeRole>,
    pub(crate) binding: Option<wyrmroot_device_proto::RegistryBinding>,
    pub(crate) publication_service_generation: u64,
    pub(crate) waiting_registry_observed: bool,
    pub(crate) publication_allocator: PublicationAllocator,
    pub(crate) last_controller_transaction: u64,
    pub(crate) next_controller_transaction: u64,
    pub(crate) driver: Option<DriverNativeAttempt>,
    /// The boot-disk driver (root `STORAGE_PLAN.md` W2). It is not part of the
    /// recovery root: nothing the console needs depends on it, its exit is
    /// reaped without a restart, and devmgr recovery and shutdown retire it
    /// first.
    pub(crate) storage_driver: Option<DriverNativeAttempt>,
    /// The storage service roles (root `STORAGE_PLAN.md` W6), by `services`
    /// spec order. Like the boot-disk driver they are outside the recovery
    /// root: an exit is reaped without a restart.
    pub(crate) services: [Option<ServiceAttempt>; SERVICE_COUNT],
    pub(crate) last_reaped_driver: Option<DriverLaunchRequest>,
    pub(crate) last_driver_attempt: u64,
    pub(crate) last_driver_session: u64,
    pub(crate) last_driver_endpoint: u64,
    pub(crate) last_driver_transaction: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DevmgrNativeAttempt {
    pub(crate) active: ActiveNativeRole,
    pub(crate) binding: wyrmroot_device_proto::RegistryBinding,
    pub(crate) publication_service_generation: u64,
    pub(crate) last_controller_transaction: u64,
    pub(crate) next_controller_transaction: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResidentPollEvent {
    DevmgrExited,
    DevmgrControlLost,
    DevmgrControlReadable,
    /// The registry's control channel peer-closed.
    RegistryControlLost,
    /// The registry's process exited.
    RegistryExited,
    DriverExited,
    /// The boot-disk driver's process exited.
    StorageDriverExited,
}

pub(crate) fn classify_resident_poll(
    result: DwWaitResultV1,
    registry_present: bool,
    driver_present: bool,
    storage_present: bool,
) -> Result<ResidentPollEvent, InitError> {
    let storage_index = 2 + u32::from(registry_present) * 2 + u32::from(driver_present);
    let item_count = storage_index as usize + usize::from(storage_present);
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
        // F3A.6h. These were one `RegistryLost` variant, which made a closed
        // channel and a dead process the same word: the first points at the
        // channel's other end or a handle lifetime, the second at registryd
        // itself, and F3A.6g could say the registry was lost four times
        // without saying how. Devmgr's two are named separately directly
        // above, and always were.
        2 if registry_present && result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 => {
            Ok(ResidentPollEvent::RegistryControlLost)
        }
        3 if registry_present && result.observed.0 & DW_SIGNAL_EXITED.0 != 0 => {
            Ok(ResidentPollEvent::RegistryExited)
        }
        index
            if driver_present
                && index == 2 + u32::from(registry_present) * 2
                && result.observed.0 & DW_SIGNAL_EXITED.0 != 0 =>
        {
            Ok(ResidentPollEvent::DriverExited)
        }
        index
            if storage_present
                && index == storage_index
                && result.observed.0 & DW_SIGNAL_EXITED.0 != 0 =>
        {
            Ok(ResidentPollEvent::StorageDriverExited)
        }
        _ => Err(InitError::Supervision),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RegistryRecoveryStep {
    Degraded,
    AwaitStatus,
    Restart,
}

/// Why a registry recovery gave up without installing a replacement.
///
/// Both exits used to `return Ok(())`, which made them indistinguishable from
/// a status: F3A.6f could say the smp profile's registry slot had been emptied
/// and not which exit emptied it. `InitError::RegistryAbandoned` carries one
/// of these.
// The reason is only *reported* under `wyr1e-production`, but every caller
// names its trigger regardless, so the names exist in every build.
pub(crate) mod abandoned {
    // Which exit gave up is not in the reason byte: it is the operation field
    // of the same status. `registry_recovery_step`'s `Degraded` exit -- the
    // controller's restart budget for the registry exhausted -- is attributed
    // `RetireRegistry` (0x0b), and the exit where
    // `launch_registry_until_ready_before` returned `Ok(None)` rather than an
    // owner is attributed `LaunchRegistry` (0x0c). One for one.
    //
    // F3A.6j needed the whole low nibble for the poll phase and found the exit
    // already encoded eight bits above it. Per
    // `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` §3.1 a collapse is permitted
    // when the fact survives on the reader's channel, and here it survives in
    // the same word; `wyr1e_product_source.rs` pins the correspondence so the
    // redundancy cannot quietly stop being true.

    /// What asked for the recovery that gave up, in the reason's high nibble.
    ///
    /// F3A.6h. The exit alone says the budget ran out; it does not say what
    /// kept spending it, and the callers are not interchangeable -- a
    /// peer-closed channel, a dead process and a shell-side poisoning have
    /// different causes. The final call's trigger is the one reported, which
    /// is the loss that exhausted the budget.
    // Each trigger belongs to a different caller, and the callers are behind
    // different features: `WYR1E_POLL_E8` needs `wyr1e8-selector33` and
    // `NONE` is only reached by host fixtures. Naming the whole set in one
    // place is what makes the reason byte readable, so the set is allowed to
    // be wider than any single build's callers rather than split across cfgs
    // that would drift out of step with them.
    pub(crate) mod trigger {
        /// `ResidentPollEvent::RegistryControlLost`.
        pub(crate) const CONTROL_LOST: u8 = 0x01;
        /// `ResidentPollEvent::RegistryExited`.
        pub(crate) const EXITED: u8 = 0x02;
        /// Devmgr reported waiting-for-registry while an owner still existed.
        pub(crate) const DEVMGR_WAITING: u8 = 0x03;
        /// `crate::PollOutcome::RecoverRegistry`.
        pub(crate) const CONSOLE_POLL: u8 = 0x04;
        /// `start_console_or_recover_registry`'s fallback after a failed start.
        pub(crate) const CONSOLE_START_FALLBACK: u8 = 0x06;
    }

    /// Which part of `crate::poll` asked, in the reason's low nibble.
    ///
    /// F3A.6j. `CONSOLE_POLL` covers twenty product sites across three
    /// functions, which is most of the poll, so on its own it named a file
    /// rather than a cause. These name the site. `NONE` is every trigger that
    /// is not the wyr1e poll.
    pub(crate) mod phase {
        /// Not a wyr1e-poll trigger.
        pub(crate) const NONE: u8 = 0x00;
        /// A publication datagram that did not parse, or was not the expected
        /// message or generation.
        pub(crate) const PUBLICATION_DATAGRAM: u8 = 0x01;
        /// The publication observer's own lifecycle: a lost or unreadable
        /// observer channel, or a refused rebind.
        pub(crate) const PUBLICATION_OBSERVER: u8 = 0x02;
        /// The job dispatcher failed and left the shell registry poisoned.
        pub(crate) const DISPATCHER_POISONED: u8 = 0x03;
        /// The console's READY deadline had already passed on entry.
        pub(crate) const READY_DEADLINE_BEFORE_WAIT: u8 = 0x04;
        /// The console wait timed out and the READY deadline had passed.
        pub(crate) const READY_DEADLINE_AFTER_WAIT: u8 = 0x05;
        /// The console wait reported an index that is not the launch channel.
        pub(crate) const CONSOLE_WAIT_INDEX: u8 = 0x06;
        /// The console wrote when no READY was outstanding.
        pub(crate) const CONSOLE_UNSOLICITED: u8 = 0x07;
        /// Retired. `0x08` was "receiving the console's message failed",
        /// which is where F3A.6j found the F bring-up dying. That site now
        /// returns the kernel status instead of laundering it into a registry
        /// recovery, so the phase can no longer be produced. The number stays
        /// spent so an older transcript still reads correctly.
        /// The console's message carried handles, which READY never does.
        pub(crate) const CONSOLE_UNEXPECTED_HANDLES: u8 = 0x09;
        /// The console's READY message failed validation.
        pub(crate) const CONSOLE_READY_INVALID: u8 = 0x0a;
        /// A recovery episode was still live when READY arrived.
        pub(crate) const CONSOLE_RECOVERY_LIVE: u8 = 0x0b;
        /// A console signal matched none of the handled cases.
        pub(crate) const CONSOLE_EVENT_UNMATCHED: u8 = 0x0c;
    }

    /// One reason byte: the trigger in the high nibble, the poll phase in the
    /// low. The exit is the operation field of the same status; see the note
    /// above the phase module.
    #[must_use]
    pub(crate) const fn reason(trigger: u8, phase: u8) -> u8 {
        (trigger & 0x0f) << 4 | (phase & 0x0f)
    }
}

pub(crate) const fn registry_recovery_step(
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
    S: ResidentPlatform,
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
    let (manifest, uart_identity) = crate::validate_retained_bootfs_c1(bootfs)?;
    validate_device_identity(device_manifest, uart_identity)?;
    let resident = slot.write(ResidentSystemInit {
        controller: manifest,
        authority,
        result: RecoveryResult::Degraded,
        active: [None; EARLY_ROLE_COUNT],
        evidence_finalized: false,
        session_complete: false,
        last_tick_ns: 0,
        product: None,
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
    // Startup phases name themselves, so a bring-up failure says which role
    // was being brought up. Before F3A.6e these reached the host as
    // `operation = 0x0f`, and F3A.6d could locate a site without being able to
    // say whether the site ran during startup or during an ordinary tick.
    let registry = attribute_failure(
        RecoveryOperation::ActivateRegistry,
        launch_registry_until_ready(
            system,
            loader,
            waits,
            &mut resident.controller,
            authority,
            bootfs,
        ),
    )?
    .ok_or(InitError::AbsentState(0x11))?;
    let (registry, mut topology) = attribute_failure(
        RecoveryOperation::ActivateRegistry,
        establish_registry_topology(system, waits, &mut resident.controller, registry),
    )?;
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
            let error =
                attribute_failure::<()>(RecoveryOperation::ActivateDevmgr, Err(error)).unwrap_err();
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
    let services = launch_services(
        system,
        loader,
        waits,
        authority,
        bootfs,
        registry.control_channel,
        &mut topology,
        &mut publication_allocator,
    );
    let session = Some(ConsoleState::new(topology.generation())?);
    let state = ResidentState {
        session,
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
        storage_driver: None,
        services,
        last_reaped_driver: None,
        last_driver_attempt: 0,
        last_driver_session: 0,
        last_driver_endpoint: 0,
        last_driver_transaction: 0,
    };
    resident.active = [Some(registry.active), Some(devmgr.active)];
    resident.result = RecoveryResult::Recovered;
    resident.product = Some(state);
    Ok(resident)
}

pub(crate) fn validate_device_identity(
    manifest: DeviceManifest<'_>,
    uart_identity: [u8; 32],
) -> Result<(), InitError> {
    manifest
        .match_com2(ContentIdentity(uart_identity))
        .map(|_| ())
        .map_err(|_| InitError::WrongManifestProfile)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn launch_devmgr<S, L, W>(
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
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let RestartState::Starting {
        generation,
        transaction_id,
        ..
    } = controller
        .role_state(RoleId::Devmgr)
        .ok_or(InitError::AbsentState(0x12))?
    else {
        return Err(InitError::WrongActivationOrder);
    };
    let grant = topology
        .issue(generation, EndpointKind::Publication)
        .map_err(InitError::Jobs)?;
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
        let reduced = custody.devmgr_claim_authority();
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
    let bytes = match encode_publication_request(request, publication.service_generation) {
        Ok(bytes) => bytes,
        Err(()) => {
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
    };
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

pub(crate) const PUBLICATION_REQUEST_BYTES: usize =
    wyrmroot_device_proto::controller_v1_1::RECORD_BYTES;

pub(crate) fn encode_publication_request(
    controller: ControllerMessage,
    service_generation: u64,
) -> Result<[u8; PUBLICATION_REQUEST_BYTES], ()> {
    let mut bytes = [0u8; PUBLICATION_REQUEST_BYTES];
    wyrmroot_device_proto::controller_v1_1::encode(
        wyrmroot_device_proto::controller_v1_1::PublicationMessage {
            controller,
            service_generation,
        },
        &mut bytes,
    )
    .map_err(|_| ())?;
    Ok(bytes)
}

pub(crate) fn install_publication<S: ResidentPlatform>(
    system: &mut S,
    control: DwHandle,
    grant: crate::jobs::EndpointGrant,
    correlation: PublicationCorrelation,
    endpoint: DwHandle,
) -> Result<(), InitError> {
    install_publication_with_policy(
        system,
        control,
        grant,
        correlation,
        endpoint,
        SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY,
    )
}

pub(crate) fn install_publication_with_policy<S: ResidentPlatform>(
    system: &mut S,
    control: DwHandle,
    grant: crate::jobs::EndpointGrant,
    correlation: PublicationCorrelation,
    endpoint: DwHandle,
    policy: PublicationPolicy,
) -> Result<(), InitError> {
    let mut bytes = [0u8; 256];
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
    crate::registry::send_registry_control(
        system,
        control,
        &bytes[..size],
        core::slice::from_ref(&transfer),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn fail_loaded_devmgr<S, W>(
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
    S: ResidentPlatform,
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

pub(crate) fn await_waiting_for_registry<S, W>(
    system: &mut S,
    waits: &mut W,
    devmgr: ActiveNativeRole,
    supervisor_generation: u64,
    last_controller_transaction: u64,
    deadline_cap: Option<u64>,
) -> Result<(), InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let now = system.now().map_err(InitError::Native)?;
    if deadline_cap.is_some_and(|deadline| now >= deadline) {
        return Err(InitError::Supervision);
    }
    let deadline = now
        .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .ok_or(InitError::Accounting)?;
    let deadline = deadline_cap.map_or(deadline, |cap| deadline.min(cap));
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
    )?;
    if let Some(deadline) = deadline_cap {
        let validated_at = system.now().map_err(InitError::Native)?;
        if validated_at >= deadline {
            return Err(InitError::Supervision);
        }
    }
    Ok(())
}

pub(crate) fn receive_waiting_for_registry<S: InitPlatform>(
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

pub(crate) fn receive_controller_status<S: InitPlatform>(
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
pub(crate) enum DevmgrControlInput {
    Status(ControllerMessage),
    DriverLaunch {
        request: DriverLaunchRequest,
        child_endpoint: DwHandle,
    },
    DriverRetired {
        bytes: [u8; DRIVER_RETIRED_BYTES],
    },
}

pub(crate) fn receive_devmgr_control<S: InitPlatform>(
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

pub(crate) fn close_received_native<S: InitPlatform>(
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

pub(crate) fn validate_driver_actor(
    bootfs: &[u8],
    request: DriverLaunchRequest,
) -> Result<&[u8], InitError> {
    // Re-run the complete retained WRRM/product validation at the construction
    // boundary, then join the request identity through WRDM to the exact
    // executable bytes actually supplied to the loader.
    let _ = crate::validate_retained_bootfs_c1(bootfs)?;
    let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
    let device_manifest = archive
        .lookup(DEVICE_MANIFEST_PATH.as_bytes())
        .map_err(map_lookup)?;
    if device_manifest.is_executable() {
        return Err(InitError::WrongManifestProfile);
    }
    let manifest = DeviceManifest::parse(device_manifest.data())
        .map_err(|_| InitError::WrongManifestProfile)?;
    let (role, path, mismatch) = match request.role_id {
        COM2_ROLE_ID => (
            manifest.match_com2(request.actor_identity),
            wyrmroot_device_proto::manifest::UART16550D_PATH,
            InitError::ArtifactIdentityMismatch(RoleId::Uart16550d),
        ),
        // The boot disk is not a WRRM role, so its executable identity comes
        // from WRDM alone (root `STORAGE_PLAN.md` W2).
        BOOT_DISK_ROLE_ID => (
            manifest.match_boot_disk(request.actor_identity),
            wyrmroot_device_proto::manifest::VIRTIO_BLKD_PATH,
            InitError::BlockDriverIdentityMismatch,
        ),
        _ => return Err(InitError::WrongManifestProfile),
    };
    let role = role.map_err(|_| InitError::WrongManifestProfile)?;
    if role.role_id != request.role_id || role.driver_path != path {
        return Err(InitError::WrongManifestProfile);
    }
    let actor = archive.lookup(path).map_err(map_lookup)?;
    if !actor.is_executable()
        || wyrmroot_runtime::sha256::digest(actor.data()) != request.actor_identity.0
    {
        return Err(mismatch);
    }
    Ok(actor.data())
}

pub(crate) fn driver_correlation_is_fresh(
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
pub(crate) fn construct_driver<S, L, W>(
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
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    // The recovery episode lives on the wyr1e console/shell supervisor, so
    // a build without that product has no episode rather than no concept of
    // one. The gate is the product, not a selector.
    let action_deadline = crate::recovery_deadline(resident)?;
    if action_deadline.is_some_and(|deadline| system.now().map_or(true, |now| now >= deadline)) {
        system
            .close_handle(child_endpoint)
            .map_err(|_| InitError::Cleanup)?;
        return Err(InitError::Supervision);
    }
    let state = resident
        .product
        .as_ref()
        .ok_or(InitError::AbsentState(0x1e))?;
    let correlation_valid = driver_correlation_is_fresh(
        devmgr.generation,
        state.last_driver_attempt,
        state.last_driver_session,
        state.last_driver_endpoint,
        state.last_driver_transaction,
        request,
    );
    // The boot disk has its own slot: it is not the console's driver, and the
    // two may run at once (root `STORAGE_PLAN.md` W2).
    let storage = request.role_id == BOOT_DISK_ROLE_ID;
    let slot_taken = if storage {
        state.storage_driver.is_some()
    } else {
        state.driver.is_some()
    };
    if !correlation_valid || slot_taken {
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
    // `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` §5.3 item 2: the driver's attempt
    // TaskGroup is no longer a child of the devmgr generation that asked for
    // it, so tearing that generation down does not take the driver with it.
    // Deliberate driver retirement stays explicit -- `reap_driver` terminates
    // this group by handle -- which is the only path that ever needed to be
    // deliberate.
    //
    // It moves *up one level*, to the resource domain itself, not out to
    // init's bootstrap group. The domain is the fail-closed boundary:
    // `WYR1_C_DEVICE_HANDOFF_CONTRACT.md` §4 makes its teardown terminal
    // recovery for the boot, and a driver holding a DeviceResource and an
    // Interrupt outside it would survive that teardown. Init's own group sits
    // outside the domain, which is exactly why init cannot claim; a driver
    // parented there would inherit that escape. Builds with no resource domain
    // keep init's group, as they always did.
    let driver_parent = resident
        .product
        .as_ref()
        .and_then(|state| state.resource_domain)
        .map_or(resident.authority.task_group, ResourceDomainCustody::handle);
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
            display_path: request.driver_path,
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

    if let Err(error) =
        crate::ensure_recovery_live(resident, system.now().map_err(InitError::Native)?)
    {
        let cleanup_failed =
            cleanup_loaded_before(system, waits, loaded, task_group, true, action_deadline)
                .is_err();
        return Err(if cleanup_failed {
            InitError::Cleanup
        } else {
            error
        });
    }

    {
        let state = resident
            .product
            .as_mut()
            .ok_or(InitError::AbsentState(0x1f))?;
        let attempt = Some(DriverNativeAttempt {
            loaded,
            task_group,
            request,
        });
        if storage {
            state.storage_driver = attempt;
        } else {
            state.driver = attempt;
        }
        state.last_driver_attempt = request.attempt_generation.0;
        state.last_driver_session = request.launch_session.0;
        state.last_driver_endpoint = request.endpoint.id.0;
        state.last_driver_transaction = request.transaction_id;
    }
    let mut ack = [0u8; LAUNCH_RESPONSE_BYTES];
    encode_constructed(request, &mut ack).map_err(|_| InitError::WrongManifestProfile)?;
    let granted = if storage {
        grant_driver_publication(
            resident,
            system,
            devmgr,
            loaded.launch_channel,
            request,
            BOOT_DISK_PUBLICATION_POLICY,
        )
    } else {
        Ok(())
    };
    if let Err(error) = granted.and_then(|()| {
        system
            .send_channel(devmgr.loaded.launch_channel, &ack)
            .map_err(InitError::Native)
    }) {
        let attempt = resident
            .product
            .as_ref()
            .and_then(|state| {
                if storage {
                    state.storage_driver
                } else {
                    state.driver
                }
            })
            .ok_or(InitError::AbsentState(0x20))?;
        let cleanup_failed = cleanup_loaded_before(
            system,
            waits,
            attempt.loaded,
            attempt.task_group,
            true,
            action_deadline,
        )
        .is_err();
        if !cleanup_failed {
            let state = resident
                .product
                .as_mut()
                .ok_or(InitError::AbsentState(0x21))?;
            if storage {
                state.storage_driver = None;
            } else {
                state.driver = None;
            }
        }
        return Err(if cleanup_failed {
            InitError::Cleanup
        } else {
            error
        });
    }
    if action_deadline.is_some_and(|deadline| system.now().map_or(true, |now| now >= deadline)) {
        return Err(InitError::Supervision);
    }
    Ok(())
}

pub(crate) fn reap_driver<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
    terminate: bool,
) -> Result<DriverLaunchRequest, InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    reap_driver_before(resident, system, waits, terminate, None)
}

pub(crate) fn reap_driver_before<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
    terminate: bool,
    deadline_cap: Option<u64>,
) -> Result<DriverLaunchRequest, InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let attempt = resident
        .product
        .as_ref()
        .and_then(|state| state.driver)
        .ok_or(InitError::AbsentState(0x28))?;
    let request = attempt.request;
    cleanup_loaded_before(
        system,
        waits,
        attempt.loaded,
        attempt.task_group,
        terminate,
        deadline_cap,
    )?;
    if let Some(state) = resident.product.as_mut() {
        if state.driver != Some(attempt) {
            return Err(InitError::WrongActivationOrder);
        }
        state.driver = None;
        if deadline_cap.is_some_and(|deadline| system.now().map_or(true, |now| now >= deadline)) {
            return Err(InitError::Supervision);
        }
        state.last_reaped_driver = Some(request);
    }
    Ok(request)
}

/// Installs `policy`'s registry publication for a PCI driver and sends the
/// driver its endpoint over its launch Channel as one WRPG grant (root
/// `STORAGE_PLAN.md` W2). The driver publishes after devmgr accepts its READY.
pub(crate) fn grant_driver_publication<S: ResidentPlatform>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    devmgr: ActiveNativeRole,
    driver_launch_channel: DwHandle,
    request: DriverLaunchRequest,
    policy: PublicationPolicy,
) -> Result<(), InitError> {
    let state = resident
        .product
        .as_mut()
        .ok_or(InitError::AbsentState(0x24))?;
    let registry = state.registry.ok_or(InitError::AbsentState(0x25))?;
    let grant = state
        .topology
        .issue(devmgr.generation, EndpointKind::Publication)
        .map_err(InitError::Jobs)?;
    let correlation = state.publication_allocator.issue()?;
    let mut bytes = [0u8; GRANT_BYTES];
    encode_grant(
        PublicationGrant {
            registry_generation: grant.registry_generation,
            endpoint_id: grant.endpoint_id,
            endpoint_generation: grant.endpoint_generation,
            transaction_id: request.transaction_id,
            service_generation: correlation.service_generation,
        },
        &mut bytes,
    )
    .map_err(|_| InitError::WrongManifestProfile)?;
    let (registry_endpoint, driver_endpoint) = create_controller_channel_pair(system)?;
    if let Err(error) = install_publication_with_policy(
        system,
        registry.control_channel,
        grant,
        correlation,
        registry_endpoint,
        policy,
    ) {
        let cleanup_failed = system.close_handle(registry_endpoint).is_err()
            | system.close_handle(driver_endpoint).is_err();
        return Err(if cleanup_failed {
            InitError::Cleanup
        } else {
            error
        });
    }
    let transfer = DwHandleTransferV1 {
        handle: driver_endpoint,
        requested_rights: wyrmroot_loader::launch::CHILD_CHANNEL_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if let Err(error) = system.send_channel_with_handles(
        driver_launch_channel,
        &bytes,
        core::slice::from_ref(&transfer),
    ) {
        return Err(if system.close_handle(driver_endpoint).is_err() {
            InitError::Cleanup
        } else {
            InitError::Native(error)
        });
    }
    Ok(())
}

/// Reaps the boot-disk driver: terminates it first when `terminate`, then
/// waits for it and closes its process, launch Channel and TaskGroup.
pub(crate) fn reap_storage_driver<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
    terminate: bool,
) -> Result<(), InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let Some(attempt) = resident
        .product
        .as_mut()
        .and_then(|state| state.storage_driver.take())
    else {
        return Ok(());
    };
    cleanup_loaded(system, waits, attempt.loaded, attempt.task_group, terminate)
}

pub(crate) fn acknowledge_driver_reaped<S: InitPlatform>(
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

pub(crate) fn expect_device_status<S, W>(
    system: &mut S,
    waits: &mut W,
    devmgr: ActiveNativeRole,
    binding: wyrmroot_device_proto::RegistryBinding,
    transaction_id: u64,
    expected_status: StatusCode,
    deadline_cap: Option<u64>,
) -> Result<(), InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let now = system.now().map_err(InitError::Native)?;
    if deadline_cap.is_some_and(|deadline| now >= deadline) {
        return Err(InitError::Supervision);
    }
    let deadline = now
        .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .ok_or(InitError::Accounting)?;
    let deadline = deadline_cap.map_or(deadline, |cap| deadline.min(cap));
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
    if let Some(deadline) = deadline_cap {
        let validated_at = system.now().map_err(InitError::Native)?;
        if validated_at >= deadline {
            return Err(InitError::Supervision);
        }
    }
    Ok(())
}
