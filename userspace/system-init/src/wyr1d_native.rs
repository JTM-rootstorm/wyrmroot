//! Native selector32 join between devmgr, the console, and retained JobV2 custody.

use super::*;
use crate::wyr1b_job::JobDispatcher;
use crate::wyr1b_native::{InstalledPeer, install_client, poll_job_dispatcher};
use crate::wyr1d_gate::Gate;
use wyrmroot_consoled::selector32::{READY, RELEASED, STATUS_BYTES, Status};
use wyrmroot_device_proto::d5_controller::{
    self, D5ControllerMessage, D5DriverIdentity, D5StreamIdentity,
};
use wyrmroot_loader::process::{ConsoledLoadRequest, load_consoled_process};

const CONSOLE_PATH: &str = "system/consoled";
const TRANSACTION: u64 = 0xD500_0001;

#[derive(Debug, Eq, PartialEq)]
pub(super) struct State {
    gate: Gate,
    jobs: JobDispatcher,
    console: Option<InstalledPeer>,
    awaiting_ready: bool,
    ready_deadline: u64,
    driver: Option<D5DriverIdentity>,
    first_driver: Option<D5DriverIdentity>,
    last_ready: Option<Status>,
    released: bool,
}

impl State {
    pub(super) fn new(bootfs: &[u8]) -> Result<Self, InitError> {
        let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
        let entry = archive
            .lookup(crate::wyr1d_gate::GATE_PATH.as_bytes())
            .map_err(map_lookup)?;
        if entry.is_executable() {
            return Err(InitError::WrongManifestProfile);
        }
        let nonce = crate::wyr1d_gate::parse_config(entry.data())
            .map_err(|_| InitError::WrongManifestProfile)?;
        Ok(Self {
            gate: Gate::new(nonce).map_err(|_| InitError::WrongManifestProfile)?,
            jobs: JobDispatcher::new(),
            console: None,
            awaiting_ready: false,
            ready_deadline: 0,
            driver: None,
            first_driver: None,
            last_ready: None,
            released: false,
        })
    }
}

pub(super) fn driver_ready<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootfs: &[u8],
    identity: D5DriverIdentity,
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
    let request = state.driver.ok_or(InitError::WrongActivationOrder)?.request;
    if identity.device_role_id != request.role_id.0
        || identity.driver_attempt_generation != request.attempt_generation.0
        || identity.driver_control_endpoint_id != request.endpoint.id.0
        || identity.driver_control_endpoint_generation != request.endpoint.generation.0
        || identity.launch_transaction_id != request.transaction_id
    {
        return Err(InitError::WrongManifestProfile);
    }
    let d5 = state.d5.as_mut().ok_or(InitError::WrongActivationOrder)?;
    if let Some(old) = d5.driver {
        if d5.gate.record_count() != 8
            || !d5.released
            || identity.bundle_generation <= old.bundle_generation
            || identity.driver_attempt_generation <= old.driver_attempt_generation
            || state
                .last_reaped_driver
                .is_none_or(|r| r.attempt_generation.0 != old.driver_attempt_generation)
        {
            return Err(InitError::WrongManifestProfile);
        }
    } else {
        d5.first_driver = Some(identity);
    }
    d5.driver = Some(identity);
    if d5.console.is_none() {
        let registry = state.registry.ok_or(InitError::WrongActivationOrder)?;
        launch_console(
            d5,
            system,
            loader,
            waits,
            resident.authority,
            bootfs,
            registry.control_channel,
            &mut state.topology,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn launch_console<S, L, W>(
    d5: &mut State,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    bootfs: &[u8],
    registry_control: DwHandle,
    topology: &mut RegistryTopology,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
    let image = archive
        .lookup(CONSOLE_PATH.as_bytes())
        .map_err(map_lookup)?;
    if !image.is_executable() || image.data().is_empty() {
        return Err(InitError::NonExecutableRole);
    }
    let registry_grant = topology
        .issue(1, EndpointKind::RegistryClient)
        .map_err(InitError::Wyr1BModel)?;
    let launch_grant = topology
        .issue(1, EndpointKind::LaunchSession)
        .map_err(InitError::Wyr1BModel)?;
    let group = system
        .create_attempt_task_group(authority.task_group)
        .map_err(InitError::Native)?;
    let (registry_endpoint, child_registry) = match create_controller_channel_pair(system) {
        Ok(pair) => pair,
        Err(error) => {
            system.close_handle(group).map_err(|_| InitError::Cleanup)?;
            return Err(error);
        }
    };
    if let Err(error) = install_client(
        system,
        registry_control,
        registry_grant,
        registry_endpoint,
        0xD500_0001,
    ) {
        let failed = system.close_handle(registry_endpoint).is_err()
            | system.close_handle(child_registry).is_err()
            | system.close_handle(group).is_err();
        return Err(if failed { InitError::Cleanup } else { error });
    }
    let (launch_endpoint, child_launch) = match create_controller_channel_pair(system) {
        Ok(pair) => pair,
        Err(error) => {
            let failed =
                system.close_handle(child_registry).is_err() | system.close_handle(group).is_err();
            return Err(if failed { InitError::Cleanup } else { error });
        }
    };
    // Install before launching: consoled synchronously creates its first child
    // before READY, so its launch session must be polled during readiness.
    if let Err(error) = d5.jobs.install_session(launch_grant, launch_endpoint) {
        let failed = system.close_handle(launch_endpoint).is_err()
            | system.close_handle(child_launch).is_err()
            | system.close_handle(child_registry).is_err()
            | system.close_handle(group).is_err();
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Wyr1BModel(error)
        });
    }
    let loaded = match load_consoled_process(
        loader,
        LoadAuthority {
            task_group: group,
            ..authority
        },
        ConsoledLoadRequest {
            image: image.data(),
            display_path: CONSOLE_PATH,
            registry_endpoint: child_registry,
            registry_generation: registry_grant.registry_generation,
            registry_endpoint_id: registry_grant.endpoint_id,
            registry_endpoint_generation: registry_grant.endpoint_generation,
            launch_endpoint: child_launch,
            launch_connection_id: launch_grant.endpoint_id,
            launch_connection_generation: launch_grant.endpoint_generation,
            transaction_id: TRANSACTION,
        },
    ) {
        Ok(loaded) => loaded,
        Err(failure) => {
            let mut failed = false;
            if !failure.registry_endpoint_consumed {
                failed |= system.close_handle(child_registry).is_err();
            }
            if !failure.launch_endpoint_consumed {
                failed |= system.close_handle(child_launch).is_err();
            }
            failed |= d5
                .jobs
                .disconnect_session(launch_grant)
                .map_or(true, |handle| system.close_handle(handle).is_err());
            failed |= system.close_handle(group).is_err();
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Loader(failure.error)
            });
        }
    };
    let configured = (|| {
        let bytes = Status::configure(d5.gate.nonce())
            .encode()
            .map_err(|_| InitError::WrongManifestProfile)?;
        system
            .send_channel(loaded.launch_channel, &bytes)
            .map_err(InitError::Native)?;
        d5.ready_deadline = system
            .now()
            .map_err(InitError::Native)?
            .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .ok_or(InitError::Accounting)?;
        Ok(())
    })();
    if let Err(error) = configured {
        let failed = cleanup_loaded(system, waits, loaded, group, true).is_err()
            | d5.jobs
                .disconnect_session(launch_grant)
                .map_or(true, |handle| system.close_handle(handle).is_err());
        return Err(if failed { InitError::Cleanup } else { error });
    }
    d5.console = Some(InstalledPeer {
        grant: launch_grant,
        loaded,
        task_group: group,
    });
    d5.awaiting_ready = true;
    Ok(())
}

pub(super) fn poll<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    now: u64,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut d5 = resident
        .wyr1c
        .as_mut()
        .and_then(|s| s.d5.take())
        .ok_or(InitError::WrongActivationOrder)?;
    let result = poll_inner(&mut d5, resident, system, loader, waits, now);
    resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?
        .d5 = Some(d5);
    result
}

fn poll_inner<S, L, W>(
    d5: &mut State,
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    now: u64,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let Some(console) = d5.console else {
        return Ok(());
    };
    poll_job_dispatcher(system, loader, waits, resident.authority, &mut d5.jobs, now)?;
    let observed = system.wait_many(
        &[
            DwWaitItemV1 {
                handle: console.loaded.process,
                signals: DW_SIGNAL_EXITED,
            },
            DwWaitItemV1 {
                handle: console.loaded.launch_channel,
                signals: deepwyrm_syscall::DwSignals(
                    DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0,
                ),
            },
        ],
        DwDeadline(now),
    );
    let observed = match observed {
        Err(NativeError::Status(s)) if s == DW_STATUS_TIMED_OUT => {
            if d5.awaiting_ready && now >= d5.ready_deadline {
                return Err(InitError::Supervision);
            }
            return Ok(());
        }
        Err(e) => return Err(InitError::Native(e)),
        Ok(value) => value,
    };
    if observed.index != 1 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(InitError::Supervision);
    }
    let mut bytes = [0; STATUS_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = system
        .receive_channel(console.loaded.launch_channel, &mut bytes, &mut handles)
        .map_err(InitError::Native)?;
    if counts.handles != 0 {
        close_received_native(system, &handles, counts.handles)?;
        return Err(InitError::WrongManifestProfile);
    }
    if d5.awaiting_ready {
        wyrmroot_loader::launch::parse_ready_for_profile(
            LaunchProfile::Consoled,
            &bytes[..counts.bytes],
            TRANSACTION,
        )
        .map_err(|_| InitError::Supervision)?;
        d5.awaiting_ready = false;
        return Ok(());
    }
    let status =
        Status::parse(&bytes[..counts.bytes]).map_err(|_| InitError::WrongManifestProfile)?;
    let state = resident
        .wyr1c
        .as_ref()
        .ok_or(InitError::WrongActivationOrder)?;
    let devmgr = state.devmgr.ok_or(InitError::WrongActivationOrder)?;
    if status.kind == RELEASED {
        let old = d5.last_ready.ok_or(InitError::WrongActivationOrder)?;
        if d5.gate.record_count() != 8
            || d5.released
            || status.nonce != old.nonce
            || status.tuple != old.tuple
            || status.job != old.job
            || status.publication != old.publication
            || status.client_transaction != old.client_transaction
            || d5.jobs.jobs.loaded_job(status.job).is_ok()
        {
            return Err(InitError::WrongManifestProfile);
        }
        send_devmgr(
            system,
            devmgr,
            D5ControllerMessage::ClientReleased(D5StreamIdentity {
                driver: d5.first_driver.ok_or(InitError::WrongActivationOrder)?,
                publication_generation: status.publication,
                client_transaction_id: status.client_transaction,
                attach_transaction_id: status.tuple.transaction,
                stream_generation: status.tuple.stream,
            }),
        )?;
        d5.released = true;
        return Ok(());
    }
    let driver = d5.driver.ok_or(InitError::WrongActivationOrder)?;
    if status.tuple.role != driver.device_role_id
        || status.tuple.bundle != driver.bundle_generation
        || status.tuple.attempt != driver.driver_attempt_generation
        || status.tuple.endpoint != driver.driver_control_endpoint_id
        || status.tuple.endpoint_generation != driver.driver_control_endpoint_generation
        || status.publication != state.publication_service_generation
    {
        return Err(InitError::WrongManifestProfile);
    }
    let loaded = d5
        .jobs
        .jobs
        .loaded_job(status.job)
        .map_err(InitError::Wyr1BModel)?;
    if loaded.loaded.process.0 == 0
        || d5
            .jobs
            .jobs
            .terminal_result(status.job)
            .map_err(InitError::Wyr1BModel)?
            .is_some()
    {
        return Err(InitError::WrongManifestProfile);
    }
    let old_clean = match d5.gate.record_count() {
        8 => {
            d5.released
                && state.last_reaped_driver.is_some_and(|r| {
                    Some(r.attempt_generation.0)
                        == d5.first_driver.map(|d| d.driver_attempt_generation)
                })
                && d5.jobs.jobs.loaded_job(d5.gate.job()).is_err()
        }
        10 => d5.jobs.jobs.loaded_job(d5.gate.job()).is_err(),
        _ => false,
    };
    let batch = d5
        .gate
        .accept(status, old_clean)
        .map_err(|_| InitError::WrongManifestProfile)?;
    if status.kind == READY {
        d5.last_ready = Some(status);
    }
    for record in &batch.records[..batch.count] {
        wyrmroot_runtime::submit_wyr1d_evidence(record).map_err(InitError::Native)?;
    }
    if let Some(line) = batch.ready {
        wyrmroot_runtime::announce_wyr1d_ready(&line).map_err(InitError::Native)?;
    }
    if batch.retire_driver {
        send_devmgr(system, devmgr, D5ControllerMessage::RequestRetire(driver))?;
    }
    Ok(())
}

fn send_devmgr<S: InitPlatform>(
    system: &mut S,
    devmgr: ActiveNativeRole,
    message: D5ControllerMessage,
) -> Result<(), InitError> {
    let mut bytes = [0; d5_controller::RECORD_BYTES];
    d5_controller::encode(message, &mut bytes).map_err(|_| InitError::WrongManifestProfile)?;
    system
        .send_channel(devmgr.loaded.launch_channel, &bytes)
        .map_err(InitError::Native)
}
