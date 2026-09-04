//! Native selector32 join between devmgr, the console, and retained JobV2 custody.

use super::*;
use crate::wyr1b_job::{JobDispatcher, SessionOwner};
use crate::wyr1b_native::{InstalledPeer, install_client, poll_job_dispatcher};
use crate::wyr1d_gate::{Batch, DrainFence, Gate, RetirementJoin};
use wyrmroot_consoled::selector32::{OBSERVED, READY, RELEASED, STATUS_BYTES, Status};
use wyrmroot_device_proto::d5_controller::{
    self, D5ControllerMessage, D5DrainIdentity, D5DriverIdentity, D5StreamIdentity,
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
    pending_release: Option<Status>,
    pending_fence: Option<DrainFence>,
    fence_deadline: u64,
    released: bool,
    retirement: Option<RetirementJoin>,
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
            pending_release: None,
            pending_fence: None,
            fence_deadline: 0,
            released: false,
            retirement: None,
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
            || identity.bundle_generation != old.bundle_generation
            || identity.driver_attempt_generation <= old.driver_attempt_generation
            || (
                identity.driver_control_endpoint_id,
                identity.driver_control_endpoint_generation,
            ) == (
                old.driver_control_endpoint_id,
                old.driver_control_endpoint_generation,
            )
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
    if let Err(error) = d5.jobs.attach_session_owner(
        launch_grant,
        SessionOwner {
            process: loaded.process,
            launch_channel: loaded.launch_channel,
            task_group: group,
        },
    ) {
        let failed = cleanup_loaded(system, waits, loaded, group, true).is_err()
            | d5.jobs
                .disconnect_session(launch_grant)
                .map_or(true, |handle| system.close_handle(handle).is_err());
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Wyr1BModel(error)
        });
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
    let state = resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?;
    let context = PollContext {
        authority: resident.authority,
        devmgr: state.devmgr,
        publication: state.publication_service_generation,
        last_reaped_driver: state.last_reaped_driver,
    };
    let d5 = state.d5.as_mut().ok_or(InitError::WrongActivationOrder)?;
    poll_inner(d5, context, system, loader, waits, now)
}

#[derive(Clone, Copy)]
struct PollContext {
    authority: LoadAuthority,
    devmgr: Option<ActiveNativeRole>,
    publication: u64,
    last_reaped_driver: Option<DriverLaunchRequest>,
}

fn poll_inner<S, L, W>(
    d5: &mut State,
    context: PollContext,
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
    if d5.pending_fence.is_some() && now >= d5.fence_deadline {
        return Err(InitError::Supervision);
    }
    poll_job_dispatcher(system, loader, waits, context.authority, &mut d5.jobs, now)?;
    // Console release and process EXITED are independent observations. Retain
    // the exact console fact until the resident has sent the driver-reaped
    // acknowledgement on the same devmgr Channel; WDR5 then follows it in FIFO
    // order even when the console cleans its child before the driver exits.
    flush_release(d5, context, system)?;
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
    if d5.pending_fence.is_some() {
        return Err(InitError::WrongManifestProfile);
    }
    let devmgr = context.devmgr.ok_or(InitError::WrongActivationOrder)?;
    if status.kind == RELEASED {
        let old = d5.last_ready.ok_or(InitError::WrongActivationOrder)?;
        if d5.gate.record_count() != 8
            || d5.released
            || d5.pending_release.is_some()
            || status.nonce != old.nonce
            || status.tuple != old.tuple
            || status.job != old.job
            || status.publication != old.publication
            || status.client_transaction != old.client_transaction
            || d5.jobs.jobs.loaded_job(status.job).is_ok()
        {
            return Err(InitError::WrongManifestProfile);
        }
        d5.pending_release = Some(status);
        flush_release(d5, context, system)?;
        return Ok(());
    }
    let driver = d5.driver.ok_or(InitError::WrongActivationOrder)?;
    if status.tuple.role != driver.device_role_id
        || status.tuple.bundle != driver.bundle_generation
        || status.tuple.attempt != driver.driver_attempt_generation
        || status.tuple.endpoint != driver.driver_control_endpoint_id
        || status.tuple.endpoint_generation != driver.driver_control_endpoint_generation
        || status.publication != context.publication
    {
        return Err(InitError::WrongManifestProfile);
    }
    validate_status_job(&d5.jobs.jobs, status, d5.last_ready)?;
    let old_clean = match d5.gate.record_count() {
        8 => {
            d5.released
                && context.last_reaped_driver.is_some_and(|r| {
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
    if matches!(status.leg, 2 | 4) {
        hold_for_drain(d5, system, devmgr, driver, status, batch, now)?;
        return Ok(());
    }
    publish_batch(system, devmgr, driver, &batch)
}

fn validate_status_job(
    jobs: &crate::wyr1b::JobController,
    status: Status,
    last_ready: Option<Status>,
) -> Result<(), InitError> {
    if status.kind == READY {
        let loaded = jobs.loaded_job(status.job).map_err(InitError::Wyr1BModel)?;
        if loaded.loaded.process.0 != 0
            && jobs
                .terminal_result(status.job)
                .map_err(InitError::Wyr1BModel)?
                .is_none()
        {
            return Ok(());
        }
    } else if status.kind == OBSERVED
        && last_ready.is_some_and(|ready| {
            ready.kind == READY
                && ready.job == status.job
                && ready.tuple == status.tuple
                && ready.nonce == status.nonce
                && ready.publication == status.publication
                && ready.client_transaction == status.client_transaction
        })
    {
        // The accepted READY already joined this exact JobV2 to its streams.
        // A queued byte observation remains valid after that job exits/reaps;
        // Gate::accept still checks sequence, leg, tuple and response hash.
        return Ok(());
    }
    Err(InitError::WrongManifestProfile)
}

pub(super) fn observe_driver_retired(
    resident: &mut ResidentSystemInit,
    request: DriverLaunchRequest,
) -> Result<(), InitError> {
    let d5 = resident
        .wyr1c
        .as_mut()
        .and_then(|s| s.d5.as_mut())
        .ok_or(InitError::WrongActivationOrder)?;
    let old = d5.first_driver.ok_or(InitError::WrongActivationOrder)?;
    if !same_driver_request(old, request) {
        return Err(InitError::WrongManifestProfile);
    }
    d5.retirement
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?
        .observe_retired(old)
        .map_err(|_| InitError::WrongManifestProfile)
}

pub(super) fn claim_publication_rebind(
    resident: &mut ResidentSystemInit,
    now: u64,
) -> Result<bool, InitError> {
    let d5 = resident
        .wyr1c
        .as_mut()
        .and_then(|s| s.d5.as_mut())
        .ok_or(InitError::WrongActivationOrder)?;
    match d5.retirement.as_mut() {
        Some(join) => join.claim_rebind(now).map_err(|_| InitError::Supervision),
        None => Ok(false),
    }
}

fn same_driver_request(driver: D5DriverIdentity, request: DriverLaunchRequest) -> bool {
    request.role_id.0 == driver.device_role_id
        && request.attempt_generation.0 == driver.driver_attempt_generation
        && request.endpoint.id.0 == driver.driver_control_endpoint_id
        && request.endpoint.generation.0 == driver.driver_control_endpoint_generation
        && request.transaction_id == driver.launch_transaction_id
}

#[allow(clippy::too_many_arguments)]
fn hold_for_drain<S: InitPlatform>(
    d5: &mut State,
    system: &mut S,
    devmgr: ActiveNativeRole,
    driver: D5DriverIdentity,
    status: Status,
    batch: Batch,
    now: u64,
) -> Result<(), InitError> {
    if d5.pending_fence.is_some() {
        return Err(InitError::WrongManifestProfile);
    }
    let deadline = now
        .checked_add(WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns)
        .ok_or(InitError::Accounting)?;
    d5.pending_fence =
        Some(DrainFence::new(driver, status, batch).map_err(|_| InitError::WrongManifestProfile)?);
    d5.fence_deadline = deadline;
    send_pending_drain(d5, system, devmgr)
}

fn send_pending_drain<S: InitPlatform>(
    d5: &mut State,
    system: &mut S,
    devmgr: ActiveNativeRole,
) -> Result<(), InitError> {
    let fence = d5
        .pending_fence
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?;
    send_devmgr(
        system,
        devmgr,
        fence
            .request()
            .map_err(|_| InitError::WrongManifestProfile)?,
    )?;
    fence
        .mark_requested()
        .map_err(|_| InitError::WrongManifestProfile)
}

pub(super) fn tx_drained<S: InitPlatform>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    identity: D5DrainIdentity,
) -> Result<(), InitError> {
    let state = resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?;
    let devmgr = state.devmgr.ok_or(InitError::WrongActivationOrder)?;
    let d5 = state.d5.as_mut().ok_or(InitError::WrongActivationOrder)?;
    let fence = take_completed_fence(d5, identity, system.now().map_err(InitError::Native)?)?;
    let batch = fence
        .completed(identity)
        .map_err(|_| InitError::WrongManifestProfile)?;
    let retirement = if batch.retire_driver {
        if d5.retirement.is_some() {
            return Err(InitError::WrongManifestProfile);
        }
        Some(
            RetirementJoin::new(
                identity.driver,
                system.now().map_err(InitError::Native)?,
                WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns,
            )
            .map_err(|_| InitError::Accounting)?,
        )
    } else {
        None
    };
    publish_batch(system, devmgr, identity.driver, batch)?;
    if retirement.is_some() {
        d5.retirement = retirement;
    }
    Ok(())
}

fn take_completed_fence(
    d5: &mut State,
    identity: D5DrainIdentity,
    now: u64,
) -> Result<DrainFence, InitError> {
    if d5.driver != Some(identity.driver) || now >= d5.fence_deadline {
        return Err(InitError::WrongManifestProfile);
    }
    d5.pending_fence
        .as_ref()
        .ok_or(InitError::WrongManifestProfile)?
        .completed(identity)
        .map_err(|_| InitError::WrongManifestProfile)?;
    // Consume once before externally publishing. A submission/send failure is
    // fatal; another completion cannot replay an already submitted record.
    d5.pending_fence
        .take()
        .ok_or(InitError::WrongManifestProfile)
}

fn publish_batch<S: InitPlatform>(
    system: &mut S,
    devmgr: ActiveNativeRole,
    driver: D5DriverIdentity,
    batch: &Batch,
) -> Result<(), InitError> {
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

fn flush_release<S: InitPlatform>(
    d5: &mut State,
    context: PollContext,
    system: &mut S,
) -> Result<(), InitError> {
    let Some(status) = d5.pending_release else {
        return Ok(());
    };
    let old = d5.first_driver.ok_or(InitError::WrongActivationOrder)?;
    let Some(reaped) = context.last_reaped_driver else {
        return Ok(());
    };
    if !same_driver_request(old, reaped) {
        return Err(InitError::WrongManifestProfile);
    }
    send_devmgr(
        system,
        context.devmgr.ok_or(InitError::WrongActivationOrder)?,
        D5ControllerMessage::ClientReleased(D5StreamIdentity {
            driver: old,
            publication_generation: status.publication,
            client_transaction_id: status.client_transaction,
            attach_transaction_id: status.tuple.transaction,
            stream_generation: status.tuple.stream,
        }),
    )?;
    d5.retirement
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?
        .release_sent(old)
        .map_err(|_| InitError::WrongManifestProfile)?;
    d5.pending_release = None;
    d5.released = true;
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn queued_observation_uses_exact_accepted_ready_after_job_reap() {
        use wyrmroot_consoled::selector32::Tuple;
        let ready = Status {
            kind: READY,
            sequence: 4,
            nonce: 42,
            tuple: Tuple {
                role: 1,
                bundle: 2,
                attempt: 3,
                endpoint: 4,
                endpoint_generation: 1,
                transaction: 6,
                stream: 7,
                console: 8,
                child: 9,
            },
            job: 10,
            rx: 0,
            tx: 0,
            leg: 0,
            value: 0,
            publication: 11,
            client_transaction: 12,
        };
        // A completed JobV2 has been removed by the cleanup dispatcher. Its
        // previously validated READY remains the exact authority join.
        let jobs = crate::wyr1b::JobController::new();
        assert_eq!(jobs.live_jobs(), 0);
        let observed = Status {
            kind: OBSERVED,
            sequence: 5,
            leg: 3,
            ..ready
        };
        assert!(validate_status_job(&jobs, observed, Some(ready)).is_ok());
        assert!(validate_status_job(&jobs, ready, Some(ready)).is_err());
        assert!(validate_status_job(&jobs, observed, None).is_err());
        for stale in [
            Status {
                job: 13,
                ..observed
            },
            Status {
                publication: 13,
                ..observed
            },
            Status {
                client_transaction: 13,
                ..observed
            },
            Status {
                nonce: 43,
                ..observed
            },
            Status {
                tuple: Tuple {
                    child: 10,
                    ..observed.tuple
                },
                ..observed
            },
        ] {
            assert!(validate_status_job(&jobs, stale, Some(ready)).is_err());
        }
    }
    use wyrmroot_consoled::selector32::Tuple;
    use wyrmroot_device_proto::coordinator::{
        AttemptGeneration, EndpointGeneration, EndpointId, LaunchSessionGeneration,
    };

    #[derive(Default)]
    struct Sender {
        sent: usize,
        fail: bool,
        last: Option<D5ControllerMessage>,
    }
    impl InitPlatform for Sender {
        fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
            assert_eq!(channel, DwHandle(30));
            if self.fail {
                return Err(NativeError::Status(DW_STATUS_TIMED_OUT));
            }
            self.last = Some(d5_controller::parse(bytes).unwrap());
            self.sent += 1;
            Ok(())
        }
        fn query_capability_info(
            &mut self,
            _: DwHandle,
        ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
            unreachable!()
        }
        fn receive_channel(
            &mut self,
            _: DwHandle,
            _: &mut [u8],
            _: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, NativeError> {
            unreachable!()
        }
        fn query_memory_object_size(&mut self, _: DwHandle) -> Result<u64, NativeError> {
            unreachable!()
        }
        fn with_bootfs_bytes<R>(
            &mut self,
            _: DwHandle,
            _: DwHandle,
            _: MappingPlan,
            _: impl for<'a> FnOnce(&mut Self, &'a [u8]) -> R,
        ) -> Result<R, NativeError> {
            unreachable!()
        }
        fn close_handle(&mut self, _: DwHandle) -> Result<(), NativeError> {
            unreachable!()
        }
        fn create_attempt_task_group(&mut self, _: DwHandle) -> Result<DwHandle, NativeError> {
            unreachable!()
        }
        fn terminate_task_group(&mut self, _: DwHandle) -> Result<(), NativeError> {
            unreachable!()
        }
        fn now(&mut self) -> Result<u64, NativeError> {
            unreachable!()
        }
        fn wait_until(&mut self, _: u64) -> Result<(), NativeError> {
            unreachable!()
        }
    }

    #[test]
    fn release_and_drain_wait_for_exact_facts_and_commit_only_after_send() {
        let driver = D5DriverIdentity {
            device_role_id: COM2_ROLE_ID.0,
            bundle_generation: 2,
            driver_attempt_generation: 3,
            driver_control_endpoint_id: 4,
            driver_control_endpoint_generation: 1,
            launch_transaction_id: 6,
        };
        let status = Status {
            kind: RELEASED,
            sequence: 0,
            nonce: 42,
            tuple: Tuple {
                role: driver.device_role_id,
                bundle: 2,
                attempt: 3,
                endpoint: 4,
                endpoint_generation: 1,
                transaction: 7,
                stream: 8,
                console: 9,
                child: 10,
            },
            job: 11,
            rx: 0,
            tx: 0,
            leg: 0,
            value: 0,
            publication: 12,
            client_transaction: 13,
        };
        let mut state = State {
            gate: Gate::new(42).unwrap(),
            jobs: JobDispatcher::new(),
            console: None,
            awaiting_ready: false,
            ready_deadline: 0,
            driver: Some(driver),
            first_driver: Some(driver),
            last_ready: Some(status),
            pending_release: Some(status),
            pending_fence: None,
            fence_deadline: 0,
            released: false,
            retirement: Some(RetirementJoin::new(driver, 0, 1_000_000).unwrap()),
        };
        let mut context = PollContext {
            authority: LoadAuthority {
                parent_root: DwHandle(1),
                bootfs: DwHandle(2),
                task_group: DwHandle(3),
            },
            devmgr: Some(ActiveNativeRole {
                role: RoleId::Devmgr,
                generation: 1,
                transaction_id: 1,
                loaded: LoadedProcess {
                    process: DwHandle(20),
                    launch_channel: DwHandle(30),
                },
                task_group: DwHandle(40),
            }),
            publication: 12,
            last_reaped_driver: None,
        };
        let mut sender = Sender::default();
        flush_release(&mut state, context, &mut sender).unwrap();
        assert_eq!(sender.sent, 0);
        assert_eq!(state.pending_release, Some(status));
        let exact = DriverLaunchRequest {
            supervisor_generation: SupervisorGeneration(1),
            role_id: COM2_ROLE_ID,
            attempt_generation: AttemptGeneration(3),
            launch_session: LaunchSessionGeneration(1),
            endpoint: wyrmroot_device_proto::ControlEndpoint {
                id: EndpointId(4),
                generation: EndpointGeneration(1),
            },
            transaction_id: 6,
            driver_path: wyrmroot_device_proto::DEVICE_DRIVER_PATH,
            actor_identity: ContentIdentity([1; 32]),
            child_is_channel: true,
            child_rights: wyrmroot_device_proto::DirectControlRights::ExactReduced,
        };
        for stale in [
            DriverLaunchRequest {
                transaction_id: 7,
                ..exact
            },
            DriverLaunchRequest {
                attempt_generation: AttemptGeneration(2),
                ..exact
            },
            DriverLaunchRequest {
                endpoint: wyrmroot_device_proto::ControlEndpoint {
                    id: EndpointId(5),
                    ..exact.endpoint
                },
                ..exact
            },
            DriverLaunchRequest {
                endpoint: wyrmroot_device_proto::ControlEndpoint {
                    generation: EndpointGeneration(2),
                    ..exact.endpoint
                },
                ..exact
            },
        ] {
            context.last_reaped_driver = Some(stale);
            assert!(flush_release(&mut state, context, &mut sender).is_err());
            assert_eq!(state.pending_release, Some(status));
            assert!(!state.released);
            assert_eq!(sender.sent, 0);
        }
        context.last_reaped_driver = Some(exact);
        sender.fail = true;
        assert!(flush_release(&mut state, context, &mut sender).is_err());
        assert_eq!(state.pending_release, Some(status));
        assert!(!state.released);
        assert!(!state.retirement.as_mut().unwrap().claim_rebind(1).unwrap());
        sender.fail = false;
        flush_release(&mut state, context, &mut sender).unwrap();
        assert!(state.released);
        assert_eq!(state.pending_release, None);
        assert_eq!(
            sender.last,
            Some(D5ControllerMessage::ClientReleased(D5StreamIdentity {
                driver,
                publication_generation: 12,
                client_transaction_id: 13,
                attach_transaction_id: 7,
                stream_generation: 8,
            }))
        );
        flush_release(&mut state, context, &mut sender).unwrap();
        assert_eq!(sender.sent, 1);
        assert!(!state.retirement.as_mut().unwrap().claim_rebind(2).unwrap());
        state
            .retirement
            .as_mut()
            .unwrap()
            .observe_retired(driver)
            .unwrap();
        assert!(state.retirement.as_mut().unwrap().claim_rebind(3).unwrap());
        assert!(!state.retirement.as_mut().unwrap().claim_rebind(4).unwrap());

        let ready = Status {
            kind: READY,
            sequence: 1,
            ..status
        };
        state.gate.accept(ready, false).unwrap();
        let mut batch = None;
        let mut final_status = ready;
        for (sequence, leg) in [(2, 1), (3, 2)] {
            let (bytes, size) = wyrmroot_consoled::selector32::response(42, leg, status.tuple);
            final_status = Status {
                kind: wyrmroot_consoled::selector32::OBSERVED,
                sequence,
                leg,
                rx: size as u64,
                tx: size as u64,
                value: wyrmroot_consoled::selector32::fnv(&bytes[..size]),
                ..status
            };
            batch = Some(state.gate.accept(final_status, false).unwrap());
        }
        let batch = batch.unwrap();
        let identity = D5DrainIdentity {
            driver,
            attach_transaction_id: status.tuple.transaction,
            stream_generation: status.tuple.stream,
            target_tx_bytes: 45,
            leg: 2,
        };
        let devmgr = context.devmgr.unwrap();
        let mut sender = Sender {
            fail: true,
            ..Sender::default()
        };
        assert!(
            hold_for_drain(
                &mut state,
                &mut sender,
                devmgr,
                driver,
                final_status,
                batch,
                1
            )
            .is_err()
        );
        assert_eq!(sender.sent, 0);
        assert!(state.pending_fence.is_some());
        assert!(take_completed_fence(&mut state, identity, 2).is_err());
        assert!(
            hold_for_drain(
                &mut state,
                &mut sender,
                devmgr,
                driver,
                final_status,
                batch,
                2
            )
            .is_err()
        );
        sender.fail = false;
        send_pending_drain(&mut state, &mut sender, devmgr).unwrap();
        assert_eq!(
            sender.last,
            Some(D5ControllerMessage::RequestDrain(identity))
        );
        assert_eq!(sender.sent, 1);
        assert!(send_pending_drain(&mut state, &mut sender, devmgr).is_err());
        assert_eq!(sender.sent, 1);
        assert!(
            take_completed_fence(
                &mut state,
                D5DrainIdentity {
                    attach_transaction_id: identity.attach_transaction_id + 1,
                    ..identity
                },
                2
            )
            .is_err()
        );
        let expired = state.fence_deadline;
        assert!(take_completed_fence(&mut state, identity, expired).is_err());
        assert!(state.pending_fence.is_some());
        let completed = take_completed_fence(&mut state, identity, 2).unwrap();
        assert_eq!(completed.completed(identity).unwrap(), &batch);
        assert!(state.pending_fence.is_none());
        assert!(take_completed_fence(&mut state, identity, 2).is_err());
        // Obtaining a completed batch is the only path that can expose its
        // retirement flag; no RequestRetire was sent while the fence waited.
        assert!(completed.completed(identity).unwrap().retire_driver);
        assert_eq!(sender.sent, 1);
    }
}
