//! The resident tick: registry and devmgr recovery, rebinding, shutdown.

use crate::jobs::{EndpointKind, RegistryTopology};
#[cfg(test)]
use crate::registry_native_attempt_for_fixture;
use crate::*;
use crate::{
    create_controller_channel_pair, launch_registry_until_ready_before,
    poison_registry_generation_before, restart_topology_or_poison_before,
    retire_registry_for_recovery_before,
};
use deepwyrm_syscall::{DW_HANDLE_TRANSFER_MOVE, DwHandleTransferV1};
use wyrmroot_device_proto::coordinator::{
    RegistryEndpoint, RegistryEndpointGeneration, RegistryEndpointId, RegistryGeneration,
    SupervisorGeneration,
};
use wyrmroot_device_proto::driver_launch::parse_driver_retired;
use wyrmroot_device_proto::{
    DriverLaunchRequest,
    controller::{ControllerMessage, StatusCode},
};

pub(crate) fn control_tick<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    now_ns: u64,
) -> Result<SystemMode, InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    if now_ns < resident.last_tick_ns {
        resident.controller.fatal();
        resident.result = RecoveryResult::Fatal;
        return Err(InitError::WrongActivationOrder);
    }
    resident.last_tick_ns = now_ns;
    crate::ensure_recovery_live(resident, now_ns)?;
    let state = resident
        .product
        .as_ref()
        .ok_or(InitError::AbsentState(0x3c))?;
    let Some(devmgr) = state.devmgr else {
        resident.result = RecoveryResult::Degraded;
        // F3A.7k. DEGRADED has no devmgr, and this used to return here -- so
        // once the WYR0-I budget exhausted, init stopped supervising the
        // console and shell it had just kept alive: no job dispatch, no
        // console exit, no session end and no terminal evidence. The console
        // stack still needs all of that; only the devmgr-driven half of the
        // tick has nothing to watch.
        return console_step(resident, system, loader, waits, now_ns, false);
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
    let observed = system.wait_many(&items[..item_count], DwDeadline(now_ns));
    match observed {
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {}
        Err(error) => return Err(InitError::Native(error)),
        Ok(result) => {
            let event = classify_resident_poll(result, registry_present, driver_present)?;
            let size = system
                .query_memory_object_size(resident.authority.bootfs)
                .map_err(InitError::Native)?;
            let plan = MappingPlan::for_bootfs(size).map_err(InitError::Mapping)?;
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
                                .product
                                .as_ref()
                                .ok_or(InitError::AbsentState(0x3d))?;
                            let devmgr = state.devmgr.ok_or(InitError::AbsentState(0x3e))?;
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
                                            resident,
                                            system,
                                            loader,
                                            waits,
                                            bootfs,
                                            true,
                                            false,
                                            abandoned::reason(
                                                abandoned::trigger::DEVMGR_WAITING,
                                                abandoned::phase::NONE,
                                            ),
                                        )
                                    } else {
                                        resident
                                            .product
                                            .as_mut()
                                            .ok_or(InitError::AbsentState(0x43))?
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
                                        start_console_or_recover_registry(
                                            resident, system, loader, waits, bootfs,
                                        )?;
                                        Ok(())
                                    }
                                }
                                Ok(DevmgrControlInput::DriverRetired { bytes }) => {
                                    let retired = (|| {
                                        let state = resident
                                            .product
                                            .as_ref()
                                            .ok_or(InitError::AbsentState(0x44))?;
                                        let request = state
                                            .last_reaped_driver
                                            .ok_or(InitError::AbsentState(0x45))?;
                                        parse_driver_retired(&bytes, request)
                                            .map_err(|_| InitError::WrongManifestProfile)?;
                                        {
                                            let rebound = rebind_publication(
                                                resident,
                                                system,
                                                waits,
                                                PublicationRebindContext::DriverRetirement,
                                            );
                                            attribute_failure(
                                                RecoveryOperation::RebindPublication,
                                                rebound,
                                            )
                                        }
                                    })();
                                    attribute_failure(RecoveryOperation::DriverRetired, retired)
                                }
                                Err(error) => recover_devmgr_after_error(
                                    resident, system, loader, waits, bootfs, error,
                                ),
                            }
                        }
                        ResidentPollEvent::RegistryControlLost => recover_registry(
                            resident,
                            system,
                            loader,
                            waits,
                            bootfs,
                            false,
                            false,
                            abandoned::reason(
                                abandoned::trigger::CONTROL_LOST,
                                abandoned::phase::NONE,
                            ),
                        ),
                        ResidentPollEvent::RegistryExited => recover_registry(
                            resident,
                            system,
                            loader,
                            waits,
                            bootfs,
                            false,
                            false,
                            abandoned::reason(abandoned::trigger::EXITED, abandoned::phase::NONE),
                        ),
                        ResidentPollEvent::DriverExited => {
                            let dependent_retirement =
                                crate::retire_dependents(resident, system, waits, false);
                            dependent_retirement?;
                            let _request = reap_driver(resident, system, waits, false);
                            let _request =
                                attribute_failure(RecoveryOperation::ReapDriver, _request)?;
                            {
                                crate::ensure_recovery_live(
                                    resident,
                                    system.now().map_err(InitError::Native)?,
                                )?;
                                let acknowledged = (|| {
                                    let state = resident
                                        .product
                                        .as_ref()
                                        .ok_or(InitError::AbsentState(0x46))?;
                                    let devmgr =
                                        state.devmgr.ok_or(InitError::AbsentState(0x47))?;
                                    acknowledge_driver_reaped(system, devmgr, _request)
                                })();
                                let acknowledged = attribute_failure(
                                    RecoveryOperation::AcknowledgeReaped,
                                    acknowledged,
                                );
                                acknowledged?;
                                crate::ensure_recovery_live(
                                    resident,
                                    system.now().map_err(InitError::Native)?,
                                )?;
                                Ok(())
                            }
                        }
                    },
                )
                .map_err(InitError::Native)??;
        }
    }
    console_step(resident, system, loader, waits, now_ns, true)
}

/// The console/shell half of the resident tick.
///
/// Factored out in F3A.7k so DEGRADED, which has no devmgr to wait on, still
/// runs it. With `devmgr_present` false only the outcomes that need no
/// devmgr are served: `Stable` and a finished session. Anything else would
/// rebuild devmgr, the registry or a console out of a publication that died
/// with devmgr, and is refused at its own site rather than attempted on half
/// a topology.
pub(crate) fn console_step<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    now_ns: u64,
    devmgr_present: bool,
) -> Result<SystemMode, InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let outcome = crate::poll(resident, system, loader, waits, now_ns)?;
    // F3A.7g. Handled before the recovery dispatch below, and outside the
    // bootfs mapping it opens: every other non-`Stable` outcome rebuilds
    // something out of the archive, and this one builds nothing.
    if outcome == crate::PollOutcome::SessionComplete {
        retire_for_session_shutdown(resident, system, waits)?;
        resident.observe_session_complete();
        return Ok(resident.controller.mode());
    }
    if outcome != crate::PollOutcome::Stable {
        if !devmgr_present {
            return Err(InitError::AbsentState(0x98));
        }
        if matches!(
            outcome,
            crate::PollOutcome::RecoverDevmgr | crate::PollOutcome::RecoverRegistry(_)
        ) && crate::recovery_deadline(resident)?.is_some()
        {
            return attribute_failure(
                RecoveryOperation::RecoveryFallback,
                Err(InitError::Supervision),
            );
        }
        let size = system
            .query_memory_object_size(resident.authority.bootfs)
            .map_err(InitError::Native)?;
        let plan = MappingPlan::for_bootfs(size).map_err(InitError::Mapping)?;
        return system
            .with_bootfs_bytes(
                resident.authority.parent_root,
                resident.authority.bootfs,
                plan,
                |system, bootfs| {
                    match outcome {
                        // Both are unreachable here: `Stable` does not
                        // enter this block and `SessionComplete` returned
                        // above. Neither is collapsed into the other, so a
                        // future outcome cannot inherit a recovery arm by
                        // accident.
                        crate::PollOutcome::Stable | crate::PollOutcome::SessionComplete => Ok(()),
                        crate::PollOutcome::LaunchConsole => {
                            let launched = crate::launch_after_publication_observed(
                                resident, system, loader, waits, bootfs,
                            );
                            attribute_failure(RecoveryOperation::StartConsole, launched)
                        }
                        crate::PollOutcome::RecoverDevmgr => {
                            recover_devmgr(resident, system, loader, waits, bootfs)
                        }
                        crate::PollOutcome::RecoverRegistry(phase) => recover_registry(
                            resident,
                            system,
                            loader,
                            waits,
                            bootfs,
                            false,
                            false,
                            abandoned::reason(abandoned::trigger::CONSOLE_POLL, phase),
                        ),
                    }?;
                    Ok(resident.controller.mode())
                },
            )
            .map_err(InitError::Native)?;
    }
    Ok(resident.controller.mode())
}

/// Retires every role this supervisor still owns, because the session ended.
///
/// F3A.7g. The first run of the supervisor half reached row 13, did not
/// relaunch anything, and then sat there: the domain never powered off and
/// the kernel emitted no completion record, because permanent init leaving
/// its loop is not the same thing as the system being finished. registryd,
/// devmgr and uart16550d were still running, and the kernel's terminal path
/// is reached when nothing remains, not when the supervisor stops looking.
///
/// So this is a shutdown and not a recovery, and the difference matters in
/// two places. It asks the controller for nothing -- no `terminal`, no
/// `fail`, no attempt accounting -- because none of these roles failed and a
/// supervision verdict about a role that is being switched off is a lie.
/// And it does not stop at the first failure: a role that will not die is a
/// reason to report, not a reason to leave the rest running.
///
/// Reverse dependency order, which is the order they were brought up in
/// reversed: the driver answers to devmgr, devmgr answers to the registry,
/// and the registry answers to nobody. A role outliving something it depends
/// on is the state every recovery path here exists to avoid, and a shutdown
/// has no more right to create it than a restart does.
pub(crate) fn retire_for_session_shutdown<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
) -> Result<(), InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    /// One bit per independent step, reported together because the shutdown
    /// runs them all. F3A.7i; see `InitError::SessionShutdown`.
    const JOBS: u8 = 1 << 0;
    const DRIVER: u8 = 1 << 1;
    const DEVMGR: u8 = 1 << 2;
    const REGISTRY: u8 = 1 << 3;
    const EARLY_ROLES: u8 = 1 << 4;

    let mut failed = 0_u8;
    if crate::drain_jobs_for_shutdown(resident, system, waits).is_err() {
        failed |= JOBS;
    }
    if let Some(state) = resident.product.as_mut() {
        if let Some(driver) = state.driver.take()
            && retire_role_for_shutdown(system, waits, driver.loaded, driver.task_group, None)
                .is_err()
        {
            failed |= DRIVER;
        }
        // `active[1]` and `active[0]` are copies of devmgr's and the
        // registry's handles, not separate roles: every path that takes one
        // clears the other with it. F3A.7j found this teardown retiring both
        // twice -- here and again through the table below, on handles already
        // closed -- which is the `EARLY_ROLES` failure run 6 reported.
        if let Some(devmgr) = state.devmgr.take() {
            resident.active[1] = None;
            if retire_role_for_shutdown(system, waits, devmgr.loaded, devmgr.task_group, None)
                .is_err()
            {
                failed |= DEVMGR;
            }
        }
        if let Some(registry) = state.registry.take() {
            resident.active[0] = None;
            if retire_role_for_shutdown(
                system,
                waits,
                registry.active.loaded,
                registry.active.task_group,
                Some(registry.control_channel),
            )
            .is_err()
            {
                failed |= REGISTRY;
            }
        }
        state.binding = None;
    }
    // Anything still in the early-role table, which after the block above is
    // only a role the resident state never held.
    for index in 0..resident.active.len() {
        let Some(active) = resident.active[index].take() else {
            continue;
        };
        if retire_role_for_shutdown(system, waits, active.loaded, active.task_group, None).is_err()
        {
            failed |= EARLY_ROLES;
        }
    }
    if failed == 0 {
        Ok(())
    } else {
        Err(InitError::SessionShutdown(failed))
    }
}

/// One role, switched off. The channel is closed first so the role observes a
/// peer close rather than only a termination, which is the ordinary way it
/// learns its supervisor is gone.
pub(crate) fn retire_role_for_shutdown<S, W>(
    system: &mut S,
    waits: &mut W,
    loaded: crate::LoadedProcess,
    task_group: DwHandle,
    control_channel: Option<DwHandle>,
) -> Result<(), InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let channel_failed =
        control_channel.is_some_and(|channel| system.close_handle(channel).is_err());
    let cleanup = crate::cleanup_loaded_before(system, waits, loaded, task_group, true, None);
    if channel_failed {
        return Err(InitError::Cleanup);
    }
    cleanup
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn recover_registry<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootfs: &[u8],
    status_already_consumed: bool,
    _e8_quiesced: bool,
    reason: u8,
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
    if action_deadline.is_some() {
        crate::ensure_recovery_live(resident, system.now().map_err(InitError::Native)?)?;
    }
    // Four arms for one fact, and two of them threw the cause away: outside
    // the selector this was a bare `bool`, so a dependent retirement that
    // failed said so without saying why. One `Option<InitError>` now, under
    // the product gate that actually has dependents.
    let dependent_cleanup_error = attribute_failure(
        RecoveryOperation::RetireDependents,
        crate::retire_dependents(resident, system, waits, true),
    )
    .err();
    let registry = resident
        .product
        .as_mut()
        .ok_or(InitError::AbsentState(0x4e))?
        .registry
        .take()
        .ok_or(InitError::AbsentState(0x4f))?;
    resident.active[0] = None;
    resident
        .product
        .as_mut()
        .ok_or(InitError::AbsentState(0x50))?
        .binding = None;
    let exhausted = if action_deadline.is_some() && dependent_cleanup_error.is_none() {
        // The authenticated, exactly quiesced action admits a fresh finite
        // episode only after dependent retirement succeeds. Ordinary failures
        // keep the boot-anchored episode, even after a long healthy lifetime.
        retire_registry_for_recovery_before(
            system,
            waits,
            &mut resident.controller,
            registry,
            action_deadline,
        )
    } else {
        poison_registry_generation_before(
            system,
            waits,
            &mut resident.controller,
            registry,
            dependent_cleanup_error.is_some(),
            action_deadline,
        )
    };
    let exhausted = attribute_failure(RecoveryOperation::RetireRegistry, exhausted);
    if let Some(error) = dependent_cleanup_error {
        return if exhausted.is_err() {
            attribute_failure(RecoveryOperation::RetireRegistry, Err(InitError::Cleanup))
        } else {
            Err(error)
        };
    }
    let exhausted = exhausted?;
    let step = registry_recovery_step(exhausted, status_already_consumed);
    match step {
        RegistryRecoveryStep::Degraded => {
            resident.result = RecoveryResult::Degraded;
            if action_deadline.is_some() {
                return attribute_failure(
                    RecoveryOperation::RetireRegistry,
                    Err(InitError::Cleanup),
                );
            }
            // F3A.6f. `state.registry` and `state.binding` were emptied above
            // and nothing was installed, so a build whose `poll` reads that
            // slot cannot continue; see `InitError::RegistryAbandoned`.
            return attribute_failure(
                RecoveryOperation::RetireRegistry,
                Err(InitError::RegistryAbandoned(reason)),
            );
        }
        RegistryRecoveryStep::Restart | RegistryRecoveryStep::AwaitStatus => {}
    }
    if action_deadline.is_some() {
        crate::ensure_recovery_live(resident, system.now().map_err(InitError::Native)?)?;
    }
    let replacement = launch_registry_until_ready_before(
        system,
        loader,
        waits,
        &mut resident.controller,
        resident.authority,
        bootfs,
        action_deadline,
    );
    let replacement = attribute_failure(RecoveryOperation::LaunchRegistry, replacement)?;
    let Some(replacement) = replacement else {
        resident.result = RecoveryResult::Degraded;
        if action_deadline.is_some() {
            return attribute_failure(
                RecoveryOperation::LaunchRegistry,
                Err(InitError::Supervision),
            );
        }
        // F3A.6f, the second of the two exits. Same reasoning as the
        // `Degraded` step above: emptied, nothing installed, terminal where a
        // `poll` depends on it.
        return attribute_failure(
            RecoveryOperation::LaunchRegistry,
            Err(InitError::RegistryAbandoned(reason)),
        );
    };
    if action_deadline.is_some()
        && let Err(error) =
            crate::ensure_recovery_live(resident, system.now().map_err(InitError::Native)?)
    {
        let cleanup = poison_registry_generation_before(
            system,
            waits,
            &mut resident.controller,
            replacement,
            false,
            action_deadline,
        );
        return if cleanup.is_err() {
            let failed: Result<(), InitError> = Err(InitError::Cleanup);
            // Which leg failed is class C of the R7A inventory, so the tag
            // stays selector-gated while the deadline check above does not.
            attribute_failure(RecoveryOperation::LaunchRegistry, failed)
        } else {
            Err(error)
        };
    }
    {
        let reserved = crate::reserve_registry_replacement(resident, replacement.active.generation);
        let reserved = attribute_failure(RecoveryOperation::CommitRegistry, reserved);
        reserved?;
    }
    let replacement = restart_topology_or_poison_before(
        system,
        waits,
        &mut resident.controller,
        &mut resident
            .product
            .as_mut()
            .ok_or(InitError::AbsentState(0x51))?
            .topology,
        replacement,
        action_deadline,
    );
    let replacement = attribute_failure(RecoveryOperation::CommitRegistry, replacement);
    let replacement = replacement?;
    {
        let committed = crate::commit_registry_replacement(resident, replacement.active.generation);
        let committed = attribute_failure(RecoveryOperation::CommitRegistry, committed);
        committed?;
    }
    resident
        .product
        .as_mut()
        .ok_or(InitError::AbsentState(0x52))?
        .registry = Some(replacement);
    resident.active[0] = Some(replacement.active);
    if step == RegistryRecoveryStep::AwaitStatus {
        let state = resident
            .product
            .as_ref()
            .ok_or(InitError::AbsentState(0x53))?;
        let devmgr = state.devmgr.ok_or(InitError::AbsentState(0x54))?;
        let waiting = await_waiting_for_registry(
            system,
            waits,
            devmgr,
            devmgr.generation,
            state.last_controller_transaction,
            action_deadline,
        );
        let waiting = attribute_failure(RecoveryOperation::RebindPublication, waiting);
        if let Err(error) = waiting {
            return recover_devmgr_after_error(resident, system, loader, waits, bootfs, error);
        }
    }
    resident
        .product
        .as_mut()
        .ok_or(InitError::AbsentState(0x55))?
        .waiting_registry_observed = true;
    let rebound = rebind_publication(
        resident,
        system,
        waits,
        PublicationRebindContext::RegistryRecovery,
    );
    let rebound = attribute_failure(RecoveryOperation::RebindPublication, rebound);
    if let Err(error) = rebound {
        return recover_devmgr_after_error(resident, system, loader, waits, bootfs, error);
    }
    if resident
        .product
        .as_ref()
        .is_some_and(|state| state.driver.is_some())
    {
        let started = start_console_or_recover_registry(resident, system, loader, waits, bootfs);
        let started = attribute_failure(RecoveryOperation::StartConsole, started);
        started?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) const FIXTURE_DEVMGR_CONTROL: DwHandle = DwHandle(0xE8B5_0021);
#[cfg(test)]
pub(crate) const FIXTURE_DRIVER_PROCESS: DwHandle = DwHandle(0xE8B5_0030);

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn install_fixture_role(
    controller: &mut SystemInit,
    role: RoleId,
    generation: u64,
    transaction_id: u64,
    executable_identity: [u8; 32],
    startup_profile: StartupProfile,
    loaded: LoadedProcess,
    task_group: DwHandle,
    started_at: u64,
) -> Result<ActiveNativeRole, InitError> {
    let reservation = controller.reserve_attempt(role, generation, transaction_id)?;
    controller.install_attempt(AttemptResources {
        role,
        generation,
        transaction_id,
        executable_identity,
        startup_profile,
        task_group,
        process: loaded.process,
        launch_channel: loaded.launch_channel,
        mappings: 0,
        reservation,
    })?;
    controller.child_started(role, generation, transaction_id, started_at)?;
    controller.ready(role, generation, transaction_id, started_at + 1)?;
    Ok(ActiveNativeRole {
        role,
        generation,
        transaction_id,
        loaded,
        task_group,
    })
}

/// The resident a recovery fixture starts from: an operational controller with
/// a live registry, devmgr and driver, and one registry binding.
///
/// Reset card R7E. This was the opening half of the E8 orchestrator bridge,
/// and that made the E8 mega-fixture the only host test in the tree that
/// reached `recover_registry`, `recover_devmgr` or `recover_devmgr_after_error`
/// at all -- measured by probe, not assumed. The resident is ordinary; only
/// the `session` state its caller supplies decides whether an episode is open, so
/// the product path can be driven without a shell, a trigger or a barrier.
#[cfg(test)]
pub(crate) fn recovery_fixture_resident(
    registry_identity: [u8; 32],
    registry_generation: u64,
    session: ConsoleState,
    topology: RegistryTopology,
    driver_request: Option<DriverLaunchRequest>,
) -> Result<
    (
        ResidentSystemInit,
        ActiveNativeRole,
        Option<DriverNativeAttempt>,
    ),
    InitError,
> {
    const REGISTRY_TRANSACTION: u64 = 0xE8B5_0001;
    const LAST_CONTROLLER_TRANSACTION: u64 = 9;
    const NEXT_CONTROLLER_TRANSACTION: u64 = 10;
    let devmgr_identity = [0xD5; 32];
    let mut controller = SystemInit {
        mode: SystemMode::Bootstrap,
        roles: [
            RoleController::new(RoleId::Registryd, registry_identity)?,
            RoleController::new(RoleId::Devmgr, devmgr_identity)?,
        ],
        degraded_transitions: 0,
        activated: [false; EARLY_ROLE_COUNT],
        accounting: AttemptLedger::new(),
        registry_startup_profile: StartupProfile::BootstrapRegistry,
        devmgr_startup_profile: StartupProfile::DeviceCoordinator,
    };
    controller.become_operational()?;
    controller.begin_registry(1, registry_generation, REGISTRY_TRANSACTION)?;
    let registry_active = install_fixture_role(
        &mut controller,
        RoleId::Registryd,
        registry_generation,
        REGISTRY_TRANSACTION,
        registry_identity,
        StartupProfile::BootstrapRegistry,
        LoadedProcess {
            process: DwHandle(0xE8B5_0011),
            launch_channel: DwHandle(0xE8B5_0012),
        },
        DwHandle(0xE8B5_0013),
        2,
    )?;
    let devmgr_transaction = REGISTRY_TRANSACTION + 1;
    let devmgr = install_fixture_role(
        &mut controller,
        RoleId::Devmgr,
        registry_generation,
        devmgr_transaction,
        devmgr_identity,
        StartupProfile::DeviceCoordinator,
        LoadedProcess {
            process: DwHandle(0xE8B5_0020),
            launch_channel: FIXTURE_DEVMGR_CONTROL,
        },
        DwHandle(0xE8B5_0022),
        4,
    )?;
    let registry = registry_native_attempt_for_fixture(registry_active, DwHandle(0xE8B5_0010), 3);
    let driver = driver_request.map(|request| DriverNativeAttempt {
        loaded: LoadedProcess {
            process: FIXTURE_DRIVER_PROCESS,
            launch_channel: DwHandle(0xE8B5_0031),
        },
        task_group: DwHandle(0xE8B5_0032),
        request,
    });
    let initial_binding = wyrmroot_device_proto::RegistryBinding {
        generation: RegistryGeneration(registry_generation),
        endpoint: RegistryEndpoint {
            id: RegistryEndpointId(1),
            generation: RegistryEndpointGeneration(1),
        },
    };
    let resident = ResidentSystemInit {
        controller,
        authority: LoadAuthority {
            parent_root: DwHandle(0xE8B5_0040),
            bootfs: DwHandle(0xE8B5_0041),
            task_group: DwHandle(0xE8B5_0042),
        },
        result: RecoveryResult::Recovered,
        active: [Some(registry_active), Some(devmgr)],
        evidence_finalized: false,
        session_complete: false,
        last_tick_ns: 0,
        product: Some(ResidentState {
            session: Some(session),
            resource_domain: Some(ResourceDomainCustody::new(DwHandle(0xE8B5_0043))),
            registry: Some(registry),
            topology,
            devmgr: Some(devmgr),
            binding: Some(initial_binding),
            publication_service_generation: driver_request
                .map_or(1, |request| request.attempt_generation.0),
            waiting_registry_observed: false,
            publication_allocator: PublicationAllocator::new(),
            last_controller_transaction: LAST_CONTROLLER_TRANSACTION,
            next_controller_transaction: NEXT_CONTROLLER_TRANSACTION,
            driver,
            last_reaped_driver: None,
            last_driver_attempt: driver_request.map_or(0, |request| request.attempt_generation.0),
            last_driver_session: driver_request.map_or(0, |request| request.launch_session.0),
            last_driver_endpoint: driver_request.map_or(0, |request| request.endpoint.id.0),
            last_driver_transaction: driver_request.map_or(0, |request| request.transaction_id),
        }),
    };

    Ok((resident, devmgr, driver))
}

pub(crate) fn start_console_or_recover_registry<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootfs: &[u8],
) -> Result<(), InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let result = crate::start_after_driver_constructed(resident, system);
    match result {
        Ok(()) => Ok(()),
        Err(_) if crate::registry_recovery_required(resident) => recover_registry(
            resident,
            system,
            loader,
            waits,
            bootfs,
            false,
            false,
            abandoned::reason(
                abandoned::trigger::CONSOLE_START_FALLBACK,
                abandoned::phase::NONE,
            ),
        ),
        Err(error) => Err(error),
    }
}

pub(crate) fn recover_devmgr_after_error<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootfs: &[u8],
    error: InitError,
) -> Result<(), InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    // `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` 3.5: the parameter was taken and
    // then discarded outside the selector, which told every reader this
    // function carried a cause it did not. It is read in every build now.
    let episode_open = crate::recovery_deadline(resident)?.is_some();
    if episode_open {
        return Err(error);
    }
    recover_devmgr(resident, system, loader, waits, bootfs)
}

pub(crate) fn recover_devmgr<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootfs: &[u8],
) -> Result<(), InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    // `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` §5.3.1 item 4. A coordinator change
    // does not by itself invalidate the device topology beneath it, so the
    // console stack is retained *through* the recovery episode and torn down
    // only once a replacement generation is actually READY and about to build
    // a driver of its own -- see `retire_retained_device_topology`. An episode
    // that exhausts instead therefore reaches DEGRADED with the console and
    // the live shell generation still serving, which is what [B] §5.4 promises
    // and what §5.4's dependency-preservation rule requires.
    //
    // With no console product installed there is no consumer, the retention is
    // false, and everything below runs exactly as it always has.
    let retained_device_topology = crate::console_depends_on_driver(resident);
    if !retained_device_topology
        && crate::retire_dependents(resident, system, waits, false).is_err()
    {
        resident.result = RecoveryResult::Degraded;
        return Err(InitError::Cleanup);
    }
    if !retained_device_topology
        && resident
            .product
            .as_ref()
            .is_some_and(|state| state.driver.is_some())
        && reap_driver(resident, system, waits, true).is_err()
    {
        resident.result = RecoveryResult::Degraded;
        return Err(InitError::Cleanup);
    }
    let active = resident
        .product
        .as_mut()
        .ok_or(InitError::AbsentState(0x64))?
        .devmgr
        .take()
        .ok_or(InitError::AbsentState(0x65))?;
    resident.active[1] = None;
    {
        let state = resident
            .product
            .as_mut()
            .ok_or(InitError::AbsentState(0x66))?;
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

/// Tears down a device topology that `recover_devmgr` retained through the
/// episode, once a replacement coordinator generation is actually READY.
///
/// This is the second half of §5.3.1 item 4. Deferring the teardown to here,
/// rather than skipping it, keeps ordinary devmgr recovery's end state exactly
/// what it was -- fresh driver, fresh console, fresh foreground shell -- while
/// an episode that never produces a replacement generation leaves the console
/// stack untouched. It runs before the new generation is installed, so the
/// replacement's first driver-launch request cannot race a live old driver.
pub(crate) fn retire_retained_device_topology<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
) -> Result<(), InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    if !crate::console_depends_on_driver(resident) {
        return Ok(());
    }
    let retired = crate::retire_dependents(resident, system, waits, false)
        .and_then(|()| reap_driver(resident, system, waits, true).map(|_| ()));
    if retired.is_err() {
        resident.result = RecoveryResult::Degraded;
        return Err(InitError::Cleanup);
    }
    Ok(())
}

pub(crate) fn launch_devmgr_replacement<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootfs: &[u8],
) -> Result<(), InitError>
where
    S: ResidentPlatform,
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
            .ok_or(InitError::AbsentState(0x68))?
        {
            RestartState::Starting { transaction_id, .. } => transaction_id,
            _ => return Err(InitError::WrongActivationOrder),
        };
        let registry = resident.product.as_ref().and_then(|state| state.registry);
        let resource_domain = resident
            .product
            .as_ref()
            .and_then(|state| state.resource_domain);
        let Some(registry) = registry else {
            resident.result = RecoveryResult::Degraded;
            return Ok(());
        };
        let refused = false;
        let attempt = if refused {
            Err(InitError::Supervision)
        } else {
            let state = resident
                .product
                .as_mut()
                .ok_or(InitError::AbsentState(0x69))?;
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
                retire_retained_device_topology(resident, system, waits)?;
                let state = resident
                    .product
                    .as_mut()
                    .ok_or(InitError::AbsentState(0x6a))?;
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
                    .ok_or(InitError::AbsentState(0x6b))?
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationRebindContext {
    RegistryRecovery,
    DriverRetirement,
}

impl PublicationRebindContext {
    pub(crate) fn expected_status(
        self,
        resource_domain: Option<ResourceDomainCustody>,
        _driver: Option<DriverNativeAttempt>,
        _reaped: Option<DriverLaunchRequest>,
        _supervisor: SupervisorGeneration,
    ) -> Result<StatusCode, InitError> {
        match self {
            Self::RegistryRecovery if resource_domain.is_some() => {
                Ok(StatusCode::OperationalResourceOwned)
            }
            Self::RegistryRecovery => Ok(StatusCode::OperationalWaitingForDeviceBundle),
            Self::DriverRetirement => {
                let reaped = _reaped.ok_or(InitError::AbsentState(0x6c))?;
                if _driver.is_some() || reaped.supervisor_generation != _supervisor {
                    return Err(InitError::WrongActivationOrder);
                }
                Ok(StatusCode::OperationalWaitingForDeviceBundle)
            }
        }
    }
}

pub(crate) fn rebind_publication<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
    context: PublicationRebindContext,
) -> Result<(), InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    // The recovery episode lives on the wyr1e console/shell supervisor, so
    // a build without that product has no episode rather than no concept of
    // one. The gate is the product, not a selector.
    let deadline_cap = crate::recovery_deadline(resident)?;
    let state = resident
        .product
        .as_mut()
        .ok_or(InitError::AbsentState(0x6d))?;
    let registry = state.registry.ok_or(InitError::AbsentState(0x6e))?;
    let devmgr = state.devmgr.ok_or(InitError::AbsentState(0x6f))?;
    let expected_status = context.expected_status(
        state.resource_domain,
        state.driver,
        state.last_reaped_driver,
        SupervisorGeneration(devmgr.generation),
    )?;
    let rebound = perform_rebind(
        system,
        waits,
        &mut state.topology,
        &mut state.publication_allocator,
        registry.control_channel,
        devmgr,
        state.next_controller_transaction,
        expected_status,
        deadline_cap,
    );
    let (binding, publication_service_generation, transaction_id) = match rebound {
        Ok(rebound) => rebound,
        Err(error) => {
            return Err(error);
        }
    };
    state.binding = Some(binding);
    state.publication_service_generation = publication_service_generation;
    state.waiting_registry_observed = false;
    state.last_controller_transaction = transaction_id;
    state.next_controller_transaction =
        transaction_id.checked_add(1).ok_or(InitError::Accounting)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn perform_rebind<S, W>(
    system: &mut S,
    waits: &mut W,
    topology: &mut RegistryTopology,
    publication_allocator: &mut PublicationAllocator,
    registry_control: DwHandle,
    devmgr: ActiveNativeRole,
    transaction_id: u64,
    expected_status: StatusCode,
    deadline_cap: Option<u64>,
) -> Result<(wyrmroot_device_proto::RegistryBinding, u64, u64), InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    if let Some(deadline) = deadline_cap {
        let now = system.now().map_err(InitError::Native)?;
        if now >= deadline {
            return Err(InitError::Supervision);
        }
    }
    let grant = topology
        .issue(devmgr.generation, EndpointKind::Publication)
        .map_err(InitError::Jobs)?;
    let publication = publication_allocator.issue()?;
    let binding = wyrmroot_device_proto::RegistryBinding {
        generation: RegistryGeneration(grant.registry_generation),
        endpoint: RegistryEndpoint {
            id: RegistryEndpointId(grant.endpoint_id),
            generation: RegistryEndpointGeneration(grant.endpoint_generation),
        },
    };
    let (registry_endpoint, devmgr_endpoint) = create_controller_channel_pair(system)?;
    if let Some(deadline) = deadline_cap {
        let now = system.now().map_err(InitError::Native)?;
        if now >= deadline {
            let failed = system.close_handle(registry_endpoint).is_err()
                | system.close_handle(devmgr_endpoint).is_err();
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Supervision
            });
        }
    }
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
    if let Some(deadline) = deadline_cap {
        let now = system.now().map_err(InitError::Native)?;
        if now >= deadline {
            return Err(if system.close_handle(devmgr_endpoint).is_err() {
                InitError::Cleanup
            } else {
                InitError::Supervision
            });
        }
    }
    let request = ControllerMessage::RebindPublication {
        supervisor_generation: SupervisorGeneration(devmgr.generation),
        binding,
        transaction_id,
    };
    let bytes = match encode_publication_request(request, publication.service_generation) {
        Ok(bytes) => bytes,
        Err(()) => {
            return Err(if system.close_handle(devmgr_endpoint).is_err() {
                InitError::Cleanup
            } else {
                InitError::WrongManifestProfile
            });
        }
    };
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
    if deadline_cap.is_some_and(|deadline| system.now().map_or(true, |now| now >= deadline)) {
        return Err(InitError::Supervision);
    }
    expect_device_status(
        system,
        waits,
        devmgr,
        binding,
        transaction_id,
        expected_status,
        deadline_cap,
    )?;
    Ok((binding, publication.service_generation, transaction_id))
}

#[cfg(test)]
mod tests;
