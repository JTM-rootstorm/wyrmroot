//! Production WYR1-E consoled and wyrmsh resident ownership.

use super::*;
use crate::wyr1b_job::{JobDispatcher, LaunchSessionScope, SessionOwner};
use crate::wyr1b_native::{
    InstalledPeer, ShellControllerState, ShellLaunchContext, create_controller_channel_pair,
    install_client, poll_job_dispatcher_with_shell, retire_console_product,
};
use wyrmroot_loader::process::{ConsoledLoadRequest, load_consoled_process};

const CONSOLE_PATH: &str = "system/consoled";
const FIRST_CONSOLE_TRANSACTION: u64 = 0xE600_0001;

#[derive(Debug, Eq, PartialEq)]
pub(super) struct State {
    jobs: JobDispatcher,
    console: Option<InstalledPeer>,
    shell: ShellControllerState,
    awaiting_ready: bool,
    bootstrap_released: bool,
    ready_deadline: u64,
    console_transaction: u64,
    next_console_transaction: u64,
    console_launch_attempts: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PollOutcome {
    Stable,
    RelaunchConsole,
    RecoverRegistry,
}

impl State {
    pub(super) fn new(registry_generation: u64) -> Result<Self, InitError> {
        Ok(Self {
            jobs: JobDispatcher::new(),
            console: None,
            shell: ShellControllerState::new(registry_generation)?,
            awaiting_ready: false,
            bootstrap_released: false,
            ready_deadline: 0,
            console_transaction: 0,
            next_console_transaction: FIRST_CONSOLE_TRANSACTION,
            console_launch_attempts: 0,
        })
    }

    fn take_console_transaction(&mut self) -> Result<u64, InitError> {
        if self.console_launch_attempts >= WYR0_I_SUPERVISION_POLICY.max_attempts {
            return Err(InitError::Cleanup);
        }
        let transaction = self.next_console_transaction;
        self.next_console_transaction = transaction.checked_add(1).ok_or(InitError::Accounting)?;
        self.console_launch_attempts = self
            .console_launch_attempts
            .checked_add(1)
            .ok_or(InitError::Accounting)?;
        Ok(transaction)
    }

    fn commit_registry_replacement(&mut self, generation: u64) -> Result<(), InitError> {
        self.shell.commit_replacement_generation(generation)?;
        // A fresh registry generation is the only event that replenishes the
        // consoled launch budget. READY alone does not erase crash history.
        self.console_launch_attempts = 0;
        Ok(())
    }
}

pub(super) fn start_after_driver_constructed<S, L, W>(
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
    let authority = resident.authority;
    let state = resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?;
    let registry = state.registry.ok_or(InitError::WrongActivationOrder)?;
    let e6 = state.e6.as_mut().ok_or(InitError::WrongActivationOrder)?;
    if e6.console.is_some() {
        return Ok(());
    }
    launch_console(
        e6,
        system,
        loader,
        waits,
        authority,
        bootfs,
        registry.control_channel,
        &mut state.topology,
    )
}

pub(super) fn registry_recovery_required(resident: &ResidentSystemInit) -> bool {
    resident
        .wyr1c
        .as_ref()
        .and_then(|state| state.e6.as_ref())
        .is_some_and(|state| {
            matches!(
                state.shell.health(),
                crate::wyr1b_native::ShellRegistryHealth::Poisoned { .. }
            )
        })
}

#[allow(clippy::too_many_arguments)]
fn launch_console<S, L, W>(
    e6: &mut State,
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
    if e6.console.is_some() {
        return Err(InitError::WrongActivationOrder);
    }
    let image = Archive::new(bootfs)
        .map_err(InitError::Bootfs)?
        .lookup(CONSOLE_PATH.as_bytes())
        .map_err(map_lookup)?;
    if !image.is_executable() || image.data().is_empty() {
        return Err(InitError::NonExecutableRole);
    }
    let transaction = e6.take_console_transaction()?;
    let registry_grant = topology
        .issue(transaction, EndpointKind::RegistryClient)
        .map_err(InitError::Wyr1BModel)?;
    let launch_grant = topology
        .issue(transaction, EndpointKind::LaunchSession)
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
        transaction,
    ) {
        let failed = system.close_handle(registry_endpoint).is_err()
            | system.close_handle(child_registry).is_err()
            | system.close_handle(group).is_err();
        return Err(if failed { InitError::Cleanup } else { error });
    }
    let (launch_endpoint, child_launch) = match create_controller_channel_pair(system) {
        Ok(pair) => pair,
        Err(error) => {
            e6.shell.poison(topology.generation());
            let failed =
                system.close_handle(child_registry).is_err() | system.close_handle(group).is_err();
            return Err(if failed { InitError::Cleanup } else { error });
        }
    };
    if let Err(error) = e6.jobs.install_scoped_session(
        launch_grant,
        launch_endpoint,
        LaunchSessionScope::ConsoleLauncher,
    ) {
        e6.shell.poison(topology.generation());
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
            transaction_id: transaction,
        },
    ) {
        Ok(loaded) => loaded,
        Err(failure) => {
            e6.shell.poison(topology.generation());
            let mut failed = false;
            if !failure.registry_endpoint_consumed {
                failed |= system.close_handle(child_registry).is_err();
            }
            if !failure.launch_endpoint_consumed {
                failed |= system.close_handle(child_launch).is_err();
            }
            failed |= e6
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
    let ready_deadline = match system.now().map_err(InitError::Native).and_then(|now| {
        now.checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .ok_or(InitError::Accounting)
    }) {
        Ok(deadline) => deadline,
        Err(error) => {
            e6.shell.poison(topology.generation());
            let failed = cleanup_loaded(system, waits, loaded, group, true).is_err()
                | e6.jobs
                    .disconnect_session(launch_grant)
                    .map_or(true, |handle| system.close_handle(handle).is_err());
            return Err(if failed { InitError::Cleanup } else { error });
        }
    };
    if let Err(error) = e6.jobs.attach_session_owner(
        launch_grant,
        SessionOwner {
            process: loaded.process,
            launch_channel: loaded.launch_channel,
            task_group: group,
        },
    ) {
        e6.shell.poison(topology.generation());
        let failed = cleanup_loaded(system, waits, loaded, group, true).is_err()
            | e6.jobs
                .disconnect_session(launch_grant)
                .map_or(true, |handle| system.close_handle(handle).is_err());
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Wyr1BModel(error)
        });
    }
    e6.ready_deadline = ready_deadline;
    e6.console = Some(InstalledPeer {
        grant: launch_grant,
        loaded,
        task_group: group,
    });
    e6.console_transaction = transaction;
    e6.awaiting_ready = true;
    e6.bootstrap_released = false;
    Ok(())
}

pub(super) fn poll<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    now: u64,
) -> Result<PollOutcome, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let authority = resident.authority;
    let state = resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?;
    let registry = state.registry.ok_or(InitError::WrongActivationOrder)?;
    let e6 = state.e6.as_mut().ok_or(InitError::WrongActivationOrder)?;
    let mut shell = ShellLaunchContext {
        registry_control: registry.control_channel,
        topology: &mut state.topology,
        state: &mut e6.shell,
    };
    if let Err(error) = poll_job_dispatcher_with_shell(
        system,
        loader,
        waits,
        authority,
        &mut e6.jobs,
        now,
        &mut shell,
    ) {
        return if matches!(
            e6.shell.health(),
            crate::wyr1b_native::ShellRegistryHealth::Poisoned { .. }
        ) {
            Ok(PollOutcome::RecoverRegistry)
        } else {
            Err(error)
        };
    }
    if e6.awaiting_ready && now >= e6.ready_deadline {
        retire_current_console(e6, system, waits, state.topology.generation(), true)?;
        return Ok(PollOutcome::RecoverRegistry);
    }
    let Some(console) = e6.console else {
        return Ok(PollOutcome::Stable);
    };
    let mut items = [DwWaitItemV1::default(); 2];
    items[0] = DwWaitItemV1 {
        handle: console.loaded.process,
        signals: DW_SIGNAL_EXITED,
    };
    let used = if e6.bootstrap_released {
        1
    } else {
        items[1] = DwWaitItemV1 {
            handle: console.loaded.launch_channel,
            signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        };
        2
    };
    let observed = match system.wait_many(&items[..used], DwDeadline(now)) {
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {
            if e6.awaiting_ready && now >= e6.ready_deadline {
                retire_current_console(e6, system, waits, state.topology.generation(), true)?;
                return Ok(PollOutcome::RecoverRegistry);
            }
            return Ok(PollOutcome::Stable);
        }
        Err(error) => return Err(InitError::Native(error)),
        Ok(observed) => observed,
    };
    if observed.index == 0 && observed.observed.0 & DW_SIGNAL_EXITED.0 != 0 {
        let peer = e6.console.take().ok_or(InitError::WrongActivationOrder)?;
        e6.awaiting_ready = false;
        e6.bootstrap_released = false;
        e6.console_transaction = 0;
        retire_console_product(system, waits, &mut e6.jobs, peer, false)?;
        return Ok(PollOutcome::RelaunchConsole);
    }
    if observed.index != 1 {
        retire_current_console(e6, system, waits, state.topology.generation(), true)?;
        return Ok(PollOutcome::RecoverRegistry);
    }
    if observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 {
        if !e6.awaiting_ready {
            retire_current_console(e6, system, waits, state.topology.generation(), true)?;
            return Ok(PollOutcome::RecoverRegistry);
        }
        let mut bytes = [0u8; 64];
        let mut handles = [DwReceivedHandleInfoV1::default(); 1];
        let counts =
            match system.receive_channel(console.loaded.launch_channel, &mut bytes, &mut handles) {
                Ok(counts) => counts,
                Err(_) => {
                    retire_current_console(e6, system, waits, state.topology.generation(), true)?;
                    return Ok(PollOutcome::RecoverRegistry);
                }
            };
        if counts.handles != 0 {
            let received_cleanup = close_received_native(system, &handles, counts.handles);
            let console_cleanup =
                retire_current_console(e6, system, waits, state.topology.generation(), true);
            return if received_cleanup.is_err() || console_cleanup.is_err() {
                Err(InitError::Cleanup)
            } else {
                Ok(PollOutcome::RecoverRegistry)
            };
        }
        if wyrmroot_loader::launch::parse_ready_for_profile(
            LaunchProfile::Consoled,
            &bytes[..counts.bytes],
            e6.console_transaction,
        )
        .is_err()
        {
            retire_current_console(e6, system, waits, state.topology.generation(), true)?;
            return Ok(PollOutcome::RecoverRegistry);
        }
        let validated_at = match system.now() {
            Ok(validated_at) => validated_at,
            Err(error) => {
                let cleanup =
                    retire_current_console(e6, system, waits, state.topology.generation(), true);
                return Err(if cleanup.is_err() {
                    InitError::Cleanup
                } else {
                    InitError::Native(error)
                });
            }
        };
        if validated_at >= e6.ready_deadline {
            retire_current_console(e6, system, waits, state.topology.generation(), true)?;
            return Ok(PollOutcome::RecoverRegistry);
        }
        e6.awaiting_ready = false;
        return Ok(PollOutcome::Stable);
    }
    if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 && !e6.awaiting_ready {
        e6.bootstrap_released = true;
        return Ok(PollOutcome::Stable);
    }
    retire_current_console(e6, system, waits, state.topology.generation(), true)?;
    Ok(PollOutcome::RecoverRegistry)
}

fn retire_current_console<S, W>(
    e6: &mut State,
    system: &mut S,
    waits: &mut W,
    registry_generation: u64,
    poison_registry: bool,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    if poison_registry {
        e6.shell.poison(registry_generation);
    }
    let Some(peer) = e6.console.take() else {
        return Ok(());
    };
    e6.awaiting_ready = false;
    e6.bootstrap_released = false;
    e6.console_transaction = 0;
    retire_console_product(system, waits, &mut e6.jobs, peer, true)
}

pub(super) fn retire_dependents<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
    poison_registry: bool,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let state = resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?;
    let generation = state.topology.generation();
    let e6 = state.e6.as_mut().ok_or(InitError::WrongActivationOrder)?;
    retire_current_console(e6, system, waits, generation, poison_registry)
}

pub(super) fn reserve_registry_replacement(
    resident: &mut ResidentSystemInit,
    generation: u64,
) -> Result<(), InitError> {
    resident
        .wyr1c
        .as_mut()
        .and_then(|state| state.e6.as_mut())
        .ok_or(InitError::WrongActivationOrder)?
        .shell
        .reserve_replacement_generation(generation)
}

pub(super) fn commit_registry_replacement(
    resident: &mut ResidentSystemInit,
    generation: u64,
) -> Result<(), InitError> {
    resident
        .wyr1c
        .as_mut()
        .and_then(|state| state.e6.as_mut())
        .ok_or(InitError::WrongActivationOrder)?
        .commit_registry_replacement(generation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_launch_budget_is_finite_and_only_fresh_registry_replenishes_it() {
        let mut state = State::new(7).unwrap();
        let first = state.take_console_transaction().unwrap();
        assert_eq!(first, FIRST_CONSOLE_TRANSACTION);
        for _ in 1..WYR0_I_SUPERVISION_POLICY.max_attempts {
            state.take_console_transaction().unwrap();
        }
        assert_eq!(state.take_console_transaction(), Err(InitError::Cleanup));

        state.shell.poison(7);
        state.shell.reserve_replacement_generation(8).unwrap();
        state.commit_registry_replacement(8).unwrap();
        assert_eq!(
            state.shell.health(),
            crate::wyr1b_native::ShellRegistryHealth::Healthy { generation: 8 }
        );
        assert!(state.take_console_transaction().is_ok());
    }
}
