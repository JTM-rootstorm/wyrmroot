//! Production WYR1-E consoled and wyrmsh resident ownership.

use super::*;
use crate::wyr1b::EndpointGrant;
use crate::wyr1b_job::{JobDispatcher, LaunchSessionScope, SessionOwner};
#[cfg(feature = "wyr1e8-selector33")]
use crate::wyr1b_native::{
    E8RecoveryAction, finish_e8_dependent_retirement, retire_console_product_with_result,
    retire_console_product_with_result_before,
};
use crate::wyr1b_native::{
    InstalledPeer, JobDispatcherPollOutcome, ShellControllerState, ShellLaunchContext,
    create_controller_channel_pair, install_client, poll_job_dispatcher_with_shell,
    retire_console_product,
};
use deepwyrm_syscall::DW_TASK_STATE_RUNNING;
use wyrmroot_loader::process::{ConsoledLoadRequest, load_consoled_process};
use wyrmroot_registry_proto::{
    Header as RegistryHeader, Message as RegistryMessage, MessageType as RegistryMessageType,
    Watch, encode_watch, parse as parse_registry,
};

const CONSOLE_PATH: &str = "system/consoled";
const FIRST_CONSOLE_TRANSACTION: u64 = 0xE600_0001;
const FIRST_PUBLICATION_OBSERVER: u64 = 0xE610_0001;
const PUBLICATION_WATCH_TRANSACTION: u64 = 1;

fn encode_publication_watch(
    grant: EndpointGrant,
    bytes: &mut [u8],
) -> Result<usize, wyrmroot_registry_proto::Error> {
    let policy = SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY;
    encode_watch(
        RegistryHeader {
            message_type: RegistryMessageType::Watch,
            registry_generation: grant.registry_generation,
            endpoint_id: grant.endpoint_id,
            endpoint_generation: grant.endpoint_generation,
            transaction_id: PUBLICATION_WATCH_TRANSACTION,
        },
        Watch {
            protocol_id: policy.protocol_id,
            last_observed_generation: 0,
            service_name: policy.service_name,
        },
        bytes,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PublicationObserver {
    client: DwHandle,
    grant: EndpointGrant,
    expected_service_generation: u64,
    expected_driver: DriverLaunchRequest,
    deadline: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct State {
    jobs: JobDispatcher,
    console: Option<InstalledPeer>,
    pub(super) shell: ShellControllerState,
    publication_observer: Option<PublicationObserver>,
    awaiting_ready: bool,
    bootstrap_released: bool,
    ready_deadline: u64,
    console_transaction: u64,
    next_console_transaction: u64,
    next_publication_observer: u64,
    console_launch_attempts: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PollOutcome {
    Stable,
    LaunchConsole,
    RecoverDevmgr,
    RecoverRegistry,
    #[cfg(feature = "wyr1e8-selector33")]
    RecoverRegistryForE8,
}

fn reconcile_job_dispatcher_outcome(
    state: &mut State,
    outcome: JobDispatcherPollOutcome,
) -> Result<Option<PollOutcome>, InitError> {
    let JobDispatcherPollOutcome::SessionClosed {
        grant,
        scope: LaunchSessionScope::ConsoleLauncher,
    } = outcome
    else {
        return Ok(None);
    };
    let peer = state.console.ok_or(InitError::WrongActivationOrder)?;
    if peer.grant != grant {
        return Err(InitError::Accounting);
    }
    #[cfg(feature = "wyr1e8-selector33")]
    if !state.shell.routine_console_relaunch_allowed() {
        return Err(InitError::Supervision);
    }
    state.console = None;
    state.awaiting_ready = false;
    state.bootstrap_released = false;
    state.console_transaction = 0;
    #[cfg(feature = "wyr1e8-selector33")]
    state
        .shell
        .clear_e8_console_control(peer.loaded.launch_channel)
        .map_err(|_| InitError::Cleanup)?;
    Ok(Some(PollOutcome::LaunchConsole))
}

impl State {
    pub(super) fn new(registry_generation: u64) -> Result<Self, InitError> {
        Ok(Self {
            jobs: JobDispatcher::new(),
            console: None,
            shell: ShellControllerState::new(registry_generation)?,
            publication_observer: None,
            awaiting_ready: false,
            bootstrap_released: false,
            ready_deadline: 0,
            console_transaction: 0,
            next_console_transaction: FIRST_CONSOLE_TRANSACTION,
            next_publication_observer: FIRST_PUBLICATION_OBSERVER,
            console_launch_attempts: 0,
        })
    }

    #[cfg(all(test, feature = "wyr1e8-selector33"))]
    pub(super) fn from_e8_registry_fixture(
        shell: ShellControllerState,
        jobs: JobDispatcher,
        console: InstalledPeer,
    ) -> Self {
        Self {
            jobs,
            console: Some(console),
            shell,
            publication_observer: None,
            awaiting_ready: false,
            bootstrap_released: false,
            ready_deadline: 0,
            console_transaction: 0,
            next_console_transaction: FIRST_CONSOLE_TRANSACTION,
            next_publication_observer: FIRST_PUBLICATION_OBSERVER,
            console_launch_attempts: 0,
        }
    }

    #[cfg(all(test, feature = "wyr1e8-selector33"))]
    pub(super) fn e8_fixture_publication_observer(&self) -> Option<(DwHandle, EndpointGrant, u64)> {
        self.publication_observer.map(|observer| {
            (
                observer.client,
                observer.grant,
                observer.expected_service_generation,
            )
        })
    }

    #[cfg(all(test, feature = "wyr1e8-selector33"))]
    pub(super) fn into_e8_registry_fixture_parts(
        self,
    ) -> (ShellControllerState, JobDispatcher, Option<InstalledPeer>) {
        (self.shell, self.jobs, self.console)
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

    fn take_publication_observer(&mut self) -> Result<u64, InitError> {
        let transaction = self.next_publication_observer;
        self.next_publication_observer = transaction.checked_add(1).ok_or(InitError::Accounting)?;
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

pub(super) fn start_after_driver_constructed<S>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
{
    let state = resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?;
    let registry = state.registry.ok_or(InitError::WrongActivationOrder)?;
    let expected_driver = state.driver.ok_or(InitError::WrongActivationOrder)?.request;
    let expected_service_generation = state.publication_service_generation;
    let e6 = state.e6.as_mut().ok_or(InitError::WrongActivationOrder)?;
    if e6.console.is_some() || e6.publication_observer.is_some() {
        return Err(InitError::WrongActivationOrder);
    }
    let started_at = system.now().map_err(InitError::Native)?;
    #[cfg(feature = "wyr1e8-selector33")]
    e6.shell.require_e8_action_live_at(started_at)?;
    let operation = e6.take_publication_observer()?;
    let deadline = started_at
        .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .ok_or(InitError::Accounting)?;
    #[cfg(feature = "wyr1e8-selector33")]
    let deadline = e6.shell.cap_e8_deadline(deadline);
    if deadline == u64::MAX {
        return Err(InitError::Accounting);
    }
    let grant = state
        .topology
        .issue(operation, EndpointKind::RegistryClient)
        .map_err(InitError::Wyr1BModel)?;
    let (registry_endpoint, client) = create_controller_channel_pair(system)?;
    #[cfg(feature = "wyr1e8-selector33")]
    if let Err(error) = e6
        .shell
        .require_e8_action_live_at(system.now().map_err(InitError::Native)?)
    {
        let failed =
            system.close_handle(registry_endpoint).is_err() | system.close_handle(client).is_err();
        return Err(if failed { InitError::Cleanup } else { error });
    }
    if let Err(error) = install_client(
        system,
        registry.control_channel,
        grant,
        registry_endpoint,
        operation,
    ) {
        let cleanup_failed =
            system.close_handle(registry_endpoint).is_err() | system.close_handle(client).is_err();
        return Err(if cleanup_failed {
            InitError::Cleanup
        } else {
            error
        });
    }
    #[cfg(feature = "wyr1e8-selector33")]
    if let Err(error) = e6
        .shell
        .require_e8_action_live_at(system.now().map_err(InitError::Native)?)
    {
        e6.shell.poison(grant.registry_generation);
        return Err(if system.close_handle(client).is_err() {
            InitError::Cleanup
        } else {
            error
        });
    }
    let mut bytes = [0u8; 256];
    let size = match encode_publication_watch(grant, &mut bytes) {
        Ok(size) => size,
        Err(error) => {
            e6.shell.poison(grant.registry_generation);
            return Err(if system.close_handle(client).is_err() {
                InitError::Cleanup
            } else {
                InitError::RegistryProtocol(error)
            });
        }
    };
    if let Err(error) = system.send_channel(client, &bytes[..size]) {
        e6.shell.poison(grant.registry_generation);
        return Err(if system.close_handle(client).is_err() {
            InitError::Cleanup
        } else {
            InitError::Native(error)
        });
    }
    #[cfg(feature = "wyr1e8-selector33")]
    if let Err(error) = e6
        .shell
        .require_e8_action_live_at(system.now().map_err(InitError::Native)?)
    {
        e6.shell.poison(grant.registry_generation);
        return Err(if system.close_handle(client).is_err() {
            InitError::Cleanup
        } else {
            error
        });
    }
    e6.publication_observer = Some(PublicationObserver {
        client,
        grant,
        expected_service_generation,
        expected_driver,
        deadline,
    });
    Ok(())
}

pub(super) fn launch_after_publication_observed<S, L, W>(
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
    if e6.publication_observer.is_some() {
        return Err(InitError::WrongActivationOrder);
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
    #[cfg(feature = "wyr1e8-selector33")]
    e6.shell
        .require_e8_action_live_at(system.now().map_err(InitError::Native)?)?;
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
    #[cfg(feature = "wyr1e8-selector33")]
    if let Err(error) = e6
        .shell
        .require_e8_action_live_at(system.now().map_err(InitError::Native)?)
    {
        let failed = system.close_handle(registry_endpoint).is_err()
            | system.close_handle(child_registry).is_err()
            | system.close_handle(group).is_err();
        return Err(if failed { InitError::Cleanup } else { error });
    }
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
    #[cfg(feature = "wyr1e8-selector33")]
    if let Err(error) = e6
        .shell
        .require_e8_action_live_at(system.now().map_err(InitError::Native)?)
    {
        e6.shell.poison(topology.generation());
        let failed =
            system.close_handle(child_registry).is_err() | system.close_handle(group).is_err();
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
    #[cfg(feature = "wyr1e8-selector33")]
    if let Err(error) = e6
        .shell
        .require_e8_action_live_at(system.now().map_err(InitError::Native)?)
    {
        e6.shell.poison(topology.generation());
        let failed = e6
            .jobs
            .disconnect_session(launch_grant)
            .map_or(true, |handle| system.close_handle(handle).is_err())
            | system.close_handle(child_launch).is_err()
            | system.close_handle(child_registry).is_err()
            | system.close_handle(group).is_err();
        return Err(if failed { InitError::Cleanup } else { error });
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
        #[cfg(feature = "wyr1e8-selector33")]
        e6.shell.require_e8_action_live_at(now)?;
        now.checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .ok_or(InitError::Accounting)
    }) {
        Ok(deadline) => {
            #[cfg(feature = "wyr1e8-selector33")]
            let deadline = e6.shell.cap_e8_deadline(deadline);
            deadline
        }
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
    #[cfg(feature = "wyr1e8-selector33")]
    if let Err(error) = e6.shell.set_e8_console_control(loaded.launch_channel) {
        e6.shell.poison(topology.generation());
        let failed = cleanup_loaded(system, waits, loaded, group, true).is_err()
            | e6.jobs
                .disconnect_session(launch_grant)
                .map_or(true, |handle| system.close_handle(handle).is_err());
        return Err(if failed { InitError::Cleanup } else { error });
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

fn clear_publication_observer<S: Wyr1BPlatform>(
    e6: &mut State,
    system: &mut S,
    registry_generation: u64,
    poison_registry: bool,
) -> Result<(), InitError> {
    if poison_registry {
        e6.shell.poison(registry_generation);
    }
    let observer = e6
        .publication_observer
        .take()
        .ok_or(InitError::WrongActivationOrder)?;
    system
        .close_handle(observer.client)
        .map_err(|_| InitError::Cleanup)
}

fn validate_publication_datagram(
    observer: PublicationObserver,
    bytes: &[u8],
    validated_at: u64,
) -> Result<(), PollOutcome> {
    let expected_header = RegistryHeader {
        message_type: RegistryMessageType::GenerationChanged,
        registry_generation: observer.grant.registry_generation,
        endpoint_id: observer.grant.endpoint_id,
        endpoint_generation: observer.grant.endpoint_generation,
        transaction_id: PUBLICATION_WATCH_TRANSACTION,
    };
    let parsed = parse_registry(bytes, 0).map_err(|_| PollOutcome::RecoverRegistry)?;
    let RegistryMessage::GenerationChanged { service_generation } = parsed.message else {
        return Err(PollOutcome::RecoverRegistry);
    };
    if parsed.header != expected_header {
        return Err(PollOutcome::RecoverRegistry);
    }
    if service_generation != observer.expected_service_generation
        || validated_at >= observer.deadline
    {
        return Err(PollOutcome::RecoverDevmgr);
    }
    Ok(())
}

fn poll_publication_observer_state<S, W>(
    e6: &mut State,
    current_driver: Option<DriverNativeAttempt>,
    registry_generation: u64,
    system: &mut S,
    waits: &mut W,
    now: u64,
) -> Result<Option<PollOutcome>, InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let Some(observer) = e6.publication_observer else {
        return Ok(None);
    };
    if now >= observer.deadline {
        clear_publication_observer(e6, system, registry_generation, false)?;
        return Ok(Some(PollOutcome::RecoverDevmgr));
    }
    let item = DwWaitItemV1 {
        handle: observer.client,
        signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
    };
    let observed = match system.wait_many(core::slice::from_ref(&item), DwDeadline(now)) {
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => return Ok(None),
        Err(error) => {
            let cleanup = clear_publication_observer(e6, system, registry_generation, false);
            return Err(if cleanup.is_err() {
                InitError::Cleanup
            } else {
                InitError::Native(error)
            });
        }
        Ok(observed) => observed,
    };
    if observed.index != 0 {
        clear_publication_observer(e6, system, registry_generation, true)?;
        return Ok(Some(PollOutcome::RecoverRegistry));
    }
    if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
        clear_publication_observer(e6, system, registry_generation, true)?;
        return Ok(Some(PollOutcome::RecoverRegistry));
    }
    if observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        clear_publication_observer(e6, system, registry_generation, true)?;
        return Ok(Some(PollOutcome::RecoverRegistry));
    }
    let mut bytes = [0u8; 256];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = match system.receive_channel(observer.client, &mut bytes, &mut handles) {
        Ok(counts) => counts,
        Err(_) => {
            clear_publication_observer(e6, system, registry_generation, true)?;
            return Ok(Some(PollOutcome::RecoverRegistry));
        }
    };
    if counts.bytes > bytes.len() || counts.handles > handles.len() {
        let received_cleanup = close_received_native(system, &handles, counts.handles);
        let observer_cleanup = clear_publication_observer(e6, system, registry_generation, true);
        return if received_cleanup.is_err() || observer_cleanup.is_err() {
            Err(InitError::Cleanup)
        } else {
            Ok(Some(PollOutcome::RecoverRegistry))
        };
    }
    if counts.handles != 0 {
        let received_cleanup = close_received_native(system, &handles, counts.handles);
        let observer_cleanup = clear_publication_observer(e6, system, registry_generation, true);
        return if received_cleanup.is_err() || observer_cleanup.is_err() {
            Err(InitError::Cleanup)
        } else {
            Ok(Some(PollOutcome::RecoverRegistry))
        };
    }
    let validated_at = match system.now() {
        Ok(validated_at) => validated_at,
        Err(error) => {
            let cleanup = clear_publication_observer(e6, system, registry_generation, false);
            return Err(if cleanup.is_err() {
                InitError::Cleanup
            } else {
                InitError::Native(error)
            });
        }
    };
    #[cfg(feature = "wyr1e8-selector33")]
    if e6.shell.e8_action_expired(validated_at) {
        let cleanup = clear_publication_observer(e6, system, registry_generation, false);
        return if cleanup.is_err() {
            Err(InitError::Cleanup)
        } else {
            e8_operation(
                E8FailureOperation::RebindPublication,
                Err(InitError::Supervision),
            )
        };
    }
    if let Err(outcome) =
        validate_publication_datagram(observer, &bytes[..counts.bytes], validated_at)
    {
        clear_publication_observer(
            e6,
            system,
            registry_generation,
            outcome == PollOutcome::RecoverRegistry,
        )?;
        return Ok(Some(outcome));
    }
    let current = match current_driver {
        Some(current) => current,
        None => {
            clear_publication_observer(e6, system, registry_generation, false)?;
            return Ok(Some(PollOutcome::RecoverDevmgr));
        }
    };
    let info = match waits.query_task_termination(current.loaded.process) {
        Ok(info) => info,
        Err(error) => {
            let cleanup = clear_publication_observer(e6, system, registry_generation, false);
            return Err(if cleanup.is_err() {
                InitError::Cleanup
            } else {
                InitError::Native(error)
            });
        }
    };
    if current.request != observer.expected_driver || info.state != DW_TASK_STATE_RUNNING {
        clear_publication_observer(e6, system, registry_generation, false)?;
        return Ok(Some(PollOutcome::RecoverDevmgr));
    }
    #[cfg(feature = "wyr1e-selector33")]
    e6.shell.observe_serial_for_e7(
        observer.expected_service_generation,
        observer.expected_driver.attempt_generation.0,
        observer.expected_driver.supervisor_generation.0,
    )?;
    #[cfg(feature = "wyr1e8-selector33")]
    e6.shell.observe_serial_for_e8(
        observer.expected_service_generation,
        observer.expected_driver,
    )?;
    clear_publication_observer(e6, system, registry_generation, false)?;
    Ok(Some(PollOutcome::LaunchConsole))
}

fn poll_publication_observer<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
    now: u64,
) -> Result<Option<PollOutcome>, InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let state = resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?;
    let registry_generation = state.topology.generation();
    let current_driver = state.driver;
    let e6 = state.e6.as_mut().ok_or(InitError::WrongActivationOrder)?;
    poll_publication_observer_state(e6, current_driver, registry_generation, system, waits, now)
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
    #[cfg(feature = "wyr1e8-selector33")]
    ensure_e8_action_live(resident, now)?;
    if let Some(outcome) = poll_publication_observer(resident, system, waits, now)? {
        return Ok(outcome);
    }
    let authority = resident.authority;
    let state = resident
        .wyr1c
        .as_mut()
        .ok_or(InitError::WrongActivationOrder)?;
    let registry = state.registry.ok_or(InitError::WrongActivationOrder)?;
    let e6 = state.e6.as_mut().ok_or(InitError::WrongActivationOrder)?;
    #[cfg(feature = "wyr1e8-selector33")]
    let poll_shell_jobs = e6.shell.job_dispatcher_poll_allowed();
    #[cfg(not(feature = "wyr1e8-selector33"))]
    let poll_shell_jobs = true;
    if poll_shell_jobs {
        let dispatcher_result = {
            let mut shell = ShellLaunchContext {
                registry_control: registry.control_channel,
                topology: &mut state.topology,
                state: &mut e6.shell,
            };
            poll_job_dispatcher_with_shell(
                system,
                loader,
                waits,
                authority,
                &mut e6.jobs,
                now,
                &mut shell,
            )
        };
        let dispatcher_outcome = match dispatcher_result {
            Ok(outcome) => outcome,
            Err(error) => {
                return if matches!(
                    e6.shell.health(),
                    crate::wyr1b_native::ShellRegistryHealth::Poisoned { .. }
                ) {
                    Ok(PollOutcome::RecoverRegistry)
                } else {
                    Err(error)
                };
            }
        };
        if let Some(outcome) = reconcile_job_dispatcher_outcome(e6, dispatcher_outcome)? {
            return Ok(outcome);
        }
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
        #[cfg(feature = "wyr1e8-selector33")]
        let relaunch_allowed = e6.shell.routine_console_relaunch_allowed();
        let peer = e6.console.take().ok_or(InitError::WrongActivationOrder)?;
        e6.awaiting_ready = false;
        e6.bootstrap_released = false;
        e6.console_transaction = 0;
        #[cfg(feature = "wyr1e8-selector33")]
        let control_failed = e6
            .shell
            .clear_e8_console_control(peer.loaded.launch_channel)
            .is_err();
        let cleanup = retire_console_product(system, waits, &mut e6.jobs, peer, false);
        #[cfg(feature = "wyr1e8-selector33")]
        if control_failed || cleanup.is_err() {
            return Err(InitError::Cleanup);
        }
        cleanup?;
        #[cfg(feature = "wyr1e8-selector33")]
        if !relaunch_allowed {
            return Err(InitError::Supervision);
        }
        return Ok(PollOutcome::LaunchConsole);
    }
    if observed.index != 1 {
        retire_current_console(e6, system, waits, state.topology.generation(), true)?;
        return Ok(PollOutcome::RecoverRegistry);
    }
    if observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 {
        #[cfg(not(feature = "wyr1e8-selector33"))]
        if !e6.awaiting_ready {
            retire_current_console(e6, system, waits, state.topology.generation(), true)?;
            return Ok(PollOutcome::RecoverRegistry);
        }
        #[cfg(feature = "wyr1e8-selector33")]
        let mut bytes = [0u8; wyrmroot_consoled::e8_control::FRAME_BYTES];
        #[cfg(not(feature = "wyr1e8-selector33"))]
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
        #[cfg(feature = "wyr1e8-selector33")]
        if bytes[..counts.bytes].starts_with(b"WRC8") {
            let message = e8_operation(
                E8FailureOperation::Quiesced,
                wyrmroot_consoled::e8_control::parse(&bytes[..counts.bytes])
                    .map_err(|_| InitError::Accounting),
            )?;
            match message {
                wyrmroot_consoled::e8_control::Message::ReadyFacts(facts) => {
                    e6.shell.observe_e8_serial_ready(
                        system,
                        crate::wyr1e8_evidence::SerialReady {
                            console_generation: facts.console_generation,
                            status_generation: facts.status_generation,
                            shell_generation: facts.shell_generation,
                            attach_transaction: facts.attach_transaction,
                            stream_generation: facts.stream_generation,
                            bundle_generation: facts.bundle_generation,
                        },
                    )?;
                    return Ok(PollOutcome::Stable);
                }
                wyrmroot_consoled::e8_control::Message::Quiesced(identity) => {
                    let quiesced_at = system.now().map_err(InitError::Native)?;
                    e8_operation(
                        E8FailureOperation::Quiesced,
                        e6.shell.require_e8_action_live_at(quiesced_at),
                    )?;
                    let action = e8_operation(
                        E8FailureOperation::Quiesced,
                        e6.shell.accept_e8_quiesced(identity, quiesced_at),
                    )?;
                    if action == E8RecoveryAction::Registry {
                        return Ok(PollOutcome::RecoverRegistryForE8);
                    }
                    e8_operation(
                        E8FailureOperation::RequestRetire,
                        e6.shell.require_e8_action_live(system),
                    )?;
                    e8_operation(
                        E8FailureOperation::RequestRetire,
                        (|| {
                            let request =
                                state.driver.ok_or(InitError::WrongActivationOrder)?.request;
                            let devmgr = state.devmgr.ok_or(InitError::WrongActivationOrder)?;
                            let identity = e6.shell.e8_driver_identity(request)?;
                            let mut request_bytes =
                                [0u8; wyrmroot_device_proto::d5_controller::RECORD_BYTES];
                            wyrmroot_device_proto::d5_controller::encode(
                            wyrmroot_device_proto::d5_controller::D5ControllerMessage::RequestRetire(
                                identity,
                            ),
                            &mut request_bytes,
                        )
                        .map_err(|_| InitError::Accounting)?;
                            system
                                .send_channel(devmgr.loaded.launch_channel, &request_bytes)
                                .map_err(InitError::Native)
                        })(),
                    )?;
                    e8_operation(
                        E8FailureOperation::RequestRetire,
                        e6.shell.require_e8_action_live(system),
                    )?;
                    return Ok(PollOutcome::Stable);
                }
                wyrmroot_consoled::e8_control::Message::Quiesce(_) => {
                    return e8_operation(
                        E8FailureOperation::Quiesced,
                        Err(InitError::WrongActivationOrder),
                    );
                }
            }
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
            #[cfg(feature = "wyr1e8-selector33")]
            if e6.shell.e8_action_expired(validated_at) {
                return e8_operation(E8FailureOperation::Quiesced, Err(InitError::Supervision));
            }
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

#[cfg(feature = "wyr1e8-selector33")]
pub(super) fn e8_action_deadline(resident: &ResidentSystemInit) -> Result<Option<u64>, InitError> {
    Ok(resident
        .wyr1c
        .as_ref()
        .and_then(|state| state.e6.as_ref())
        .ok_or(InitError::WrongActivationOrder)?
        .shell
        .e8_action_deadline())
}

#[cfg(feature = "wyr1e8-selector33")]
pub(super) fn ensure_e8_action_live(
    resident: &ResidentSystemInit,
    now: u64,
) -> Result<(), InitError> {
    let state = resident
        .wyr1c
        .as_ref()
        .and_then(|state| state.e6.as_ref())
        .ok_or(InitError::WrongActivationOrder)?;
    e8_operation(
        E8FailureOperation::Quiesced,
        state.shell.require_e8_action_live_at(now),
    )
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
    #[cfg(feature = "wyr1e8-selector33")]
    let control_failed = e6
        .shell
        .clear_e8_console_control(peer.loaded.launch_channel)
        .is_err();
    let result = retire_console_product(system, waits, &mut e6.jobs, peer, true);
    #[cfg(feature = "wyr1e8-selector33")]
    if control_failed || result.is_err() {
        return Err(InitError::Cleanup);
    }
    result
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
    #[cfg(feature = "wyr1e8-selector33")]
    let pending_action = e6.shell.e8_pending_action();
    #[cfg(feature = "wyr1e8-selector33")]
    let expected_action = if poison_registry {
        E8RecoveryAction::Registry
    } else {
        E8RecoveryAction::Driver
    };
    #[cfg(feature = "wyr1e8-selector33")]
    if pending_action.is_some_and(|action| action != expected_action) {
        return Err(InitError::WrongActivationOrder);
    }
    #[cfg(feature = "wyr1e8-selector33")]
    let held = match pending_action {
        Some(_) => Some(e6.shell.e8_held_for_action(expected_action)?),
        None => None,
    };
    #[cfg(feature = "wyr1e8-selector33")]
    if let Some(held) = held {
        e6.shell
            .require_e8_action_live_at(system.now().map_err(InitError::Native)?)?;
        if held.deadline != e6.shell.e8_action_deadline().ok_or(InitError::Accounting)? {
            return Err(InitError::Accounting);
        }
    }
    if poison_registry {
        e6.shell.poison(generation);
    }
    let observer_failed = e6
        .publication_observer
        .take()
        .is_some_and(|observer| system.close_handle(observer.client).is_err());
    let Some(peer) = e6.console.take() else {
        return if observer_failed || {
            #[cfg(feature = "wyr1e8-selector33")]
            {
                pending_action.is_some()
            }
            #[cfg(not(feature = "wyr1e8-selector33"))]
            {
                false
            }
        } {
            Err(InitError::Cleanup)
        } else {
            Ok(())
        };
    };
    e6.awaiting_ready = false;
    e6.bootstrap_released = false;
    e6.console_transaction = 0;
    #[cfg(feature = "wyr1e8-selector33")]
    let control_failed = e6
        .shell
        .clear_e8_console_control(peer.loaded.launch_channel)
        .is_err();
    #[cfg(feature = "wyr1e8-selector33")]
    let console_result = match held {
        Some(held) => retire_console_product_with_result_before(
            system,
            waits,
            &mut e6.jobs,
            peer,
            true,
            held.deadline,
        ),
        None => retire_console_product_with_result(system, waits, &mut e6.jobs, peer, true),
    };
    #[cfg(not(feature = "wyr1e8-selector33"))]
    let console_result =
        retire_console_product(system, waits, &mut e6.jobs, peer, true).map(|_| None);
    if observer_failed || console_result.is_err() || {
        #[cfg(feature = "wyr1e8-selector33")]
        {
            control_failed
        }
        #[cfg(not(feature = "wyr1e8-selector33"))]
        {
            false
        }
    } {
        Err(InitError::Cleanup)
    } else {
        #[cfg(feature = "wyr1e8-selector33")]
        if let Some(held) = held {
            let result = console_result?.ok_or(InitError::WrongActivationOrder)?;
            finish_e8_dependent_retirement(system, &mut e6.jobs, &mut e6.shell, held, result)?;
        }
        Ok(())
    }
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
    use deepwyrm_syscall::{
        DW_SIGNAL_READABLE, DW_TASK_STATE_CREATED, DW_TASK_STATE_RUNNING,
        DW_TERMINATION_NORMAL_EXIT, DwStatus,
    };

    const FAILURE: NativeError = NativeError::Status(DwStatus(-1));

    struct ObserverPlatform {
        inbound: [u8; 256],
        inbound_len: usize,
        post_receive_now: u64,
        wait_count: usize,
        receive_count: usize,
        closed: [DwHandle; 2],
        close_count: usize,
    }

    impl ObserverPlatform {
        fn generation(observed: PublicationObserver, post_receive_now: u64) -> Self {
            let mut inbound = [0u8; 256];
            let size = wyrmroot_registry_proto::encode_generation_changed(
                RegistryHeader {
                    message_type: RegistryMessageType::GenerationChanged,
                    registry_generation: observed.grant.registry_generation,
                    endpoint_id: observed.grant.endpoint_id,
                    endpoint_generation: observed.grant.endpoint_generation,
                    transaction_id: PUBLICATION_WATCH_TRANSACTION,
                },
                observed.expected_service_generation,
                &mut inbound,
            )
            .unwrap();
            Self {
                inbound,
                inbound_len: size,
                post_receive_now,
                wait_count: 0,
                receive_count: 0,
                closed: [DwHandle(0); 2],
                close_count: 0,
            }
        }
    }

    impl InitPlatform for ObserverPlatform {
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
            self.receive_count += 1;
            bytes[..self.inbound_len].copy_from_slice(&self.inbound[..self.inbound_len]);
            Ok(ReceiveCounts {
                bytes: self.inbound_len,
                handles: 0,
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
            Ok(self.post_receive_now)
        }

        fn wait_until(&mut self, _deadline_ns: u64) -> Result<(), NativeError> {
            Err(FAILURE)
        }
    }

    impl Wyr1BPlatform for ObserverPlatform {
        fn channel_create(
            &mut self,
            _rights: DwRights,
        ) -> Result<(DwHandle, DwHandle), NativeError> {
            Err(FAILURE)
        }

        fn send_channel_with_handles(
            &mut self,
            _channel: DwHandle,
            _bytes: &[u8],
            _transfers: &[DwHandleTransferV1],
        ) -> Result<(), NativeError> {
            Err(FAILURE)
        }

        fn wait_many(
            &mut self,
            items: &[DwWaitItemV1],
            _deadline: DwDeadline,
        ) -> Result<DwWaitResultV1, NativeError> {
            self.wait_count += 1;
            assert_eq!(items.len(), 1);
            Ok(DwWaitResultV1 {
                index: 0,
                observed: DW_SIGNAL_READABLE,
                ..DwWaitResultV1::default()
            })
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

    struct ObserverWaits {
        state: deepwyrm_syscall::DwTaskState,
        query_count: usize,
    }

    impl SupervisionPlatform for ObserverWaits {
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
            process: DwHandle,
        ) -> Result<DwTaskTerminationInfoV1, Self::Error> {
            assert_eq!(process, DwHandle(91));
            self.query_count += 1;
            Ok(DwTaskTerminationInfoV1 {
                state: self.state,
                reason: DW_TERMINATION_NORMAL_EXIT,
                ..DwTaskTerminationInfoV1::default()
            })
        }
    }

    fn driver_request() -> DriverLaunchRequest {
        DriverLaunchRequest {
            supervisor_generation: SupervisorGeneration(7),
            role_id: wyrmroot_device_proto::COM2_ROLE_ID,
            attempt_generation: wyrmroot_device_proto::coordinator::AttemptGeneration(1),
            launch_session: wyrmroot_device_proto::coordinator::LaunchSessionGeneration(2),
            endpoint: wyrmroot_device_proto::ControlEndpoint {
                id: wyrmroot_device_proto::coordinator::EndpointId(3),
                generation: wyrmroot_device_proto::coordinator::EndpointGeneration(1),
            },
            transaction_id: 9,
            driver_path: wyrmroot_device_proto::DEVICE_DRIVER_PATH,
            actor_identity: wyrmroot_device_proto::manifest::ContentIdentity([0x5a; 32]),
            child_is_channel: true,
            child_rights: wyrmroot_device_proto::DirectControlRights::ExactReduced,
        }
    }

    fn observer() -> PublicationObserver {
        PublicationObserver {
            client: DwHandle(90),
            grant: EndpointGrant {
                registry_generation: 7,
                endpoint_id: 8,
                endpoint_generation: 9,
                role_generation: 10,
                kind: EndpointKind::RegistryClient,
            },
            expected_service_generation: 11,
            expected_driver: driver_request(),
            deadline: 100,
        }
    }

    fn driver_attempt() -> DriverNativeAttempt {
        DriverNativeAttempt {
            loaded: LoadedProcess {
                process: DwHandle(91),
                launch_channel: DwHandle(92),
            },
            task_group: DwHandle(93),
            request: driver_request(),
        }
    }

    fn console_peer() -> InstalledPeer {
        InstalledPeer {
            grant: EndpointGrant {
                registry_generation: 7,
                endpoint_id: 12,
                endpoint_generation: 13,
                role_generation: 14,
                kind: EndpointKind::LaunchSession,
            },
            loaded: LoadedProcess {
                process: DwHandle(94),
                launch_channel: DwHandle(95),
            },
            task_group: DwHandle(96),
        }
    }

    fn generation_changed(observed: PublicationObserver) -> ([u8; 72], usize) {
        let mut bytes = [0u8; 72];
        let size = wyrmroot_registry_proto::encode_generation_changed(
            RegistryHeader {
                message_type: RegistryMessageType::GenerationChanged,
                registry_generation: observed.grant.registry_generation,
                endpoint_id: observed.grant.endpoint_id,
                endpoint_generation: observed.grant.endpoint_generation,
                transaction_id: PUBLICATION_WATCH_TRANSACTION,
            },
            observed.expected_service_generation,
            &mut bytes,
        )
        .unwrap();
        (bytes, size)
    }

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

    #[test]
    fn closed_console_session_discards_stale_owner_and_requests_fresh_launch() {
        let peer = console_peer();
        let mut state = State::new(7).unwrap();
        state.console = Some(peer);
        state.awaiting_ready = true;
        state.bootstrap_released = true;
        state.console_transaction = 23;
        #[cfg(feature = "wyr1e8-selector33")]
        state
            .shell
            .set_e8_console_control(peer.loaded.launch_channel)
            .unwrap();

        assert_eq!(
            reconcile_job_dispatcher_outcome(
                &mut state,
                JobDispatcherPollOutcome::SessionClosed {
                    grant: peer.grant,
                    scope: LaunchSessionScope::ConsoleLauncher,
                },
            ),
            Ok(Some(PollOutcome::LaunchConsole))
        );
        assert_eq!(state.console, None);
        assert!(!state.awaiting_ready);
        assert!(!state.bootstrap_released);
        assert_eq!(state.console_transaction, 0);
    }

    #[test]
    fn closed_console_session_with_wrong_grant_fails_without_discarding_owner() {
        let peer = console_peer();
        let mut state = State::new(7).unwrap();
        state.console = Some(peer);
        let mut wrong_grant = peer.grant;
        wrong_grant.endpoint_generation += 1;

        assert_eq!(
            reconcile_job_dispatcher_outcome(
                &mut state,
                JobDispatcherPollOutcome::SessionClosed {
                    grant: wrong_grant,
                    scope: LaunchSessionScope::ConsoleLauncher,
                },
            ),
            Err(InitError::Accounting)
        );
        assert_eq!(state.console, Some(peer));
    }

    #[test]
    fn publication_watch_requires_exact_tuple_generation_and_predeadline_validation() {
        let observed = observer();
        let mut request = [0u8; 256];
        let request_size = encode_publication_watch(observed.grant, &mut request).unwrap();
        let parsed_request = parse_registry(&request[..request_size], 0).unwrap();
        assert_eq!(
            parsed_request.header,
            RegistryHeader {
                message_type: RegistryMessageType::Watch,
                registry_generation: observed.grant.registry_generation,
                endpoint_id: observed.grant.endpoint_id,
                endpoint_generation: observed.grant.endpoint_generation,
                transaction_id: PUBLICATION_WATCH_TRANSACTION,
            }
        );
        assert_eq!(
            parsed_request.message,
            RegistryMessage::Watch(Watch {
                protocol_id: SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY.protocol_id,
                last_observed_generation: 0,
                service_name: SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY.service_name,
            })
        );
        let (mut bytes, size) = generation_changed(observed);
        assert_eq!(
            validate_publication_datagram(observed, &bytes[..size], observed.deadline - 1),
            Ok(())
        );
        assert_eq!(
            validate_publication_datagram(observed, &bytes[..size], observed.deadline),
            Err(PollOutcome::RecoverDevmgr)
        );

        let mut stale_generation = observed;
        stale_generation.expected_service_generation += 1;
        assert_eq!(
            validate_publication_datagram(stale_generation, &bytes[..size], observed.deadline - 1,),
            Err(PollOutcome::RecoverDevmgr)
        );

        bytes[48] ^= 1;
        assert_eq!(
            validate_publication_datagram(observed, &bytes[..size], observed.deadline - 1),
            Err(PollOutcome::RecoverRegistry)
        );
        assert_eq!(
            validate_publication_datagram(observed, &bytes[..size - 1], observed.deadline - 1),
            Err(PollOutcome::RecoverRegistry)
        );
    }

    #[test]
    fn observer_deadline_wins_before_receive_and_after_exact_reply_validation() {
        let observed = observer();
        let mut e6 = State::new(observed.grant.registry_generation).unwrap();
        e6.publication_observer = Some(observed);
        let mut platform = ObserverPlatform::generation(observed, observed.deadline);
        let mut waits = ObserverWaits {
            state: DW_TASK_STATE_RUNNING,
            query_count: 0,
        };
        assert_eq!(
            poll_publication_observer_state(
                &mut e6,
                Some(driver_attempt()),
                observed.grant.registry_generation,
                &mut platform,
                &mut waits,
                observed.deadline,
            ),
            Ok(Some(PollOutcome::RecoverDevmgr))
        );
        assert_eq!(platform.wait_count, 0);
        assert_eq!(platform.receive_count, 0);
        assert_eq!(platform.closed[..platform.close_count], [observed.client]);
        assert_eq!(waits.query_count, 0);
        assert!(e6.publication_observer.is_none());

        e6.publication_observer = Some(observed);
        let mut platform = ObserverPlatform::generation(observed, observed.deadline);
        assert_eq!(
            poll_publication_observer_state(
                &mut e6,
                Some(driver_attempt()),
                observed.grant.registry_generation,
                &mut platform,
                &mut waits,
                observed.deadline - 1,
            ),
            Ok(Some(PollOutcome::RecoverDevmgr))
        );
        assert_eq!(platform.wait_count, 1);
        assert_eq!(platform.receive_count, 1);
        assert_eq!(platform.closed[..platform.close_count], [observed.client]);
        assert_eq!(waits.query_count, 0);
    }

    #[test]
    fn exact_queued_watch_cannot_launch_an_already_exited_driver() {
        let observed = observer();
        let mut e6 = State::new(observed.grant.registry_generation).unwrap();
        e6.publication_observer = Some(observed);
        let mut platform = ObserverPlatform::generation(observed, observed.deadline - 1);
        let mut waits = ObserverWaits {
            state: DW_TASK_STATE_EXITED,
            query_count: 0,
        };
        assert_eq!(
            poll_publication_observer_state(
                &mut e6,
                Some(driver_attempt()),
                observed.grant.registry_generation,
                &mut platform,
                &mut waits,
                observed.deadline - 1,
            ),
            Ok(Some(PollOutcome::RecoverDevmgr))
        );
        assert_eq!(waits.query_count, 1);
        assert_eq!(platform.closed[..platform.close_count], [observed.client]);
        assert!(e6.publication_observer.is_none());
    }

    #[test]
    fn exact_queued_watch_requires_driver_to_be_running() {
        let observed = observer();
        let mut e6 = State::new(observed.grant.registry_generation).unwrap();
        e6.publication_observer = Some(observed);
        let mut platform = ObserverPlatform::generation(observed, observed.deadline - 1);
        let mut waits = ObserverWaits {
            state: DW_TASK_STATE_CREATED,
            query_count: 0,
        };
        assert_eq!(
            poll_publication_observer_state(
                &mut e6,
                Some(driver_attempt()),
                observed.grant.registry_generation,
                &mut platform,
                &mut waits,
                observed.deadline - 1,
            ),
            Ok(Some(PollOutcome::RecoverDevmgr))
        );
        assert_eq!(waits.query_count, 1);
        assert_eq!(platform.closed[..platform.close_count], [observed.client]);
        assert!(e6.publication_observer.is_none());
    }
}
