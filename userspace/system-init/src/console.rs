//! The console: consoled and wyrmsh ownership, publication watches.

use crate::job_sessions::{JobDispatcher, LaunchSessionScope, SessionOwner};
use crate::jobs::EndpointGrant;
use crate::*;
use crate::{
    InstalledPeer, JobDispatcherPollOutcome, ShellControllerState, ShellLaunchContext,
    create_controller_channel_pair, install_client, poll_job_dispatcher_with_shell,
    retire_console_product,
};
use deepwyrm_syscall::DW_TASK_STATE_RUNNING;
use wyrmroot_device_proto::{DriverLaunchRequest, SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY};
use wyrmroot_loader::process::{ConsoledLoadRequest, load_consoled_process};
use wyrmroot_registry_proto::{
    Header as RegistryHeader, Message as RegistryMessage, MessageType as RegistryMessageType,
    Watch, encode_watch, parse as parse_registry,
};

pub(crate) use wyrmroot_bootfs::paths::CONSOLED_PATH as CONSOLE_PATH;
pub(crate) const FIRST_CONSOLE_TRANSACTION: u64 = 0xE600_0001;
pub(crate) const FIRST_PUBLICATION_OBSERVER: u64 = 0xE610_0001;
pub(crate) const PUBLICATION_WATCH_TRANSACTION: u64 = 1;

pub(crate) fn encode_publication_watch(
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
pub(crate) struct PublicationObserver {
    pub(crate) client: DwHandle,
    pub(crate) grant: EndpointGrant,
    pub(crate) expected_service_generation: u64,
    pub(crate) expected_driver: DriverLaunchRequest,
    pub(crate) deadline: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct ConsoleState {
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
    /// The console child ended the interactive session and the console has
    /// been retired. Nothing replaces it.
    ///
    /// F3A.7g. This is the one outcome that is not a recovery. Every other
    /// non-`Stable` outcome names something to rebuild; this one says the
    /// system finished what it was booted to do, and the supervisor's only
    /// remaining obligation is to stop.
    SessionComplete,
    RecoverDevmgr,
    /// The poll phase that asked, per `crate::abandoned::phase`.
    ///
    /// F3A.6j: `RecoverRegistry` alone covered twenty product sites across
    /// three functions, so a transcript that named it named most of this file.
    RecoverRegistry(u8),
}

pub(crate) fn reconcile_job_dispatcher_outcome(
    state: &mut ConsoleState,
    outcome: JobDispatcherPollOutcome,
) -> Result<Option<PollOutcome>, InitError> {
    let JobDispatcherPollOutcome::SessionClosed {
        grant,
        scope: LaunchSessionScope::ConsoleLauncher,
    } = outcome
    else {
        return Ok(None);
    };
    let peer = state.console.ok_or(InitError::AbsentState(0x80))?;
    if peer.grant != grant {
        return Err(InitError::Accounting);
    }
    state.console = None;
    state.awaiting_ready = false;
    state.bootstrap_released = false;
    state.console_transaction = 0;
    Ok(Some(PollOutcome::LaunchConsole))
}

impl ConsoleState {
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

    pub(crate) fn take_console_transaction(&mut self) -> Result<u64, InitError> {
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

    pub(crate) fn take_publication_observer(&mut self) -> Result<u64, InitError> {
        let transaction = self.next_publication_observer;
        self.next_publication_observer = transaction.checked_add(1).ok_or(InitError::Accounting)?;
        Ok(transaction)
    }

    pub(crate) fn commit_registry_replacement(&mut self, generation: u64) -> Result<(), InitError> {
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
    S: ResidentPlatform,
{
    let state = resident
        .product
        .as_mut()
        .ok_or(InitError::AbsentState(0x81))?;
    let registry = state.registry.ok_or(InitError::AbsentState(0x82))?;
    let expected_driver = state.driver.ok_or(InitError::AbsentState(0x83))?.request;
    let expected_service_generation = state.publication_service_generation;
    let session = state.session.as_mut().ok_or(InitError::AbsentState(0x84))?;
    if session.console.is_some() || session.publication_observer.is_some() {
        return Err(InitError::WrongActivationOrder);
    }
    let started_at = system.now().map_err(InitError::Native)?;
    session.shell.require_recovery_live_at(started_at)?;
    let operation = session.take_publication_observer()?;
    let deadline = started_at
        .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .ok_or(InitError::Accounting)?;
    let deadline = session.shell.cap_recovery_deadline(deadline);
    if deadline == u64::MAX {
        return Err(InitError::Accounting);
    }
    let grant = state
        .topology
        .issue(operation, EndpointKind::RegistryClient)
        .map_err(InitError::Jobs)?;
    let (registry_endpoint, client) = create_controller_channel_pair(system)?;
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
    let mut bytes = [0u8; 256];
    let size = match encode_publication_watch(grant, &mut bytes) {
        Ok(size) => size,
        Err(error) => {
            session.shell.poison(grant.registry_generation);
            return Err(if system.close_handle(client).is_err() {
                InitError::Cleanup
            } else {
                InitError::RegistryProtocol(error)
            });
        }
    };
    if let Err(error) = system.send_channel(client, &bytes[..size]) {
        session.shell.poison(grant.registry_generation);
        return Err(if system.close_handle(client).is_err() {
            InitError::Cleanup
        } else {
            InitError::Native(error)
        });
    }
    session.publication_observer = Some(PublicationObserver {
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
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let authority = resident.authority;
    let state = resident
        .product
        .as_mut()
        .ok_or(InitError::AbsentState(0x85))?;
    let registry = state.registry.ok_or(InitError::AbsentState(0x86))?;
    let session = state.session.as_mut().ok_or(InitError::AbsentState(0x87))?;
    if session.publication_observer.is_some() {
        return Err(InitError::WrongActivationOrder);
    }
    launch_console(
        session,
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
        .product
        .as_ref()
        .and_then(|state| state.session.as_ref())
        .is_some_and(|state| {
            matches!(
                state.shell.health(),
                crate::ShellRegistryHealth::Poisoned { .. }
            )
        })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn launch_console<S, L, W>(
    session: &mut ConsoleState,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    bootfs: &[u8],
    registry_control: DwHandle,
    topology: &mut RegistryTopology,
) -> Result<(), InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    if session.console.is_some() {
        return Err(InitError::WrongActivationOrder);
    }
    let image = Archive::new(bootfs)
        .map_err(InitError::Bootfs)?
        .lookup(CONSOLE_PATH.as_bytes())
        .map_err(map_lookup)?;
    if !image.is_executable() || image.data().is_empty() {
        return Err(InitError::NonExecutableRole);
    }
    let transaction = session.take_console_transaction()?;
    let registry_grant = topology
        .issue(transaction, EndpointKind::RegistryClient)
        .map_err(InitError::Jobs)?;
    let launch_grant = topology
        .issue(transaction, EndpointKind::LaunchSession)
        .map_err(InitError::Jobs)?;
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
            session.shell.poison(topology.generation());
            let failed =
                system.close_handle(child_registry).is_err() | system.close_handle(group).is_err();
            return Err(if failed { InitError::Cleanup } else { error });
        }
    };
    if let Err(error) = session.jobs.install_scoped_session(
        launch_grant,
        launch_endpoint,
        LaunchSessionScope::ConsoleLauncher,
    ) {
        session.shell.poison(topology.generation());
        let failed = system.close_handle(launch_endpoint).is_err()
            | system.close_handle(child_launch).is_err()
            | system.close_handle(child_registry).is_err()
            | system.close_handle(group).is_err();
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Jobs(error)
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
            session.shell.poison(topology.generation());
            let mut failed = false;
            if !failure.registry_endpoint_consumed {
                failed |= system.close_handle(child_registry).is_err();
            }
            if !failure.launch_endpoint_consumed {
                failed |= system.close_handle(child_launch).is_err();
            }
            failed |= session
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
        session.shell.require_recovery_live_at(now)?;
        now.checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .ok_or(InitError::Accounting)
    }) {
        Ok(deadline) => session.shell.cap_recovery_deadline(deadline),
        Err(error) => {
            session.shell.poison(topology.generation());
            let failed = cleanup_loaded(system, waits, loaded, group, true).is_err()
                | session
                    .jobs
                    .disconnect_session(launch_grant)
                    .map_or(true, |handle| system.close_handle(handle).is_err());
            return Err(if failed { InitError::Cleanup } else { error });
        }
    };
    if let Err(error) = session.jobs.attach_session_owner(
        launch_grant,
        SessionOwner {
            process: loaded.process,
            launch_channel: loaded.launch_channel,
            task_group: group,
        },
    ) {
        session.shell.poison(topology.generation());
        let failed = cleanup_loaded(system, waits, loaded, group, true).is_err()
            | session
                .jobs
                .disconnect_session(launch_grant)
                .map_or(true, |handle| system.close_handle(handle).is_err());
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Jobs(error)
        });
    }
    session.ready_deadline = ready_deadline;
    session.console = Some(InstalledPeer {
        grant: launch_grant,
        loaded,
        task_group: group,
    });
    session.console_transaction = transaction;
    session.awaiting_ready = true;
    session.bootstrap_released = false;
    Ok(())
}

pub(crate) fn clear_publication_observer<S: ResidentPlatform>(
    session: &mut ConsoleState,
    system: &mut S,
    registry_generation: u64,
    poison_registry: bool,
) -> Result<(), InitError> {
    if poison_registry {
        session.shell.poison(registry_generation);
    }
    let observer = session
        .publication_observer
        .take()
        .ok_or(InitError::AbsentState(0x88))?;
    system
        .close_handle(observer.client)
        .map_err(|_| InitError::Cleanup)
}

pub(crate) fn validate_publication_datagram(
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
    let parsed = parse_registry(bytes, 0)
        .map_err(|_| PollOutcome::RecoverRegistry(crate::abandoned::phase::PUBLICATION_DATAGRAM))?;
    let RegistryMessage::GenerationChanged { service_generation } = parsed.message else {
        return Err(PollOutcome::RecoverRegistry(
            crate::abandoned::phase::PUBLICATION_DATAGRAM,
        ));
    };
    if parsed.header != expected_header {
        return Err(PollOutcome::RecoverRegistry(
            crate::abandoned::phase::PUBLICATION_DATAGRAM,
        ));
    }
    if service_generation != observer.expected_service_generation
        || validated_at >= observer.deadline
    {
        return Err(PollOutcome::RecoverDevmgr);
    }
    Ok(())
}

pub(crate) fn poll_publication_observer_state<S, W>(
    session: &mut ConsoleState,
    current_driver: Option<DriverNativeAttempt>,
    registry_generation: u64,
    system: &mut S,
    waits: &mut W,
    now: u64,
) -> Result<Option<PollOutcome>, InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let Some(observer) = session.publication_observer else {
        return Ok(None);
    };
    if now >= observer.deadline {
        clear_publication_observer(session, system, registry_generation, false)?;
        return Ok(Some(PollOutcome::RecoverDevmgr));
    }
    let item = DwWaitItemV1 {
        handle: observer.client,
        signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
    };
    let observed = match system.wait_many(core::slice::from_ref(&item), DwDeadline(now)) {
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => return Ok(None),
        Err(error) => {
            let cleanup = clear_publication_observer(session, system, registry_generation, false);
            return Err(if cleanup.is_err() {
                InitError::Cleanup
            } else {
                InitError::Native(error)
            });
        }
        Ok(observed) => observed,
    };
    if observed.index != 0 {
        clear_publication_observer(session, system, registry_generation, true)?;
        return Ok(Some(PollOutcome::RecoverRegistry(
            crate::abandoned::phase::PUBLICATION_OBSERVER,
        )));
    }
    if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
        clear_publication_observer(session, system, registry_generation, true)?;
        return Ok(Some(PollOutcome::RecoverRegistry(
            crate::abandoned::phase::PUBLICATION_OBSERVER,
        )));
    }
    if observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        clear_publication_observer(session, system, registry_generation, true)?;
        return Ok(Some(PollOutcome::RecoverRegistry(
            crate::abandoned::phase::PUBLICATION_OBSERVER,
        )));
    }
    let mut bytes = [0u8; 256];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = match system.receive_channel(observer.client, &mut bytes, &mut handles) {
        Ok(counts) => counts,
        Err(_) => {
            clear_publication_observer(session, system, registry_generation, true)?;
            return Ok(Some(PollOutcome::RecoverRegistry(
                crate::abandoned::phase::PUBLICATION_OBSERVER,
            )));
        }
    };
    if counts.bytes > bytes.len() || counts.handles > handles.len() {
        let received_cleanup = close_received_native(system, &handles, counts.handles);
        let observer_cleanup =
            clear_publication_observer(session, system, registry_generation, true);
        return if received_cleanup.is_err() || observer_cleanup.is_err() {
            Err(InitError::Cleanup)
        } else {
            Ok(Some(PollOutcome::RecoverRegistry(
                crate::abandoned::phase::PUBLICATION_OBSERVER,
            )))
        };
    }
    if counts.handles != 0 {
        let received_cleanup = close_received_native(system, &handles, counts.handles);
        let observer_cleanup =
            clear_publication_observer(session, system, registry_generation, true);
        return if received_cleanup.is_err() || observer_cleanup.is_err() {
            Err(InitError::Cleanup)
        } else {
            Ok(Some(PollOutcome::RecoverRegistry(
                crate::abandoned::phase::PUBLICATION_OBSERVER,
            )))
        };
    }
    let validated_at = match system.now() {
        Ok(validated_at) => validated_at,
        Err(error) => {
            let cleanup = clear_publication_observer(session, system, registry_generation, false);
            return Err(if cleanup.is_err() {
                InitError::Cleanup
            } else {
                InitError::Native(error)
            });
        }
    };
    if session.shell.recovery_deadline_expired(validated_at) {
        let cleanup = clear_publication_observer(session, system, registry_generation, false);
        return if cleanup.is_err() {
            Err(InitError::Cleanup)
        } else {
            let expired = Err(InitError::Supervision);
            attribute_failure(RecoveryOperation::RebindPublication, expired)
        };
    }
    if let Err(outcome) =
        validate_publication_datagram(observer, &bytes[..counts.bytes], validated_at)
    {
        clear_publication_observer(
            session,
            system,
            registry_generation,
            matches!(outcome, PollOutcome::RecoverRegistry(_)),
        )?;
        return Ok(Some(outcome));
    }
    let current = match current_driver {
        Some(current) => current,
        None => {
            clear_publication_observer(session, system, registry_generation, false)?;
            return Ok(Some(PollOutcome::RecoverDevmgr));
        }
    };
    let info = match waits.query_task_termination(current.loaded.process) {
        Ok(info) => info,
        Err(error) => {
            let cleanup = clear_publication_observer(session, system, registry_generation, false);
            return Err(if cleanup.is_err() {
                InitError::Cleanup
            } else {
                InitError::Native(error)
            });
        }
    };
    if current.request != observer.expected_driver || info.state != DW_TASK_STATE_RUNNING {
        clear_publication_observer(session, system, registry_generation, false)?;
        return Ok(Some(PollOutcome::RecoverDevmgr));
    }
    clear_publication_observer(session, system, registry_generation, false)?;
    Ok(Some(PollOutcome::LaunchConsole))
}

pub(crate) fn poll_publication_observer<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
    now: u64,
) -> Result<Option<PollOutcome>, InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let state = resident
        .product
        .as_mut()
        .ok_or(InitError::AbsentState(0x89))?;
    let registry_generation = state.topology.generation();
    let current_driver = state.driver;
    let session = state.session.as_mut().ok_or(InitError::AbsentState(0x8a))?;
    poll_publication_observer_state(
        session,
        current_driver,
        registry_generation,
        system,
        waits,
        now,
    )
}

pub(crate) fn handle_console_process_exit<S, W>(
    session: &mut ConsoleState,
    system: &mut S,
    waits: &mut W,
    defer_to_coordinated_retirement: bool,
) -> Result<PollOutcome, InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    // Recovery retires the console session, process, and task group as one
    // ownership unit. An independently observed process exit must not consume
    // that unit before the resident recovery path reaches its join.
    if defer_to_coordinated_retirement {
        return Ok(PollOutcome::Stable);
    }
    let peer = session.console.take().ok_or(InitError::AbsentState(0x8b))?;
    session.awaiting_ready = false;
    session.bootstrap_released = false;
    session.console_transaction = 0;
    let cleanup = retire_console_product(system, waits, &mut session.jobs, peer, false);
    cleanup?;
    // Whether this ends the session is `conclude_session`'s decision, not
    // this route's: see there.
    Ok(PollOutcome::LaunchConsole)
}

/// F3A.7j. The one place a console departure is turned into a finished
/// session.
///
/// Init sees consoled leave by two routes -- its launch session closing in
/// the job dispatcher, and its process exiting -- and which one a tick reaches
/// first is timing. F3A.7g put the session-ended check on the process-exit
/// route alone, so a run whose session closed first relaunched the console
/// it had just been told to stop (F3A.7 run 7, `0xAF18_0E04`). Deciding here,
/// on whatever `poll` concluded, covers every route including any added
/// later.
///
/// Both routes answer `LaunchConsole` only after the console is retired and
/// return an error if the retirement failed, so a `SessionComplete` from here
/// never stands for a teardown that did not finish. The latch is always set
/// before either route can fire: consoled exits only after receiving the
/// shell's terminal result, and the latch is set as that result is sent.
pub(crate) const fn conclude_session(outcome: PollOutcome, session_shutdown: bool) -> PollOutcome {
    match outcome {
        PollOutcome::LaunchConsole if session_shutdown => PollOutcome::SessionComplete,
        outcome => outcome,
    }
}

pub(crate) fn poll_console_event<S: ResidentPlatform>(
    system: &mut S,
    console: LoadedProcess,
    bootstrap_released: bool,
    defer_to_coordinated_retirement: bool,
    now: u64,
) -> Result<Option<DwWaitResultV1>, NativeError> {
    let items = [
        DwWaitItemV1 {
            handle: console.process,
            signals: DW_SIGNAL_EXITED,
        },
        DwWaitItemV1 {
            handle: console.launch_channel,
            signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        },
    ];
    // A retained process exit is level-triggered. Once recovery owns its
    // retirement, waiting on it would repeatedly select the first item and
    // starve a committed control reply needed by that same recovery action.
    let first = usize::from(defer_to_coordinated_retirement);
    let end = if bootstrap_released { 1 } else { 2 };
    if first == end {
        return Ok(None);
    }
    match system.wait_many(&items[first..end], DwDeadline(now)) {
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => Ok(None),
        Err(error) => Err(error),
        Ok(mut observed) => {
            // Keep the caller's process/control indices independent of which
            // owner is currently responsible for process retirement.
            observed.index += first as u32;
            Ok(Some(observed))
        }
    }
}

/// The lowest site number in `wyr1e_native.rs`'s absent-owner block.
///
/// Sites `0xa0..=0xbf` are this block: the base or'd with a five-bit mask of
/// which owner slots of `ResidentState` were empty. The base is aligned to the
/// mask width so the two cannot overlap; `0x98..=0x9f` stay free for ordinary
/// single sites.
pub(crate) const ABSENT_OWNER_SITE_BASE: u8 = 0xa0;

/// Which of the resident state's owner slots are empty, as one site number.
///
/// F3A.6e left a contradiction this exists to settle. `poll` reported site
/// `0x8d` -- `registry` absent -- while that field is assigned `Some` at every
/// non-test site and its only `take()` sits behind `dw1e3-selector31`, which
/// an F product does not compile. A bare "the registry is missing" cannot
/// distinguish a state whose registry alone was cleared from one that was
/// rebuilt or zeroed wholesale, and the two have different causes. Reporting
/// the siblings separates them in a single boot.
///
/// Per `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` §5 the encoding is bounded and
/// total: all thirty-two combinations are representable, so no value has to be
/// read as at-the-limit.
pub(crate) fn absent_owner_site(state: &ResidentState) -> u8 {
    let mut absent = 0u8;
    if state.registry.is_none() {
        absent |= 0x01;
    }
    if state.session.is_none() {
        absent |= 0x02;
    }
    if state.devmgr.is_none() {
        absent |= 0x04;
    }
    if state.binding.is_none() {
        absent |= 0x08;
    }
    if state.driver.is_none() {
        absent |= 0x10;
    }
    ABSENT_OWNER_SITE_BASE | absent
}

pub(super) fn poll<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    now: u64,
) -> Result<PollOutcome, InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let outcome = poll_observations(resident, system, loader, waits, now)?;
    let session_shutdown = resident
        .product
        .as_ref()
        .and_then(|state| state.session.as_ref())
        .is_some_and(|session| session.shell.session_shutdown());
    Ok(conclude_session(outcome, session_shutdown))
}

pub(crate) fn poll_observations<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    now: u64,
) -> Result<PollOutcome, InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let publication = poll_publication_observer(resident, system, waits, now);
    let publication = attribute_failure(RecoveryOperation::RebindPublication, publication);
    if let Some(outcome) = publication? {
        return Ok(outcome);
    }
    let authority = resident.authority;
    let state = resident
        .product
        .as_mut()
        .ok_or(InitError::AbsentState(0x8c))?;
    let registry = match state.registry {
        Some(registry) => registry,
        // Not `ok_or(AbsentState(0x8d))`. F3A.6e reported that bare site from
        // here on a path where the slot cannot be empty, so the site now says
        // which of the state's siblings are empty too.
        None => return Err(InitError::AbsentState(absent_owner_site(state))),
    };
    let session = state.session.as_mut().ok_or(InitError::AbsentState(0x8e))?;
    let poll_shell_jobs = true;
    if poll_shell_jobs {
        let dispatcher_result = {
            let mut shell = ShellLaunchContext {
                registry_control: registry.control_channel,
                topology: &mut state.topology,
                state: &mut session.shell,
            };
            poll_job_dispatcher_with_shell(
                system,
                loader,
                waits,
                authority,
                &mut session.jobs,
                now,
                &mut shell,
            )
        };
        let dispatcher_outcome = match dispatcher_result {
            Ok(outcome) => outcome,
            Err(error) => {
                return if matches!(
                    session.shell.health(),
                    crate::ShellRegistryHealth::Poisoned { .. }
                ) {
                    Ok(PollOutcome::RecoverRegistry(
                        crate::abandoned::phase::DISPATCHER_POISONED,
                    ))
                } else {
                    Err(error)
                };
            }
        };
        if let Some(outcome) = reconcile_job_dispatcher_outcome(session, dispatcher_outcome)? {
            return Ok(outcome);
        }
    }
    if session.awaiting_ready && now >= session.ready_deadline {
        retire_current_console(session, system, waits, state.topology.generation(), true)?;
        return Ok(PollOutcome::RecoverRegistry(
            crate::abandoned::phase::READY_DEADLINE_BEFORE_WAIT,
        ));
    }
    let Some(console) = session.console else {
        return Ok(PollOutcome::Stable);
    };
    let defer_to_coordinated_retirement = false;
    let observed = match poll_console_event(
        system,
        console.loaded,
        session.bootstrap_released,
        defer_to_coordinated_retirement,
        now,
    ) {
        Ok(None) => {
            if session.awaiting_ready && now >= session.ready_deadline {
                retire_current_console(session, system, waits, state.topology.generation(), true)?;
                return Ok(PollOutcome::RecoverRegistry(
                    crate::abandoned::phase::READY_DEADLINE_AFTER_WAIT,
                ));
            }
            return Ok(PollOutcome::Stable);
        }
        Err(error) => return Err(InitError::Native(error)),
        Ok(Some(observed)) => observed,
    };
    if observed.index == 0 && observed.observed.0 & DW_SIGNAL_EXITED.0 != 0 {
        return handle_console_process_exit(
            session,
            system,
            waits,
            defer_to_coordinated_retirement,
        );
    }
    if observed.index != 1 {
        retire_current_console(session, system, waits, state.topology.generation(), true)?;
        return Ok(PollOutcome::RecoverRegistry(
            crate::abandoned::phase::CONSOLE_WAIT_INDEX,
        ));
    }
    if observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 {
        if !session.awaiting_ready {
            retire_current_console(session, system, waits, state.topology.generation(), true)?;
            return Ok(PollOutcome::RecoverRegistry(
                crate::abandoned::phase::CONSOLE_UNSOLICITED,
            ));
        }
        let mut bytes = [0u8; 64];
        let mut handles = [DwReceivedHandleInfoV1::default(); 1];
        let counts =
            match system.receive_channel(console.loaded.launch_channel, &mut bytes, &mut handles) {
                Ok(counts) => counts,
                // F3A.6j. This arm is why the F bring-up took six boots to
                // locate: it discarded the kernel status that says why the
                // console's own message could not be received, retired the
                // console, and reported a *registry* recovery. The failure
                // then spent the registry's restart budget and surfaced as an
                // abandoned registry, four ticks and two indirections from
                // the actual refusal.
                //
                // The console wait twenty lines above already preserves its
                // native error; this one did not, and this one is the one
                // that fires. `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` §3.2:
                // the instance is owed to the reader's channel, and the
                // process exit status is that channel.
                //
                // Attributed here rather than left to the tick, because
                // `attribute_failure` keeps the innermost operation: the
                // reader gets `ActivateConsole` and the status, not
                // `ResidentTick` and the status.
                Err(error) => {
                    // A cleanup failure supersedes, per the same shape the
                    // READY-validation arm below already uses. The receive's
                    // own status survives whenever cleanup completes. Written
                    // as a returned `Result` rather than an unwrapped error so
                    // the product carries no panic path for it.
                    let cleanup = retire_current_console(
                        session,
                        system,
                        waits,
                        state.topology.generation(),
                        true,
                    );
                    let failed: Result<PollOutcome, InitError> = Err(InitError::Native(error));
                    return if cleanup.is_err() {
                        Err(InitError::Cleanup)
                    } else {
                        attribute_failure(RecoveryOperation::ActivateConsole, failed)
                    };
                }
            };
        if counts.handles != 0 {
            let received_cleanup = close_received_native(system, &handles, counts.handles);
            let console_cleanup =
                retire_current_console(session, system, waits, state.topology.generation(), true);
            return if received_cleanup.is_err() || console_cleanup.is_err() {
                Err(InitError::Cleanup)
            } else {
                Ok(PollOutcome::RecoverRegistry(
                    crate::abandoned::phase::CONSOLE_UNEXPECTED_HANDLES,
                ))
            };
        }
        if wyrmroot_loader::launch::parse_ready_for_profile(
            LaunchProfile::Consoled,
            &bytes[..counts.bytes],
            session.console_transaction,
        )
        .is_err()
        {
            retire_current_console(session, system, waits, state.topology.generation(), true)?;
            return Ok(PollOutcome::RecoverRegistry(
                crate::abandoned::phase::CONSOLE_READY_INVALID,
            ));
        }
        let validated_at = match system.now() {
            Ok(validated_at) => validated_at,
            Err(error) => {
                let cleanup = retire_current_console(
                    session,
                    system,
                    waits,
                    state.topology.generation(),
                    true,
                );
                return Err(if cleanup.is_err() {
                    InitError::Cleanup
                } else {
                    InitError::Native(error)
                });
            }
        };
        if validated_at >= session.ready_deadline {
            retire_current_console(session, system, waits, state.topology.generation(), true)?;
            if session.shell.recovery_deadline_expired(validated_at) {
                let expired = Err(InitError::Supervision);
                let expired = attribute_failure(RecoveryOperation::ActionDeadline, expired);
                return expired;
            }
            return Ok(PollOutcome::RecoverRegistry(
                crate::abandoned::phase::CONSOLE_RECOVERY_LIVE,
            ));
        }
        session.awaiting_ready = false;
        return Ok(PollOutcome::Stable);
    }
    if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 && !session.awaiting_ready {
        session.bootstrap_released = true;
        return Ok(PollOutcome::Stable);
    }
    retire_current_console(session, system, waits, state.topology.generation(), true)?;
    Ok(PollOutcome::RecoverRegistry(
        crate::abandoned::phase::CONSOLE_EVENT_UNMATCHED,
    ))
}

/// The deadline of the recovery episode in flight, if one is open.
///
/// Ordinary supervision state since R7B-1. A build that never opens an episode
/// reads `None` here, which is what the removed `not(wyr1e8-selector33)` arms
/// wrote by hand at every call site.
pub(super) fn recovery_deadline(resident: &ResidentSystemInit) -> Result<Option<u64>, InitError> {
    Ok(resident
        .product
        .as_ref()
        .and_then(|state| state.session.as_ref())
        .ok_or(InitError::AbsentState(0x91))?
        .shell
        .recovery_deadline())
}

/// Refuses to continue a recovery leg once its episode's budget has passed.
///
/// With no episode open this is `Ok(())` without reading the clock.
pub(super) fn ensure_recovery_live(
    resident: &ResidentSystemInit,
    now: u64,
) -> Result<(), InitError> {
    let state = resident
        .product
        .as_ref()
        .and_then(|state| state.session.as_ref())
        .ok_or(InitError::AbsentState(0x92))?;
    let live = state.shell.require_recovery_live_at(now);
    // The cause tag stays selector-gated: carrying which leg failed is class C
    // of the R7A inventory and is R7B's next increment, not this one.
    attribute_failure(RecoveryOperation::ActionDeadline, live)
}

pub(crate) fn retire_current_console<S, W>(
    session: &mut ConsoleState,
    system: &mut S,
    waits: &mut W,
    registry_generation: u64,
    poison_registry: bool,
) -> Result<(), InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    if poison_registry {
        session.shell.poison(registry_generation);
    }
    let Some(peer) = session.console.take() else {
        return Ok(());
    };
    session.awaiting_ready = false;
    session.bootstrap_released = false;
    session.console_transaction = 0;

    retire_console_product(system, waits, &mut session.jobs, peer, true)
}

/// Releases what the job dispatcher still holds, for a session that ended.
///
/// F3A.7g. The console product is already retired by the time this runs --
/// `handle_console_process_exit` did it, because a console that ended the
/// session is released exactly like one that crashed -- so what is left here
/// is whatever the dispatcher itself still owns: sessions nothing reconnects
/// to, and jobs whose owner is gone. `drain_job_dispatcher` is the same drain
/// a fatal tick uses; the difference is only that nothing follows it.
pub(super) fn drain_jobs_for_shutdown<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
) -> Result<(), InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let Some(state) = resident.product.as_mut() else {
        return Ok(());
    };
    let Some(session) = state.session.as_mut() else {
        return Ok(());
    };
    let observer_failed = session
        .publication_observer
        .take()
        .is_some_and(|observer| system.close_handle(observer.client).is_err());
    let drained = crate::drain_job_dispatcher(system, waits, &mut session.jobs);
    if observer_failed {
        return Err(InitError::Cleanup);
    }
    drained
}

pub(super) fn retire_dependents<S, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    waits: &mut W,
    poison_registry: bool,
) -> Result<(), InitError>
where
    S: ResidentPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let state = resident
        .product
        .as_mut()
        .ok_or(InitError::AbsentState(0x93))?;
    let generation = state.topology.generation();
    let session = state.session.as_mut().ok_or(InitError::AbsentState(0x94))?;
    if poison_registry {
        session.shell.poison(generation);
    }
    let observer_failed = session
        .publication_observer
        .take()
        .is_some_and(|observer| system.close_handle(observer.client).is_err());
    let Some(peer) = session.console.take() else {
        return if observer_failed || { false } {
            Err(InitError::Cleanup)
        } else {
            Ok(())
        };
    };
    session.awaiting_ready = false;
    session.bootstrap_released = false;
    session.console_transaction = 0;
    let console_result = retire_console_product(system, waits, &mut session.jobs, peer, true);
    if observer_failed || console_result.is_err() || { false } {
        Err(InitError::Cleanup)
    } else {
        Ok(())
    }
}

/// Whether a console product is installed on the stream the current device
/// topology established.
///
/// `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` §5.3.1 item 4 makes this the condition
/// under which a devmgr generation change leaves the device topology beneath
/// it alone. It is a dependency fact, not a product or selector gate: a build
/// with no console product has no consumer, and reaps exactly as before.
pub(super) fn console_depends_on_driver(resident: &ResidentSystemInit) -> bool {
    resident.product.as_ref().is_some_and(|state| {
        state.driver.is_some()
            && state
                .session
                .as_ref()
                .is_some_and(|session| session.console.is_some())
    })
}

pub(super) fn reserve_registry_replacement(
    resident: &mut ResidentSystemInit,
    generation: u64,
) -> Result<(), InitError> {
    resident
        .product
        .as_mut()
        .and_then(|state| state.session.as_mut())
        .ok_or(InitError::AbsentState(0x96))?
        .shell
        .reserve_replacement_generation(generation)
}

pub(super) fn commit_registry_replacement(
    resident: &mut ResidentSystemInit,
    generation: u64,
) -> Result<(), InitError> {
    resident
        .product
        .as_mut()
        .and_then(|state| state.session.as_mut())
        .ok_or(InitError::AbsentState(0x97))?
        .commit_registry_replacement(generation)
}

#[cfg(test)]
mod tests;
