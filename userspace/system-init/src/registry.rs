//! The registry role: launch, topology, retirement and replacement.

use crate::job_sessions::LaunchSessionScope;
use crate::jobs::{EndpointGrant, JobError, RegistryTopology};
use crate::*;
use deepwyrm_syscall::{
    DW_HANDLE_TRANSFER_MOVE, DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_INSPECT, DW_RIGHT_READ,
    DW_RIGHT_TRANSFER, DW_RIGHT_WAIT, DW_RIGHT_WRITE, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE,
    DwHandleTransferV1, DwRights,
};
use wyrmroot_loader::launch::{CHILD_CHANNEL_RIGHTS, LaunchProfile};
use wyrmroot_registry_proto::{
    EnumerationScope, HEADER_BYTES as REGISTRY_HEADER_BYTES, Header as RegistryHeader,
    InstallClient, MAX_SERVICE_LIST_PAGES, Message as RegistryMessage,
    MessageType as RegistryMessageType, SERVICE_LIST_PREFIX_BYTES, SERVICE_LIST_RECORD_BYTES,
    encode_empty as encode_registry_empty, encode_install_client, parse as parse_registry_message,
};

pub(crate) use wyrmroot_bootfs::paths::REGISTRYD_PATH as REGISTRY_PATH;
pub(crate) const INSTALL_CLIENT_TRANSACTION: u64 = 3;
pub(crate) const CONTROLLER_CHANNEL_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_TRANSFER.0,
);
pub(crate) const WYRMSH_REGISTRY_DEADLINE_NS: u64 = 1_000_000_000;
pub(crate) const WYRMSH_FIRST_INSTALL_TRANSACTION: u64 = 0xE300_0001;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShellRegistryHealth {
    Healthy { generation: u64 },
    Poisoned { generation: u64 },
    Exhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ShellControllerState {
    pub(crate) health: ShellRegistryHealth,
    pub(crate) next_install_transaction: u64,
    pub(crate) replacement_attempts: u16,
    pub(crate) last_console_generation: u64,
    pub(crate) last_status_generation: u64,
    pub(crate) last_child_generation: u64,
    /// The deadline of the recovery episode in flight, if one is.
    ///
    /// R7B-1. Every recovery leg's own deadline is capped by this one and
    /// every step refuses to proceed past it, so an episode cannot outlive its
    /// budget by accumulating individually-legal legs. Nothing in the product
    /// opens an episode yet, so product builds hold `None` here and behave
    /// exactly as the removed `not(wyr1e8-selector33)` arms did: no cap, no
    /// expiry. What was selector-specific was never the property, only the one
    /// caller that asks for it.
    pub(crate) recovery_deadline: Option<u64>,
    /// Whether a console child ended the interactive session.
    ///
    /// F3A.7g. `wyrmsh` exits with
    /// `wyrmroot_launch_proto::SHELL_SESSION_SHUTDOWN_STATUS` when it was
    /// asked to end the session rather than merely to end itself, and this is
    /// where that status stops being a number on a wire. It is latched at the
    /// WAIT reply -- the one place init has the child's terminal result in
    /// hand -- and read at the console process exit that follows, which is
    /// otherwise indistinguishable from a console that crashed and has to be
    /// relaunched.
    ///
    /// Set once and never cleared. A session that ended cannot be un-ended by
    /// a later generation, and there is no later generation: nothing replaces
    /// the console after this.
    pub(crate) session_shutdown: bool,
}

impl ShellControllerState {
    pub(crate) fn new(registry_generation: u64) -> Result<Self, InitError> {
        if registry_generation == 0 {
            return Err(InitError::Accounting);
        }
        Ok(Self {
            health: ShellRegistryHealth::Healthy {
                generation: registry_generation,
            },
            next_install_transaction: WYRMSH_FIRST_INSTALL_TRANSACTION,
            replacement_attempts: 0,
            last_console_generation: 0,
            last_status_generation: 0,
            last_child_generation: 0,
            recovery_deadline: None,
            session_shutdown: false,
        })
    }

    /// Latches a console child's request to end the session.
    ///
    /// The caller has already established that the terminal result belongs to
    /// a `ConsoleLauncher` session and carries the shutdown status; this only
    /// remembers it.
    pub(crate) const fn observe_session_shutdown(&mut self) {
        self.session_shutdown = true;
    }

    #[must_use]
    pub(crate) const fn session_shutdown(&self) -> bool {
        self.session_shutdown
    }

    pub(crate) fn recovery_deadline_expired(&self, now: u64) -> bool {
        self.recovery_deadline
            .is_some_and(|deadline| now >= deadline)
    }

    pub(crate) fn recovery_deadline(&self) -> Option<u64> {
        self.recovery_deadline
    }

    pub(crate) fn cap_recovery_deadline(&self, deadline: u64) -> u64 {
        self.recovery_deadline
            .map_or(deadline, |episode| deadline.min(episode))
    }

    pub(crate) fn require_recovery_live_at(&self, now: u64) -> Result<(), InitError> {
        if self.recovery_deadline_expired(now) {
            Err(InitError::Supervision)
        } else {
            Ok(())
        }
    }

    pub(crate) const fn health(&self) -> ShellRegistryHealth {
        self.health
    }

    pub(crate) fn reserve_install_transaction(
        &mut self,
        generation: u64,
    ) -> Result<u64, InitError> {
        if self.health != (ShellRegistryHealth::Healthy { generation }) {
            return Err(InitError::Cleanup);
        }
        let transaction = self.next_install_transaction;
        self.next_install_transaction = transaction.checked_add(1).ok_or(InitError::Accounting)?;
        Ok(transaction)
    }

    pub(crate) fn reserve_shell_generation(
        &mut self,
        request: wyrmroot_launch_proto::ShellV1Request,
    ) -> Result<(), InitError> {
        if self.last_console_generation != 0
            && (request.console_generation < self.last_console_generation
                || request.status_generation <= self.last_status_generation
                || request.requested_child_generation <= self.last_child_generation)
        {
            return Err(InitError::Jobs(JobError::StaleGeneration));
        }
        self.last_console_generation = request.console_generation;
        self.last_status_generation = request.status_generation;
        self.last_child_generation = request.requested_child_generation;
        Ok(())
    }

    pub(crate) fn poison(&mut self, generation: u64) {
        if self.health == (ShellRegistryHealth::Healthy { generation }) {
            self.health = ShellRegistryHealth::Poisoned { generation };
        }
    }

    pub(crate) fn reserve_replacement_generation(
        &mut self,
        generation: u64,
    ) -> Result<(), InitError> {
        let ShellRegistryHealth::Poisoned {
            generation: previous,
        } = self.health
        else {
            return Err(InitError::WrongActivationOrder);
        };
        if generation <= previous {
            return Err(InitError::Accounting);
        }
        self.replacement_attempts = self
            .replacement_attempts
            .checked_add(1)
            .ok_or(InitError::Accounting)?;
        if self.replacement_attempts > u16::from(WYR0_I_SUPERVISION_POLICY.max_attempts) {
            self.health = ShellRegistryHealth::Exhausted;
            return Err(InitError::Cleanup);
        }
        Ok(())
    }

    pub(crate) fn commit_replacement_generation(
        &mut self,
        generation: u64,
    ) -> Result<(), InitError> {
        let ShellRegistryHealth::Poisoned {
            generation: previous,
        } = self.health
        else {
            return Err(InitError::WrongActivationOrder);
        };
        if generation <= previous {
            return Err(InitError::Accounting);
        }
        self.health = ShellRegistryHealth::Healthy { generation };
        self.next_install_transaction = WYRMSH_FIRST_INSTALL_TRANSACTION;
        Ok(())
    }
}

pub(crate) struct ShellLaunchContext<'a> {
    pub(crate) registry_control: DwHandle,
    pub(crate) topology: &'a mut RegistryTopology,
    pub(crate) state: &'a mut ShellControllerState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InstalledPeer {
    pub(crate) grant: EndpointGrant,
    pub(crate) loaded: LoadedProcess,
    pub(crate) task_group: DwHandle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JobDispatcherPollOutcome {
    Stable,
    SessionClosed {
        grant: EndpointGrant,
        scope: LaunchSessionScope,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RegistryNativeAttempt {
    pub(crate) active: ActiveNativeRole,
    pub(crate) control_channel: DwHandle,
    pub(crate) ready_at: u64,
}

#[cfg(test)]
pub(crate) const fn registry_native_attempt_for_fixture(
    active: ActiveNativeRole,
    control_channel: DwHandle,
    ready_at: u64,
) -> RegistryNativeAttempt {
    RegistryNativeAttempt {
        active,
        control_channel,
        ready_at,
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct StagedChannelPair {
    pub(crate) first: Option<DwHandle>,
    pub(crate) second: Option<DwHandle>,
}

impl StagedChannelPair {
    pub(crate) const fn new(first: DwHandle, second: DwHandle) -> Self {
        Self {
            first: Some(first),
            second: Some(second),
        }
    }

    pub(crate) fn second(&self) -> Result<DwHandle, InitError> {
        self.second.ok_or(InitError::Accounting)
    }

    pub(crate) fn commit_second_move(&mut self) -> Result<(), InitError> {
        self.second.take().map(|_| ()).ok_or(InitError::Accounting)
    }

    pub(crate) fn take_first(&mut self) -> Result<DwHandle, InitError> {
        self.first.take().ok_or(InitError::Accounting)
    }

    pub(crate) fn cleanup<S: InitPlatform>(&mut self, system: &mut S) -> bool {
        let mut failed = false;
        for slot in [&mut self.second, &mut self.first] {
            if let Some(handle) = slot.take() {
                failed |= system.close_handle(handle).is_err();
            }
        }
        !failed
    }
}

/// Validates the C1 retained closure while preserving the selector-27 gate's
/// separate marker/configuration contract.
///
/// The returned UART identity comes from the validated WRRM. Retained roles
/// intentionally remain outside [`SystemInit`]'s early-role launch API.
pub(crate) fn validate_retained_bootfs_c1(
    bytes: &[u8],
) -> Result<(SystemInit, [u8; 32]), InitError> {
    let archive = Archive::new(bytes).map_err(InitError::Bootfs)?;
    let manifest_entry = archive
        .lookup(MANIFEST_PATH.as_bytes())
        .map_err(map_lookup)?;
    let manifest_bytes = manifest_entry.data();
    let encoded_generation: [u8; 32] = manifest_bytes
        .get(48..80)
        .ok_or(InitError::Manifest(ManifestParseError::TruncatedHeader))?
        .try_into()
        .expect("checked WRRM generation slice");
    if encoded_generation == [0; 32] {
        return Err(InitError::ZeroBootGeneration);
    }
    let manifest = Manifest::parse_structural(manifest_bytes, &encoded_generation)
        .map_err(InitError::Manifest)?;
    let uart_identity = *manifest
        .role(RoleId::Uart16550d)
        .ok_or(InitError::WrongManifestProfile)?
        .executable_identity();
    let controller = SystemInit::from_manifest(manifest)?;
    for role in manifest.roles() {
        let entry = archive.lookup(role.path().as_bytes()).map_err(map_lookup)?;
        if !entry.is_executable() || entry.data().is_empty() {
            return Err(InitError::NonExecutableRole);
        }
        if wyrmroot_runtime::sha256::digest(entry.data()) != *role.executable_identity() {
            return Err(InitError::ArtifactIdentityMismatch(role.id()));
        }
    }
    let init = archive
        .lookup(SYSTEM_INIT_PATH.as_bytes())
        .map_err(map_lookup)?;
    if !init.is_executable() || init.data().is_empty() {
        return Err(InitError::NonExecutableRole);
    }
    for edge in manifest.edges() {
        if let Some(path) = edge.target_path() {
            archive.lookup(path.as_bytes()).map_err(map_lookup)?;
        }
    }
    Ok((controller, uart_identity))
}

pub(crate) fn install_client<S: ResidentPlatform>(
    system: &mut S,
    control: DwHandle,
    grant: EndpointGrant,
    registry_endpoint: DwHandle,
    client_id: u64,
) -> Result<(), InitError> {
    let mut bytes = [0u8; 104];
    let size = encode_install_client(
        RegistryHeader {
            message_type: RegistryMessageType::InstallClient,
            registry_generation: grant.registry_generation,
            endpoint_id: 0,
            endpoint_generation: 0,
            transaction_id: INSTALL_CLIENT_TRANSACTION,
        },
        InstallClient {
            endpoint_id: grant.endpoint_id,
            endpoint_generation: grant.endpoint_generation,
            client_id,
            client_generation: grant.role_generation,
            scope: EnumerationScope::None,
        },
        &mut bytes,
    )
    .map_err(InitError::RegistryProtocol)?;
    move_endpoint(system, control, &bytes[..size], registry_endpoint)
}

pub(crate) fn install_wyrmsh_registry_client<S: ResidentPlatform>(
    system: &mut S,
    control: DwHandle,
    grant: EndpointGrant,
    registry_endpoint: DwHandle,
    transaction_id: u64,
) -> Result<(), InitError> {
    let mut bytes = [0_u8; 104];
    let size = encode_install_client(
        RegistryHeader {
            message_type: RegistryMessageType::InstallClient,
            registry_generation: grant.registry_generation,
            endpoint_id: 0,
            endpoint_generation: 0,
            transaction_id,
        },
        InstallClient {
            endpoint_id: grant.endpoint_id,
            endpoint_generation: grant.endpoint_generation,
            // Registry client IDs cannot repeat within a registry generation,
            // even when a replacement consoled restarts its local counters.
            // The reserved init transaction survives that console replacement.
            client_id: transaction_id,
            client_generation: grant.role_generation,
            scope: EnumerationScope::BootstrapMetadata,
        },
        &mut bytes,
    )
    .map_err(InitError::RegistryProtocol)?;
    move_endpoint(system, control, &bytes[..size], registry_endpoint)
}

pub(crate) fn preflight_wyrmsh_registry<S: ResidentPlatform>(
    system: &mut S,
    client: DwHandle,
    grant: EndpointGrant,
    deadline_cap: Option<u64>,
) -> Result<(), InitError> {
    let now = system.now().map_err(InitError::Native)?;
    if deadline_cap.is_some_and(|deadline| now >= deadline) {
        return Err(InitError::Supervision);
    }
    let header = RegistryHeader {
        message_type: RegistryMessageType::Enumerate,
        registry_generation: grant.registry_generation,
        endpoint_id: grant.endpoint_id,
        endpoint_generation: grant.endpoint_generation,
        transaction_id: 1,
    };
    let mut request = [0_u8; REGISTRY_HEADER_BYTES];
    let request_size =
        encode_registry_empty(header, &mut request).map_err(InitError::RegistryProtocol)?;
    system
        .send_channel(client, &request[..request_size])
        .map_err(InitError::Native)?;
    let deadline = DwDeadline(
        now.checked_add(WYRMSH_REGISTRY_DEADLINE_NS)
            .map(|deadline| deadline_cap.map_or(deadline, |cap| deadline.min(cap)))
            .or(deadline_cap)
            .ok_or(InitError::Accounting)?,
    );
    let mut expected_page = 0_u16;
    let mut expected_page_count = None;
    let mut expected_total = None;
    let mut observed_total = 0_u16;
    let mut previous_name = [0_u8; wyrmroot_registry_proto::MAX_SERVICE_NAME_BYTES];
    let mut previous_name_len = 0_usize;
    loop {
        let observed = system
            .wait_many(
                core::slice::from_ref(&DwWaitItemV1 {
                    handle: client,
                    signals: deepwyrm_syscall::DwSignals(
                        DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0,
                    ),
                }),
                deadline,
            )
            .map_err(InitError::Native)?;
        if deadline_cap.is_some_and(|deadline| system.now().map_or(true, |now| now >= deadline)) {
            return Err(InitError::Supervision);
        }
        if observed.index != 0
            || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0
            || observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0
        {
            return Err(InitError::Supervision);
        }
        let mut bytes = [0_u8;
            SERVICE_LIST_PREFIX_BYTES
                + wyrmroot_registry_proto::MAX_SERVICE_LIST_RECORDS * SERVICE_LIST_RECORD_BYTES];
        let mut handles = [DwReceivedHandleInfoV1::default(); 1];
        let counts = system
            .receive_channel(client, &mut bytes, &mut handles)
            .map_err(InitError::Native)?;
        if counts.bytes > bytes.len() || counts.handles != 0 {
            if counts.handles != 0 && handles[0].handle.0 != 0 {
                system
                    .close_handle(handles[0].handle)
                    .map_err(|_| InitError::Cleanup)?;
            }
            return Err(InitError::RegistryProtocol(
                wyrmroot_registry_proto::Error::WrongHandleCount,
            ));
        }
        let parsed = parse_registry_message(&bytes[..counts.bytes], counts.handles)
            .map_err(InitError::RegistryProtocol)?;
        if parsed.header.registry_generation != grant.registry_generation
            || parsed.header.endpoint_id != grant.endpoint_id
            || parsed.header.endpoint_generation != grant.endpoint_generation
            || parsed.header.transaction_id != 1
        {
            return Err(InitError::ResourceIdentityMismatch);
        }
        let RegistryMessage::ServiceList(page) = parsed.message else {
            return Err(InitError::WrongManifestProfile);
        };
        if page.page_index != expected_page
            || expected_page_count.is_some_and(|count| count != page.page_count)
            || expected_total.is_some_and(|count| count != page.total_count)
        {
            return Err(InitError::WrongManifestProfile);
        }
        expected_page_count = Some(page.page_count);
        expected_total = Some(page.total_count);
        for index in 0..usize::from(page.record_count) {
            let record = page.record(index).ok_or(InitError::WrongManifestProfile)?;
            if previous_name_len != 0 && previous_name[..previous_name_len] >= *record.service_name
            {
                return Err(InitError::WrongManifestProfile);
            }
            previous_name[..record.service_name.len()].copy_from_slice(record.service_name);
            previous_name_len = record.service_name.len();
        }
        observed_total = observed_total
            .checked_add(page.record_count)
            .ok_or(InitError::Accounting)?;
        expected_page = expected_page.checked_add(1).ok_or(InitError::Accounting)?;
        if expected_page == page.page_count {
            if observed_total != page.total_count {
                return Err(InitError::WrongManifestProfile);
            }
            return Ok(());
        }
        if usize::from(expected_page) >= MAX_SERVICE_LIST_PAGES {
            return Err(InitError::WrongManifestProfile);
        }
    }
}

pub(crate) fn move_endpoint<S: ResidentPlatform>(
    system: &mut S,
    control: DwHandle,
    bytes: &[u8],
    endpoint: DwHandle,
) -> Result<(), InitError> {
    validate_controller_channel(system, endpoint)?;
    let transfer = DwHandleTransferV1 {
        handle: endpoint,
        requested_rights: CHILD_CHANNEL_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    system
        .send_channel_with_handles(control, bytes, core::slice::from_ref(&transfer))
        .map_err(InitError::Native)
}

pub(crate) fn validate_controller_channel<S: InitPlatform>(
    system: &mut S,
    handle: DwHandle,
) -> Result<(), InitError> {
    let info = system
        .query_capability_info(handle)
        .map_err(InitError::Native)?;
    if info.object_type != DW_OBJECT_TYPE_CHANNEL || info.rights != CONTROLLER_CHANNEL_RIGHTS {
        return Err(InitError::ResourceIdentityMismatch);
    }
    Ok(())
}

pub(crate) fn create_controller_channel_pair<S: ResidentPlatform>(
    system: &mut S,
) -> Result<(DwHandle, DwHandle), InitError> {
    system
        .channel_create(CONTROLLER_CHANNEL_RIGHTS)
        .map_err(InitError::Native)
}

pub(crate) fn launch_registry<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    controller: &mut SystemInit,
    authority: LoadAuthority,
    bootfs: &[u8],
    deadline_cap: Option<u64>,
) -> Result<RegistryNativeAttempt, InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    if let Some(deadline) = deadline_cap {
        let now = system.now().map_err(InitError::Native)?;
        if now >= deadline {
            return Err(InitError::Supervision);
        }
    }
    let RestartState::Starting {
        generation,
        transaction_id,
        ..
    } = controller
        .role_state(RoleId::Registryd)
        .ok_or(InitError::WrongActivationOrder)?
    else {
        return Err(InitError::WrongActivationOrder);
    };
    let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
    let image = archive
        .lookup(REGISTRY_PATH.as_bytes())
        .map_err(map_lookup)?;
    let executable_identity = controller.executable_identity(RoleId::Registryd)?;
    if !image.is_executable()
        || wyrmroot_runtime::sha256::digest(image.data()) != executable_identity
    {
        return Err(InitError::ArtifactIdentityMismatch(RoleId::Registryd));
    }
    if let Some(deadline) = deadline_cap {
        let now = system.now().map_err(InitError::Native)?;
        if now >= deadline {
            return Err(InitError::Supervision);
        }
    }
    let task_group = system
        .create_attempt_task_group(authority.task_group)
        .map_err(InitError::Native)?;
    let reservation =
        match controller.reserve_attempt(RoleId::Registryd, generation, transaction_id) {
            Ok(reservation) => reservation,
            Err(error) => {
                return Err(if system.close_handle(task_group).is_err() {
                    InitError::Cleanup
                } else {
                    error
                });
            }
        };
    let mut channels = match create_controller_channel_pair(system) {
        Ok((first, second)) => StagedChannelPair::new(first, second),
        Err(error) => {
            let close_failed = system.close_handle(task_group).is_err();
            let release_failed = controller.abort_reservation(reservation).is_err();
            return Err(if close_failed || release_failed {
                InitError::Cleanup
            } else {
                error
            });
        }
    };
    let child_control = channels.second()?;
    if let Err(error) = validate_controller_channel(system, child_control) {
        let mut failed = !channels.cleanup(system);
        failed |= system.close_handle(task_group).is_err();
        failed |= controller.abort_reservation(reservation).is_err();
        return Err(if failed { InitError::Cleanup } else { error });
    }
    let loaded = match load_service_process(
        loader,
        LoadAuthority {
            task_group,
            ..authority
        },
        ServiceLoadRequest {
            image: image.data(),
            display_path: REGISTRY_PATH,
            profile: LaunchProfile::BootstrapRegistry,
            service_channel: child_control,
            correlation: None,
            transaction_id,
        },
    ) {
        Ok(loaded) => loaded,
        Err(failure) => {
            if failure.service_channel_consumed {
                channels.commit_second_move()?;
            }
            let control_failed = !channels.cleanup(system);
            let group_failed = system.close_handle(task_group).is_err();
            let release_failed = controller.abort_reservation(reservation).is_err();
            return Err(if control_failed || group_failed || release_failed {
                InitError::Cleanup
            } else {
                InitError::Loader(failure.error)
            });
        }
    };
    channels.commit_second_move()?;
    let started_at = match system.now().map_err(InitError::Native) {
        Ok(now) => now,
        Err(error) => {
            let mut failed =
                cleanup_loaded_before(system, waits, loaded, task_group, true, deadline_cap)
                    .is_err();
            failed |= !channels.cleanup(system);
            failed |= controller.abort_reservation(reservation).is_err();
            return Err(if failed { InitError::Cleanup } else { error });
        }
    };
    if deadline_cap.is_some_and(|deadline| started_at >= deadline) {
        let mut failed =
            cleanup_loaded_before(system, waits, loaded, task_group, true, deadline_cap).is_err();
        failed |= !channels.cleanup(system);
        failed |= controller.abort_reservation(reservation).is_err();
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Supervision
        });
    }
    let deadline = match started_at.checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns) {
        Some(deadline) => deadline_cap.map_or(deadline, |cap| deadline.min(cap)),
        None => {
            let mut failed =
                cleanup_loaded_before(system, waits, loaded, task_group, true, deadline_cap)
                    .is_err();
            failed |= !channels.cleanup(system);
            failed |= controller.abort_reservation(reservation).is_err();
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Accounting
            });
        }
    };
    let resources = AttemptResources {
        role: RoleId::Registryd,
        generation,
        transaction_id,
        executable_identity,
        startup_profile: StartupProfile::BootstrapRegistry,
        task_group,
        process: loaded.process,
        launch_channel: loaded.launch_channel,
        mappings: 0,
        reservation,
    };
    if let Err(error) = controller.install_attempt(resources) {
        let cleanup = cleanup_loaded_before(system, waits, loaded, task_group, true, deadline_cap);
        let control_failed = !channels.cleanup(system);
        return Err(if cleanup.is_err() || control_failed {
            InitError::Cleanup
        } else {
            error
        });
    }
    let control_channel = channels.take_first()?;
    if let Err(error) =
        controller.child_started(RoleId::Registryd, generation, transaction_id, started_at)
    {
        return Err(reconcile_failed_registry_launch(
            system,
            waits,
            controller,
            loaded,
            task_group,
            control_channel,
            generation,
            transaction_id,
            started_at,
            AttemptFailure::CreationFailed,
            error,
            deadline_cap,
        ));
    }
    if let Err(_error) = await_child_ready_profile_observed(
        waits,
        loaded.process,
        loaded.launch_channel,
        LaunchProfile::BootstrapRegistry,
        transaction_id,
        DwDeadline(deadline),
    ) {
        return Err(reconcile_failed_registry_launch(
            system,
            waits,
            controller,
            loaded,
            task_group,
            control_channel,
            generation,
            transaction_id,
            started_at,
            AttemptFailure::WaitFailed,
            InitError::Supervision,
            deadline_cap,
        ));
    }
    let ready_at = match system.now().map_err(InitError::Native) {
        Ok(now) => now,
        Err(error) => {
            return Err(reconcile_failed_registry_launch(
                system,
                waits,
                controller,
                loaded,
                task_group,
                control_channel,
                generation,
                transaction_id,
                started_at,
                AttemptFailure::WaitFailed,
                error,
                deadline_cap,
            ));
        }
    };
    if deadline_cap.is_some_and(|deadline| ready_at >= deadline) {
        return Err(reconcile_failed_registry_launch(
            system,
            waits,
            controller,
            loaded,
            task_group,
            control_channel,
            generation,
            transaction_id,
            ready_at,
            AttemptFailure::WaitFailed,
            InitError::Supervision,
            deadline_cap,
        ));
    }
    if let Err(error) = controller.ready(RoleId::Registryd, generation, transaction_id, ready_at) {
        return Err(reconcile_failed_registry_launch(
            system,
            waits,
            controller,
            loaded,
            task_group,
            control_channel,
            generation,
            transaction_id,
            ready_at,
            AttemptFailure::WaitFailed,
            error,
            deadline_cap,
        ));
    }
    let installed_generation = match controller
        .resources(RoleId::Registryd)
        .map(|resources| resources.generation)
    {
        Some(generation) => generation,
        None => {
            return Err(reconcile_failed_registry_launch(
                system,
                waits,
                controller,
                loaded,
                task_group,
                control_channel,
                generation,
                transaction_id,
                ready_at,
                AttemptFailure::WaitFailed,
                InitError::MissingAttemptResources,
                deadline_cap,
            ));
        }
    };
    if installed_generation != generation {
        return Err(reconcile_failed_registry_launch(
            system,
            waits,
            controller,
            loaded,
            task_group,
            control_channel,
            generation,
            transaction_id,
            ready_at,
            AttemptFailure::WaitFailed,
            InitError::ResourceIdentityMismatch,
            deadline_cap,
        ));
    }
    Ok(RegistryNativeAttempt {
        active: ActiveNativeRole {
            role: RoleId::Registryd,
            generation,
            transaction_id,
            loaded,
            task_group,
        },
        control_channel,
        ready_at,
    })
}

pub(crate) fn establish_registry_topology<S, W>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    registry: RegistryNativeAttempt,
) -> Result<(RegistryNativeAttempt, RegistryTopology), InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    match RegistryTopology::new(registry.active.generation).map_err(InitError::Jobs) {
        Ok(topology) => Ok((registry, topology)),
        Err(error) => Err(reconcile_failed_registry_launch(
            system,
            waits,
            controller,
            registry.active.loaded,
            registry.active.task_group,
            registry.control_channel,
            registry.active.generation,
            registry.active.transaction_id,
            registry.ready_at,
            AttemptFailure::WaitFailed,
            error,
            None,
        )),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn reconcile_failed_registry_launch<
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    loaded: LoadedProcess,
    task_group: DwHandle,
    control_channel: DwHandle,
    generation: u64,
    transaction_id: u64,
    classified_at: u64,
    failure: AttemptFailure,
    original: InitError,
    deadline_cap: Option<u64>,
) -> InitError {
    let transition = match controller.role_state(RoleId::Registryd) {
        Some(RestartState::Starting { .. }) | Some(RestartState::Ready { .. }) => controller.fail(
            RoleId::Registryd,
            generation,
            transaction_id,
            classified_at,
            failure,
        ),
        Some(RestartState::AwaitingReady { .. }) => controller.ready_wait_failed(
            RoleId::Registryd,
            generation,
            transaction_id,
            classified_at,
            failure,
        ),
        _ => Err(InitError::WrongActivationOrder),
    };
    if transition.is_err() {
        let _ = cleanup_loaded_before(system, waits, loaded, task_group, true, deadline_cap);
        let _ = system.close_handle(control_channel);
        controller.fatal();
        return InitError::Cleanup;
    }
    let cleanup_failed =
        cleanup_loaded_before(system, waits, loaded, task_group, true, deadline_cap).is_err()
            | system.close_handle(control_channel).is_err();
    let completed_at = match system.now() {
        Ok(value) => value,
        Err(_) => {
            controller.fatal();
            return InitError::Cleanup;
        }
    };
    let retired_at = match classified_at.checked_add(1) {
        Some(value) => value.max(completed_at),
        None => {
            controller.fatal();
            return InitError::Accounting;
        }
    };
    if cleanup_failed {
        let _ =
            controller.cleanup_failed(RoleId::Registryd, generation, transaction_id, retired_at);
        return InitError::Cleanup;
    }
    match controller.cleanup_complete(RoleId::Registryd, generation, transaction_id, retired_at) {
        Ok(()) => original,
        Err(_) => {
            controller.fatal();
            InitError::Cleanup
        }
    }
}

pub(crate) fn launch_registry_until_ready<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    controller: &mut SystemInit,
    authority: LoadAuthority,
    bootfs: &[u8],
) -> Result<Option<RegistryNativeAttempt>, InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    launch_registry_until_ready_inner(system, loader, waits, controller, authority, bootfs, None)
}

/// The deadline-capped launch, matching the eight other `_before` helpers that
/// were already ordinary. R7B-4 took the selector gate off and the argument to
/// `Option<u64>`: with no episode open the cap is `None` and this is the plain
/// launch, which is what the `not(selector)` call site used to spell by hand.
#[allow(clippy::too_many_arguments)]
pub(crate) fn launch_registry_until_ready_before<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    controller: &mut SystemInit,
    authority: LoadAuthority,
    bootfs: &[u8],
    deadline_cap: Option<u64>,
) -> Result<Option<RegistryNativeAttempt>, InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    launch_registry_until_ready_inner(
        system,
        loader,
        waits,
        controller,
        authority,
        bootfs,
        deadline_cap,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn launch_registry_until_ready_inner<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    controller: &mut SystemInit,
    authority: LoadAuthority,
    bootfs: &[u8],
    deadline_cap: Option<u64>,
) -> Result<Option<RegistryNativeAttempt>, InitError>
where
    S: ResidentPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    loop {
        let attempt_transaction = match controller
            .role_state(RoleId::Registryd)
            .ok_or(InitError::WrongActivationOrder)?
        {
            RestartState::Starting { transaction_id, .. } => transaction_id,
            _ => return Err(InitError::WrongActivationOrder),
        };
        let attempt_time = system.now().map_err(InitError::Native)?;
        if deadline_cap.is_some_and(|deadline| attempt_time >= deadline) {
            return Err(InitError::Supervision);
        }
        match launch_registry(
            system,
            loader,
            waits,
            controller,
            authority,
            bootfs,
            deadline_cap,
        ) {
            Ok(value) => return Ok(Some(value)),
            Err(error) => {
                let now = attempt_time;
                let state = controller
                    .role_state(RoleId::Registryd)
                    .ok_or(InitError::WrongActivationOrder)?;
                let (generation, transaction_id) = match state {
                    RestartState::Starting {
                        generation,
                        transaction_id,
                        ..
                    } => (generation, transaction_id),
                    RestartState::Backoff { .. } => {
                        if advance_registry_or_exhausted_with_cap(
                            system,
                            controller,
                            attempt_transaction,
                            deadline_cap,
                        )? {
                            return Ok(None);
                        }
                        continue;
                    }
                    RestartState::PermanentFailure { .. } => return Ok(None),
                    _ => return Err(InitError::WrongActivationOrder),
                };
                controller.fail(
                    RoleId::Registryd,
                    generation,
                    transaction_id,
                    now,
                    AttemptFailure::CreationFailed,
                )?;
                let retired_at = now.checked_add(1).ok_or(InitError::Accounting)?;
                if error == InitError::Cleanup {
                    controller.cleanup_failed(
                        RoleId::Registryd,
                        generation,
                        transaction_id,
                        retired_at,
                    )?;
                    return Ok(None);
                }
                controller.cleanup_complete(
                    RoleId::Registryd,
                    generation,
                    transaction_id,
                    retired_at,
                )?;
                if advance_registry_or_exhausted_with_cap(
                    system,
                    controller,
                    transaction_id,
                    deadline_cap,
                )? {
                    return Ok(None);
                }
            }
        }
    }
}

pub(crate) fn poison_registry_generation<S, W>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    registry: RegistryNativeAttempt,
    dependent_cleanup_failed: bool,
) -> Result<bool, InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    poison_registry_generation_before(
        system,
        waits,
        controller,
        registry,
        dependent_cleanup_failed,
        None,
    )
}

pub(crate) fn poison_registry_generation_before<S, W>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    registry: RegistryNativeAttempt,
    dependent_cleanup_failed: bool,
    deadline_cap: Option<u64>,
) -> Result<bool, InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    retire_registry_generation(
        system,
        waits,
        controller,
        registry,
        dependent_cleanup_failed,
        deadline_cap,
        RegistryRetirement::Failure,
    )
}

pub(crate) fn retire_registry_for_recovery_before<S, W>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    registry: RegistryNativeAttempt,
    deadline_cap: Option<u64>,
) -> Result<bool, InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    retire_registry_generation(
        system,
        waits,
        controller,
        registry,
        false,
        deadline_cap,
        RegistryRetirement::CoordinatedRecovery,
    )
}

pub(crate) enum RegistryRetirement {
    Failure,
    /// Retire a published, healthy owner as part of an admitted recovery
    /// episode, keeping its accounting token. Only reachable while an episode
    /// is open, so a build that opens none never selects it.
    CoordinatedRecovery,
}

pub(crate) fn retire_registry_generation<S, W>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    registry: RegistryNativeAttempt,
    dependent_cleanup_failed: bool,
    deadline_cap: Option<u64>,
    retirement: RegistryRetirement,
) -> Result<bool, InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let observed_now = system.now().map_err(InitError::Native);
    let (transition_now, transition) = match observed_now {
        Ok(now) => (
            Some(now),
            match retirement {
                RegistryRetirement::Failure => controller.fail(
                    RoleId::Registryd,
                    registry.active.generation,
                    registry.active.transaction_id,
                    now,
                    AttemptFailure::WaitFailed,
                ),
                RegistryRetirement::CoordinatedRecovery
                    if deadline_cap.is_some_and(|deadline| now < deadline) =>
                {
                    controller.admit_recovery(
                        RoleId::Registryd,
                        registry.active.generation,
                        registry.active.transaction_id,
                        now,
                    )
                }
                RegistryRetirement::CoordinatedRecovery => Err(InitError::Supervision),
            },
        ),
        Err(error) => (None, Err(error)),
    };
    let native_cleanup_failed = cleanup_loaded_before(
        system,
        waits,
        registry.active.loaded,
        registry.active.task_group,
        true,
        deadline_cap,
    )
    .is_err()
        | system.close_handle(registry.control_channel).is_err()
        | dependent_cleanup_failed;

    let now = match transition {
        Ok(()) => transition_now.ok_or(InitError::Accounting)?,
        Err(error) => {
            let identity_mismatch = matches!(
                error,
                InitError::Restart(RestartTransitionError::StaleGeneration)
                    | InitError::Restart(RestartTransitionError::TransactionMismatch)
            );
            let retirement = if identity_mismatch || transition_now.is_none() {
                controller.retire_attempt_after_fatal(RoleId::Registryd)
            } else {
                controller.retire_active_fail_closed(
                    RoleId::Registryd,
                    registry.active.generation,
                    registry.active.transaction_id,
                    transition_now.ok_or(InitError::Accounting)?,
                    AttemptFailure::WaitFailed,
                    if native_cleanup_failed {
                        CleanupDisposition::Failed
                    } else {
                        CleanupDisposition::Complete
                    },
                )
            };
            if retirement.is_err() {
                let _ = controller.retire_attempt_after_fatal(RoleId::Registryd);
            }
            return Err(if native_cleanup_failed || retirement.is_err() {
                InitError::Cleanup
            } else {
                // Preserve the original transition error after complete native
                // cleanup; its exact type explains why fail()->CleaningUp did
                // not commit while the role is now truthfully permanent.
                error
            });
        }
    };
    let completed_at = system.now().map_err(InitError::Native)?;
    let retired_at = now
        .checked_add(1)
        .map_or(completed_at, |minimum| minimum.max(completed_at));
    let deadline_expired = deadline_cap.is_some_and(|deadline| completed_at >= deadline);
    let cleanup_must_fail = native_cleanup_failed || retired_at == now;
    if cleanup_must_fail {
        if controller
            .cleanup_failed(
                RoleId::Registryd,
                registry.active.generation,
                registry.active.transaction_id,
                retired_at,
            )
            .is_err()
        {
            let _ = controller.retire_attempt_after_fatal(RoleId::Registryd);
            return Err(InitError::Cleanup);
        }
        return if retired_at == now && !native_cleanup_failed {
            Err(InitError::Accounting)
        } else {
            Ok(true)
        };
    }
    if let Err(error) = controller.cleanup_complete(
        RoleId::Registryd,
        registry.active.generation,
        registry.active.transaction_id,
        retired_at,
    ) {
        let _ = controller.retire_attempt_after_fatal(RoleId::Registryd);
        return Err(error);
    }
    if deadline_expired {
        return Err(InitError::Supervision);
    }
    advance_registry_or_exhausted_with_cap(
        system,
        controller,
        registry.active.transaction_id,
        deadline_cap,
    )
}

pub(crate) fn restart_topology_or_poison_before<S, W>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    topology: &mut RegistryTopology,
    registry: RegistryNativeAttempt,
    deadline_cap: Option<u64>,
) -> Result<RegistryNativeAttempt, InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    if deadline_cap.is_some_and(|deadline| system.now().map_or(true, |now| now >= deadline)) {
        let cleanup = poison_registry_generation_before(
            system,
            waits,
            controller,
            registry,
            false,
            deadline_cap,
        );
        return match cleanup {
            Err(InitError::Cleanup) => Err(InitError::Cleanup),
            Err(error) => Err(error),
            Ok(_) => Err(InitError::Supervision),
        };
    }
    if let Err(error) = topology
        .restart(registry.active.generation)
        .map_err(InitError::Jobs)
    {
        let _ = poison_registry_generation_before(
            system,
            waits,
            controller,
            registry,
            false,
            deadline_cap,
        )?;
        return Err(error);
    }
    if deadline_cap.is_some_and(|deadline| system.now().map_or(true, |now| now >= deadline)) {
        let _ = poison_registry_generation_before(
            system,
            waits,
            controller,
            registry,
            false,
            deadline_cap,
        )?;
        return Err(InitError::Supervision);
    }
    Ok(registry)
}

pub(crate) fn advance_registry_or_exhausted<S: InitPlatform>(
    system: &mut S,
    controller: &mut SystemInit,
    transaction_id: u64,
) -> Result<bool, InitError> {
    let _ = advance_or_degrade(system, controller, RoleId::Registryd, transaction_id)?;
    Ok(matches!(
        controller
            .role_state(RoleId::Registryd)
            .ok_or(InitError::WrongActivationOrder)?,
        RestartState::PermanentFailure { .. }
    ))
}

pub(crate) fn advance_registry_or_exhausted_with_cap<S: InitPlatform>(
    system: &mut S,
    controller: &mut SystemInit,
    transaction_id: u64,
    deadline_cap: Option<u64>,
) -> Result<bool, InitError> {
    let Some(action_deadline) = deadline_cap else {
        return advance_registry_or_exhausted(system, controller, transaction_id);
    };
    match controller
        .role_state(RoleId::Registryd)
        .ok_or(InitError::WrongActivationOrder)?
    {
        RestartState::PermanentFailure { .. } => Ok(true),
        RestartState::Backoff {
            next_generation,
            deadline_ns,
            ..
        } => {
            let wait_deadline = deadline_ns.min(action_deadline);
            system
                .wait_until(wait_deadline)
                .map_err(InitError::Native)?;
            let observed_now = system.now().map_err(InitError::Native)?;
            if observed_now < wait_deadline {
                return Err(InitError::WrongActivationOrder);
            }
            if observed_now >= action_deadline {
                return Err(InitError::Supervision);
            }
            controller.start_replacement(
                RoleId::Registryd,
                observed_now,
                next_generation,
                next_transaction(transaction_id)?,
            )?;
            Ok(matches!(controller.mode(), SystemMode::Degraded))
        }
        _ => Err(InitError::WrongActivationOrder),
    }
}
