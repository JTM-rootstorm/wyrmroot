//! Native selector-27 registry and dependent-peer controller.

use super::*;
use crate::launch_transaction::{
    LaunchResources, LaunchStage, LaunchToken, LaunchTransactionError,
};
use crate::wyr1b::{
    EndpointGrant, EndpointKind, JobError, JobResult as ControllerJobResult, LaunchChannelRelease,
    LaunchEngineError, PolicyView, PreparedJob, RegistryTopology, RequestTicket,
    commit_prepared_job, observe_prepared_ready, prepare_reserved_job,
};
use crate::wyr1b_job::{JobDispatcher, LaunchSessionScope, SessionOwner};
use deepwyrm_syscall::{
    DW_HANDLE_TRANSFER_MOVE, DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_INSPECT, DW_RIGHT_READ,
    DW_RIGHT_TRANSFER, DW_RIGHT_WAIT, DW_RIGHT_WRITE, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE,
    DW_STATUS_NO_MEMORY, DW_STATUS_NO_RESOURCES, DW_TASK_STATE_EXITED, DW_TERMINATION_AUTHORIZED,
    DW_TERMINATION_NORMAL_EXIT, DW_TERMINATION_RESOURCE_POLICY, DW_TERMINATION_TASK_GROUP_TEARDOWN,
    DW_TERMINATION_UNHANDLED_EXCEPTION, DwHandleTransferV1, DwRights,
};
use wyrmroot_launch_proto::{
    ErrorCode as LaunchErrorCode, Message as LaunchMessage, MessageType as LaunchMessageType,
    Reservation as LaunchReservation, TerminationClassification, TerminationResult,
    encode_error as encode_launch_error, encode_job_list, encode_job_message, encode_job_result,
    encode_job_state, encode_shell_v1_accepted,
    encode_shell_v1_error as encode_shell_v1_error_reply, parse_message as parse_launch_message,
    parse_reservation_prefix, parse_shell_v1_request, parse_shell_v1_reservation_prefix,
};
use wyrmroot_loader::{
    launch::{CHILD_CHANNEL_RIGHTS, LaunchProfile},
    process::{WyrmshLoadRequest, load_wyrmsh_process},
};
use wyrmroot_registry_proto::{
    EnumerationScope, HEADER_BYTES as REGISTRY_HEADER_BYTES, Header as RegistryHeader,
    InstallClient, MAX_SERVICE_LIST_PAGES, Message as RegistryMessage,
    MessageType as RegistryMessageType, SERVICE_LIST_PREFIX_BYTES, SERVICE_LIST_RECORD_BYTES,
    encode_empty as encode_registry_empty, encode_install_client, parse as parse_registry_message,
};

const REGISTRY_PATH: &str = "system/registryd";
const INSTALL_CLIENT_TRANSACTION: u64 = 3;
const CONTROLLER_CHANNEL_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_TRANSFER.0,
);
const WYRMSH_REGISTRY_DEADLINE_NS: u64 = 1_000_000_000;
const WYRMSH_FIRST_INSTALL_TRANSACTION: u64 = 0xE300_0001;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShellRegistryHealth {
    Healthy { generation: u64 },
    Poisoned { generation: u64 },
    Exhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ShellControllerState {
    health: ShellRegistryHealth,
    next_install_transaction: u64,
    replacement_attempts: u16,
    last_console_generation: u64,
    last_status_generation: u64,
    last_child_generation: u64,
    /// The deadline of the recovery episode in flight, if one is.
    ///
    /// R7B-1. Every recovery leg's own deadline is capped by this one and
    /// every step refuses to proceed past it, so an episode cannot outlive its
    /// budget by accumulating individually-legal legs. Nothing in the product
    /// opens an episode yet, so product builds hold `None` here and behave
    /// exactly as the removed `not(wyr1e8-selector33)` arms did: no cap, no
    /// expiry. What was selector-specific was never the property, only the one
    /// caller that asks for it.
    recovery_deadline: Option<u64>,
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
    session_shutdown: bool,
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

    fn reserve_install_transaction(&mut self, generation: u64) -> Result<u64, InitError> {
        if self.health != (ShellRegistryHealth::Healthy { generation }) {
            return Err(InitError::Cleanup);
        }
        let transaction = self.next_install_transaction;
        self.next_install_transaction = transaction.checked_add(1).ok_or(InitError::Accounting)?;
        Ok(transaction)
    }

    fn reserve_shell_generation(
        &mut self,
        request: wyrmroot_launch_proto::ShellV1Request,
    ) -> Result<(), InitError> {
        if self.last_console_generation != 0
            && (request.console_generation < self.last_console_generation
                || request.status_generation <= self.last_status_generation
                || request.requested_child_generation <= self.last_child_generation)
        {
            return Err(InitError::Wyr1BModel(JobError::StaleGeneration));
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
    ready_at: u64,
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
struct StagedChannelPair {
    first: Option<DwHandle>,
    second: Option<DwHandle>,
}

impl StagedChannelPair {
    const fn new(first: DwHandle, second: DwHandle) -> Self {
        Self {
            first: Some(first),
            second: Some(second),
        }
    }

    fn second(&self) -> Result<DwHandle, InitError> {
        self.second.ok_or(InitError::Accounting)
    }

    fn commit_second_move(&mut self) -> Result<(), InitError> {
        self.second.take().map(|_| ()).ok_or(InitError::Accounting)
    }

    fn take_first(&mut self) -> Result<DwHandle, InitError> {
        self.first.take().ok_or(InitError::Accounting)
    }

    fn cleanup<S: InitPlatform>(&mut self, system: &mut S) -> bool {
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
    let controller = SystemInit::from_wyr1e_manifest(manifest)?;
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

pub(crate) fn install_client<S: Wyr1BPlatform>(
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

fn install_wyrmsh_registry_client<S: Wyr1BPlatform>(
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

fn preflight_wyrmsh_registry<S: Wyr1BPlatform>(
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

fn move_endpoint<S: Wyr1BPlatform>(
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

fn validate_controller_channel<S: InitPlatform>(
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

pub(crate) fn create_controller_channel_pair<S: Wyr1BPlatform>(
    system: &mut S,
) -> Result<(DwHandle, DwHandle), InitError> {
    system
        .channel_create(CONTROLLER_CHANNEL_RIGHTS)
        .map_err(InitError::Native)
}

fn launch_registry<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    controller: &mut SystemInit,
    authority: LoadAuthority,
    bootfs: &[u8],
    deadline_cap: Option<u64>,
) -> Result<RegistryNativeAttempt, InitError>
where
    S: Wyr1BPlatform,
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
    match RegistryTopology::new(registry.active.generation).map_err(InitError::Wyr1BModel) {
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
fn reconcile_failed_registry_launch<
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
    S: Wyr1BPlatform,
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
    S: Wyr1BPlatform,
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
fn launch_registry_until_ready_inner<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    controller: &mut SystemInit,
    authority: LoadAuthority,
    bootfs: &[u8],
    deadline_cap: Option<u64>,
) -> Result<Option<RegistryNativeAttempt>, InitError>
where
    S: Wyr1BPlatform,
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

enum RegistryRetirement {
    Failure,
    /// Retire a published, healthy owner as part of an admitted recovery
    /// episode, keeping its accounting token. Only reachable while an episode
    /// is open, so a build that opens none never selects it.
    CoordinatedRecovery,
}

fn retire_registry_generation<S, W>(
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
        .map_err(InitError::Wyr1BModel)
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

fn advance_registry_or_exhausted<S: InitPlatform>(
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

fn advance_registry_or_exhausted_with_cap<S: InitPlatform>(
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

fn report_deadline<S: InitPlatform>(system: &mut S) -> Result<DwDeadline, InitError> {
    Ok(DwDeadline(
        system
            .now()
            .map_err(InitError::Native)?
            .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .ok_or(InitError::Accounting)?,
    ))
}

fn close_received_reverse<S: InitPlatform>(
    system: &mut S,
    handles: &[DwReceivedHandleInfoV1],
    count: usize,
) -> bool {
    let mut failed = false;
    for handle in handles[..count.min(handles.len())].iter().rev() {
        failed |= system.close_handle(handle.handle).is_err();
    }
    failed
}

fn launch_engine_error(error: LaunchEngineError<NativeError>) -> InitError {
    match error {
        LaunchEngineError::Job(error) => InitError::Wyr1BModel(error),
        LaunchEngineError::Validation {
            error,
            abort_failed,
            cleanup_failed,
        } => {
            if abort_failed || cleanup_failed {
                InitError::Cleanup
            } else {
                InitError::Wyr1BModel(error)
            }
        }
        LaunchEngineError::Loader {
            error,
            abort_failed,
            cleanup_failed,
            ..
        } => {
            if abort_failed || cleanup_failed {
                InitError::Cleanup
            } else {
                InitError::Loader(error)
            }
        }
        LaunchEngineError::Publication { error, .. } => InitError::Wyr1BModel(error),
    }
}

#[allow(clippy::too_many_arguments)]
fn publish_launch_accepted<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    reservation: LaunchReservation,
    loaded: crate::wyr1b::LoadedJob,
    release: LaunchChannelRelease,
) -> Result<(LaunchChannelRelease, SentLaunchAccepted), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut response = [0_u8; 88];
    let size = encode_job_message(
        reservation,
        LaunchMessageType::LaunchAccepted,
        loaded.job_id,
        &mut response,
    )
    .map_err(|_| InitError::Accounting)?;
    if let Err(error) = system.send_channel(session, &response[..size]) {
        jobs.jobs.restore_launch_channel(release);
        let cleanup_failed = force_cleanup_job_before(system, waits, jobs, loaded, None).is_err();
        return Err(if cleanup_failed {
            InitError::Cleanup
        } else {
            InitError::Native(error)
        });
    }
    Ok((release, SentLaunchAccepted {}))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SentLaunchAccepted {}

impl SentLaunchAccepted {}

fn force_cleanup_job<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    loaded: crate::wyr1b::LoadedJob,
) -> Result<TerminationResult, InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    force_cleanup_job_before(system, waits, jobs, loaded, None)
}

fn force_cleanup_job_before<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    loaded: crate::wyr1b::LoadedJob,
    deadline_cap: Option<u64>,
) -> Result<TerminationResult, InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    if let Some(resources) = jobs
        .jobs
        .forced_termination_resources(loaded.job_id)
        .map_err(InitError::Wyr1BModel)?
    {
        if system
            .terminate_task_group(DwHandle(resources.task_group))
            .is_err()
        {
            jobs.jobs
                .record_cleanup_bits(loaded.job_id, 1 << 0)
                .map_err(InitError::Wyr1BModel)?;
        } else {
            jobs.jobs
                .commit_forced_termination(loaded.job_id, resources)
                .map_err(InitError::Wyr1BModel)?;
        }
    }
    let result = reap_job_before(system, waits, jobs, loaded, deadline_cap)?;
    if result.cleanup_result != 0 {
        Err(InitError::Cleanup)
    } else {
        Ok(result)
    }
}

fn rollback_prepared_job<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    prepared: crate::wyr1b::PreparedJob,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    force_cleanup_job(
        system,
        waits,
        jobs,
        crate::wyr1b::LoadedJob {
            job_id: prepared.job_id(),
            loaded: prepared.loaded,
            task_group: prepared.task_group,
        },
    )
    .map(|_| ())
}

/// Validates, reserves, loads and arms the READY deadline, and stops there.
///
/// Everything up to and including `report_deadline` is work the request's own
/// frame has to do: it consumes the moved stream handles and the borrowed
/// request, neither of which outlives the dispatch. What it returns is the
/// small record the observation needs afterwards.
#[allow(clippy::too_many_arguments)]
fn construct_reserved_launch<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: &PolicyView<'_>,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    reservation: LaunchReservation,
    request_ticket: RequestTicket,
    request: wyrmroot_launch_proto::LaunchRequest<'_>,
    received: &[DwReceivedHandleInfoV1],
    handle_count: usize,
) -> Result<ConstructedLaunch, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    for info in &received[..handle_count] {
        if let Err(error) = validate_controller_channel(system, info.handle) {
            let failed = close_received_reverse(system, received, handle_count);
            return Err(if failed { InitError::Cleanup } else { error });
        }
    }
    let ticket = match jobs.jobs.begin_reserved_launch(request_ticket) {
        Ok(ticket) => ticket,
        Err(error) => {
            let failed = close_received_reverse(system, received, handle_count);
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Wyr1BModel(error)
            });
        }
    };
    let streams = [received[0].handle, received[1].handle, received[2].handle];
    let streams = &streams[..handle_count];
    let task_group = match system.create_attempt_task_group(authority.task_group) {
        Ok(task_group) => task_group,
        Err(error) => {
            return Err(
                if close_received_reverse(system, received, handle_count)
                    | jobs.jobs.abort_launch(ticket).is_err()
                {
                    InitError::Cleanup
                } else {
                    InitError::Native(error)
                },
            );
        }
    };
    let prepared = match prepare_reserved_job(
        &mut jobs.jobs,
        policy,
        loader,
        authority,
        task_group.0,
        reservation,
        ticket,
        request,
        streams,
    ) {
        Ok(prepared) => prepared,
        Err(LaunchEngineError::Publication {
            error,
            ticket,
            loaded,
            task_group,
        }) => {
            let cleanup_failed =
                cleanup_loaded(system, waits, loaded, DwHandle(task_group), true).is_err();
            let abort_failed = jobs.jobs.abort_launch(ticket).is_err();
            return Err(if cleanup_failed || abort_failed {
                InitError::Cleanup
            } else {
                InitError::Wyr1BModel(error)
            });
        }
        Err(error) => {
            let mapped = launch_engine_error(error);
            return Err(if system.close_handle(task_group).is_err() {
                InitError::Cleanup
            } else {
                mapped
            });
        }
    };
    let deadline = match report_deadline(system) {
        Ok(deadline) => deadline,
        Err(error) => {
            return Err(
                if rollback_prepared_job(system, waits, jobs, prepared).is_err() {
                    InitError::Cleanup
                } else {
                    error
                },
            );
        }
    };
    Ok(ConstructedLaunch {
        prepared,
        deadline,
        session,
        reservation,
    })
}

/// A launch whose child exists and whose READY has not been observed yet.
///
/// Reset plan §7: this is the boundary between `Constructed` and
/// `AwaitingReady`. Everything in it is a fact the observation and the
/// publication still need, and every one of them used to be a local of
/// `accept_reserved_launch`'s frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConstructedLaunch {
    prepared: PreparedJob,
    deadline: DwDeadline,
    session: DwHandle,
    reservation: LaunchReservation,
}

/// Observes the exact READY and publishes, or rolls the launch back.
///
/// Split out of `accept_reserved_launch` by reset card R6B. It is the half
/// that may not run in the frame that read the request: `observe_prepared_ready`
/// blocks until the child answers or `deadline` expires, and §3's invariant 6
/// says that wait must not hold the resident dispatcher. R6B moves the call
/// site; the sequence inside is unchanged.
#[allow(clippy::too_many_arguments)]
fn finish_constructed_launch<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    constructed: ConstructedLaunch,
) -> Result<(crate::wyr1b::LoadedJob, SentLaunchAccepted), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let ConstructedLaunch {
        prepared,
        deadline,
        session,
        reservation,
    } = constructed;
    let observation = observe_prepared_ready(waits, &prepared, deadline);
    if observation.is_err() {
        return Err(
            if rollback_prepared_job(system, waits, jobs, prepared).is_err() {
                InitError::Cleanup
            } else {
                InitError::Supervision
            },
        );
    }
    let observation = observation.expect("checked exact READY observation");
    let loaded = match commit_prepared_job(&mut jobs.jobs, prepared, observation) {
        Ok(loaded) => loaded,
        Err(error) => {
            return Err(
                if rollback_prepared_job(system, waits, jobs, prepared).is_err() {
                    InitError::Cleanup
                } else {
                    InitError::Wyr1BModel(error)
                },
            );
        }
    };
    let release = jobs
        .jobs
        .release_launch_channel(loaded.job_id, loaded.loaded.launch_channel.0)
        .map_err(InitError::Wyr1BModel)?;
    let (release, sent_response) =
        publish_launch_accepted(system, waits, jobs, session, reservation, loaded, release)?;
    if system.close_handle(loaded.loaded.launch_channel).is_err() {
        jobs.jobs.restore_launch_channel(release);
        jobs.jobs
            .record_cleanup_bits(loaded.job_id, 1 << 2)
            .map_err(InitError::Wyr1BModel)?;
        if system
            .terminate_task_group(DwHandle(loaded.task_group))
            .is_err()
        {
            jobs.jobs
                .record_cleanup_bits(loaded.job_id, 1 << 0)
                .map_err(InitError::Wyr1BModel)?;
        } else {
            let resources = jobs
                .jobs
                .forced_termination_resources(loaded.job_id)
                .map_err(InitError::Wyr1BModel)?
                .ok_or(InitError::Accounting)?;
            jobs.jobs
                .commit_forced_termination(loaded.job_id, resources)
                .map_err(InitError::Wyr1BModel)?;
        }
        let loaded = jobs
            .jobs
            .loaded_job(loaded.job_id)
            .map_err(InitError::Wyr1BModel)?;
        return Ok((loaded, sent_response));
    }
    // The accepted job's retained resources are now owned by the model, which
    // recorded the released launch Channel. Returning the pre-release snapshot
    // would hand callers a closed launch-Channel handle to close again.
    let loaded = jobs
        .jobs
        .loaded_job(loaded.job_id)
        .map_err(InitError::Wyr1BModel)?;
    Ok((loaded, sent_response))
}

fn classify_termination(
    info: &DwTaskTerminationInfoV1,
) -> Result<TerminationClassification, InitError> {
    Ok(if info.reason == DW_TERMINATION_NORMAL_EXIT {
        TerminationClassification::NormalExit
    } else if info.reason == DW_TERMINATION_AUTHORIZED {
        TerminationClassification::Authorized
    } else if info.reason == DW_TERMINATION_UNHANDLED_EXCEPTION {
        TerminationClassification::UnhandledException
    } else if info.reason == DW_TERMINATION_RESOURCE_POLICY {
        TerminationClassification::ResourcePolicy
    } else if info.reason == DW_TERMINATION_TASK_GROUP_TEARDOWN {
        TerminationClassification::TaskGroupTeardown
    } else {
        return Err(InitError::Supervision);
    })
}

/// Bounded preterminal observation rounds allowed for one child Process exit.
///
/// A scripted controller may close a child's launch Channel and reap immediately,
/// so the child can still be pre-exit when the first observation runs. Each round
/// is one `WYR0_I_SUPERVISION_POLICY.ready_timeout_ns` wait followed by a fresh
/// level-triggered task-state query, which keeps the total bound explicit and
/// removes the dependence on a single wait observing the exact EXITED transition.
const JOB_EXIT_OBSERVATION_ROUNDS: u16 = WYR0_I_SUPERVISION_POLICY.max_attempts as u16;

/// Observes one child Process reaching its level-triggered EXITED state within
/// the bounded round budget above. `Err(())` means the caller must record
/// cleanup bit 1 and leave the job retained for a later cleanup attempt.
fn await_job_exit<S, W>(
    system: &mut S,
    waits: &mut W,
    process: DwHandle,
    deadline_cap: Option<u64>,
) -> Result<DwTaskTerminationInfoV1, ()>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut info = waits.query_task_termination(process).map_err(|_| ())?;
    let mut round = 0_u16;
    while info.state != DW_TASK_STATE_EXITED {
        if round == JOB_EXIT_OBSERVATION_ROUNDS {
            return Err(());
        }
        round += 1;
        let now = system.now().map_err(|_| ())?;
        if deadline_cap.is_some_and(|cap| now >= cap) {
            return Err(());
        }
        let deadline = now
            .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .map(|deadline| deadline_cap.map_or(deadline, |cap| deadline.min(cap)))
            .or(deadline_cap)
            .map(DwDeadline)
            .ok_or(())?;
        match waits.wait_many(
            core::slice::from_ref(&DwWaitItemV1 {
                handle: process,
                signals: DW_SIGNAL_EXITED,
            }),
            deadline,
        ) {
            Ok(_) => {}
            // A round that expires without the exit signal is not yet a cleanup
            // failure: the child may simply not have been scheduled. Any other
            // native wait failure stays fatal for this attempt.
            Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {}
            Err(_) => return Err(()),
        }
        info = waits.query_task_termination(process).map_err(|_| ())?;
        if deadline_cap.is_some() {
            let now = system.now().map_err(|_| ())?;
            if now >= deadline_cap.ok_or(())? {
                return Err(());
            }
        }
    }
    Ok(info)
}

fn reap_job<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    loaded: crate::wyr1b::LoadedJob,
) -> Result<TerminationResult, InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    reap_job_before(system, waits, jobs, loaded, None)
}

fn reap_job_before<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    loaded: crate::wyr1b::LoadedJob,
    deadline_cap: Option<u64>,
) -> Result<TerminationResult, InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let terminal = match jobs
        .jobs
        .terminal_result(loaded.job_id)
        .map_err(InitError::Wyr1BModel)?
    {
        Some(terminal) => terminal,
        None => {
            if loaded.loaded.process.0 == 0 {
                return Err(InitError::Accounting);
            }
            let info = match await_job_exit(system, waits, loaded.loaded.process, deadline_cap) {
                Ok(info) => info,
                Err(()) => {
                    jobs.jobs
                        .record_cleanup_bits(loaded.job_id, 1 << 1)
                        .map_err(InitError::Wyr1BModel)?;
                    return Err(InitError::Cleanup);
                }
            };
            ControllerJobResult {
                classification: classify_termination(&info)?.as_u32(),
                application_code: info.application_code,
                exception_class: info.exception_type.0,
                exception_detail: info.detail,
                exception_address: info.fault_address,
                cleanup_result: 0,
            }
        }
    };
    let mut closed_mask = 0_u32;
    let mut failed_bits = 0_u32;
    if loaded.loaded.launch_channel.0 != 0 {
        if system.close_handle(loaded.loaded.launch_channel).is_err() {
            failed_bits |= 1 << 2;
        } else {
            closed_mask |= 1 << 2;
        }
    }
    if loaded.loaded.process.0 != 0 {
        if system.close_handle(loaded.loaded.process).is_err() {
            failed_bits |= 1 << 3;
        } else {
            closed_mask |= 1 << 3;
        }
    }
    if loaded.task_group != 0 {
        if system.close_handle(DwHandle(loaded.task_group)).is_err() {
            failed_bits |= 1 << 4;
        } else {
            closed_mask |= 1 << 4;
        }
    }
    let completed = jobs
        .jobs
        .apply_cleanup_progress(loaded.job_id, terminal, closed_mask, failed_bits)
        .map_err(InitError::Wyr1BModel)?;
    let Some(completed) = completed else {
        return Err(InitError::Cleanup);
    };
    jobs.jobs.reclaim_closed_sessions();
    controller_result_to_wire(completed)
}

const fn job_error_code(error: JobError) -> LaunchErrorCode {
    match error {
        JobError::TransactionReplay => LaunchErrorCode::TransactionReplay,
        JobError::UnknownConnection
        | JobError::ClosedConnection
        | JobError::StaleGeneration
        | JobError::DuplicateConnection
        | JobError::ZeroIdentity => LaunchErrorCode::StaleOrUnknownSession,
        JobError::ForeignJob | JobError::UnknownJob => LaunchErrorCode::ForeignOrUnknownJob,
        JobError::Capacity | JobError::ArithmeticOverflow => LaunchErrorCode::Capacity,
        JobError::Policy(_)
        | JobError::PolicyMissing
        | JobError::PolicyExecutable
        | JobError::Bootfs(_)
        | JobError::BootGenerationMismatch
        | JobError::ArtifactNotExecutable
        | JobError::ArtifactIdentityMismatch
        | JobError::StreamPolicy => LaunchErrorCode::PolicyRejected,
        JobError::WrongState | JobError::ResourceIdentity => LaunchErrorCode::InvalidState,
    }
}

/// A native failure during a launch, as the launch protocol's own vocabulary.
///
/// F3A.6n. `ErrorCode::Capacity` exists and was unreachable from the case it
/// describes. It is produced only by `job_error_code` from
/// `JobError::Capacity`, which is the *shell's own job table* filling up; a
/// **kernel** resource exhaustion arrived as `InitError::Native(status)` and
/// was reported as `LoaderFailure`. So "the loader broke" and "the system is
/// full" were the same word on the wire, and a reader could not tell a
/// defective artifact from a full machine.
///
/// `NO_MEMORY` and `NO_RESOURCES` are the kernel's two exhaustion statuses
/// (`deepwyrm/abi/schema/status.toml`, values -12 and -13). They are capacity
/// by any reading. Everything else native -- including an output-contract
/// fault, which is our own ABI handling and not the machine's limits -- keeps
/// `LoaderFailure`.
///
/// This is a §3.1 collapse and it stays one: `ErrorCode` is a bare
/// `#[repr(u32)]` enum with no payload, so the exact status cannot ride the
/// reply. Its own doc comment says Deepwyrm statuses "remain available only in
/// a terminal `JOB_RESULT`" -- an escape hatch a *refused* launch never has,
/// because no job is created. Until an out-of-band channel carries it per
/// §4.2, distinguishing the two classes is the whole improvement available
/// here, and it is the one the reader needs first.
const fn native_launch_error_code(error: NativeError) -> LaunchErrorCode {
    match error {
        NativeError::Status(status)
            if status.0 == DW_STATUS_NO_MEMORY.0 || status.0 == DW_STATUS_NO_RESOURCES.0 =>
        {
            LaunchErrorCode::Capacity
        }
        NativeError::Status(_) | NativeError::Output(_) => LaunchErrorCode::LoaderFailure,
    }
}

const fn launch_error_code(error: &InitError) -> LaunchErrorCode {
    match error {
        InitError::Wyr1BModel(error) => job_error_code(*error),
        InitError::Native(error) => native_launch_error_code(*error),
        // A load that failed *inside a platform stage* carries the kernel's
        // own cause, and that is where a handle- or memory-table exhaustion
        // during a launch actually surfaces -- not as a bare
        // `InitError::Native`. Reading only the outer variant would have left
        // the exhaustion case still answering `loader-failure`, which is the
        // mistake this change exists to correct.
        InitError::Loader(wyrmroot_loader::process::LoadError::Platform { cause, .. }) => {
            native_launch_error_code(*cause)
        }
        // The rest of `LoadError` genuinely names the loader or the artifact:
        // a malformed ELF, a bad startup block, a refused launch message.
        // `tools/e7_vm.py` pins `loader-failure` for a malformed ELF, and this
        // is the arm that keeps that answer.
        //
        // `Supervision` keeps the code rather than moving to a more accurate
        // one: nothing has been observed reaching it on this path, and moving
        // a code nothing has seen fire is churn with a conformance risk
        // attached.
        InitError::Loader(_) | InitError::Supervision => LaunchErrorCode::LoaderFailure,
        InitError::Cleanup | InitError::Accounting => LaunchErrorCode::CleanupFailure,
        _ => LaunchErrorCode::PolicyRejected,
    }
}

/// The shell launch path's mapping.
///
/// F3A.6n. The default arm used to be `LoaderFailure`, which is why the F
/// campaign's refused `spawn bin/cpu-hog` said `loader-failure` and meant
/// nothing: every `InitError` that was not `Wyr1BModel`, `Cleanup` or
/// `Accounting` claimed the loader had failed, including errors with no
/// relation to it. `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` §3.4 forbids a
/// wildcard over an error type at a status boundary and the compiler enforces
/// it -- but this is a *protocol reply* boundary, which that rule does not
/// reach, so the shape survived here.
///
/// Defaulting to a *specific* claim is the defect, not the defaulting. The
/// arms that can name their fault now do, by sharing `launch_error_code`'s
/// vocabulary, and what remains unclassified defaults to `PolicyRejected` --
/// "this request was refused" -- which claims nothing about where the fault
/// was. That is the honest answer for an error this function cannot attribute.
const fn shell_launch_error_code(error: &InitError) -> LaunchErrorCode {
    launch_error_code(error)
}

fn send_job_error<S: InitPlatform>(
    system: &mut S,
    session: DwHandle,
    reservation: LaunchReservation,
    code: LaunchErrorCode,
) -> Result<(), InitError> {
    let mut response = [0_u8; 88];
    let size =
        encode_launch_error(reservation, code, &mut response).map_err(|_| InitError::Accounting)?;
    system
        .send_channel(session, &response[..size])
        .map_err(InitError::Native)
}

/// Constructs the child, parks the transaction, and returns to the event loop.
///
/// Reset card R6B-2, and the whole of what it changes. The one-frame path is
/// `accept_reserved_launch`, which runs `construct_reserved_launch` and
/// `finish_constructed_launch` back to back; this runs only the first and
/// leaves the second to `finish_deferred_launch` on a later tick. Everything
/// the second half will need is written into the arena before this returns,
/// because the request buffer, the moved handles and the bootfs mapping all die
/// with this frame.
///
/// Failures before the child exists are answered here, exactly as they were:
/// the request bytes are still in hand, so the error reply and its evidence
/// record are unchanged. The one new failure is parking itself, and it is the
/// dangerous one -- a constructed child whose transaction never reached the
/// arena is a child nothing owns. It is rolled back before the reply, by the
/// same `rollback_prepared_job` the synchronous path uses.
#[allow(clippy::too_many_arguments)]
fn defer_reserved_launch<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: &PolicyView<'_>,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    grant: EndpointGrant,
    scope: LaunchSessionScope,
    reservation: LaunchReservation,
    request_ticket: RequestTicket,
    request: wyrmroot_launch_proto::LaunchRequest<'_>,
    moved: &[DwReceivedHandleInfoV1],
    handle_count: usize,
) -> Result<JobDispatchOutcome, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let constructed = match construct_reserved_launch(
        system,
        loader,
        waits,
        authority,
        policy,
        jobs,
        session,
        reservation,
        request_ticket,
        request,
        moved,
        handle_count,
    ) {
        Ok(constructed) => constructed,
        Err(error) => {
            send_observed_job_error(system, session, reservation, launch_error_code(&error))?;
            return if error == InitError::Cleanup {
                Err(error)
            } else {
                Ok(JobDispatchOutcome::Responded)
            };
        }
    };
    if let Err(error) = park_constructed_launch(jobs, grant, scope, constructed) {
        let cleanup_failed =
            rollback_prepared_job(system, waits, jobs, constructed.prepared).is_err();
        send_observed_job_error(system, session, reservation, launch_error_code(&error))?;
        return Err(if cleanup_failed {
            InitError::Cleanup
        } else {
            error
        });
    }
    Ok(JobDispatchOutcome::Constructed)
}

/// Writes one constructed launch into the arena and leaves it `AwaitingReady`.
///
/// Every stage edge is taken explicitly rather than assigned, so the arena's
/// own graph gets to refuse a sequence the dispatcher should not be producing.
fn park_constructed_launch(
    jobs: &mut JobDispatcher,
    grant: EndpointGrant,
    scope: LaunchSessionScope,
    constructed: ConstructedLaunch,
) -> Result<(), InitError> {
    let token = jobs
        .launches
        .open(grant, constructed.session, scope, constructed.reservation)
        .map_err(launch_transaction_error)?;
    let record = || -> Result<(), LaunchTransactionError> {
        jobs.launches
            .attach_job(token, constructed.prepared.job_id())?;
        jobs.launches.advance(token, LaunchStage::Constructed)?;
        jobs.launches.attach_resources(
            token,
            constructed.prepared.profile(),
            LaunchResources {
                process: constructed.prepared.loaded.process,
                launch_channel: constructed.prepared.loaded.launch_channel,
                task_group: DwHandle(constructed.prepared.task_group),
            },
        )?;
        jobs.launches
            .arm_ready_deadline(token, constructed.deadline)?;
        jobs.launches.advance(token, LaunchStage::AwaitingReady)
    }();
    if let Err(error) = record {
        // The slot exists but does not describe the child. Empty it so it
        // cannot be mistaken for one that owns handles, and let the caller
        // roll the child back.
        let _ = jobs.launches.take_resources(token);
        let _ = jobs.launches.advance(token, LaunchStage::Failing);
        let _ = jobs.launches.advance(token, LaunchStage::Cleanup);
        let _ = jobs.launches.advance(token, LaunchStage::Complete);
        let _ = jobs.launches.close(token);
        return Err(launch_transaction_error(error));
    }
    Ok(())
}

/// The arena's refusals are accounting errors: every one of them means the
/// dispatcher asked for a transition its own sequence should have made
/// impossible.
fn launch_transaction_error(error: LaunchTransactionError) -> InitError {
    match error {
        LaunchTransactionError::Capacity => InitError::Wyr1BModel(JobError::Capacity),
        LaunchTransactionError::SessionBusy => InitError::Wyr1BModel(JobError::WrongState),
        _ => InitError::Accounting,
    }
}

#[allow(clippy::too_many_arguments)]
fn send_observed_job_error<S: Wyr1BPlatform>(
    system: &mut S,
    session: DwHandle,
    reservation: LaunchReservation,
    code: LaunchErrorCode,
) -> Result<(), InitError> {
    let mut response = [0_u8; 88];
    let size =
        encode_launch_error(reservation, code, &mut response).map_err(|_| InitError::Accounting)?;
    system
        .send_channel(session, &response[..size])
        .map_err(InitError::Native)?;
    Ok(())
}

fn send_shell_v1_error<S: InitPlatform>(
    system: &mut S,
    session: DwHandle,
    reservation: LaunchReservation,
    code: LaunchErrorCode,
) -> Result<(), InitError> {
    let mut response = [0_u8; wyrmroot_launch_proto::SHELL_V1_REPLY_BYTES];
    let size = encode_shell_v1_error_reply(reservation, code, &mut response)
        .map_err(|_| InitError::Accounting)?;
    system
        .send_channel(session, &response[..size])
        .map_err(InitError::Native)
}

fn controller_result_to_wire(result: ControllerJobResult) -> Result<TerminationResult, InitError> {
    let classification = match result.classification {
        1 => TerminationClassification::NormalExit,
        2 => TerminationClassification::Authorized,
        3 => TerminationClassification::UnhandledException,
        4 => TerminationClassification::ResourcePolicy,
        5 => TerminationClassification::TaskGroupTeardown,
        _ => return Err(InitError::Accounting),
    };
    Ok(TerminationResult {
        classification,
        application_code: result.application_code,
        exception_class: result.exception_class,
        exception_detail: result.exception_detail,
        exception_address: result.exception_address,
        cleanup_result: result.cleanup_result,
    })
}

#[allow(clippy::too_many_arguments, clippy::needless_option_as_deref)]
fn dispatch_reserved_operation_observed<S, W>(
    system: &mut S,
    _waits: &mut W,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    grant: EndpointGrant,
    reservation: LaunchReservation,
    ticket: RequestTicket,
    message: LaunchMessage<'_>,
    request_bytes: &[u8],
    scope: LaunchSessionScope,
    mut evidence: Option<&mut ShellControllerState>,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut response = [0_u8; 320];
    let result: Result<Option<usize>, JobError> = match message {
        LaunchMessage::Query { job_id } => {
            jobs.jobs
                .query_reserved(ticket, job_id)
                .and_then(|snapshot| {
                    let phase = match snapshot.phase {
                        crate::wyr1b::JobPhase::Running => wyrmroot_launch_proto::JobPhase::Running,
                        crate::wyr1b::JobPhase::Terminating => {
                            wyrmroot_launch_proto::JobPhase::Terminating
                        }
                        crate::wyr1b::JobPhase::Reserved => return Err(JobError::WrongState),
                    };
                    encode_job_state(reservation, job_id, phase, &mut response)
                        .map(Some)
                        .map_err(|_| JobError::WrongState)
                })
        }
        LaunchMessage::Wait { job_id } => (|| -> Result<Option<usize>, JobError> {
            match jobs.jobs.result_reserved(ticket, job_id) {
                Ok(controller) => {
                    let terminal =
                        controller_result_to_wire(controller).map_err(|_| JobError::WrongState)?;
                    observe_session_shutdown_result(scope, evidence.as_deref_mut(), terminal);
                    encode_job_result(reservation, job_id, terminal, &mut response)
                        .map(Some)
                        .map_err(|_| JobError::WrongState)
                }
                Err(JobError::UnknownJob) => {
                    jobs.jobs.query_reserved(ticket, job_id)?;
                    jobs.install_pending_wait(grant, reservation, job_id, request_bytes)?;
                    Ok(None)
                }
                Err(error) => Err(error),
            }
        })(),
        LaunchMessage::Terminate { job_id } => {
            let resources = match jobs.jobs.authorize_terminate_reserved(ticket, job_id) {
                Ok(resources) => resources,
                Err(error) => {
                    return send_observed_job_error(
                        system,
                        session,
                        reservation,
                        job_error_code(error),
                    );
                }
            };
            if system
                .terminate_task_group(DwHandle(resources.task_group))
                .is_err()
            {
                jobs.jobs
                    .record_cleanup_bits(job_id, 1 << 0)
                    .map_err(InitError::Wyr1BModel)?;
                return send_observed_job_error(
                    system,
                    session,
                    reservation,
                    LaunchErrorCode::CleanupFailure,
                );
            }
            jobs.jobs
                .commit_terminate(job_id, resources)
                .and_then(|()| {
                    encode_job_message(
                        reservation,
                        LaunchMessageType::TerminationAccepted,
                        job_id,
                        &mut response,
                    )
                    .map(Some)
                    .map_err(|_| JobError::WrongState)
                })
        }
        LaunchMessage::ListJobs => {
            let mut ids = [0_u64; wyrmroot_launch_proto::MAX_LIVE_JOBS];
            jobs.jobs.list_reserved(ticket, &mut ids).and_then(|count| {
                encode_job_list(reservation, &ids[..count], &mut response)
                    .map(Some)
                    .map_err(|_| JobError::WrongState)
            })
        }
        LaunchMessage::CloseJob { job_id } => {
            jobs.jobs.close_job_reserved(ticket, job_id).and_then(|()| {
                jobs.drop_job_waits(grant, job_id);
                encode_job_message(
                    reservation,
                    LaunchMessageType::Closed,
                    job_id,
                    &mut response,
                )
                .map(Some)
                .map_err(|_| JobError::WrongState)
            })
        }
        LaunchMessage::Cancel {
            target_transaction_id,
        } => {
            if jobs
                .cancel_pending_wait(grant, target_transaction_id)
                .is_none()
            {
                return send_observed_job_error(
                    system,
                    session,
                    reservation,
                    LaunchErrorCode::CancellationUnavailable,
                );
            }
            encode_job_message(
                reservation,
                LaunchMessageType::Cancelled,
                target_transaction_id,
                &mut response,
            )
            .map(Some)
            .map_err(|_| JobError::WrongState)
        }
        _ => Err(JobError::WrongState),
    };
    match result {
        Ok(Some(size)) => {
            system
                .send_channel(session, &response[..size])
                .map_err(InitError::Native)?;
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(error) => send_observed_job_error(system, session, reservation, job_error_code(error)),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JobDispatchOutcome {
    Responded,
    Launched(crate::wyr1b::LoadedJob),
    /// The child exists and its READY deadline is armed, but nothing has been
    /// published yet. Reset card R6B-2: the transaction is in the arena and the
    /// dispatcher has gone back to the event loop.
    Constructed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JobWireVersion {
    Legacy,
    ShellV1,
}

fn close_shell_session_for_job<S: InitPlatform>(
    system: &mut S,
    jobs: &mut JobDispatcher,
    job_id: u64,
) -> Result<(), InitError> {
    let Some(grant) = jobs.shell_session_for_outer_job(job_id) else {
        return Ok(());
    };
    let disconnected = jobs
        .disconnect_owned_session(grant)
        .map_err(InitError::Wyr1BModel)?;
    if disconnected.owner.is_some()
        || disconnected.outer_job != Some(job_id)
        || system.close_handle(disconnected.channel).is_err()
    {
        return Err(InitError::Cleanup);
    }
    Ok(())
}

fn cleanup_shell_before_publication<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    loaded: crate::wyr1b::LoadedJob,
) -> Result<TerminationResult, InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    cleanup_shell_before_publication_before(system, waits, jobs, loaded, None)
}

fn cleanup_shell_before_publication_before<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    loaded: crate::wyr1b::LoadedJob,
    deadline_cap: Option<u64>,
) -> Result<TerminationResult, InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let cleanup = force_cleanup_job_before(system, waits, jobs, loaded, deadline_cap);
    let session_cleanup = close_shell_session_for_job(system, jobs, loaded.job_id);
    match (cleanup, session_cleanup) {
        (Ok(result), Ok(())) => Ok(result),
        _ => Err(InitError::Cleanup),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AcceptedShell {
    loaded: crate::wyr1b::LoadedJob,
    request: wyrmroot_launch_proto::ShellV1Request,
    registry_grant: EndpointGrant,
    shell_grant: EndpointGrant,
}

#[allow(clippy::too_many_arguments)]
fn accept_reserved_shell<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: &PolicyView<'_>,
    jobs: &mut JobDispatcher,
    reservation: LaunchReservation,
    request_ticket: RequestTicket,
    request: wyrmroot_launch_proto::ShellV1Request,
    received: &[DwReceivedHandleInfoV1],
    context: &mut ShellLaunchContext<'_>,
) -> Result<AcceptedShell, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    if jobs.has_shell_session() {
        let failed = close_received_reverse(system, received, received.len());
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Wyr1BModel(JobError::Capacity)
        });
    }
    let image = match policy.authorize_wyrmsh() {
        Ok(image) => image,
        Err(error) => {
            let failed = close_received_reverse(system, received, received.len());
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Wyr1BModel(error)
            });
        }
    };
    let ticket = match jobs.jobs.begin_reserved_launch(request_ticket) {
        Ok(ticket) => ticket,
        Err(error) => {
            let failed = close_received_reverse(system, received, received.len());
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Wyr1BModel(error)
            });
        }
    };
    if let Err(error) = context.state.reserve_shell_generation(request) {
        let failed = close_received_reverse(system, received, received.len())
            | jobs.jobs.abort_launch(ticket).is_err();
        return Err(if failed { InitError::Cleanup } else { error });
    }
    let group = match system.create_attempt_task_group(authority.task_group) {
        Ok(group) => group,
        Err(error) => {
            let failed = close_received_reverse(system, received, received.len())
                | jobs.jobs.abort_launch(ticket).is_err();
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Native(error)
            });
        }
    };
    let install_transaction = match context
        .state
        .reserve_install_transaction(context.topology.generation())
    {
        Ok(transaction) => transaction,
        Err(error) => {
            let failed = close_received_reverse(system, received, received.len())
                | system.close_handle(group).is_err()
                | jobs.jobs.abort_launch(ticket).is_err();
            return Err(if failed { InitError::Cleanup } else { error });
        }
    };
    let registry_grant = match context.topology.issue(
        request.requested_child_generation,
        EndpointKind::RegistryClient,
    ) {
        Ok(grant) => grant,
        Err(error) => {
            let failed = close_received_reverse(system, received, received.len())
                | system.close_handle(group).is_err()
                | jobs.jobs.abort_launch(ticket).is_err();
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Wyr1BModel(error)
            });
        }
    };
    let (registry_server, registry_client) = match create_controller_channel_pair(system) {
        Ok(pair) => pair,
        Err(error) => {
            let failed = close_received_reverse(system, received, received.len())
                | system.close_handle(group).is_err()
                | jobs.jobs.abort_launch(ticket).is_err();
            return Err(if failed { InitError::Cleanup } else { error });
        }
    };
    if let Err(error) = install_wyrmsh_registry_client(
        system,
        context.registry_control,
        registry_grant,
        registry_server,
        install_transaction,
    ) {
        let failed = close_received_reverse(system, received, received.len())
            | system.close_handle(registry_server).is_err()
            | system.close_handle(registry_client).is_err()
            | system.close_handle(group).is_err()
            | jobs.jobs.abort_launch(ticket).is_err();
        return Err(if failed { InitError::Cleanup } else { error });
    }
    let fail_after_install = |system: &mut S,
                              jobs: &mut JobDispatcher,
                              context: &mut ShellLaunchContext<'_>,
                              original: InitError,
                              close_client: bool|
     -> InitError {
        context.state.poison(registry_grant.registry_generation);
        let failed = close_received_reverse(system, received, received.len())
            | (close_client && system.close_handle(registry_client).is_err())
            | system.close_handle(group).is_err()
            | jobs.jobs.abort_launch(ticket).is_err();
        if failed { InitError::Cleanup } else { original }
    };
    if let Err(error) = preflight_wyrmsh_registry(system, registry_client, registry_grant, None) {
        return Err(fail_after_install(system, jobs, context, error, true));
    }
    let shell_grant = match context.topology.issue(
        request.requested_child_generation,
        EndpointKind::LaunchSession,
    ) {
        Ok(grant) => grant,
        Err(error) => {
            return Err(fail_after_install(
                system,
                jobs,
                context,
                InitError::Wyr1BModel(error),
                true,
            ));
        }
    };
    let (shell_controller, shell_child) = match create_controller_channel_pair(system) {
        Ok(pair) => pair,
        Err(error) => {
            return Err(fail_after_install(system, jobs, context, error, true));
        }
    };
    if let Err(error) = jobs.install_scoped_session(
        shell_grant,
        shell_controller,
        crate::wyr1b_job::LaunchSessionScope::ShellJobs,
    ) {
        let failed = system.close_handle(shell_controller).is_err()
            | system.close_handle(shell_child).is_err();
        return Err(fail_after_install(
            system,
            jobs,
            context,
            if failed {
                InitError::Cleanup
            } else {
                InitError::Wyr1BModel(error)
            },
            true,
        ));
    }
    let loaded = match load_wyrmsh_process(
        loader,
        LoadAuthority {
            task_group: group,
            ..authority
        },
        WyrmshLoadRequest {
            image,
            stdin: received[0].handle,
            stdout: received[1].handle,
            stderr: received[2].handle,
            console_status: received[3].handle,
            registry_client,
            launch_session: shell_child,
            registry_generation: registry_grant.registry_generation,
            registry_endpoint_id: registry_grant.endpoint_id,
            registry_endpoint_generation: registry_grant.endpoint_generation,
            launch_connection_id: shell_grant.endpoint_id,
            launch_connection_generation: shell_grant.endpoint_generation,
            console_generation: request.console_generation,
            status_generation: request.status_generation,
            child_generation: request.requested_child_generation,
            outer_launch_transaction: reservation.transaction_id,
            transaction_id: install_transaction,
        },
    ) {
        Ok(loaded) => loaded,
        Err(failure) => {
            let disconnected = jobs.disconnect_session(shell_grant);
            let mut failed =
                disconnected.map_or(true, |channel| system.close_handle(channel).is_err());
            if !failure.stdin_consumed {
                failed |= close_received_reverse(system, received, received.len());
                failed |= system.close_handle(registry_client).is_err();
                failed |= system.close_handle(shell_child).is_err();
            }
            failed |= system.close_handle(group).is_err();
            failed |= jobs.jobs.abort_launch(ticket).is_err();
            context.state.poison(registry_grant.registry_generation);
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Loader(failure.error)
            });
        }
    };
    if let Err(error) =
        jobs.jobs
            .stage_launch(ticket, loaded.process.0, group.0, loaded.launch_channel.0)
    {
        let failed = cleanup_loaded(system, waits, loaded, group, true).is_err()
            | jobs
                .disconnect_session(shell_grant)
                .map_or(true, |channel| system.close_handle(channel).is_err())
            | jobs.jobs.abort_launch(ticket).is_err();
        context.state.poison(registry_grant.registry_generation);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Wyr1BModel(error)
        });
    }
    let loaded_job = crate::wyr1b::LoadedJob {
        job_id: ticket.job_id(),
        loaded,
        task_group: group.0,
    };
    if let Err(error) = jobs.attach_outer_job(shell_grant, loaded_job.job_id) {
        let failed = force_cleanup_job(system, waits, jobs, loaded_job).is_err()
            | jobs
                .disconnect_session(shell_grant)
                .map_or(true, |channel| system.close_handle(channel).is_err());
        context.state.poison(registry_grant.registry_generation);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Wyr1BModel(error)
        });
    }
    let ready_deadline = match report_deadline(system) {
        Ok(deadline) => deadline,
        Err(error) => {
            let failed = cleanup_shell_before_publication(system, waits, jobs, loaded_job).is_err();
            context.state.poison(registry_grant.registry_generation);
            return Err(if failed { InitError::Cleanup } else { error });
        }
    };
    let exact_ready = await_child_ready_profile_observed(
        waits,
        loaded.process,
        loaded.launch_channel,
        LaunchProfile::Wyrmsh,
        install_transaction,
        ready_deadline,
    )
    .is_ok();
    let running = waits
        .query_task_termination(loaded.process)
        .is_ok_and(|info| info.state == deepwyrm_syscall::DW_TASK_STATE_RUNNING);
    if !exact_ready || !running {
        let failed = cleanup_shell_before_publication(system, waits, jobs, loaded_job).is_err();
        context.state.poison(registry_grant.registry_generation);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Supervision
        });
    }
    if let Err(error) =
        jobs.jobs
            .commit_launch(ticket, loaded.process.0, group.0, loaded.launch_channel.0)
    {
        let failed = cleanup_shell_before_publication(system, waits, jobs, loaded_job).is_err();
        context.state.poison(registry_grant.registry_generation);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Wyr1BModel(error)
        });
    }
    Ok(AcceptedShell {
        loaded: loaded_job,
        request,
        registry_grant,
        shell_grant,
    })
}

fn send_versioned_job_error<S: InitPlatform>(
    system: &mut S,
    session: DwHandle,
    reservation: LaunchReservation,
    version: JobWireVersion,
    code: LaunchErrorCode,
) -> Result<(), InitError> {
    match version {
        JobWireVersion::Legacy => send_job_error(system, session, reservation, code),
        JobWireVersion::ShellV1 => send_shell_v1_error(system, session, reservation, code),
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch_one_job_request<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: Option<&PolicyView<'_>>,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    grant: EndpointGrant,
) -> Result<JobDispatchOutcome, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    dispatch_one_job_request_inner(
        system, loader, waits, authority, policy, jobs, session, grant, None,
    )
}

#[allow(clippy::too_many_arguments)]
fn dispatch_one_job_request_with_shell<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: Option<&PolicyView<'_>>,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    grant: EndpointGrant,
    shell: &mut ShellLaunchContext<'_>,
) -> Result<JobDispatchOutcome, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    dispatch_one_job_request_inner(
        system,
        loader,
        waits,
        authority,
        policy,
        jobs,
        session,
        grant,
        Some(shell),
    )
}

#[allow(clippy::too_many_arguments)]
fn dispatch_one_job_request_inner<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: Option<&PolicyView<'_>>,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    grant: EndpointGrant,
    mut shell: Option<&mut ShellLaunchContext<'_>>,
) -> Result<JobDispatchOutcome, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let scope = jobs.session_scope(grant).map_err(InitError::Wyr1BModel)?;
    let legacy_handle_limit = wyrmroot_launch_proto::STREAM_COUNT;
    let mut bytes = [0_u8; wyrmroot_launch_proto::MAX_LAUNCH_MESSAGE_BYTES];
    let mut received =
        [DwReceivedHandleInfoV1::default(); wyrmroot_launch_proto::SHELL_V1_HANDLE_COUNT];
    let counts = system
        .receive_channel(session, &mut bytes, &mut received)
        .map_err(InitError::Native)?;
    if counts.bytes > bytes.len() || counts.handles > received.len() {
        let failed = close_received_reverse(system, &received, counts.handles);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Wyr1BModel(JobError::StreamPolicy)
        });
    }
    let (version, reservation) = match parse_reservation_prefix(&bytes[..counts.bytes]) {
        Ok(reservation) => (JobWireVersion::Legacy, reservation),
        Err(_) => match parse_shell_v1_reservation_prefix(&bytes[..counts.bytes]) {
            Ok(reservation) => (JobWireVersion::ShellV1, reservation),
            Err(_) => {
                let failed = close_received_reverse(system, &received, counts.handles);
                return Err(if failed {
                    InitError::Cleanup
                } else if counts.handles > legacy_handle_limit {
                    InitError::Wyr1BModel(JobError::StreamPolicy)
                } else {
                    InitError::Wyr1BModel(JobError::WrongState)
                });
            }
        },
    };
    if version == JobWireVersion::Legacy && counts.handles > legacy_handle_limit {
        let failed = close_received_reverse(system, &received, counts.handles);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Wyr1BModel(JobError::StreamPolicy)
        });
    }
    if reservation.connection_id != grant.endpoint_id
        || reservation.generation != grant.endpoint_generation
    {
        let failed = close_received_reverse(system, &received, counts.handles);
        if failed {
            return Err(InitError::Cleanup);
        }
        send_versioned_job_error(
            system,
            session,
            reservation,
            version,
            LaunchErrorCode::StaleOrUnknownSession,
        )?;
        return Ok(JobDispatchOutcome::Responded);
    }
    let request_ticket = match jobs.jobs.reserve_request(reservation) {
        Ok(ticket) => ticket,
        Err(error) => {
            let failed = close_received_reverse(system, &received, counts.handles);
            if failed {
                return Err(InitError::Cleanup);
            }
            send_versioned_job_error(system, session, reservation, version, job_error_code(error))?;
            return Ok(JobDispatchOutcome::Responded);
        }
    };
    if version == JobWireVersion::ShellV1 {
        let parsed_shell = match parse_shell_v1_request(&bytes[..counts.bytes], counts.handles) {
            Ok(parsed) => parsed,
            Err(_) => {
                let failed = close_received_reverse(system, &received, counts.handles);
                if failed {
                    return Err(InitError::Cleanup);
                }
                send_shell_v1_error(
                    system,
                    session,
                    reservation,
                    LaunchErrorCode::MalformedRequest,
                )?;
                return Ok(JobDispatchOutcome::Responded);
            }
        };
        if !scope.admits_shell_v1() {
            if close_received_reverse(system, &received, counts.handles) {
                return Err(InitError::Cleanup);
            }
            send_shell_v1_error(
                system,
                session,
                reservation,
                LaunchErrorCode::PolicyRejected,
            )?;
            return Ok(JobDispatchOutcome::Responded);
        }
        for info in &received[..counts.handles] {
            if let Err(error) = validate_controller_channel(system, info.handle) {
                if close_received_reverse(system, &received, counts.handles) {
                    return Err(InitError::Cleanup);
                }
                send_shell_v1_error(system, session, reservation, launch_error_code(&error))?;
                return Ok(JobDispatchOutcome::Responded);
            }
        }
        let (Some(policy), Some(shell)) = (policy, shell.as_deref_mut()) else {
            if close_received_reverse(system, &received, counts.handles) {
                return Err(InitError::Cleanup);
            }
            send_shell_v1_error(system, session, reservation, LaunchErrorCode::LoaderFailure)?;
            return Ok(JobDispatchOutcome::Responded);
        };
        let accepted = match accept_reserved_shell(
            system,
            loader,
            waits,
            authority,
            policy,
            jobs,
            reservation,
            request_ticket,
            parsed_shell.request,
            &received[..counts.handles],
            shell,
        ) {
            Ok(accepted) => accepted,
            Err(error) => {
                let response = send_shell_v1_error(
                    system,
                    session,
                    reservation,
                    shell_launch_error_code(&error),
                );
                return if error == InitError::Cleanup {
                    Err(error)
                } else {
                    response?;
                    Ok(JobDispatchOutcome::Responded)
                };
            }
        };
        let loaded = accepted.loaded;
        let release = jobs
            .jobs
            .release_launch_channel(loaded.job_id, loaded.loaded.launch_channel.0)
            .map_err(InitError::Wyr1BModel)?;
        let mut response = [0_u8; wyrmroot_launch_proto::SHELL_V1_REPLY_BYTES];
        let response_size = encode_shell_v1_accepted(reservation, loaded.job_id, &mut response)
            .map_err(|_| InitError::Accounting)?;
        if let Err(error) = system.send_channel(session, &response[..response_size]) {
            jobs.jobs.restore_launch_channel(release);
            shell.state.poison(shell.topology.generation());
            return Err(
                if cleanup_shell_before_publication(system, waits, jobs, loaded).is_err() {
                    InitError::Cleanup
                } else {
                    InitError::Native(error)
                },
            );
        }
        if system.close_handle(loaded.loaded.launch_channel).is_err() {
            jobs.jobs.restore_launch_channel(release);
            jobs.jobs
                .record_cleanup_bits(loaded.job_id, 1 << 2)
                .map_err(InitError::Wyr1BModel)?;
            shell.state.poison(shell.topology.generation());
            let _ = cleanup_shell_before_publication(system, waits, jobs, loaded);
            return Err(InitError::Cleanup);
        }
        return Ok(JobDispatchOutcome::Launched(
            jobs.jobs
                .loaded_job(loaded.job_id)
                .map_err(InitError::Wyr1BModel)?,
        ));
    }
    let parsed = match parse_launch_message(&bytes[..counts.bytes], counts.handles) {
        Ok(parsed) => parsed,
        Err(_) => {
            let failed = close_received_reverse(system, &received, counts.handles);
            if failed {
                return Err(InitError::Cleanup);
            }
            send_job_error(
                system,
                session,
                reservation,
                LaunchErrorCode::MalformedRequest,
            )?;
            return Ok(JobDispatchOutcome::Responded);
        }
    };
    match parsed.message {
        LaunchMessage::Launch(request) => {
            if !scope.admits_legacy_launch(request.path) {
                if close_received_reverse(system, &received, counts.handles) {
                    return Err(InitError::Cleanup);
                }
                send_observed_job_error(
                    system,
                    session,
                    reservation,
                    LaunchErrorCode::PolicyRejected,
                )?;
                return Ok(JobDispatchOutcome::Responded);
            }
            let Some(policy) = policy else {
                if close_received_reverse(system, &received, counts.handles) {
                    return Err(InitError::Cleanup);
                }
                send_observed_job_error(
                    system,
                    session,
                    reservation,
                    LaunchErrorCode::PolicyRejected,
                )?;
                return Ok(JobDispatchOutcome::Responded);
            };
            defer_reserved_launch(
                system,
                loader,
                waits,
                authority,
                policy,
                jobs,
                session,
                grant,
                scope,
                reservation,
                request_ticket,
                request,
                &received[..legacy_handle_limit],
                counts.handles,
            )
        }
        message => {
            if close_received_reverse(system, &received, counts.handles) {
                return Err(InitError::Cleanup);
            }
            dispatch_reserved_operation_observed(
                system,
                waits,
                jobs,
                session,
                grant,
                reservation,
                request_ticket,
                message,
                &bytes[..counts.bytes],
                scope,
                shell.map(|context| &mut *context.state),
            )?;
            Ok(JobDispatchOutcome::Responded)
        }
    }
}

/// Rolls back the launch a departing session left parked, if it left one.
///
/// Reset card R6C's cancel edge. A session that peer-closes, or that is
/// disconnected by the tick's emergency cleanup, may have a transaction still
/// sitting at `AwaitingReady`: its child is constructed and unpublished, and the
/// only names for that child's Process, launch Channel and TaskGroup are in the
/// arena slot. Disconnecting the session without this would close the Channel
/// the slot recorded and leave the child to be collected at its deadline --
/// bounded, but by then the reply would be attempted on a closed handle and the
/// resources would have sat for the whole budget.
///
/// Nothing is sent. The peer that would have received `LAUNCH_ACCEPTED` or
/// `ERROR` is exactly the peer that has gone.
fn cancel_parked_launch<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    grant: EndpointGrant,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let Some(token) = jobs.launches.session_transaction(grant) else {
        return Ok(());
    };
    if jobs
        .launches
        .stage(token)
        .map_err(launch_transaction_error)?
        != LaunchStage::AwaitingReady
    {
        // Every other open stage is reached and left inside one call. A
        // transaction found in one here would mean a launch was parked at a
        // stage nothing polls, which is an accounting fault rather than a
        // cancel.
        return Err(InitError::Accounting);
    }
    let reservation = jobs
        .launches
        .response_envelope(token)
        .map_err(launch_transaction_error)?
        .1;
    let job_id = jobs
        .launches
        .job_id(token)
        .map_err(launch_transaction_error)?;
    let profile = jobs
        .launches
        .profile(token)
        .map_err(launch_transaction_error)?
        .ok_or(InitError::Accounting)?;
    let prepared = jobs
        .jobs
        .staged_job(
            grant.endpoint_id,
            grant.endpoint_generation,
            job_id,
            reservation.transaction_id,
            profile,
        )
        .map_err(InitError::Wyr1BModel)?;
    jobs.launches
        .take_resources(token)
        .map_err(launch_transaction_error)?;
    let cleanup_failed = rollback_prepared_job(system, waits, jobs, prepared).is_err();
    close_deferred_launch(jobs, token, false)?;
    if cleanup_failed {
        return Err(InitError::Cleanup);
    }
    Ok(())
}

/// Whether a parked launch has anything to say yet.
///
/// Reset card R6C. `finish_deferred_launch` ends in `observe_prepared_ready`,
/// which waits on the child's launch Channel and Process until one of them
/// signals or the READY deadline expires. R6B-2 moved that wait to a tick of
/// its own; it did not stop it being a wait, so a child that never answers
/// still held the tick that went to finish it.
///
/// This is the gate. It polls the same two handles the observation will wait
/// on, with an already-passed deadline, so it cannot block:
///
/// - something signalled that the observation can act on without waiting again
///   -- a READY message, or the child's exit -- so the launch is finished now;
/// - nothing signalled and the budget is spent, so the launch is failed here
///   without observing at all. Handing the spent deadline back to
///   `observe_prepared_ready` and letting its own `wait_many` time out would
///   reach the same disposition in production, but by way of a second clock --
///   the one the wait sees rather than the one the loop measured against. One
///   clock decides, and it is this one;
/// - nothing signalled and there is budget left, so the launch stays parked and
///   the tick goes on to the sessions.
///
/// READY is checked before expiry deliberately. A child that signalled in the
/// same instant its deadline passed is published, exactly as the one-frame
/// `wait_many` would have published it -- the deadline bounds how long the
/// supervisor waits, not how late an answer may be.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParkedLaunch {
    /// Silent, with budget left. Stays parked.
    Waiting,
    /// Its Channel or its Process said something. Finish it.
    Signalled,
    /// Silent, and out of budget. Fail it.
    Expired,
}

fn parked_launch_disposition<S: Wyr1BPlatform>(
    system: &mut S,
    jobs: &JobDispatcher,
    token: LaunchToken,
    now_ns: u64,
) -> Result<ParkedLaunch, InitError> {
    let resources = jobs
        .launches
        .resources(token)
        .map_err(launch_transaction_error)?
        .ok_or(InitError::Accounting)?;
    let deadline = jobs
        .launches
        .ready_deadline(token)
        .map_err(launch_transaction_error)?
        .ok_or(InitError::Accounting)?;
    // R6D. `PEER_CLOSED` is deliberately not asked for, and this is the whole
    // reason the gate is a signal set rather than "did anything happen".
    //
    // `await_child_ready_profile_observed` branches on what its own wait
    // selects. `READABLE` is the READY message, which it receives and parses;
    // `EXITED` is the early-exit record, which it queries and returns. Both
    // finish without waiting again. But a launch Channel that is `PEER_CLOSED`
    // and *not* `READABLE` sends it into a second `wait_many` for the Process's
    // `EXITED`, and that one is bounded only by the launch's own deadline. A
    // child that dropped its end of the Channel and then declined to die would
    // hold the tick for the whole budget -- one failing child blocking every
    // other launch client, which is exactly what R6D has to refute.
    //
    // So a peer-closed-but-silent child is left parked. Its Channel stays
    // closed, so the condition is level-triggered and every later tick sees it
    // again; it leaves through `Expired` when the budget runs out, by the same
    // door as a child that said nothing at all. What is lost is the terminal
    // record `PeerClosedBeforeReady` would have carried, and only when the
    // Process outlives its Channel by the whole budget.
    let items = [
        DwWaitItemV1 {
            handle: resources.launch_channel,
            signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0),
        },
        DwWaitItemV1 {
            handle: resources.process,
            signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_EXITED.0),
        },
    ];
    match system.wait_many(&items, DwDeadline(now_ns)) {
        Ok(_) => Ok(ParkedLaunch::Signalled),
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {
            if now_ns >= deadline.0 {
                Ok(ParkedLaunch::Expired)
            } else {
                Ok(ParkedLaunch::Waiting)
            }
        }
        Err(error) => Err(InitError::Native(error)),
    }
}

/// Runs the half of a launch that was left parked, on a tick of its own.
///
/// Reset card R6B-2. This is `finish_constructed_launch` with its inputs read
/// back out of the arena instead of off the frame that constructed them, and
/// with the evidence record finished from the digests taken then. The sequence
/// inside `finish_constructed_launch` is untouched, including every rollback.
///
/// The prepared job is not stored; it is asked for. `JobController::staged_job`
/// rebuilds it from the model's own record of the job, which is why a slot can
/// be resolved a tick later without the arena holding a `LaunchTicket` that
/// names a job-table position the model may have reused. The handles the model
/// hands back are checked against the ones the arena recorded, because two
/// records of the same child disagreeing is exactly the state neither of them
/// could detect alone.
fn finish_deferred_launch<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    token: LaunchToken,
    mut shell: Option<&mut ShellLaunchContext<'_>>,
    disposition: ParkedLaunch,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    // A build with no evidence surface and no recovery trigger has nothing to
    // ask the shell context for; it still takes one, because the caller is the
    // same poll loop in every build.
    let _ = &mut shell;
    let (session, reservation) = jobs
        .launches
        .response_envelope(token)
        .map_err(launch_transaction_error)?;
    let grant = jobs
        .launches
        .grant(token)
        .map_err(launch_transaction_error)?;
    let job_id = jobs
        .launches
        .job_id(token)
        .map_err(launch_transaction_error)?;
    let deadline = jobs
        .launches
        .ready_deadline(token)
        .map_err(launch_transaction_error)?
        .ok_or(InitError::Accounting)?;
    let profile = jobs
        .launches
        .profile(token)
        .map_err(launch_transaction_error)?
        .ok_or(InitError::Accounting)?;
    let recorded = jobs
        .launches
        .resources(token)
        .map_err(launch_transaction_error)?
        .ok_or(InitError::Accounting)?;
    let prepared = jobs
        .jobs
        .staged_job(
            grant.endpoint_id,
            grant.endpoint_generation,
            job_id,
            reservation.transaction_id,
            profile,
        )
        .map_err(InitError::Wyr1BModel)?;
    if prepared.loaded.process != recorded.process
        || prepared.loaded.launch_channel != recorded.launch_channel
        || prepared.task_group != recorded.task_group.0
    {
        return Err(InitError::Accounting);
    }
    // The transaction stops owning the handles here. Whichever way the rest of
    // this goes -- published, or rolled back -- they are accounted for by the
    // model or closed by the rollback, and a slot that still claimed them could
    // not be closed at all.
    jobs.launches
        .take_resources(token)
        .map_err(launch_transaction_error)?;
    let constructed = ConstructedLaunch {
        prepared,
        deadline,
        session,
        reservation,
    };
    let outcome = match disposition {
        ParkedLaunch::Signalled => finish_constructed_launch(system, waits, jobs, constructed),
        // Out of budget, and nothing to observe. This is the disposition the
        // one-frame path reached when its `wait_many` hit the deadline, and the
        // rollback is the same one: the child is not published, and whether the
        // teardown itself failed is what decides between `Cleanup` and
        // `Supervision`.
        ParkedLaunch::Waiting | ParkedLaunch::Expired => Err(
            if rollback_prepared_job(system, waits, jobs, constructed.prepared).is_err() {
                InitError::Cleanup
            } else {
                InitError::Supervision
            },
        ),
    };
    let published = match outcome {
        Ok(_) => Ok(()),
        Err(error) => {
            // Best-effort, and deliberately not `?`. The reply is owed to a
            // session that may already be gone -- peer close, or an emergency
            // disconnect elsewhere in the tick, closes the Channel this slot
            // recorded, and sending on a closed handle fails. What is *not*
            // best-effort is emptying the slot below: a transaction left open
            // here would be handed back by `awaiting_ready_from` on every
            // subsequent tick, for ever, holding a child nothing else can name.
            let reply =
                send_deferred_launch_error(system, session, reservation, launch_error_code(&error));
            Err(match reply {
                Ok(()) => error,
                // A failed reply does not relabel the launch's own failure, for
                // the same reason `LaunchTransactions::fail` keeps the first
                // disposition: the caller asked why the launch failed, not what
                // went wrong telling it.
                Err(InitError::Cleanup) => InitError::Cleanup,
                Err(_) => error,
            })
        }
    };
    close_deferred_launch(jobs, token, published.is_ok())?;
    // One launch failing is not the tick failing. The one-frame path answered a
    // failed launch with an `ERROR` reply and returned `Responded`, and only a
    // failed *cleanup* escalated -- because a cleanup that did not happen means
    // resources nobody can name, while a child that missed READY has already
    // been rolled back by the time we get here. R6C keeps that split: a launch
    // that never answers must not take down the supervisor, which is most of
    // what R6D has to prove.
    match published {
        Ok(()) => Ok(()),
        Err(InitError::Cleanup) => Err(InitError::Cleanup),
        Err(_) => Ok(()),
    }
}

/// Walks the parked transaction out of the arena by the same door every
/// transaction leaves by: a disposition, then `Cleanup`, then `Complete`.
fn close_deferred_launch(
    jobs: &mut JobDispatcher,
    token: LaunchToken,
    published: bool,
) -> Result<(), InitError> {
    let disposition = if published {
        LaunchStage::Published
    } else {
        LaunchStage::Failing
    };
    jobs.launches
        .advance(token, disposition)
        .map_err(launch_transaction_error)?;
    jobs.launches
        .advance(token, LaunchStage::Cleanup)
        .map_err(launch_transaction_error)?;
    jobs.launches
        .advance(token, LaunchStage::Complete)
        .map_err(launch_transaction_error)?;
    jobs.launches
        .close(token)
        .map(|_| ())
        .map_err(launch_transaction_error)
}

/// Sends the error reply a deferred launch owes its session, and records it.
fn send_deferred_launch_error<S: Wyr1BPlatform>(
    system: &mut S,
    session: DwHandle,
    reservation: LaunchReservation,
    code: LaunchErrorCode,
) -> Result<(), InitError> {
    let mut response = [0_u8; 88];
    let size =
        encode_launch_error(reservation, code, &mut response).map_err(|_| InitError::Accounting)?;
    system
        .send_channel(session, &response[..size])
        .map_err(InitError::Native)?;
    Ok(())
}

/// E3C adapter for the selected console controller. The caller supplies the
/// current registry generation and poison state; request bytes cannot select
/// either authority.
#[allow(clippy::too_many_arguments)]
pub(crate) fn poll_job_dispatcher_with_shell<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    jobs: &mut JobDispatcher,
    now_ns: u64,
    shell: &mut ShellLaunchContext<'_>,
) -> Result<JobDispatcherPollOutcome, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    poll_job_dispatcher_inner(system, loader, waits, authority, jobs, now_ns, Some(shell))
}

#[allow(clippy::too_many_arguments)]
fn poll_job_dispatcher_inner<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    jobs: &mut JobDispatcher,
    now_ns: u64,
    mut shell: Option<&mut ShellLaunchContext<'_>>,
) -> Result<JobDispatcherPollOutcome, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut outcome = JobDispatcherPollOutcome::Stable;
    // Reset cards R6B-2 and R6C. A launch parked by a previous tick is looked at
    // before any new request is read -- the child is already alive and its READY
    // deadline is already running, so it has the older claim -- but it is only
    // *finished* if its own handles say something has happened, or if its budget
    // has run out. R6B-2 moved the blocking observation off the frame that read
    // the request; R6C is what stops it blocking the tick as well.
    //
    // The tick does not end here either way. A parked child that is still
    // silent costs one non-blocking poll of two handles, and the session poll
    // below runs regardless, which is the property R6D has to prove: a child
    // that never answers cannot take a session's turn.
    //
    // The cursor moves past the slot it looked at, so a silent child cannot
    // starve the one behind it.
    if let Some(token) = jobs.launches.awaiting_ready_from(jobs.launch_cursor) {
        jobs.launch_cursor = token.slot().wrapping_add(1);
        match parked_launch_disposition(system, jobs, token, now_ns)? {
            ParkedLaunch::Waiting => {}
            disposition => finish_deferred_launch(
                system,
                waits,
                jobs,
                token,
                shell.as_deref_mut(),
                disposition,
            )?,
        }
    }
    if let Some((grant, session)) = jobs.next_session() {
        let item = DwWaitItemV1 {
            handle: session,
            signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        };
        match system.wait_many(core::slice::from_ref(&item), DwDeadline(now_ns)) {
            Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {}
            Err(error) => return Err(InitError::Native(error)),
            Ok(observed) if observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 => {
                // Read before the dispatch, which may disconnect the session.
                let scope = jobs.session_scope(grant).map_err(InitError::Wyr1BModel)?;
                let size = system
                    .query_memory_object_size(authority.bootfs)
                    .map_err(InitError::Native)?;
                let plan = MappingPlan::for_bootfs(size).map_err(InitError::Mapping)?;
                let dispatched = system
                    .with_bootfs_bytes(
                        authority.parent_root,
                        authority.bootfs,
                        plan,
                        |system, bootfs| {
                            let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
                            let manifest = archive
                                .lookup(MANIFEST_PATH.as_bytes())
                                .map_err(map_lookup)?;
                            let boot_generation: [u8; 32] = manifest
                                .data()
                                .get(48..80)
                                .ok_or(InitError::Accounting)?
                                .try_into()
                                .map_err(|_| InitError::Accounting)?;
                            let policy = PolicyView::from_bootfs(archive, boot_generation)
                                .map_err(InitError::Wyr1BModel)?;
                            if let Some(shell) = shell.as_deref_mut() {
                                dispatch_one_job_request_with_shell(
                                    system,
                                    loader,
                                    waits,
                                    authority,
                                    Some(&policy),
                                    jobs,
                                    session,
                                    grant,
                                    shell,
                                )
                            } else {
                                dispatch_one_job_request(
                                    system,
                                    loader,
                                    waits,
                                    authority,
                                    Some(&policy),
                                    jobs,
                                    session,
                                    grant,
                                )
                            }
                        },
                    )
                    .map_err(InitError::Native)?;
                if let Err(dispatch_error) = dispatched {
                    // R6C. Whatever this session had in flight goes with it.
                    let cancel_failed = cancel_parked_launch(system, waits, jobs, grant).is_err();
                    // Both arms ran the same emergency cleanup; only one said
                    // which half of it failed. The other collapsed to a bare
                    // `Cleanup`, losing the initiating error entirely -- the
                    // collapse `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` 3.2 says
                    // owes an instance. One arm now, and the reported kind is
                    // unchanged: a failed cleanup still reports kind 04.
                    let disconnected = jobs.disconnect_owned_session(grant);
                    let emergency_cleanup = match disconnected {
                        Ok(session) => {
                            let channel_close_failed =
                                system.close_handle(session.channel).is_err();
                            let owner_cleanup_failed =
                                cleanup_session_owner(system, waits, session.owner, true);
                            EmergencyCleanup::Attempted {
                                channel_close_failed,
                                owner_cleanup_failed,
                            }
                        }
                        Err(_) => EmergencyCleanup::DisconnectFailed,
                    };
                    let emergency_cleanup = match emergency_cleanup {
                        EmergencyCleanup::Attempted {
                            channel_close_failed,
                            owner_cleanup_failed,
                        } => EmergencyCleanup::Attempted {
                            channel_close_failed,
                            owner_cleanup_failed: owner_cleanup_failed | cancel_failed,
                        },
                        other => other,
                    };
                    // F3A.7j. Named by the session's scope, so a failed
                    // request says whose it was; `attribute_failure` keeps
                    // an operation the error already carries.
                    let operation = match scope {
                        LaunchSessionScope::ConsoleLauncher => {
                            RecoveryOperation::DispatchConsoleJob
                        }
                        LaunchSessionScope::ShellJobs => RecoveryOperation::DispatchShellJob,
                    };
                    let attributed =
                        attribute_failure(operation, Err::<(), _>(dispatch_error)).unwrap_err();
                    return Err(dispatch_failure(attributed, emergency_cleanup));
                }
            }
            Ok(observed) if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 => {
                let scope = jobs.session_scope(grant).map_err(InitError::Wyr1BModel)?;
                let defer_console_retirement = false;
                // When recovery owns this session and its process as one
                // coordinated retirement, observe peer close without consuming
                // either owner ahead of that join.
                if !defer_console_retirement {
                    // R6C's cancel. The peer that asked for this launch is gone
                    // before it was told the child exists, so nothing owns the
                    // child and nothing is owed a reply. Rolling it back here
                    // rather than leaving it to its deadline means the session's
                    // resources and its child's go in one step -- and means the
                    // slot is not still holding a Channel this branch is about
                    // to close.
                    cancel_parked_launch(system, waits, jobs, grant)?;
                    let outer = if scope == crate::wyr1b_job::LaunchSessionScope::ConsoleLauncher {
                        jobs.jobs
                            .loaded_job_for_owner(grant.endpoint_id, grant.endpoint_generation)
                            .map_err(InitError::Wyr1BModel)?
                    } else {
                        None
                    };
                    let disconnected = jobs
                        .disconnect_owned_session(grant)
                        .map_err(InitError::Wyr1BModel)?;
                    let mut failed = system.close_handle(disconnected.channel).is_err()
                        | cleanup_session_owner(system, waits, disconnected.owner, true)
                        | disconnected.outer_job.is_some_and(|job_id| {
                            let loaded = jobs.jobs.loaded_job(job_id);
                            loaded.map_or(true, |loaded| {
                                force_cleanup_job(system, waits, jobs, loaded).is_err()
                            })
                        });
                    if let Some(outer) = outer {
                        failed |=
                            cleanup_shell_before_publication(system, waits, jobs, outer).is_err();
                    }
                    if failed {
                        return Err(InitError::Cleanup);
                    }
                    outcome = JobDispatcherPollOutcome::SessionClosed { grant, scope };
                }
            }
            Ok(_) => return Err(InitError::Supervision),
        }
    }
    if let Some(loaded) = jobs.next_cleanup_job() {
        let terminal_staged = jobs
            .jobs
            .terminal_result(loaded.job_id)
            .map_err(InitError::Wyr1BModel)?
            .is_some();
        let exited = if terminal_staged {
            true
        } else if loaded.loaded.process.0 == 0 {
            return Err(InitError::Accounting);
        } else {
            match waits.query_task_termination(loaded.loaded.process) {
                Ok(info) => info.state == DW_TASK_STATE_EXITED,
                Err(_) => {
                    jobs.jobs
                        .record_cleanup_bits(loaded.job_id, 1 << 1)
                        .map_err(InitError::Wyr1BModel)?;
                    return Err(InitError::Cleanup);
                }
            }
        };
        if exited {
            let result = reap_job(system, waits, jobs, loaded)?;
            let nested = close_shell_session_for_job(system, jobs, loaded.job_id);
            if result.cleanup_result != 0 || nested.is_err() {
                return Err(InitError::Cleanup);
            }
        }
    }
    if let Some(shell) = shell {
        service_pending_wait_inner(system, waits, jobs, Some(&mut *shell.state))?;
    } else {
        service_pending_wait(system, waits, jobs)?;
    }
    Ok(outcome)
}

/// Latches a console child's session shutdown, at either WAIT reply.
///
/// F3A.7g. Both replies encode the same terminal result and both are reached
/// for the same child, so the fact is read once, here, rather than at two
/// sites that could drift apart.
///
/// The scope is what makes this specific. A `ConsoleLauncher` session belongs
/// to `consoled`, which launches exactly one child -- its shell -- so any
/// terminal result crossing it is that shell's. A `ShellJobs` session belongs
/// to the shell itself, and the jobs *it* launches are ordinary user programs
/// whose exit codes it prints; one of those happening to exit with the same
/// value must not end the session.
fn observe_session_shutdown_result(
    scope: LaunchSessionScope,
    state: Option<&mut ShellControllerState>,
    terminal: wyrmroot_launch_proto::TerminationResult,
) {
    if scope != LaunchSessionScope::ConsoleLauncher
        || terminal.classification != wyrmroot_launch_proto::TerminationClassification::NormalExit
        || terminal.application_code != wyrmroot_launch_proto::SHELL_SESSION_SHUTDOWN_STATUS
    {
        return;
    }
    if let Some(state) = state {
        state.observe_session_shutdown();
    }
}

fn service_pending_wait<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    service_pending_wait_inner(system, waits, jobs, None)
}

#[allow(unused_mut)]
fn service_pending_wait_inner<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    mut evidence: Option<&mut ShellControllerState>,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let Some(pending) = jobs.next_pending_wait() else {
        return Ok(());
    };
    let scope = jobs
        .session_scope(pending.grant)
        .map_err(InitError::Wyr1BModel)?;
    let result = match jobs.jobs.result_for_owner(
        pending.reservation.connection_id,
        pending.reservation.generation,
        pending.job_id,
    ) {
        Ok(result) => result,
        Err(JobError::UnknownJob) => return Ok(()),
        Err(error) => return Err(InitError::Wyr1BModel(error)),
    };
    let session = jobs
        .session_handle(pending.grant)
        .map_err(InitError::Wyr1BModel)?;
    let terminal = controller_result_to_wire(result)?;
    observe_session_shutdown_result(scope, evidence, terminal);
    let mut response = [0_u8; 88];
    let size = encode_job_result(pending.reservation, pending.job_id, terminal, &mut response)
        .map_err(|_| InitError::Accounting)?;
    if let Err(error) = system.send_channel(session, &response[..size]) {
        jobs.finish_pending_wait(pending)
            .map_err(InitError::Wyr1BModel)?;
        let disconnected = jobs
            .disconnect_owned_session(pending.grant)
            .map_err(InitError::Wyr1BModel)?;
        let failed = system.close_handle(disconnected.channel).is_err()
            | cleanup_session_owner(system, waits, disconnected.owner, true);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Native(error)
        });
    }
    jobs.finish_pending_wait(pending)
        .map_err(InitError::Wyr1BModel)
}

fn cleanup_session_owner<S, W>(
    system: &mut S,
    waits: &mut W,
    owner: Option<SessionOwner>,
    terminate: bool,
) -> bool
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    cleanup_session_owner_before(system, waits, owner, terminate, None)
}

fn cleanup_session_owner_before<S, W>(
    system: &mut S,
    waits: &mut W,
    owner: Option<SessionOwner>,
    terminate: bool,
    deadline_cap: Option<u64>,
) -> bool
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    owner.is_some_and(|owner| {
        cleanup_loaded_before(
            system,
            waits,
            LoadedProcess {
                process: owner.process,
                launch_channel: owner.launch_channel,
            },
            owner.task_group,
            terminate,
            deadline_cap,
        )
        .is_err()
    })
}

/// Retires one product consoled generation and its foreground shell while
/// preserving already-published background jobs as invisible controller-owned
/// orphans. The caller retains the dispatcher so those jobs can still reap.
pub(crate) fn retire_console_product<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    peer: InstalledPeer,
    terminate: bool,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    retire_console_product_inner(system, waits, jobs, peer, terminate, None).map(|_| ())
}

fn retire_console_product_inner<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    peer: InstalledPeer,
    terminate: bool,
    deadline_cap: Option<u64>,
) -> Result<Option<TerminationResult>, InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let outer = jobs
        .jobs
        .loaded_job_for_owner(peer.grant.endpoint_id, peer.grant.endpoint_generation)
        .map_err(InitError::Wyr1BModel)?;
    let disconnected = jobs
        .disconnect_owned_session(peer.grant)
        .map_err(InitError::Wyr1BModel)?;
    let expected_owner = SessionOwner {
        process: peer.loaded.process,
        launch_channel: peer.loaded.launch_channel,
        task_group: peer.task_group,
    };
    // Accounting disagreement must not short-circuit cleanup of resources we
    // still own. Preserve the mismatch as a cleanup failure after attempting
    // every independent close in this generation.
    let owner_mismatch = disconnected.owner != Some(expected_owner);
    let outer_mismatch = disconnected.outer_job.is_some();
    let channel_close_failed = system.close_handle(disconnected.channel).is_err();
    let owner_cleanup_failed =
        cleanup_session_owner_before(system, waits, disconnected.owner, terminate, deadline_cap);
    let mut failed = owner_mismatch | outer_mismatch | channel_close_failed | owner_cleanup_failed;
    let outer_result = match outer {
        Some(outer) => {
            match cleanup_shell_before_publication_before(system, waits, jobs, outer, deadline_cap)
            {
                Ok(result) => Some(result),
                Err(_) => {
                    failed = true;
                    None
                }
            }
        }
        None => None,
    };
    if failed {
        Err(InitError::Cleanup)
    } else {
        Ok(outer_result)
    }
}

pub(crate) fn drain_job_dispatcher<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut sessions = [None; crate::wyr1b_job::MAX_SESSIONS];
    let session_count = jobs.drain_sessions(&mut sessions);
    let mut failed = false;
    for session in sessions[..session_count].iter().rev().flatten().copied() {
        failed |= system.close_handle(session.channel).is_err()
            | cleanup_session_owner(system, waits, session.owner, true);
    }
    let job_count = jobs.jobs.live_jobs();
    for _ in 0..job_count {
        let Some(loaded) = jobs.next_cleanup_job() else {
            break;
        };
        if let Some(resources) = jobs
            .jobs
            .forced_termination_resources(loaded.job_id)
            .map_err(InitError::Wyr1BModel)?
        {
            if system
                .terminate_task_group(DwHandle(resources.task_group))
                .is_err()
            {
                jobs.jobs
                    .record_cleanup_bits(loaded.job_id, 1 << 0)
                    .map_err(InitError::Wyr1BModel)?;
                failed = true;
            } else {
                jobs.jobs
                    .commit_forced_termination(loaded.job_id, resources)
                    .map_err(InitError::Wyr1BModel)?;
            }
        }
        match reap_job(system, waits, jobs, loaded) {
            Ok(result) => failed |= result.cleanup_result != 0,
            Err(_) => failed = true,
        }
    }
    if jobs.jobs.live_jobs() != 0 || failed {
        Err(InitError::Cleanup)
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../consoled/src/stream_transfer.rs"]
mod consoled_stream_transfer;

#[cfg(test)]
mod tests {

    /// F3A.6n. `ErrorCode::Capacity` was unreachable from the case it names,
    /// and `loader-failure` was the answer to a full machine.
    #[test]
    fn a_kernel_exhaustion_is_capacity_and_only_the_loader_is_a_loader_failure() {
        use deepwyrm_syscall::DwStatus;

        // The two kernel exhaustion statuses reach the code that describes
        // them, on both launch paths.
        for status in [DW_STATUS_NO_MEMORY, DW_STATUS_NO_RESOURCES] {
            let error = InitError::Native(NativeError::Status(status));
            assert_eq!(launch_error_code(&error), LaunchErrorCode::Capacity);
            assert_eq!(shell_launch_error_code(&error), LaunchErrorCode::Capacity);
        }

        // Any other native failure is not capacity. An output-contract fault
        // is our own ABI handling, not the machine's limits.
        let other = InitError::Native(NativeError::Status(DwStatus(-5)));
        assert_eq!(launch_error_code(&other), LaunchErrorCode::LoaderFailure);
        let output = InitError::Native(NativeError::Output(
            wyrmroot_runtime::NativeOutputError::InvalidChannelReceive,
        ));
        assert_eq!(launch_error_code(&output), LaunchErrorCode::LoaderFailure);

        // A malformed ELF keeps `loader-failure`, because `tools/e7_vm.py`
        // pins exactly that answer for `run test/wyr1-e/malformed-elf`.
        assert_eq!(
            launch_error_code(&InitError::Loader(
                wyrmroot_loader::process::LoadError::Elf(wyrmroot_loader::elf::ElfError::BadMagic)
            )),
            LaunchErrorCode::LoaderFailure
        );

        // But an exhaustion inside a platform stage of the same load is
        // capacity, which is where this actually bites: the kernel's cause is
        // nested in `LoadError::Platform`, not in a bare `InitError::Native`.
        assert_eq!(
            launch_error_code(&InitError::Loader(
                wyrmroot_loader::process::LoadError::Platform {
                    stage: wyrmroot_loader::process::LoadStage::ChannelCreate,
                    cause: NativeError::Status(DW_STATUS_NO_RESOURCES),
                    rollback_failed: false,
                }
            )),
            LaunchErrorCode::Capacity
        );

        // And the shell path no longer defaults to claiming the loader failed.
        // An unclassified error says the request was refused, which claims
        // nothing about where the fault was.
        assert_eq!(
            shell_launch_error_code(&InitError::WrongActivationOrder),
            LaunchErrorCode::PolicyRejected
        );
        assert_ne!(
            shell_launch_error_code(&InitError::WrongActivationOrder),
            LaunchErrorCode::LoaderFailure
        );

        // The shell job table filling up is still its own code, unchanged:
        // that is what `Capacity` already meant and it must not be confused
        // with the kernel's exhaustion above.
        assert_eq!(
            shell_launch_error_code(&InitError::Wyr1BModel(JobError::Capacity)),
            LaunchErrorCode::Capacity
        );
    }
    extern crate alloc;

    use super::*;
    use crate::wyr1b_job::LaunchSessionScope;
    use alloc::{vec, vec::Vec};
    use deepwyrm_syscall::{DwMemoryProtection, DwStatus, DwWaitResultV1};

    use wyrmroot_loader::process::{ParentMapping, ProcessCreateRequest, ProcessCreateResult};

    const FAILURE: NativeError = NativeError::Status(DwStatus(-1));

    struct MockPlatform {
        sent: [u8; 256],
        sent_len: usize,
        transfer: DwHandleTransferV1,
        fresh_rights: DwRights,
        queried: [DwHandle; 4],
        query_count: usize,
        created_rights: DwRights,
        closed: [DwHandle; 8],
        close_count: usize,
        fail_close: Option<DwHandle>,
        now: Option<u64>,
        terminate_count: usize,
        fail_terminate: bool,
        allow_wait: bool,
        session_poll_timeout: bool,
        task_group: Option<DwHandle>,
        fail_send: bool,
        inbound: [u8; 256],
        inbound_len: usize,
        inbound_handles: [DwReceivedHandleInfoV1; 16],
        inbound_handle_count: usize,
        bootfs: Option<Vec<u8>>,
        session_poll_readable: bool,
        /// Reports the session's peer as gone, for R6C's cancel edge.
        session_poll_peer_closed: bool,
        /// What R6C's parked-launch poll should see, when a test has a parked
        /// launch at all.
        ///
        /// A poll of a parked child is the only wait on this platform that asks
        /// for `EXITED`, so it is distinguishable from the session poll without
        /// the mock having to know which handle is which. `None` means the test
        /// has no opinion and the child poll answers the same way the session
        /// poll does, which is what every test written before R6C expects.
        child_poll_readable: Option<bool>,
        /// The signals the last parked-child poll asked about, for R6D.
        child_poll_signals: Vec<u64>,
        /// The deadline of every platform wait, in order, for R6D.
        wait_deadlines: Vec<u64>,
        /// Which session Channel the last reply went to, so a test with two
        /// launch clients can say which one was answered.
        last_sent_channel: Option<DwHandle>,
    }

    impl MockPlatform {
        fn new() -> Self {
            Self {
                sent: [0; 256],
                sent_len: 0,
                transfer: DwHandleTransferV1::default(),
                fresh_rights: CONTROLLER_CHANNEL_RIGHTS,
                queried: [DwHandle(0); 4],
                query_count: 0,
                created_rights: DwRights(0),
                closed: [DwHandle(0); 8],
                close_count: 0,
                fail_close: None,
                now: None,
                terminate_count: 0,
                fail_terminate: false,
                allow_wait: false,
                session_poll_timeout: false,
                task_group: None,
                fail_send: true,
                inbound: [0; 256],
                inbound_len: 0,
                inbound_handles: [DwReceivedHandleInfoV1::default(); 16],
                inbound_handle_count: 0,
                bootfs: None,
                session_poll_readable: false,
                session_poll_peer_closed: false,
                child_poll_readable: None,
                child_poll_signals: Vec::new(),
                wait_deadlines: Vec::new(),
                last_sent_channel: None,
            }
        }
    }

    struct InitSendLoader {
        next: u64,
        closed: [DwHandle; 32],
        close_count: usize,
        transferred_service: Option<DwHandle>,
        sent_init: Vec<u8>,
        sent_transfers: Vec<DwHandleTransferV1>,
        fail_init: bool,
    }

    impl InitSendLoader {
        const fn new() -> Self {
            Self {
                next: 0x1000,
                closed: [DwHandle(0); 32],
                close_count: 0,
                transferred_service: None,
                sent_init: Vec::new(),
                sent_transfers: Vec::new(),
                fail_init: true,
            }
        }

        fn handle(&mut self) -> DwHandle {
            let handle = DwHandle(self.next);
            self.next += 1;
            handle
        }
    }

    impl LoaderPlatform for InitSendLoader {
        type Error = NativeError;

        fn channel_create(
            &mut self,
            _rights: DwRights,
        ) -> Result<(DwHandle, DwHandle), Self::Error> {
            Ok((self.handle(), self.handle()))
        }

        fn duplicate(
            &mut self,
            _handle: DwHandle,
            _rights: DwRights,
        ) -> Result<DwHandle, Self::Error> {
            Ok(self.handle())
        }

        fn close(&mut self, handle: DwHandle) -> Result<(), Self::Error> {
            self.closed[self.close_count] = handle;
            self.close_count += 1;
            Ok(())
        }

        fn process_create(
            &mut self,
            _request: ProcessCreateRequest,
        ) -> Result<ProcessCreateResult, Self::Error> {
            Ok(ProcessCreateResult {
                process: self.handle(),
                root: self.handle(),
                child_bootstrap: self.handle(),
            })
        }

        fn memory_create(
            &mut self,
            _bytes: u64,
            _rights: DwRights,
        ) -> Result<DwHandle, Self::Error> {
            Ok(self.handle())
        }

        fn materialize_parent(
            &mut self,
            _parent_root: DwHandle,
            memory: DwHandle,
            object_size: u64,
            _destination_offset: u64,
            _source: &[u8],
        ) -> Result<ParentMapping, Self::Error> {
            Ok(ParentMapping {
                address: 0x6000_0000 + memory.0 * 0x10_0000,
                bytes: object_size,
            })
        }

        fn materialize_parent_with(
            &mut self,
            _parent_root: DwHandle,
            memory: DwHandle,
            object_size: u64,
            _destination_offset: u64,
            destination_size: usize,
            materialize: impl FnOnce(&mut [u8]),
        ) -> Result<ParentMapping, Self::Error> {
            let mut destination = vec![0; destination_size];
            materialize(&mut destination);
            Ok(ParentMapping {
                address: 0x6000_0000 + memory.0 * 0x10_0000,
                bytes: object_size,
            })
        }

        fn unmap_parent(
            &mut self,
            _parent_root: DwHandle,
            _mapping: ParentMapping,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn map_child(
            &mut self,
            _child_root: DwHandle,
            _memory: DwHandle,
            _address: u64,
            _bytes: u64,
            _protection: DwMemoryProtection,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn unmap_child(
            &mut self,
            _child_root: DwHandle,
            _address: u64,
            _bytes: u64,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn thread_create(
            &mut self,
            _process: DwHandle,
            _rights: DwRights,
        ) -> Result<DwHandle, Self::Error> {
            Ok(self.handle())
        }

        fn send_init(
            &mut self,
            _channel: DwHandle,
            bytes: &[u8],
            transfers: &[DwHandleTransferV1],
        ) -> Result<(), Self::Error> {
            self.transferred_service = transfers.last().map(|transfer| transfer.handle);
            self.sent_init = bytes.to_vec();
            self.sent_transfers = transfers.to_vec();
            if self.fail_init { Err(FAILURE) } else { Ok(()) }
        }

        fn thread_start(
            &mut self,
            _thread: DwHandle,
            _entry: u64,
            _stack_pointer: u64,
            _child_bootstrap: DwHandle,
            _startup_abi: u64,
        ) -> Result<(), Self::Error> {
            if self.fail_init {
                panic!("failed INIT must prevent thread start")
            }
            Ok(())
        }

        fn thread_terminate(&mut self, _thread: DwHandle) -> Result<(), Self::Error> {
            Ok(())
        }

        fn process_terminate(&mut self, _process: DwHandle) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn executable() -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x2000];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x400000_u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&0x1000_u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&0x400000_u64.to_le_bytes());
        bytes[88..96].copy_from_slice(&0x400000_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&16_u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&32_u64.to_le_bytes());
        bytes[112..120].copy_from_slice(&4096_u64.to_le_bytes());
        bytes
    }

    impl InitPlatform for MockPlatform {
        fn query_capability_info(
            &mut self,
            handle: DwHandle,
        ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
            self.queried[self.query_count] = handle;
            self.query_count += 1;
            Ok(CapabilityInfo {
                object_type: DW_OBJECT_TYPE_CHANNEL,
                rights: self.fresh_rights,
            })
        }
        fn receive_channel(
            &mut self,
            _channel: DwHandle,
            bytes: &mut [u8],
            handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, NativeError> {
            if self.inbound_len == 0 {
                return Err(FAILURE);
            }
            if self.inbound_len > bytes.len() || self.inbound_handle_count > handles.len() {
                return Err(FAILURE);
            }
            bytes[..self.inbound_len].copy_from_slice(&self.inbound[..self.inbound_len]);
            handles[..self.inbound_handle_count]
                .copy_from_slice(&self.inbound_handles[..self.inbound_handle_count]);
            let bytes = self.inbound_len;
            let handles = self.inbound_handle_count;
            self.inbound_len = 0;
            self.inbound_handle_count = 0;
            Ok(ReceiveCounts { bytes, handles })
        }
        fn query_memory_object_size(&mut self, _handle: DwHandle) -> Result<u64, NativeError> {
            self.bootfs
                .as_ref()
                .map(|bootfs| bootfs.len() as u64)
                .ok_or(FAILURE)
        }
        fn with_bootfs_bytes<R>(
            &mut self,
            _root: DwHandle,
            _bootfs: DwHandle,
            _plan: MappingPlan,
            use_bytes: impl for<'a> FnOnce(&mut Self, &'a [u8]) -> R,
        ) -> Result<R, NativeError> {
            let bootfs = self.bootfs.take().ok_or(FAILURE)?;
            let result = use_bytes(self, &bootfs);
            self.bootfs = Some(bootfs);
            Ok(result)
        }
        fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
            if self.fail_send {
                return Err(FAILURE);
            }
            self.sent[..bytes.len()].copy_from_slice(bytes);
            self.sent_len = bytes.len();
            self.last_sent_channel = Some(channel);
            Ok(())
        }
        fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
            self.closed[self.close_count] = handle;
            self.close_count += 1;
            if self.fail_close == Some(handle) {
                Err(FAILURE)
            } else {
                Ok(())
            }
        }
        fn create_attempt_task_group(
            &mut self,
            _parent: DwHandle,
        ) -> Result<DwHandle, NativeError> {
            self.task_group.ok_or(FAILURE)
        }
        fn terminate_task_group(&mut self, _task_group: DwHandle) -> Result<(), NativeError> {
            self.terminate_count += 1;
            if self.fail_terminate {
                Err(FAILURE)
            } else {
                Ok(())
            }
        }
        fn now(&mut self) -> Result<u64, NativeError> {
            self.now.ok_or(FAILURE)
        }
        fn wait_until(&mut self, deadline_ns: u64) -> Result<(), NativeError> {
            if self.allow_wait {
                self.now = Some(deadline_ns);
                Ok(())
            } else {
                Err(FAILURE)
            }
        }
    }

    struct TerminalWaits;

    impl SupervisionPlatform for TerminalWaits {
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
            _process: DwHandle,
        ) -> Result<DwTaskTerminationInfoV1, Self::Error> {
            Ok(DwTaskTerminationInfoV1 {
                state: DW_TASK_STATE_EXITED,
                reason: DW_TERMINATION_NORMAL_EXIT,
                ..DwTaskTerminationInfoV1::default()
            })
        }
    }

    impl Wyr1BPlatform for MockPlatform {
        fn channel_create(
            &mut self,
            rights: DwRights,
        ) -> Result<(DwHandle, DwHandle), NativeError> {
            self.created_rights = rights;
            Ok((DwHandle(20), DwHandle(21)))
        }
        fn send_channel_with_handles(
            &mut self,
            _channel: DwHandle,
            bytes: &[u8],
            transfers: &[DwHandleTransferV1],
        ) -> Result<(), NativeError> {
            assert_eq!(transfers.len(), 1);
            self.sent[..bytes.len()].copy_from_slice(bytes);
            self.sent_len = bytes.len();
            self.transfer = transfers[0];
            Ok(())
        }
        fn wait_many(
            &mut self,
            items: &[DwWaitItemV1],
            deadline: DwDeadline,
        ) -> Result<DwWaitResultV1, NativeError> {
            self.wait_deadlines.push(deadline.0);
            let child_poll = items
                .iter()
                .any(|item| item.signals.0 & DW_SIGNAL_EXITED.0 != 0);
            if child_poll {
                self.child_poll_signals = items.iter().map(|item| item.signals.0).collect();
            }
            if let (true, Some(readable)) = (child_poll, self.child_poll_readable) {
                return if readable {
                    Ok(DwWaitResultV1 {
                        index: 0,
                        observed: DW_SIGNAL_READABLE,
                        ..DwWaitResultV1::default()
                    })
                } else {
                    Err(NativeError::Status(DW_STATUS_TIMED_OUT))
                };
            }
            if self.session_poll_peer_closed {
                Ok(DwWaitResultV1 {
                    index: 0,
                    observed: DW_SIGNAL_PEER_CLOSED,
                    ..DwWaitResultV1::default()
                })
            } else if self.session_poll_readable {
                Ok(DwWaitResultV1 {
                    index: 0,
                    observed: DW_SIGNAL_READABLE,
                    ..DwWaitResultV1::default()
                })
            } else if self.session_poll_timeout {
                Err(NativeError::Status(DW_STATUS_TIMED_OUT))
            } else {
                Err(FAILURE)
            }
        }

        fn materialize_read_only_memory(
            &mut self,
            _root: DwHandle,
            _bytes: &[u8],
            _rights: DwRights,
        ) -> Result<DwHandle, NativeError> {
            Ok(DwHandle(0x7fff))
        }
    }

    fn grant(kind: EndpointKind, endpoint_id: u64, role_generation: u64) -> EndpointGrant {
        EndpointGrant {
            registry_generation: 7,
            endpoint_id,
            endpoint_generation: 3,
            role_generation,
            kind,
        }
    }

    fn reservation(transaction_id: u64) -> LaunchReservation {
        LaunchReservation {
            connection_id: 1,
            generation: 3,
            transaction_id,
        }
    }

    #[test]
    fn console_shell_v1_admission_cleans_handles_and_stops_at_e3c_boundary() {
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        let mut waits = TerminalWaits;
        let mut loader = InitSendLoader::new();
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_scoped_session(owner, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
            .unwrap();
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };
        let request = wyrmroot_launch_proto::ShellV1Request {
            console_generation: 2,
            status_generation: 3,
            requested_child_generation: 4,
        };

        platform.inbound_len = wyrmroot_launch_proto::encode_shell_v1_request(
            reservation(1),
            request,
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_handle_count = 4;
        for (index, info) in platform.inbound_handles[..4].iter_mut().enumerate() {
            info.handle = DwHandle(41 + index as u64);
        }
        assert_eq!(
            dispatch_one_job_request(
                &mut platform,
                &mut loader,
                &mut waits,
                authority,
                None,
                &mut jobs,
                DwHandle(90),
                owner,
            ),
            Ok(JobDispatchOutcome::Responded)
        );
        assert_eq!(
            platform.closed[..4],
            [DwHandle(44), DwHandle(43), DwHandle(42), DwHandle(41)]
        );
        assert_eq!(
            platform.queried,
            [DwHandle(41), DwHandle(42), DwHandle(43), DwHandle(44)]
        );
        assert_eq!(platform.query_count, 4);
        assert_eq!(
            CONTROLLER_CHANNEL_RIGHTS.0 & deepwyrm_syscall::DW_RIGHT_DUPLICATE.0,
            0
        );
        assert_eq!(
            wyrmroot_launch_proto::parse_shell_v1_reply(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .reply,
            wyrmroot_launch_proto::ShellV1Reply::Error {
                code: LaunchErrorCode::LoaderFailure,
            }
        );
        assert_eq!(jobs.jobs.live_jobs(), 0);

        platform.inbound_len = wyrmroot_launch_proto::encode_shell_v1_request(
            reservation(1),
            request,
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_handle_count = 4;
        for (index, info) in platform.inbound_handles[..4].iter_mut().enumerate() {
            info.handle = DwHandle(51 + index as u64);
        }
        dispatch_one_job_request(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            None,
            &mut jobs,
            DwHandle(90),
            owner,
        )
        .unwrap();
        assert_eq!(
            platform.closed[4..8],
            [DwHandle(54), DwHandle(53), DwHandle(52), DwHandle(51)]
        );
        assert_eq!(
            wyrmroot_launch_proto::parse_shell_v1_reply(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .reply,
            wyrmroot_launch_proto::ShellV1Reply::Error {
                code: LaunchErrorCode::TransactionReplay,
            }
        );
    }

    #[test]
    fn e3c_shell_identity_namespaces_are_independently_fresh() {
        let mut state = ShellControllerState::new(1).unwrap();
        state
            .reserve_shell_generation(wyrmroot_launch_proto::ShellV1Request {
                console_generation: 2,
                status_generation: 3,
                requested_child_generation: 4,
            })
            .unwrap();
        assert_eq!(
            state.reserve_shell_generation(wyrmroot_launch_proto::ShellV1Request {
                console_generation: 3,
                status_generation: 3,
                requested_child_generation: 5,
            }),
            Err(InitError::Wyr1BModel(JobError::StaleGeneration))
        );
        assert_eq!(
            state.reserve_shell_generation(wyrmroot_launch_proto::ShellV1Request {
                console_generation: 3,
                status_generation: 4,
                requested_child_generation: 4,
            }),
            Err(InitError::Wyr1BModel(JobError::StaleGeneration))
        );
        state
            .reserve_shell_generation(wyrmroot_launch_proto::ShellV1Request {
                console_generation: 2,
                status_generation: 4,
                requested_child_generation: 5,
            })
            .unwrap();
    }

    #[test]
    fn malformed_shell_v1_is_cleaned_and_its_fresh_transaction_replays() {
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        let mut waits = TerminalWaits;
        let mut loader = InitSendLoader::new();
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_scoped_session(owner, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
            .unwrap();
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };
        let request = wyrmroot_launch_proto::ShellV1Request {
            console_generation: 2,
            status_generation: 3,
            requested_child_generation: 4,
        };
        platform.inbound_len = wyrmroot_launch_proto::encode_shell_v1_request(
            reservation(1),
            request,
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound[112] ^= 1;
        platform.inbound_handle_count = 4;
        for (index, info) in platform.inbound_handles[..4].iter_mut().enumerate() {
            info.handle = DwHandle(41 + index as u64);
        }
        dispatch_one_job_request(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            None,
            &mut jobs,
            DwHandle(90),
            owner,
        )
        .unwrap();
        assert_eq!(
            wyrmroot_launch_proto::parse_shell_v1_reply(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .reply,
            wyrmroot_launch_proto::ShellV1Reply::Error {
                code: LaunchErrorCode::MalformedRequest,
            }
        );
        assert_eq!(platform.close_count, 4);
        assert_eq!(platform.query_count, 0);

        platform.inbound_len = wyrmroot_launch_proto::encode_shell_v1_request(
            reservation(1),
            request,
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_handle_count = 4;
        for (index, info) in platform.inbound_handles[..4].iter_mut().enumerate() {
            info.handle = DwHandle(51 + index as u64);
        }
        dispatch_one_job_request(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            None,
            &mut jobs,
            DwHandle(90),
            owner,
        )
        .unwrap();
        assert_eq!(
            wyrmroot_launch_proto::parse_shell_v1_reply(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .reply,
            wyrmroot_launch_proto::ShellV1Reply::Error {
                code: LaunchErrorCode::TransactionReplay,
            }
        );
        assert_eq!(platform.close_count, 8);
        assert_eq!(platform.query_count, 0);
    }

    #[test]
    fn shell_v1_receive_failure_retains_uncommitted_sender_handles() {
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        let mut waits = TerminalWaits;
        let mut loader = InitSendLoader::new();
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_scoped_session(owner, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
            .unwrap();
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };
        platform.inbound_len = wyrmroot_launch_proto::encode_shell_v1_request(
            reservation(1),
            wyrmroot_launch_proto::ShellV1Request {
                console_generation: 2,
                status_generation: 3,
                requested_child_generation: 4,
            },
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_handle_count = 5;
        for (index, info) in platform.inbound_handles[..5].iter_mut().enumerate() {
            info.handle = DwHandle(41 + index as u64);
        }

        assert_eq!(
            dispatch_one_job_request(
                &mut platform,
                &mut loader,
                &mut waits,
                authority,
                None,
                &mut jobs,
                DwHandle(90),
                owner,
            ),
            Err(InitError::Native(FAILURE))
        );
        assert_eq!(platform.inbound_handle_count, 5);
        assert_eq!(platform.close_count, 0);
        assert_eq!(platform.sent_len, 0);
    }

    #[test]
    fn shell_v1_rejects_duplicate_rights_after_committed_move_cleanup() {
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        platform.fresh_rights =
            DwRights(CONTROLLER_CHANNEL_RIGHTS.0 | deepwyrm_syscall::DW_RIGHT_DUPLICATE.0);
        let mut waits = TerminalWaits;
        let mut loader = InitSendLoader::new();
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_scoped_session(owner, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
            .unwrap();
        platform.inbound_len = wyrmroot_launch_proto::encode_shell_v1_request(
            reservation(1),
            wyrmroot_launch_proto::ShellV1Request {
                console_generation: 2,
                status_generation: 3,
                requested_child_generation: 4,
            },
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_handle_count = 4;
        for (index, info) in platform.inbound_handles[..4].iter_mut().enumerate() {
            info.handle = DwHandle(41 + index as u64);
        }
        dispatch_one_job_request(
            &mut platform,
            &mut loader,
            &mut waits,
            LoadAuthority {
                parent_root: DwHandle(1),
                bootfs: DwHandle(2),
                task_group: DwHandle(3),
            },
            None,
            &mut jobs,
            DwHandle(90),
            owner,
        )
        .unwrap();
        assert_eq!(platform.query_count, 1);
        assert_eq!(platform.close_count, 4);
        assert_eq!(
            wyrmroot_launch_proto::parse_shell_v1_reply(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .reply,
            wyrmroot_launch_proto::ShellV1Reply::Error {
                code: LaunchErrorCode::PolicyRejected,
            }
        );
    }

    #[test]
    fn scoped_sessions_keep_minor_zero_job_operations() {
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };
        for scope in [
            LaunchSessionScope::ConsoleLauncher,
            LaunchSessionScope::ShellJobs,
        ] {
            let mut platform = MockPlatform::new();
            platform.fail_send = false;
            let mut waits = TerminalWaits;
            let mut loader = InitSendLoader::new();
            let mut jobs = JobDispatcher::new();
            let owner = grant(EndpointKind::LaunchSession, 1, 1);
            jobs.install_scoped_session(owner, DwHandle(90), scope)
                .unwrap();
            platform.inbound[..wyrmroot_launch_proto::HEADER_BYTES].fill(0);
            wyrmroot_launch_proto::encode(reservation(1), &mut platform.inbound).unwrap();
            platform.inbound[40..44]
                .copy_from_slice(&(LaunchMessageType::ListJobs as u32).to_le_bytes());
            platform.inbound_len = wyrmroot_launch_proto::HEADER_BYTES;
            dispatch_one_job_request(
                &mut platform,
                &mut loader,
                &mut waits,
                authority,
                None,
                &mut jobs,
                DwHandle(90),
                owner,
            )
            .unwrap();
            assert!(matches!(
                parse_launch_message(&platform.sent[..platform.sent_len], 0)
                    .unwrap()
                    .message,
                LaunchMessage::JobList(ids) if ids.is_empty()
            ));
        }
    }

    fn ready_registry() -> (SystemInit, RegistryNativeAttempt) {
        let mut controller = SystemInit {
            mode: SystemMode::Bootstrap,
            roles: [
                RoleController::new(RoleId::Registryd, [1; 32]).unwrap(),
                RoleController::new(RoleId::Devmgr, [2; 32]).unwrap(),
            ],
            degraded_transitions: 0,
            activated: [false; EARLY_ROLE_COUNT],
            accounting: AttemptLedger::new(),
            registry_startup_profile: StartupProfile::BootstrapRegistry,
            devmgr_startup_profile: StartupProfile::EarlyBootStub,
        };
        controller.become_operational().unwrap();
        controller.begin_registry(0, 1, 0x1001).unwrap();
        let reservation = controller
            .reserve_attempt(RoleId::Registryd, 1, 0x1001)
            .unwrap();
        let loaded = LoadedProcess {
            process: DwHandle(31),
            launch_channel: DwHandle(32),
        };
        let task_group = DwHandle(30);
        controller
            .install_attempt(AttemptResources {
                role: RoleId::Registryd,
                generation: 1,
                transaction_id: 0x1001,
                executable_identity: [1; 32],
                startup_profile: StartupProfile::BootstrapRegistry,
                task_group,
                process: loaded.process,
                launch_channel: loaded.launch_channel,
                mappings: 0,
                reservation,
            })
            .unwrap();
        controller
            .child_started(RoleId::Registryd, 1, 0x1001, 1)
            .unwrap();
        controller.ready(RoleId::Registryd, 1, 0x1001, 2).unwrap();
        (
            controller,
            RegistryNativeAttempt {
                active: ActiveNativeRole {
                    role: RoleId::Registryd,
                    generation: 1,
                    transaction_id: 0x1001,
                    loaded,
                    task_group,
                },
                control_channel: DwHandle(33),
                ready_at: 2,
            },
        )
    }

    #[test]
    fn poison_consumes_every_native_owner_when_clock_transition_cannot_start() {
        let (mut controller, registry) = ready_registry();
        let mut platform = MockPlatform::new();
        let mut waits = TerminalWaits;

        assert_eq!(
            poison_registry_generation(&mut platform, &mut waits, &mut controller, registry, false,),
            Err(InitError::Native(FAILURE))
        );
        assert_eq!(platform.terminate_count, 1);
        assert_eq!(
            platform.closed[..platform.close_count],
            [DwHandle(32), DwHandle(31), DwHandle(30), DwHandle(33)]
        );
        assert!(controller.resources(RoleId::Registryd).is_none());
        assert_eq!(controller.mode(), SystemMode::Fatal);
    }

    #[test]
    fn poison_transition_rejection_still_consumes_native_owners_and_retires_fatal() {
        let (mut controller, mut registry) = ready_registry();
        registry.active.transaction_id += 1;
        let mut platform = MockPlatform::new();
        platform.now = Some(3);
        let mut waits = TerminalWaits;

        assert_eq!(
            poison_registry_generation(&mut platform, &mut waits, &mut controller, registry, false,),
            Err(InitError::Restart(
                RestartTransitionError::TransactionMismatch
            ))
        );
        assert_eq!(platform.terminate_count, 1);
        assert_eq!(
            platform.closed[..platform.close_count],
            [DwHandle(32), DwHandle(31), DwHandle(30), DwHandle(33)]
        );
        assert!(controller.resources(RoleId::Registryd).is_none());
        assert_eq!(controller.mode(), SystemMode::Fatal);
        assert!(!matches!(
            controller.role_state(RoleId::Registryd),
            Some(RestartState::CleaningUp { .. })
        ));
    }

    #[test]
    fn poison_cleanup_failure_is_permanent_and_blocks_replacement() {
        let (mut controller, registry) = ready_registry();
        let mut platform = MockPlatform::new();
        platform.now = Some(3);
        platform.fail_close = Some(registry.control_channel);
        let mut waits = TerminalWaits;

        assert_eq!(
            poison_registry_generation(&mut platform, &mut waits, &mut controller, registry, true,),
            Ok(true)
        );
        assert!(matches!(
            controller.role_state(RoleId::Registryd),
            Some(RestartState::PermanentFailure { .. })
        ));
        assert_eq!(controller.mode(), SystemMode::Degraded);
        assert!(
            controller
                .start_replacement(RoleId::Registryd, 4, 2, 0x1002)
                .is_err()
        );
    }

    #[test]
    fn poison_complete_cleanup_admits_exact_next_registry_generation() {
        let (mut controller, registry) = ready_registry();
        let mut platform = MockPlatform::new();
        platform.now = Some(3);
        platform.allow_wait = true;
        let mut waits = TerminalWaits;

        assert_eq!(
            poison_registry_generation(&mut platform, &mut waits, &mut controller, registry, false,),
            Ok(false)
        );
        assert!(matches!(
            controller.role_state(RoleId::Registryd),
            Some(RestartState::Starting {
                generation: 2,
                transaction_id: 0x1002,
                ..
            })
        ));
    }

    #[test]
    fn consoled_stream_descriptors_survive_init_then_reduce_at_actual_loader_move() {
        use deepwyrm_syscall::DW_RIGHT_DUPLICATE;
        use wyrmroot_loader::launch::{CHILD_CHANNEL_TRANSFER_RIGHTS, parse_init};
        use wyrmroot_loader::process::{JobLoadRequest, load_job_process};

        let streams = [DwHandle(0x901), DwHandle(0x902), DwHandle(0x903)];
        let mut platform = MockPlatform::new();
        for stream in streams {
            let transfer = consoled_stream_transfer::move_transfer(stream);
            assert_eq!(transfer.handle, stream);
            assert_eq!(transfer.operation, DW_HANDLE_TRANSFER_MOVE);
            assert_eq!(transfer.requested_rights, CHILD_CHANNEL_TRANSFER_RIGHTS);
            assert_eq!(transfer.requested_rights.0 & DW_RIGHT_DUPLICATE.0, 0);
            assert_eq!((transfer.reserved0, transfer.reserved), (0, [0; 2]));
            // Query the authority delivered by the actual first-hop descriptor.
            platform.fresh_rights = transfer.requested_rights;
            validate_controller_channel(&mut platform, stream).unwrap();
        }
        assert_eq!(platform.queried[..platform.query_count], streams);

        let image = executable();
        let mut loader = InitSendLoader::new();
        loader.fail_init = false;
        load_job_process(
            &mut loader,
            LoadAuthority {
                parent_root: DwHandle(1),
                task_group: DwHandle(2),
                bootfs: DwHandle(3),
            },
            JobLoadRequest {
                image: &image,
                policy_path: "bin/console-echo",
                argv: &["bin/console-echo"],
                environment: &[],
                streams: &streams,
                transaction_id: 0xd500,
            },
        )
        .unwrap();
        assert_eq!(loader.sent_transfers.len(), 3);
        let mut received = [DwReceivedHandleInfoV1::default(); 3];
        for (index, transfer) in loader.sent_transfers.iter().enumerate() {
            assert_eq!(transfer.handle, streams[index]);
            assert_eq!(transfer.operation, DW_HANDLE_TRANSFER_MOVE);
            assert_eq!(transfer.requested_rights, CHILD_CHANNEL_RIGHTS);
            assert_eq!(
                transfer.requested_rights.0 & (DW_RIGHT_TRANSFER.0 | DW_RIGHT_DUPLICATE.0),
                0
            );
            received[index] = DwReceivedHandleInfoV1 {
                handle: transfer.handle,
                rights: transfer.requested_rights,
                object_type: DW_OBJECT_TYPE_CHANNEL,
                ..DwReceivedHandleInfoV1::default()
            };
        }
        parse_init(LaunchProfile::JobV2Streams, &loader.sent_init, &received).unwrap();
    }

    #[test]
    fn consoled_stream_ingress_rejects_early_reduction_and_duplicate_authority() {
        use deepwyrm_syscall::DW_RIGHT_DUPLICATE;

        let transfer = consoled_stream_transfer::move_transfer(DwHandle(0x901));
        for rights in [
            DwRights(transfer.requested_rights.0 & !DW_RIGHT_TRANSFER.0),
            DwRights(transfer.requested_rights.0 | DW_RIGHT_DUPLICATE.0),
        ] {
            let mut platform = MockPlatform::new();
            platform.fresh_rights = rights;
            assert_eq!(
                validate_controller_channel(&mut platform, transfer.handle),
                Err(InitError::ResourceIdentityMismatch)
            );
            assert_eq!(platform.query_count, 1);
        }
    }

    #[test]
    fn staged_channel_cleanup_is_affine_and_reverse_ordered() {
        let mut platform = MockPlatform::new();
        let mut owner = StagedChannelPair::new(DwHandle(20), DwHandle(21));
        assert!(owner.cleanup(&mut platform));
        assert!(owner.cleanup(&mut platform));
        assert_eq!(
            platform.closed[..platform.close_count],
            [DwHandle(21), DwHandle(20)]
        );
    }
}
