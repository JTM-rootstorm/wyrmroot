//! Permanent WYR1-A supervisor policy and native startup boundary.
//!
//! The fixed controller composes `RestartSupervisor`; it does not implement a
//! dependency solver or copy restart-policy transitions.

#![no_std]
#![forbid(unsafe_code)]

use deepwyrm_syscall::{
    DW_SIGNAL_EXITED, DW_TERMINATION_AUTHORIZED, DW_TERMINATION_NORMAL_EXIT,
    DW_TERMINATION_TASK_GROUP_TEARDOWN, DwDeadline, DwHandle, DwObjectType, DwReceivedHandleInfoV1,
    DwRights, DwWaitItemV1,
};
use wyrmroot_bootfs::archive::{Archive, LookupError, ParseError};
use wyrmroot_loader::{
    launch::{HEADER_BYTES, LaunchProfile, SUPERVISOR_BYTES, encode_ready_for_profile, parse_init},
    process::{LoadAuthority, LoadError, LoadRequest, LoadedProcess, LoaderPlatform, load_process},
};
use wyrmroot_rrc_manifest::{
    Activation, DependencyKind, MANIFEST_PATH, Manifest, ParseError as ManifestParseError, RoleId,
    StartupProfile,
};
use wyrmroot_runtime::{
    AttemptFailure, CleanupDisposition, RestartState, RestartSupervisor, RestartTransitionError,
    TerminalDisposition, WYR0_I_SUPERVISION_POLICY,
};
use wyrmroot_runtime::{
    BOOTFS_EXPECTATION, BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, CapabilityValidationError,
    InitCapability, LOADER_TASK_GROUP_EXPECTATION, MappingPlan, MappingPlanError, NativeError,
    ReceiveCounts, SELF_ROOT_EXPECTATION, SupervisionError, SupervisionPlatform,
    await_child_ready_profile, validate_bootstrap_channel, validate_init_capabilities_v2,
    validate_successful_exit,
};

pub const SYSTEM_INIT_PATH: &str = "system/init";
pub const EARLY_ROLE_COUNT: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemMode {
    Bootstrap,
    SupervisorOperational,
    ActivatingEarlyRoles,
    Normal,
    Degraded,
    Fatal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryResult {
    Recovered,
    Degraded,
    Fatal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptResources {
    pub role: RoleId,
    pub generation: u64,
    pub transaction_id: u64,
    pub executable_identity: [u8; 32],
    pub startup_profile: StartupProfile,
    pub task_group: DwHandle,
    pub process: DwHandle,
    pub launch_channel: DwHandle,
    pub mappings: u8,
    pub accounting_reserved: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitError {
    WrongManifestProfile,
    UnlaunchableRole,
    WrongActivationOrder,
    MissingAttemptResources,
    ResourcesAlreadyInstalled,
    ResourceIdentityMismatch,
    InvalidResourceHandle,
    Restart(RestartTransitionError),
    Bootfs(ParseError),
    MissingRetainedMaterial,
    NonExecutableRole,
    Manifest(ManifestParseError),
    ZeroBootGeneration,
    ArtifactIdentityMismatch(RoleId),
    Native(NativeError),
    Capability(CapabilityValidationError),
    Mapping(MappingPlanError),
    Launch(wyrmroot_loader::launch::LaunchError),
    Loader,
    Supervision,
    Cleanup,
}

impl From<RestartTransitionError> for InitError {
    fn from(value: RestartTransitionError) -> Self {
        Self::Restart(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RoleController {
    role: RoleId,
    executable_identity: [u8; 32],
    restart: RestartSupervisor,
    resources: Option<AttemptResources>,
}

impl RoleController {
    fn new(role: RoleId, identity: [u8; 32]) -> Result<Self, InitError> {
        Ok(Self {
            role,
            executable_identity: identity,
            restart: RestartSupervisor::new(WYR0_I_SUPERVISION_POLICY)?,
            resources: None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemInit {
    mode: SystemMode,
    roles: [RoleController; EARLY_ROLE_COUNT],
    degraded_transitions: u8,
    activated: [bool; EARLY_ROLE_COUNT],
}

impl SystemInit {
    /// Consumes an already product-validated WRRM manifest and binds exact
    /// executable identities to the two WYR1-A launchable roles.
    pub fn from_manifest(manifest: Manifest<'_>) -> Result<Self, InitError> {
        if manifest.role_count() != 5 {
            return Err(InitError::WrongManifestProfile);
        }
        for (expected, role) in [
            RoleId::Registryd,
            RoleId::Devmgr,
            RoleId::Uart16550d,
            RoleId::Consoled,
            RoleId::Wyrmsh,
        ]
        .into_iter()
        .zip(manifest.roles())
        {
            let launchable = matches!(expected, RoleId::Registryd | RoleId::Devmgr);
            let expected_shape = if launchable {
                (Activation::Early, StartupProfile::EarlyBootStub)
            } else if expected == RoleId::Uart16550d {
                (Activation::DeviceBound, StartupProfile::Retained)
            } else {
                (Activation::ConsoleBound, StartupProfile::Retained)
            };
            if role.id() != expected
                || (role.activation(), role.startup_profile()) != expected_shape
            {
                return Err(InitError::WrongManifestProfile);
            }
        }
        let mut ready_edges = 0u8;
        for edge in manifest.edges() {
            if edge.kind() != DependencyKind::RoleReady {
                continue;
            }
            let bit = match (edge.owner(), edge.target_role()) {
                (RoleId::Devmgr, Some(RoleId::Registryd)) => 1,
                (RoleId::Uart16550d, Some(RoleId::Devmgr)) => 2,
                (RoleId::Consoled, Some(RoleId::Uart16550d)) => 4,
                (RoleId::Wyrmsh, Some(RoleId::Consoled)) => 8,
                _ => return Err(InitError::WrongManifestProfile),
            };
            if ready_edges & bit != 0 {
                return Err(InitError::WrongManifestProfile);
            }
            ready_edges |= bit;
        }
        if ready_edges != 0x0f {
            return Err(InitError::WrongManifestProfile);
        }
        let registry = manifest
            .role(RoleId::Registryd)
            .ok_or(InitError::WrongManifestProfile)?;
        let devmgr = manifest
            .role(RoleId::Devmgr)
            .ok_or(InitError::WrongManifestProfile)?;
        Ok(Self {
            mode: SystemMode::Bootstrap,
            roles: [
                RoleController::new(RoleId::Registryd, *registry.executable_identity())?,
                RoleController::new(RoleId::Devmgr, *devmgr.executable_identity())?,
            ],
            degraded_transitions: 0,
            activated: [false; EARLY_ROLE_COUNT],
        })
    }

    #[must_use]
    pub const fn mode(&self) -> SystemMode {
        self.mode
    }
    #[must_use]
    pub const fn result(&self) -> Option<RecoveryResult> {
        match self.mode {
            SystemMode::Normal => Some(RecoveryResult::Recovered),
            SystemMode::Degraded => Some(RecoveryResult::Degraded),
            SystemMode::Fatal => Some(RecoveryResult::Fatal),
            _ => None,
        }
    }
    #[must_use]
    pub const fn degraded_transitions(&self) -> u8 {
        self.degraded_transitions
    }
    #[must_use]
    pub fn role_state(&self, role: RoleId) -> Option<RestartState> {
        self.index(role).map(|i| self.roles[i].restart.state())
    }
    #[must_use]
    pub fn resources(&self, role: RoleId) -> Option<AttemptResources> {
        self.index(role).and_then(|i| self.roles[i].resources)
    }

    /// Marks manifest/closure/controller initialization complete. This is the
    /// exact state acknowledged by the supervisor READY to primordial.
    pub fn become_operational(&mut self) -> Result<(), InitError> {
        if self.mode != SystemMode::Bootstrap {
            return Err(InitError::WrongActivationOrder);
        }
        self.mode = SystemMode::SupervisorOperational;
        Ok(())
    }

    pub fn begin_registry(
        &mut self,
        now: u64,
        generation: u64,
        transaction: u64,
    ) -> Result<(), InitError> {
        if self.mode != SystemMode::SupervisorOperational {
            return Err(InitError::WrongActivationOrder);
        }
        self.roles[0].restart.begin(now, generation, transaction)?;
        self.mode = SystemMode::ActivatingEarlyRoles;
        Ok(())
    }

    pub fn install_attempt(&mut self, resources: AttemptResources) -> Result<(), InitError> {
        let index = self
            .index(resources.role)
            .ok_or(InitError::UnlaunchableRole)?;
        if resources.task_group.0 == 0
            || resources.process.0 == 0
            || resources.launch_channel.0 == 0
        {
            return Err(InitError::InvalidResourceHandle);
        }
        if resources.startup_profile != StartupProfile::EarlyBootStub
            || resources.executable_identity != self.roles[index].executable_identity
        {
            return Err(InitError::ResourceIdentityMismatch);
        }
        let RestartState::Starting {
            generation,
            transaction_id,
            ..
        } = self.roles[index].restart.state()
        else {
            return Err(InitError::WrongActivationOrder);
        };
        if (generation, transaction_id) != (resources.generation, resources.transaction_id) {
            return Err(InitError::ResourceIdentityMismatch);
        }
        if self.roles[index].resources.is_some() {
            return Err(InitError::ResourcesAlreadyInstalled);
        }
        self.roles[index].resources = Some(resources);
        Ok(())
    }

    pub fn child_started(
        &mut self,
        role: RoleId,
        generation: u64,
        transaction: u64,
        now: u64,
    ) -> Result<(), InitError> {
        let controller = self.controller_mut(role)?;
        if controller.resources.is_none() {
            return Err(InitError::MissingAttemptResources);
        }
        controller
            .restart
            .child_started(generation, transaction, now)?;
        Ok(())
    }

    pub fn ready(
        &mut self,
        role: RoleId,
        generation: u64,
        transaction: u64,
        now: u64,
    ) -> Result<(), InitError> {
        let index = self.index(role).ok_or(InitError::UnlaunchableRole)?;
        self.roles[index]
            .restart
            .ready(generation, transaction, now)?;
        self.activated[index] = true;
        if role == RoleId::Registryd {
            if self.roles[1].restart.state() != RestartState::Stopped {
                return Err(InitError::WrongActivationOrder);
            }
            self.roles[1].restart.begin(
                now,
                generation,
                transaction.checked_add(1).ok_or(InitError::Restart(
                    RestartTransitionError::ArithmeticOverflow,
                ))?,
            )?;
        } else if role == RoleId::Devmgr && self.activated[0] {
            self.mode = SystemMode::Normal;
        }
        Ok(())
    }

    pub fn fail(
        &mut self,
        role: RoleId,
        generation: u64,
        transaction: u64,
        now: u64,
        failure: AttemptFailure,
    ) -> Result<(), InitError> {
        self.controller_mut(role)?
            .restart
            .fail_attempt(generation, transaction, now, failure)?;
        Ok(())
    }

    pub fn terminal(
        &mut self,
        role: RoleId,
        generation: u64,
        transaction: u64,
        now: u64,
        disposition: TerminalDisposition,
    ) -> Result<(), InitError> {
        self.controller_mut(role)?
            .restart
            .terminal(generation, transaction, now, disposition)?;
        if self.mode == SystemMode::Normal {
            self.mode = SystemMode::ActivatingEarlyRoles;
        }
        Ok(())
    }

    pub fn cleanup_complete(
        &mut self,
        role: RoleId,
        generation: u64,
        transaction: u64,
        now: u64,
    ) -> Result<(), InitError> {
        let controller = self.controller_mut(role)?;
        let unpublished = matches!(
            controller.restart.state(),
            RestartState::CleaningUp {
                action: wyrmroot_runtime::CleanupAction::CloseUnpublished,
                ..
            }
        );
        if controller.resources.take().is_none() && !unpublished {
            return Err(InitError::MissingAttemptResources);
        }
        controller
            .restart
            .cleanup_complete(generation, transaction, now)?;
        self.update_permanent_failure(role);
        Ok(())
    }

    pub fn cleanup_failed(
        &mut self,
        role: RoleId,
        generation: u64,
        transaction: u64,
        now: u64,
    ) -> Result<(), InitError> {
        let controller = self.controller_mut(role)?;
        controller.resources = None;
        controller
            .restart
            .cleanup_failed(generation, transaction, now)?;
        self.update_permanent_failure(role);
        Ok(())
    }

    pub fn start_replacement(
        &mut self,
        role: RoleId,
        now: u64,
        generation: u64,
        transaction: u64,
    ) -> Result<(), InitError> {
        self.controller_mut(role)?
            .restart
            .start_replacement(now, generation, transaction)?;
        self.update_permanent_failure(role);
        Ok(())
    }

    pub fn fatal(&mut self) {
        self.mode = SystemMode::Fatal;
    }

    fn update_permanent_failure(&mut self, role: RoleId) {
        if self
            .role_state(role)
            .is_some_and(|state| matches!(state, RestartState::PermanentFailure { .. }))
            && self.mode != SystemMode::Degraded
        {
            self.mode = SystemMode::Degraded;
            self.degraded_transitions = self.degraded_transitions.saturating_add(1);
        }
    }
    fn index(&self, role: RoleId) -> Option<usize> {
        match role {
            RoleId::Registryd => Some(0),
            RoleId::Devmgr => Some(1),
            _ => None,
        }
    }
    fn controller_mut(&mut self, role: RoleId) -> Result<&mut RoleController, InitError> {
        let i = self.index(role).ok_or(InitError::UnlaunchableRole)?;
        Ok(&mut self.roles[i])
    }
}

/// Validates the runtime half of the selected-generation trust boundary.
///
/// Build tooling externally authenticates the bootfs/manifest receipts. Init
/// has no fourth startup authority with which to re-authenticate those
/// receipts; it validates the retained bytes it actually received, including
/// canonical WRRM form, the fixed product graph, and every role artifact hash.
pub fn validate_retained_bootfs(bytes: &[u8]) -> Result<SystemInit, InitError> {
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
    // Init itself and all declared immutable dependencies must resolve from
    // the same retained archive. Their bytes are hashed here; their expected
    // identities remain bound by the external selected-generation receipt.
    let init = archive
        .lookup(SYSTEM_INIT_PATH.as_bytes())
        .map_err(map_lookup)?;
    if !init.is_executable() || init.data().is_empty() {
        return Err(InitError::NonExecutableRole);
    }
    let _init_identity = wyrmroot_runtime::sha256::digest(init.data());
    for edge in manifest.edges() {
        if let Some(path) = edge.target_path() {
            let entry = archive.lookup(path.as_bytes()).map_err(map_lookup)?;
            let _observed_identity = wyrmroot_runtime::sha256::digest(entry.data());
        }
    }
    Ok(controller)
}

fn map_lookup(_: LookupError) -> InitError {
    InitError::MissingRetainedMaterial
}

/// Native operations owned by permanent init in addition to the reusable
/// loader and readiness platform boundaries.
pub trait InitPlatform {
    fn query_capability_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError>;
    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError>;
    fn query_memory_object_size(&mut self, handle: DwHandle) -> Result<u64, NativeError>;
    fn with_bootfs_bytes<R>(
        &mut self,
        root: DwHandle,
        bootfs: DwHandle,
        plan: MappingPlan,
        use_bytes: impl for<'a> FnOnce(&mut Self, &'a [u8]) -> R,
    ) -> Result<R, NativeError>;
    fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError>;
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError>;
    fn create_attempt_task_group(&mut self, parent: DwHandle) -> Result<DwHandle, NativeError>;
    fn now(&mut self) -> Result<u64, NativeError>;
    fn wait_until(&mut self, deadline_ns: u64) -> Result<(), NativeError>;
}

/// Runs the native selected-generation activation through NORMAL or DEGRADED.
/// The caller remains alive afterward as the permanent supervisor loop.
pub fn run_system_init<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootstrap_channel: DwHandle,
) -> Result<RecoveryResult, InitError>
where
    S: InitPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let channel = system
        .query_capability_info(bootstrap_channel)
        .map_err(InitError::Native)?;
    validate_bootstrap_channel(channel, BOOTSTRAP_CHANNEL_EXPECTATION)
        .map_err(InitError::Capability)?;
    let mut init_bytes = [0; SUPERVISOR_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 3];
    let counts = system
        .receive_channel(bootstrap_channel, &mut init_bytes, &mut handles)
        .map_err(InitError::Native)?;
    if counts
        != (ReceiveCounts {
            bytes: SUPERVISOR_BYTES,
            handles: 3,
        })
    {
        return Err(InitError::Launch(
            wyrmroot_loader::launch::LaunchError::HandleCount,
        ));
    }
    let parsed =
        parse_init(LaunchProfile::Supervisor, &init_bytes, &handles).map_err(InitError::Launch)?;
    let capabilities = [
        fresh_capability(system, handles[0])?,
        fresh_capability(system, handles[1])?,
        fresh_capability(system, handles[2])?,
    ];
    validate_init_capabilities_v2(
        &capabilities,
        SELF_ROOT_EXPECTATION,
        BOOTFS_EXPECTATION,
        LOADER_TASK_GROUP_EXPECTATION,
    )
    .map_err(InitError::Capability)?;
    let authority = LoadAuthority {
        parent_root: handles[0].handle,
        bootfs: handles[1].handle,
        task_group: handles[2].handle,
    };
    let size = system
        .query_memory_object_size(authority.bootfs)
        .map_err(InitError::Native)?;
    let plan = MappingPlan::for_bootfs(size).map_err(InitError::Mapping)?;
    let activation = system
        .with_bootfs_bytes(
            authority.parent_root,
            authority.bootfs,
            plan,
            |system, bootfs| {
                activate_retained_bootfs(
                    system,
                    loader,
                    waits,
                    authority,
                    bootstrap_channel,
                    parsed.transaction_id,
                    bootfs,
                )
            },
        )
        .map_err(InitError::Native)?;
    let mut cleanup_failed = false;
    for handle in handles {
        cleanup_failed |= system.close_handle(handle.handle).is_err();
    }
    cleanup_failed |= system.close_handle(bootstrap_channel).is_err();
    if cleanup_failed {
        return Err(InitError::Cleanup);
    }
    activation
}

fn activate_retained_bootfs<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    bootstrap_channel: DwHandle,
    parent_transaction: u64,
    bootfs: &[u8],
) -> Result<RecoveryResult, InitError>
where
    S: InitPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut controller = validate_retained_bootfs(bootfs)?;
    controller.become_operational()?;
    let mut ready = [0; HEADER_BYTES];
    let ready_len =
        encode_ready_for_profile(LaunchProfile::Supervisor, parent_transaction, &mut ready)
            .map_err(InitError::Launch)?;
    system
        .send_channel(bootstrap_channel, &ready[..ready_len])
        .map_err(InitError::Native)?;
    let now = system.now().map_err(InitError::Native)?;
    controller.begin_registry(now, 1, 0x1001)?;
    for role in [RoleId::Registryd, RoleId::Devmgr] {
        loop {
            let RestartState::Starting {
                generation,
                transaction_id,
                ..
            } = controller
                .role_state(role)
                .ok_or(InitError::WrongActivationOrder)?
            else {
                return Err(InitError::WrongActivationOrder);
            };
            let task_group = system
                .create_attempt_task_group(authority.task_group)
                .map_err(InitError::Native)?;
            let role_authority = LoadAuthority {
                task_group,
                ..authority
            };
            let loaded = match load_role(loader, role_authority, bootfs, role, transaction_id) {
                Ok(value) => value,
                Err(_) => {
                    let now = system.now().map_err(InitError::Native)?;
                    controller.fail(
                        role,
                        generation,
                        transaction_id,
                        now,
                        AttemptFailure::CreationFailed,
                    )?;
                    system.close_handle(task_group).map_err(InitError::Native)?;
                    controller.cleanup_complete(role, generation, transaction_id, now + 1)?;
                    if advance_or_degrade(system, &mut controller, role, transaction_id)? {
                        return Ok(RecoveryResult::Degraded);
                    }
                    continue;
                }
            };
            controller.install_attempt(AttemptResources {
                role,
                generation,
                transaction_id,
                executable_identity: role_identity(bootfs, role)?,
                startup_profile: StartupProfile::EarlyBootStub,
                task_group,
                process: loaded.process,
                launch_channel: loaded.launch_channel,
                mappings: 0,
                accounting_reserved: true,
            })?;
            let now = system.now().map_err(InitError::Native)?;
            controller.child_started(role, generation, transaction_id, now)?;
            let deadline = DwDeadline(
                now.checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
                    .ok_or(InitError::Restart(
                        RestartTransitionError::ArithmeticOverflow,
                    ))?,
            );
            match await_child_ready_profile(
                waits,
                loaded.process,
                loaded.launch_channel,
                LaunchProfile::EarlyBootStub,
                transaction_id,
                deadline,
            ) {
                Ok(()) => {
                    let now = system.now().map_err(InitError::Native)?;
                    controller.ready(role, generation, transaction_id, now)?;
                    match observe_terminal(waits, loaded.process, deadline) {
                        Ok(disposition) => {
                            let now = system.now().map_err(InitError::Native)?;
                            controller.terminal(
                                role,
                                generation,
                                transaction_id,
                                now,
                                disposition,
                            )?;
                            cleanup_loaded(system, loader, loaded, task_group, false)?;
                            controller.cleanup_complete(
                                role,
                                generation,
                                transaction_id,
                                now + 1,
                            )?;
                            if disposition == TerminalDisposition::NormalExit(0) {
                                break;
                            }
                            if advance_or_degrade(system, &mut controller, role, transaction_id)? {
                                return Ok(RecoveryResult::Degraded);
                            }
                        }
                        Err(failure) => {
                            let now = system.now().map_err(InitError::Native)?;
                            controller.fail(role, generation, transaction_id, now, failure)?;
                            cleanup_loaded(system, loader, loaded, task_group, true)?;
                            controller.cleanup_complete(
                                role,
                                generation,
                                transaction_id,
                                now + 1,
                            )?;
                            if advance_or_degrade(system, &mut controller, role, transaction_id)? {
                                return Ok(RecoveryResult::Degraded);
                            }
                        }
                    }
                }
                Err(error) => {
                    let failure = classify_supervision(&error);
                    let now = system.now().map_err(InitError::Native)?;
                    controller.fail(role, generation, transaction_id, now, failure)?;
                    cleanup_loaded(
                        system,
                        loader,
                        loaded,
                        task_group,
                        !error.process_exit_observed(),
                    )?;
                    controller.cleanup_complete(role, generation, transaction_id, now + 1)?;
                    if advance_or_degrade(system, &mut controller, role, transaction_id)? {
                        return Ok(RecoveryResult::Degraded);
                    }
                }
            }
        }
    }
    Ok(RecoveryResult::Recovered)
}

fn fresh_capability<S: InitPlatform>(
    system: &mut S,
    info: DwReceivedHandleInfoV1,
) -> Result<InitCapability<DwObjectType, DwRights>, InitError> {
    Ok(InitCapability {
        received: CapabilityInfo {
            object_type: info.object_type,
            rights: info.rights,
        },
        fresh: system
            .query_capability_info(info.handle)
            .map_err(InitError::Native)?,
    })
}
fn role_identity(bytes: &[u8], role: RoleId) -> Result<[u8; 32], InitError> {
    let a = Archive::new(bytes).map_err(InitError::Bootfs)?;
    let m = a.lookup(MANIFEST_PATH.as_bytes()).map_err(map_lookup)?;
    let id: [u8; 32] = m
        .data()
        .get(48..80)
        .ok_or(InitError::ZeroBootGeneration)?
        .try_into()
        .unwrap();
    let manifest = Manifest::parse_structural(m.data(), &id).map_err(InitError::Manifest)?;
    Ok(*manifest
        .role(role)
        .ok_or(InitError::WrongManifestProfile)?
        .executable_identity())
}
fn load_role<L: LoaderPlatform<Error = NativeError>>(
    loader: &mut L,
    authority: LoadAuthority,
    bytes: &[u8],
    role: RoleId,
    transaction_id: u64,
) -> Result<LoadedProcess, InitError> {
    let archive = Archive::new(bytes).map_err(InitError::Bootfs)?;
    let path = match role {
        RoleId::Registryd => "system/registryd",
        RoleId::Devmgr => "system/devmgr",
        _ => return Err(InitError::UnlaunchableRole),
    };
    let e = archive.lookup(path.as_bytes()).map_err(map_lookup)?;
    load_process(
        loader,
        authority,
        LoadRequest {
            image: e.data(),
            display_path: path,
            profile: LaunchProfile::EarlyBootStub,
            transaction_id,
        },
    )
    .map_err(|_: LoadError<NativeError>| InitError::Loader)
}
fn observe_terminal<W: SupervisionPlatform<Error = NativeError>>(
    waits: &mut W,
    process: DwHandle,
    deadline: DwDeadline,
) -> Result<TerminalDisposition, AttemptFailure> {
    let item = DwWaitItemV1 {
        handle: process,
        signals: DW_SIGNAL_EXITED,
    };
    let result = waits
        .wait_many(core::slice::from_ref(&item), deadline)
        .map_err(|_| AttemptFailure::WaitFailed)?;
    if result.index != 0 || result.observed.0 & DW_SIGNAL_EXITED.0 == 0 {
        return Err(AttemptFailure::WaitFailed);
    }
    let info = waits
        .query_task_termination(process)
        .map_err(|_| AttemptFailure::ExitQueryFailed)?;
    if validate_successful_exit(&info).is_ok() {
        return Ok(TerminalDisposition::NormalExit(0));
    }
    if info.reason == DW_TERMINATION_NORMAL_EXIT {
        return Ok(TerminalDisposition::NormalExit(info.application_code));
    }
    if info.reason == DW_TERMINATION_AUTHORIZED {
        return Ok(TerminalDisposition::AuthorizedTermination);
    }
    if info.reason == DW_TERMINATION_TASK_GROUP_TEARDOWN {
        return Ok(TerminalDisposition::TaskGroupTeardown);
    }
    Ok(TerminalDisposition::UnhandledException)
}
fn cleanup_loaded<S: InitPlatform, L: LoaderPlatform<Error = NativeError>>(
    system: &mut S,
    loader: &mut L,
    loaded: LoadedProcess,
    task_group: DwHandle,
    terminate: bool,
) -> Result<(), InitError> {
    if terminate {
        loader
            .process_terminate(loaded.process)
            .map_err(|_| InitError::Cleanup)?;
    }
    for h in [loaded.launch_channel, loaded.process, task_group] {
        system.close_handle(h).map_err(InitError::Native)?;
    }
    Ok(())
}
fn classify_supervision(error: &SupervisionError<NativeError>) -> AttemptFailure {
    match error {
        SupervisionError::Ready(wyrmroot_loader::launch::LaunchError::TransactionMismatch) => {
            AttemptFailure::WrongTransactionReady
        }
        SupervisionError::Ready(_) | SupervisionError::InvalidReadyReceive(_) => {
            AttemptFailure::MalformedReady
        }
        SupervisionError::PeerClosedBeforeReady => AttemptFailure::PeerClosedBeforeReady,
        SupervisionError::ExitedBeforeReady
        | SupervisionError::Exit(_)
        | SupervisionError::ExitQuery(_) => {
            AttemptFailure::ExitBeforeReady(TerminalDisposition::NormalExit(1))
        }
        _ => AttemptFailure::WaitFailed,
    }
}
fn advance_or_degrade<S: InitPlatform>(
    system: &mut S,
    controller: &mut SystemInit,
    role: RoleId,
    transaction: u64,
) -> Result<bool, InitError> {
    match controller
        .role_state(role)
        .ok_or(InitError::WrongActivationOrder)?
    {
        RestartState::PermanentFailure { .. } => Ok(true),
        RestartState::Backoff {
            next_generation,
            deadline_ns,
            ..
        } => {
            system.wait_until(deadline_ns).map_err(InitError::Native)?;
            controller.start_replacement(
                role,
                deadline_ns,
                next_generation,
                transaction.checked_add(1).ok_or(InitError::Restart(
                    RestartTransitionError::ArithmeticOverflow,
                ))?,
            )?;
            Ok(matches!(controller.mode(), SystemMode::Degraded))
        }
        _ => Err(InitError::WrongActivationOrder),
    }
}

/// Distinguishes process existence from profile-aware READY validation.
pub fn observe_ready(
    bytes: &[u8],
    handles: usize,
    expected_transaction: u64,
) -> Result<(), AttemptFailure> {
    if handles != 0 || bytes.len() != wyrmroot_loader::launch::HEADER_BYTES {
        return Err(AttemptFailure::MalformedReady);
    }
    match wyrmroot_loader::launch::parse_ready_for_profile(
        wyrmroot_loader::launch::LaunchProfile::EarlyBootStub,
        bytes,
        expected_transaction,
    ) {
        Ok(()) => Ok(()),
        Err(wyrmroot_loader::launch::LaunchError::TransactionMismatch) => {
            Err(AttemptFailure::WrongTransactionReady)
        }
        Err(_) => Err(AttemptFailure::MalformedReady),
    }
}

/// Converts an exact Process result into the restart engine's typed terminal disposition.
#[must_use]
pub const fn normal_exit(code: u32) -> TerminalDisposition {
    TerminalDisposition::NormalExit(code)
}

#[must_use]
pub const fn cleanup_is_permanent(state: RestartState) -> bool {
    matches!(
        state,
        RestartState::PermanentFailure {
            cleanup: CleanupDisposition::Failed,
            ..
        }
    )
}
