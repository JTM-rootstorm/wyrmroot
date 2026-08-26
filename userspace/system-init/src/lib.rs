//! Permanent WYR1-A supervisor policy and native startup boundary.
//!
//! The fixed controller composes `RestartSupervisor`; it does not implement a
//! dependency solver or copy restart-policy transitions.

#![no_std]
#![forbid(unsafe_code)]

pub mod evidence;
pub mod gate;

#[cfg(feature = "wyr1-test-evidence")]
use core::sync::atomic::{AtomicU8, Ordering};

use crate::evidence::{EvidenceError, EvidenceEvent, EvidenceLog};
use crate::gate::{GATE_CONFIG_PATH, GateConfig, GateConfigError, parse_gate_config};
use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_SIGNAL_EXITED, DW_SIGNAL_PEER_CLOSED, DW_TASK_STATE_EXITED,
    DW_TERMINATION_AUTHORIZED, DW_TERMINATION_NORMAL_EXIT, DW_TERMINATION_TASK_GROUP_TEARDOWN,
    DwDeadline, DwHandle, DwObjectType, DwReceivedHandleInfoV1, DwRights, DwTaskTerminationInfoV1,
    DwWaitItemV1,
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
    ObservedSupervisionError, ReceiveCounts, SELF_ROOT_EXPECTATION, SupervisionError,
    SupervisionPlatform, await_child_ready_profile_observed, supervise_ready_child_profile,
    validate_bootstrap_channel, validate_init_capabilities_v2,
};

pub const SYSTEM_INIT_PATH: &str = "system/init";
pub const EARLY_ROLE_COUNT: usize = 2;
const EXPECTED_ROLE_PATHS: [(RoleId, &str); 5] = [
    (RoleId::Registryd, "system/registryd"),
    (RoleId::Devmgr, "system/devmgr"),
    (RoleId::Uart16550d, "system/uart16550d"),
    (RoleId::Consoled, "system/consoled"),
    (RoleId::Wyrmsh, "system/wyrmsh"),
];

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

/// Process application status used when permanent init cannot safely continue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum InitApplicationStatus {
    /// Fatal bootstrap/supervision failure; platform recovery requires reboot.
    FatalRebootRequired = 0xAF01_0002,
}

#[must_use]
pub const fn fatal_application_status(_error: &InitError) -> InitApplicationStatus {
    InitApplicationStatus::FatalRebootRequired
}

/// Test-only application status that preserves the top-level init failure
/// category across the selector's process-exit boundary. These values are
/// diagnostic evidence, not part of the production application-status ABI.
#[cfg(feature = "wyr1-test-evidence")]
#[must_use]
pub fn wyr1_test_failure_application_status(error: &InitError) -> u32 {
    if matches!(
        error,
        InitError::Restart(RestartTransitionError::InvalidState)
    ) {
        let stage = WYR1_TEST_RESTART_STAGE.load(Ordering::Relaxed);
        return 0xAF13_0003 | ((stage as u32) << 8);
    }
    let category = match error {
        InitError::WrongManifestProfile => 0x01,
        InitError::UnlaunchableRole => 0x02,
        InitError::WrongActivationOrder => 0x03,
        InitError::MissingAttemptResources => 0x04,
        InitError::ResourcesAlreadyInstalled => 0x05,
        InitError::ResourceIdentityMismatch => 0x06,
        InitError::InvalidResourceHandle => 0x07,
        InitError::Restart(_) => 0x08,
        InitError::Bootfs(_) => 0x09,
        InitError::MissingRetainedMaterial => 0x0a,
        InitError::NonExecutableRole => 0x0b,
        InitError::Manifest(_) => 0x0c,
        InitError::ZeroBootGeneration => 0x0d,
        InitError::ArtifactIdentityMismatch(_) => 0x0e,
        InitError::Native(_) => 0x0f,
        InitError::Capability(_) => 0x10,
        InitError::Mapping(_) => 0x11,
        InitError::Launch(_) => 0x12,
        InitError::Loader(_) => 0x13,
        InitError::Supervision => 0x14,
        InitError::Cleanup => 0x15,
        InitError::Accounting => 0x16,
        InitError::GateConfig(_) => 0x17,
        InitError::Evidence(_) => 0x18,
    };
    0xAF11_0000 | category
}

#[cfg(feature = "wyr1-test-evidence")]
static WYR1_TEST_RESTART_STAGE: AtomicU8 = AtomicU8::new(0);

#[cfg(feature = "wyr1-test-evidence")]
fn wyr1_test_set_restart_stage(stage: u8) {
    WYR1_TEST_RESTART_STAGE.store(stage, Ordering::Relaxed);
}

#[cfg(not(feature = "wyr1-test-evidence"))]
fn wyr1_test_set_restart_stage(_stage: u8) {}

/// Boot-lifetime owner of the fixed supervisor state and primordial authority.
/// The immutable bootfs handle is retained and remapped narrowly for each load;
/// no borrowed mapping escapes a transition.
#[derive(Debug, Eq, PartialEq)]
pub struct ResidentSystemInit {
    controller: SystemInit,
    authority: LoadAuthority,
    result: RecoveryResult,
    last_tick_ns: u64,
}

impl ResidentSystemInit {
    #[must_use]
    pub const fn result(&self) -> RecoveryResult {
        self.result
    }

    #[must_use]
    pub const fn controller(&self) -> &SystemInit {
        &self.controller
    }

    #[must_use]
    pub const fn authority(&self) -> LoadAuthority {
        self.authority
    }

    /// Advances the permanent fixed-role control loop without inventing service
    /// manager policy. Native role events are consumed during activation and
    /// future reached profiles can extend this exact generation-owned tick.
    pub fn control_tick(&mut self, now_ns: u64) -> Result<SystemMode, InitError> {
        if now_ns < self.last_tick_ns {
            self.controller.fatal();
            self.result = RecoveryResult::Fatal;
            return Err(InitError::WrongActivationOrder);
        }
        self.last_tick_ns = now_ns;
        Ok(self.controller.mode())
    }
}

#[derive(Debug, Eq, PartialEq)]
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
    pub reservation: AttemptReservation,
}

/// Affine token proving one fixed-role generation was reserved before child
/// publication. It is intentionally neither `Copy` nor `Clone`.
#[derive(Debug, Eq, PartialEq)]
pub struct AttemptReservation {
    role: RoleId,
    generation: u64,
    transaction_id: u64,
    nonce: u64,
    published: bool,
    released: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReservationSlot {
    last_generation: u64,
    transaction_id: u64,
    nonce: u64,
    outstanding: bool,
    published: bool,
}

impl ReservationSlot {
    const EMPTY: Self = Self {
        last_generation: 0,
        transaction_id: 0,
        nonce: 0,
        outstanding: false,
        published: false,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AttemptLedger {
    slots: [ReservationSlot; EARLY_ROLE_COUNT],
    next_nonce: u64,
}

impl AttemptLedger {
    const fn new() -> Self {
        Self {
            slots: [ReservationSlot::EMPTY; EARLY_ROLE_COUNT],
            next_nonce: 1,
        }
    }

    fn reserve(
        &mut self,
        index: usize,
        role: RoleId,
        generation: u64,
        transaction_id: u64,
    ) -> Result<AttemptReservation, InitError> {
        let slot = &mut self.slots[index];
        if generation == 0 || transaction_id == 0 || slot.outstanding {
            return Err(InitError::Accounting);
        }
        if generation <= slot.last_generation || self.next_nonce == 0 {
            return Err(InitError::Accounting);
        }
        let nonce = self.next_nonce;
        self.next_nonce = self
            .next_nonce
            .checked_add(1)
            .ok_or(InitError::Accounting)?;
        *slot = ReservationSlot {
            last_generation: generation,
            transaction_id,
            nonce,
            outstanding: true,
            published: false,
        };
        Ok(AttemptReservation {
            role,
            generation,
            transaction_id,
            nonce,
            published: false,
            released: false,
        })
    }

    fn publish(&mut self, token: &mut AttemptReservation) -> Result<(), InitError> {
        let index = role_index(token.role)?;
        let slot = &mut self.slots[index];
        validate_reservation(slot, token)?;
        if token.published || slot.published {
            return Err(InitError::Accounting);
        }
        token.published = true;
        slot.published = true;
        Ok(())
    }

    fn release(&mut self, token: &mut AttemptReservation) -> Result<(), InitError> {
        let index = role_index(token.role)?;
        let slot = &mut self.slots[index];
        validate_reservation(slot, token)?;
        token.released = true;
        slot.outstanding = false;
        slot.published = false;
        slot.transaction_id = 0;
        slot.nonce = 0;
        Ok(())
    }

    const fn outstanding(&self) -> usize {
        self.slots[0].outstanding as usize + self.slots[1].outstanding as usize
    }
}

fn validate_reservation(
    slot: &ReservationSlot,
    token: &AttemptReservation,
) -> Result<(), InitError> {
    if token.released
        || !slot.outstanding
        || slot.last_generation != token.generation
        || slot.transaction_id != token.transaction_id
        || slot.nonce != token.nonce
    {
        Err(InitError::Accounting)
    } else {
        Ok(())
    }
}

fn role_index(role: RoleId) -> Result<usize, InitError> {
    match role {
        RoleId::Registryd => Ok(0),
        RoleId::Devmgr => Ok(1),
        _ => Err(InitError::UnlaunchableRole),
    }
}

#[derive(Debug, Eq, PartialEq)]
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
    Loader(LoadError<NativeError>),
    Supervision,
    Cleanup,
    Accounting,
    GateConfig(GateConfigError),
    Evidence(EvidenceError),
}

impl From<RestartTransitionError> for InitError {
    fn from(value: RestartTransitionError) -> Self {
        Self::Restart(value)
    }
}

#[derive(Debug, Eq, PartialEq)]
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

#[derive(Debug, Eq, PartialEq)]
pub struct SystemInit {
    mode: SystemMode,
    roles: [RoleController; EARLY_ROLE_COUNT],
    degraded_transitions: u8,
    activated: [bool; EARLY_ROLE_COUNT],
    accounting: AttemptLedger,
    gate: Option<GateConfig>,
    evidence: Option<EvidenceLog>,
}

impl SystemInit {
    /// Consumes an already product-validated WRRM manifest and binds exact
    /// executable identities to the two WYR1-A launchable roles.
    pub fn from_manifest(manifest: Manifest<'_>) -> Result<Self, InitError> {
        if manifest.role_count() != 5 {
            return Err(InitError::WrongManifestProfile);
        }
        for ((expected, expected_path), role) in
            EXPECTED_ROLE_PATHS.into_iter().zip(manifest.roles())
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
                || role.path() != expected_path
                || !role.required()
                || !role.requires_ready()
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
            accounting: AttemptLedger::new(),
            gate: None,
            evidence: None,
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
    pub fn resources(&self, role: RoleId) -> Option<&AttemptResources> {
        self.index(role)
            .and_then(|i| self.roles[i].resources.as_ref())
    }

    pub fn reserve_attempt(
        &mut self,
        role: RoleId,
        generation: u64,
        transaction: u64,
    ) -> Result<AttemptReservation, InitError> {
        let index = role_index(role)?;
        self.accounting
            .reserve(index, role, generation, transaction)
    }

    pub fn abort_reservation(
        &mut self,
        mut reservation: AttemptReservation,
    ) -> Result<(), InitError> {
        self.accounting.release(&mut reservation)
    }

    #[must_use]
    pub const fn outstanding_reservations(&self) -> usize {
        self.accounting.outstanding()
    }

    #[must_use]
    pub const fn gate_config(&self) -> Option<GateConfig> {
        self.gate
    }

    #[must_use]
    pub fn evidence_line(&self, index: usize) -> Option<&[u8]> {
        self.evidence
            .as_ref()?
            .line(index)
            .map(|line| line.as_slice())
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

    pub fn install_attempt(&mut self, mut resources: AttemptResources) -> Result<(), InitError> {
        let index = self
            .index(resources.role)
            .ok_or(InitError::UnlaunchableRole)?;
        if resources.task_group.0 == 0
            || resources.process.0 == 0
            || resources.launch_channel.0 == 0
        {
            self.accounting.release(&mut resources.reservation)?;
            return Err(InitError::InvalidResourceHandle);
        }
        if resources.startup_profile != StartupProfile::EarlyBootStub
            || resources.executable_identity != self.roles[index].executable_identity
        {
            self.accounting.release(&mut resources.reservation)?;
            return Err(InitError::ResourceIdentityMismatch);
        }
        let RestartState::Starting {
            generation,
            transaction_id,
            ..
        } = self.roles[index].restart.state()
        else {
            self.accounting.release(&mut resources.reservation)?;
            return Err(InitError::WrongActivationOrder);
        };
        if (generation, transaction_id) != (resources.generation, resources.transaction_id) {
            self.accounting.release(&mut resources.reservation)?;
            return Err(InitError::ResourceIdentityMismatch);
        }
        if self.roles[index].resources.is_some() {
            self.accounting.release(&mut resources.reservation)?;
            return Err(InitError::ResourcesAlreadyInstalled);
        }
        if resources.reservation.role != resources.role
            || resources.reservation.generation != resources.generation
            || resources.reservation.transaction_id != resources.transaction_id
        {
            self.accounting.release(&mut resources.reservation)?;
            return Err(InitError::Accounting);
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
        let index = self.index(role).ok_or(InitError::UnlaunchableRole)?;
        if self.roles[index].resources.is_none() {
            return Err(InitError::MissingAttemptResources);
        }
        self.roles[index]
            .restart
            .child_started(generation, transaction, now)?;
        let resources = self.roles[index]
            .resources
            .as_mut()
            .ok_or(InitError::MissingAttemptResources)?;
        self.accounting.publish(&mut resources.reservation)?;
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
        self.record_evidence(EvidenceEvent::Ready, role, generation, transaction, 0)?;
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

    pub fn ready_wait_failed(
        &mut self,
        role: RoleId,
        generation: u64,
        transaction: u64,
        now: u64,
        failure: AttemptFailure,
    ) -> Result<(), InitError> {
        let controller = self.controller_mut(role)?;
        if let RestartState::AwaitingReady { deadline_ns, .. } = controller.restart.state()
            && now >= deadline_ns
        {
            controller
                .restart
                .deadline_elapsed(generation, transaction, deadline_ns, now)?;
            return Ok(());
        }
        controller
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
        let index = self.index(role).ok_or(InitError::UnlaunchableRole)?;
        let controller = &mut self.roles[index];
        let had_resources = controller.resources.is_some();
        let unpublished = matches!(
            controller.restart.state(),
            RestartState::CleaningUp {
                action: wyrmroot_runtime::CleanupAction::CloseUnpublished,
                ..
            }
        );
        if controller.resources.is_none() && !unpublished {
            return Err(InitError::MissingAttemptResources);
        }
        controller
            .restart
            .cleanup_complete(generation, transaction, now)?;
        if let Some(mut resources) = controller.resources.take() {
            self.accounting.release(&mut resources.reservation)?;
        }
        if had_resources {
            let value = self.roles[index]
                .restart
                .history()
                .as_slice()
                .last()
                .and_then(|record| *record)
                .map(|record| reap_evidence_value(record.failure))
                .ok_or(InitError::Accounting)?;
            self.record_evidence(EvidenceEvent::Reap, role, generation, transaction, value)?;
        }
        self.update_permanent_failure(role)?;
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
        controller
            .restart
            .cleanup_failed(generation, transaction, now)?;
        self.update_permanent_failure(role)?;
        Ok(())
    }

    pub fn start_replacement(
        &mut self,
        role: RoleId,
        now: u64,
        generation: u64,
        transaction: u64,
    ) -> Result<(), InitError> {
        let previous = self
            .index(role)
            .and_then(|index| self.roles[index].restart.history().as_slice().last())
            .and_then(|record| *record)
            .map(|record| (record.generation, record.transaction_id))
            .ok_or(InitError::Accounting)?;
        self.controller_mut(role)?
            .restart
            .start_replacement(now, generation, transaction)?;
        self.record_evidence(
            EvidenceEvent::Restart,
            role,
            previous.0,
            previous.1,
            generation,
        )?;
        self.update_permanent_failure(role)?;
        Ok(())
    }

    pub fn fatal(&mut self) {
        self.mode = SystemMode::Fatal;
    }

    fn retire_attempt_after_fatal(&mut self, role: RoleId) -> Result<(), InitError> {
        let index = self.index(role).ok_or(InitError::UnlaunchableRole)?;
        if let Some(mut resources) = self.roles[index].resources.take() {
            self.accounting.release(&mut resources.reservation)?;
        }
        self.fatal();
        Ok(())
    }

    fn update_permanent_failure(&mut self, role: RoleId) -> Result<(), InitError> {
        if self
            .role_state(role)
            .is_some_and(|state| matches!(state, RestartState::PermanentFailure { .. }))
            && self.mode != SystemMode::Degraded
        {
            self.mode = SystemMode::Degraded;
            self.degraded_transitions = self.degraded_transitions.saturating_add(1);
            let identity = self
                .index(role)
                .and_then(|index| self.roles[index].restart.history().as_slice().last())
                .and_then(|record| *record)
                .map(|record| (record.generation, record.transaction_id));
            if let Some((last_generation, last_transaction_id)) = identity {
                self.record_evidence(
                    EvidenceEvent::PermanentFailure,
                    role,
                    last_generation,
                    last_transaction_id,
                    1,
                )?;
            }
        }
        Ok(())
    }
    fn record_evidence(
        &mut self,
        event: EvidenceEvent,
        role: RoleId,
        generation: u64,
        transaction: u64,
        value: u64,
    ) -> Result<(), InitError> {
        if let Some(evidence) = &mut self.evidence {
            evidence
                .record(event, role as u32, generation, transaction, value)
                .map_err(InitError::Evidence)?;
        }
        Ok(())
    }

    fn finalize_evidence(&mut self, result: RecoveryResult) -> Result<(), InitError> {
        if let Some(evidence) = &mut self.evidence {
            match result {
                RecoveryResult::Recovered | RecoveryResult::Degraded => {}
                RecoveryResult::Fatal => return Ok(()),
            }
            evidence
                .record(EvidenceEvent::Terminal, 0, 0, 0, 0)
                .map_err(InitError::Evidence)?;
        }
        Ok(())
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

    fn executable_identity(&self, role: RoleId) -> Result<[u8; 32], InitError> {
        let index = self.index(role).ok_or(InitError::UnlaunchableRole)?;
        Ok(self.roles[index].executable_identity)
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
    let mut controller = SystemInit::from_manifest(manifest)?;
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
    controller.gate = match archive.lookup(GATE_CONFIG_PATH.as_bytes()) {
        Ok(entry) => Some(parse_gate_config(entry.data()).map_err(InitError::GateConfig)?),
        Err(LookupError::NotFound) => None,
        Err(error) => return Err(map_lookup(error)),
    };
    controller.evidence = controller
        .gate
        .map(|config| EvidenceLog::new(config.nonce, config.scenario))
        .transpose()
        .map_err(InitError::Evidence)?;
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
    fn terminate_task_group(&mut self, task_group: DwHandle) -> Result<(), NativeError>;
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
) -> Result<ResidentSystemInit, InitError>
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
        let error = InitError::Launch(wyrmroot_loader::launch::LaunchError::HandleCount);
        close_malformed_startup(system, &handles, counts.handles, bootstrap_channel)?;
        return Err(error);
    }
    let startup = (|| {
        let parsed = parse_init(LaunchProfile::Supervisor, &init_bytes, &handles)
            .map_err(InitError::Launch)?;
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
            .map_err(InitError::Native)??;
        Ok::<_, InitError>((authority, activation))
    })();
    let (authority, (result, controller)) = match startup {
        Ok(value) => value,
        Err(error) => {
            close_startup_failure(system, &handles, bootstrap_channel)?;
            return Err(error);
        }
    };
    system
        .close_handle(bootstrap_channel)
        .map_err(InitError::Native)?;
    Ok(ResidentSystemInit {
        controller,
        authority,
        result,
        last_tick_ns: system.now().map_err(InitError::Native)?,
    })
}

fn close_startup_failure<S: InitPlatform>(
    system: &mut S,
    handles: &[DwReceivedHandleInfoV1],
    bootstrap_channel: DwHandle,
) -> Result<(), InitError> {
    let mut failed = false;
    for handle in handles {
        if handle.handle.0 != 0 {
            failed |= system.close_handle(handle.handle).is_err();
        }
    }
    failed |= system.close_handle(bootstrap_channel).is_err();
    if failed {
        Err(InitError::Cleanup)
    } else {
        Ok(())
    }
}

fn close_malformed_startup<S: InitPlatform>(
    system: &mut S,
    handles: &[DwReceivedHandleInfoV1; 3],
    reported_handles: usize,
    bootstrap_channel: DwHandle,
) -> Result<(), InitError> {
    let initialized = core::cmp::min(reported_handles, handles.len());
    close_startup_failure(system, &handles[..initialized], bootstrap_channel)
}

fn activate_retained_bootfs<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    bootstrap_channel: DwHandle,
    parent_transaction: u64,
    bootfs: &[u8],
) -> Result<(RecoveryResult, SystemInit), InitError>
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
    let retire_now = system.now().map_err(InitError::Native)?;
    let retire_deadline = retire_now
        .checked_add(WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns)
        .ok_or(InitError::Restart(
            RestartTransitionError::ArithmeticOverflow,
        ))?;
    let retire_item = DwWaitItemV1 {
        handle: bootstrap_channel,
        signals: DW_SIGNAL_PEER_CLOSED,
    };
    let retired = waits
        .wait_many(
            core::slice::from_ref(&retire_item),
            DwDeadline(retire_deadline),
        )
        .map_err(|_| InitError::Supervision)?;
    if retired.index != 0 || retired.observed.0 & DW_SIGNAL_PEER_CLOSED.0 == 0 {
        return Err(InitError::Supervision);
    }
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
            let executable_identity = controller.executable_identity(role)?;
            let task_group = system
                .create_attempt_task_group(authority.task_group)
                .map_err(InitError::Native)?;
            let reservation = controller.reserve_attempt(role, generation, transaction_id)?;
            let role_authority = LoadAuthority {
                task_group,
                ..authority
            };
            let loaded = match load_role(
                loader,
                role_authority,
                bootfs,
                role,
                executable_identity,
                transaction_id,
            ) {
                Ok(value) => value,
                Err(error) => {
                    let now = match system.now().map_err(InitError::Native) {
                        Ok(now) => now,
                        Err(clock_error) => {
                            let close_failed = system.close_handle(task_group).is_err();
                            let release_failed = controller.abort_reservation(reservation).is_err();
                            controller.fatal();
                            return Err(if close_failed || release_failed {
                                InitError::Cleanup
                            } else {
                                clock_error
                            });
                        }
                    };
                    wyr1_test_set_restart_stage(6);
                    if let Err(transition_error) = controller.fail(
                        role,
                        generation,
                        transaction_id,
                        now,
                        AttemptFailure::CreationFailed,
                    ) {
                        let close_failed = system.close_handle(task_group).is_err();
                        let release_failed = controller.abort_reservation(reservation).is_err();
                        controller.fatal();
                        return Err(if close_failed || release_failed {
                            InitError::Cleanup
                        } else {
                            transition_error
                        });
                    }
                    let rollback_failed = matches!(
                        error,
                        InitError::Loader(LoadError::Platform {
                            rollback_failed: true,
                            ..
                        })
                    );
                    let close_failed = system.close_handle(task_group).is_err();
                    if rollback_failed || close_failed {
                        let retired_at = now.checked_add(1).ok_or(InitError::Accounting)?;
                        wyr1_test_set_restart_stage(7);
                        controller.cleanup_failed(role, generation, transaction_id, retired_at)?;
                        controller.fatal();
                        return Err(error);
                    }
                    controller.abort_reservation(reservation)?;
                    let retired_at = now.checked_add(1).ok_or(InitError::Accounting)?;
                    wyr1_test_set_restart_stage(7);
                    controller.cleanup_complete(role, generation, transaction_id, retired_at)?;
                    wyr1_test_set_restart_stage(10);
                    if advance_or_degrade(system, &mut controller, role, transaction_id)? {
                        controller.finalize_evidence(RecoveryResult::Degraded)?;
                        return Ok((RecoveryResult::Degraded, controller));
                    }
                    continue;
                }
            };
            let install = controller.install_attempt(AttemptResources {
                role,
                generation,
                transaction_id,
                executable_identity,
                startup_profile: StartupProfile::EarlyBootStub,
                task_group,
                process: loaded.process,
                launch_channel: loaded.launch_channel,
                mappings: 0,
                reservation,
            });
            if let Err(error) = install {
                controller.fatal();
                return match cleanup_loaded(system, waits, loaded, task_group, true) {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(cleanup),
                };
            }
            let now = match system.now().map_err(InitError::Native) {
                Ok(now) => now,
                Err(error) => {
                    return Err(cleanup_after_transition_error(
                        system,
                        waits,
                        &mut controller,
                        loaded,
                        task_group,
                        role,
                        error,
                    ));
                }
            };
            if let Err(error) = controller.child_started(role, generation, transaction_id, now) {
                return Err(cleanup_after_transition_error(
                    system,
                    waits,
                    &mut controller,
                    loaded,
                    task_group,
                    role,
                    error,
                ));
            }
            let deadline = match now.checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns) {
                Some(deadline) => DwDeadline(deadline),
                None => {
                    return Err(cleanup_after_transition_error(
                        system,
                        waits,
                        &mut controller,
                        loaded,
                        task_group,
                        role,
                        InitError::Restart(RestartTransitionError::ArithmeticOverflow),
                    ));
                }
            };
            match await_child_ready_profile_observed(
                waits,
                loaded.process,
                loaded.launch_channel,
                LaunchProfile::EarlyBootStub,
                transaction_id,
                deadline,
            ) {
                Ok(()) => {
                    let now = match system.now().map_err(InitError::Native) {
                        Ok(now) => now,
                        Err(error) => {
                            return Err(cleanup_after_transition_error(
                                system,
                                waits,
                                &mut controller,
                                loaded,
                                task_group,
                                role,
                                error,
                            ));
                        }
                    };
                    if let Err(error) = controller.ready(role, generation, transaction_id, now) {
                        return Err(cleanup_after_transition_error(
                            system,
                            waits,
                            &mut controller,
                            loaded,
                            task_group,
                            role,
                            error,
                        ));
                    }
                    match supervise_ready_child_profile(
                        waits,
                        loaded.process,
                        loaded.launch_channel,
                        LaunchProfile::EarlyBootStub,
                        transaction_id,
                        DW_DEADLINE_INFINITE,
                    ) {
                        Ok(info) => {
                            let disposition = terminal_disposition(&info);
                            let now = match system.now().map_err(InitError::Native) {
                                Ok(now) => now,
                                Err(error) => {
                                    return Err(cleanup_after_transition_error(
                                        system,
                                        waits,
                                        &mut controller,
                                        loaded,
                                        task_group,
                                        role,
                                        error,
                                    ));
                                }
                            };
                            if let Err(error) = controller.terminal(
                                role,
                                generation,
                                transaction_id,
                                now,
                                disposition,
                            ) {
                                return Err(cleanup_after_transition_error(
                                    system,
                                    waits,
                                    &mut controller,
                                    loaded,
                                    task_group,
                                    role,
                                    error,
                                ));
                            }
                            complete_native_cleanup(
                                system,
                                waits,
                                &mut controller,
                                loaded,
                                task_group,
                                false,
                                role,
                                generation,
                                transaction_id,
                                now,
                            )?;
                            if disposition == TerminalDisposition::NormalExit(0) {
                                break;
                            }
                            wyr1_test_set_restart_stage(10);
                            if advance_or_degrade(system, &mut controller, role, transaction_id)? {
                                controller.finalize_evidence(RecoveryResult::Degraded)?;
                                return Ok((RecoveryResult::Degraded, controller));
                            }
                        }
                        Err(error) => {
                            let failure = classify_observed_supervision(&error, true);
                            let now = match system.now().map_err(InitError::Native) {
                                Ok(now) => now,
                                Err(error) => {
                                    return Err(cleanup_after_transition_error(
                                        system,
                                        waits,
                                        &mut controller,
                                        loaded,
                                        task_group,
                                        role,
                                        error,
                                    ));
                                }
                            };
                            wyr1_test_set_restart_stage(8);
                            if let Err(error) =
                                controller.fail(role, generation, transaction_id, now, failure)
                            {
                                return Err(cleanup_after_transition_error(
                                    system,
                                    waits,
                                    &mut controller,
                                    loaded,
                                    task_group,
                                    role,
                                    error,
                                ));
                            }
                            complete_native_cleanup(
                                system,
                                waits,
                                &mut controller,
                                loaded,
                                task_group,
                                !error.process_exit_observed(),
                                role,
                                generation,
                                transaction_id,
                                now,
                            )?;
                            wyr1_test_set_restart_stage(10);
                            if advance_or_degrade(system, &mut controller, role, transaction_id)? {
                                controller.finalize_evidence(RecoveryResult::Degraded)?;
                                return Ok((RecoveryResult::Degraded, controller));
                            }
                        }
                    }
                }
                Err(error) => {
                    let failure = classify_observed_supervision(&error, false);
                    let now = match system.now().map_err(InitError::Native) {
                        Ok(now) => now,
                        Err(error) => {
                            return Err(cleanup_after_transition_error(
                                system,
                                waits,
                                &mut controller,
                                loaded,
                                task_group,
                                role,
                                error,
                            ));
                        }
                    };
                    wyr1_test_set_restart_stage(9);
                    if let Err(error) =
                        controller.ready_wait_failed(role, generation, transaction_id, now, failure)
                    {
                        return Err(cleanup_after_transition_error(
                            system,
                            waits,
                            &mut controller,
                            loaded,
                            task_group,
                            role,
                            error,
                        ));
                    }
                    complete_native_cleanup(
                        system,
                        waits,
                        &mut controller,
                        loaded,
                        task_group,
                        !error.process_exit_observed(),
                        role,
                        generation,
                        transaction_id,
                        now,
                    )?;
                    wyr1_test_set_restart_stage(10);
                    if advance_or_degrade(system, &mut controller, role, transaction_id)? {
                        controller.finalize_evidence(RecoveryResult::Degraded)?;
                        return Ok((RecoveryResult::Degraded, controller));
                    }
                }
            }
        }
    }
    controller.finalize_evidence(RecoveryResult::Recovered)?;
    Ok((RecoveryResult::Recovered, controller))
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
fn load_role<L: LoaderPlatform<Error = NativeError>>(
    loader: &mut L,
    authority: LoadAuthority,
    bytes: &[u8],
    role: RoleId,
    expected_identity: [u8; 32],
    transaction_id: u64,
) -> Result<LoadedProcess, InitError> {
    let archive = Archive::new(bytes).map_err(InitError::Bootfs)?;
    let path = match role {
        RoleId::Registryd => "system/registryd",
        RoleId::Devmgr => "system/devmgr",
        _ => return Err(InitError::UnlaunchableRole),
    };
    let e = archive.lookup(path.as_bytes()).map_err(map_lookup)?;
    if wyrmroot_runtime::sha256::digest(e.data()) != expected_identity {
        return Err(InitError::ArtifactIdentityMismatch(role));
    }
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
    .map_err(InitError::Loader)
}
fn cleanup_loaded<S: InitPlatform, W: SupervisionPlatform<Error = NativeError>>(
    system: &mut S,
    waits: &mut W,
    loaded: LoadedProcess,
    task_group: DwHandle,
    terminate: bool,
) -> Result<(), InitError> {
    let mut failed = false;
    let cleanup_deadline = system
        .now()
        .ok()
        .and_then(|now| now.checked_add(WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns));
    if terminate && system.terminate_task_group(task_group).is_err() {
        // A termination request may race the child's own terminal transition.
        failed |= !matches!(
            waits.query_task_termination(loaded.process),
            Ok(info) if info.state == DW_TASK_STATE_EXITED
        );
    }
    let mut terminal = matches!(
        waits.query_task_termination(loaded.process),
        Ok(info) if info.state == DW_TASK_STATE_EXITED
    );
    if !terminal && let Some(deadline) = cleanup_deadline {
        let item = DwWaitItemV1 {
            handle: loaded.process,
            signals: DW_SIGNAL_EXITED,
        };
        terminal = matches!(
            waits.wait_many(core::slice::from_ref(&item), DwDeadline(deadline)),
            Ok(result) if result.index == 0 && result.observed.0 & DW_SIGNAL_EXITED.0 != 0
        ) && matches!(
            waits.query_task_termination(loaded.process),
            Ok(info) if info.state == DW_TASK_STATE_EXITED
        );
    }
    failed |= !terminal;
    for h in [loaded.launch_channel, loaded.process, task_group] {
        failed |= system.close_handle(h).is_err();
    }
    if failed {
        Err(InitError::Cleanup)
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn cleanup_after_transition_error<S: InitPlatform, W: SupervisionPlatform<Error = NativeError>>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    loaded: LoadedProcess,
    task_group: DwHandle,
    role: RoleId,
    transition_error: InitError,
) -> InitError {
    if cleanup_loaded(system, waits, loaded, task_group, true).is_err() {
        controller.fatal();
        return InitError::Cleanup;
    }
    match controller.retire_attempt_after_fatal(role) {
        Ok(()) => transition_error,
        Err(error) => {
            controller.fatal();
            error
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn complete_native_cleanup<S: InitPlatform, W: SupervisionPlatform<Error = NativeError>>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    loaded: LoadedProcess,
    task_group: DwHandle,
    terminate: bool,
    role: RoleId,
    generation: u64,
    transaction: u64,
    classified_at: u64,
) -> Result<(), InitError> {
    match cleanup_loaded(system, waits, loaded, task_group, terminate) {
        Ok(()) => {
            let retired_at = classified_at.checked_add(1).ok_or(InitError::Accounting)?;
            match controller.cleanup_complete(role, generation, transaction, retired_at) {
                Ok(()) => Ok(()),
                Err(error) => {
                    let retirement = controller.retire_attempt_after_fatal(role);
                    match retirement {
                        Ok(()) => Err(error),
                        Err(retirement_error) => Err(retirement_error),
                    }
                }
            }
        }
        Err(error) => {
            let classified = classified_at.checked_add(1).ok_or(InitError::Accounting)?;
            let transition = controller.cleanup_failed(role, generation, transaction, classified);
            controller.fatal();
            match transition {
                Ok(()) => Err(error),
                Err(_) => Err(InitError::Cleanup),
            }
        }
    }
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
        SupervisionError::ExitedBeforeReady | SupervisionError::Exit(_) => {
            AttemptFailure::ExitQueryFailed
        }
        SupervisionError::ExitQuery(_) => AttemptFailure::ExitQueryFailed,
        _ => AttemptFailure::WaitFailed,
    }
}

fn classify_observed_supervision(
    error: &ObservedSupervisionError<NativeError>,
    after_ready: bool,
) -> AttemptFailure {
    let disposition = match error {
        ObservedSupervisionError::ExitedBeforeReady(info)
        | ObservedSupervisionError::PeerClosedBeforeReady(info)
        | ObservedSupervisionError::Exit(_, info)
        | ObservedSupervisionError::ExitObservedReadiness(_, info) => {
            Some(terminal_disposition(info))
        }
        ObservedSupervisionError::Supervision(_) => None,
    };
    match disposition {
        Some(disposition) if after_ready => AttemptFailure::ExitAfterReady(disposition),
        Some(disposition) => AttemptFailure::ExitBeforeReady(disposition),
        None => match error {
            ObservedSupervisionError::Supervision(error) => classify_supervision(error),
            _ => unreachable!("termination-bearing variants were handled above"),
        },
    }
}

fn terminal_disposition(info: &DwTaskTerminationInfoV1) -> TerminalDisposition {
    if info.reason == DW_TERMINATION_NORMAL_EXIT
        && info.exception_type.0 == 0
        && info.detail == 0
        && info.fault_address == 0
    {
        TerminalDisposition::NormalExit(info.application_code)
    } else if info.reason == DW_TERMINATION_TASK_GROUP_TEARDOWN
        && info.exception_type.0 == 0
        && info.detail == 0
        && info.fault_address == 0
    {
        TerminalDisposition::TaskGroupTeardown
    } else if info.reason == DW_TERMINATION_AUTHORIZED
        && info.exception_type.0 == 0
        && info.detail == 0
        && info.fault_address == 0
    {
        TerminalDisposition::AuthorizedTermination
    } else {
        TerminalDisposition::UnhandledException
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
            let observed_now = wait_for_replacement(system, deadline_ns)?;
            controller.start_replacement(
                role,
                observed_now,
                next_generation,
                next_transaction(transaction)?,
            )?;
            Ok(matches!(controller.mode(), SystemMode::Degraded))
        }
        _ => Err(InitError::WrongActivationOrder),
    }
}

fn wait_for_replacement<S: InitPlatform>(
    system: &mut S,
    deadline_ns: u64,
) -> Result<u64, InitError> {
    system.wait_until(deadline_ns).map_err(InitError::Native)?;
    let observed_now = system.now().map_err(InitError::Native)?;
    if observed_now < deadline_ns {
        return Err(InitError::WrongActivationOrder);
    }
    Ok(observed_now)
}

fn next_transaction(transaction: u64) -> Result<u64, InitError> {
    transaction.checked_add(1).ok_or(InitError::Restart(
        RestartTransitionError::ArithmeticOverflow,
    ))
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

pub const REAP_CLASS_NORMAL_EXIT: u32 = 1;
pub const REAP_CLASS_AUTHORIZED_TERMINATION: u32 = 2;
pub const REAP_CLASS_TASK_GROUP_TEARDOWN: u32 = 3;
pub const REAP_CLASS_UNHANDLED_EXCEPTION: u32 = 4;

#[must_use]
pub const fn reap_evidence_value(failure: AttemptFailure) -> u64 {
    let disposition = match failure {
        AttemptFailure::ExitBeforeReady(disposition)
        | AttemptFailure::ExitAfterReady(disposition) => disposition,
        AttemptFailure::MalformedReady
        | AttemptFailure::DuplicateReady
        | AttemptFailure::ReadinessFailedAfterExit
        | AttemptFailure::WrongTransactionReady
        | AttemptFailure::PeerClosedBeforeReady
        | AttemptFailure::WaitFailed
        | AttemptFailure::ReadyTimeout
        | AttemptFailure::Cancelled => TerminalDisposition::TaskGroupTeardown,
        AttemptFailure::ExitQueryFailed => TerminalDisposition::UnhandledException,
        AttemptFailure::CreationFailed | AttemptFailure::StartFailed => {
            TerminalDisposition::AuthorizedTermination
        }
    };
    match disposition {
        TerminalDisposition::NormalExit(code) => {
            ((REAP_CLASS_NORMAL_EXIT as u64) << 32) | code as u64
        }
        TerminalDisposition::AuthorizedTermination => {
            (REAP_CLASS_AUTHORIZED_TERMINATION as u64) << 32
        }
        TerminalDisposition::TaskGroupTeardown => (REAP_CLASS_TASK_GROUP_TEARDOWN as u64) << 32,
        TerminalDisposition::UnhandledException => (REAP_CLASS_UNHANDLED_EXCEPTION as u64) << 32,
    }
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

#[cfg(test)]
mod native_cleanup_tests {
    use super::*;
    use deepwyrm_syscall::{
        DW_TASK_STATE_EXITED, DwStatus, DwTaskState, DwTaskTerminationInfoV1, DwWaitResultV1,
    };
    use wyrmroot_runtime::NativeOutputError;

    const FAILURE: NativeError = NativeError::Status(DwStatus(-1));

    struct MockNative {
        now: u64,
        terminate_fails: bool,
        close_failure: DwHandle,
        closed: [DwHandle; 4],
        close_count: usize,
        wake_now: Option<u64>,
    }

    impl MockNative {
        const fn new() -> Self {
            Self {
                now: 10,
                terminate_fails: false,
                close_failure: DwHandle(0),
                closed: [DwHandle(0); 4],
                close_count: 0,
                wake_now: None,
            }
        }
    }

    impl InitPlatform for MockNative {
        fn query_capability_info(
            &mut self,
            _handle: DwHandle,
        ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
            Err(FAILURE)
        }

        fn receive_channel(
            &mut self,
            _channel: DwHandle,
            _bytes: &mut [u8],
            _handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, NativeError> {
            Err(FAILURE)
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
            if handle == self.close_failure {
                Err(FAILURE)
            } else {
                Ok(())
            }
        }

        fn create_attempt_task_group(
            &mut self,
            _parent: DwHandle,
        ) -> Result<DwHandle, NativeError> {
            Err(FAILURE)
        }

        fn terminate_task_group(&mut self, _task_group: DwHandle) -> Result<(), NativeError> {
            if self.terminate_fails {
                Err(FAILURE)
            } else {
                Ok(())
            }
        }

        fn now(&mut self) -> Result<u64, NativeError> {
            Ok(self.now)
        }

        fn wait_until(&mut self, _deadline_ns: u64) -> Result<(), NativeError> {
            match self.wake_now {
                Some(now) => {
                    self.now = now;
                    Ok(())
                }
                None => Err(FAILURE),
            }
        }
    }

    struct MockWaits {
        query_count: u8,
        terminal_at: u8,
        wait_exited: bool,
    }

    impl SupervisionPlatform for MockWaits {
        type Error = NativeError;

        fn wait_many(
            &mut self,
            _items: &[DwWaitItemV1],
            _deadline: DwDeadline,
        ) -> Result<DwWaitResultV1, Self::Error> {
            if self.wait_exited {
                Ok(DwWaitResultV1 {
                    index: 0,
                    observed: DW_SIGNAL_EXITED,
                    ..DwWaitResultV1::default()
                })
            } else {
                Err(NativeError::Output(NativeOutputError::InvalidWaitResult))
            }
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
            self.query_count += 1;
            Ok(DwTaskTerminationInfoV1 {
                state: if self.query_count >= self.terminal_at {
                    DW_TASK_STATE_EXITED
                } else {
                    DwTaskState(0)
                },
                ..DwTaskTerminationInfoV1::default()
            })
        }
    }

    const LOADED: LoadedProcess = LoadedProcess {
        process: DwHandle(20),
        launch_channel: DwHandle(30),
    };

    #[test]
    fn task_group_termination_race_reconciles_with_fresh_terminal_query() {
        let mut native = MockNative::new();
        native.terminate_fails = true;
        let mut waits = MockWaits {
            query_count: 0,
            terminal_at: 1,
            wait_exited: false,
        };
        assert_eq!(
            cleanup_loaded(&mut native, &mut waits, LOADED, DwHandle(10), true),
            Ok(())
        );
        assert_eq!(
            &native.closed[..3],
            &[DwHandle(30), DwHandle(20), DwHandle(10)]
        );
    }

    #[test]
    fn cleanup_closes_every_handle_after_individual_close_failure() {
        let mut native = MockNative::new();
        native.close_failure = DwHandle(20);
        let mut waits = MockWaits {
            query_count: 0,
            terminal_at: 1,
            wait_exited: false,
        };
        assert_eq!(
            cleanup_loaded(&mut native, &mut waits, LOADED, DwHandle(10), false),
            Err(InitError::Cleanup)
        );
        assert_eq!(native.close_count, 3);
        assert_eq!(
            &native.closed[..3],
            &[DwHandle(30), DwHandle(20), DwHandle(10)]
        );
    }

    #[test]
    fn cleanup_deadline_failure_is_visible_after_closing_all_handles() {
        let mut native = MockNative::new();
        let mut waits = MockWaits {
            query_count: 0,
            terminal_at: u8::MAX,
            wait_exited: false,
        };
        assert_eq!(
            cleanup_loaded(&mut native, &mut waits, LOADED, DwHandle(10), true),
            Err(InitError::Cleanup)
        );
        assert_eq!(native.close_count, 3);
    }

    #[test]
    fn oversized_startup_count_closes_every_initialized_handle_and_channel() {
        let handles = [
            DwReceivedHandleInfoV1 {
                handle: DwHandle(1),
                ..DwReceivedHandleInfoV1::default()
            },
            DwReceivedHandleInfoV1 {
                handle: DwHandle(2),
                ..DwReceivedHandleInfoV1::default()
            },
            DwReceivedHandleInfoV1 {
                handle: DwHandle(3),
                ..DwReceivedHandleInfoV1::default()
            },
        ];
        let mut native = MockNative::new();
        assert_eq!(
            close_malformed_startup(&mut native, &handles, usize::MAX, DwHandle(4)),
            Ok(())
        );
        assert_eq!(
            native.closed,
            [DwHandle(1), DwHandle(2), DwHandle(3), DwHandle(4)]
        );
    }

    #[test]
    fn replacement_uses_fresh_delayed_wake_and_rejects_early_wake() {
        let mut native = MockNative::new();
        native.wake_now = Some(125);
        assert_eq!(wait_for_replacement(&mut native, 100), Ok(125));
        native.wake_now = Some(99);
        assert_eq!(
            wait_for_replacement(&mut native, 100),
            Err(InitError::WrongActivationOrder)
        );
    }

    #[test]
    fn replacement_transaction_overflow_is_structured() {
        assert_eq!(
            next_transaction(u64::MAX),
            Err(InitError::Restart(
                RestartTransitionError::ArithmeticOverflow
            ))
        );
    }

    #[test]
    fn exact_terminal_records_map_to_all_reap_classes() {
        let mut info = DwTaskTerminationInfoV1 {
            reason: DW_TERMINATION_NORMAL_EXIT,
            application_code: 0xA101_F001,
            ..DwTaskTerminationInfoV1::default()
        };
        assert_eq!(
            terminal_disposition(&info),
            TerminalDisposition::NormalExit(0xA101_F001)
        );
        info.reason = DW_TERMINATION_AUTHORIZED;
        info.application_code = 0;
        assert_eq!(
            terminal_disposition(&info),
            TerminalDisposition::AuthorizedTermination
        );
        info.reason = deepwyrm_syscall::DW_TERMINATION_UNHANDLED_EXCEPTION;
        info.exception_type = deepwyrm_syscall::DW_EXCEPTION_ILLEGAL_INSTRUCTION;
        assert_eq!(
            terminal_disposition(&info),
            TerminalDisposition::UnhandledException
        );
        info.reason = DW_TERMINATION_TASK_GROUP_TEARDOWN;
        info.exception_type = deepwyrm_syscall::DwExceptionType(0);
        assert_eq!(
            terminal_disposition(&info),
            TerminalDisposition::TaskGroupTeardown
        );
        assert_eq!(
            reap_evidence_value(AttemptFailure::ExitAfterReady(terminal_disposition(&info))),
            (REAP_CLASS_TASK_GROUP_TEARDOWN as u64) << 32
        );
        assert_eq!(
            reap_evidence_value(AttemptFailure::DuplicateReady),
            (REAP_CLASS_TASK_GROUP_TEARDOWN as u64) << 32
        );
    }

    #[test]
    fn rollback_failure_maps_to_exact_fatal_reboot_status() {
        let error = InitError::Loader(LoadError::Platform {
            stage: wyrmroot_loader::process::LoadStage::ProcessCreate,
            cause: FAILURE,
            rollback_failed: true,
        });
        assert_eq!(
            fatal_application_status(&error),
            InitApplicationStatus::FatalRebootRequired
        );
        assert_eq!(fatal_application_status(&error) as u32, 0xAF01_0002);
    }

    #[cfg(feature = "wyr1-test-evidence")]
    #[test]
    fn wyr1_test_failure_status_preserves_top_level_category() {
        assert_eq!(
            wyr1_test_failure_application_status(&InitError::Cleanup),
            0xAF11_0015
        );
        assert_eq!(
            wyr1_test_failure_application_status(&InitError::Accounting),
            0xAF11_0016
        );
        assert_eq!(
            wyr1_test_failure_application_status(&InitError::WrongActivationOrder),
            0xAF11_0003
        );
        wyr1_test_set_restart_stage(3);
        assert_eq!(
            wyr1_test_failure_application_status(&InitError::Restart(
                RestartTransitionError::InvalidState
            )),
            0xAF13_0303
        );
    }
}
