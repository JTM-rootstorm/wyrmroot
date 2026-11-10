//! The restart controller: per-role restart state and the attempt ledger.

use crate::*;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct AttemptResources {
    pub(crate) role: RoleId,
    pub(crate) generation: u64,
    pub(crate) transaction_id: u64,
    pub(crate) executable_identity: [u8; 32],
    pub(crate) startup_profile: StartupProfile,
    pub(crate) task_group: DwHandle,
    pub(crate) process: DwHandle,
    pub(crate) launch_channel: DwHandle,
    pub(crate) mappings: u8,
    pub(crate) reservation: AttemptReservation,
}

/// Affine token proving one fixed-role generation was reserved before child
/// publication. It is intentionally neither `Copy` nor `Clone`.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct AttemptReservation {
    pub(crate) role: RoleId,
    pub(crate) generation: u64,
    pub(crate) transaction_id: u64,
    pub(crate) nonce: u64,
    pub(crate) published: bool,
    pub(crate) released: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReservationSlot {
    pub(crate) last_generation: u64,
    pub(crate) transaction_id: u64,
    pub(crate) nonce: u64,
    pub(crate) outstanding: bool,
    pub(crate) published: bool,
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
pub(crate) struct AttemptLedger {
    pub(crate) slots: [ReservationSlot; EARLY_ROLE_COUNT],
    pub(crate) next_nonce: u64,
}

impl AttemptLedger {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [ReservationSlot::EMPTY; EARLY_ROLE_COUNT],
            next_nonce: 1,
        }
    }

    pub(crate) fn reserve(
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

    pub(crate) fn publish(&mut self, token: &mut AttemptReservation) -> Result<(), InitError> {
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

    pub(crate) fn release(&mut self, token: &mut AttemptReservation) -> Result<(), InitError> {
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
}

pub(crate) fn validate_reservation(
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

pub(crate) fn role_index(role: RoleId) -> Result<usize, InitError> {
    match role {
        RoleId::Registryd => Ok(0),
        RoleId::Devmgr => Ok(1),
        _ => Err(InitError::UnlaunchableRole),
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RoleController {
    pub(crate) role: RoleId,
    pub(crate) executable_identity: [u8; 32],
    pub(crate) restart: RestartSupervisor,
    pub(crate) resources: Option<AttemptResources>,
}

impl RoleController {
    pub(crate) fn new(role: RoleId, identity: [u8; 32]) -> Result<Self, InitError> {
        Ok(Self {
            role,
            executable_identity: identity,
            restart: RestartSupervisor::new(WYR0_I_SUPERVISION_POLICY)?,
            resources: None,
        })
    }

    pub(crate) fn admit_recovery(
        &mut self,
        accounting: &AttemptLedger,
        generation: u64,
        transaction: u64,
        now: u64,
    ) -> Result<(), InitError> {
        let resources = self
            .resources
            .as_ref()
            .ok_or(InitError::MissingAttemptResources)?;
        if resources.generation != generation {
            return Err(RestartTransitionError::StaleGeneration.into());
        }
        if resources.transaction_id != transaction {
            return Err(RestartTransitionError::TransactionMismatch.into());
        }
        let reservation = &resources.reservation;
        let slot = &accounting.slots[role_index(self.role)?];
        validate_reservation(slot, reservation)?;
        if resources.role != self.role
            || reservation.role != self.role
            || reservation.generation != generation
            || reservation.transaction_id != transaction
            || !reservation.published
            || !slot.published
        {
            return Err(InitError::Accounting);
        }
        self.restart
            .admit_recovery(generation, transaction, now, AttemptFailure::WaitFailed)?;
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct SystemInit {
    pub(crate) mode: SystemMode,
    pub(crate) roles: [RoleController; EARLY_ROLE_COUNT],
    pub(crate) degraded_transitions: u8,
    pub(crate) activated: [bool; EARLY_ROLE_COUNT],
    pub(crate) accounting: AttemptLedger,
    pub(crate) registry_startup_profile: StartupProfile,
    pub(crate) devmgr_startup_profile: StartupProfile,
}

impl SystemInit {
    pub(crate) fn from_manifest(manifest: Manifest<'_>) -> Result<Self, InitError> {
        Self::from_manifest_with_profiles(
            manifest,
            StartupProfile::BootstrapRegistry,
            StartupProfile::DeviceCoordinator,
            StartupProfile::Wyrmsh,
        )
    }

    pub(crate) fn from_manifest_with_profiles(
        manifest: Manifest<'_>,
        registry_startup_profile: StartupProfile,
        devmgr_startup_profile: StartupProfile,
        wyrmsh_startup_profile: StartupProfile,
    ) -> Result<Self, InitError> {
        if manifest.role_count() != 5 {
            return Err(InitError::WrongManifestProfile);
        }
        for ((expected, expected_path), role) in
            EXPECTED_ROLE_PATHS.into_iter().zip(manifest.roles())
        {
            let expected_shape = if expected == RoleId::Registryd {
                (Activation::Early, registry_startup_profile)
            } else if expected == RoleId::Devmgr {
                (Activation::Early, devmgr_startup_profile)
            } else if expected == RoleId::Uart16550d {
                (Activation::DeviceBound, StartupProfile::Retained)
            } else if expected == RoleId::Wyrmsh {
                (Activation::ConsoleBound, wyrmsh_startup_profile)
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
            registry_startup_profile,
            devmgr_startup_profile,
        })
    }

    #[must_use]
    pub(crate) const fn mode(&self) -> SystemMode {
        self.mode
    }
    #[must_use]
    pub(crate) fn role_state(&self, role: RoleId) -> Option<RestartState> {
        self.index(role).map(|i| self.roles[i].restart.state())
    }

    #[must_use]
    pub(crate) fn resources(&self, role: RoleId) -> Option<&AttemptResources> {
        self.index(role)
            .and_then(|i| self.roles[i].resources.as_ref())
    }

    pub(crate) fn reserve_attempt(
        &mut self,
        role: RoleId,
        generation: u64,
        transaction: u64,
    ) -> Result<AttemptReservation, InitError> {
        let index = role_index(role)?;
        self.accounting
            .reserve(index, role, generation, transaction)
    }

    pub(crate) fn abort_reservation(
        &mut self,
        mut reservation: AttemptReservation,
    ) -> Result<(), InitError> {
        self.accounting.release(&mut reservation)
    }

    /// Marks manifest/closure/controller initialization complete. This is the
    /// exact state acknowledged by the supervisor READY to primordial.
    pub(crate) fn become_operational(&mut self) -> Result<(), InitError> {
        if self.mode != SystemMode::Bootstrap {
            return Err(InitError::WrongActivationOrder);
        }
        self.mode = SystemMode::SupervisorOperational;
        Ok(())
    }

    pub(crate) fn begin_registry(
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

    pub(crate) fn install_attempt(
        &mut self,
        mut resources: AttemptResources,
    ) -> Result<(), InitError> {
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
        let expected_profile = match resources.role {
            RoleId::Registryd => self.registry_startup_profile,
            RoleId::Devmgr => self.devmgr_startup_profile,
            _ => return Err(InitError::UnlaunchableRole),
        };
        if resources.startup_profile != expected_profile
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

    pub(crate) fn child_started(
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

    pub(crate) fn ready(
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
        match role {
            RoleId::Registryd if !self.activated[1] => {
                if self.mode != SystemMode::ActivatingEarlyRoles
                    && self.mode != SystemMode::Degraded
                {
                    return Err(InitError::WrongActivationOrder);
                }
                match self.roles[1].restart.state() {
                    RestartState::Stopped => self.roles[1].restart.begin(
                        now,
                        generation,
                        next_transaction(transaction)?,
                    )?,
                    RestartState::PermanentFailure { .. } if self.mode == SystemMode::Degraded => {}
                    _ => return Err(InitError::WrongActivationOrder),
                }
            }
            RoleId::Registryd if self.activated[1] => self.mode = SystemMode::Normal,
            RoleId::Devmgr if self.activated[0] => self.mode = SystemMode::Normal,
            _ => {}
        }
        Ok(())
    }

    pub(crate) fn fail(
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

    /// Starts one explicitly admitted post-stability recovery episode without
    /// releasing the exact published owner's resources or accounting token.
    ///
    /// `RestartSupervisor::admit_recovery` in `wyrmroot-runtime` has always
    /// been ordinary, documented supervision. Only these two wrappers named a
    /// selector, so only they were removed at R7B-4.
    pub(crate) fn admit_recovery(
        &mut self,
        role: RoleId,
        generation: u64,
        transaction: u64,
        now: u64,
    ) -> Result<(), InitError> {
        let index = self.index(role).ok_or(InitError::UnlaunchableRole)?;
        self.roles[index].admit_recovery(&self.accounting, generation, transaction, now)
    }

    pub(crate) fn ready_wait_failed(
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

    pub(crate) fn cleanup_complete(
        &mut self,
        role: RoleId,
        generation: u64,
        transaction: u64,
        now: u64,
    ) -> Result<(), InitError> {
        let index = self.index(role).ok_or(InitError::UnlaunchableRole)?;
        let controller = &mut self.roles[index];
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
        self.update_permanent_failure(role)?;
        Ok(())
    }

    pub(crate) fn cleanup_failed(
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

    /// Retires an exact active role after its ordinary transition into
    /// `CleaningUp` failed but the caller has already attempted native owner
    /// release. Complete cleanup releases the installed accounting reservation
    /// exactly once; failed cleanup remains retained and blocks replacement.
    pub(crate) fn retire_active_fail_closed(
        &mut self,
        role: RoleId,
        generation: u64,
        transaction: u64,
        now: u64,
        failure: AttemptFailure,
        cleanup: CleanupDisposition,
    ) -> Result<(), InitError> {
        let index = self.index(role).ok_or(InitError::UnlaunchableRole)?;
        if self.roles[index].resources.is_none() {
            return Err(InitError::MissingAttemptResources);
        }
        self.roles[index].restart.retire_active_fail_closed(
            generation,
            transaction,
            now,
            failure,
            cleanup,
        )?;
        if cleanup == CleanupDisposition::Complete {
            let mut resources = self.roles[index]
                .resources
                .take()
                .ok_or(InitError::MissingAttemptResources)?;
            self.accounting.release(&mut resources.reservation)?;
        }
        self.update_permanent_failure(role)?;
        Ok(())
    }

    pub(crate) fn start_replacement(
        &mut self,
        role: RoleId,
        now: u64,
        generation: u64,
        transaction: u64,
    ) -> Result<(), InitError> {
        self.controller_mut(role)?
            .restart
            .start_replacement(now, generation, transaction)?;
        self.update_permanent_failure(role)?;
        Ok(())
    }

    pub(crate) fn fatal(&mut self) {
        self.mode = SystemMode::Fatal;
    }

    pub(crate) fn retire_attempt_after_fatal(&mut self, role: RoleId) -> Result<(), InitError> {
        let index = self.index(role).ok_or(InitError::UnlaunchableRole)?;
        if let Some(mut resources) = self.roles[index].resources.take() {
            self.accounting.release(&mut resources.reservation)?;
        }
        self.fatal();
        Ok(())
    }

    pub(crate) fn update_permanent_failure(&mut self, role: RoleId) -> Result<(), InitError> {
        if self
            .role_state(role)
            .is_some_and(|state| matches!(state, RestartState::PermanentFailure { .. }))
            && self.mode != SystemMode::Degraded
        {
            self.mode = SystemMode::Degraded;
            self.degraded_transitions = self.degraded_transitions.saturating_add(1);
        }
        Ok(())
    }

    pub(crate) fn index(&self, role: RoleId) -> Option<usize> {
        match role {
            RoleId::Registryd => Some(0),
            RoleId::Devmgr => Some(1),
            _ => None,
        }
    }
    pub(crate) fn controller_mut(
        &mut self,
        role: RoleId,
    ) -> Result<&mut RoleController, InitError> {
        let i = self.index(role).ok_or(InitError::UnlaunchableRole)?;
        Ok(&mut self.roles[i])
    }

    pub(crate) fn executable_identity(&self, role: RoleId) -> Result<[u8; 32], InitError> {
        let index = self.index(role).ok_or(InitError::UnlaunchableRole)?;
        Ok(self.roles[index].executable_identity)
    }
}

pub(crate) fn map_lookup(_: LookupError) -> InitError {
    InitError::MissingRetainedMaterial
}
