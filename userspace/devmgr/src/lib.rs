//! WYR1-C `/system/devmgr` coordinator policy.
//!
//! Historical profiles stop after validating the immutable role manifest and
//! supervisor generation. WYR1-C4 additionally admits one exact COM2
//! DeviceResource claim without constructing an Interrupt or driver bundle.

#![no_std]
#![forbid(unsafe_code)]

pub mod connector;
pub mod role;
pub mod staging;

use {
    deepwyrm_syscall as _, wyrmroot_loader as _, wyrmroot_registry_proto as _,
    wyrmroot_runtime as _,
};

use deepwyrm_syscall::{
    DW_DEVICE_RESOURCE_INFO_V1_SIZE, DW_DEVICE_RESOURCE_INFO_V1_VERSION,
    DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT, DwDeviceResourceInfoV1,
};

use wyrmroot_device_proto::controller::{
    ControllerMessage, ControllerParseError, StatusCode, validate_binding_transition,
};
use wyrmroot_device_proto::coordinator::{
    AttemptGeneration, BundleGeneration, EndpointGeneration, EndpointId, LaunchSessionGeneration,
};
use wyrmroot_device_proto::coordinator::{
    Coordinator, CoordinatorError, CoordinatorState, RegistryBinding, SupervisorGeneration,
};
use wyrmroot_device_proto::manifest::{
    ContentIdentity, Manifest, ManifestError, MetadataPolicyId, PioRange, ProfileId,
    ProfileVersion, RoleId,
};
use wyrmroot_device_proto::{
    ControlEndpoint, DirectControlRights, DriverLaunch, DriverLaunchError, DriverLaunchRequest,
    DriverLaunchState,
};

/// Each supervisor generation owns one disjoint 32-bit driver-correlation
/// namespace. A replacement devmgr therefore cannot reset an identity below
/// the previous resident high-water mark.
const DRIVER_CORRELATION_STRIDE: u64 = 1u64 << 32;
const DRIVER_ATTEMPT_OFFSET: u64 = 1;
const DRIVER_SESSION_OFFSET: u64 = (1u64 << 30) + 1;
const DRIVER_ENDPOINT_OFFSET: u64 = (2u64 << 30) + 1;
const DRIVER_TRANSACTION_OFFSET: u64 = (3u64 << 30) + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationalStatus {
    pub supervisor_generation: SupervisorGeneration,
    pub state: CoordinatorState,
    pub profile: ProfileId,
    pub profile_version: ProfileVersion,
    pub role_id: RoleId,
    pub pio: PioRange,
    pub irq: u32,
    pub driver_identity: ContentIdentity,
    pub metadata_policy: MetadataPolicyId,
    /// The WRDM boot-disk role's driver identity, when the product has one
    /// (root `STORAGE_PLAN.md` W2).
    pub boot_disk_identity: Option<ContentIdentity>,
}

pub const COM2_RESOURCE_ID: u64 = 1;

impl OperationalStatus {
    /// C1 cannot truthfully reach any device-bound phase.
    pub const fn is_device_bound(self) -> bool {
        matches!(
            self.state,
            CoordinatorState::Matched
                | CoordinatorState::LaunchingDriver
                | CoordinatorState::AwaitingDriverReady
                | CoordinatorState::AwaitingPublication
                | CoordinatorState::Published
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevmgrError {
    Manifest(ManifestError),
    Coordinator(CoordinatorError),
    MissingRole,
    Controller(ControllerParseError),
    StartupCorrelation,
    StaleControllerTransaction,
    /// A coordinator lifecycle lookup or counter refused, naming which.
    ///
    /// This carried nothing across twenty-seven sites: a counter at its limit,
    /// an absent active driver and an absent bundle generation all arrived as
    /// one value. Run 6 of card R1 was fourteen causes arriving as one status
    /// and produced a whole gate; this was twice that, in a crate the gate
    /// never read. `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` §3.3.
    ControllerLifecycle(ControllerLifecycleFault),
    /// A coordinator state-machine precondition did not hold.
    ///
    /// Split from `ControllerLifecycle` so a refused *lookup* is at least
    /// distinguishable from a step reached in the wrong state. The individual
    /// preconditions are not yet named; they are the remaining half of this
    /// repair, and each is an explicit `return` rather than a wildcard.
    ControllerPrecondition,
    DriverLaunch(DriverLaunchError),
    ResourceIdentity,
}

/// Which coordinator lifecycle fact refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerLifecycleFault {
    /// A monotonic counter or deadline reached its limit.
    Exhausted(ControllerCounter),
    /// Coordinator state a step required was absent.
    Absent(ControllerDatum),
}

/// The counters and deadlines a coordinator step can exhaust.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerCounter {
    DriverAttempt,
    DriverSession,
    DriverEndpoint,
    DriverTransaction,
    InterruptTransaction,
    ReadyTransaction,
    NextTransaction,
    StageGeneration,
    RequestTransaction,
    DriverFailures,
    RetryDeadline,
}

/// The coordinator state a step can find absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerDatum {
    ActiveDriver,
    ActiveDriverRequest,
    BundleGeneration,
    RetryDeadline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationAcknowledgementError {
    Lifecycle(DevmgrError),
    Encoding(ControllerParseError),
}

impl From<ControllerParseError> for DevmgrError {
    fn from(error: ControllerParseError) -> Self {
        Self::Controller(error)
    }
}

impl From<ManifestError> for DevmgrError {
    fn from(error: ManifestError) -> Self {
        Self::Manifest(error)
    }
}

impl From<CoordinatorError> for DevmgrError {
    fn from(error: CoordinatorError) -> Self {
        Self::Coordinator(error)
    }
}

impl From<DriverLaunchError> for DevmgrError {
    fn from(error: DriverLaunchError) -> Self {
        Self::DriverLaunch(error)
    }
}

/// Validates the complete C1 manifest and constructs the bounded status copied
/// out before the read-only manifest mapping is released.
pub fn prepare_operational(
    manifest_bytes: &[u8],
    supervisor_generation: u64,
) -> Result<OperationalStatus, DevmgrError> {
    let manifest = Manifest::parse_padded(manifest_bytes)?;
    let candidate = manifest.get(0).ok_or(DevmgrError::MissingRole)?;
    let mut coordinator = Coordinator::new(SupervisorGeneration(supervisor_generation))?;
    coordinator.intake_manifest(manifest, candidate.content_identity)?;
    let role = coordinator.role().ok_or(DevmgrError::MissingRole)?;
    let boot_disk_identity = manifest.boot_disk()?.map(|role| role.content_identity);
    Ok(OperationalStatus {
        supervisor_generation: coordinator.supervisor_generation(),
        state: coordinator.state(),
        profile: wyrmroot_device_proto::manifest::PROFILE_Q35,
        profile_version: wyrmroot_device_proto::manifest::PROFILE_Q35_VERSION,
        role_id: role.role_id,
        pio: role.pio,
        irq: role.irq,
        driver_identity: role.content_identity,
        metadata_policy: role.metadata_policy,
        boot_disk_identity,
    })
}

/// The allocation-free resident C1 control state.  The immutable manifest is
/// checked before this is constructed; the resident state intentionally keeps
/// only copied metadata, never a mapping borrowed from startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResidentController {
    status: OperationalStatus,
    startup_transaction_id: u64,
    last_transaction_id: u64,
    last_binding: Option<RegistryBinding>,
    // Owner-issued service generation high-water mark survives retirement.
    publication_service_generation: u64,
    active_binding: Option<RegistryBinding>,
    retired_binding: Option<RegistryBinding>,
    retired_driver_attempt: Option<u64>,
    active_driver: Option<DriverLaunch>,
    bundle_generation: Option<BundleGeneration>,
    driver_ready: bool,
    publication_current: bool,
    next_driver_attempt: u64,
    next_driver_session: u64,
    next_driver_endpoint: u64,
    next_driver_transaction: u64,
    next_driver_stage_generation: u64,
    driver_failures: u8,
    retry_until_ns: Option<u64>,
    driver_lease_generation: Option<u64>,
    driver_irq_binding: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerAction {
    InitialPublicationBound,
    PublicationRebound,
}

impl ResidentController {
    pub fn new(
        status: OperationalStatus,
        startup_transaction_id: u64,
    ) -> Result<Self, DevmgrError> {
        if startup_transaction_id == 0 {
            return Err(DevmgrError::StartupCorrelation);
        }
        if status.state != CoordinatorState::WaitingForRegistry {
            return Err(DevmgrError::ControllerPrecondition);
        }
        let driver_namespace = status
            .supervisor_generation
            .0
            .checked_mul(DRIVER_CORRELATION_STRIDE)
            .ok_or(DevmgrError::StartupCorrelation)?;
        let driver_attempt = driver_namespace
            .checked_add(DRIVER_ATTEMPT_OFFSET)
            .ok_or(DevmgrError::StartupCorrelation)?;
        let driver_session = driver_namespace
            .checked_add(DRIVER_SESSION_OFFSET)
            .ok_or(DevmgrError::StartupCorrelation)?;
        let driver_endpoint = driver_namespace
            .checked_add(DRIVER_ENDPOINT_OFFSET)
            .ok_or(DevmgrError::StartupCorrelation)?;
        let driver_transaction = driver_namespace
            .checked_add(DRIVER_TRANSACTION_OFFSET)
            .ok_or(DevmgrError::StartupCorrelation)?;
        Ok(Self {
            status,
            startup_transaction_id,
            last_transaction_id: 0,
            last_binding: None,
            publication_service_generation: 0,
            active_binding: None,
            retired_binding: None,
            retired_driver_attempt: None,
            active_driver: None,
            bundle_generation: None,
            driver_ready: false,
            publication_current: false,
            next_driver_attempt: driver_attempt,
            next_driver_session: driver_session,
            next_driver_endpoint: driver_endpoint,
            next_driver_transaction: driver_transaction,
            next_driver_stage_generation: driver_attempt,
            driver_failures: 0,
            retry_until_ns: None,
            driver_lease_generation: None,
            driver_irq_binding: None,
        })
    }

    pub const fn status(&self) -> OperationalStatus {
        self.status
    }

    pub const fn active_binding(&self) -> Option<RegistryBinding> {
        self.active_binding
    }

    pub const fn publication_service_generation(&self) -> Option<u64> {
        if self.active_binding.is_some() && self.publication_service_generation != 0 {
            Some(self.publication_service_generation)
        } else {
            None
        }
    }

    pub const fn bundle_generation(&self) -> Option<BundleGeneration> {
        self.bundle_generation
    }

    pub(crate) fn set_driver_bindings(
        &mut self,
        lease_generation: u64,
        irq_binding: u64,
    ) -> Result<(), DevmgrError> {
        if lease_generation == 0
            || irq_binding == 0
            || self.bundle_generation != Some(BundleGeneration(lease_generation))
        {
            return Err(DevmgrError::ResourceIdentity);
        }
        self.driver_lease_generation = Some(lease_generation);
        self.driver_irq_binding = Some(irq_binding);
        Ok(())
    }

    pub const fn driver_ready(&self) -> bool {
        self.driver_ready
    }

    pub const fn active_driver_request(&self) -> Option<DriverLaunchRequest> {
        match self.active_driver {
            Some(launch) => Some(launch.request()),
            None => None,
        }
    }

    pub(crate) const fn retry_until_ns(&self) -> Option<u64> {
        self.retry_until_ns
    }

    /// Admits one exact queried COM2 resource for this devmgr generation.
    /// The kernel lease generation is the Wyrmroot bundle generation; no
    /// supervisor, endpoint, or driver-attempt identity may substitute for it.
    pub fn admit_device_resource(
        &mut self,
        resource: DwDeviceResourceInfoV1,
    ) -> Result<BundleGeneration, DevmgrError> {
        if self.status.state != CoordinatorState::WaitingForDeviceBundle
            || self.active_binding.is_none()
            || self.bundle_generation.is_some()
            || resource.size != DW_DEVICE_RESOURCE_INFO_V1_SIZE
            || resource.version != DW_DEVICE_RESOURCE_INFO_V1_VERSION
            || resource.kind != DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT
            || resource.flags != 0
            || resource.resource_id != COM2_RESOURCE_ID
            || resource.lease_generation == 0
            || resource.pio_base != self.status.pio.base
            || resource.pio_length != self.status.pio.length
            || resource.interrupt_source != self.status.irq
            || resource.reserved != 0
        {
            return Err(DevmgrError::ResourceIdentity);
        }
        let generation = BundleGeneration(resource.lease_generation);
        self.bundle_generation = Some(generation);
        self.status.state = CoordinatorState::Matched;
        Ok(generation)
    }

    /// Issues exactly one pre-resource C3 launch correlation.  The caller
    /// creates the Channel pair and retains its broad peer; this policy layer
    /// can represent only the reduced child endpoint that crosses init.
    pub fn issue_driver_launch(
        &mut self,
        child_is_channel: bool,
        child_rights: DirectControlRights,
    ) -> Result<DriverLaunchRequest, DevmgrError> {
        if self.active_binding.is_none() || self.active_driver.is_some() {
            return Err(DevmgrError::ControllerPrecondition);
        }
        let request = DriverLaunchRequest {
            supervisor_generation: self.status.supervisor_generation,
            role_id: self.status.role_id,
            attempt_generation: AttemptGeneration(self.next_driver_attempt),
            launch_session: LaunchSessionGeneration(self.next_driver_session),
            endpoint: ControlEndpoint {
                id: EndpointId(self.next_driver_endpoint),
                generation: EndpointGeneration(1),
            },
            transaction_id: self.next_driver_transaction,
            driver_path: wyrmroot_device_proto::DEVICE_DRIVER_PATH,
            actor_identity: self.status.driver_identity,
            child_is_channel,
            child_rights,
        };
        let launch = DriverLaunch::new(request)?;
        self.active_driver = Some(launch);
        self.next_driver_attempt =
            self.next_driver_attempt
                .checked_add(1)
                .ok_or(DevmgrError::ControllerLifecycle(
                    ControllerLifecycleFault::Exhausted(ControllerCounter::DriverAttempt),
                ))?;
        self.next_driver_session =
            self.next_driver_session
                .checked_add(1)
                .ok_or(DevmgrError::ControllerLifecycle(
                    ControllerLifecycleFault::Exhausted(ControllerCounter::DriverSession),
                ))?;
        self.next_driver_endpoint =
            self.next_driver_endpoint
                .checked_add(1)
                .ok_or(DevmgrError::ControllerLifecycle(
                    ControllerLifecycleFault::Exhausted(ControllerCounter::DriverEndpoint),
                ))?;
        self.next_driver_transaction =
            self.next_driver_transaction
                .checked_add(1)
                .ok_or(DevmgrError::ControllerLifecycle(
                    ControllerLifecycleFault::Exhausted(ControllerCounter::DriverTransaction),
                ))?;
        Ok(request)
    }

    /// Issues the boot-disk driver's launch correlation and its STAGE
    /// transaction (root `STORAGE_PLAN.md` W2). They come from the same
    /// monotonic counters as the console driver's, so init's freshness check
    /// holds across both; the console driver's attempt state is untouched.
    pub fn issue_storage_launch(&mut self) -> Result<(DriverLaunchRequest, u64), DevmgrError> {
        if self.active_binding.is_none() {
            return Err(DevmgrError::ControllerPrecondition);
        }
        let identity = self
            .status
            .boot_disk_identity
            .ok_or(DevmgrError::MissingRole)?;
        let stage_transaction =
            self.next_driver_transaction
                .checked_add(1)
                .ok_or(DevmgrError::ControllerLifecycle(
                    ControllerLifecycleFault::Exhausted(ControllerCounter::DriverTransaction),
                ))?;
        let request = DriverLaunchRequest {
            supervisor_generation: self.status.supervisor_generation,
            role_id: wyrmroot_device_proto::manifest::BOOT_DISK_ROLE_ID,
            attempt_generation: AttemptGeneration(self.next_driver_attempt),
            launch_session: LaunchSessionGeneration(self.next_driver_session),
            endpoint: ControlEndpoint {
                id: EndpointId(self.next_driver_endpoint),
                generation: EndpointGeneration(1),
            },
            transaction_id: self.next_driver_transaction,
            driver_path: wyrmroot_device_proto::BLOCK_DRIVER_PATH,
            actor_identity: identity,
            child_is_channel: true,
            child_rights: DirectControlRights::ExactReduced,
        };
        DriverLaunch::new(request)?;
        let exhausted = |counter| {
            DevmgrError::ControllerLifecycle(ControllerLifecycleFault::Exhausted(counter))
        };
        let next_attempt = self
            .next_driver_attempt
            .checked_add(1)
            .ok_or(exhausted(ControllerCounter::DriverAttempt))?;
        let next_session = self
            .next_driver_session
            .checked_add(1)
            .ok_or(exhausted(ControllerCounter::DriverSession))?;
        let next_endpoint = self
            .next_driver_endpoint
            .checked_add(1)
            .ok_or(exhausted(ControllerCounter::DriverEndpoint))?;
        let next_transaction = stage_transaction
            .checked_add(1)
            .ok_or(exhausted(ControllerCounter::DriverTransaction))?;
        self.next_driver_attempt = next_attempt;
        self.next_driver_session = next_session;
        self.next_driver_endpoint = next_endpoint;
        self.next_driver_transaction = next_transaction;
        Ok((request, stage_transaction))
    }

    /// C5 entry point: construction is impossible until the exact broad
    /// resource claim has been admitted for this devmgr generation.
    pub fn issue_driver_launch_with_bundle(
        &mut self,
        child_is_channel: bool,
        child_rights: DirectControlRights,
    ) -> Result<DriverLaunchRequest, DevmgrError> {
        if self.bundle_generation.is_none() || self.status.state != CoordinatorState::Matched {
            return Err(DevmgrError::ControllerPrecondition);
        }
        self.issue_driver_launch(child_is_channel, child_rights)
    }

    /// Reserves all D3 stage identities from resident-owned high-water marks.
    /// The returned transaction interval is consumed even if later native
    /// staging fails, so a replacement launch cannot reuse any stage identity.
    pub fn reserve_d3_stage_correlations(
        &mut self,
        request: DriverLaunchRequest,
    ) -> Result<staging::D3StageCorrelations, DevmgrError> {
        if self.active_driver_request() != Some(request) {
            return Err(DevmgrError::ControllerPrecondition);
        }
        let stage_generation = self.next_driver_stage_generation;
        let device_transaction_id = self.next_driver_transaction;
        let interrupt_transaction_id =
            device_transaction_id
                .checked_add(1)
                .ok_or(DevmgrError::ControllerLifecycle(
                    ControllerLifecycleFault::Exhausted(ControllerCounter::InterruptTransaction),
                ))?;
        let ready_transaction_id =
            interrupt_transaction_id
                .checked_add(1)
                .ok_or(DevmgrError::ControllerLifecycle(
                    ControllerLifecycleFault::Exhausted(ControllerCounter::ReadyTransaction),
                ))?;
        let next_transaction =
            ready_transaction_id
                .checked_add(1)
                .ok_or(DevmgrError::ControllerLifecycle(
                    ControllerLifecycleFault::Exhausted(ControllerCounter::NextTransaction),
                ))?;
        let next_stage_generation =
            stage_generation
                .checked_add(1)
                .ok_or(DevmgrError::ControllerLifecycle(
                    ControllerLifecycleFault::Exhausted(ControllerCounter::StageGeneration),
                ))?;
        self.next_driver_transaction = next_transaction;
        self.next_driver_stage_generation = next_stage_generation;
        Ok(staging::D3StageCorrelations {
            stage_generation: staging::StageGeneration(stage_generation),
            device_transaction_id,
            interrupt_transaction_id,
            ready_transaction_id,
        })
    }

    /// Reserves the first direct-connector attach transaction and stream
    /// generation from resident-owned high-water marks. The broker owns later
    /// checked increments for the same live driver generation.
    pub(crate) fn reserve_d3_connector_correlations(
        &mut self,
        request: DriverLaunchRequest,
    ) -> Result<(u64, u64), DevmgrError> {
        if self.active_driver_request() != Some(request) || !self.publication_current {
            return Err(DevmgrError::ControllerPrecondition);
        }
        let attach_transaction = self.next_driver_transaction;
        let stream_generation = self.next_driver_stage_generation;
        self.next_driver_transaction =
            attach_transaction
                .checked_add(1)
                .ok_or(DevmgrError::ControllerLifecycle(
                    ControllerLifecycleFault::Exhausted(ControllerCounter::DriverTransaction),
                ))?;
        self.next_driver_stage_generation =
            stream_generation
                .checked_add(1)
                .ok_or(DevmgrError::ControllerLifecycle(
                    ControllerLifecycleFault::Exhausted(ControllerCounter::StageGeneration),
                ))?;
        Ok((attach_transaction, stream_generation))
    }

    pub fn driver_constructed(&mut self) -> Result<(), DevmgrError> {
        self.active_driver
            .as_mut()
            .ok_or(DevmgrError::ControllerLifecycle(
                ControllerLifecycleFault::Absent(ControllerDatum::ActiveDriver),
            ))?
            .constructed()?;
        Ok(())
    }

    /// Binds the current resource lease to the one constructed driver attempt.
    /// Native code moves the exact two-handle bundle only after this message is
    /// produced and does not mutate this state when the Channel send fails.
    pub fn resource_bundle_message(
        &mut self,
    ) -> Result<wyrmroot_device_proto::ControlMessage, DevmgrError> {
        if self.status.state != CoordinatorState::Matched || self.driver_ready {
            return Err(DevmgrError::ControllerPrecondition);
        }
        let launch = self.active_driver.ok_or(DevmgrError::ControllerLifecycle(
            ControllerLifecycleFault::Absent(ControllerDatum::ActiveDriver),
        ))?;
        if launch.state() != DriverLaunchState::AwaitingControlReady {
            return Err(DevmgrError::ControllerPrecondition);
        }
        let request = launch.request();
        let bundle_generation = self
            .bundle_generation
            .ok_or(DevmgrError::ControllerLifecycle(
                ControllerLifecycleFault::Absent(ControllerDatum::BundleGeneration),
            ))?;
        Ok(wyrmroot_device_proto::ControlMessage::ResourceBundle {
            role_id: request.role_id,
            bundle_generation,
            attempt_generation: request.attempt_generation,
            endpoint: request.endpoint,
            transaction_id: request.transaction_id,
        })
    }

    pub fn bundle_transferred(&mut self) -> Result<(), DevmgrError> {
        if self.status.state != CoordinatorState::Matched || self.driver_ready {
            return Err(DevmgrError::ControllerPrecondition);
        }
        self.active_driver
            .as_mut()
            .ok_or(DevmgrError::ControllerLifecycle(
                ControllerLifecycleFault::Absent(ControllerDatum::ActiveDriver),
            ))?
            .bundle_transferred()?;
        self.status.state = CoordinatorState::AwaitingDriverReady;
        Ok(())
    }

    /// Accepts only the post-bundle, generation-exact DRIVER_READY.
    pub fn accept_driver_ready(
        &mut self,
        message: wyrmroot_device_proto::ControlMessage,
    ) -> Result<(), DevmgrError> {
        let request = self
            .active_driver_request()
            .ok_or(DevmgrError::ControllerLifecycle(
                ControllerLifecycleFault::Absent(ControllerDatum::ActiveDriverRequest),
            ))?;
        self.accept_driver_ready_for_transaction(message, request.transaction_id)
    }

    /// Accepts DRIVER_READY against an authority-reserved transaction. D3 uses
    /// this entry point so its READY identity remains distinct from launch and
    /// both staged MOVE transactions without changing the historical C5 path.
    pub fn accept_driver_ready_for_transaction(
        &mut self,
        message: wyrmroot_device_proto::ControlMessage,
        ready_transaction_id: u64,
    ) -> Result<(), DevmgrError> {
        if self.status.state != CoordinatorState::AwaitingDriverReady || self.driver_ready {
            return Err(DevmgrError::ControllerPrecondition);
        }
        if ready_transaction_id == 0 {
            return Err(DevmgrError::ControllerPrecondition);
        }
        let request = self
            .active_driver_request()
            .ok_or(DevmgrError::ControllerLifecycle(
                ControllerLifecycleFault::Absent(ControllerDatum::ActiveDriverRequest),
            ))?;
        let expected = wyrmroot_device_proto::ControlMessage::Ready {
            role_id: request.role_id,
            bundle_generation: self
                .bundle_generation
                .ok_or(DevmgrError::ControllerLifecycle(
                    ControllerLifecycleFault::Absent(ControllerDatum::BundleGeneration),
                ))?,
            attempt_generation: request.attempt_generation,
            endpoint: request.endpoint,
            transaction_id: ready_transaction_id,
        };
        if message != expected {
            return Err(DevmgrError::ControllerPrecondition);
        }
        self.active_driver
            .as_mut()
            .ok_or(DevmgrError::ControllerLifecycle(
                ControllerLifecycleFault::Absent(ControllerDatum::ActiveDriver),
            ))?
            .driver_ready()?;
        self.driver_ready = true;
        self.publication_current = false;
        self.status.state = CoordinatorState::AwaitingPublication;
        Ok(())
    }

    pub fn publication_committed(&mut self) -> Result<(), DevmgrError> {
        if self.status.state != CoordinatorState::AwaitingPublication
            || !self.driver_ready
            || self.active_binding.is_none()
            || self.publication_current
        {
            return Err(DevmgrError::ControllerPrecondition);
        }
        self.publication_current = true;
        self.status.state = CoordinatorState::Published;
        Ok(())
    }

    /// Records an exact failure from the active driver. Publication becomes
    /// stale immediately, while the broad D1 lease remains resident for a
    /// driver-only retry after cleanup.
    pub fn driver_failed(
        &mut self,
        endpoint: wyrmroot_device_proto::ControlEndpoint,
    ) -> Result<(), DevmgrError> {
        if !matches!(
            self.status.state,
            CoordinatorState::AwaitingDriverReady
                | CoordinatorState::AwaitingPublication
                | CoordinatorState::Published
        ) {
            return Err(DevmgrError::ControllerPrecondition);
        }
        let request = self
            .active_driver_request()
            .ok_or(DevmgrError::ControllerLifecycle(
                ControllerLifecycleFault::Absent(ControllerDatum::ActiveDriverRequest),
            ))?;
        if request.endpoint != endpoint {
            return Err(DevmgrError::ControllerPrecondition);
        }
        self.driver_ready = false;
        self.publication_current = false;
        self.status.state = CoordinatorState::CleaningUp;
        Ok(())
    }

    /// Accepts the exact terminal observation for a driver whose intentional
    /// retirement already opened cleanup. This is distinct from
    /// `driver_failed`: `retire_message` has already invalidated publication
    /// and performed the one-way transition to `CleaningUp`.
    pub fn accept_intentional_driver_terminal(
        &mut self,
        request: DriverLaunchRequest,
    ) -> Result<(), DevmgrError> {
        if self.status.state != CoordinatorState::CleaningUp
            || !self.driver_ready
            || self.publication_current
            || self.active_driver_request() != Some(request)
        {
            return Err(DevmgrError::ControllerPrecondition);
        }
        self.driver_ready = false;
        Ok(())
    }

    /// Allocates the endpoint-local registry transaction used to retire the
    /// failed driver's publication. Publish has already completed with the
    /// launch transaction, so replay protection requires a distinct identity.
    pub fn publication_retire_transaction(
        &self,
        request: DriverLaunchRequest,
    ) -> Result<u64, DevmgrError> {
        if self.status.state != CoordinatorState::CleaningUp
            || self.active_driver_request() != Some(request)
        {
            return Err(DevmgrError::ControllerPrecondition);
        }
        request
            .transaction_id
            .checked_add(1)
            .ok_or(DevmgrError::ControllerLifecycle(
                ControllerLifecycleFault::Exhausted(ControllerCounter::RequestTransaction),
            ))
    }

    /// Drops only the retired registry endpoint. The D1 resource lease and
    /// failed attempt identity remain until init confirms reaping.
    pub fn publication_retired(&mut self) -> Result<(), DevmgrError> {
        if self.status.state != CoordinatorState::CleaningUp || self.active_binding.is_none() {
            return Err(DevmgrError::ControllerPrecondition);
        }
        self.retired_binding = self.active_binding;
        self.retired_driver_attempt = self
            .active_driver_request()
            .map(|request| request.attempt_generation.0);
        self.active_binding = None;
        Ok(())
    }

    pub fn retire_message(&mut self) -> Result<wyrmroot_device_proto::ControlMessage, DevmgrError> {
        if !self.driver_ready {
            return Err(DevmgrError::ControllerPrecondition);
        }
        let request = self
            .active_driver_request()
            .ok_or(DevmgrError::ControllerLifecycle(
                ControllerLifecycleFault::Absent(ControllerDatum::ActiveDriverRequest),
            ))?;
        let message = wyrmroot_device_proto::ControlMessage::Retire {
            role_id: request.role_id,
            bundle_generation: self
                .bundle_generation
                .ok_or(DevmgrError::ControllerLifecycle(
                    ControllerLifecycleFault::Absent(ControllerDatum::BundleGeneration),
                ))?,
            attempt_generation: request.attempt_generation,
            endpoint: request.endpoint,
            transaction_id: request.transaction_id,
        };
        self.publication_current = false;
        self.status.state = CoordinatorState::CleaningUp;
        Ok(message)
    }

    pub fn accept_driver_control_ready(
        &mut self,
        message: wyrmroot_device_proto::ControlMessage,
    ) -> Result<(), DevmgrError> {
        self.active_driver
            .as_mut()
            .ok_or(DevmgrError::ControllerLifecycle(
                ControllerLifecycleFault::Absent(ControllerDatum::ActiveDriver),
            ))?
            .accept_control_ready(message)?;
        Ok(())
    }

    pub fn reap_driver(&mut self) -> Result<(), DevmgrError> {
        let mut launch = self
            .active_driver
            .take()
            .ok_or(DevmgrError::ControllerLifecycle(
                ControllerLifecycleFault::Absent(ControllerDatum::ActiveDriver),
            ))?;
        launch.reap()?;
        self.driver_ready = false;
        self.publication_current = false;
        Ok(())
    }

    /// Completes the native cleanup join and opens the bounded retry window.
    /// The fourth failure is terminal; no replacement may overlap incomplete
    /// cleanup or reuse an old driver identity.
    pub fn complete_driver_failure_cleanup(&mut self, now_ns: u64) -> Result<(), DevmgrError> {
        if self.status.state != CoordinatorState::CleaningUp {
            return Err(DevmgrError::ControllerPrecondition);
        }
        self.driver_failures =
            self.driver_failures
                .checked_add(1)
                .ok_or(DevmgrError::ControllerLifecycle(
                    ControllerLifecycleFault::Exhausted(ControllerCounter::DriverFailures),
                ))?;
        if self.driver_failures >= wyrmroot_device_proto::coordinator::MAX_ATTEMPTS {
            self.retry_until_ns = None;
            self.status.state = CoordinatorState::PermanentFailure;
            return Ok(());
        }
        self.retry_until_ns = Some(
            now_ns
                .checked_add(wyrmroot_device_proto::coordinator::RETRY_BACKOFF_NS)
                .ok_or(DevmgrError::ControllerLifecycle(
                    ControllerLifecycleFault::Exhausted(ControllerCounter::RetryDeadline),
                ))?,
        );
        self.status.state = CoordinatorState::Backoff {
            attempt: AttemptGeneration(self.next_driver_attempt),
            until_ns: self.retry_until_ns.unwrap(),
        };
        Ok(())
    }

    pub fn driver_retry_ready(&mut self, now_ns: u64) -> Result<(), DevmgrError> {
        let until = self.retry_until_ns.ok_or(DevmgrError::ControllerLifecycle(
            ControllerLifecycleFault::Absent(ControllerDatum::RetryDeadline),
        ))?;
        if now_ns < until || !matches!(self.status.state, CoordinatorState::Backoff { .. }) {
            return Err(DevmgrError::ControllerPrecondition);
        }
        self.retry_until_ns = None;
        self.status.state = CoordinatorState::Matched;
        Ok(())
    }

    /// Applies a syntactically validated WRCS controller message.  Handle
    /// count is checked here; native code separately validates the moved
    /// replacement Channel's type and exact rights before calling this.
    pub fn accept(
        &mut self,
        message: ControllerMessage,
        received_handles: u32,
    ) -> Result<ControllerAction, DevmgrError> {
        // Once an explicit service identity has been installed, a legacy
        // message cannot silently discard that namespace on replacement.
        if self.publication_service_generation != 0 {
            return Err(DevmgrError::StaleControllerTransaction);
        }
        self.accept_controller(message, received_handles)
    }

    pub fn accept_publication(
        &mut self,
        message: wyrmroot_device_proto::controller_v1_1::PublicationMessage,
        received_handles: u32,
    ) -> Result<ControllerAction, DevmgrError> {
        if message.service_generation <= self.publication_service_generation {
            return Err(DevmgrError::StaleControllerTransaction);
        }
        let action = self.accept_controller(message.controller, received_handles)?;
        self.publication_service_generation = message.service_generation;
        Ok(action)
    }

    fn accept_controller(
        &mut self,
        message: ControllerMessage,
        received_handles: u32,
    ) -> Result<ControllerAction, DevmgrError> {
        if received_handles != message.handle_count() {
            return Err(DevmgrError::Controller(
                ControllerParseError::WrongHandleCount,
            ));
        }
        match message {
            ControllerMessage::InstallPublication {
                supervisor_generation,
                binding,
                transaction_id,
            } => {
                if transaction_id != self.startup_transaction_id
                    || self.last_binding.is_some()
                    || self.status.supervisor_generation != supervisor_generation
                {
                    return Err(DevmgrError::StartupCorrelation);
                }
                let binding = validate_binding_transition(
                    self.status.supervisor_generation,
                    None,
                    ControllerMessage::InstallPublication {
                        supervisor_generation,
                        binding,
                        transaction_id,
                    },
                )?;
                self.last_transaction_id = transaction_id;
                self.last_binding = Some(binding);
                self.active_binding = Some(binding);
                self.status.state = CoordinatorState::WaitingForDeviceBundle;
                Ok(ControllerAction::InitialPublicationBound)
            }
            ControllerMessage::RebindPublication {
                supervisor_generation,
                binding,
                transaction_id,
            } => {
                let cleanup_rebind = self.status.state == CoordinatorState::CleaningUp;
                if self.status.supervisor_generation != supervisor_generation
                    || self.last_binding.is_none()
                    || self.active_binding.is_some()
                    || transaction_id <= self.last_transaction_id
                {
                    return Err(DevmgrError::StaleControllerTransaction);
                }
                let binding = validate_binding_transition(
                    self.status.supervisor_generation,
                    self.last_binding,
                    ControllerMessage::RebindPublication {
                        supervisor_generation,
                        binding,
                        transaction_id,
                    },
                )?;
                self.last_transaction_id = transaction_id;
                self.last_binding = Some(binding);
                self.active_binding = Some(binding);
                self.status.state = if cleanup_rebind {
                    CoordinatorState::CleaningUp
                } else if self.driver_ready {
                    CoordinatorState::AwaitingPublication
                } else if self.bundle_generation.is_some() {
                    CoordinatorState::Matched
                } else {
                    CoordinatorState::WaitingForDeviceBundle
                };
                Ok(ControllerAction::PublicationRebound)
            }
            ControllerMessage::Status { .. } => Err(DevmgrError::ControllerPrecondition),
        }
    }

    /// The registry-side peer can disappear without replacing this devmgr
    /// generation.  Keep the historical binding solely to enforce a monotonic
    /// replacement later; it is no longer an active publication binding.
    pub fn publication_peer_closed(&mut self) -> Result<(), DevmgrError> {
        if self.active_binding.is_none() {
            return Err(DevmgrError::ControllerPrecondition);
        }
        self.active_binding = None;
        self.publication_current = false;
        self.status.state = CoordinatorState::WaitingForRegistry;
        Ok(())
    }

    /// Acknowledges an installed publication binding without claiming that
    /// the driver has published through it. Retained custody and a reaped
    /// driver awaiting a replacement bundle are distinct postconditions.
    pub fn publication_acknowledgement(
        &self,
    ) -> Result<
        [u8; wyrmroot_device_proto::controller::STATUS_BYTES],
        PublicationAcknowledgementError,
    > {
        // A precondition, not a refused lookup: no active binding, or the
        // publication is already current.
        let invalid =
            PublicationAcknowledgementError::Lifecycle(DevmgrError::ControllerPrecondition);
        if self.active_binding.is_none() || self.publication_current {
            return Err(invalid);
        }
        let status = match self.status.state {
            CoordinatorState::CleaningUp if self.active_driver.is_none() && !self.driver_ready => {
                StatusCode::OperationalWaitingForDeviceBundle
            }
            CoordinatorState::Matched | CoordinatorState::AwaitingPublication
                if self.bundle_generation.is_some() =>
            {
                StatusCode::OperationalResourceOwned
            }
            CoordinatorState::WaitingForDeviceBundle if self.bundle_generation.is_none() => {
                StatusCode::OperationalWaitingForDeviceBundle
            }
            _ => return Err(invalid),
        };
        let message = self
            .report(status)
            .map_err(PublicationAcknowledgementError::Lifecycle)?;
        let mut bytes = [0; wyrmroot_device_proto::controller::STATUS_BYTES];
        wyrmroot_device_proto::controller::encode(message, &mut bytes)
            .map_err(PublicationAcknowledgementError::Encoding)?;
        Ok(bytes)
    }

    pub fn report(&self, status: StatusCode) -> Result<ControllerMessage, DevmgrError> {
        if status.is_device_bound() {
            return Err(DevmgrError::Controller(
                ControllerParseError::DeviceBoundStatus,
            ));
        }
        let binding = match status {
            StatusCode::OperationalWaitingForRegistry => None,
            StatusCode::OperationalWaitingForDeviceBundle => self.active_binding,
            StatusCode::OperationalResourceOwned => {
                if self.bundle_generation.is_none() {
                    return Err(DevmgrError::ControllerPrecondition);
                }
                self.active_binding
            }
            StatusCode::CleaningUp | StatusCode::Backoff | StatusCode::PermanentFailure => {
                return Err(DevmgrError::ControllerPrecondition);
            }
        };
        if self.last_transaction_id == 0 {
            return Err(DevmgrError::ControllerPrecondition);
        }
        Ok(ControllerMessage::Status {
            supervisor_generation: self.status.supervisor_generation,
            binding,
            transaction_id: self.last_transaction_id,
            status,
            attempt_generation: None,
        })
    }
}

#[cfg(test)]
mod tests;
