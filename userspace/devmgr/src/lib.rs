//! WYR1-C `/system/devmgr` coordinator policy.
//!
//! Historical profiles stop after validating the immutable role manifest and
//! supervisor generation. WYR1-C4 additionally admits one exact COM2
//! DeviceResource claim without constructing an Interrupt or driver bundle.

#![no_std]
#![forbid(unsafe_code)]

pub mod connector;
pub mod staging;

#[cfg(feature = "native-devmgr")]
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
    ControllerLifecycle,
    DriverLaunch(DriverLaunchError),
    ResourceIdentity,
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
            return Err(DevmgrError::ControllerLifecycle);
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

    pub const fn retired_binding(&self) -> Option<RegistryBinding> {
        self.retired_binding
    }

    pub const fn retired_driver_attempt(&self) -> Option<u64> {
        self.retired_driver_attempt
    }

    pub const fn last_transaction_id(&self) -> u64 {
        self.last_transaction_id
    }

    pub const fn bundle_generation(&self) -> Option<BundleGeneration> {
        self.bundle_generation
    }

    pub const fn driver_lease_generation(&self) -> Option<u64> {
        self.driver_lease_generation
    }

    pub const fn driver_irq_binding(&self) -> Option<u64> {
        self.driver_irq_binding
    }

    pub fn set_driver_bindings(
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

    pub const fn retry_until_ns(&self) -> Option<u64> {
        self.retry_until_ns
    }

    pub const fn driver_failures(&self) -> u8 {
        self.driver_failures
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
            return Err(DevmgrError::ControllerLifecycle);
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
        self.next_driver_attempt = self
            .next_driver_attempt
            .checked_add(1)
            .ok_or(DevmgrError::ControllerLifecycle)?;
        self.next_driver_session = self
            .next_driver_session
            .checked_add(1)
            .ok_or(DevmgrError::ControllerLifecycle)?;
        self.next_driver_endpoint = self
            .next_driver_endpoint
            .checked_add(1)
            .ok_or(DevmgrError::ControllerLifecycle)?;
        self.next_driver_transaction = self
            .next_driver_transaction
            .checked_add(1)
            .ok_or(DevmgrError::ControllerLifecycle)?;
        Ok(request)
    }

    /// C5 entry point: construction is impossible until the exact broad
    /// resource claim has been admitted for this devmgr generation.
    pub fn issue_driver_launch_with_bundle(
        &mut self,
        child_is_channel: bool,
        child_rights: DirectControlRights,
    ) -> Result<DriverLaunchRequest, DevmgrError> {
        if self.bundle_generation.is_none() || self.status.state != CoordinatorState::Matched {
            return Err(DevmgrError::ControllerLifecycle);
        }
        self.issue_driver_launch(child_is_channel, child_rights)
    }

    pub fn driver_constructed(&mut self) -> Result<(), DevmgrError> {
        self.active_driver
            .as_mut()
            .ok_or(DevmgrError::ControllerLifecycle)?
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
            return Err(DevmgrError::ControllerLifecycle);
        }
        let launch = self.active_driver.ok_or(DevmgrError::ControllerLifecycle)?;
        if launch.state() != DriverLaunchState::AwaitingControlReady {
            return Err(DevmgrError::ControllerLifecycle);
        }
        let request = launch.request();
        let bundle_generation = self
            .bundle_generation
            .ok_or(DevmgrError::ControllerLifecycle)?;
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
            return Err(DevmgrError::ControllerLifecycle);
        }
        self.active_driver
            .as_mut()
            .ok_or(DevmgrError::ControllerLifecycle)?
            .bundle_transferred()?;
        self.status.state = CoordinatorState::AwaitingDriverReady;
        Ok(())
    }

    /// Accepts only the post-bundle, generation-exact DRIVER_READY.
    pub fn accept_driver_ready(
        &mut self,
        message: wyrmroot_device_proto::ControlMessage,
    ) -> Result<(), DevmgrError> {
        if self.status.state != CoordinatorState::AwaitingDriverReady || self.driver_ready {
            return Err(DevmgrError::ControllerLifecycle);
        }
        let request = self
            .active_driver_request()
            .ok_or(DevmgrError::ControllerLifecycle)?;
        let expected = wyrmroot_device_proto::ControlMessage::Ready {
            role_id: request.role_id,
            bundle_generation: self
                .bundle_generation
                .ok_or(DevmgrError::ControllerLifecycle)?,
            attempt_generation: request.attempt_generation,
            endpoint: request.endpoint,
            transaction_id: request.transaction_id,
        };
        if message != expected {
            return Err(DevmgrError::ControllerLifecycle);
        }
        self.active_driver
            .as_mut()
            .ok_or(DevmgrError::ControllerLifecycle)?
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
            return Err(DevmgrError::ControllerLifecycle);
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
            return Err(DevmgrError::ControllerLifecycle);
        }
        let request = self
            .active_driver_request()
            .ok_or(DevmgrError::ControllerLifecycle)?;
        if request.endpoint != endpoint {
            return Err(DevmgrError::ControllerLifecycle);
        }
        self.driver_ready = false;
        self.publication_current = false;
        self.status.state = CoordinatorState::CleaningUp;
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
            return Err(DevmgrError::ControllerLifecycle);
        }
        request
            .transaction_id
            .checked_add(1)
            .ok_or(DevmgrError::ControllerLifecycle)
    }

    /// Drops only the retired registry endpoint. The D1 resource lease and
    /// failed attempt identity remain until init confirms reaping.
    pub fn publication_retired(&mut self) -> Result<(), DevmgrError> {
        if self.status.state != CoordinatorState::CleaningUp || self.active_binding.is_none() {
            return Err(DevmgrError::ControllerLifecycle);
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
            return Err(DevmgrError::ControllerLifecycle);
        }
        let request = self
            .active_driver_request()
            .ok_or(DevmgrError::ControllerLifecycle)?;
        let message = wyrmroot_device_proto::ControlMessage::Retire {
            role_id: request.role_id,
            bundle_generation: self
                .bundle_generation
                .ok_or(DevmgrError::ControllerLifecycle)?,
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
            .ok_or(DevmgrError::ControllerLifecycle)?
            .accept_control_ready(message)?;
        Ok(())
    }

    pub fn reap_driver(&mut self) -> Result<(), DevmgrError> {
        let mut launch = self
            .active_driver
            .take()
            .ok_or(DevmgrError::ControllerLifecycle)?;
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
            return Err(DevmgrError::ControllerLifecycle);
        }
        self.driver_failures = self
            .driver_failures
            .checked_add(1)
            .ok_or(DevmgrError::ControllerLifecycle)?;
        if self.driver_failures >= wyrmroot_device_proto::coordinator::MAX_ATTEMPTS {
            self.retry_until_ns = None;
            self.status.state = CoordinatorState::PermanentFailure;
            return Ok(());
        }
        self.retry_until_ns = Some(
            now_ns
                .checked_add(wyrmroot_device_proto::coordinator::RETRY_BACKOFF_NS)
                .ok_or(DevmgrError::ControllerLifecycle)?,
        );
        self.status.state = CoordinatorState::Backoff {
            attempt: AttemptGeneration(self.next_driver_attempt),
            until_ns: self.retry_until_ns.unwrap(),
        };
        Ok(())
    }

    pub fn driver_retry_ready(&mut self, now_ns: u64) -> Result<(), DevmgrError> {
        let until = self
            .retry_until_ns
            .ok_or(DevmgrError::ControllerLifecycle)?;
        if now_ns < until || !matches!(self.status.state, CoordinatorState::Backoff { .. }) {
            return Err(DevmgrError::ControllerLifecycle);
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
            ControllerMessage::Status { .. } => Err(DevmgrError::ControllerLifecycle),
        }
    }

    /// The registry-side peer can disappear without replacing this devmgr
    /// generation.  Keep the historical binding solely to enforce a monotonic
    /// replacement later; it is no longer an active publication binding.
    pub fn publication_peer_closed(&mut self) -> Result<(), DevmgrError> {
        if self.active_binding.is_none() {
            return Err(DevmgrError::ControllerLifecycle);
        }
        self.active_binding = None;
        self.publication_current = false;
        self.status.state = CoordinatorState::WaitingForRegistry;
        Ok(())
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
                    return Err(DevmgrError::ControllerLifecycle);
                }
                self.active_binding
            }
            StatusCode::CleaningUp | StatusCode::Backoff | StatusCode::PermanentFailure => {
                return Err(DevmgrError::ControllerLifecycle);
            }
        };
        if self.last_transaction_id == 0 {
            return Err(DevmgrError::ControllerLifecycle);
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
mod tests {
    use super::*;
    use wyrmroot_device_proto::manifest::{
        HEADER_BYTES, MAGIC, MAJOR, MINOR, PROFILE_Q35, PROFILE_Q35_VERSION, RECORD_BYTES,
        UART16550D_PATH,
    };

    fn manifest() -> [u8; HEADER_BYTES + RECORD_BYTES] {
        let mut bytes = [0; HEADER_BYTES + RECORD_BYTES];
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4..6].copy_from_slice(&MAJOR.to_le_bytes());
        bytes[6..8].copy_from_slice(&MINOR.to_le_bytes());
        let total = bytes.len() as u32;
        bytes[8..12].copy_from_slice(&total.to_le_bytes());
        bytes[12..14].copy_from_slice(&1u16.to_le_bytes());
        bytes[16..20].copy_from_slice(&PROFILE_Q35.0.to_le_bytes());
        bytes[20..24].copy_from_slice(&PROFILE_Q35_VERSION.0.to_le_bytes());
        let record = HEADER_BYTES;
        bytes[record..record + 8].copy_from_slice(&1u64.to_le_bytes());
        bytes[record + 8..record + 12].copy_from_slice(&2u32.to_le_bytes());
        bytes[record + 12..record + 16].copy_from_slice(&1u32.to_le_bytes());
        bytes[record + 16..record + 18].copy_from_slice(&0x2f8u16.to_le_bytes());
        bytes[record + 18..record + 20].copy_from_slice(&8u16.to_le_bytes());
        bytes[record + 20..record + 24].copy_from_slice(&3u32.to_le_bytes());
        bytes[record + 24..record + 26]
            .copy_from_slice(&(UART16550D_PATH.len() as u16).to_le_bytes());
        bytes[record + 28..record + 60].copy_from_slice(&[0x5a; 32]);
        bytes[record + 60..record + 64].copy_from_slice(&1u32.to_le_bytes());
        bytes[record + 72..record + 72 + UART16550D_PATH.len()].copy_from_slice(UART16550D_PATH);
        bytes
    }

    #[test]
    fn exact_manifest_becomes_operational_but_not_device_bound() {
        let status = prepare_operational(&manifest(), 7).unwrap();
        assert_eq!(status.supervisor_generation, SupervisorGeneration(7));
        assert_eq!(status.state, CoordinatorState::WaitingForRegistry);
        assert_eq!(
            status.pio,
            PioRange {
                base: 0x2f8,
                length: 8
            }
        );
        assert_eq!(status.irq, 3);
        assert!(!status.is_device_bound());
    }

    #[test]
    fn page_padded_manifest_becomes_operational_only_when_padding_is_zero() {
        let exact = manifest();
        let mut page = [0u8; 4096];
        page[..exact.len()].copy_from_slice(&exact);
        assert_eq!(
            prepare_operational(&page, 7).unwrap().state,
            CoordinatorState::WaitingForRegistry
        );
        page[exact.len()] = 1;
        assert_eq!(
            prepare_operational(&page, 7),
            Err(DevmgrError::Manifest(ManifestError::NonzeroObjectPadding))
        );
    }

    #[test]
    fn malformed_or_com1_manifest_never_becomes_operational() {
        let mut bytes = manifest();
        bytes[0] = b'X';
        assert_eq!(
            prepare_operational(&bytes, 1),
            Err(DevmgrError::Manifest(ManifestError::WrongMagic))
        );
        bytes = manifest();
        bytes[HEADER_BYTES + 8..HEADER_BYTES + 12].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            prepare_operational(&bytes, 1),
            Err(DevmgrError::Coordinator(CoordinatorError::Manifest(
                ManifestError::Com1Rejected
            )))
        );
    }

    #[test]
    fn zero_supervisor_generation_is_rejected() {
        assert_eq!(
            prepare_operational(&manifest(), 0),
            Err(DevmgrError::Coordinator(
                CoordinatorError::InvalidSupervisorGeneration
            ))
        );
    }

    fn binding(generation: u64, endpoint: u64) -> RegistryBinding {
        RegistryBinding {
            generation: wyrmroot_device_proto::coordinator::RegistryGeneration(generation),
            endpoint: wyrmroot_device_proto::coordinator::RegistryEndpoint {
                id: wyrmroot_device_proto::coordinator::RegistryEndpointId(endpoint),
                generation: wyrmroot_device_proto::coordinator::RegistryEndpointGeneration(1),
            },
        }
    }

    fn install(binding: RegistryBinding, transaction_id: u64) -> ControllerMessage {
        install_for(7, binding, transaction_id)
    }

    fn install_for(
        supervisor_generation: u64,
        binding: RegistryBinding,
        transaction_id: u64,
    ) -> ControllerMessage {
        ControllerMessage::InstallPublication {
            supervisor_generation: SupervisorGeneration(supervisor_generation),
            binding,
            transaction_id,
        }
    }

    fn rebind(binding: RegistryBinding, transaction_id: u64) -> ControllerMessage {
        ControllerMessage::RebindPublication {
            supervisor_generation: SupervisorGeneration(7),
            binding,
            transaction_id,
        }
    }

    fn exact_resource(lease_generation: u64) -> DwDeviceResourceInfoV1 {
        DwDeviceResourceInfoV1 {
            size: DW_DEVICE_RESOURCE_INFO_V1_SIZE,
            version: DW_DEVICE_RESOURCE_INFO_V1_VERSION,
            kind: DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT,
            flags: 0,
            resource_id: COM2_RESOURCE_ID,
            lease_generation,
            pio_base: 0x2f8,
            pio_length: 8,
            interrupt_source: 3,
            reserved: 0,
        }
    }

    #[test]
    fn controller_correlates_zero_handle_install_to_startup_then_reports_waiting() {
        let mut resident =
            ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
        let installed = binding(1, 7);
        assert_eq!(
            resident.accept(install(installed, 41), 0),
            Ok(ControllerAction::InitialPublicationBound)
        );
        assert_eq!(
            resident.status().state,
            CoordinatorState::WaitingForDeviceBundle
        );
        assert_eq!(
            resident.report(StatusCode::OperationalWaitingForDeviceBundle),
            Ok(ControllerMessage::Status {
                supervisor_generation: SupervisorGeneration(7),
                binding: Some(installed),
                transaction_id: 41,
                status: StatusCode::OperationalWaitingForDeviceBundle,
                attempt_generation: None,
            })
        );
    }

    #[test]
    fn c4_admits_exact_claimed_resource_and_uses_kernel_lease_generation() {
        let mut resident =
            ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
        let installed = binding(1, 7);
        resident.accept(install(installed, 41), 0).unwrap();
        assert_eq!(
            resident.admit_device_resource(exact_resource(19)),
            Ok(BundleGeneration(19))
        );
        assert_eq!(resident.bundle_generation(), Some(BundleGeneration(19)));
        assert_eq!(resident.status().state, CoordinatorState::Matched);
        assert!(resident.status().is_device_bound());
        assert_eq!(
            resident.report(StatusCode::OperationalResourceOwned),
            Ok(ControllerMessage::Status {
                supervisor_generation: SupervisorGeneration(7),
                binding: Some(installed),
                transaction_id: 41,
                status: StatusCode::OperationalResourceOwned,
                attempt_generation: None,
            })
        );
        assert_eq!(
            resident.admit_device_resource(exact_resource(20)),
            Err(DevmgrError::ResourceIdentity)
        );
    }

    #[test]
    fn c4_registry_rebind_preserves_the_owned_resource_without_a_second_claim() {
        let mut resident =
            ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
        let first = binding(1, 7);
        resident.accept(install(first, 41), 0).unwrap();
        resident.admit_device_resource(exact_resource(19)).unwrap();
        resident.publication_peer_closed().unwrap();

        let second = binding(1, 8);
        assert_eq!(
            resident.accept(rebind(second, 42), 1),
            Ok(ControllerAction::PublicationRebound)
        );
        assert_eq!(resident.bundle_generation(), Some(BundleGeneration(19)));
        assert_eq!(resident.status().state, CoordinatorState::Matched);
        assert_eq!(
            resident.report(StatusCode::OperationalResourceOwned),
            Ok(ControllerMessage::Status {
                supervisor_generation: SupervisorGeneration(7),
                binding: Some(second),
                transaction_id: 42,
                status: StatusCode::OperationalResourceOwned,
                attempt_generation: None,
            })
        );
        assert_eq!(
            resident.admit_device_resource(exact_resource(20)),
            Err(DevmgrError::ResourceIdentity)
        );
    }

    #[test]
    fn c4_rejects_every_mismatched_resource_identity_field() {
        let mut cases = [exact_resource(7); 10];
        cases[0].size = 47;
        cases[1].version = 2;
        cases[2].kind = deepwyrm_syscall::DwDeviceResourceKind(2);
        cases[3].flags = 1;
        cases[4].resource_id = 2;
        cases[5].lease_generation = 0;
        cases[6].pio_base = 0x3f8;
        cases[7].pio_length = 7;
        cases[8].interrupt_source = 4;
        cases[9].reserved = 1;
        for resource in cases {
            let mut resident =
                ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
            resident.accept(install(binding(1, 7), 41), 0).unwrap();
            assert_eq!(
                resident.admit_device_resource(resource),
                Err(DevmgrError::ResourceIdentity)
            );
            assert_eq!(resident.bundle_generation(), None);
            assert_eq!(
                resident.status().state,
                CoordinatorState::WaitingForDeviceBundle
            );
        }
    }

    #[test]
    fn c4_cannot_claim_before_the_exact_registry_binding() {
        let mut resident =
            ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
        assert_eq!(
            resident.admit_device_resource(exact_resource(1)),
            Err(DevmgrError::ResourceIdentity)
        );
    }

    #[test]
    fn c5_requires_claim_then_constructed_bundle_before_generation_ready_and_publish() {
        let mut resident =
            ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
        resident.accept(install(binding(1, 7), 41), 0).unwrap();
        assert_eq!(
            resident.issue_driver_launch_with_bundle(true, DirectControlRights::ExactReduced),
            Err(DevmgrError::ControllerLifecycle)
        );
        resident.admit_device_resource(exact_resource(19)).unwrap();
        let request = resident
            .issue_driver_launch_with_bundle(true, DirectControlRights::ExactReduced)
            .unwrap();
        assert_eq!(
            resident.resource_bundle_message(),
            Err(DevmgrError::ControllerLifecycle)
        );
        resident.driver_constructed().unwrap();
        let bundle = resident.resource_bundle_message().unwrap();
        assert_eq!(
            bundle,
            wyrmroot_device_proto::ControlMessage::ResourceBundle {
                role_id: request.role_id,
                bundle_generation: BundleGeneration(19),
                attempt_generation: request.attempt_generation,
                endpoint: request.endpoint,
                transaction_id: request.transaction_id,
            }
        );
        assert_eq!(resident.status().state, CoordinatorState::Matched);
        resident.bundle_transferred().unwrap();
        assert_eq!(
            resident.status().state,
            CoordinatorState::AwaitingDriverReady
        );
        assert_eq!(
            resident.accept_driver_ready(wyrmroot_device_proto::ControlMessage::Ready {
                role_id: request.role_id,
                bundle_generation: BundleGeneration(20),
                attempt_generation: request.attempt_generation,
                endpoint: request.endpoint,
                transaction_id: request.transaction_id,
            }),
            Err(DevmgrError::ControllerLifecycle)
        );
        resident
            .accept_driver_ready(wyrmroot_device_proto::ControlMessage::Ready {
                role_id: request.role_id,
                bundle_generation: BundleGeneration(19),
                attempt_generation: request.attempt_generation,
                endpoint: request.endpoint,
                transaction_id: request.transaction_id,
            })
            .unwrap();
        assert_eq!(
            resident.status().state,
            CoordinatorState::AwaitingPublication
        );
        resident.publication_committed().unwrap();
        assert_eq!(resident.status().state, CoordinatorState::Published);
        assert_eq!(
            resident.publication_committed(),
            Err(DevmgrError::ControllerLifecycle)
        );
    }

    #[test]
    fn c5_retire_is_generation_exact_and_cleanup_clears_driver_readiness() {
        let mut resident =
            ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
        resident.accept(install(binding(1, 7), 41), 0).unwrap();
        resident.admit_device_resource(exact_resource(19)).unwrap();
        let request = resident
            .issue_driver_launch_with_bundle(true, DirectControlRights::ExactReduced)
            .unwrap();
        resident.driver_constructed().unwrap();
        resident.resource_bundle_message().unwrap();
        resident.bundle_transferred().unwrap();
        resident
            .accept_driver_ready(wyrmroot_device_proto::ControlMessage::Ready {
                role_id: request.role_id,
                bundle_generation: BundleGeneration(19),
                attempt_generation: request.attempt_generation,
                endpoint: request.endpoint,
                transaction_id: request.transaction_id,
            })
            .unwrap();
        assert_eq!(
            resident.retire_message(),
            Ok(wyrmroot_device_proto::ControlMessage::Retire {
                role_id: request.role_id,
                bundle_generation: BundleGeneration(19),
                attempt_generation: request.attempt_generation,
                endpoint: request.endpoint,
                transaction_id: request.transaction_id,
            })
        );
        assert_eq!(resident.status().state, CoordinatorState::CleaningUp);
        resident.reap_driver().unwrap();
        assert!(!resident.driver_ready());
        assert_eq!(
            resident.retire_message(),
            Err(DevmgrError::ControllerLifecycle)
        );
    }

    #[test]
    fn c6_failure_rebind_preserves_cleanup_gate_before_retry() {
        let mut resident =
            ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
        resident.accept(install(binding(1, 7), 41), 0).unwrap();
        resident.admit_device_resource(exact_resource(19)).unwrap();
        let request = resident
            .issue_driver_launch_with_bundle(true, DirectControlRights::ExactReduced)
            .unwrap();
        resident.driver_constructed().unwrap();
        resident.resource_bundle_message().unwrap();
        resident.bundle_transferred().unwrap();
        resident
            .accept_driver_ready(wyrmroot_device_proto::ControlMessage::Ready {
                role_id: request.role_id,
                bundle_generation: BundleGeneration(19),
                attempt_generation: request.attempt_generation,
                endpoint: request.endpoint,
                transaction_id: request.transaction_id,
            })
            .unwrap();
        resident.publication_committed().unwrap();
        resident.driver_failed(request.endpoint).unwrap();
        let retire_transaction = resident.publication_retire_transaction(request).unwrap();
        assert_eq!(retire_transaction, request.transaction_id + 1);
        assert_ne!(retire_transaction, request.transaction_id);
        resident.publication_retired().unwrap();
        resident.reap_driver().unwrap();
        assert_eq!(
            resident.accept(rebind(binding(1, 8), 42), 1),
            Ok(ControllerAction::PublicationRebound)
        );
        assert_eq!(
            resident.report(StatusCode::OperationalWaitingForDeviceBundle),
            Ok(ControllerMessage::Status {
                supervisor_generation: SupervisorGeneration(7),
                binding: Some(binding(1, 8)),
                transaction_id: 42,
                status: StatusCode::OperationalWaitingForDeviceBundle,
                attempt_generation: None,
            })
        );
        assert_eq!(resident.status().state, CoordinatorState::CleaningUp);
        resident.complete_driver_failure_cleanup(0).unwrap();
        assert_eq!(
            resident.status().state,
            CoordinatorState::Backoff {
                attempt: AttemptGeneration(request.attempt_generation.0 + 1),
                until_ns: wyrmroot_device_proto::coordinator::RETRY_BACKOFF_NS,
            }
        );
        resident
            .driver_retry_ready(wyrmroot_device_proto::coordinator::RETRY_BACKOFF_NS)
            .unwrap();
        let next = resident
            .issue_driver_launch_with_bundle(true, DirectControlRights::ExactReduced)
            .unwrap();
        assert!(next.attempt_generation.0 > request.attempt_generation.0);
    }

    #[test]
    fn controller_rejects_wrong_install_correlation_or_handle_count() {
        let mut resident =
            ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
        assert_eq!(
            resident.accept(install(binding(1, 7), 40), 0),
            Err(DevmgrError::StartupCorrelation)
        );
        assert_eq!(
            resident.accept(install(binding(1, 7), 41), 1),
            Err(DevmgrError::Controller(
                ControllerParseError::WrongHandleCount
            ))
        );
    }

    #[test]
    fn peer_close_keeps_generation_and_requires_monotonic_one_handle_rebind() {
        let mut resident =
            ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
        let first = binding(1, 7);
        resident.accept(install(first, 41), 0).unwrap();
        resident.publication_peer_closed().unwrap();
        assert_eq!(
            resident.status().supervisor_generation,
            SupervisorGeneration(7)
        );
        assert_eq!(
            resident.status().state,
            CoordinatorState::WaitingForRegistry
        );
        assert_eq!(resident.active_binding(), None);
        assert_eq!(
            resident.report(StatusCode::OperationalWaitingForRegistry),
            Ok(ControllerMessage::Status {
                supervisor_generation: SupervisorGeneration(7),
                binding: None,
                transaction_id: 41,
                status: StatusCode::OperationalWaitingForRegistry,
                attempt_generation: None,
            })
        );
        assert_eq!(
            resident.accept(rebind(first, 42), 1),
            Err(DevmgrError::Controller(ControllerParseError::StaleBinding))
        );
        let second = binding(1, 8);
        assert_eq!(
            resident.accept(rebind(second, 42), 1),
            Ok(ControllerAction::PublicationRebound)
        );
        assert_eq!(resident.active_binding(), Some(second));
        assert_eq!(
            resident.status().supervisor_generation,
            SupervisorGeneration(7)
        );
    }

    #[test]
    fn status_and_replay_messages_cannot_drive_the_resident() {
        let mut resident =
            ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
        let first = binding(1, 7);
        resident.accept(install(first, 41), 0).unwrap();
        assert_eq!(
            resident.accept(rebind(binding(2, 8), 41), 1),
            Err(DevmgrError::StaleControllerTransaction)
        );
        assert_eq!(
            resident.accept(
                ControllerMessage::Status {
                    supervisor_generation: SupervisorGeneration(7),
                    binding: Some(first),
                    transaction_id: 42,
                    status: StatusCode::OperationalWaitingForDeviceBundle,
                    attempt_generation: None,
                },
                0,
            ),
            Err(DevmgrError::ControllerLifecycle)
        );
    }

    #[test]
    fn c3_launch_is_fresh_direct_and_ready_is_correlation_exact() {
        let mut resident =
            ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
        resident.accept(install(binding(1, 7), 41), 0).unwrap();
        let request = resident
            .issue_driver_launch(true, DirectControlRights::ExactReduced)
            .unwrap();
        assert_eq!(request.supervisor_generation, SupervisorGeneration(7));
        assert_eq!(request.role_id, RoleId(1));
        assert_eq!(
            request.attempt_generation.0,
            7 * DRIVER_CORRELATION_STRIDE + DRIVER_ATTEMPT_OFFSET
        );
        assert_ne!(request.attempt_generation.0, request.launch_session.0);
        assert_ne!(request.attempt_generation.0, request.endpoint.id.0);
        assert_ne!(request.attempt_generation.0, request.transaction_id);
        assert_ne!(request.launch_session.0, request.endpoint.id.0);
        assert_ne!(request.launch_session.0, request.transaction_id);
        assert_ne!(request.endpoint.id.0, request.transaction_id);
        resident.driver_constructed().unwrap();
        assert_eq!(
            resident.accept_driver_control_ready(
                wyrmroot_device_proto::ControlMessage::ControlReady {
                    role_id: request.role_id,
                    attempt_generation: request.attempt_generation,
                    endpoint: request.endpoint,
                    transaction_id: request.transaction_id,
                }
            ),
            Ok(())
        );
        assert!(
            resident
                .issue_driver_launch(true, DirectControlRights::ExactReduced)
                .is_err()
        );
        resident.reap_driver().unwrap();
        let replacement = resident
            .issue_driver_launch(true, DirectControlRights::ExactReduced)
            .unwrap();
        assert!(replacement.attempt_generation.0 > request.attempt_generation.0);
        assert_ne!(replacement.endpoint, request.endpoint);
    }

    #[test]
    fn selector29_u1_is_the_first_supervisor_namespaced_attempt() {
        let mut resident =
            ResidentController::new(prepare_operational(&manifest(), 1).unwrap(), 41).unwrap();
        resident
            .accept(install_for(1, binding(1, 1), 41), 0)
            .unwrap();
        let request = resident
            .issue_driver_launch(true, DirectControlRights::ExactReduced)
            .unwrap();
        assert_eq!(
            request.attempt_generation.0,
            wyrmroot_device_proto::SELECTOR29_FAILURE_ATTEMPT_GENERATION
        );
        assert!(wyrmroot_device_proto::selector29_should_fail(
            request.supervisor_generation,
            request.attempt_generation
        ));
    }

    #[test]
    fn replacement_devmgr_uses_a_supervisor_owned_monotonic_driver_namespace() {
        let mut first =
            ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
        first.accept(install_for(7, binding(1, 7), 41), 0).unwrap();
        let old = first
            .issue_driver_launch(true, DirectControlRights::ExactReduced)
            .unwrap();

        let mut replacement =
            ResidentController::new(prepare_operational(&manifest(), 8).unwrap(), 42).unwrap();
        replacement
            .accept(install_for(8, binding(2, 8), 42), 0)
            .unwrap();
        let fresh = replacement
            .issue_driver_launch(true, DirectControlRights::ExactReduced)
            .unwrap();
        assert!(fresh.attempt_generation.0 > old.attempt_generation.0);
        assert!(fresh.launch_session.0 > old.launch_session.0);
        assert!(fresh.endpoint.id.0 > old.endpoint.id.0);
        assert!(fresh.transaction_id > old.transaction_id);
        assert_ne!(fresh.attempt_generation.0, fresh.launch_session.0);
        assert_ne!(fresh.attempt_generation.0, fresh.endpoint.id.0);
        assert_ne!(fresh.attempt_generation.0, fresh.transaction_id);
        assert_ne!(fresh.launch_session.0, fresh.endpoint.id.0);
        assert_ne!(fresh.launch_session.0, fresh.transaction_id);
        assert_ne!(fresh.endpoint.id.0, fresh.transaction_id);
        replacement.driver_constructed().unwrap();
        assert_eq!(
            replacement.accept_driver_control_ready(
                wyrmroot_device_proto::ControlMessage::ControlReady {
                    role_id: old.role_id,
                    attempt_generation: old.attempt_generation,
                    endpoint: old.endpoint,
                    transaction_id: old.transaction_id,
                }
            ),
            Err(DevmgrError::DriverLaunch(DriverLaunchError::StaleEndpoint))
        );
        assert_eq!(
            replacement.accept_driver_control_ready(
                wyrmroot_device_proto::ControlMessage::ControlReady {
                    role_id: fresh.role_id,
                    attempt_generation: fresh.attempt_generation,
                    endpoint: fresh.endpoint,
                    transaction_id: fresh.transaction_id,
                }
            ),
            Ok(())
        );
    }

    #[test]
    fn c3_rejects_wrong_child_rights_and_stale_ready() {
        let mut resident =
            ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
        resident.accept(install(binding(1, 7), 41), 0).unwrap();
        assert_eq!(
            resident.issue_driver_launch(true, DirectControlRights::Other),
            Err(DevmgrError::DriverLaunch(DriverLaunchError::WrongRights))
        );
        let request = resident
            .issue_driver_launch(true, DirectControlRights::ExactReduced)
            .unwrap();
        resident.driver_constructed().unwrap();
        assert_eq!(
            resident.accept_driver_control_ready(
                wyrmroot_device_proto::ControlMessage::ControlReady {
                    role_id: request.role_id,
                    attempt_generation: request.attempt_generation,
                    endpoint: ControlEndpoint {
                        id: request.endpoint.id,
                        generation: EndpointGeneration(9)
                    },
                    transaction_id: request.transaction_id,
                }
            ),
            Err(DevmgrError::DriverLaunch(DriverLaunchError::StaleEndpoint))
        );
    }
}
