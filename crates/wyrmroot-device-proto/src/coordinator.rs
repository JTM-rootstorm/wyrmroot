//! Allocation-free host model for the WYR1-C devmgr lifecycle.

use crate::manifest::{ContentIdentity, DeviceRole, Manifest, ManifestError, RoleId};

pub const MAX_ATTEMPTS: u8 = 4;
pub const RETRY_BACKOFF_NS: u64 = 25_000_000;

macro_rules! identity {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(pub u64);
    };
}

identity!(SupervisorGeneration);
identity!(BundleGeneration);
identity!(AttemptGeneration);
identity!(LaunchSessionGeneration);
identity!(EndpointId);
identity!(EndpointGeneration);
identity!(RegistryGeneration);
identity!(RegistryEndpointId);
identity!(RegistryEndpointGeneration);
identity!(PublishedServiceGeneration);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceBundle {
    pub role_id: RoleId,
    pub generation: BundleGeneration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DriverAttempt {
    pub generation: AttemptGeneration,
    pub launch_session: LaunchSessionGeneration,
    pub endpoint: DriverEndpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DriverEndpoint {
    pub id: EndpointId,
    pub generation: EndpointGeneration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryEndpoint {
    pub id: RegistryEndpointId,
    pub generation: RegistryEndpointGeneration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryBinding {
    pub generation: RegistryGeneration,
    pub endpoint: RegistryEndpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorState {
    Starting,
    WaitingForRegistry,
    WaitingForDeviceBundle,
    Matched,
    LaunchingDriver,
    AwaitingDriverReady,
    AwaitingPublication,
    Published,
    CleaningUp,
    Backoff {
        attempt: AttemptGeneration,
        until_ns: u64,
    },
    PermanentFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorError {
    InvalidSupervisorGeneration,
    InvalidState,
    Manifest(ManifestError),
    StaleRegistry,
    InvalidRegistryIdentity,
    InvalidBundle,
    StaleBundle,
    InvalidAttempt,
    AttemptBudgetExhausted,
    StaleDriverEndpoint,
    DriverAlreadyReady,
    StalePublicationEndpoint,
    BackoffNotElapsed,
    TimeOverflow,
}

impl From<ManifestError> for CoordinatorError {
    fn from(error: ManifestError) -> Self {
        Self::Manifest(error)
    }
}

pub struct Coordinator<'a> {
    supervisor_generation: SupervisorGeneration,
    state: CoordinatorState,
    role: Option<DeviceRole<'a>>,
    bundle: Option<DeviceBundle>,
    attempt: Option<DriverAttempt>,
    attempts_started: u8,
    registry: Option<RegistryBinding>,
    publication_endpoint: Option<RegistryEndpoint>,
    published_generation: Option<PublishedServiceGeneration>,
    next_attempt: u64,
    next_session: u64,
    next_endpoint: u64,
    last_bundle_generation: u64,
}

impl<'a> Coordinator<'a> {
    pub const fn new(
        supervisor_generation: SupervisorGeneration,
    ) -> Result<Self, CoordinatorError> {
        if supervisor_generation.0 == 0 {
            return Err(CoordinatorError::InvalidSupervisorGeneration);
        }
        Ok(Self {
            supervisor_generation,
            state: CoordinatorState::Starting,
            role: None,
            bundle: None,
            attempt: None,
            attempts_started: 0,
            registry: None,
            publication_endpoint: None,
            published_generation: None,
            next_attempt: 1,
            next_session: 1,
            next_endpoint: 1,
            last_bundle_generation: 0,
        })
    }

    pub const fn state(&self) -> CoordinatorState {
        self.state
    }
    pub const fn supervisor_generation(&self) -> SupervisorGeneration {
        self.supervisor_generation
    }
    pub const fn role(&self) -> Option<DeviceRole<'a>> {
        self.role
    }
    pub const fn bundle(&self) -> Option<DeviceBundle> {
        self.bundle
    }
    pub const fn attempt(&self) -> Option<DriverAttempt> {
        self.attempt
    }
    pub const fn registry(&self) -> Option<RegistryBinding> {
        self.registry
    }
    pub const fn publication_endpoint(&self) -> Option<RegistryEndpoint> {
        self.publication_endpoint
    }
    pub const fn published_generation(&self) -> Option<PublishedServiceGeneration> {
        self.published_generation
    }
    pub const fn attempts_started(&self) -> u8 {
        self.attempts_started
    }

    pub fn intake_manifest(
        &mut self,
        manifest: Manifest<'a>,
        content: ContentIdentity,
    ) -> Result<(), CoordinatorError> {
        if self.state != CoordinatorState::Starting {
            return Err(CoordinatorError::InvalidState);
        }
        self.role = Some(manifest.match_com2(content)?);
        self.state = CoordinatorState::WaitingForRegistry;
        Ok(())
    }

    pub fn registry_ready(&mut self, binding: RegistryBinding) -> Result<(), CoordinatorError> {
        validate_registry(binding)?;
        if self.state != CoordinatorState::WaitingForRegistry {
            return Err(CoordinatorError::InvalidState);
        }
        self.registry = Some(binding);
        self.state = CoordinatorState::WaitingForDeviceBundle;
        Ok(())
    }

    /// Replace only registry-facing state.  The devmgr supervisor generation,
    /// device bundle, and current driver attempt remain independent.
    pub fn replace_registry(&mut self, binding: RegistryBinding) -> Result<(), CoordinatorError> {
        validate_registry(binding)?;
        if let Some(old) = self.registry {
            if old == binding {
                return Err(CoordinatorError::StaleRegistry);
            }
            if binding.generation == old.generation || binding.endpoint == old.endpoint {
                return Err(CoordinatorError::StaleRegistry);
            }
        }
        self.registry = Some(binding);
        self.publication_endpoint = None;
        self.published_generation = None;
        if self.state == CoordinatorState::Published {
            self.state = CoordinatorState::AwaitingPublication;
        }
        Ok(())
    }

    pub fn accept_bundle(&mut self, bundle: DeviceBundle) -> Result<(), CoordinatorError> {
        if self.state != CoordinatorState::WaitingForDeviceBundle {
            return Err(CoordinatorError::InvalidState);
        }
        if bundle.generation.0 == 0 || self.role.map(|role| role.role_id) != Some(bundle.role_id) {
            return Err(CoordinatorError::InvalidBundle);
        }
        if bundle.generation.0 <= self.last_bundle_generation {
            return Err(CoordinatorError::StaleBundle);
        }
        self.last_bundle_generation = bundle.generation.0;
        self.attempts_started = 0;
        self.bundle = Some(bundle);
        self.state = CoordinatorState::Matched;
        Ok(())
    }

    pub fn begin_launch(&mut self) -> Result<(), CoordinatorError> {
        if self.state != CoordinatorState::Matched {
            return Err(CoordinatorError::InvalidState);
        }
        if self.attempts_started >= MAX_ATTEMPTS {
            return Err(CoordinatorError::AttemptBudgetExhausted);
        }
        let generation = AttemptGeneration(self.next_attempt);
        let session = LaunchSessionGeneration(self.next_session);
        let endpoint = DriverEndpoint {
            id: EndpointId(self.next_endpoint),
            generation: EndpointGeneration(self.next_attempt),
        };
        self.next_attempt = self
            .next_attempt
            .checked_add(1)
            .ok_or(CoordinatorError::InvalidAttempt)?;
        self.next_session = self
            .next_session
            .checked_add(1)
            .ok_or(CoordinatorError::InvalidAttempt)?;
        self.next_endpoint = self
            .next_endpoint
            .checked_add(1)
            .ok_or(CoordinatorError::InvalidAttempt)?;
        self.attempts_started = self
            .attempts_started
            .checked_add(1)
            .ok_or(CoordinatorError::InvalidAttempt)?;
        self.attempt = Some(DriverAttempt {
            generation,
            launch_session: session,
            endpoint,
        });
        self.state = CoordinatorState::LaunchingDriver;
        Ok(())
    }

    pub fn launch_accepted(&mut self, endpoint: DriverEndpoint) -> Result<(), CoordinatorError> {
        if self.state != CoordinatorState::LaunchingDriver {
            return Err(CoordinatorError::InvalidState);
        }
        if self.attempt.map(|attempt| attempt.endpoint) != Some(endpoint)
            || endpoint.id.0 == 0
            || endpoint.generation.0 == 0
        {
            return Err(CoordinatorError::StaleDriverEndpoint);
        }
        self.state = CoordinatorState::AwaitingDriverReady;
        Ok(())
    }

    pub fn driver_ready(&mut self, endpoint: DriverEndpoint) -> Result<(), CoordinatorError> {
        if self.state == CoordinatorState::AwaitingPublication {
            return Err(CoordinatorError::DriverAlreadyReady);
        }
        if self.state != CoordinatorState::AwaitingDriverReady {
            return Err(CoordinatorError::InvalidState);
        }
        if self.attempt.map(|attempt| attempt.endpoint) != Some(endpoint) {
            return Err(CoordinatorError::StaleDriverEndpoint);
        }
        self.state = CoordinatorState::AwaitingPublication;
        Ok(())
    }

    pub fn publish(
        &mut self,
        endpoint: RegistryEndpoint,
        service_generation: PublishedServiceGeneration,
    ) -> Result<(), CoordinatorError> {
        if self.state != CoordinatorState::AwaitingPublication {
            return Err(CoordinatorError::InvalidState);
        }
        if service_generation.0 == 0
            || self.registry.map(|binding| binding.endpoint) != Some(endpoint)
        {
            return Err(CoordinatorError::StalePublicationEndpoint);
        }
        self.publication_endpoint = Some(endpoint);
        self.published_generation = Some(service_generation);
        self.state = CoordinatorState::Published;
        Ok(())
    }

    pub fn retire(&mut self) -> Result<(), CoordinatorError> {
        if self.state != CoordinatorState::Published
            && self.state != CoordinatorState::AwaitingPublication
        {
            return Err(CoordinatorError::InvalidState);
        }
        self.publication_endpoint = None;
        self.published_generation = None;
        self.state = CoordinatorState::CleaningUp;
        Ok(())
    }

    /// Complete an intentional retire.  The static manifest and registry stay
    /// resident, while the old bundle/driver identities are discarded.
    pub fn complete_retire_cleanup(&mut self) -> Result<(), CoordinatorError> {
        if self.state != CoordinatorState::CleaningUp {
            return Err(CoordinatorError::InvalidState);
        }
        self.bundle = None;
        self.attempt = None;
        self.state = CoordinatorState::WaitingForDeviceBundle;
        Ok(())
    }

    pub fn driver_failed(&mut self, endpoint: DriverEndpoint) -> Result<(), CoordinatorError> {
        if self.state != CoordinatorState::AwaitingDriverReady
            && self.state != CoordinatorState::AwaitingPublication
        {
            return Err(CoordinatorError::InvalidState);
        }
        if self.attempt.map(|attempt| attempt.endpoint) != Some(endpoint) {
            return Err(CoordinatorError::StaleDriverEndpoint);
        }
        self.publication_endpoint = None;
        self.published_generation = None;
        self.state = CoordinatorState::CleaningUp;
        Ok(())
    }

    pub fn complete_failure_cleanup(&mut self, now_ns: u64) -> Result<(), CoordinatorError> {
        if self.state != CoordinatorState::CleaningUp {
            return Err(CoordinatorError::InvalidState);
        }
        self.attempt = None;
        if self.attempts_started >= MAX_ATTEMPTS {
            self.state = CoordinatorState::PermanentFailure;
            return Ok(());
        }
        let until_ns = now_ns
            .checked_add(RETRY_BACKOFF_NS)
            .ok_or(CoordinatorError::TimeOverflow)?;
        let next = AttemptGeneration(self.attempts_started as u64 + 1);
        self.state = CoordinatorState::Backoff {
            attempt: next,
            until_ns,
        };
        Ok(())
    }

    pub fn backoff_elapsed(&mut self, now_ns: u64) -> Result<(), CoordinatorError> {
        let until_ns = match self.state {
            CoordinatorState::Backoff { until_ns, .. } => until_ns,
            _ => return Err(CoordinatorError::InvalidState),
        };
        if now_ns < until_ns {
            return Err(CoordinatorError::BackoffNotElapsed);
        }
        if self.bundle.is_none() {
            return Err(CoordinatorError::InvalidBundle);
        }
        self.state = CoordinatorState::Matched;
        Ok(())
    }
}

fn validate_registry(binding: RegistryBinding) -> Result<(), CoordinatorError> {
    if binding.generation.0 == 0 || binding.endpoint.id.0 == 0 || binding.endpoint.generation.0 == 0
    {
        return Err(CoordinatorError::InvalidRegistryIdentity);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{self, ContentIdentity, HEADER_BYTES, RECORD_BYTES, UART16550D_PATH};

    fn bytes() -> [u8; HEADER_BYTES + RECORD_BYTES] {
        let mut out = [0; HEADER_BYTES + RECORD_BYTES];
        out[..4].copy_from_slice(b"WRDM");
        out[4..6].copy_from_slice(&1u16.to_le_bytes());
        let total = out.len() as u32;
        out[8..12].copy_from_slice(&total.to_le_bytes());
        out[12..14].copy_from_slice(&1u16.to_le_bytes());
        out[16..20].copy_from_slice(&1u32.to_le_bytes());
        out[20..24].copy_from_slice(&1u32.to_le_bytes());
        let b = HEADER_BYTES;
        out[b..b + 8].copy_from_slice(&1u64.to_le_bytes());
        out[b + 8..b + 12].copy_from_slice(&2u32.to_le_bytes());
        out[b + 12..b + 16].copy_from_slice(&1u32.to_le_bytes());
        out[b + 16..b + 18].copy_from_slice(&0x2f8u16.to_le_bytes());
        out[b + 18..b + 20].copy_from_slice(&8u16.to_le_bytes());
        out[b + 20..b + 24].copy_from_slice(&3u32.to_le_bytes());
        out[b + 24..b + 26].copy_from_slice(&(UART16550D_PATH.len() as u16).to_le_bytes());
        out[b + 28..b + 60].copy_from_slice(&[9; 32]);
        out[b + 60..b + 64].copy_from_slice(&1u32.to_le_bytes());
        out[b + 72..b + 72 + UART16550D_PATH.len()].copy_from_slice(UART16550D_PATH);
        out
    }

    fn ready_coordinator<'a>(input: &'a [u8]) -> Coordinator<'a> {
        let parsed = manifest::Manifest::parse(input).unwrap();
        let mut c = Coordinator::new(SupervisorGeneration(10)).unwrap();
        c.intake_manifest(parsed, ContentIdentity([9; 32])).unwrap();
        c.registry_ready(RegistryBinding {
            generation: RegistryGeneration(1),
            endpoint: RegistryEndpoint {
                id: RegistryEndpointId(2),
                generation: RegistryEndpointGeneration(1),
            },
        })
        .unwrap();
        c.accept_bundle(DeviceBundle {
            role_id: RoleId(1),
            generation: BundleGeneration(1),
        })
        .unwrap();
        c.begin_launch().unwrap();
        let ep = c.attempt().unwrap().endpoint;
        c.launch_accepted(ep).unwrap();
        c.driver_ready(ep).unwrap();
        c
    }

    #[test]
    fn full_intake_publish_retire_restart() {
        let data = bytes();
        let mut c = ready_coordinator(&data);
        let reg = c.registry().unwrap().endpoint;
        c.publish(reg, PublishedServiceGeneration(1)).unwrap();
        c.retire().unwrap();
        c.complete_retire_cleanup().unwrap();
        c.accept_bundle(DeviceBundle {
            role_id: RoleId(1),
            generation: BundleGeneration(2),
        })
        .unwrap();
        c.begin_launch().unwrap();
        assert_eq!(c.attempt().unwrap().generation, AttemptGeneration(2));
    }

    #[test]
    fn stale_ready_and_registry_replacement_do_not_cross_generations() {
        let data = bytes();
        let mut c = ready_coordinator(&data);
        let old_attempt = c.attempt().unwrap();
        let old_registry = c.registry().unwrap();
        c.publish(old_registry.endpoint, PublishedServiceGeneration(1))
            .unwrap();
        c.replace_registry(RegistryBinding {
            generation: RegistryGeneration(2),
            endpoint: RegistryEndpoint {
                id: RegistryEndpointId(3),
                generation: RegistryEndpointGeneration(1),
            },
        })
        .unwrap();
        assert_eq!(c.state(), CoordinatorState::AwaitingPublication);
        assert_eq!(c.attempt(), Some(old_attempt));
        assert_eq!(c.publication_endpoint(), None);
        assert_eq!(
            c.publish(old_registry.endpoint, PublishedServiceGeneration(2)),
            Err(CoordinatorError::StalePublicationEndpoint)
        );
    }

    #[test]
    fn four_failed_attempts_reach_permanent_failure() {
        let data = bytes();
        let mut c = ready_coordinator(&data);
        for expected in 1..=4 {
            let attempt = c.attempt().unwrap().endpoint;
            c.driver_failed(attempt).unwrap();
            c.complete_failure_cleanup((expected - 1) * RETRY_BACKOFF_NS)
                .unwrap();
            if expected != 4 {
                c.backoff_elapsed(expected * RETRY_BACKOFF_NS).unwrap();
                c.begin_launch().unwrap();
                let next = c.attempt().unwrap().endpoint;
                c.launch_accepted(next).unwrap();
                c.driver_ready(next).unwrap();
            }
        }
        assert_eq!(c.state(), CoordinatorState::PermanentFailure);
    }
}
