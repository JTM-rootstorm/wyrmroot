//! C3's private, pre-resource devmgr-to-init driver construction contract.
//!
//! This is intentionally not WYR1-B's public job protocol.  It records only
//! the child direct-control endpoint and the correlations which make a launch
//! attempt unique.  A future DeviceResource bundle is absent by construction.

use crate::{
    control::{ControlEndpoint, ControlMessage},
    coordinator::{
        AttemptGeneration, EndpointGeneration, EndpointId, LaunchSessionGeneration,
        SupervisorGeneration,
    },
    manifest::{ContentIdentity, RoleId, UART16550D_PATH},
};

pub const DEVICE_DRIVER_PATH: &str = "/system/uart16550d";
pub const LAUNCH_REQUEST_BYTES: usize = 128;
pub const LAUNCH_REQUEST_HANDLE_COUNT: u32 = 1;
pub const LAUNCH_RESPONSE_BYTES: usize = 80;

/// Semantic witness supplied by the loader/native boundary, where generated
/// ABI rights are available. This policy crate intentionally does not copy
/// syscall bit values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectControlRights {
    ExactReduced,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DriverLaunchRequest {
    pub supervisor_generation: SupervisorGeneration,
    pub role_id: RoleId,
    pub attempt_generation: AttemptGeneration,
    pub launch_session: LaunchSessionGeneration,
    pub endpoint: ControlEndpoint,
    pub transaction_id: u64,
    pub driver_path: &'static str,
    pub actor_identity: ContentIdentity,
    pub child_is_channel: bool,
    pub child_rights: DirectControlRights,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverLaunchState {
    Constructed,
    AwaitingControlReady,
    ControlReady,
    Reaped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverLaunchError {
    ZeroIdentity,
    WrongPath,
    WrongChannel,
    WrongRights,
    WrongMessage,
    StaleEndpoint,
    Replay,
    AlreadyReaped,
    SupervisorReplaced,
}

/// Init acknowledges only successful construction.  The response carries no
/// handles and cannot stand in for the driver's direct `ControlReady`.
pub fn encode_constructed(
    request: DriverLaunchRequest,
    output: &mut [u8],
) -> Result<(), DriverLaunchError> {
    let _ = DriverLaunch::new(request)?;
    if output.len() != LAUNCH_RESPONSE_BYTES {
        return Err(DriverLaunchError::WrongMessage);
    }
    output.fill(0);
    output[..4].copy_from_slice(b"WRLA");
    output[4..6].copy_from_slice(&1u16.to_le_bytes());
    output[8..12].copy_from_slice(&1u32.to_le_bytes());
    output[16..20].copy_from_slice(&(LAUNCH_RESPONSE_BYTES as u32).to_le_bytes());
    for (offset, value) in [
        (24, request.supervisor_generation.0),
        (32, request.role_id.0),
        (40, request.attempt_generation.0),
        (48, request.launch_session.0),
        (56, request.endpoint.id.0),
        (64, request.endpoint.generation.0),
        (72, request.transaction_id),
    ] {
        output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    Ok(())
}

pub fn parse_constructed(
    bytes: &[u8],
    request: DriverLaunchRequest,
) -> Result<(), DriverLaunchError> {
    if bytes.len() != LAUNCH_RESPONSE_BYTES
        || bytes[..4] != *b"WRLA"
        || u16::from_le_bytes(bytes[4..6].try_into().unwrap()) != 1
        || u16::from_le_bytes(bytes[6..8].try_into().unwrap()) != 0
        || u32::from_le_bytes(bytes[8..12].try_into().unwrap()) != 1
        || u32::from_le_bytes(bytes[12..16].try_into().unwrap()) != 0
        || u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize != LAUNCH_RESPONSE_BYTES
        || bytes[20..24].iter().any(|byte| *byte != 0)
    {
        return Err(DriverLaunchError::WrongMessage);
    }
    let get = |offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
    if [
        get(24),
        get(32),
        get(40),
        get(48),
        get(56),
        get(64),
        get(72),
    ] != [
        request.supervisor_generation.0,
        request.role_id.0,
        request.attempt_generation.0,
        request.launch_session.0,
        request.endpoint.id.0,
        request.endpoint.generation.0,
        request.transaction_id,
    ] {
        return Err(DriverLaunchError::StaleEndpoint);
    }
    Ok(())
}

/// Fixed private devmgr-to-init request. The moved handle is the child half of
/// the fresh direct pair; it is deliberately the sole transferred object.
pub fn encode_request(
    request: DriverLaunchRequest,
    output: &mut [u8],
) -> Result<(), DriverLaunchError> {
    let _ = DriverLaunch::new(request)?;
    if output.len() != LAUNCH_REQUEST_BYTES {
        return Err(DriverLaunchError::WrongMessage);
    }
    output.fill(0);
    output[..4].copy_from_slice(b"WRDL");
    output[4..6].copy_from_slice(&1u16.to_le_bytes());
    output[8..12].copy_from_slice(&1u32.to_le_bytes());
    output[16..20].copy_from_slice(&(LAUNCH_REQUEST_BYTES as u32).to_le_bytes());
    output[20..24].copy_from_slice(&LAUNCH_REQUEST_HANDLE_COUNT.to_le_bytes());
    for (offset, value) in [
        (24, request.supervisor_generation.0),
        (32, request.role_id.0),
        (40, request.attempt_generation.0),
        (48, request.launch_session.0),
        (56, request.endpoint.id.0),
        (64, request.endpoint.generation.0),
        (72, request.transaction_id),
    ] {
        output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    output[80..112].copy_from_slice(&request.actor_identity.0);
    Ok(())
}

pub fn parse_request(bytes: &[u8]) -> Result<DriverLaunchRequest, DriverLaunchError> {
    if bytes.len() != LAUNCH_REQUEST_BYTES
        || bytes[..4] != *b"WRDL"
        || u16::from_le_bytes(bytes[4..6].try_into().unwrap()) != 1
        || u16::from_le_bytes(bytes[6..8].try_into().unwrap()) != 0
        || u32::from_le_bytes(bytes[8..12].try_into().unwrap()) != 1
        || u32::from_le_bytes(bytes[12..16].try_into().unwrap()) != 0
        || u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize != LAUNCH_REQUEST_BYTES
        || u32::from_le_bytes(bytes[20..24].try_into().unwrap()) != LAUNCH_REQUEST_HANDLE_COUNT
        || bytes[112..].iter().any(|byte| *byte != 0)
    {
        return Err(DriverLaunchError::WrongMessage);
    }
    let get = |offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
    let mut identity = [0; 32];
    identity.copy_from_slice(&bytes[80..112]);
    let request = DriverLaunchRequest {
        supervisor_generation: SupervisorGeneration(get(24)),
        role_id: RoleId(get(32)),
        attempt_generation: AttemptGeneration(get(40)),
        launch_session: LaunchSessionGeneration(get(48)),
        endpoint: ControlEndpoint {
            id: EndpointId(get(56)),
            generation: EndpointGeneration(get(64)),
        },
        transaction_id: get(72),
        driver_path: DEVICE_DRIVER_PATH,
        actor_identity: ContentIdentity(identity),
        child_is_channel: true,
        child_rights: DirectControlRights::ExactReduced,
    };
    let _ = DriverLaunch::new(request)?;
    Ok(request)
}

/// Allocation-free ownership model for exactly one C3 attempt.  It documents
/// the boundary at which init may construct/reap a child without ever holding
/// a future bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DriverLaunch {
    request: DriverLaunchRequest,
    state: DriverLaunchState,
}

impl DriverLaunch {
    pub fn new(request: DriverLaunchRequest) -> Result<Self, DriverLaunchError> {
        if request.supervisor_generation.0 == 0
            || request.role_id.0 == 0
            || request.attempt_generation.0 == 0
            || request.launch_session.0 == 0
            || request.endpoint.id.0 == 0
            || request.endpoint.generation.0 == 0
            || request.transaction_id == 0
            || request.actor_identity.0 == [0; 32]
        {
            return Err(DriverLaunchError::ZeroIdentity);
        }
        if request.driver_path != DEVICE_DRIVER_PATH || UART16550D_PATH != b"system/uart16550d" {
            return Err(DriverLaunchError::WrongPath);
        }
        if !request.child_is_channel {
            return Err(DriverLaunchError::WrongChannel);
        }
        if request.child_rights != DirectControlRights::ExactReduced {
            return Err(DriverLaunchError::WrongRights);
        }
        Ok(Self {
            request,
            state: DriverLaunchState::Constructed,
        })
    }

    pub fn constructed(&mut self) -> Result<(), DriverLaunchError> {
        if self.state != DriverLaunchState::Constructed {
            return Err(DriverLaunchError::Replay);
        }
        self.state = DriverLaunchState::AwaitingControlReady;
        Ok(())
    }

    pub const fn request(&self) -> DriverLaunchRequest {
        self.request
    }
    pub const fn state(&self) -> DriverLaunchState {
        self.state
    }

    pub fn accept_control_ready(
        &mut self,
        message: ControlMessage,
    ) -> Result<(), DriverLaunchError> {
        if self.state == DriverLaunchState::Reaped {
            return Err(DriverLaunchError::AlreadyReaped);
        }
        if self.state != DriverLaunchState::AwaitingControlReady {
            return Err(DriverLaunchError::Replay);
        }
        let ControlMessage::ControlReady {
            role_id,
            attempt_generation,
            endpoint,
            transaction_id,
        } = message
        else {
            return Err(DriverLaunchError::WrongMessage);
        };
        if role_id != self.request.role_id
            || attempt_generation != self.request.attempt_generation
            || endpoint != self.request.endpoint
            || transaction_id != self.request.transaction_id
        {
            return Err(DriverLaunchError::StaleEndpoint);
        }
        self.state = DriverLaunchState::ControlReady;
        Ok(())
    }

    /// Terminal child exit is reaped by init.  As no bundle exists in this
    /// model, this transition cannot transfer or lose future hardware state.
    pub fn reap(&mut self) -> Result<(), DriverLaunchError> {
        if self.state == DriverLaunchState::Reaped {
            return Err(DriverLaunchError::AlreadyReaped);
        }
        self.state = DriverLaunchState::Reaped;
        Ok(())
    }

    /// A supervisor or launch-session replacement invalidates the old direct
    /// endpoint before any replacement attempt can be constructed.
    pub fn invalidate_for_replacement(
        &mut self,
        supervisor_generation: SupervisorGeneration,
        launch_session: LaunchSessionGeneration,
    ) -> Result<(), DriverLaunchError> {
        if supervisor_generation.0 == 0 || launch_session.0 == 0 {
            return Err(DriverLaunchError::ZeroIdentity);
        }
        if supervisor_generation == self.request.supervisor_generation
            && launch_session == self.request.launch_session
        {
            return Err(DriverLaunchError::Replay);
        }
        self.state = DriverLaunchState::Reaped;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> DriverLaunchRequest {
        DriverLaunchRequest {
            supervisor_generation: SupervisorGeneration(1),
            role_id: RoleId(2),
            attempt_generation: AttemptGeneration(3),
            launch_session: LaunchSessionGeneration(4),
            endpoint: ControlEndpoint {
                id: EndpointId(5),
                generation: EndpointGeneration(6),
            },
            transaction_id: 7,
            driver_path: DEVICE_DRIVER_PATH,
            actor_identity: ContentIdentity([8; 32]),
            child_is_channel: true,
            child_rights: DirectControlRights::ExactReduced,
        }
    }
    fn ready() -> ControlMessage {
        ControlMessage::ControlReady {
            role_id: RoleId(2),
            attempt_generation: AttemptGeneration(3),
            endpoint: ControlEndpoint {
                id: EndpointId(5),
                generation: EndpointGeneration(6),
            },
            transaction_id: 7,
        }
    }
    #[test]
    fn accepts_only_current_direct_pre_resource_ready() {
        let mut launch = DriverLaunch::new(request()).unwrap();
        launch.constructed().unwrap();
        launch.accept_control_ready(ready()).unwrap();
        assert_eq!(launch.state(), DriverLaunchState::ControlReady);
        assert_eq!(
            launch.accept_control_ready(ready()),
            Err(DriverLaunchError::Replay)
        );
    }
    #[test]
    fn rejects_profile_endpoint_and_rights_confusion() {
        let mut wrong = request();
        wrong.driver_path = "system/uart16550d";
        assert_eq!(DriverLaunch::new(wrong), Err(DriverLaunchError::WrongPath));
        let mut wrong = request();
        wrong.child_rights = DirectControlRights::Other;
        assert_eq!(
            DriverLaunch::new(wrong),
            Err(DriverLaunchError::WrongRights)
        );
        let mut launch = DriverLaunch::new(request()).unwrap();
        launch.constructed().unwrap();
        let ControlMessage::ControlReady {
            role_id,
            attempt_generation,
            mut endpoint,
            transaction_id,
        } = ready()
        else {
            unreachable!()
        };
        endpoint.generation = EndpointGeneration(9);
        assert_eq!(
            launch.accept_control_ready(ControlMessage::ControlReady {
                role_id,
                attempt_generation,
                endpoint,
                transaction_id
            }),
            Err(DriverLaunchError::StaleEndpoint)
        );
    }
    #[test]
    fn pre_resource_exit_reaps_without_a_bundle() {
        let mut launch = DriverLaunch::new(request()).unwrap();
        launch.constructed().unwrap();
        launch.reap().unwrap();
        assert_eq!(launch.state(), DriverLaunchState::Reaped);
    }
    #[test]
    fn supervisor_or_session_replacement_invalidates_the_old_endpoint() {
        let mut launch = DriverLaunch::new(request()).unwrap();
        launch.constructed().unwrap();
        launch
            .invalidate_for_replacement(SupervisorGeneration(9), LaunchSessionGeneration(4))
            .unwrap();
        assert_eq!(
            launch.accept_control_ready(ready()),
            Err(DriverLaunchError::AlreadyReaped)
        );
    }
    #[test]
    fn request_is_fixed_and_binds_all_c3_correlations() {
        let request = request();
        let mut bytes = [0; LAUNCH_REQUEST_BYTES];
        encode_request(request, &mut bytes).unwrap();
        let parsed = parse_request(&bytes).unwrap();
        assert_eq!(parsed.supervisor_generation, request.supervisor_generation);
        assert_eq!(parsed.launch_session, request.launch_session);
        assert_eq!(parsed.endpoint, request.endpoint);
        bytes[20] = 0;
        assert_eq!(parse_request(&bytes), Err(DriverLaunchError::WrongMessage));
    }
    #[test]
    fn construction_ack_is_not_direct_ready_and_is_correlation_exact() {
        let mut bytes = [0; LAUNCH_RESPONSE_BYTES];
        encode_constructed(request(), &mut bytes).unwrap();
        assert_eq!(parse_constructed(&bytes, request()), Ok(()));
        bytes[72] ^= 1;
        assert_eq!(
            parse_constructed(&bytes, request()),
            Err(DriverLaunchError::StaleEndpoint)
        );
    }
}
