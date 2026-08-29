//! WRCS v1 supervisor/controller relationship for the C1 coordinator.
//!
//! The controller installs the registry publication endpoint before any
//! device resource exists.  Messages carry correlation only; the endpoint
//! itself is transferred separately by the native Channel.  The status
//! vocabulary contains waiting/operational outcomes only, so this codec
//! cannot encode a device-bound success claim.

use crate::coordinator::{
    AttemptGeneration, RegistryBinding, RegistryEndpoint, RegistryEndpointGeneration,
    RegistryEndpointId, RegistryGeneration, SupervisorGeneration,
};

pub const MAGIC: [u8; 4] = *b"WRCS";
pub const MAJOR: u16 = 1;
pub const MINOR: u16 = 0;
pub const HEADER_BYTES: usize = 72;
pub const INSTALL_BYTES: usize = HEADER_BYTES;
pub const STATUS_BYTES: usize = HEADER_BYTES + 16;
/// Initial activation binds the publication endpoint already transferred by
/// WRLP 1.5; its controller message carries no additional handle.
pub const INSTALL_HANDLE_COUNT: u32 = 0;
/// A rebind transfers exactly one fresh replacement publication endpoint.
pub const REBIND_HANDLE_COUNT: u32 = 1;
pub const STATUS_HANDLE_COUNT: u32 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum MessageType {
    InstallPublication = 1,
    RebindPublication = 2,
    Status = 3,
}

impl MessageType {
    fn parse(value: u32) -> Result<Self, ControllerParseError> {
        match value {
            1 => Ok(Self::InstallPublication),
            2 => Ok(Self::RebindPublication),
            3 => Ok(Self::Status),
            _ => Err(ControllerParseError::UnknownMessage),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum StatusCode {
    OperationalWaitingForRegistry = 1,
    OperationalWaitingForDeviceBundle = 2,
    CleaningUp = 3,
    Backoff = 4,
    PermanentFailure = 5,
}

impl StatusCode {
    fn parse(value: u32) -> Result<Self, ControllerParseError> {
        match value {
            1 => Ok(Self::OperationalWaitingForRegistry),
            2 => Ok(Self::OperationalWaitingForDeviceBundle),
            3 => Ok(Self::CleaningUp),
            4 => Ok(Self::Backoff),
            5 => Ok(Self::PermanentFailure),
            _ => Err(ControllerParseError::DeviceBoundStatus),
        }
    }

    /// C1 status never claims a matched, ready, or published device.
    pub const fn is_device_bound(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerMessage {
    InstallPublication {
        supervisor_generation: SupervisorGeneration,
        binding: RegistryBinding,
        transaction_id: u64,
    },
    RebindPublication {
        supervisor_generation: SupervisorGeneration,
        binding: RegistryBinding,
        transaction_id: u64,
    },
    Status {
        supervisor_generation: SupervisorGeneration,
        binding: Option<RegistryBinding>,
        transaction_id: u64,
        status: StatusCode,
        attempt_generation: Option<AttemptGeneration>,
    },
}

impl ControllerMessage {
    pub const fn message_type(self) -> MessageType {
        match self {
            Self::InstallPublication { .. } => MessageType::InstallPublication,
            Self::RebindPublication { .. } => MessageType::RebindPublication,
            Self::Status { .. } => MessageType::Status,
        }
    }

    pub const fn wire_size(self) -> usize {
        match self {
            Self::Status { .. } => STATUS_BYTES,
            Self::InstallPublication { .. } | Self::RebindPublication { .. } => INSTALL_BYTES,
        }
    }

    pub const fn handle_count(self) -> u32 {
        match self {
            Self::InstallPublication { .. } => INSTALL_HANDLE_COUNT,
            Self::RebindPublication { .. } => REBIND_HANDLE_COUNT,
            Self::Status { .. } => STATUS_HANDLE_COUNT,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerParseError {
    WrongSize,
    WrongMagic,
    WrongVersion,
    UnknownMessage,
    NonzeroFlags,
    WrongHandleCount,
    ZeroIdentity,
    NonzeroReserved,
    StaleBinding,
    DeviceBoundStatus,
    MissingAttempt,
}

pub fn encode(message: ControllerMessage, output: &mut [u8]) -> Result<(), ControllerParseError> {
    if output.len() != message.wire_size() {
        return Err(ControllerParseError::WrongSize);
    }
    validate_message(message)?;
    output.fill(0);
    output[..4].copy_from_slice(&MAGIC);
    put16(output, 4, MAJOR);
    put16(output, 6, MINOR);
    put32(output, 8, message.message_type() as u32);
    put32(output, 16, output.len() as u32);
    put32(output, 20, message.handle_count());
    put64(output, 24, supervisor_generation(message).0);
    if let Some(binding) = binding(message) {
        put64(output, 32, binding.generation.0);
        put64(output, 40, binding.endpoint.id.0);
        put64(output, 48, binding.endpoint.generation.0);
    }
    put64(output, 56, transaction_id(message));
    match message {
        ControllerMessage::Status {
            status,
            attempt_generation,
            ..
        } => {
            put32(output, HEADER_BYTES, status as u32);
            put64(
                output,
                HEADER_BYTES + 8,
                attempt_generation.map_or(0, |v| v.0),
            );
        }
        ControllerMessage::InstallPublication { .. }
        | ControllerMessage::RebindPublication { .. } => {}
    }
    Ok(())
}

pub fn parse(bytes: &[u8]) -> Result<ControllerMessage, ControllerParseError> {
    if bytes.len() < HEADER_BYTES {
        return Err(ControllerParseError::WrongSize);
    }
    if bytes[..4] != MAGIC {
        return Err(ControllerParseError::WrongMagic);
    }
    if get16(bytes, 4) != MAJOR || get16(bytes, 6) != MINOR {
        return Err(ControllerParseError::WrongVersion);
    }
    if get32(bytes, 12) != 0 {
        return Err(ControllerParseError::NonzeroFlags);
    }
    let message_type = MessageType::parse(get32(bytes, 8))?;
    let expected_size = match message_type {
        MessageType::Status => STATUS_BYTES,
        MessageType::InstallPublication | MessageType::RebindPublication => INSTALL_BYTES,
    };
    if bytes.len() != expected_size || get32(bytes, 16) as usize != expected_size {
        return Err(ControllerParseError::WrongSize);
    }
    let expected_handles = match message_type {
        MessageType::Status => STATUS_HANDLE_COUNT,
        MessageType::InstallPublication => INSTALL_HANDLE_COUNT,
        MessageType::RebindPublication => REBIND_HANDLE_COUNT,
    };
    if get32(bytes, 20) != expected_handles {
        return Err(ControllerParseError::WrongHandleCount);
    }
    if get64(bytes, 64) != 0 {
        return Err(ControllerParseError::NonzeroReserved);
    }
    let supervisor_generation = SupervisorGeneration(get64(bytes, 24));
    let binding = binding_from_bytes(bytes)?;
    let transaction_id = get64(bytes, 56);
    if supervisor_generation.0 == 0 || transaction_id == 0 {
        return Err(ControllerParseError::ZeroIdentity);
    }
    let message = match message_type {
        MessageType::InstallPublication => ControllerMessage::InstallPublication {
            supervisor_generation,
            binding: binding.ok_or(ControllerParseError::ZeroIdentity)?,
            transaction_id,
        },
        MessageType::RebindPublication => ControllerMessage::RebindPublication {
            supervisor_generation,
            binding: binding.ok_or(ControllerParseError::ZeroIdentity)?,
            transaction_id,
        },
        MessageType::Status => {
            if get32(bytes, HEADER_BYTES + 4) != 0 {
                return Err(ControllerParseError::NonzeroReserved);
            }
            let status = StatusCode::parse(get32(bytes, HEADER_BYTES))?;
            let raw_attempt = get64(bytes, HEADER_BYTES + 8);
            let attempt_generation = if raw_attempt == 0 {
                None
            } else {
                Some(AttemptGeneration(raw_attempt))
            };
            if matches!(
                status,
                StatusCode::OperationalWaitingForDeviceBundle
                    | StatusCode::CleaningUp
                    | StatusCode::Backoff
                    | StatusCode::PermanentFailure
            ) && binding.is_none()
            {
                return Err(ControllerParseError::StaleBinding);
            }
            if matches!(status, StatusCode::Backoff) && attempt_generation.is_none() {
                return Err(ControllerParseError::MissingAttempt);
            }
            ControllerMessage::Status {
                supervisor_generation,
                binding,
                transaction_id,
                status,
                attempt_generation,
            }
        }
    };
    validate_message(message)?;
    Ok(message)
}

/// Validate a monotonic publication install/rebind against the current
/// supervisor generation.  A replacement changes only registry-facing state;
/// it cannot reset or replace the devmgr supervisor generation.
pub fn validate_binding_transition(
    supervisor_generation: SupervisorGeneration,
    current: Option<RegistryBinding>,
    incoming: ControllerMessage,
) -> Result<RegistryBinding, ControllerParseError> {
    let (generation, binding) = match incoming {
        ControllerMessage::InstallPublication {
            supervisor_generation: incoming_supervisor,
            binding,
            ..
        }
        | ControllerMessage::RebindPublication {
            supervisor_generation: incoming_supervisor,
            binding,
            ..
        } => (incoming_supervisor, binding),
        ControllerMessage::Status { .. } => return Err(ControllerParseError::StaleBinding),
    };
    if generation != supervisor_generation {
        return Err(ControllerParseError::StaleBinding);
    }
    match incoming {
        ControllerMessage::InstallPublication { .. } if current.is_some() => {
            return Err(ControllerParseError::StaleBinding);
        }
        ControllerMessage::RebindPublication { .. } if current.is_none() => {
            return Err(ControllerParseError::StaleBinding);
        }
        ControllerMessage::Status { .. } => return Err(ControllerParseError::StaleBinding),
        _ => {}
    }
    if let Some(old) = current {
        if binding.generation.0 <= old.generation.0
            || (binding.endpoint.id.0 == old.endpoint.id.0
                && binding.endpoint.generation.0 <= old.endpoint.generation.0)
        {
            return Err(ControllerParseError::StaleBinding);
        }
    }
    Ok(binding)
}

fn validate_message(message: ControllerMessage) -> Result<(), ControllerParseError> {
    if supervisor_generation(message).0 == 0 || transaction_id(message) == 0 {
        return Err(ControllerParseError::ZeroIdentity);
    }
    if let Some(binding) = binding(message) {
        if binding.generation.0 == 0
            || binding.endpoint.id.0 == 0
            || binding.endpoint.generation.0 == 0
        {
            return Err(ControllerParseError::ZeroIdentity);
        }
    }
    if let ControllerMessage::Status {
        status,
        attempt_generation,
        ..
    } = message
    {
        if status.is_device_bound() {
            return Err(ControllerParseError::DeviceBoundStatus);
        }
        if matches!(status, StatusCode::Backoff) && attempt_generation.is_none() {
            return Err(ControllerParseError::MissingAttempt);
        }
    }
    Ok(())
}

fn supervisor_generation(message: ControllerMessage) -> SupervisorGeneration {
    match message {
        ControllerMessage::InstallPublication {
            supervisor_generation,
            ..
        }
        | ControllerMessage::RebindPublication {
            supervisor_generation,
            ..
        }
        | ControllerMessage::Status {
            supervisor_generation,
            ..
        } => supervisor_generation,
    }
}

fn binding(message: ControllerMessage) -> Option<RegistryBinding> {
    match message {
        ControllerMessage::InstallPublication { binding, .. }
        | ControllerMessage::RebindPublication { binding, .. } => Some(binding),
        ControllerMessage::Status { binding, .. } => binding,
    }
}

fn transaction_id(message: ControllerMessage) -> u64 {
    match message {
        ControllerMessage::InstallPublication { transaction_id, .. }
        | ControllerMessage::RebindPublication { transaction_id, .. }
        | ControllerMessage::Status { transaction_id, .. } => transaction_id,
    }
}

fn binding_from_bytes(bytes: &[u8]) -> Result<Option<RegistryBinding>, ControllerParseError> {
    let generation = get64(bytes, 32);
    let id = get64(bytes, 40);
    let endpoint_generation = get64(bytes, 48);
    if generation == 0 && id == 0 && endpoint_generation == 0 {
        return Ok(None);
    }
    if generation == 0 || id == 0 || endpoint_generation == 0 {
        return Err(ControllerParseError::ZeroIdentity);
    }
    Ok(Some(RegistryBinding {
        generation: RegistryGeneration(generation),
        endpoint: RegistryEndpoint {
            id: RegistryEndpointId(id),
            generation: RegistryEndpointGeneration(endpoint_generation),
        },
    }))
}

fn put16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn get16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}
fn get32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("fixed header"))
}
fn get64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("fixed header"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUPERVISOR: SupervisorGeneration = SupervisorGeneration(7);
    const BINDING: RegistryBinding = RegistryBinding {
        generation: RegistryGeneration(3),
        endpoint: RegistryEndpoint {
            id: RegistryEndpointId(11),
            generation: RegistryEndpointGeneration(4),
        },
    };

    #[test]
    fn install_rebind_and_safe_status_round_trip() {
        let install = ControllerMessage::InstallPublication {
            supervisor_generation: SUPERVISOR,
            binding: BINDING,
            transaction_id: 1,
        };
        let mut bytes = [0; INSTALL_BYTES];
        encode(install, &mut bytes).unwrap();
        assert_eq!(parse(&bytes), Ok(install));
        assert_eq!(
            validate_binding_transition(SUPERVISOR, None, install),
            Ok(BINDING)
        );

        let status = ControllerMessage::Status {
            supervisor_generation: SUPERVISOR,
            binding: Some(BINDING),
            transaction_id: 2,
            status: StatusCode::OperationalWaitingForDeviceBundle,
            attempt_generation: None,
        };
        let mut status_bytes = [0; STATUS_BYTES];
        encode(status, &mut status_bytes).unwrap();
        assert_eq!(parse(&status_bytes), Ok(status));
    }

    #[test]
    fn initial_operational_status_has_no_binding_and_no_device_claim() {
        let status = ControllerMessage::Status {
            supervisor_generation: SUPERVISOR,
            binding: None,
            transaction_id: 3,
            status: StatusCode::OperationalWaitingForRegistry,
            attempt_generation: None,
        };
        let mut bytes = [0; STATUS_BYTES];
        encode(status, &mut bytes).unwrap();
        assert_eq!(parse(&bytes), Ok(status));
        assert!(!StatusCode::OperationalWaitingForRegistry.is_device_bound());
    }

    #[test]
    fn flags_reserved_handle_count_and_device_status_fail_closed() {
        let message = ControllerMessage::RebindPublication {
            supervisor_generation: SUPERVISOR,
            binding: BINDING,
            transaction_id: 4,
        };
        let mut bytes = [0; INSTALL_BYTES];
        encode(message, &mut bytes).unwrap();
        bytes[12] = 1;
        assert_eq!(parse(&bytes), Err(ControllerParseError::NonzeroFlags));
        encode(message, &mut bytes).unwrap();
        bytes[64] = 1;
        assert_eq!(parse(&bytes), Err(ControllerParseError::NonzeroReserved));
        encode(message, &mut bytes).unwrap();
        bytes[20..24].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(parse(&bytes), Err(ControllerParseError::WrongHandleCount));
        encode(message, &mut bytes).unwrap();
        assert_eq!(
            validate_binding_transition(SupervisorGeneration(8), Some(BINDING), message),
            Err(ControllerParseError::StaleBinding)
        );
    }

    #[test]
    fn replay_and_endpoint_reuse_are_rejected() {
        let install = ControllerMessage::InstallPublication {
            supervisor_generation: SUPERVISOR,
            binding: BINDING,
            transaction_id: 5,
        };
        assert_eq!(
            validate_binding_transition(SUPERVISOR, Some(BINDING), install),
            Err(ControllerParseError::StaleBinding)
        );
        let replay = ControllerMessage::RebindPublication {
            supervisor_generation: SUPERVISOR,
            binding: RegistryBinding {
                generation: RegistryGeneration(4),
                endpoint: RegistryEndpoint {
                    id: RegistryEndpointId(11),
                    generation: RegistryEndpointGeneration(4),
                },
            },
            transaction_id: 6,
        };
        assert_eq!(
            validate_binding_transition(SUPERVISOR, Some(BINDING), replay),
            Err(ControllerParseError::StaleBinding)
        );
    }
}
