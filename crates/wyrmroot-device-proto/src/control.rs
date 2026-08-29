//! WRDC v1 direct devmgr-to-driver control envelope.
//!
//! Handle values are intentionally absent from this wire format.  A
//! `RESOURCE_BUNDLE` carries exactly two already-validated handles in the
//! native Channel transfer, but this crate does not invent their object or
//! rights ABI.

pub const MAGIC: [u8; 4] = *b"WRDC";
pub const MAJOR: u16 = 1;
pub const MINOR: u16 = 0;
pub const HEADER_BYTES: usize = 72;
pub const CONFIGURE_BYTES: usize = HEADER_BYTES + 16;
pub const RESOURCE_BUNDLE_BYTES: usize = HEADER_BYTES;
pub const READY_BYTES: usize = HEADER_BYTES;
pub const FAILURE_BYTES: usize = HEADER_BYTES + 8;
pub const RETIRE_BYTES: usize = HEADER_BYTES;
pub const CONFIGURE_HANDLE_COUNT: u32 = 0;
pub const RESOURCE_BUNDLE_HANDLE_COUNT: u32 = 2;
pub const READY_HANDLE_COUNT: u32 = 0;
pub const FAILURE_HANDLE_COUNT: u32 = 0;
pub const RETIRE_HANDLE_COUNT: u32 = 0;

use crate::coordinator::{AttemptGeneration, BundleGeneration, EndpointGeneration, EndpointId};
use crate::manifest::{PROFILE_Q35, PROFILE_Q35_VERSION, ProfileId, ProfileVersion, RoleId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlEndpoint {
    pub id: EndpointId,
    pub generation: EndpointGeneration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureCode {
    MalformedResource = 1,
    DriverRejected = 2,
    DriverExited = 3,
    CleanupFailed = 4,
}

impl FailureCode {
    fn parse(value: u32) -> Result<Self, ControlParseError> {
        match value {
            1 => Ok(Self::MalformedResource),
            2 => Ok(Self::DriverRejected),
            3 => Ok(Self::DriverExited),
            4 => Ok(Self::CleanupFailed),
            _ => Err(ControlParseError::UnknownFailure),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlMessage {
    Configure {
        role_id: RoleId,
        bundle_generation: BundleGeneration,
        attempt_generation: AttemptGeneration,
        endpoint: ControlEndpoint,
        transaction_id: u64,
        profile: ProfileId,
        profile_version: ProfileVersion,
    },
    ResourceBundle {
        role_id: RoleId,
        bundle_generation: BundleGeneration,
        attempt_generation: AttemptGeneration,
        endpoint: ControlEndpoint,
        transaction_id: u64,
    },
    Ready {
        role_id: RoleId,
        bundle_generation: BundleGeneration,
        attempt_generation: AttemptGeneration,
        endpoint: ControlEndpoint,
        transaction_id: u64,
    },
    Failure {
        role_id: RoleId,
        bundle_generation: BundleGeneration,
        attempt_generation: AttemptGeneration,
        endpoint: ControlEndpoint,
        transaction_id: u64,
        code: FailureCode,
    },
    Retire {
        role_id: RoleId,
        bundle_generation: BundleGeneration,
        attempt_generation: AttemptGeneration,
        endpoint: ControlEndpoint,
        transaction_id: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlParseError {
    WrongSize,
    WrongMagic,
    WrongVersion,
    UnknownMessage,
    NonzeroFlags,
    WrongHandleCount,
    ZeroIdentity,
    NonzeroReserved,
    InvalidProfile,
    UnknownFailure,
}

impl ControlMessage {
    pub const fn handle_count(self) -> u32 {
        match self {
            Self::ResourceBundle { .. } => RESOURCE_BUNDLE_HANDLE_COUNT,
            _ => 0,
        }
    }

    pub const fn wire_size(self) -> usize {
        match self {
            Self::Configure { .. } => CONFIGURE_BYTES,
            Self::ResourceBundle { .. } => RESOURCE_BUNDLE_BYTES,
            Self::Ready { .. } | Self::Retire { .. } => HEADER_BYTES,
            Self::Failure { .. } => FAILURE_BYTES,
        }
    }
}

pub fn encode(message: ControlMessage, output: &mut [u8]) -> Result<(), ControlParseError> {
    if output.len() != message.wire_size() {
        return Err(ControlParseError::WrongSize);
    }
    validate_identity(message)?;
    output.fill(0);
    output[..4].copy_from_slice(&MAGIC);
    put16(output, 4, MAJOR);
    put16(output, 6, MINOR);
    put32(output, 8, message_type(message));
    put32(output, 16, output.len() as u32);
    put32(output, 20, message.handle_count());
    put64(output, 24, role_id(message).0);
    put64(output, 32, bundle_generation(message).0);
    put64(output, 40, attempt_generation(message).0);
    put64(output, 48, endpoint(message).id.0);
    put64(output, 56, endpoint(message).generation.0);
    put64(output, 64, transaction_id(message));
    match message {
        ControlMessage::Configure {
            profile,
            profile_version,
            ..
        } => {
            put32(output, HEADER_BYTES, profile.0);
            put32(output, HEADER_BYTES + 4, profile_version.0);
        }
        ControlMessage::ResourceBundle { .. } => {}
        ControlMessage::Ready { .. } | ControlMessage::Retire { .. } => {}
        ControlMessage::Failure { code, .. } => put32(output, HEADER_BYTES, code as u32),
    }
    Ok(())
}

pub fn parse(bytes: &[u8]) -> Result<ControlMessage, ControlParseError> {
    if bytes.len() < HEADER_BYTES {
        return Err(ControlParseError::WrongSize);
    }
    if bytes[..4] != MAGIC {
        return Err(ControlParseError::WrongMagic);
    }
    if get16(bytes, 4) != MAJOR || get16(bytes, 6) != MINOR {
        return Err(ControlParseError::WrongVersion);
    }
    if get32(bytes, 12) != 0 || get64(bytes, 64) == 0 {
        return Err(if get32(bytes, 12) != 0 {
            ControlParseError::NonzeroFlags
        } else {
            ControlParseError::ZeroIdentity
        });
    }
    let size = get32(bytes, 16) as usize;
    let handles = get32(bytes, 20);
    if size != bytes.len() {
        return Err(ControlParseError::WrongSize);
    }
    let role_id = RoleId(get64(bytes, 24));
    let bundle_generation = BundleGeneration(get64(bytes, 32));
    let attempt_generation = AttemptGeneration(get64(bytes, 40));
    let endpoint = ControlEndpoint {
        id: EndpointId(get64(bytes, 48)),
        generation: EndpointGeneration(get64(bytes, 56)),
    };
    let transaction_id = get64(bytes, 64);
    let message = match get32(bytes, 8) {
        1 => {
            if bytes.len() != CONFIGURE_BYTES
                || handles != CONFIGURE_HANDLE_COUNT
                || get64(bytes, HEADER_BYTES + 8) != 0
            {
                return Err(ControlParseError::WrongSize);
            }
            let profile = ProfileId(get32(bytes, HEADER_BYTES));
            let profile_version = ProfileVersion(get32(bytes, HEADER_BYTES + 4));
            if profile != PROFILE_Q35 || profile_version != PROFILE_Q35_VERSION {
                return Err(ControlParseError::InvalidProfile);
            }
            ControlMessage::Configure {
                role_id,
                bundle_generation,
                attempt_generation,
                endpoint,
                transaction_id,
                profile,
                profile_version,
            }
        }
        2 => {
            if bytes.len() != RESOURCE_BUNDLE_BYTES || handles != RESOURCE_BUNDLE_HANDLE_COUNT {
                return Err(ControlParseError::WrongHandleCount);
            }
            ControlMessage::ResourceBundle {
                role_id,
                bundle_generation,
                attempt_generation,
                endpoint,
                transaction_id,
            }
        }
        3 => {
            if bytes.len() != READY_BYTES || handles != READY_HANDLE_COUNT {
                return Err(ControlParseError::WrongHandleCount);
            }
            ControlMessage::Ready {
                role_id,
                bundle_generation,
                attempt_generation,
                endpoint,
                transaction_id,
            }
        }
        4 => {
            if bytes.len() != FAILURE_BYTES
                || handles != FAILURE_HANDLE_COUNT
                || get32(bytes, HEADER_BYTES + 4) != 0
            {
                return Err(ControlParseError::NonzeroReserved);
            }
            ControlMessage::Failure {
                role_id,
                bundle_generation,
                attempt_generation,
                endpoint,
                transaction_id,
                code: FailureCode::parse(get32(bytes, HEADER_BYTES))?,
            }
        }
        5 => {
            if bytes.len() != RETIRE_BYTES || handles != RETIRE_HANDLE_COUNT {
                return Err(ControlParseError::WrongHandleCount);
            }
            ControlMessage::Retire {
                role_id,
                bundle_generation,
                attempt_generation,
                endpoint,
                transaction_id,
            }
        }
        _ => return Err(ControlParseError::UnknownMessage),
    };
    validate_identity(message)?;
    Ok(message)
}

fn validate_identity(message: ControlMessage) -> Result<(), ControlParseError> {
    let role = role_id(message);
    let bundle = bundle_generation(message);
    let attempt = attempt_generation(message);
    let endpoint = endpoint(message);
    if role.0 == 0
        || bundle.0 == 0
        || attempt.0 == 0
        || endpoint.id.0 == 0
        || endpoint.generation.0 == 0
        || transaction_id(message) == 0
    {
        return Err(ControlParseError::ZeroIdentity);
    }
    if let ControlMessage::Configure {
        profile,
        profile_version,
        ..
    } = message
        && (profile != PROFILE_Q35 || profile_version != PROFILE_Q35_VERSION)
    {
        return Err(ControlParseError::InvalidProfile);
    }
    Ok(())
}

const fn message_type(message: ControlMessage) -> u32 {
    match message {
        ControlMessage::Configure { .. } => 1,
        ControlMessage::ResourceBundle { .. } => 2,
        ControlMessage::Ready { .. } => 3,
        ControlMessage::Failure { .. } => 4,
        ControlMessage::Retire { .. } => 5,
    }
}
const fn role_id(message: ControlMessage) -> RoleId {
    match message {
        ControlMessage::Configure { role_id, .. }
        | ControlMessage::ResourceBundle { role_id, .. }
        | ControlMessage::Ready { role_id, .. }
        | ControlMessage::Failure { role_id, .. }
        | ControlMessage::Retire { role_id, .. } => role_id,
    }
}
const fn bundle_generation(message: ControlMessage) -> BundleGeneration {
    match message {
        ControlMessage::Configure {
            bundle_generation, ..
        }
        | ControlMessage::ResourceBundle {
            bundle_generation, ..
        }
        | ControlMessage::Ready {
            bundle_generation, ..
        }
        | ControlMessage::Failure {
            bundle_generation, ..
        }
        | ControlMessage::Retire {
            bundle_generation, ..
        } => bundle_generation,
    }
}
const fn attempt_generation(message: ControlMessage) -> AttemptGeneration {
    match message {
        ControlMessage::Configure {
            attempt_generation, ..
        }
        | ControlMessage::ResourceBundle {
            attempt_generation, ..
        }
        | ControlMessage::Ready {
            attempt_generation, ..
        }
        | ControlMessage::Failure {
            attempt_generation, ..
        }
        | ControlMessage::Retire {
            attempt_generation, ..
        } => attempt_generation,
    }
}
const fn endpoint(message: ControlMessage) -> ControlEndpoint {
    match message {
        ControlMessage::Configure { endpoint, .. }
        | ControlMessage::ResourceBundle { endpoint, .. }
        | ControlMessage::Ready { endpoint, .. }
        | ControlMessage::Failure { endpoint, .. }
        | ControlMessage::Retire { endpoint, .. } => endpoint,
    }
}
const fn transaction_id(message: ControlMessage) -> u64 {
    match message {
        ControlMessage::Configure { transaction_id, .. }
        | ControlMessage::ResourceBundle { transaction_id, .. }
        | ControlMessage::Ready { transaction_id, .. }
        | ControlMessage::Failure { transaction_id, .. }
        | ControlMessage::Retire { transaction_id, .. } => transaction_id,
    }
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

    fn ids() -> (RoleId, BundleGeneration, AttemptGeneration, ControlEndpoint) {
        (
            RoleId(1),
            BundleGeneration(2),
            AttemptGeneration(3),
            ControlEndpoint {
                id: EndpointId(4),
                generation: EndpointGeneration(5),
            },
        )
    }

    #[test]
    fn resource_bundle_has_exactly_two_opaque_handles() {
        let (role, bundle, attempt, endpoint) = ids();
        let message = ControlMessage::ResourceBundle {
            role_id: role,
            bundle_generation: bundle,
            attempt_generation: attempt,
            endpoint,
            transaction_id: 6,
        };
        let mut bytes = [0; RESOURCE_BUNDLE_BYTES];
        encode(message, &mut bytes).unwrap();
        assert_eq!(parse(&bytes), Ok(message));
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(parse(&bytes), Err(ControlParseError::WrongHandleCount));
    }

    #[test]
    fn ready_and_failure_are_bounded_and_versioned() {
        let (role, bundle, attempt, endpoint) = ids();
        let ready = ControlMessage::Ready {
            role_id: role,
            bundle_generation: bundle,
            attempt_generation: attempt,
            endpoint,
            transaction_id: 7,
        };
        let mut bytes = [0; READY_BYTES];
        encode(ready, &mut bytes).unwrap();
        assert_eq!(parse(&bytes), Ok(ready));
        bytes[6] = 1;
        assert_eq!(parse(&bytes), Err(ControlParseError::WrongVersion));
    }

    #[test]
    fn configure_is_exact_q35_and_reserved_bytes_fail_closed() {
        let (role, bundle, attempt, endpoint) = ids();
        let message = ControlMessage::Configure {
            role_id: role,
            bundle_generation: bundle,
            attempt_generation: attempt,
            endpoint,
            transaction_id: 8,
            profile: PROFILE_Q35,
            profile_version: PROFILE_Q35_VERSION,
        };
        let mut bytes = [0; CONFIGURE_BYTES];
        encode(message, &mut bytes).unwrap();
        assert_eq!(parse(&bytes), Ok(message));
        bytes[HEADER_BYTES + 8] = 1;
        assert_eq!(parse(&bytes), Err(ControlParseError::WrongSize));
        bytes[HEADER_BYTES + 8] = 0;
        bytes[HEADER_BYTES..HEADER_BYTES + 4].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(parse(&bytes), Err(ControlParseError::InvalidProfile));
    }

    #[test]
    fn every_common_identity_and_flag_is_required() {
        let (role, bundle, attempt, endpoint) = ids();
        let message = ControlMessage::Retire {
            role_id: role,
            bundle_generation: bundle,
            attempt_generation: attempt,
            endpoint,
            transaction_id: 9,
        };
        let mut bytes = [0; RETIRE_BYTES];
        encode(message, &mut bytes).unwrap();
        bytes[12] = 1;
        assert_eq!(parse(&bytes), Err(ControlParseError::NonzeroFlags));
        bytes[12] = 0;
        bytes[32..40].fill(0);
        assert_eq!(parse(&bytes), Err(ControlParseError::ZeroIdentity));
    }
}
