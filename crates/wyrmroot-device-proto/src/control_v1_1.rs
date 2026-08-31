//! WRDC 1.1 production device/interrupt staging and stream attachment.
//!
//! This codec is deliberately separate from [`crate::control`]. Historical
//! WRDC 1.0 parsers therefore cannot reinterpret any 1.1 message.

use crate::control::{ControlEndpoint, FailureCode};
use crate::coordinator::{AttemptGeneration, BundleGeneration};
use crate::manifest::RoleId;

pub const MAGIC: [u8; 4] = *b"WRDC";
pub const MAJOR: u16 = 1;
pub const MINOR: u16 = 1;
pub const HEADER_BYTES: usize = 72;
pub const DEVICE_STAGE_BYTES: usize = 112;
pub const DEVICE_QUIESCED_BYTES: usize = 80;
pub const INTERRUPT_STAGE_BYTES: usize = 96;
pub const ATTACH_STREAM_BYTES: usize = 96;
pub const STREAM_READY_BYTES: usize = 96;
pub const STREAM_DETACHED_BYTES: usize = 96;
pub const READY_BYTES: usize = HEADER_BYTES;
pub const FAILURE_BYTES: usize = HEADER_BYTES + 8;
pub const RETIRE_BYTES: usize = HEADER_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlIdentityV1_1 {
    pub role_id: RoleId,
    pub bundle_generation: BundleGeneration,
    pub attempt_generation: AttemptGeneration,
    pub endpoint: ControlEndpoint,
    pub transaction_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlMessageV1_1 {
    DeviceStage {
        identity: ControlIdentityV1_1,
        stage_generation: u64,
        resource_id: u64,
        pio_base: u16,
        pio_length: u16,
        source: u32,
    },
    DeviceQuiesced {
        identity: ControlIdentityV1_1,
        stage_generation: u64,
    },
    InterruptStage {
        identity: ControlIdentityV1_1,
        stage_generation: u64,
        parent_resource_id: u64,
        source: u32,
    },
    AttachStream {
        identity: ControlIdentityV1_1,
        stream_generation: u64,
        publication_generation: u64,
    },
    StreamReady {
        identity: ControlIdentityV1_1,
        stream_generation: u64,
        publication_generation: u64,
    },
    StreamDetached {
        identity: ControlIdentityV1_1,
        stream_generation: u64,
        publication_generation: u64,
    },
    Ready {
        identity: ControlIdentityV1_1,
    },
    Failure {
        identity: ControlIdentityV1_1,
        code: FailureCode,
    },
    Retire {
        identity: ControlIdentityV1_1,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlParseErrorV1_1 {
    WrongSize,
    WrongMagic,
    WrongVersion,
    UnknownMessage,
    NonzeroFlags,
    WrongHandleCount,
    ZeroIdentity,
    NonzeroReserved,
    UnknownFailure,
}

impl ControlMessageV1_1 {
    pub const fn identity(self) -> ControlIdentityV1_1 {
        match self {
            Self::DeviceStage { identity, .. }
            | Self::DeviceQuiesced { identity, .. }
            | Self::InterruptStage { identity, .. }
            | Self::AttachStream { identity, .. }
            | Self::StreamReady { identity, .. }
            | Self::StreamDetached { identity, .. }
            | Self::Ready { identity }
            | Self::Failure { identity, .. }
            | Self::Retire { identity } => identity,
        }
    }

    pub const fn wire_size(self) -> usize {
        match self {
            Self::DeviceStage { .. } => DEVICE_STAGE_BYTES,
            Self::DeviceQuiesced { .. } => DEVICE_QUIESCED_BYTES,
            Self::InterruptStage { .. } => INTERRUPT_STAGE_BYTES,
            Self::AttachStream { .. } | Self::StreamReady { .. } | Self::StreamDetached { .. } => {
                ATTACH_STREAM_BYTES
            }
            Self::Ready { .. } | Self::Retire { .. } => HEADER_BYTES,
            Self::Failure { .. } => FAILURE_BYTES,
        }
    }

    pub const fn handle_count(self) -> u32 {
        match self {
            Self::DeviceStage { .. } | Self::InterruptStage { .. } | Self::AttachStream { .. } => 1,
            _ => 0,
        }
    }
}

pub fn encode(message: ControlMessageV1_1, output: &mut [u8]) -> Result<(), ControlParseErrorV1_1> {
    if output.len() != message.wire_size() {
        return Err(ControlParseErrorV1_1::WrongSize);
    }
    validate_identity(message.identity())?;
    validate_body(message)?;
    output.fill(0);
    output[..4].copy_from_slice(&MAGIC);
    put16(output, 4, MAJOR);
    put16(output, 6, MINOR);
    put32(output, 8, message_type(message));
    put32(output, 16, output.len() as u32);
    put32(output, 20, message.handle_count());
    let identity = message.identity();
    put64(output, 24, identity.role_id.0);
    put64(output, 32, identity.bundle_generation.0);
    put64(output, 40, identity.attempt_generation.0);
    put64(output, 48, identity.endpoint.id.0);
    put64(output, 56, identity.endpoint.generation.0);
    put64(output, 64, identity.transaction_id);
    match message {
        ControlMessageV1_1::DeviceStage {
            stage_generation,
            resource_id,
            pio_base,
            pio_length,
            source,
            ..
        } => {
            put64(output, 72, stage_generation);
            put64(output, 80, resource_id);
            put16(output, 88, pio_base);
            put16(output, 90, pio_length);
            put32(output, 92, source);
        }
        ControlMessageV1_1::DeviceQuiesced {
            stage_generation, ..
        } => put64(output, 72, stage_generation),
        ControlMessageV1_1::InterruptStage {
            stage_generation,
            parent_resource_id,
            source,
            ..
        } => {
            put64(output, 72, stage_generation);
            put64(output, 80, parent_resource_id);
            put32(output, 88, source);
        }
        ControlMessageV1_1::AttachStream {
            stream_generation,
            publication_generation,
            ..
        }
        | ControlMessageV1_1::StreamReady {
            stream_generation,
            publication_generation,
            ..
        }
        | ControlMessageV1_1::StreamDetached {
            stream_generation,
            publication_generation,
            ..
        } => {
            put64(output, 72, stream_generation);
            put64(output, 80, publication_generation);
        }
        ControlMessageV1_1::Failure { code, .. } => put32(output, 72, code as u32),
        ControlMessageV1_1::Ready { .. } | ControlMessageV1_1::Retire { .. } => {}
    }
    Ok(())
}

pub fn parse(bytes: &[u8]) -> Result<ControlMessageV1_1, ControlParseErrorV1_1> {
    if bytes.len() < HEADER_BYTES {
        return Err(ControlParseErrorV1_1::WrongSize);
    }
    if bytes[..4] != MAGIC {
        return Err(ControlParseErrorV1_1::WrongMagic);
    }
    if get16(bytes, 4) != MAJOR || get16(bytes, 6) != MINOR {
        return Err(ControlParseErrorV1_1::WrongVersion);
    }
    if get32(bytes, 12) != 0 {
        return Err(ControlParseErrorV1_1::NonzeroFlags);
    }
    if get32(bytes, 16) as usize != bytes.len() {
        return Err(ControlParseErrorV1_1::WrongSize);
    }
    let identity = ControlIdentityV1_1 {
        role_id: RoleId(get64(bytes, 24)),
        bundle_generation: BundleGeneration(get64(bytes, 32)),
        attempt_generation: AttemptGeneration(get64(bytes, 40)),
        endpoint: ControlEndpoint {
            id: crate::coordinator::EndpointId(get64(bytes, 48)),
            generation: crate::coordinator::EndpointGeneration(get64(bytes, 56)),
        },
        transaction_id: get64(bytes, 64),
    };
    validate_identity(identity)?;
    let handles = get32(bytes, 20);
    let message = match get32(bytes, 8) {
        8 => {
            require_shape(bytes, DEVICE_STAGE_BYTES, handles, 1)?;
            require_zero(bytes, 96, 112)?;
            ControlMessageV1_1::DeviceStage {
                identity,
                stage_generation: get64(bytes, 72),
                resource_id: get64(bytes, 80),
                pio_base: get16(bytes, 88),
                pio_length: get16(bytes, 90),
                source: get32(bytes, 92),
            }
        }
        9 => {
            require_shape(bytes, DEVICE_QUIESCED_BYTES, handles, 0)?;
            ControlMessageV1_1::DeviceQuiesced {
                identity,
                stage_generation: get64(bytes, 72),
            }
        }
        10 => {
            require_shape(bytes, INTERRUPT_STAGE_BYTES, handles, 1)?;
            require_zero(bytes, 92, 96)?;
            ControlMessageV1_1::InterruptStage {
                identity,
                stage_generation: get64(bytes, 72),
                parent_resource_id: get64(bytes, 80),
                source: get32(bytes, 88),
            }
        }
        11..=13 => {
            require_shape(
                bytes,
                ATTACH_STREAM_BYTES,
                handles,
                u32::from(get32(bytes, 8) == 11),
            )?;
            require_zero(bytes, 88, 96)?;
            let stream_generation = get64(bytes, 72);
            let publication_generation = get64(bytes, 80);
            match get32(bytes, 8) {
                11 => ControlMessageV1_1::AttachStream {
                    identity,
                    stream_generation,
                    publication_generation,
                },
                12 => ControlMessageV1_1::StreamReady {
                    identity,
                    stream_generation,
                    publication_generation,
                },
                _ => ControlMessageV1_1::StreamDetached {
                    identity,
                    stream_generation,
                    publication_generation,
                },
            }
        }
        3 => {
            require_shape(bytes, READY_BYTES, handles, 0)?;
            ControlMessageV1_1::Ready { identity }
        }
        4 => {
            require_shape(bytes, FAILURE_BYTES, handles, 0)?;
            require_zero(bytes, 76, 80)?;
            let code = match get32(bytes, 72) {
                1 => FailureCode::MalformedResource,
                2 => FailureCode::DriverRejected,
                3 => FailureCode::DriverExited,
                4 => FailureCode::CleanupFailed,
                5 => FailureCode::IntentionalRestart,
                _ => return Err(ControlParseErrorV1_1::UnknownFailure),
            };
            ControlMessageV1_1::Failure { identity, code }
        }
        5 => {
            require_shape(bytes, RETIRE_BYTES, handles, 0)?;
            ControlMessageV1_1::Retire { identity }
        }
        _ => return Err(ControlParseErrorV1_1::UnknownMessage),
    };
    validate_body(message)?;
    Ok(message)
}

fn validate_identity(identity: ControlIdentityV1_1) -> Result<(), ControlParseErrorV1_1> {
    if identity.role_id.0 == 0
        || identity.bundle_generation.0 == 0
        || identity.attempt_generation.0 == 0
        || identity.endpoint.id.0 == 0
        || identity.endpoint.generation.0 == 0
        || identity.transaction_id == 0
    {
        Err(ControlParseErrorV1_1::ZeroIdentity)
    } else {
        Ok(())
    }
}

fn validate_body(message: ControlMessageV1_1) -> Result<(), ControlParseErrorV1_1> {
    let valid = match message {
        ControlMessageV1_1::DeviceStage {
            stage_generation,
            resource_id,
            pio_length,
            source,
            ..
        } => stage_generation != 0 && resource_id != 0 && pio_length != 0 && source != 0,
        ControlMessageV1_1::DeviceQuiesced {
            stage_generation, ..
        } => stage_generation != 0,
        ControlMessageV1_1::InterruptStage {
            stage_generation,
            parent_resource_id,
            source,
            ..
        } => stage_generation != 0 && parent_resource_id != 0 && source != 0,
        ControlMessageV1_1::AttachStream {
            stream_generation,
            publication_generation,
            ..
        }
        | ControlMessageV1_1::StreamReady {
            stream_generation,
            publication_generation,
            ..
        }
        | ControlMessageV1_1::StreamDetached {
            stream_generation,
            publication_generation,
            ..
        } => stream_generation != 0 && publication_generation != 0,
        ControlMessageV1_1::Failure { code, .. } => code != FailureCode::IntentionalRestart,
        ControlMessageV1_1::Ready { .. } | ControlMessageV1_1::Retire { .. } => true,
    };
    if valid {
        Ok(())
    } else {
        Err(ControlParseErrorV1_1::ZeroIdentity)
    }
}

fn require_shape(
    bytes: &[u8],
    size: usize,
    actual_handles: u32,
    expected_handles: u32,
) -> Result<(), ControlParseErrorV1_1> {
    if bytes.len() != size {
        Err(ControlParseErrorV1_1::WrongSize)
    } else if actual_handles != expected_handles {
        Err(ControlParseErrorV1_1::WrongHandleCount)
    } else {
        Ok(())
    }
}

fn require_zero(bytes: &[u8], start: usize, end: usize) -> Result<(), ControlParseErrorV1_1> {
    if bytes[start..end].iter().any(|value| *value != 0) {
        Err(ControlParseErrorV1_1::NonzeroReserved)
    } else {
        Ok(())
    }
}

const fn message_type(message: ControlMessageV1_1) -> u32 {
    match message {
        ControlMessageV1_1::Ready { .. } => 3,
        ControlMessageV1_1::Failure { .. } => 4,
        ControlMessageV1_1::Retire { .. } => 5,
        ControlMessageV1_1::DeviceStage { .. } => 8,
        ControlMessageV1_1::DeviceQuiesced { .. } => 9,
        ControlMessageV1_1::InterruptStage { .. } => 10,
        ControlMessageV1_1::AttachStream { .. } => 11,
        ControlMessageV1_1::StreamReady { .. } => 12,
        ControlMessageV1_1::StreamDetached { .. } => 13,
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
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed control field"),
    )
}
fn get64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed control field"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::{EndpointGeneration, EndpointId};

    fn identity(transaction_id: u64) -> ControlIdentityV1_1 {
        ControlIdentityV1_1 {
            role_id: RoleId(1),
            bundle_generation: BundleGeneration(2),
            attempt_generation: AttemptGeneration(3),
            endpoint: ControlEndpoint {
                id: EndpointId(4),
                generation: EndpointGeneration(5),
            },
            transaction_id,
        }
    }

    fn round_trip(message: ControlMessageV1_1) {
        let mut bytes = [0; DEVICE_STAGE_BYTES];
        let output = &mut bytes[..message.wire_size()];
        encode(message, output).unwrap();
        assert_eq!(parse(output), Ok(message));
    }

    #[test]
    fn every_production_shape_round_trips() {
        round_trip(ControlMessageV1_1::DeviceStage {
            identity: identity(6),
            stage_generation: 7,
            resource_id: 1,
            pio_base: 0x2f8,
            pio_length: 8,
            source: 3,
        });
        round_trip(ControlMessageV1_1::DeviceQuiesced {
            identity: identity(8),
            stage_generation: 7,
        });
        round_trip(ControlMessageV1_1::InterruptStage {
            identity: identity(9),
            stage_generation: 7,
            parent_resource_id: 1,
            source: 3,
        });
        for message in [
            ControlMessageV1_1::AttachStream {
                identity: identity(10),
                stream_generation: 11,
                publication_generation: 12,
            },
            ControlMessageV1_1::StreamReady {
                identity: identity(10),
                stream_generation: 11,
                publication_generation: 12,
            },
            ControlMessageV1_1::StreamDetached {
                identity: identity(10),
                stream_generation: 11,
                publication_generation: 12,
            },
            ControlMessageV1_1::Ready {
                identity: identity(13),
            },
            ControlMessageV1_1::Failure {
                identity: identity(14),
                code: FailureCode::DriverRejected,
            },
            ControlMessageV1_1::Retire {
                identity: identity(15),
            },
        ] {
            round_trip(message);
        }
    }

    #[test]
    fn minor_zero_and_reserved_or_handle_mutations_fail_closed() {
        let message = ControlMessageV1_1::DeviceStage {
            identity: identity(6),
            stage_generation: 7,
            resource_id: 1,
            pio_base: 0x2f8,
            pio_length: 8,
            source: 3,
        };
        let mut bytes = [0; DEVICE_STAGE_BYTES];
        encode(message, &mut bytes).unwrap();
        bytes[6] = 0;
        assert_eq!(parse(&bytes), Err(ControlParseErrorV1_1::WrongVersion));
        bytes[6] = 1;
        bytes[20..24].copy_from_slice(&0_u32.to_le_bytes());
        assert_eq!(parse(&bytes), Err(ControlParseErrorV1_1::WrongHandleCount));
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[111] = 1;
        assert_eq!(parse(&bytes), Err(ControlParseErrorV1_1::NonzeroReserved));
    }
}
