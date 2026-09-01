//! Byte-defined selector-31 raw COM2 challenge and controller handshake.

#![no_std]
#![forbid(unsafe_code)]

// The selector feature supplies the native actor's dependencies. Cargo also
// enables it while checking this companion protocol library, where the actor-
// only crates are intentionally not referenced otherwise.
#[cfg(feature = "native-probe")]
use deepwyrm_syscall as _;
#[cfg(feature = "native-probe")]
use wyrmroot_device_proto as _;
#[cfg(feature = "native-probe")]
use wyrmroot_loader as _;
#[cfg(feature = "native-probe")]
use wyrmroot_registry_proto as _;
#[cfg(feature = "native-probe")]
use wyrmroot_runtime as _;
#[cfg(feature = "native-probe")]
use wyrmroot_stream_proto as _;

pub const CONTROL_MAGIC: [u8; 4] = *b"WRE3";
pub const CONTROL_VERSION: u16 = 1;
pub const CONTROL_BYTES: usize = 80;
pub const CHALLENGE_BYTES: usize = 24;
pub const RESPONSE_BYTES: usize = CHALLENGE_BYTES;
pub const CLIENT_TRANSACTION_ID: u64 = 1;
pub const CONNECT_TRANSACTION_ID: u64 = 2;
pub const CHALLENGE_GENERATION: u64 = 1;
pub const DEVMGR_CONFIG_BYTES: usize = 48;
pub const DEVMGR_CONFIG_MAGIC: [u8; 4] = *b"WDE3";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DevmgrConfig {
    pub nonce: u64,
    pub publication_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DevmgrReady {
    pub nonce: u64,
    pub publication_generation: u64,
}

pub fn encode_devmgr_config(config: DevmgrConfig, output: &mut [u8]) -> Result<(), ProtocolError> {
    encode_devmgr_record(1, config.nonce, config.publication_generation, output)
}

pub fn parse_devmgr_config(bytes: &[u8]) -> Result<DevmgrConfig, ProtocolError> {
    let (nonce, publication_generation) = parse_devmgr_record(bytes, 1)?;
    Ok(DevmgrConfig {
        nonce,
        publication_generation,
    })
}

pub fn encode_devmgr_ready(ready: DevmgrReady, output: &mut [u8]) -> Result<(), ProtocolError> {
    encode_devmgr_record(2, ready.nonce, ready.publication_generation, output)
}

pub fn parse_devmgr_ready(bytes: &[u8]) -> Result<DevmgrReady, ProtocolError> {
    let (nonce, publication_generation) = parse_devmgr_record(bytes, 2)?;
    Ok(DevmgrReady {
        nonce,
        publication_generation,
    })
}

fn encode_devmgr_record(
    message_type: u16,
    nonce: u64,
    publication_generation: u64,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    if output.len() != DEVMGR_CONFIG_BYTES {
        return Err(ProtocolError::WrongSize);
    }
    if nonce == 0 || publication_generation == 0 {
        return Err(ProtocolError::ZeroIdentity);
    }
    output.fill(0);
    output[..4].copy_from_slice(&DEVMGR_CONFIG_MAGIC);
    put16(output, 4, CONTROL_VERSION);
    put16(output, 6, message_type);
    put32(output, 8, DEVMGR_CONFIG_BYTES as u32);
    put64(output, 16, nonce);
    put64(output, 24, publication_generation);
    Ok(())
}

fn parse_devmgr_record(bytes: &[u8], expected_type: u16) -> Result<(u64, u64), ProtocolError> {
    if bytes.len() != DEVMGR_CONFIG_BYTES || get32(bytes, 8) != DEVMGR_CONFIG_BYTES as u32 {
        return Err(ProtocolError::WrongSize);
    }
    if bytes[..4] != DEVMGR_CONFIG_MAGIC {
        return Err(ProtocolError::WrongMagic);
    }
    if get16(bytes, 4) != CONTROL_VERSION {
        return Err(ProtocolError::WrongVersion);
    }
    if get16(bytes, 6) != expected_type {
        return Err(ProtocolError::WrongType);
    }
    if get32(bytes, 12) != 0 || bytes[32..].iter().any(|byte| *byte != 0) {
        return Err(ProtocolError::NonzeroReserved);
    }
    let nonce = get64(bytes, 16);
    let publication_generation = get64(bytes, 24);
    if nonce == 0 || publication_generation == 0 {
        return Err(ProtocolError::ZeroIdentity);
    }
    Ok((nonce, publication_generation))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerMessage {
    Configure {
        nonce: u64,
        publication_generation: u64,
        challenge_generation: u64,
        expected_length: u64,
        expected_hash: u64,
    },
    Attached {
        nonce: u64,
        publication_generation: u64,
        stream_generation: u64,
        challenge_generation: u64,
    },
    ArmPermit {
        nonce: u64,
        publication_generation: u64,
        stream_generation: u64,
        challenge_generation: u64,
        expected_length: u64,
        expected_hash: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    WrongSize,
    WrongMagic,
    WrongVersion,
    WrongType,
    ZeroIdentity,
    WrongLength,
    NonzeroReserved,
}

pub fn encode(message: ControllerMessage, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() != CONTROL_BYTES {
        return Err(ProtocolError::WrongSize);
    }
    validate(message)?;
    output.fill(0);
    output[..4].copy_from_slice(&CONTROL_MAGIC);
    put16(output, 4, CONTROL_VERSION);
    put16(output, 6, message_type(message));
    put32(output, 8, CONTROL_BYTES as u32);
    match message {
        ControllerMessage::Configure {
            nonce,
            publication_generation,
            challenge_generation,
            expected_length,
            expected_hash,
        } => {
            put64(output, 16, nonce);
            put64(output, 24, publication_generation);
            put64(output, 40, challenge_generation);
            put64(output, 48, expected_length);
            put64(output, 56, expected_hash);
        }
        ControllerMessage::Attached {
            nonce,
            publication_generation,
            stream_generation,
            challenge_generation,
        } => {
            put64(output, 16, nonce);
            put64(output, 24, publication_generation);
            put64(output, 32, stream_generation);
            put64(output, 40, challenge_generation);
        }
        ControllerMessage::ArmPermit {
            nonce,
            publication_generation,
            stream_generation,
            challenge_generation,
            expected_length,
            expected_hash,
        } => {
            put64(output, 16, nonce);
            put64(output, 24, publication_generation);
            put64(output, 32, stream_generation);
            put64(output, 40, challenge_generation);
            put64(output, 48, expected_length);
            put64(output, 56, expected_hash);
        }
    }
    Ok(())
}

pub fn parse(bytes: &[u8]) -> Result<ControllerMessage, ProtocolError> {
    if bytes.len() != CONTROL_BYTES || get32(bytes, 8) != CONTROL_BYTES as u32 {
        return Err(ProtocolError::WrongSize);
    }
    if bytes[..4] != CONTROL_MAGIC {
        return Err(ProtocolError::WrongMagic);
    }
    if get16(bytes, 4) != CONTROL_VERSION {
        return Err(ProtocolError::WrongVersion);
    }
    if get32(bytes, 12) != 0 || bytes[64..].iter().any(|byte| *byte != 0) {
        return Err(ProtocolError::NonzeroReserved);
    }
    let nonce = get64(bytes, 16);
    let publication_generation = get64(bytes, 24);
    let stream_generation = get64(bytes, 32);
    let challenge_generation = get64(bytes, 40);
    let expected_length = get64(bytes, 48);
    let expected_hash = get64(bytes, 56);
    let message = match get16(bytes, 6) {
        1 => {
            if stream_generation != 0 {
                return Err(ProtocolError::NonzeroReserved);
            }
            ControllerMessage::Configure {
                nonce,
                publication_generation,
                challenge_generation,
                expected_length,
                expected_hash,
            }
        }
        2 => {
            if expected_length != 0 || expected_hash != 0 {
                return Err(ProtocolError::NonzeroReserved);
            }
            ControllerMessage::Attached {
                nonce,
                publication_generation,
                stream_generation,
                challenge_generation,
            }
        }
        3 => ControllerMessage::ArmPermit {
            nonce,
            publication_generation,
            stream_generation,
            challenge_generation,
            expected_length,
            expected_hash,
        },
        _ => return Err(ProtocolError::WrongType),
    };
    validate(message)?;
    Ok(message)
}

fn validate(message: ControllerMessage) -> Result<(), ProtocolError> {
    let (nonce, publication, stream, challenge, length, hash) = match message {
        ControllerMessage::Configure {
            nonce,
            publication_generation,
            challenge_generation,
            expected_length,
            expected_hash,
        } => (
            nonce,
            publication_generation,
            1,
            challenge_generation,
            expected_length,
            expected_hash,
        ),
        ControllerMessage::Attached {
            nonce,
            publication_generation,
            stream_generation,
            challenge_generation,
        } => (
            nonce,
            publication_generation,
            stream_generation,
            challenge_generation,
            CHALLENGE_BYTES as u64,
            1,
        ),
        ControllerMessage::ArmPermit {
            nonce,
            publication_generation,
            stream_generation,
            challenge_generation,
            expected_length,
            expected_hash,
        } => (
            nonce,
            publication_generation,
            stream_generation,
            challenge_generation,
            expected_length,
            expected_hash,
        ),
    };
    if [nonce, publication, stream, challenge, hash]
        .into_iter()
        .any(|value| value == 0)
    {
        return Err(ProtocolError::ZeroIdentity);
    }
    if length != CHALLENGE_BYTES as u64 {
        return Err(ProtocolError::WrongLength);
    }
    Ok(())
}

pub fn challenge(nonce: u64) -> [u8; CHALLENGE_BYTES] {
    let mut bytes = [0u8; CHALLENGE_BYTES];
    bytes[..8].copy_from_slice(&[0x0d, 0x0a, 0x00, 0x7f, b'D', b'W', b'1', b'E']);
    bytes[8..16].copy_from_slice(&nonce.to_le_bytes());
    bytes[16..24].copy_from_slice(&nonce.rotate_left(17).to_le_bytes());
    bytes
}

pub fn response(input: &[u8; CHALLENGE_BYTES]) -> [u8; RESPONSE_BYTES] {
    let mut output = [0u8; RESPONSE_BYTES];
    let mut index = 0;
    while index != input.len() {
        output[index] = input[input.len() - 1 - index] ^ (0xa5u8.wrapping_add(index as u8));
        index += 1;
    }
    output
}

pub const fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut index = 0;
    while index != bytes.len() {
        hash ^= bytes[index] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        index += 1;
    }
    hash
}

const fn message_type(message: ControllerMessage) -> u16 {
    match message {
        ControllerMessage::Configure { .. } => 1,
        ControllerMessage::Attached { .. } => 2,
        ControllerMessage::ArmPermit { .. } => 3,
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
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("fixed WRE3 field"),
    )
}
fn get32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed WRE3 field"),
    )
}
fn get64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed WRE3 field"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_is_binary_safe_nonce_bound_and_response_is_exact() {
        let first = challenge(0x0123_4567_89ab_cdef);
        let second = challenge(0xfedc_ba98_7654_3210);
        assert_ne!(first, second);
        for byte in [0x0d, 0x0a, 0x00, 0x7f, b'D'] {
            assert!(first.contains(&byte));
        }
        assert_ne!(response(&first), first);
        assert_ne!(fnv1a64(&response(&first)), fnv1a64(&first));
    }

    #[test]
    fn controller_records_round_trip_and_reject_reserved_bytes() {
        let message = ControllerMessage::ArmPermit {
            nonce: 1,
            publication_generation: 2,
            stream_generation: 3,
            challenge_generation: 4,
            expected_length: CHALLENGE_BYTES as u64,
            expected_hash: 5,
        };
        let mut bytes = [0; CONTROL_BYTES];
        encode(message, &mut bytes).unwrap();
        assert_eq!(parse(&bytes), Ok(message));
        bytes[79] = 1;
        assert_eq!(parse(&bytes), Err(ProtocolError::NonzeroReserved));
    }

    #[test]
    fn devmgr_config_and_ready_are_directional_and_generation_exact() {
        let config = DevmgrConfig {
            nonce: 7,
            publication_generation: 9,
        };
        let mut bytes = [0; DEVMGR_CONFIG_BYTES];
        encode_devmgr_config(config, &mut bytes).unwrap();
        assert_eq!(parse_devmgr_config(&bytes), Ok(config));
        assert_eq!(parse_devmgr_ready(&bytes), Err(ProtocolError::WrongType));

        let ready = DevmgrReady {
            nonce: config.nonce,
            publication_generation: config.publication_generation,
        };
        encode_devmgr_ready(ready, &mut bytes).unwrap();
        assert_eq!(parse_devmgr_ready(&bytes), Ok(ready));
        assert_eq!(parse_devmgr_config(&bytes), Err(ProtocolError::WrongType));
        bytes[47] = 1;
        assert_eq!(
            parse_devmgr_ready(&bytes),
            Err(ProtocolError::NonzeroReserved)
        );
    }
}
