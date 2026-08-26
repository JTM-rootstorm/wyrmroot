//! Selector-27-only WRTG v1 control/report protocol.

#![no_std]
#![forbid(unsafe_code)]

pub const RECORD_BYTES: usize = 96;
const MAGIC: [u8; 4] = *b"WRTG";
const MAJOR: u16 = 1;
const MINOR: u16 = 0;

pub const ECHO_SERVICE_NAME: &[u8] = b"test.wyr1-b.echo";
pub const ECHO_PROTOCOL_ID: u64 = 0x4F48_4345_3152_5957;
pub const ECHO_VERSION_MAJOR: u16 = 1;
pub const ECHO_VERSION_MINOR: u16 = 0;
/// Test-private role. It is gate content and is never RRC-A eligible.
pub const TEST_PRIVATE_PUBLISHER_ROLE_ID: u32 = 0xFFFF_001B;
pub const MAX_FAILURE_CLASS: u64 = 0x0000_FFFF;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum MessageType {
    ConfigurePublisher = 1,
    ConfigureRegistryClient = 2,
    ConfigureLaunchOwner = 3,
    ConfigureLaunchForeign = 4,
    Published = 5,
    Connected = 6,
    DirectChallenge = 7,
    DirectEcho = 8,
    Echoed = 9,
    Exchanged = 10,
    Retire = 11,
    Retired = 12,
    ProbeStale = 13,
    StaleRejected = 14,
    JobAccepted = 15,
    JobResult = 16,
    ProbeForeign = 17,
    ForeignRejected = 18,
    OrphanDisconnecting = 19,
    Done = 20,
    Failure = 255,
}

impl MessageType {
    fn parse(value: u32) -> Result<Self, Error> {
        Ok(match value {
            1 => Self::ConfigurePublisher,
            2 => Self::ConfigureRegistryClient,
            3 => Self::ConfigureLaunchOwner,
            4 => Self::ConfigureLaunchForeign,
            5 => Self::Published,
            6 => Self::Connected,
            7 => Self::DirectChallenge,
            8 => Self::DirectEcho,
            9 => Self::Echoed,
            10 => Self::Exchanged,
            11 => Self::Retire,
            12 => Self::Retired,
            13 => Self::ProbeStale,
            14 => Self::StaleRejected,
            15 => Self::JobAccepted,
            16 => Self::JobResult,
            17 => Self::ProbeForeign,
            18 => Self::ForeignRejected,
            19 => Self::OrphanDisconnecting,
            20 => Self::Done,
            255 => Self::Failure,
            _ => return Err(Error::UnknownType),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    InitToChild,
    ChildToInit,
    ClientToDirect,
    PublisherToDirect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Record {
    pub message_type: MessageType,
    pub nonce: u64,
    pub registry_generation: u64,
    pub actor_id: u64,
    pub actor_generation: u64,
    pub object_id: u64,
    pub object_generation: u64,
    pub operation_id: u64,
    pub value: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    WrongSize,
    WrongMagic,
    WrongVersion,
    UnknownType,
    NonzeroEnvelope,
    ZeroCommonIdentity,
    InvalidIdentityShape,
    InvalidOperation,
    InvalidValue,
    WrongDirection,
    ChallengeMismatch,
}

pub fn parse(bytes: &[u8]) -> Result<Record, Error> {
    if bytes.len() != RECORD_BYTES {
        return Err(Error::WrongSize);
    }
    if bytes[..4] != MAGIC {
        return Err(Error::WrongMagic);
    }
    if get16(bytes, 4) != MAJOR || get16(bytes, 6) != MINOR {
        return Err(Error::WrongVersion);
    }
    if get32(bytes, 12) != 0
        || get32(bytes, 16) != RECORD_BYTES as u32
        || get32(bytes, 20) != 0
        || get64(bytes, 88) != 0
    {
        return Err(Error::NonzeroEnvelope);
    }
    let record = Record {
        message_type: MessageType::parse(get32(bytes, 8))?,
        nonce: get64(bytes, 24),
        registry_generation: get64(bytes, 32),
        actor_id: get64(bytes, 40),
        actor_generation: get64(bytes, 48),
        object_id: get64(bytes, 56),
        object_generation: get64(bytes, 64),
        operation_id: get64(bytes, 72),
        value: get64(bytes, 80),
    };
    validate(record)?;
    Ok(record)
}

pub fn parse_for(bytes: &[u8], direction: Direction) -> Result<Record, Error> {
    let record = parse(bytes)?;
    if record.direction() != direction {
        return Err(Error::WrongDirection);
    }
    Ok(record)
}

pub fn encode(record: Record, output: &mut [u8]) -> Result<(), Error> {
    if output.len() != RECORD_BYTES {
        return Err(Error::WrongSize);
    }
    validate(record)?;
    output.fill(0);
    output[..4].copy_from_slice(&MAGIC);
    put16(output, 4, MAJOR);
    put16(output, 6, MINOR);
    put32(output, 8, record.message_type as u32);
    put32(output, 16, RECORD_BYTES as u32);
    for (offset, value) in [
        (24, record.nonce),
        (32, record.registry_generation),
        (40, record.actor_id),
        (48, record.actor_generation),
        (56, record.object_id),
        (64, record.object_generation),
        (72, record.operation_id),
        (80, record.value),
    ] {
        put64(output, offset, value);
    }
    Ok(())
}

impl Record {
    pub const fn direction(self) -> Direction {
        match self.message_type {
            MessageType::ConfigurePublisher
            | MessageType::ConfigureRegistryClient
            | MessageType::ConfigureLaunchOwner
            | MessageType::ConfigureLaunchForeign
            | MessageType::Retire
            | MessageType::ProbeStale
            | MessageType::ProbeForeign
            | MessageType::Done => Direction::InitToChild,
            MessageType::DirectChallenge => Direction::ClientToDirect,
            MessageType::DirectEcho => Direction::PublisherToDirect,
            _ => Direction::ChildToInit,
        }
    }
}

pub const fn challenge(record: Record) -> u64 {
    let (client, client_generation, publisher, publisher_generation) = match record.message_type {
        MessageType::DirectEcho | MessageType::Echoed => (
            record.object_id,
            record.object_generation,
            record.actor_id,
            record.actor_generation,
        ),
        _ => (
            record.actor_id,
            record.actor_generation,
            record.object_id,
            record.object_generation,
        ),
    };
    fnv1a64([
        record.nonce,
        record.registry_generation,
        client,
        client_generation,
        publisher,
        publisher_generation,
        record.operation_id,
    ])
}

fn validate(record: Record) -> Result<(), Error> {
    if record.nonce == 0 || record.registry_generation == 0 {
        return Err(Error::ZeroCommonIdentity);
    }
    let actor = record.actor_id != 0 && record.actor_generation != 0;
    let object = record.object_id != 0 && record.object_generation != 0;
    let no_object = record.object_id == 0 && record.object_generation == 0;
    let both_actor_zero = record.actor_id == 0 && record.actor_generation == 0;
    let shape_ok = match record.message_type {
        MessageType::ConfigureLaunchOwner | MessageType::Done => actor && no_object,
        MessageType::JobAccepted | MessageType::JobResult | MessageType::OrphanDisconnecting => {
            actor && object && record.object_generation == record.actor_generation
        }
        MessageType::Failure => {
            (actor && no_object) || (both_actor_zero && no_object && record.operation_id == 1)
        }
        _ => actor && object,
    };
    if !shape_ok {
        return Err(Error::InvalidIdentityShape);
    }
    let operation_ok = match record.message_type {
        MessageType::ConfigurePublisher
        | MessageType::ConfigureRegistryClient
        | MessageType::Published
        | MessageType::Connected
        | MessageType::DirectChallenge
        | MessageType::DirectEcho
        | MessageType::Echoed
        | MessageType::Exchanged => matches!(record.operation_id, 1 | 2),
        MessageType::Retire | MessageType::Retired => record.operation_id == 1,
        MessageType::ProbeStale | MessageType::StaleRejected => record.operation_id == 2,
        MessageType::ConfigureLaunchOwner => matches!(record.operation_id, 3 | 5),
        MessageType::ConfigureLaunchForeign
        | MessageType::ProbeForeign
        | MessageType::ForeignRejected => record.operation_id == 4,
        MessageType::JobAccepted | MessageType::JobResult => record.operation_id == 3,
        MessageType::OrphanDisconnecting => record.operation_id == 5,
        MessageType::Done | MessageType::Failure => matches!(record.operation_id, 1..=5),
    };
    if !operation_ok {
        return Err(Error::InvalidOperation);
    }
    let challenge_value = matches!(
        record.message_type,
        MessageType::DirectChallenge
            | MessageType::DirectEcho
            | MessageType::Echoed
            | MessageType::Exchanged
    );
    if (!challenge_value && record.message_type != MessageType::Failure && record.value != 0)
        || (record.message_type == MessageType::Failure
            && (record.value == 0 || record.value > MAX_FAILURE_CLASS))
    {
        return Err(Error::InvalidValue);
    }
    if challenge_value && record.value != challenge(record) {
        return Err(Error::ChallengeMismatch);
    }
    Ok(())
}

pub const fn fnv1a64(values: [u64; 7]) -> u64 {
    let mut hash = 0xCBF2_9CE4_8422_2325u64;
    let mut i = 0;
    while i < values.len() {
        let bytes = values[i].to_le_bytes();
        let mut j = 0;
        while j < bytes.len() {
            hash ^= bytes[j] as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
            j += 1;
        }
        i += 1;
    }
    hash
}

fn get16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn get32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn get64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(message_type: MessageType) -> Record {
        Record {
            message_type,
            nonce: 1,
            registry_generation: 2,
            actor_id: 3,
            actor_generation: 4,
            object_id: 5,
            object_generation: 6,
            operation_id: 1,
            value: 0,
        }
    }

    #[test]
    fn golden_direct_challenge_is_exact_and_direction_bound() {
        assert_eq!(fnv1a64([1, 2, 3, 4, 5, 6, 1]), 0x4322_F621_3655_B843);
        let mut value = record(MessageType::DirectChallenge);
        value.value = challenge(value);
        let mut bytes = [0u8; RECORD_BYTES];
        encode(value, &mut bytes).unwrap();
        assert_eq!(&bytes[..8], b"WRTG\x01\x00\x00\x00");
        assert_eq!(parse_for(&bytes, Direction::ClientToDirect), Ok(value));
        assert_eq!(
            parse_for(&bytes, Direction::PublisherToDirect),
            Err(Error::WrongDirection)
        );
        bytes[80] ^= 1;
        assert_eq!(
            parse_for(&bytes, Direction::ClientToDirect),
            Err(Error::ChallengeMismatch)
        );
    }

    #[test]
    fn all_types_have_exact_shapes_operations_and_directions() {
        for kind in 1u32..=20 {
            let message_type = MessageType::parse(kind).unwrap();
            let mut value = record(message_type);
            value.operation_id = match message_type {
                MessageType::ConfigureLaunchOwner => 3,
                MessageType::ConfigureLaunchForeign
                | MessageType::ProbeForeign
                | MessageType::ForeignRejected => 4,
                MessageType::JobAccepted | MessageType::JobResult => 3,
                MessageType::OrphanDisconnecting => 5,
                MessageType::ProbeStale | MessageType::StaleRejected => 2,
                _ => 1,
            };
            if matches!(
                message_type,
                MessageType::ConfigureLaunchOwner | MessageType::Done
            ) {
                value.object_id = 0;
                value.object_generation = 0;
            }
            if matches!(
                message_type,
                MessageType::JobAccepted
                    | MessageType::JobResult
                    | MessageType::OrphanDisconnecting
            ) {
                value.object_generation = value.actor_generation;
            }
            if matches!(
                message_type,
                MessageType::DirectChallenge
                    | MessageType::DirectEcho
                    | MessageType::Echoed
                    | MessageType::Exchanged
            ) {
                value.value = challenge(value);
            }
            let mut bytes = [0u8; RECORD_BYTES];
            encode(value, &mut bytes).unwrap();
            assert_eq!(parse_for(&bytes, value.direction()), Ok(value));
        }
    }

    #[test]
    fn malformed_envelope_identity_operation_and_value_fail_closed() {
        let base = record(MessageType::Published);
        for malformed in [
            Record { nonce: 0, ..base },
            Record {
                actor_id: 0,
                ..base
            },
            Record {
                object_generation: 0,
                ..base
            },
            Record {
                operation_id: 3,
                ..base
            },
            Record { value: 1, ..base },
        ] {
            let mut bytes = [0u8; RECORD_BYTES];
            assert!(encode(malformed, &mut bytes).is_err());
        }
        let mut bytes = [0u8; RECORD_BYTES];
        encode(base, &mut bytes).unwrap();
        for offset in [0usize, 4, 8, 12, 16, 20, 88] {
            let mut malformed = bytes;
            malformed[offset] ^= 1;
            assert!(parse(&malformed).is_err(), "offset {offset}");
        }
    }

    #[test]
    fn failure_has_only_the_one_preconfigure_identity_exception() {
        let configured = Record {
            message_type: MessageType::Failure,
            object_id: 0,
            object_generation: 0,
            operation_id: 5,
            value: 1,
            ..record(MessageType::Failure)
        };
        let mut bytes = [0u8; RECORD_BYTES];
        encode(configured, &mut bytes).unwrap();
        let startup = Record {
            actor_id: 0,
            actor_generation: 0,
            operation_id: 1,
            ..configured
        };
        encode(startup, &mut bytes).unwrap();
        assert_eq!(parse_for(&bytes, Direction::ChildToInit), Ok(startup));
        encode(
            Record {
                value: MAX_FAILURE_CLASS,
                ..startup
            },
            &mut bytes,
        )
        .unwrap();
        assert_eq!(
            encode(
                Record {
                    value: 0,
                    ..startup
                },
                &mut bytes
            ),
            Err(Error::InvalidValue)
        );
        assert_eq!(
            encode(
                Record {
                    value: MAX_FAILURE_CLASS + 1,
                    ..startup
                },
                &mut bytes,
            ),
            Err(Error::InvalidValue)
        );
        assert_eq!(
            encode(
                Record {
                    operation_id: 2,
                    ..startup
                },
                &mut bytes
            ),
            Err(Error::InvalidIdentityShape)
        );
    }

    #[test]
    fn launch_reports_bind_object_generation_to_actor_generation() {
        for message_type in [
            MessageType::JobAccepted,
            MessageType::JobResult,
            MessageType::OrphanDisconnecting,
        ] {
            let operation_id = if message_type == MessageType::OrphanDisconnecting {
                5
            } else {
                3
            };
            let valid = Record {
                message_type,
                actor_generation: 9,
                object_generation: 9,
                operation_id,
                ..record(message_type)
            };
            let mut bytes = [0; RECORD_BYTES];
            encode(valid, &mut bytes).unwrap();
            assert_eq!(
                encode(
                    Record {
                        object_generation: 10,
                        ..valid
                    },
                    &mut bytes,
                ),
                Err(Error::InvalidIdentityShape)
            );
        }
    }
}
