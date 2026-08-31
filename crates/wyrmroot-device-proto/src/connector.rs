//! Fixed WRSC 1.1 direct serial connector records.

pub const MAGIC: [u8; 4] = *b"WRSC";
pub const MAJOR: u16 = 1;
pub const MINOR: u16 = 1;
pub const RECORD_BYTES: usize = 128;
pub const CLIENT_STREAM_HANDLE_COUNT: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorIdentity {
    pub publication_generation: u64,
    pub client_transaction_id: u64,
    pub device_role_id: u64,
    pub bundle_generation: u64,
    pub driver_attempt_generation: u64,
    pub driver_control_endpoint_id: u64,
    pub driver_control_endpoint_generation: u64,
    pub attach_transaction_id: u64,
    pub stream_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorErrorCode {
    Busy = 1,
    NotReady = 2,
    Stale = 3,
    InternalFailure = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorMessage {
    ConnectStream {
        publication_generation: u64,
        client_transaction_id: u64,
    },
    Connected {
        identity: ConnectorIdentity,
    },
    Error {
        publication_generation: u64,
        client_transaction_id: u64,
        code: ConnectorErrorCode,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorParseError {
    WrongSize,
    WrongMagic,
    WrongVersion,
    UnknownMessage,
    NonzeroFlags,
    WrongHandleCount,
    ZeroIdentity,
    InvalidResult,
    NonzeroReserved,
}

impl ConnectorMessage {
    pub const fn handle_count(self) -> u32 {
        match self {
            Self::Connected { .. } => CLIENT_STREAM_HANDLE_COUNT,
            _ => 0,
        }
    }
}

pub fn encode(message: ConnectorMessage, output: &mut [u8]) -> Result<(), ConnectorParseError> {
    if output.len() != RECORD_BYTES {
        return Err(ConnectorParseError::WrongSize);
    }
    validate(message)?;
    output.fill(0);
    output[..4].copy_from_slice(&MAGIC);
    put16(output, 4, MAJOR);
    put16(output, 6, MINOR);
    put32(output, 8, message_type(message));
    put32(output, 16, RECORD_BYTES as u32);
    put32(output, 20, message.handle_count());
    match message {
        ConnectorMessage::ConnectStream {
            publication_generation,
            client_transaction_id,
        } => {
            put64(output, 24, publication_generation);
            put64(output, 32, client_transaction_id);
        }
        ConnectorMessage::Connected { identity } => put_identity(output, identity),
        ConnectorMessage::Error {
            publication_generation,
            client_transaction_id,
            code,
        } => {
            put64(output, 24, publication_generation);
            put64(output, 32, client_transaction_id);
            put32(output, 96, code as u32);
        }
    }
    Ok(())
}

pub fn parse(bytes: &[u8]) -> Result<ConnectorMessage, ConnectorParseError> {
    if bytes.len() != RECORD_BYTES {
        return Err(ConnectorParseError::WrongSize);
    }
    if bytes[..4] != MAGIC {
        return Err(ConnectorParseError::WrongMagic);
    }
    if get16(bytes, 4) != MAJOR || get16(bytes, 6) != MINOR {
        return Err(ConnectorParseError::WrongVersion);
    }
    if get32(bytes, 12) != 0 {
        return Err(ConnectorParseError::NonzeroFlags);
    }
    if get32(bytes, 16) != RECORD_BYTES as u32 {
        return Err(ConnectorParseError::WrongSize);
    }
    if bytes[100..].iter().any(|value| *value != 0) {
        return Err(ConnectorParseError::NonzeroReserved);
    }
    let handles = get32(bytes, 20);
    let publication_generation = get64(bytes, 24);
    let client_transaction_id = get64(bytes, 32);
    let message = match get32(bytes, 8) {
        1 => {
            if handles != 0 {
                return Err(ConnectorParseError::WrongHandleCount);
            }
            if bytes[40..100].iter().any(|value| *value != 0) {
                return Err(ConnectorParseError::NonzeroReserved);
            }
            ConnectorMessage::ConnectStream {
                publication_generation,
                client_transaction_id,
            }
        }
        2 => {
            if handles != CLIENT_STREAM_HANDLE_COUNT {
                return Err(ConnectorParseError::WrongHandleCount);
            }
            if get32(bytes, 96) != 0 {
                return Err(ConnectorParseError::InvalidResult);
            }
            ConnectorMessage::Connected {
                identity: get_identity(bytes),
            }
        }
        3 => {
            if handles != 0 {
                return Err(ConnectorParseError::WrongHandleCount);
            }
            if bytes[40..96].iter().any(|value| *value != 0) {
                return Err(ConnectorParseError::NonzeroReserved);
            }
            let code = match get32(bytes, 96) {
                1 => ConnectorErrorCode::Busy,
                2 => ConnectorErrorCode::NotReady,
                3 => ConnectorErrorCode::Stale,
                4 => ConnectorErrorCode::InternalFailure,
                _ => return Err(ConnectorParseError::InvalidResult),
            };
            ConnectorMessage::Error {
                publication_generation,
                client_transaction_id,
                code,
            }
        }
        _ => return Err(ConnectorParseError::UnknownMessage),
    };
    validate(message)?;
    Ok(message)
}

fn validate(message: ConnectorMessage) -> Result<(), ConnectorParseError> {
    let valid = match message {
        ConnectorMessage::ConnectStream {
            publication_generation,
            client_transaction_id,
        }
        | ConnectorMessage::Error {
            publication_generation,
            client_transaction_id,
            ..
        } => publication_generation != 0 && client_transaction_id != 0,
        ConnectorMessage::Connected { identity } => [
            identity.publication_generation,
            identity.client_transaction_id,
            identity.device_role_id,
            identity.bundle_generation,
            identity.driver_attempt_generation,
            identity.driver_control_endpoint_id,
            identity.driver_control_endpoint_generation,
            identity.attach_transaction_id,
            identity.stream_generation,
        ]
        .into_iter()
        .all(|value| value != 0),
    };
    if valid {
        Ok(())
    } else {
        Err(ConnectorParseError::ZeroIdentity)
    }
}

const fn message_type(message: ConnectorMessage) -> u32 {
    match message {
        ConnectorMessage::ConnectStream { .. } => 1,
        ConnectorMessage::Connected { .. } => 2,
        ConnectorMessage::Error { .. } => 3,
    }
}

fn put_identity(output: &mut [u8], identity: ConnectorIdentity) {
    put64(output, 24, identity.publication_generation);
    put64(output, 32, identity.client_transaction_id);
    put64(output, 40, identity.device_role_id);
    put64(output, 48, identity.bundle_generation);
    put64(output, 56, identity.driver_attempt_generation);
    put64(output, 64, identity.driver_control_endpoint_id);
    put64(output, 72, identity.driver_control_endpoint_generation);
    put64(output, 80, identity.attach_transaction_id);
    put64(output, 88, identity.stream_generation);
}

fn get_identity(bytes: &[u8]) -> ConnectorIdentity {
    ConnectorIdentity {
        publication_generation: get64(bytes, 24),
        client_transaction_id: get64(bytes, 32),
        device_role_id: get64(bytes, 40),
        bundle_generation: get64(bytes, 48),
        driver_attempt_generation: get64(bytes, 56),
        driver_control_endpoint_id: get64(bytes, 64),
        driver_control_endpoint_generation: get64(bytes, 72),
        attach_transaction_id: get64(bytes, 80),
        stream_generation: get64(bytes, 88),
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
            .expect("fixed connector field"),
    )
}
fn get32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed connector field"),
    )
}
fn get64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed connector field"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> ConnectorIdentity {
        ConnectorIdentity {
            publication_generation: 1,
            client_transaction_id: 2,
            device_role_id: 3,
            bundle_generation: 4,
            driver_attempt_generation: 5,
            driver_control_endpoint_id: 6,
            driver_control_endpoint_generation: 7,
            attach_transaction_id: 8,
            stream_generation: 9,
        }
    }

    #[test]
    fn all_connector_records_round_trip() {
        for message in [
            ConnectorMessage::ConnectStream {
                publication_generation: 1,
                client_transaction_id: 2,
            },
            ConnectorMessage::Connected {
                identity: identity(),
            },
            ConnectorMessage::Error {
                publication_generation: 1,
                client_transaction_id: 2,
                code: ConnectorErrorCode::Busy,
            },
        ] {
            let mut bytes = [0; RECORD_BYTES];
            encode(message, &mut bytes).unwrap();
            assert_eq!(parse(&bytes), Ok(message));
        }
    }

    #[test]
    fn connector_rejects_minor_zero_extra_handles_and_reserved_data() {
        let mut bytes = [0; RECORD_BYTES];
        encode(
            ConnectorMessage::ConnectStream {
                publication_generation: 1,
                client_transaction_id: 2,
            },
            &mut bytes,
        )
        .unwrap();
        bytes[6] = 0;
        assert_eq!(parse(&bytes), Err(ConnectorParseError::WrongVersion));
        bytes[6] = 1;
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(parse(&bytes), Err(ConnectorParseError::WrongHandleCount));
        bytes[20..24].fill(0);
        bytes[127] = 1;
        assert_eq!(parse(&bytes), Err(ConnectorParseError::NonzeroReserved));
    }
}
