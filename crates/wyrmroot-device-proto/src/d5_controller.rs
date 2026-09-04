//! Selector-private WDR5 v1.0 devmgr/controller relay records.
//!
//! The D5 acceptance controller receives correlation-exact driver publication
//! facts, requests intentional U1 retirement, and relays the exact old stream
//! identity after the client endpoint has been closed. This is test-selector
//! coordination only; it is not a public device protocol.

pub const MAGIC: [u8; 4] = *b"WDR5";
pub const MAJOR: u16 = 1;
pub const MINOR: u16 = 0;
pub const RECORD_BYTES: usize = 96;

const DRIVER_READY: u16 = 1;
const REQUEST_RETIRE: u16 = 2;
const CLIENT_RELEASED: u16 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D5DriverIdentity {
    pub device_role_id: u64,
    pub bundle_generation: u64,
    pub driver_attempt_generation: u64,
    pub driver_control_endpoint_id: u64,
    pub driver_control_endpoint_generation: u64,
    pub launch_transaction_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D5StreamIdentity {
    pub driver: D5DriverIdentity,
    pub publication_generation: u64,
    pub client_transaction_id: u64,
    pub attach_transaction_id: u64,
    pub stream_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum D5ControllerMessage {
    DriverReady(D5DriverIdentity),
    RequestRetire(D5DriverIdentity),
    ClientReleased(D5StreamIdentity),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum D5ControllerParseError {
    WrongSize,
    WrongMagic,
    WrongVersion,
    UnknownMessage,
    NonzeroFlags,
    ZeroIdentity,
    NonzeroReserved,
}

pub fn encode(
    message: D5ControllerMessage,
    output: &mut [u8],
) -> Result<(), D5ControllerParseError> {
    if output.len() != RECORD_BYTES {
        return Err(D5ControllerParseError::WrongSize);
    }
    validate(message)?;
    output.fill(0);
    output[..4].copy_from_slice(&MAGIC);
    put16(output, 4, MAJOR);
    put16(output, 6, MINOR);
    put16(output, 8, message_type(message));
    put32(output, 12, RECORD_BYTES as u32);
    put_driver(output, driver_identity(message));
    if let D5ControllerMessage::ClientReleased(identity) = message {
        put64(output, 64, identity.publication_generation);
        put64(output, 72, identity.client_transaction_id);
        put64(output, 80, identity.attach_transaction_id);
        put64(output, 88, identity.stream_generation);
    }
    Ok(())
}

pub fn parse(bytes: &[u8]) -> Result<D5ControllerMessage, D5ControllerParseError> {
    if bytes.len() != RECORD_BYTES {
        return Err(D5ControllerParseError::WrongSize);
    }
    if bytes[..4] != MAGIC {
        return Err(D5ControllerParseError::WrongMagic);
    }
    if get16(bytes, 4) != MAJOR || get16(bytes, 6) != MINOR {
        return Err(D5ControllerParseError::WrongVersion);
    }
    if get16(bytes, 10) != 0 {
        return Err(D5ControllerParseError::NonzeroFlags);
    }
    if get32(bytes, 12) != RECORD_BYTES as u32 {
        return Err(D5ControllerParseError::WrongSize);
    }
    let driver = get_driver(bytes);
    let message = match get16(bytes, 8) {
        DRIVER_READY => {
            require_zero(&bytes[64..])?;
            D5ControllerMessage::DriverReady(driver)
        }
        REQUEST_RETIRE => {
            require_zero(&bytes[64..])?;
            D5ControllerMessage::RequestRetire(driver)
        }
        CLIENT_RELEASED => D5ControllerMessage::ClientReleased(D5StreamIdentity {
            driver,
            publication_generation: get64(bytes, 64),
            client_transaction_id: get64(bytes, 72),
            attach_transaction_id: get64(bytes, 80),
            stream_generation: get64(bytes, 88),
        }),
        _ => return Err(D5ControllerParseError::UnknownMessage),
    };
    validate(message)?;
    Ok(message)
}

fn validate(message: D5ControllerMessage) -> Result<(), D5ControllerParseError> {
    let driver = driver_identity(message);
    if [
        driver.device_role_id,
        driver.bundle_generation,
        driver.driver_attempt_generation,
        driver.driver_control_endpoint_id,
        driver.driver_control_endpoint_generation,
        driver.launch_transaction_id,
    ]
    .into_iter()
    .any(|value| value == 0)
    {
        return Err(D5ControllerParseError::ZeroIdentity);
    }
    if let D5ControllerMessage::ClientReleased(identity) = message
        && [
            identity.publication_generation,
            identity.client_transaction_id,
            identity.attach_transaction_id,
            identity.stream_generation,
        ]
        .into_iter()
        .any(|value| value == 0)
    {
        return Err(D5ControllerParseError::ZeroIdentity);
    }
    Ok(())
}

const fn message_type(message: D5ControllerMessage) -> u16 {
    match message {
        D5ControllerMessage::DriverReady(_) => DRIVER_READY,
        D5ControllerMessage::RequestRetire(_) => REQUEST_RETIRE,
        D5ControllerMessage::ClientReleased(_) => CLIENT_RELEASED,
    }
}

const fn driver_identity(message: D5ControllerMessage) -> D5DriverIdentity {
    match message {
        D5ControllerMessage::DriverReady(identity)
        | D5ControllerMessage::RequestRetire(identity) => identity,
        D5ControllerMessage::ClientReleased(identity) => identity.driver,
    }
}

fn put_driver(output: &mut [u8], identity: D5DriverIdentity) {
    put64(output, 16, identity.device_role_id);
    put64(output, 24, identity.bundle_generation);
    put64(output, 32, identity.driver_attempt_generation);
    put64(output, 40, identity.driver_control_endpoint_id);
    put64(output, 48, identity.driver_control_endpoint_generation);
    put64(output, 56, identity.launch_transaction_id);
}

fn get_driver(bytes: &[u8]) -> D5DriverIdentity {
    D5DriverIdentity {
        device_role_id: get64(bytes, 16),
        bundle_generation: get64(bytes, 24),
        driver_attempt_generation: get64(bytes, 32),
        driver_control_endpoint_id: get64(bytes, 40),
        driver_control_endpoint_generation: get64(bytes, 48),
        launch_transaction_id: get64(bytes, 56),
    }
}

fn require_zero(bytes: &[u8]) -> Result<(), D5ControllerParseError> {
    if bytes.iter().any(|value| *value != 0) {
        Err(D5ControllerParseError::NonzeroReserved)
    } else {
        Ok(())
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
            .expect("fixed WDR5 field"),
    )
}

fn get32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed WDR5 field"),
    )
}

fn get64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed WDR5 field"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const DRIVER: D5DriverIdentity = D5DriverIdentity {
        device_role_id: 1,
        bundle_generation: 2,
        driver_attempt_generation: 3,
        driver_control_endpoint_id: 4,
        driver_control_endpoint_generation: 5,
        launch_transaction_id: 6,
    };

    const STREAM: D5StreamIdentity = D5StreamIdentity {
        driver: DRIVER,
        publication_generation: 7,
        client_transaction_id: 8,
        attach_transaction_id: 9,
        stream_generation: 10,
    };

    fn roundtrip(message: D5ControllerMessage) {
        let mut bytes = [0u8; RECORD_BYTES];
        encode(message, &mut bytes).unwrap();
        assert_eq!(parse(&bytes), Ok(message));
    }

    #[test]
    fn all_messages_roundtrip_as_one_exact_no_handle_record() {
        roundtrip(D5ControllerMessage::DriverReady(DRIVER));
        roundtrip(D5ControllerMessage::RequestRetire(DRIVER));
        roundtrip(D5ControllerMessage::ClientReleased(STREAM));
    }

    #[test]
    fn driver_messages_require_zero_stream_tail() {
        let mut bytes = [0u8; RECORD_BYTES];
        encode(D5ControllerMessage::DriverReady(DRIVER), &mut bytes).unwrap();
        bytes[88] = 1;
        assert_eq!(parse(&bytes), Err(D5ControllerParseError::NonzeroReserved));
    }

    #[test]
    fn malformed_header_and_zero_identities_are_rejected() {
        let mut bytes = [0u8; RECORD_BYTES];
        encode(D5ControllerMessage::ClientReleased(STREAM), &mut bytes).unwrap();
        bytes[0] = b'X';
        assert_eq!(parse(&bytes), Err(D5ControllerParseError::WrongMagic));
        bytes[0] = b'W';
        bytes[32..40].fill(0);
        assert_eq!(parse(&bytes), Err(D5ControllerParseError::ZeroIdentity));
    }

    #[test]
    fn wrong_size_version_and_message_are_rejected() {
        let mut bytes = [0u8; RECORD_BYTES];
        encode(D5ControllerMessage::RequestRetire(DRIVER), &mut bytes).unwrap();
        assert_eq!(
            parse(&bytes[..RECORD_BYTES - 1]),
            Err(D5ControllerParseError::WrongSize)
        );
        bytes[4] = 2;
        assert_eq!(parse(&bytes), Err(D5ControllerParseError::WrongVersion));
        bytes[4] = 1;
        bytes[8..12].copy_from_slice(&99u32.to_le_bytes());
        assert_eq!(parse(&bytes), Err(D5ControllerParseError::UnknownMessage));
    }
}
