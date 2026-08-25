//! Narrow WYR1 launch/job protocol reservation.
//!
//! This crate freezes only a versioned, connection- and generation-scoped
//! envelope. It deliberately supplies no path resolution, launch operation,
//! PID namespace, signal model, descriptor inheritance, or WYR1-B behavior.

#![no_std]
#![forbid(unsafe_code)]

pub const ENVELOPE_BYTES: usize = 40;
const MAGIC: [u8; 4] = *b"WRLJ";
const MAJOR: u16 = 1;
const MINOR: u16 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reservation {
    pub connection_id: u64,
    pub generation: u64,
    pub transaction_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    WrongSize,
    WrongMagic,
    UnsupportedVersion,
    NonzeroReserved,
    ZeroIdentity,
}

pub fn encode(value: Reservation, output: &mut [u8]) -> Result<usize, Error> {
    if output.len() < ENVELOPE_BYTES {
        return Err(Error::WrongSize);
    }
    if value.connection_id == 0 || value.generation == 0 || value.transaction_id == 0 {
        return Err(Error::ZeroIdentity);
    }
    output[..ENVELOPE_BYTES].fill(0);
    output[..4].copy_from_slice(&MAGIC);
    output[4..6].copy_from_slice(&MAJOR.to_le_bytes());
    output[6..8].copy_from_slice(&MINOR.to_le_bytes());
    output[8..16].copy_from_slice(&value.connection_id.to_le_bytes());
    output[16..24].copy_from_slice(&value.generation.to_le_bytes());
    output[24..32].copy_from_slice(&value.transaction_id.to_le_bytes());
    Ok(ENVELOPE_BYTES)
}

pub fn parse(bytes: &[u8]) -> Result<Reservation, Error> {
    if bytes.len() != ENVELOPE_BYTES {
        return Err(Error::WrongSize);
    }
    if bytes[..4] != MAGIC {
        return Err(Error::WrongMagic);
    }
    if u16::from_le_bytes(bytes[4..6].try_into().unwrap()) != MAJOR
        || u16::from_le_bytes(bytes[6..8].try_into().unwrap()) != MINOR
    {
        return Err(Error::UnsupportedVersion);
    }
    if bytes[32..40] != [0; 8] {
        return Err(Error::NonzeroReserved);
    }
    let value = Reservation {
        connection_id: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        generation: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        transaction_id: u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
    };
    if value.connection_id == 0 || value.generation == 0 || value.transaction_id == 0 {
        return Err(Error::ZeroIdentity);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_envelope_is_generation_and_connection_scoped() {
        let value = Reservation {
            connection_id: 7,
            generation: 9,
            transaction_id: 11,
        };
        let mut bytes = [0xaa; ENVELOPE_BYTES];
        assert_eq!(encode(value, &mut bytes), Ok(ENVELOPE_BYTES));
        assert_eq!(parse(&bytes), Ok(value));
        for offset in [0, 4, 6, 32] {
            let mut malformed = bytes;
            malformed[offset] ^= 1;
            assert!(parse(&malformed).is_err());
        }
    }

    #[test]
    fn zero_or_wrong_sized_reservations_fail_closed() {
        let mut bytes = [0; ENVELOPE_BYTES];
        assert_eq!(
            encode(
                Reservation {
                    connection_id: 0,
                    generation: 1,
                    transaction_id: 1
                },
                &mut bytes
            ),
            Err(Error::ZeroIdentity)
        );
        assert_eq!(parse(&bytes[..39]), Err(Error::WrongSize));
    }
}
