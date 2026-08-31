//! Byte-defined, allocation-free WRST v1 records.
//!
//! This crate has no syscall dependency: callers supply complete Channel
//! datagrams and account for moved handles separately.

#![no_std]
#![forbid(unsafe_code)]

/// Exact WRST v1 header size.
pub const HEADER_BYTES: usize = 24;
/// Largest admitted DATA payload.
pub const MAX_PAYLOAD_BYTES: usize = 1024;
/// Largest complete WRST datagram.
pub const MAX_RECORD_BYTES: usize = HEADER_BYTES + MAX_PAYLOAD_BYTES;

const MAGIC: [u8; 4] = *b"WRST";
const MAJOR: u16 = 1;
const MINOR: u16 = 0;
const DATA: u16 = 1;

/// A validated DATA payload borrowed from one complete Channel datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Data<'a> {
    payload: &'a [u8],
}

impl<'a> Data<'a> {
    /// Returns stream bytes; an empty payload is a valid no-op.
    pub const fn payload(self) -> &'a [u8] {
        self.payload
    }
}

/// A malformed or unsupported WRST datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    TooShort,
    Magic,
    Version,
    HeaderBytes,
    MessageType,
    Flags,
    PayloadTooLarge,
    SizeMismatch,
    Reserved,
}

/// Encodes one DATA record into `output` and returns its exact initialized size.
pub fn encode_data(payload: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(Error::PayloadTooLarge);
    }
    let size = HEADER_BYTES
        .checked_add(payload.len())
        .ok_or(Error::SizeMismatch)?;
    if output.len() < size {
        return Err(Error::SizeMismatch);
    }
    output[..size].fill(0);
    output[0..4].copy_from_slice(&MAGIC);
    put_u16(output, 4, MAJOR);
    put_u16(output, 6, MINOR);
    put_u16(output, 8, HEADER_BYTES as u16);
    put_u16(output, 10, DATA);
    put_u32(output, 16, payload.len() as u32);
    output[HEADER_BYTES..size].copy_from_slice(payload);
    Ok(size)
}

/// Parses exactly one complete handle-free WRST DATA record.
pub fn decode_data(bytes: &[u8]) -> Result<Data<'_>, Error> {
    if bytes.len() < HEADER_BYTES {
        return Err(Error::TooShort);
    }
    if bytes[0..4] != MAGIC {
        return Err(Error::Magic);
    }
    if get_u16(bytes, 4) != MAJOR || get_u16(bytes, 6) != MINOR {
        return Err(Error::Version);
    }
    if get_u16(bytes, 8) as usize != HEADER_BYTES {
        return Err(Error::HeaderBytes);
    }
    if get_u16(bytes, 10) != DATA {
        return Err(Error::MessageType);
    }
    if get_u32(bytes, 12) != 0 {
        return Err(Error::Flags);
    }
    let payload = get_u32(bytes, 16) as usize;
    if payload > MAX_PAYLOAD_BYTES {
        return Err(Error::PayloadTooLarge);
    }
    if get_u32(bytes, 20) != 0 {
        return Err(Error::Reserved);
    }
    let end = HEADER_BYTES
        .checked_add(payload)
        .ok_or(Error::SizeMismatch)?;
    if end != bytes.len() {
        return Err(Error::SizeMismatch);
    }
    Ok(Data {
        payload: &bytes[HEADER_BYTES..end],
    })
}

const fn get_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}
const fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}
fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip_arbitrary_bytes_and_boundary() {
        let mut record = [0u8; MAX_RECORD_BYTES];
        let mut payload = [0u8; MAX_PAYLOAD_BYTES];
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let size = encode_data(&payload, &mut record).unwrap();
        assert_eq!(size, MAX_RECORD_BYTES);
        assert_eq!(decode_data(&record).unwrap().payload(), payload);
    }
    #[test]
    fn malformed_header_corpus_fails_closed() {
        let mut record = [0u8; MAX_RECORD_BYTES];
        let size = encode_data(b"x", &mut record).unwrap();
        for (offset, value) in [(0, 0), (4, 2), (6, 1), (8, 0), (10, 2), (12, 1), (20, 1)] {
            let mut bad = record[..size].to_vec();
            bad[offset] = value;
            assert!(decode_data(&bad).is_err());
        }
        assert!(decode_data(&record[..size - 1]).is_err());
        let mut trailing = record[..size].to_vec();
        trailing.push(0);
        assert_eq!(decode_data(&trailing), Err(Error::SizeMismatch));
    }
}
