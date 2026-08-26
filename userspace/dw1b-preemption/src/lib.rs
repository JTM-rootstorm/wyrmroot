#![no_std]
#![forbid(unsafe_code)]

//! Selector-26-only payloads and fixed handle-free challenge protocol.

#[cfg(feature = "native-payloads")]
use core::convert::Infallible;
use deepwyrm_syscall as _;
#[cfg(feature = "native-payloads")]
use deepwyrm_syscall::{DwHandle, DwReceivedHandleInfoV1};
use wyrmroot_loader as _;
#[cfg(feature = "native-payloads")]
use wyrmroot_loader::launch::{HEADER_BYTES, LaunchProfile, encode_ready_for_profile, parse_init};
use wyrmroot_runtime as _;
#[cfg(feature = "native-payloads")]
use wyrmroot_runtime::{close_handle, receive_channel, send_channel, submit_dw1b_progress};

pub const ROUND_COUNT: usize = 8;
pub const RECORD_BYTES: usize = 32;
pub const CHALLENGE_DIGEST: u64 = 0x5E4E_054B_5C24_4ACE;
pub const HOG_TRANSACTION_ID: u64 = 0xD1B0_0001;
pub const PROGRESS_TRANSACTION_ID: u64 = 0xD1B0_0002;

const MAGIC: &[u8; 4] = b"DWP1";
const VERSION: u16 = 1;
const CHALLENGE: u16 = 1;
const REPLY: u16 = 2;
const CHALLENGES: [u64; ROUND_COUNT] = [
    0x4447_3142_0000_0001,
    0x4447_3142_0000_0002,
    0x4447_3142_0000_0004,
    0x4447_3142_0000_0008,
    0x4447_3142_0000_0010,
    0x4447_3142_0000_0020,
    0x4447_3142_0000_0040,
    0x4447_3142_0000_0080,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    Framing,
    Round,
    Value,
}

#[must_use]
pub const fn challenge(round: usize) -> u64 {
    CHALLENGES[round]
}

#[must_use]
pub const fn reply(round: usize) -> u64 {
    challenge(round).rotate_left((round + 1) as u32) ^ 0xD15E_A5E5_C0DE_C0DE
}

#[must_use]
pub fn encode_challenge(round: usize) -> [u8; RECORD_BYTES] {
    encode(CHALLENGE, round, challenge(round), 0)
}

#[must_use]
pub fn encode_reply(round: usize) -> [u8; RECORD_BYTES] {
    encode(REPLY, round, challenge(round), reply(round))
}

pub fn parse_challenge(bytes: &[u8], expected_round: usize) -> Result<(), ProtocolError> {
    parse(
        bytes,
        CHALLENGE,
        expected_round,
        challenge(expected_round),
        0,
    )
}

pub fn parse_reply(bytes: &[u8], expected_round: usize) -> Result<(), ProtocolError> {
    parse(
        bytes,
        REPLY,
        expected_round,
        challenge(expected_round),
        reply(expected_round),
    )
}

fn encode(kind: u16, round: usize, challenge: u64, response: u64) -> [u8; RECORD_BYTES] {
    let mut out = [0; RECORD_BYTES];
    out[..4].copy_from_slice(MAGIC);
    out[4..6].copy_from_slice(&VERSION.to_le_bytes());
    out[6..8].copy_from_slice(&kind.to_le_bytes());
    out[8..12].copy_from_slice(&(RECORD_BYTES as u32).to_le_bytes());
    out[12..16].copy_from_slice(&(round as u32).to_le_bytes());
    out[16..24].copy_from_slice(&challenge.to_le_bytes());
    out[24..32].copy_from_slice(&response.to_le_bytes());
    out
}

fn parse(
    bytes: &[u8],
    kind: u16,
    round: usize,
    challenge: u64,
    response: u64,
) -> Result<(), ProtocolError> {
    if bytes.len() != RECORD_BYTES
        || &bytes[..4] != MAGIC
        || u16::from_le_bytes([bytes[4], bytes[5]]) != VERSION
        || u16::from_le_bytes([bytes[6], bytes[7]]) != kind
        || u32::from_le_bytes(bytes[8..12].try_into().unwrap()) != RECORD_BYTES as u32
    {
        return Err(ProtocolError::Framing);
    }
    if u32::from_le_bytes(bytes[12..16].try_into().unwrap()) != round as u32 {
        return Err(ProtocolError::Round);
    }
    if u64::from_le_bytes(bytes[16..24].try_into().unwrap()) != challenge
        || u64::from_le_bytes(bytes[24..32].try_into().unwrap()) != response
    {
        return Err(ProtocolError::Value);
    }
    Ok(())
}

/// Runs the CPU hog. The executed terminal loop contains no call, syscall,
/// yield, memory access, or blocking instruction.
#[cfg(feature = "native-payloads")]
pub fn run_cpu_hog(channel: DwHandle) -> Result<Infallible, u32> {
    receive_startup_and_ready(channel, HOG_TRANSACTION_ID)?;
    close_handle(channel).map_err(|_| 0xD1B0_0104_u32)?;
    loop {
        core::hint::spin_loop();
    }
}

/// Runs the progress peer and attests only after all eight exact replies.
#[cfg(feature = "native-payloads")]
pub fn run_progress(channel: DwHandle) -> Result<(), u32> {
    receive_startup_and_ready(channel, PROGRESS_TRANSACTION_ID)?;
    for round in 0..ROUND_COUNT {
        let mut bytes = [0; RECORD_BYTES];
        let mut handles = [];
        let counts =
            receive_channel(channel, &mut bytes, &mut handles).map_err(|_| 0xD1B0_0201_u32)?;
        if counts.bytes != RECORD_BYTES
            || counts.handles != 0
            || parse_challenge(&bytes, round).is_err()
        {
            return Err(0xD1B0_0202);
        }
        send_channel(channel, &encode_reply(round), &[]).map_err(|_| 0xD1B0_0203_u32)?;
    }
    submit_dw1b_progress(CHALLENGE_DIGEST).map_err(|_| 0xD1B0_0204_u32)?;
    close_handle(channel).map_err(|_| 0xD1B0_0205_u32)
}

#[cfg(feature = "native-payloads")]
fn receive_startup_and_ready(channel: DwHandle, transaction: u64) -> Result<(), u32> {
    let mut bytes = [0; HEADER_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(channel, &mut bytes, &mut handles).map_err(|_| 0xD1B0_0101_u32)?;
    if counts.bytes != HEADER_BYTES || counts.handles != 0 {
        return Err(0xD1B0_0102);
    }
    let init = parse_init(LaunchProfile::Hello, &bytes, &[]).map_err(|_| 0xD1B0_0102_u32)?;
    if init.transaction_id != transaction {
        return Err(0xD1B0_0102);
    }
    let mut ready = [0; HEADER_BYTES];
    let size = encode_ready_for_profile(LaunchProfile::Hello, transaction, &mut ready)
        .map_err(|_| 0xD1B0_0103_u32)?;
    send_channel(channel, &ready[..size], &[]).map_err(|_| 0xD1B0_0103_u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_transcript_has_frozen_digest() {
        let mut digest = 0xCBF2_9CE4_8422_2325_u64;
        for round in 0..ROUND_COUNT {
            for record in [encode_challenge(round), encode_reply(round)] {
                for byte in record {
                    digest = (digest ^ u64::from(byte)).wrapping_mul(0x100_0000_01B3);
                }
            }
        }
        assert_eq!(digest, CHALLENGE_DIGEST);
    }

    #[test]
    fn exact_direction_round_and_values_are_enforced() {
        for round in 0..ROUND_COUNT {
            assert_eq!(parse_challenge(&encode_challenge(round), round), Ok(()));
            assert_eq!(parse_reply(&encode_reply(round), round), Ok(()));
            assert!(parse_reply(&encode_challenge(round), round).is_err());
            assert!(parse_challenge(&encode_reply(round), round).is_err());
        }
        assert_eq!(parse_reply(&encode_reply(1), 0), Err(ProtocolError::Round));
    }
}
