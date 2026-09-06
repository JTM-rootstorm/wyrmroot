#![no_std]
#![forbid(unsafe_code)]

//! Selector-26-only payloads and fixed handle-free challenge protocol.

use core::convert::Infallible;
#[cfg(feature = "native-payloads")]
use deepwyrm_syscall::DW_DEADLINE_INFINITE;
use deepwyrm_syscall::{
    DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DwHandle, DwObjectType, DwReceivedHandleInfoV1,
    DwRights, DwSignals,
};
use wyrmroot_loader::launch::{HEADER_BYTES, LaunchProfile, encode_ready_for_profile, parse_init};
use wyrmroot_runtime as _;
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, NativeError, ReceiveCounts,
    validate_bootstrap_channel,
};
#[cfg(feature = "native-payloads")]
use wyrmroot_runtime::{
    close_handle, receive_channel, send_channel, submit_dw1b_progress, wait_one,
};

pub const ROUND_COUNT: usize = 8;
pub const RECORD_BYTES: usize = 32;
pub const CHALLENGE_DIGEST: u64 = 0x5E4E_054B_5C24_4ACE;
pub const HOG_TRANSACTION_ID: u64 = 0xD1B0_0001;
pub const PROGRESS_TRANSACTION_ID: u64 = 0xD1B0_0002;
pub const JOB_CPU_HOG_PATH: &str = "bin/cpu-hog";

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

pub trait JobActorSystem {
    fn query_capability_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError>;
    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError>;
    fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError>;
    fn wait_channel(
        &mut self,
        channel: DwHandle,
        signals: DwSignals,
    ) -> Result<DwSignals, NativeError>;
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobActorError {
    Native,
    Bootstrap,
    Init,
    Release,
    Cleanup,
}

impl JobActorError {
    #[must_use]
    pub const fn exit_code(self) -> u32 {
        0xD1B7_0000
            | match self {
                Self::Native => 1,
                Self::Bootstrap => 2,
                Self::Init => 3,
                Self::Release => 4,
                Self::Cleanup => 5,
            }
    }
}

pub fn validate_job_cpu_hog_entry(
    version: u64,
    argc: usize,
    argv0: Option<&str>,
    envc: usize,
) -> Result<(), JobActorError> {
    if version == wyrmroot_runtime::STARTUP_ABI_V2
        && argc == 1
        && argv0 == Some(JOB_CPU_HOG_PATH)
        && envc == 0
    {
        Ok(())
    } else {
        Err(JobActorError::Init)
    }
}

pub fn prepare_job_cpu_hog<System: JobActorSystem>(
    system: &mut System,
    bootstrap: DwHandle,
) -> Result<u64, JobActorError> {
    let result = (|| {
        let info = system
            .query_capability_info(bootstrap)
            .map_err(|_| JobActorError::Native)?;
        validate_bootstrap_channel(info, BOOTSTRAP_CHANNEL_EXPECTATION)
            .map_err(|_| JobActorError::Bootstrap)?;

        let mut bytes = [0u8; HEADER_BYTES];
        let mut unexpected = [DwReceivedHandleInfoV1::default(); 1];
        let counts = system
            .receive_channel(bootstrap, &mut bytes, &mut unexpected)
            .map_err(|_| JobActorError::Native)?;
        if counts.bytes != HEADER_BYTES || counts.handles != 0 {
            let mut cleanup_failed = false;
            for info in unexpected[..counts.handles.min(unexpected.len())]
                .iter()
                .rev()
            {
                if info.handle.0 != 0 {
                    cleanup_failed |= system.close_handle(info.handle).is_err();
                }
            }
            return Err(if cleanup_failed {
                JobActorError::Cleanup
            } else {
                JobActorError::Init
            });
        }
        let init =
            parse_init(LaunchProfile::JobV2, &bytes, &[]).map_err(|_| JobActorError::Init)?;
        let mut ready = [0u8; HEADER_BYTES];
        let size = encode_ready_for_profile(LaunchProfile::JobV2, init.transaction_id, &mut ready)
            .map_err(|_| JobActorError::Init)?;
        system
            .send_channel(bootstrap, &ready[..size])
            .map_err(|_| JobActorError::Native)?;

        let requested = DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0);
        let observed = system
            .wait_channel(bootstrap, requested)
            .map_err(|_| JobActorError::Native)?;
        if observed.0 != DW_SIGNAL_PEER_CLOSED.0 {
            return Err(JobActorError::Release);
        }
        Ok(init.transaction_id)
    })();
    let cleanup = system.close_handle(bootstrap);
    match (result, cleanup) {
        (_, Err(_)) => Err(JobActorError::Cleanup),
        (result, Ok(())) => result,
    }
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
    receive_hog_startup_and_ready(channel)?;
    close_handle(channel).map_err(|_| 0xD1B0_0104_u32)?;
    run_cpu_hog_body()
}

/// Executes the accepted no-yield CPU hog body shared by historical and
/// dynamic JobV2 entry adapters.
pub fn run_cpu_hog_body() -> Result<Infallible, u32> {
    loop {
        core::hint::spin_loop();
    }
}

/// Runs the progress peer and attests only after all eight exact replies.
#[cfg(feature = "native-payloads")]
pub fn run_progress(channel: DwHandle) -> Result<(), u32> {
    let data_channel = receive_progress_startup_and_ready(channel)?;
    close_handle(channel).map_err(|_| 0xD1B0_0206_u32)?;
    for round in 0..ROUND_COUNT {
        let observed = wait_one(
            data_channel,
            DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
            DW_DEADLINE_INFINITE,
        )
        .map_err(|_| 0xD1B0_0207_u32)?;
        if observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
            return Err(0xD1B0_0208);
        }
        let mut bytes = [0; RECORD_BYTES];
        let mut handles = [];
        let counts =
            receive_channel(data_channel, &mut bytes, &mut handles).map_err(|_| 0xD1B0_0201_u32)?;
        if counts.bytes != RECORD_BYTES
            || counts.handles != 0
            || parse_challenge(&bytes, round).is_err()
        {
            return Err(0xD1B0_0202);
        }
        send_channel(data_channel, &encode_reply(round), &[]).map_err(|_| 0xD1B0_0203_u32)?;
    }
    submit_dw1b_progress(CHALLENGE_DIGEST).map_err(|_| 0xD1B0_0204_u32)?;
    close_handle(data_channel).map_err(|_| 0xD1B0_0205_u32)
}

#[cfg(feature = "native-payloads")]
fn receive_hog_startup_and_ready(channel: DwHandle) -> Result<(), u32> {
    let mut bytes = [0; HEADER_BYTES];
    let mut handles = [];
    let counts = receive_channel(channel, &mut bytes, &mut handles).map_err(|_| 0xD1B0_0101_u32)?;
    if counts.bytes != HEADER_BYTES || counts.handles != 0 {
        return Err(0xD1B0_0102);
    }
    let init = parse_init(LaunchProfile::Hello, &bytes, &[]).map_err(|_| 0xD1B0_0102_u32)?;
    if init.transaction_id != HOG_TRANSACTION_ID {
        return Err(0xD1B0_0102);
    }
    let mut ready = [0; HEADER_BYTES];
    let size = encode_ready_for_profile(LaunchProfile::Hello, HOG_TRANSACTION_ID, &mut ready)
        .map_err(|_| 0xD1B0_0103_u32)?;
    send_channel(channel, &ready[..size], &[]).map_err(|_| 0xD1B0_0103_u32)
}

#[cfg(feature = "native-payloads")]
fn receive_progress_startup_and_ready(channel: DwHandle) -> Result<DwHandle, u32> {
    let mut bytes = [0; HEADER_BYTES + 8];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(channel, &mut bytes, &mut handles).map_err(|_| 0xD1B0_0211_u32)?;
    if counts.bytes != bytes.len() || counts.handles != 1 {
        return Err(0xD1B0_0212);
    }
    let init =
        parse_init(LaunchProfile::Dw1bProgress, &bytes, &handles).map_err(|_| 0xD1B0_0212_u32)?;
    if init.transaction_id != PROGRESS_TRANSACTION_ID {
        return Err(0xD1B0_0212);
    }
    let mut ready = [0; HEADER_BYTES];
    let size = encode_ready_for_profile(
        LaunchProfile::Dw1bProgress,
        PROGRESS_TRANSACTION_ID,
        &mut ready,
    )
    .map_err(|_| 0xD1B0_0213_u32)?;
    send_channel(channel, &ready[..size], &[]).map_err(|_| 0xD1B0_0213_u32)?;
    Ok(handles[0].handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use deepwyrm_syscall::{DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_DUPLICATE, DW_STATUS_BAD_HANDLE};

    const CHANNEL: DwHandle = DwHandle(11);

    struct JobFixture {
        init: [u8; HEADER_BYTES],
        rights: DwRights,
        unexpected: Option<DwHandle>,
        signals: DwSignals,
        sent: [u8; HEADER_BYTES],
        sent_len: usize,
        closes: [DwHandle; 2],
        close_count: usize,
        wait_count: usize,
    }

    impl JobFixture {
        fn new(transaction: u64) -> Self {
            let mut init = [0; HEADER_BYTES];
            wyrmroot_loader::launch::encode_init(LaunchProfile::JobV2, transaction, &mut init)
                .unwrap();
            Self {
                init,
                rights: BOOTSTRAP_CHANNEL_EXPECTATION.rights,
                unexpected: None,
                signals: DW_SIGNAL_PEER_CLOSED,
                sent: [0; HEADER_BYTES],
                sent_len: 0,
                closes: [DwHandle(0); 2],
                close_count: 0,
                wait_count: 0,
            }
        }
    }

    impl JobActorSystem for JobFixture {
        fn query_capability_info(
            &mut self,
            handle: DwHandle,
        ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
            if handle != CHANNEL {
                return Err(NativeError::Status(DW_STATUS_BAD_HANDLE));
            }
            Ok(CapabilityInfo {
                object_type: DW_OBJECT_TYPE_CHANNEL,
                rights: self.rights,
            })
        }

        fn receive_channel(
            &mut self,
            channel: DwHandle,
            bytes: &mut [u8],
            handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, NativeError> {
            assert_eq!(channel, CHANNEL);
            bytes.copy_from_slice(&self.init);
            if let Some(handle) = self.unexpected {
                handles[0] = DwReceivedHandleInfoV1 {
                    handle,
                    object_type: DW_OBJECT_TYPE_CHANNEL,
                    rights: BOOTSTRAP_CHANNEL_EXPECTATION.rights,
                    ..DwReceivedHandleInfoV1::default()
                };
            }
            Ok(ReceiveCounts {
                bytes: self.init.len(),
                handles: usize::from(self.unexpected.is_some()),
            })
        }

        fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
            assert_eq!(channel, CHANNEL);
            self.sent[..bytes.len()].copy_from_slice(bytes);
            self.sent_len = bytes.len();
            Ok(())
        }

        fn wait_channel(
            &mut self,
            channel: DwHandle,
            signals: DwSignals,
        ) -> Result<DwSignals, NativeError> {
            assert_eq!(channel, CHANNEL);
            assert_eq!(
                signals,
                DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0)
            );
            self.wait_count += 1;
            Ok(self.signals)
        }

        fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
            self.closes[self.close_count] = handle;
            self.close_count += 1;
            Ok(())
        }
    }

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

    #[test]
    fn job_cpu_hog_uses_dynamic_job_v2_ready_then_clean_release() {
        assert_eq!(
            validate_job_cpu_hog_entry(
                wyrmroot_runtime::STARTUP_ABI_V2,
                1,
                Some(JOB_CPU_HOG_PATH),
                0
            ),
            Ok(())
        );
        let mut fixture = JobFixture::new(77);
        assert_eq!(prepare_job_cpu_hog(&mut fixture, CHANNEL), Ok(77));
        assert_eq!(
            wyrmroot_loader::launch::parse_ready_for_profile(
                LaunchProfile::JobV2,
                &fixture.sent[..fixture.sent_len],
                77
            ),
            Ok(())
        );
        assert_eq!(fixture.wait_count, 1);
        assert_eq!(fixture.closes[..fixture.close_count], [CHANNEL]);
    }

    #[test]
    fn job_cpu_hog_rejects_authority_and_release_abuse_with_cleanup() {
        let mut excess = JobFixture::new(88);
        excess.rights = DwRights(excess.rights.0 | DW_RIGHT_DUPLICATE.0);
        assert_eq!(
            prepare_job_cpu_hog(&mut excess, CHANNEL),
            Err(JobActorError::Bootstrap)
        );
        assert_eq!(excess.closes[..excess.close_count], [CHANNEL]);

        let mut delegated = JobFixture::new(89);
        delegated.unexpected = Some(DwHandle(21));
        assert_eq!(
            prepare_job_cpu_hog(&mut delegated, CHANNEL),
            Err(JobActorError::Init)
        );
        assert_eq!(
            delegated.closes[..delegated.close_count],
            [DwHandle(21), CHANNEL]
        );

        let mut readable = JobFixture::new(90);
        readable.signals = DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0);
        assert_eq!(
            prepare_job_cpu_hog(&mut readable, CHANNEL),
            Err(JobActorError::Release)
        );
        assert_eq!(readable.closes[..readable.close_count], [CHANNEL]);
    }
}
