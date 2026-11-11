#![no_std]
#![forbid(unsafe_code)]

//! The `bin/cpu-hog` job: a no-yield CPU hog started as a JobV2 payload.
//!
//! While it spins it holds its own XMM registers, MXCSR and FS base and
//! checks them on every pass, so two hogs preempting each other witness
//! that the kernel saves and restores per-Thread user state.

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

pub const JOB_CPU_HOG_PATH: &str = "bin/cpu-hog";

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

/// Bytes of user register state the hog holds: xmm0 through xmm15.
pub const WITNESS_BYTES: usize = 256;
/// MXCSR the hog holds: every exception masked, round toward zero, so it
/// differs from the initial 0x1F80 a fresh Thread must start with.
pub const WITNESS_MXCSR: u32 = 0x7f80;
/// The MXCSR and x87 control word a Thread that has never run must see.
pub const INITIAL_MXCSR: u32 = 0x1f80;
pub const INITIAL_FCW: u16 = 0x037f;

/// Why the hog stopped spinning. The hog holds its own FP registers and FS
/// base across every preemption; seeing either change means the kernel
/// lost or leaked user state (Deepwyrm toolchain D1, D2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessFailure {
    /// The hog did not start from the initial FP state.
    InitialState,
    /// `thread_set_fs_base` refused the hog's anchor.
    SetFsBase,
    /// An XMM register or MXCSR changed while the hog was preempted.
    FpState,
    /// The FS base changed while the hog was preempted.
    FsBase,
}

impl WitnessFailure {
    #[must_use]
    pub const fn exit_code(self) -> u32 {
        0xD1B7_0010
            | match self {
                Self::InitialState => 0,
                Self::SetFsBase => 1,
                Self::FpState => 2,
                Self::FsBase => 3,
            }
    }
}

/// The register pattern one hog holds, distinct per launch `seed` and never
/// all zero in any register (splitmix64).
#[must_use]
pub fn witness_pattern(seed: u64) -> [u8; WITNESS_BYTES] {
    let mut state = seed;
    let mut pattern = [0u8; WITNESS_BYTES];
    for chunk in pattern.as_chunks_mut::<8>().0 {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        chunk.copy_from_slice(&(z | 1).to_le_bytes());
    }
    pattern
}

/// The value at the hog's FS base: its seed, folded so it is never zero.
#[must_use]
pub const fn fs_anchor_value(seed: u64) -> u64 {
    seed ^ 0x5753_5f42_4153_4521 | 1
}

/// Checks the state a hog reads before it loads its own: every XMM
/// register zero, MXCSR and FCW at their initial values.
#[must_use]
pub fn is_initial_state(xmm: &[u8; WITNESS_BYTES], mxcsr: u32, fcw: u16) -> bool {
    mxcsr == INITIAL_MXCSR && fcw == INITIAL_FCW && xmm.iter().all(|byte| *byte == 0)
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

    #[test]
    fn witness_patterns_differ_per_launch_and_never_zero_a_register() {
        let first = witness_pattern(7);
        let second = witness_pattern(8);
        assert_ne!(first, second);
        assert_eq!(first, witness_pattern(7));
        for pattern in [first, second, witness_pattern(0)] {
            for register in pattern.as_chunks::<16>().0 {
                assert!(register.iter().any(|byte| *byte != 0));
            }
        }
    }

    #[test]
    fn the_initial_state_is_zero_registers_and_reset_controls() {
        let zero = [0u8; WITNESS_BYTES];
        assert!(is_initial_state(&zero, 0x1f80, 0x037f));
        assert!(!is_initial_state(&zero, WITNESS_MXCSR, 0x037f));
        assert!(!is_initial_state(&zero, 0x1f80, 0x027f));
        let mut dirty = zero;
        dirty[255] = 1;
        assert!(!is_initial_state(&dirty, 0x1f80, 0x037f));
        assert_ne!(WITNESS_MXCSR, INITIAL_MXCSR);
    }

    #[test]
    fn fs_anchors_are_never_zero_and_follow_the_seed() {
        assert_ne!(fs_anchor_value(0), 0);
        assert_ne!(fs_anchor_value(1), fs_anchor_value(2));
    }

    #[test]
    fn witness_failures_have_distinct_exit_codes() {
        let codes = [
            WitnessFailure::InitialState,
            WitnessFailure::SetFsBase,
            WitnessFailure::FpState,
            WitnessFailure::FsBase,
        ]
        .map(WitnessFailure::exit_code);
        for (index, code) in codes.iter().enumerate() {
            assert!(!codes[..index].contains(code));
            assert_ne!(*code, 0);
        }
    }
}
