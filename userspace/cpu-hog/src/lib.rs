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
/// A JobV2 INIT: the header and the self-root role.
const JOB_INIT_BYTES: usize = HEADER_BYTES + 8;

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
    /// The startup auxv lacked the page size or named another entry point.
    Auxv,
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
                Self::Auxv => 6,
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

/// The auxv a job's startup block carries (root
/// `TOOLCHAIN_POSIX_LAYER_DESIGN.md` W2): exactly one `AT_PAGESZ` of 4096 and
/// one `AT_ENTRY` naming the job's own entry point.
pub fn validate_job_cpu_hog_auxv(
    entries: impl Iterator<Item = (u64, u64)>,
    entry_point: u64,
) -> Result<(), JobActorError> {
    const AT_PAGESZ: u64 = 6;
    const AT_ENTRY: u64 = 9;
    let (mut page_size, mut entry) = (0usize, 0usize);
    for (kind, value) in entries {
        match kind {
            AT_PAGESZ if value == 4096 => page_size += 1,
            AT_ENTRY if value == entry_point => entry += 1,
            AT_PAGESZ | AT_ENTRY => return Err(JobActorError::Auxv),
            _ => {}
        }
    }
    if (page_size, entry) == (1, 1) {
        Ok(())
    } else {
        Err(JobActorError::Auxv)
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

        // INIT carries exactly the job's self root (WRLP 1.12). The hog maps
        // nothing, so it checks the root and closes it at once.
        let mut bytes = [0u8; JOB_INIT_BYTES];
        let mut received = [DwReceivedHandleInfoV1::default(); 2];
        let counts = system
            .receive_channel(bootstrap, &mut bytes, &mut received)
            .map_err(|_| JobActorError::Native)?;
        let received = &received[..counts.handles.min(received.len())];
        let init = if counts.bytes == JOB_INIT_BYTES && received.len() == 1 {
            parse_init(LaunchProfile::JobV2, &bytes, received).map_err(|_| JobActorError::Init)
        } else {
            Err(JobActorError::Init)
        };
        let mut cleanup_failed = false;
        for info in received.iter().rev() {
            if info.handle.0 != 0 {
                cleanup_failed |= system.close_handle(info.handle).is_err();
            }
        }
        if cleanup_failed {
            return Err(JobActorError::Cleanup);
        }
        let init = init?;
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
/// Bytes of an FXSAVE image.
pub const FXSAVE_BYTES: usize = 512;
/// Selectors the hog holds in DS, ES or GS: the DPL3 data and code
/// descriptors at any RPL. None is null, so a selector reset to null shows up
/// as a change. Null selectors with a nonzero RPL are left out: IRET back to
/// CPL3 reloads DS and ES as 0 when they hold one, on every interrupt return,
/// so they cannot survive preemption on any kernel.
pub const LOADABLE_SELECTORS: [u16; 8] = [0x28, 0x29, 0x2a, 0x2b, 0x30, 0x31, 0x32, 0x33];

/// Why the hog stopped spinning. The hog holds its own FP registers, FS
/// base and DS/ES/GS selectors across every preemption; seeing any of them
/// change means the kernel lost or leaked user state (Deepwyrm toolchain
/// D1, D2, and the D1/D2 security review).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessFailure {
    /// The hog did not start from the initial FP state and null selectors.
    InitialState,
    /// `thread_set_fs_base` refused the hog's anchor.
    SetFsBase,
    /// An XMM register or MXCSR changed while the hog was preempted.
    FpState,
    /// The FS base changed while the hog was preempted.
    FsBase,
    /// DS, ES or GS changed while the hog was preempted.
    Selectors,
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
                Self::Selectors => 4,
            }
    }
}

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// The register pattern one hog holds, distinct per launch `seed` and never
/// all zero in any register (splitmix64).
#[must_use]
pub fn witness_pattern(seed: u64) -> [u8; WITNESS_BYTES] {
    let mut state = seed;
    let mut pattern = [0u8; WITNESS_BYTES];
    for chunk in pattern.as_chunks_mut::<8>().0 {
        chunk.copy_from_slice(&(splitmix(&mut state) | 1).to_le_bytes());
    }
    pattern
}

/// The DS, ES and GS selectors one hog holds, chosen from
/// [`LOADABLE_SELECTORS`] by its launch `seed`.
#[must_use]
pub fn witness_selectors(seed: u64) -> [u16; 3] {
    let mut state = !seed;
    [(); 3].map(|()| {
        let index = splitmix(&mut state) % LOADABLE_SELECTORS.len() as u64;
        LOADABLE_SELECTORS[index as usize]
    })
}

/// The value at the hog's FS base: its seed, folded so it is never zero.
#[must_use]
pub const fn fs_anchor_value(seed: u64) -> u64 {
    seed ^ 0x5753_5f42_4153_4521 | 1
}

/// Checks the state the hog's `_start` captured before any compiled code
/// ran: an FXSAVE image of the initial x87 and SSE state (FCW 0x037F, empty
/// stack, MXCSR 0x1F80, every ST and XMM register zero) and null DS, ES, FS
/// and GS. FOP, FIP and FDP are not checked: CPUs that skip them on restore
/// show the kernel's fixed scrub addresses there instead of zero.
#[must_use]
pub fn is_initial_entry_state(fxsave: &[u8; FXSAVE_BYTES], selectors: [u16; 4]) -> bool {
    let word = |at: usize| u16::from_le_bytes([fxsave[at], fxsave[at + 1]]);
    let mxcsr = u32::from_le_bytes([fxsave[24], fxsave[25], fxsave[26], fxsave[27]]);
    word(0) == INITIAL_FCW
        && word(2) == 0
        && fxsave[4] == 0
        && mxcsr == INITIAL_MXCSR
        && fxsave[32..416].iter().all(|byte| *byte == 0)
        && selectors == [0; 4]
}

#[cfg(test)]
mod tests {
    use super::*;
    use deepwyrm_syscall::{DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_DUPLICATE, DW_STATUS_BAD_HANDLE};

    const CHANNEL: DwHandle = DwHandle(11);

    const ROOT: DwHandle = DwHandle(20);

    struct JobFixture {
        init: [u8; JOB_INIT_BYTES],
        rights: DwRights,
        unexpected: Option<DwHandle>,
        signals: DwSignals,
        sent: [u8; HEADER_BYTES],
        sent_len: usize,
        closes: [DwHandle; 4],
        close_count: usize,
        wait_count: usize,
    }

    impl JobFixture {
        fn new(transaction: u64) -> Self {
            let mut init = [0; JOB_INIT_BYTES];
            wyrmroot_loader::launch::encode_init(LaunchProfile::JobV2, transaction, &mut init)
                .unwrap();
            Self {
                init,
                rights: BOOTSTRAP_CHANNEL_EXPECTATION.rights,
                unexpected: None,
                signals: DW_SIGNAL_PEER_CLOSED,
                sent: [0; HEADER_BYTES],
                sent_len: 0,
                closes: [DwHandle(0); 4],
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
            handles[0] = DwReceivedHandleInfoV1 {
                handle: ROOT,
                object_type: deepwyrm_syscall::DW_OBJECT_TYPE_ADDRESS_REGION,
                rights: wyrmroot_loader::launch::SELF_ROOT_RIGHTS,
                ..DwReceivedHandleInfoV1::default()
            };
            if let Some(handle) = self.unexpected {
                handles[1] = DwReceivedHandleInfoV1 {
                    handle,
                    object_type: DW_OBJECT_TYPE_CHANNEL,
                    rights: BOOTSTRAP_CHANNEL_EXPECTATION.rights,
                    ..DwReceivedHandleInfoV1::default()
                };
            }
            Ok(ReceiveCounts {
                bytes: self.init.len(),
                handles: 1 + usize::from(self.unexpected.is_some()),
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
        // The unused self root is closed before READY, the bootstrap last.
        assert_eq!(fixture.closes[..fixture.close_count], [ROOT, CHANNEL]);
    }

    #[test]
    fn the_auxv_must_carry_the_page_size_and_this_entry_point() {
        let entry = 0x40_1000;
        let good = [(3, 0x40_0040), (6, 4096), (9, entry)];
        assert_eq!(validate_job_cpu_hog_auxv(good.into_iter(), entry), Ok(()));
        for bad in [
            &[(6, 4096)][..],
            &[(9, entry)][..],
            &[(6, 8192), (9, entry)][..],
            &[(6, 4096), (9, entry + 1)][..],
            &[(6, 4096), (6, 4096), (9, entry)][..],
            &[][..],
        ] {
            assert_eq!(
                validate_job_cpu_hog_auxv(bad.iter().copied(), entry),
                Err(JobActorError::Auxv),
                "{bad:?}"
            );
        }
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
            [DwHandle(21), ROOT, CHANNEL]
        );

        let mut readable = JobFixture::new(90);
        readable.signals = DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0);
        assert_eq!(
            prepare_job_cpu_hog(&mut readable, CHANNEL),
            Err(JobActorError::Release)
        );
        assert_eq!(readable.closes[..readable.close_count], [ROOT, CHANNEL]);
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

    fn initial_image() -> [u8; FXSAVE_BYTES] {
        let mut image = [0u8; FXSAVE_BYTES];
        image[0..2].copy_from_slice(&INITIAL_FCW.to_le_bytes());
        image[24..28].copy_from_slice(&INITIAL_MXCSR.to_le_bytes());
        // MXCSR_MASK, FOP, FIP and FDP are the CPU's business.
        image[28..32].copy_from_slice(&0xffffu32.to_le_bytes());
        image[8..16].copy_from_slice(&0xffff_ffff_8000_1000u64.to_le_bytes());
        image
    }

    #[test]
    fn the_initial_state_is_the_reset_fp_image_and_null_selectors() {
        assert!(is_initial_entry_state(&initial_image(), [0; 4]));
        assert_ne!(WITNESS_MXCSR, INITIAL_MXCSR);
        for (at, value) in [
            (0, 0x7eu8),
            (2, 1),
            (4, 1),
            (24, 0x00),
            (32, 1),
            (160, 1),
            (415, 1),
        ] {
            let mut image = initial_image();
            image[at] = value;
            assert!(!is_initial_entry_state(&image, [0; 4]), "byte {at}");
        }
        for index in 0..4 {
            let mut selectors = [0; 4];
            selectors[index] = 0x2b;
            assert!(!is_initial_entry_state(&initial_image(), selectors));
        }
    }

    #[test]
    fn witness_selectors_are_loadable_and_never_null() {
        for seed in [0, 1, 7, 8, u64::MAX] {
            for selector in witness_selectors(seed) {
                assert!(LOADABLE_SELECTORS.contains(&selector));
                assert_ne!(selector, 0);
            }
        }
        let first = witness_selectors(0);
        assert!((1..16).any(|seed| witness_selectors(seed) != first));
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
            WitnessFailure::Selectors,
        ]
        .map(WitnessFailure::exit_code);
        for (index, code) in codes.iter().enumerate() {
            assert!(!codes[..index].contains(code));
            assert_ne!(*code, 0);
        }
    }
}
