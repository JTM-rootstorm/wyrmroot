#![no_std]
#![forbid(unsafe_code)]

//! The `bin/cpu-hog` job: a no-yield CPU hog started as a JobV2 payload.

use core::convert::Infallible;
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

/// Executes the no-yield CPU hog body.
pub fn run_cpu_hog_body() -> Result<Infallible, u32> {
    loop {
        core::hint::spin_loop();
    }
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
}
