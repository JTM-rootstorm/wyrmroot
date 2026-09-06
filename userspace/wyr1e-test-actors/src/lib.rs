#![no_std]
#![forbid(unsafe_code)]

//! Bounded WYR1-E JobV2 test actors.

use deepwyrm_syscall::{
    DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DwHandle, DwObjectType, DwReceivedHandleInfoV1,
    DwRights, DwSignals,
};
use wyrmroot_loader::launch::{CHILD_CHANNEL_RIGHTS, LaunchProfile, encode_ready_for_profile};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, NativeError, ReceiveCounts,
    extract_job_v2_streams, validate_bootstrap_channel,
};

pub const EXIT_NONZERO_PATH: &str = "test/wyr1-e/exit-nonzero";
pub const FAULT_PATH: &str = "test/wyr1-e/fault";
pub const NONZERO_EXIT_CODE: u32 = 37;
const INIT_BYTES: usize = 64;
const STREAM_COUNT: usize = 3;

pub trait ActorSystem {
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
pub enum ActorError {
    Native,
    Bootstrap,
    Startup,
    Init,
    StreamAuthority,
    Release,
    Cleanup,
}

impl ActorError {
    #[must_use]
    pub const fn exit_code(self) -> u32 {
        0xE7A0_0000
            | match self {
                Self::Native => 1,
                Self::Bootstrap => 2,
                Self::Startup => 3,
                Self::Init => 4,
                Self::StreamAuthority => 5,
                Self::Release => 6,
                Self::Cleanup => 7,
            }
    }
}

pub fn validate_actor_entry(
    version: u64,
    argc: usize,
    argv0: Option<&str>,
    envc: usize,
    expected_path: &str,
) -> Result<(), ActorError> {
    if version == wyrmroot_runtime::STARTUP_ABI_V2
        && argc == 1
        && argv0 == Some(expected_path)
        && envc == 0
    {
        Ok(())
    } else {
        Err(ActorError::Startup)
    }
}

pub fn prepare_stream_actor<System: ActorSystem>(
    system: &mut System,
    bootstrap: DwHandle,
) -> Result<u64, ActorError> {
    let mut handles = [DwReceivedHandleInfoV1::default(); STREAM_COUNT + 1];
    let mut initialized = 0;
    let result = (|| {
        let bootstrap_info = system
            .query_capability_info(bootstrap)
            .map_err(|_| ActorError::Native)?;
        validate_bootstrap_channel(bootstrap_info, BOOTSTRAP_CHANNEL_EXPECTATION)
            .map_err(|_| ActorError::Bootstrap)?;

        let mut init = [0u8; INIT_BYTES];
        let counts = system
            .receive_channel(bootstrap, &mut init, &mut handles)
            .map_err(|_| ActorError::Native)?;
        initialized = counts.handles.min(handles.len());
        if counts.bytes != INIT_BYTES || counts.handles != STREAM_COUNT {
            return Err(ActorError::Init);
        }
        let streams = extract_job_v2_streams(&init, &handles[..STREAM_COUNT])
            .map_err(|_| ActorError::Init)?;
        for endpoint in [streams.stdin, streams.stdout, streams.stderr] {
            let fresh = system
                .query_capability_info(endpoint.handle())
                .map_err(|_| ActorError::Native)?;
            if fresh.object_type != deepwyrm_syscall::DW_OBJECT_TYPE_CHANNEL
                || fresh.rights != CHILD_CHANNEL_RIGHTS
            {
                return Err(ActorError::StreamAuthority);
            }
        }

        let parsed = wyrmroot_loader::launch::parse_init(
            LaunchProfile::JobV2Streams,
            &init,
            &handles[..STREAM_COUNT],
        )
        .map_err(|_| ActorError::Init)?;
        let mut ready = [0u8; wyrmroot_loader::launch::HEADER_BYTES];
        let size = encode_ready_for_profile(
            LaunchProfile::JobV2Streams,
            parsed.transaction_id,
            &mut ready,
        )
        .map_err(|_| ActorError::Init)?;
        system
            .send_channel(bootstrap, &ready[..size])
            .map_err(|_| ActorError::Native)?;
        let requested = DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0);
        let observed = system
            .wait_channel(bootstrap, requested)
            .map_err(|_| ActorError::Native)?;
        if observed != DW_SIGNAL_PEER_CLOSED {
            return Err(ActorError::Release);
        }
        Ok(parsed.transaction_id)
    })();

    let mut cleanup_failed = false;
    for received in handles[..initialized].iter().rev() {
        if received.handle.0 != 0 {
            cleanup_failed |= system.close_handle(received.handle).is_err();
        }
    }
    cleanup_failed |= system.close_handle(bootstrap).is_err();
    if cleanup_failed {
        Err(ActorError::Cleanup)
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use deepwyrm_syscall::{DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_DUPLICATE, DW_STATUS_BAD_HANDLE};
    use std::vec::Vec;
    use wyrmroot_loader::launch::{encode_init, parse_ready_for_profile};

    const BOOTSTRAP: DwHandle = DwHandle(10);

    struct Fixture {
        init: [u8; INIT_BYTES],
        handles: [DwReceivedHandleInfoV1; STREAM_COUNT + 1],
        handle_count: usize,
        fresh_rights: DwRights,
        signals: DwSignals,
        sent: Vec<u8>,
        closed: Vec<DwHandle>,
        events: Vec<&'static str>,
        failed_close: Option<DwHandle>,
    }

    impl Fixture {
        fn new() -> Self {
            let mut init = [0; INIT_BYTES];
            encode_init(LaunchProfile::JobV2Streams, 41, &mut init).unwrap();
            let received = |raw| DwReceivedHandleInfoV1 {
                handle: DwHandle(raw),
                object_type: DW_OBJECT_TYPE_CHANNEL,
                rights: CHILD_CHANNEL_RIGHTS,
                ..DwReceivedHandleInfoV1::default()
            };
            Self {
                init,
                handles: [received(21), received(22), received(23), received(24)],
                handle_count: STREAM_COUNT,
                fresh_rights: CHILD_CHANNEL_RIGHTS,
                signals: DW_SIGNAL_PEER_CLOSED,
                sent: Vec::new(),
                closed: Vec::new(),
                events: Vec::new(),
                failed_close: None,
            }
        }
    }

    impl ActorSystem for Fixture {
        fn query_capability_info(
            &mut self,
            handle: DwHandle,
        ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
            self.events.push("query");
            if handle == BOOTSTRAP {
                Ok(CapabilityInfo {
                    object_type: DW_OBJECT_TYPE_CHANNEL,
                    rights: BOOTSTRAP_CHANNEL_EXPECTATION.rights,
                })
            } else if (21..=24).contains(&handle.0) {
                Ok(CapabilityInfo {
                    object_type: DW_OBJECT_TYPE_CHANNEL,
                    rights: self.fresh_rights,
                })
            } else {
                Err(NativeError::Status(DW_STATUS_BAD_HANDLE))
            }
        }

        fn receive_channel(
            &mut self,
            channel: DwHandle,
            bytes: &mut [u8],
            handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, NativeError> {
            assert_eq!(channel, BOOTSTRAP);
            self.events.push("receive");
            bytes.copy_from_slice(&self.init);
            handles[..self.handle_count].copy_from_slice(&self.handles[..self.handle_count]);
            Ok(ReceiveCounts {
                bytes: INIT_BYTES,
                handles: self.handle_count,
            })
        }

        fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
            assert_eq!(channel, BOOTSTRAP);
            self.events.push("ready");
            self.sent.extend_from_slice(bytes);
            Ok(())
        }

        fn wait_channel(
            &mut self,
            channel: DwHandle,
            signals: DwSignals,
        ) -> Result<DwSignals, NativeError> {
            assert_eq!(channel, BOOTSTRAP);
            assert_eq!(
                signals,
                DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0)
            );
            self.events.push("release");
            Ok(self.signals)
        }

        fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
            self.events.push("close");
            self.closed.push(handle);
            if self.failed_close == Some(handle) {
                Err(NativeError::Status(DW_STATUS_BAD_HANDLE))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn exact_stream_init_ready_release_and_reverse_cleanup() {
        let mut fixture = Fixture::new();
        assert_eq!(prepare_stream_actor(&mut fixture, BOOTSTRAP), Ok(41));
        assert_eq!(
            parse_ready_for_profile(LaunchProfile::JobV2Streams, &fixture.sent, 41),
            Ok(())
        );
        assert_eq!(
            fixture.closed,
            [DwHandle(23), DwHandle(22), DwHandle(21), BOOTSTRAP]
        );
        assert_eq!(
            fixture.events,
            [
                "query", "receive", "query", "query", "query", "ready", "release", "close",
                "close", "close", "close"
            ]
        );
    }

    #[test]
    fn malformed_or_excess_authority_is_rejected_and_cleaned() {
        let mut wrong_rights = Fixture::new();
        wrong_rights.fresh_rights = DwRights(CHILD_CHANNEL_RIGHTS.0 | DW_RIGHT_DUPLICATE.0);
        assert_eq!(
            prepare_stream_actor(&mut wrong_rights, BOOTSTRAP),
            Err(ActorError::StreamAuthority)
        );
        assert!(wrong_rights.sent.is_empty());
        assert_eq!(
            wrong_rights.closed,
            [DwHandle(23), DwHandle(22), DwHandle(21), BOOTSTRAP]
        );

        let mut extra = Fixture::new();
        extra.handle_count = 4;
        assert_eq!(
            prepare_stream_actor(&mut extra, BOOTSTRAP),
            Err(ActorError::Init)
        );
        assert_eq!(
            extra.closed,
            [
                DwHandle(24),
                DwHandle(23),
                DwHandle(22),
                DwHandle(21),
                BOOTSTRAP
            ]
        );

        let mut wrong_role = Fixture::new();
        wrong_role.init[40..44].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            prepare_stream_actor(&mut wrong_role, BOOTSTRAP),
            Err(ActorError::Init)
        );
        assert!(wrong_role.sent.is_empty());
        assert_eq!(wrong_role.closed.len(), 4);
    }

    #[test]
    fn readable_release_data_is_rejected_after_ready_with_cleanup() {
        let mut fixture = Fixture::new();
        fixture.signals = DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0);
        assert_eq!(
            prepare_stream_actor(&mut fixture, BOOTSTRAP),
            Err(ActorError::Release)
        );
        assert!(!fixture.sent.is_empty());
        assert_eq!(fixture.closed.len(), 4);
    }

    #[test]
    fn cleanup_attempts_every_owned_handle_and_dominates_success() {
        let mut fixture = Fixture::new();
        fixture.failed_close = Some(DwHandle(22));
        assert_eq!(
            prepare_stream_actor(&mut fixture, BOOTSTRAP),
            Err(ActorError::Cleanup)
        );
        assert_eq!(
            fixture.closed,
            [DwHandle(23), DwHandle(22), DwHandle(21), BOOTSTRAP]
        );
    }

    #[test]
    fn startup_identity_is_exact_and_nonzero_actor_exit_is_37() {
        assert_eq!(NONZERO_EXIT_CODE, 37);
        for path in [EXIT_NONZERO_PATH, FAULT_PATH] {
            assert_eq!(
                validate_actor_entry(wyrmroot_runtime::STARTUP_ABI_V2, 1, Some(path), 0, path),
                Ok(())
            );
            assert_eq!(
                validate_actor_entry(1, 1, Some(path), 0, path),
                Err(ActorError::Startup)
            );
            assert_eq!(
                validate_actor_entry(
                    wyrmroot_runtime::STARTUP_ABI_V2,
                    1,
                    Some("bin/hello"),
                    0,
                    path
                ),
                Err(ActorError::Startup)
            );
        }
    }
}
