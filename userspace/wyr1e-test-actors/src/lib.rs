#![no_std]
#![forbid(unsafe_code)]

//! Bounded WYR1-E JobV2 test actors.

use deepwyrm_syscall::{
    DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DwHandle, DwObjectType, DwReceivedHandleInfoV1,
    DwRights, DwSignals,
};
use wyrmroot_loader::launch::{CHILD_CHANNEL_RIGHTS, LaunchProfile, encode_ready_for_profile};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, JobV2Streams, NativeError, NativeOutput,
    ReceiveCounts, StreamError, StreamSystem, extract_job_v2_streams, validate_bootstrap_channel,
};

pub const EXIT_NONZERO_PATH: &str = "test/wyr1-e/exit-nonzero";
pub const FAULT_PATH: &str = "test/wyr1-e/fault";
pub const RECOVERY_TRIGGER_PATH: &str = "test/wyr1-e/recovery-trigger";
pub const RECOVERY_DRIVER_ACTION: &str = "driver";
pub const RECOVERY_REGISTRY_ACTION: &str = "registry";
pub const STDOUT_PRESSURE_PATH: &str = "test/wyr1-e/stdout-pressure";
pub const NONZERO_EXIT_CODE: u32 = 37;
pub const STDOUT_PRESSURE_CHUNKS: usize = 256;
pub const STDOUT_PRESSURE_CHUNK_BYTES: usize = 1024;
pub const STDOUT_PRESSURE_BYTES: usize = STDOUT_PRESSURE_CHUNKS * STDOUT_PRESSURE_CHUNK_BYTES;
pub const STDOUT_PRESSURE_SHA256: &str =
    "df1878cecca437f240a27321523bf204e607a7a5b85d6569e81ce1290a4dcf79";
pub const MAX_REPORTED_WOULD_BLOCKS: u32 = 4095;
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
    Stream,
    PressureNotObserved,
    PressureCountOverflow,
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
                Self::Stream => 8,
                Self::PressureNotObserved => 9,
                Self::PressureCountOverflow => 10,
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

pub fn validate_recovery_trigger_entry(
    version: u64,
    argc: usize,
    argv0: Option<&str>,
    stage: Option<&str>,
    nonce: Option<&str>,
    envc: usize,
) -> Result<(), ActorError> {
    let valid_stage = matches!(
        stage,
        Some(RECOVERY_DRIVER_ACTION | RECOVERY_REGISTRY_ACTION)
    );
    let valid_nonce = nonce.is_some_and(|value| {
        value.len() == 16
            && value != "0000000000000000"
            && value
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(byte))
    });
    if version == wyrmroot_runtime::STARTUP_ABI_V2
        && argc == 3
        && argv0 == Some(RECOVERY_TRIGGER_PATH)
        && valid_stage
        && valid_nonce
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
    run_stream_actor(system, bootstrap, |_, _| Ok(()))
}

pub fn run_stream_actor<System: ActorSystem, Action>(
    system: &mut System,
    bootstrap: DwHandle,
    action: Action,
) -> Result<u64, ActorError>
where
    Action: FnOnce(&mut System, JobV2Streams) -> Result<(), ActorError>,
{
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
        action(system, streams)?;
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

#[must_use]
pub const fn stdout_pressure_byte(chunk: usize, offset: usize) -> u8 {
    0x21 + ((17 * chunk + 29 * offset) % 94) as u8
}

pub fn run_stdout_pressure<System>(
    system: &mut System,
    bootstrap: DwHandle,
) -> Result<u32, ActorError>
where
    System: ActorSystem + StreamSystem,
{
    let mut would_blocks = 0u32;
    run_stream_actor(system, bootstrap, |system, streams| {
        let mut stdout = NativeOutput::new(streams.stdout);
        let mut chunk = 0usize;
        while chunk != STDOUT_PRESSURE_CHUNKS {
            let mut payload = [0u8; STDOUT_PRESSURE_CHUNK_BYTES];
            let mut offset = 0usize;
            while offset != payload.len() {
                payload[offset] = stdout_pressure_byte(chunk, offset);
                offset += 1;
            }
            match stdout.write(system, &payload) {
                Ok(written) if written == payload.len() => chunk += 1,
                Ok(_) => return Err(ActorError::Stream),
                Err(StreamError::WouldBlock) => {
                    would_blocks = would_blocks
                        .checked_add(1)
                        .filter(|count| *count <= MAX_REPORTED_WOULD_BLOCKS)
                        .ok_or(ActorError::PressureCountOverflow)?;
                    stdout
                        .wait_writable(system)
                        .map_err(|_| ActorError::Stream)?;
                }
                Err(_) => return Err(ActorError::Stream),
            }
        }
        Ok(())
    })?;
    if would_blocks == 0 {
        Err(ActorError::PressureNotObserved)
    } else {
        Ok(would_blocks)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use deepwyrm_syscall::{
        DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_DUPLICATE, DW_SIGNAL_WRITABLE, DW_STATUS_BAD_HANDLE,
        DW_STATUS_WOULD_BLOCK,
    };
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
        output_attempts: usize,
        block_output_attempt: Option<usize>,
        output_waits: usize,
        output: Vec<u8>,
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
                output_attempts: 0,
                block_output_attempt: None,
                output_waits: 0,
                output: Vec::new(),
            }
        }
    }

    impl StreamSystem for Fixture {
        fn receive(
            &mut self,
            _: DwHandle,
            _: &mut [u8],
            _: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, NativeError> {
            panic!("stdout actor never receives through an output stream")
        }

        fn send(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
            assert_eq!(channel, DwHandle(22));
            self.output_attempts += 1;
            if self.block_output_attempt == Some(self.output_attempts) {
                return Err(NativeError::Status(DW_STATUS_WOULD_BLOCK));
            }
            const WRST_HEADER_BYTES: usize = 24;
            assert_eq!(bytes.len(), WRST_HEADER_BYTES + STDOUT_PRESSURE_CHUNK_BYTES);
            assert_eq!(&bytes[..4], b"WRST");
            self.output.extend_from_slice(&bytes[WRST_HEADER_BYTES..]);
            Ok(())
        }

        fn close(&mut self, handle: DwHandle) -> Result<(), NativeError> {
            self.close_handle(handle)
        }

        fn wait(
            &mut self,
            channel: DwHandle,
            signals: DwSignals,
        ) -> Result<DwSignals, NativeError> {
            assert_eq!(channel, DwHandle(22));
            assert_eq!(signals, wyrmroot_runtime::OUTPUT_WAIT_SIGNALS);
            self.output_waits += 1;
            Ok(DW_SIGNAL_WRITABLE)
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
    fn recovery_trigger_requires_exact_stage_and_uppercase_nonce() {
        assert_eq!(
            validate_recovery_trigger_entry(
                wyrmroot_runtime::STARTUP_ABI_V2,
                3,
                Some(RECOVERY_TRIGGER_PATH),
                Some("driver"),
                Some("E800000000000001"),
                0,
            ),
            Ok(())
        );
        for (stage, nonce) in [
            ("uart", "E800000000000001"),
            ("registry", "e800000000000001"),
            ("registry", "0000000000000000"),
            ("registry", "E80000000000001"),
        ] {
            assert_eq!(
                validate_recovery_trigger_entry(
                    wyrmroot_runtime::STARTUP_ABI_V2,
                    3,
                    Some(RECOVERY_TRIGGER_PATH),
                    Some(stage),
                    Some(nonce),
                    0,
                ),
                Err(ActorError::Startup)
            );
        }
    }

    #[test]
    fn stdout_pressure_retries_exact_blocked_chunk_and_reports_real_count() {
        let mut fixture = Fixture::new();
        fixture.block_output_attempt = Some(2);
        assert_eq!(run_stdout_pressure(&mut fixture, BOOTSTRAP), Ok(1));
        assert_eq!(fixture.output_attempts, STDOUT_PRESSURE_CHUNKS + 1);
        assert_eq!(fixture.output_waits, 1);
        assert_eq!(fixture.output.len(), STDOUT_PRESSURE_BYTES);
        for (index, byte) in fixture.output.iter().copied().enumerate() {
            assert_eq!(
                byte,
                stdout_pressure_byte(
                    index / STDOUT_PRESSURE_CHUNK_BYTES,
                    index % STDOUT_PRESSURE_CHUNK_BYTES,
                )
            );
        }
        assert_eq!(
            fixture.closed,
            [DwHandle(23), DwHandle(22), DwHandle(21), BOOTSTRAP]
        );
    }

    #[test]
    fn stdout_pressure_rejects_an_unpressured_path() {
        let mut fixture = Fixture::new();
        assert_eq!(
            run_stdout_pressure(&mut fixture, BOOTSTRAP),
            Err(ActorError::PressureNotObserved)
        );
        assert_eq!(fixture.output.len(), STDOUT_PRESSURE_BYTES);
        assert_eq!(fixture.output_waits, 0);
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
