use deepwyrm_syscall::{
    DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT, DW_RIGHT_READ, DW_RIGHT_WAIT,
    DW_RIGHT_WRITE, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DW_STATUS_BAD_HANDLE,
    DW_STATUS_NO_RESOURCES, DwHandle, DwObjectType, DwReceivedHandleInfoV1, DwRights, DwSignals,
};
use wyrmroot_hello::{
    HelloError, HelloNativeOperation, HelloSystem, JobHelloSystem, run_hello, run_job_hello,
    run_stream_hello,
};
use wyrmroot_loader::launch::{LaunchProfile, encode_init, parse_ready, parse_ready_for_profile};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, CapabilityValidationError, NativeError,
    ReceiveCounts, StreamSystem,
};

const CHANNEL: DwHandle = DwHandle(11);

#[test]
fn live_exit_code_identifies_hello_owned_failure() {
    assert_eq!(
        HelloError::ReceiveCounts(ReceiveCounts {
            bytes: 0,
            handles: 1,
        })
        .exit_code(),
        0x4800_0003
    );
}

#[test]
fn live_exit_code_preserves_native_operation_and_cause() {
    assert_eq!(
        HelloError::Native {
            operation: HelloNativeOperation::SendReady,
            cause: NativeError::Status(DW_STATUS_NO_RESOURCES),
        }
        .exit_code(),
        0x4803_000d
    );
}

const ROOT: DwHandle = DwHandle(20);

fn root() -> DwReceivedHandleInfoV1 {
    DwReceivedHandleInfoV1 {
        handle: ROOT,
        object_type: deepwyrm_syscall::DW_OBJECT_TYPE_ADDRESS_REGION,
        rights: wyrmroot_loader::launch::SELF_ROOT_RIGHTS,
        ..DwReceivedHandleInfoV1::default()
    }
}

struct Fixture {
    init: Vec<u8>,
    wait_signals: DwSignals,
    wait_count: usize,
    received_handles: usize,
    channel_rights: DwRights,
    sent: Vec<u8>,
    closed: Vec<DwHandle>,
}

impl Fixture {
    fn valid() -> Self {
        Self::profile(LaunchProfile::Hello)
    }

    fn profile(profile: LaunchProfile) -> Self {
        let mut init = vec![0_u8; profile.init_size()];
        encode_init(profile, 2, &mut init).unwrap();
        Self {
            init,
            wait_signals: DW_SIGNAL_PEER_CLOSED,
            wait_count: 0,
            received_handles: profile.capability_count(),
            channel_rights: BOOTSTRAP_CHANNEL_EXPECTATION.rights,
            sent: Vec::new(),
            closed: Vec::new(),
        }
    }
}

impl HelloSystem for Fixture {
    fn query_capability_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
        if handle == CHANNEL {
            Ok(CapabilityInfo {
                object_type: DW_OBJECT_TYPE_CHANNEL,
                rights: self.channel_rights,
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
        assert_eq!(channel, CHANNEL);
        bytes[..self.init.len()].copy_from_slice(&self.init);
        if let Some(slot) = handles.first_mut() {
            *slot = root();
        }
        Ok(ReceiveCounts {
            bytes: self.init.len(),
            handles: self.received_handles,
        })
    }

    fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
        assert_eq!(channel, CHANNEL);
        self.sent.extend_from_slice(bytes);
        Ok(())
    }

    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        self.closed.push(handle);
        Ok(())
    }
}

impl JobHelloSystem for Fixture {
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
        Ok(self.wait_signals)
    }
}

#[test]
fn hello_acknowledges_the_parent_channel_then_closes_it() {
    let mut fixture = Fixture::valid();
    assert_eq!(run_hello(&mut fixture, CHANNEL), Ok(()));
    assert_eq!(parse_ready(&fixture.sent, 2), Ok(()));
    assert_eq!(fixture.closed, [CHANNEL]);
}

#[test]
fn job_hello_takes_and_closes_its_self_root_under_wrlp_1_12() {
    let mut fixture = Fixture::profile(LaunchProfile::JobV2);
    assert_eq!(run_job_hello(&mut fixture, CHANNEL), Ok(()));
    assert_eq!(
        parse_ready_for_profile(LaunchProfile::JobV2, &fixture.sent, 2),
        Ok(())
    );
    assert_eq!(fixture.closed, [ROOT, CHANNEL]);
    assert_eq!(fixture.wait_count, 1);
}

#[test]
fn job_hello_rejects_readable_post_ready_data() {
    let mut fixture = Fixture::profile(LaunchProfile::JobV2);
    fixture.wait_signals = DW_SIGNAL_READABLE;
    assert_eq!(
        run_job_hello(&mut fixture, CHANNEL),
        Err(HelloError::PostReadySignals(DW_SIGNAL_READABLE))
    );
    assert_eq!(fixture.closed, [ROOT]);
}

#[test]
fn hello_rejects_any_delegated_handle() {
    let mut fixture = Fixture::valid();
    fixture.received_handles = 1;
    assert_eq!(
        run_hello(&mut fixture, CHANNEL),
        Err(HelloError::ReceiveCounts(ReceiveCounts {
            bytes: 40,
            handles: 1,
        }))
    );
    assert!(fixture.sent.is_empty());
    assert!(fixture.closed.is_empty());
}

#[test]
fn hello_rejects_bootstrap_channel_excess_rights() {
    let mut fixture = Fixture::valid();
    fixture.channel_rights = DwRights(
        DW_RIGHT_READ.0
            | DW_RIGHT_WRITE.0
            | DW_RIGHT_WAIT.0
            | DW_RIGHT_INSPECT.0
            | DW_RIGHT_DUPLICATE.0,
    );

    assert_eq!(
        run_hello(&mut fixture, CHANNEL),
        Err(HelloError::BootstrapChannel(
            CapabilityValidationError::InvalidBootstrapChannel
        ))
    );
    assert!(fixture.sent.is_empty());
    assert!(fixture.closed.is_empty());
}

struct StreamFixture {
    init: Vec<u8>,
    handles: Vec<DwReceivedHandleInfoV1>,
    wait_signals: DwSignals,
    wait_count: usize,
    sent: Vec<Vec<u8>>,
    closed: Vec<DwHandle>,
    events: Vec<&'static str>,
}
impl StreamFixture {
    fn new() -> Self {
        Self::profile(LaunchProfile::JobV2Streams)
    }
    /// A file launch's INIT: the streams, then the namespace (handle 24).
    fn with_namespace() -> Self {
        Self::profile(LaunchProfile::JobV2Namespace)
    }
    fn profile(profile: LaunchProfile) -> Self {
        let mut init = vec![0; profile.init_size()];
        encode_init(profile, 9, &mut init).unwrap();
        let handle = |raw| DwReceivedHandleInfoV1 {
            handle: DwHandle(raw),
            object_type: DW_OBJECT_TYPE_CHANNEL,
            rights: wyrmroot_loader::launch::CHILD_CHANNEL_RIGHTS,
            ..DwReceivedHandleInfoV1::default()
        };
        let mut handles = vec![root(), handle(21), handle(22), handle(23), handle(24)];
        handles.truncate(profile.capability_count());
        Self {
            init,
            handles,
            wait_signals: DW_SIGNAL_PEER_CLOSED,
            wait_count: 0,
            sent: vec![],
            closed: vec![],
            events: vec![],
        }
    }
}
impl HelloSystem for StreamFixture {
    fn query_capability_info(
        &mut self,
        _: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
        Ok(CapabilityInfo {
            object_type: DW_OBJECT_TYPE_CHANNEL,
            rights: BOOTSTRAP_CHANNEL_EXPECTATION.rights,
        })
    }
    fn receive_channel(
        &mut self,
        _: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError> {
        bytes[..self.init.len()].copy_from_slice(&self.init);
        handles[..self.handles.len()].copy_from_slice(&self.handles);
        Ok(ReceiveCounts {
            bytes: self.init.len(),
            handles: self.handles.len(),
        })
    }
    fn send_channel(&mut self, _: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
        self.events.push("ready");
        self.sent.push(bytes.to_vec());
        Ok(())
    }
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        self.events.push(match handle {
            CHANNEL => "close-bootstrap",
            DwHandle(21..=23) => "close-stream",
            ROOT => "close-root",
            DwHandle(24) => "close-namespace",
            _ => "close-other",
        });
        self.closed.push(handle);
        Ok(())
    }
}
impl JobHelloSystem for StreamFixture {
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
        self.events.push("wait-release");
        Ok(self.wait_signals)
    }
}
impl StreamSystem for StreamFixture {
    fn receive(
        &mut self,
        _: DwHandle,
        _: &mut [u8],
        _: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError> {
        unreachable!()
    }
    fn send(&mut self, _: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
        self.events.push("stdout-data");
        self.sent.push(bytes.to_vec());
        Ok(())
    }
    fn close(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        self.closed.push(handle);
        Ok(())
    }
    fn wait(&mut self, _: DwHandle, _: DwSignals) -> Result<DwSignals, NativeError> {
        Ok(DW_SIGNAL_PEER_CLOSED)
    }
}

#[test]
fn stream_hello_uses_only_a_validated_native_stdout_record() {
    let mut fixture = StreamFixture::new();
    assert_eq!(run_stream_hello(&mut fixture, CHANNEL), Ok(()));
    assert_eq!(
        wyrmroot_stream_proto::decode_data(&fixture.sent[0])
            .unwrap()
            .payload(),
        b"hello from native stdout\n"
    );
    assert_eq!(
        fixture.closed,
        [ROOT, DwHandle(21), DwHandle(22), DwHandle(23), CHANNEL]
    );
    assert_eq!(fixture.wait_count, 1);
    assert_eq!(
        fixture.events,
        [
            "close-root",
            "stdout-data",
            "close-stream",
            "close-stream",
            "close-stream",
            "ready",
            "wait-release",
            "close-bootstrap",
        ]
    );
}

#[test]
fn stream_hello_rejects_readable_post_ready_data() {
    let mut fixture = StreamFixture::new();
    fixture.wait_signals = DW_SIGNAL_READABLE;
    assert_eq!(
        run_stream_hello(&mut fixture, CHANNEL),
        Err(HelloError::PostReadySignals(DW_SIGNAL_READABLE))
    );
    assert_eq!(fixture.wait_count, 1);
    assert_eq!(
        fixture.closed,
        [ROOT, DwHandle(21), DwHandle(22), DwHandle(23)]
    );
    assert_eq!(fixture.events.last(), Some(&"wait-release"));
}

/// A hello run from a file receives a namespace (WRLP 1.13), closes it with
/// its self root, and answers READY under the namespace profile.
#[test]
fn stream_hello_closes_a_namespace_and_answers_under_its_profile() {
    let mut fixture = StreamFixture::with_namespace();
    assert_eq!(run_stream_hello(&mut fixture, CHANNEL), Ok(()));
    assert_eq!(
        fixture.closed,
        [
            ROOT,
            DwHandle(24),
            DwHandle(21),
            DwHandle(22),
            DwHandle(23),
            CHANNEL
        ]
    );
    let ready = fixture.sent.last().unwrap();
    assert!(
        wyrmroot_loader::launch::parse_ready_for_profile(LaunchProfile::JobV2Namespace, ready, 9)
            .is_ok()
    );

    // Any other handle count is refused before anything is closed.
    let mut short = StreamFixture::new();
    short.handles.truncate(3);
    assert!(matches!(
        run_stream_hello(&mut short, CHANNEL),
        Err(HelloError::ReceiveCounts(_))
    ));
    assert!(short.closed.is_empty());
}
