use deepwyrm_syscall::{
    DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT, DW_RIGHT_READ, DW_RIGHT_WAIT,
    DW_RIGHT_WRITE, DW_STATUS_BAD_HANDLE, DwHandle, DwObjectType, DwReceivedHandleInfoV1, DwRights,
};
use wyrmroot_hello::{HelloError, HelloSystem, run_hello};
use wyrmroot_loader::launch::{LaunchProfile, encode_init, parse_ready};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, CapabilityValidationError, NativeError,
    ReceiveCounts,
};

const CHANNEL: DwHandle = DwHandle(11);

struct Fixture {
    init: [u8; 40],
    received_handles: usize,
    channel_rights: DwRights,
    sent: Vec<u8>,
    closed: Vec<DwHandle>,
}

impl Fixture {
    fn valid() -> Self {
        let mut init = [0_u8; 40];
        encode_init(LaunchProfile::Hello, 2, &mut init).unwrap();
        Self {
            init,
            received_handles: 0,
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
        _: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError> {
        assert_eq!(channel, CHANNEL);
        bytes.copy_from_slice(&self.init);
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

#[test]
fn hello_acknowledges_the_parent_channel_then_closes_it() {
    let mut fixture = Fixture::valid();
    assert_eq!(run_hello(&mut fixture, CHANNEL), Ok(()));
    assert_eq!(parse_ready(&fixture.sent, 2), Ok(()));
    assert_eq!(fixture.closed, [CHANNEL]);
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
