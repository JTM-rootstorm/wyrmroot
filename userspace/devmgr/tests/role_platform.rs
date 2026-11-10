//! devmgr's role driven through the runtime's recording platform.
//!
//! These drive `wyrmroot_devmgr::role::run` with scripted kernel replies and
//! check the exact syscall sequence and the failure code it stops with. They
//! cover the bootstrap stages, which need no manifest or driver.

use wyrmroot_runtime as _;
use {deepwyrm_syscall as _, wyrmroot_device_proto as _, wyrmroot_devmgr as _};
#[cfg(feature = "native-devmgr")]
use {wyrmroot_loader as _, wyrmroot_registry_proto as _};

#[cfg(feature = "native-devmgr")]
mod bootstrap {
    use deepwyrm_syscall::{
        DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_READ, DW_STATUS_PEER_CLOSED, DwHandle,
        DwReceivedHandleInfoV1,
    };
    use wyrmroot_devmgr::role::run;
    use wyrmroot_runtime::platform::recording::{Call, Datagram, RecordingPlatform, Reply};
    use wyrmroot_runtime::{BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, NativeError};

    const BOOTSTRAP: DwHandle = DwHandle(0x10);

    /// devmgr's failure codes are `0xC101_0000 | stage`.
    const fn failure(stage: u32) -> u32 {
        0xC101_0000 | stage
    }

    #[cfg(not(feature = "wyr1c5-production"))]
    const INIT_BYTES: usize = wyrmroot_loader::launch::DEVICE_COORDINATOR_BYTES;
    #[cfg(feature = "wyr1c5-production")]
    const INIT_BYTES: usize = wyrmroot_loader::launch::DEVICE_COORDINATOR_RESOURCE_BYTES;
    #[cfg(not(feature = "wyr1c5-production"))]
    const INIT_HANDLES: usize = 3;
    #[cfg(feature = "wyr1c5-production")]
    const INIT_HANDLES: usize = 4;

    fn valid_bootstrap() -> Reply {
        Reply::CapabilityInfo(Ok(CapabilityInfo {
            object_type: BOOTSTRAP_CHANNEL_EXPECTATION.object_type,
            rights: BOOTSTRAP_CHANNEL_EXPECTATION.rights,
        }))
    }

    fn received(count: usize) -> Vec<DwReceivedHandleInfoV1> {
        (0..count)
            .map(|index| DwReceivedHandleInfoV1 {
                handle: DwHandle(0x20 + index as u64),
                object_type: DW_OBJECT_TYPE_CHANNEL,
                rights: DW_RIGHT_READ,
                ..DwReceivedHandleInfoV1::default()
            })
            .collect()
    }

    fn query_then_receive() -> [Call; 2] {
        [
            Call::QueryCapabilityInfo { handle: BOOTSTRAP },
            Call::ReceiveChannel {
                channel: BOOTSTRAP,
                byte_capacity: INIT_BYTES,
                handle_capacity: INIT_HANDLES,
            },
        ]
    }

    /// The bootstrap query is the first syscall. Its status stops the
    /// generation at stage 1, and nothing else runs.
    #[test]
    fn a_failed_bootstrap_query_stops_at_stage_1() {
        let mut platform = RecordingPlatform::scripted([Reply::CapabilityInfo(Err(
            NativeError::Status(DW_STATUS_PEER_CLOSED),
        ))]);
        assert_eq!(run(&mut platform, BOOTSTRAP), Err(failure(1)));
        assert_eq!(
            platform.calls(),
            [Call::QueryCapabilityInfo { handle: BOOTSTRAP }]
        );
        platform.assert_script_consumed();
    }

    /// A bootstrap Channel with the wrong rights is refused before INIT is
    /// received.
    #[test]
    fn a_wrong_bootstrap_channel_stops_at_stage_2() {
        let mut platform =
            RecordingPlatform::scripted([Reply::CapabilityInfo(Ok(CapabilityInfo {
                object_type: BOOTSTRAP_CHANNEL_EXPECTATION.object_type,
                rights: DW_RIGHT_READ,
            }))]);
        assert_eq!(run(&mut platform, BOOTSTRAP), Err(failure(2)));
        assert_eq!(
            platform.calls(),
            [Call::QueryCapabilityInfo { handle: BOOTSTRAP }]
        );
        platform.assert_script_consumed();
    }

    /// INIT is received into buffers sized for this build's launch profile.
    #[test]
    fn a_failed_init_receive_stops_at_stage_3() {
        let mut platform = RecordingPlatform::scripted([
            valid_bootstrap(),
            Reply::Receive(Err(NativeError::Status(DW_STATUS_PEER_CLOSED))),
        ]);
        assert_eq!(run(&mut platform, BOOTSTRAP), Err(failure(3)));
        assert_eq!(platform.calls(), query_then_receive());
        platform.assert_script_consumed();
    }

    /// An INIT with too few handles closes every handle it did receive, in
    /// order, before stopping at stage 4.
    #[test]
    fn a_short_handle_set_closes_what_arrived_then_stops_at_stage_4() {
        let handles = received(INIT_HANDLES - 1);
        let mut script = vec![
            valid_bootstrap(),
            Reply::Receive(Ok(Datagram {
                bytes: vec![0; INIT_BYTES],
                handles: handles.clone(),
            })),
        ];
        script.extend(handles.iter().map(|_| Reply::Unit(Ok(()))));
        let mut platform = RecordingPlatform::scripted(script);
        assert_eq!(run(&mut platform, BOOTSTRAP), Err(failure(4)));
        let mut expected = query_then_receive().to_vec();
        expected.extend(handles.iter().map(|info| Call::CloseHandle {
            handle: info.handle,
        }));
        assert_eq!(platform.calls(), expected);
        platform.assert_script_consumed();
    }

    /// A malformed INIT record with the right handle count closes every
    /// received handle before stopping at stage 5. A failed close does not
    /// stop the others.
    #[test]
    fn a_malformed_init_closes_every_handle_then_stops_at_stage_5() {
        let handles = received(INIT_HANDLES);
        let mut script = vec![
            valid_bootstrap(),
            Reply::Receive(Ok(Datagram {
                bytes: vec![0xff; INIT_BYTES],
                handles: handles.clone(),
            })),
            Reply::Unit(Err(NativeError::Status(DW_STATUS_PEER_CLOSED))),
        ];
        script.extend(handles.iter().skip(1).map(|_| Reply::Unit(Ok(()))));
        let mut platform = RecordingPlatform::scripted(script);
        assert_eq!(run(&mut platform, BOOTSTRAP), Err(failure(5)));
        let mut expected = query_then_receive().to_vec();
        expected.extend(handles.iter().map(|info| Call::CloseHandle {
            handle: info.handle,
        }));
        assert_eq!(platform.calls(), expected);
        platform.assert_script_consumed();
    }
}
