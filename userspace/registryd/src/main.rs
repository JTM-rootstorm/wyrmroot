#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;
use deepwyrm_syscall::{
    DW_CHANNEL_MAX_HANDLES, DW_DEADLINE_INFINITE, DW_HANDLE_TRANSFER_MOVE,
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_INSPECT, DW_RIGHT_READ,
    DW_RIGHT_TRANSFER, DW_RIGHT_WAIT, DW_RIGHT_WRITE, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE,
    DwHandle, DwHandleTransferV1, DwReceivedHandleInfoV1, DwRights, DwSignals, DwWaitItemV1,
};
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, HEADER_BYTES as WRLP_HEADER_BYTES, LaunchProfile,
    encode_ready_for_profile, parse_init,
};
use wyrmroot_registry_proto as _;
use wyrmroot_registryd::InstalledEndpoint;
use wyrmroot_registryd::service::{
    ChannelRights, MAX_RECEIVED_HANDLES, ReceiveCounts, ReceivedHandle, RegistryService, Transport,
    WaitEvent,
};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, StartupBlock, close_handle, panic_abort, query_capability_info,
    receive_channel, send_channel, validate_bootstrap_channel, wait_many,
};

const BROAD_CHANNEL_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_TRANSFER.0,
);

fn main(startup: StartupBlock<'_>) -> u32 {
    match run(startup) {
        Ok(()) => 0,
        Err(code) => code,
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    panic_abort()
}

const _: () = assert!(MAX_RECEIVED_HANDLES == DW_CHANNEL_MAX_HANDLES as usize);

fn run(startup: StartupBlock<'_>) -> Result<(), u32> {
    let bootstrap = startup.bootstrap_channel().as_abi();
    let bootstrap_info = query_capability_info(bootstrap).map_err(|_| 0xB101_0001_u32)?;
    validate_bootstrap_channel(bootstrap_info, BOOTSTRAP_CHANNEL_EXPECTATION)
        .map_err(|_| 0xB101_0002_u32)?;
    let mut init = [0u8; 64];
    let mut handles = [DwReceivedHandleInfoV1::default(); 2];
    let counts =
        receive_channel(bootstrap, &mut init, &mut handles).map_err(|_| 0xB101_0003_u32)?;
    if counts.bytes > init.len() || counts.handles != 2 {
        return Err(0xB101_0004_u32);
    }
    let parsed = parse_init(
        LaunchProfile::BootstrapRegistry,
        &init[..counts.bytes],
        &handles,
    )
    .map_err(|_| 0xB101_0005_u32)?;
    validate_received(
        handles[0],
        DW_OBJECT_TYPE_ADDRESS_REGION,
        wyrmroot_loader::launch::SELF_ROOT_RIGHTS,
    )
    .map_err(|_| 0xB101_0006_u32)?;
    validate_received(handles[1], DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS)
        .map_err(|_| 0xB101_0007_u32)?;
    let self_root = handles[0].handle;
    let control = handles[1].handle;
    let mut ready = [0u8; WRLP_HEADER_BYTES];
    let ready_len = encode_ready_for_profile(
        LaunchProfile::BootstrapRegistry,
        parsed.transaction_id,
        &mut ready,
    )
    .map_err(|_| 0xB101_0008_u32)?;
    send_channel(bootstrap, &ready[..ready_len], &[]).map_err(|_| 0xB101_0009_u32)?;
    close_handle(bootstrap).map_err(|_| 0xB101_000A_u32)?;
    close_handle(self_root).map_err(|_| 0xB101_000B_u32)?;

    let mut service = RegistryService::new(control.0);
    let mut transport = NativeTransport;
    loop {
        service.step(&mut transport).map_err(|_| 0xB101_0010_u32)?;
    }
}

struct NativeTransport;

impl Transport for NativeTransport {
    type Error = u32;

    fn wait(&mut self, control: u64, endpoints: &[InstalledEndpoint]) -> Result<WaitEvent, u32> {
        let mut items = [DwWaitItemV1::default(); 65];
        items[0] = wait_item(DwHandle(control));
        for (index, endpoint) in endpoints.iter().enumerate() {
            items[index + 1] = wait_item(DwHandle(endpoint.handle));
        }
        let observed = wait_many(&items[..endpoints.len() + 1], DW_DEADLINE_INFINITE)
            .map_err(|_| 0xB101_0011_u32)?;
        let index = usize::try_from(observed.index).map_err(|_| 0xB101_0012_u32)?;
        Ok(WaitEvent {
            endpoint_index: (index != 0).then_some(index - 1),
            readable: observed.observed.0 & DW_SIGNAL_READABLE.0 != 0,
            peer_closed: observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0,
        })
    }

    fn receive(
        &mut self,
        channel: u64,
        bytes: &mut [u8],
        handles: &mut [ReceivedHandle],
    ) -> Result<ReceiveCounts, u32> {
        let mut native = [DwReceivedHandleInfoV1::default(); MAX_RECEIVED_HANDLES];
        let counts =
            receive_channel(DwHandle(channel), bytes, &mut native).map_err(|_| 0xB101_0013_u32)?;
        if counts.handles <= handles.len() {
            for index in 0..counts.handles {
                handles[index] = ReceivedHandle {
                    handle: native[index].handle.0,
                    metadata_is_channel: native[index].object_type == DW_OBJECT_TYPE_CHANNEL,
                    metadata_rights: native[index].rights.0,
                };
            }
        }
        Ok(ReceiveCounts {
            bytes: counts.bytes,
            handles: counts.handles,
        })
    }

    fn validate_channel(
        &mut self,
        handle: ReceivedHandle,
        rights: ChannelRights,
    ) -> Result<(), u32> {
        let expected = match rights {
            ChannelRights::Child => CHILD_CHANNEL_RIGHTS,
            ChannelRights::Broad => BROAD_CHANNEL_RIGHTS,
        };
        if !handle.metadata_is_channel || handle.metadata_rights != expected.0 {
            return Err(0xB101_0014_u32);
        }
        let fresh = query_capability_info(DwHandle(handle.handle)).map_err(|_| 0xB101_0015_u32)?;
        if fresh.object_type != DW_OBJECT_TYPE_CHANNEL || fresh.rights != expected {
            return Err(0xB101_0016_u32);
        }
        Ok(())
    }

    fn send(&mut self, channel: u64, bytes: &[u8]) -> Result<(), u32> {
        send_channel(DwHandle(channel), bytes, &[]).map_err(|_| 0xB101_0017_u32)
    }

    fn send_move(
        &mut self,
        channel: u64,
        bytes: &[u8],
        moved_handle: u64,
        reduced_rights: ChannelRights,
    ) -> Result<(), u32> {
        let requested_rights = match reduced_rights {
            ChannelRights::Child => CHILD_CHANNEL_RIGHTS,
            ChannelRights::Broad => BROAD_CHANNEL_RIGHTS,
        };
        let transfer = DwHandleTransferV1 {
            handle: DwHandle(moved_handle),
            requested_rights,
            operation: DW_HANDLE_TRANSFER_MOVE,
            reserved0: 0,
            reserved: [0; 2],
        };
        send_channel(DwHandle(channel), bytes, &[transfer]).map_err(|_| 0xB101_0018_u32)
    }

    fn close(&mut self, handle: u64) {
        let _ = close_handle(DwHandle(handle));
    }
}

fn validate_received(
    info: DwReceivedHandleInfoV1,
    object_type: deepwyrm_syscall::DwObjectType,
    rights: DwRights,
) -> Result<(), ()> {
    if info.object_type != object_type || info.rights != rights {
        return Err(());
    }
    let fresh = query_capability_info(info.handle).map_err(|_| ())?;
    if fresh.object_type != object_type || fresh.rights != rights {
        return Err(());
    }
    Ok(())
}

const fn wait_item(handle: DwHandle) -> DwWaitItemV1 {
    DwWaitItemV1 {
        handle,
        signals: DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
    }
}

wyrmroot_runtime::native_entry!(crate::main);
