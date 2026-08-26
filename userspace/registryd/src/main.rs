#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;
use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_HANDLE_TRANSFER_MOVE, DW_OBJECT_TYPE_ADDRESS_REGION,
    DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_INSPECT, DW_RIGHT_READ, DW_RIGHT_TRANSFER, DW_RIGHT_WAIT,
    DW_RIGHT_WRITE, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DwHandle, DwHandleTransferV1,
    DwReceivedHandleInfoV1, DwRights, DwSignals, DwWaitItemV1,
};
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, HEADER_BYTES as WRLP_HEADER_BYTES, LaunchProfile,
    encode_ready_for_profile, parse_init,
};
use wyrmroot_registry_proto::{
    HEADER_BYTES as WRRG_HEADER_BYTES, Header, Lookup, Message, MessageType, encode_empty,
    encode_error, encode_lookup, parse,
};
use wyrmroot_registryd::{EndpointIdentity, EndpointKind, RegistryState};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, StartupBlock, close_handle, panic_abort, query_capability_info,
    receive_channel, send_channel, validate_bootstrap_channel, wait_many,
};

const MAX_ENDPOINTS: usize = 64;
const MAX_WAIT_ITEMS: usize = 1 + MAX_ENDPOINTS;
const MESSAGE_BYTES: usize = 512;
const BROAD_CHANNEL_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_TRANSFER.0,
);

fn main(startup: StartupBlock<'_>) -> u32 {
    match run(startup) {
        Ok(()) => 0,
        Err(code) => code,
    }
}

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

    let mut state = None;
    loop {
        service_once(control, &mut state)?;
    }
}

fn service_once(control: DwHandle, state: &mut Option<RegistryState>) -> Result<(), u32> {
    let mut items = [DwWaitItemV1::default(); MAX_WAIT_ITEMS];
    items[0] = wait_item(control);
    let mut count = 1;
    if let Some(registry) = state.as_ref() {
        while let Some(endpoint) = registry.installed_endpoint(count - 1) {
            items[count] = wait_item(DwHandle(endpoint.handle));
            count += 1;
        }
    }
    let observed = wait_many(&items[..count], DW_DEADLINE_INFINITE).map_err(|_| 0xB101_0010_u32)?;
    let index = usize::try_from(observed.index).map_err(|_| 0xB101_0011_u32)?;
    if index == 0 && observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
        return Err(0xB101_0012_u32);
    }
    if index != 0 && observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
        let registry = state.as_mut().ok_or(0xB101_0013_u32)?;
        let endpoint = registry
            .installed_endpoint(index - 1)
            .ok_or(0xB101_0014_u32)?;
        let handle = registry
            .peer_closed(endpoint.identity)
            .map_err(|_| 0xB101_0015_u32)?;
        close_handle(DwHandle(handle)).map_err(|_| 0xB101_0016_u32)?;
        return Ok(());
    }
    if observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(0xB101_0017_u32);
    }

    let endpoint = if index == 0 {
        None
    } else {
        Some(
            state
                .as_ref()
                .and_then(|registry| registry.installed_endpoint(index - 1))
                .ok_or(0xB101_0018_u32)?,
        )
    };
    let channel = endpoint.map_or(control, |value| DwHandle(value.handle));
    let mut bytes = [0u8; MESSAGE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(channel, &mut bytes, &mut handles).map_err(|_| 0xB101_0019_u32)?;
    if counts.bytes > bytes.len() || counts.handles > handles.len() {
        close_received(&handles[..counts.handles.min(handles.len())]);
        return Err(0xB101_001A_u32);
    }
    let request = match parse(&bytes[..counts.bytes], counts.handles) {
        Ok(request) => request,
        Err(_) => {
            close_received(&handles[..counts.handles]);
            return Ok(());
        }
    };

    if let Some(endpoint) = endpoint {
        if request.header.endpoint_id != endpoint.identity.id
            || request.header.endpoint_generation != endpoint.identity.generation
            || state
                .as_ref()
                .is_none_or(|registry| request.header.registry_generation != registry.generation())
        {
            close_received(&handles[..counts.handles]);
            return Ok(());
        }
        handle_endpoint(
            channel,
            endpoint.kind,
            request.header,
            request.message,
            handles,
            state,
        )
    } else {
        handle_control(request.header, request.message, handles, state)
    }
}

fn handle_control(
    header: Header,
    message: Message<'_>,
    handles: [DwReceivedHandleInfoV1; 1],
    state: &mut Option<RegistryState>,
) -> Result<(), u32> {
    if !matches!(
        message,
        Message::InstallPublication(_) | Message::InstallClient(_)
    ) {
        close_received(&handles);
        return Ok(());
    }
    if validate_received(handles[0], DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS).is_err() {
        close_received(&handles);
        return Ok(());
    }
    if state.is_none() {
        *state = Some(RegistryState::new(header.registry_generation).map_err(|_| 0xB101_0021_u32)?);
    }
    let registry = state.as_mut().ok_or(0xB101_0022_u32)?;
    let result = match message {
        Message::InstallPublication(install) => {
            registry.install_publication(header.registry_generation, handles[0].handle.0, install)
        }
        Message::InstallClient(install) => {
            registry.install_client(header.registry_generation, handles[0].handle.0, install)
        }
        _ => unreachable!(),
    };
    if result.is_err() {
        close_received(&handles);
    }
    Ok(())
}

fn handle_endpoint(
    channel: DwHandle,
    kind: EndpointKind,
    header: Header,
    message: Message<'_>,
    handles: [DwReceivedHandleInfoV1; 1],
    state: &mut Option<RegistryState>,
) -> Result<(), u32> {
    let registry = state.as_mut().ok_or(0xB101_0030_u32)?;
    let identity = EndpointIdentity {
        id: header.endpoint_id,
        generation: header.endpoint_generation,
    };
    let reply_type = match (kind, message) {
        (EndpointKind::Publication, Message::Publish) => {
            registry
                .publish(identity, header.transaction_id)
                .map_err(|_| 0xB101_0031_u32)?;
            Some(MessageType::Published)
        }
        (EndpointKind::Publication, Message::Retire) => {
            registry
                .retire(identity, header.transaction_id)
                .map_err(|_| 0xB101_0032_u32)?;
            Some(MessageType::Retired)
        }
        (EndpointKind::Client, Message::LookupConnect(lookup)) => {
            if validate_received(handles[0], DW_OBJECT_TYPE_CHANNEL, BROAD_CHANNEL_RIGHTS).is_err()
            {
                close_received(&handles);
                return Ok(());
            }
            connect(
                registry,
                channel,
                identity,
                header,
                lookup,
                handles[0].handle,
            )?;
            return Ok(());
        }
        _ => {
            close_received(&handles);
            None
        }
    };
    if let Some(message_type) = reply_type {
        let mut reply = [0u8; WRRG_HEADER_BYTES];
        let size = encode_empty(
            Header {
                message_type,
                ..header
            },
            &mut reply,
        )
        .map_err(|_| 0xB101_0034_u32)?;
        send_channel(channel, &reply[..size], &[]).map_err(|_| 0xB101_0035_u32)?;
    }
    Ok(())
}

fn connect(
    registry: &mut RegistryState,
    client_channel: DwHandle,
    client: EndpointIdentity,
    header: Header,
    lookup: Lookup<'_>,
    service_endpoint: DwHandle,
) -> Result<(), u32> {
    let offer = match registry.lookup(client, header.transaction_id, lookup) {
        Ok(offer) => offer,
        Err(_) => {
            close_handle(service_endpoint).map_err(|_| 0xB101_0040_u32)?;
            send_error(client_channel, header, 1)?;
            return Ok(());
        }
    };
    let offer_header = Header {
        message_type: MessageType::ConnectOffer,
        endpoint_id: offer.publication.id,
        endpoint_generation: offer.publication.generation,
        ..header
    };
    let mut bytes = [0u8; MESSAGE_BYTES];
    let size = encode_lookup(offer_header, lookup, &mut bytes).map_err(|_| 0xB101_0041_u32)?;
    let transfer = DwHandleTransferV1 {
        handle: service_endpoint,
        requested_rights: CHILD_CHANNEL_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if send_channel(
        DwHandle(offer.publication_handle),
        &bytes[..size],
        &[transfer],
    )
    .is_err()
    {
        close_handle(service_endpoint).map_err(|_| 0xB101_0042_u32)?;
        send_error(client_channel, header, 1)?;
        return Ok(());
    }
    let mut connected = [0u8; WRRG_HEADER_BYTES];
    let size = encode_empty(
        Header {
            message_type: MessageType::Connected,
            ..header
        },
        &mut connected,
    )
    .map_err(|_| 0xB101_0043_u32)?;
    send_channel(client_channel, &connected[..size], &[]).map_err(|_| 0xB101_0044_u32)
}

fn send_error(channel: DwHandle, header: Header, code: u32) -> Result<(), u32> {
    let mut bytes = [0u8; 72];
    let size = encode_error(
        Header {
            message_type: MessageType::Error,
            ..header
        },
        code,
        &mut bytes,
    )
    .map_err(|_| 0xB101_0050_u32)?;
    send_channel(channel, &bytes[..size], &[]).map_err(|_| 0xB101_0051_u32)
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

fn close_received(handles: &[DwReceivedHandleInfoV1]) {
    for info in handles {
        let _ = close_handle(info.handle);
    }
}

const fn wait_item(handle: DwHandle) -> DwWaitItemV1 {
    DwWaitItemV1 {
        handle,
        signals: DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
    }
}

wyrmroot_runtime::native_entry!(crate::main);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    panic_abort()
}
