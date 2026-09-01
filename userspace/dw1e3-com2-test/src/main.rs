#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

use deepwyrm_syscall::{
    DW_HANDLE_TRANSFER_MOVE, DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL,
    DW_RIGHT_INSPECT, DW_RIGHT_READ, DW_RIGHT_TRANSFER, DW_RIGHT_WAIT, DW_RIGHT_WRITE,
    DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DW_SIGNAL_WRITABLE, DW_STATUS_WOULD_BLOCK, DwHandle,
    DwHandleTransferV1, DwObjectType, DwReceivedHandleInfoV1, DwRights, DwSignals,
};
use wyrmroot_device_proto::{
    ConnectorMessage, SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY,
    connector::{
        RECORD_BYTES as CONNECTOR_BYTES, encode as encode_connector, parse as parse_connector,
    },
};
use wyrmroot_dw1e3_com2_test::{
    CHALLENGE_BYTES, CHALLENGE_GENERATION, CLIENT_TRANSACTION_ID, CONNECT_TRANSACTION_ID,
    CONTROL_BYTES, ControllerMessage, challenge_matches_commitment, encode as encode_controller,
    fnv1a64, parse as parse_controller, response,
};
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, HEADER_BYTES as WRLP_HEADER_BYTES, LaunchProfile, SELF_ROOT_RIGHTS,
    encode_ready_for_profile, parse_init,
};
use wyrmroot_registry_proto::{
    HEADER_BYTES as REGISTRY_HEADER_BYTES, Header as RegistryHeader, Lookup,
    Message as RegistryMessage, MessageType as RegistryMessageType, ProtocolVersion, encode_lookup,
    parse as parse_registry, parse_correlation_environment,
};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, Dw1e3ReportEvent, NativeError, StartupBlock, close_handle,
    create_channel, dw1e3_build_nonce, dw1e3_report, panic_abort, query_capability_info,
    receive_channel, send_channel, validate_bootstrap_channel, wait_one,
};
use wyrmroot_stream_proto::{MAX_RECORD_BYTES, decode_data, encode_data};

const FAILURE_BASE: u32 = 0xE3A2_0000;
const PROBE_INIT_BYTES: usize = LaunchProfile::RegistryClient.init_size();
const BROAD_CHANNEL_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_TRANSFER.0,
);

fn probe_main(startup: StartupBlock<'_>) -> u32 {
    run(startup).unwrap_or_else(|step| FAILURE_BASE | step)
}

fn run(startup: StartupBlock<'_>) -> Result<u32, u32> {
    let parent = startup.bootstrap_channel().as_abi();
    validate_bootstrap_channel(
        query_capability_info(parent).map_err(|_| 1u32)?,
        BOOTSTRAP_CHANNEL_EXPECTATION,
    )
    .map_err(|_| 2u32)?;
    if startup.envc() != 3 {
        return Err(3);
    }
    let environment = [
        startup.env(0).ok_or(4u32)?.as_str(),
        startup.env(1).ok_or(4u32)?.as_str(),
        startup.env(2).ok_or(4u32)?.as_str(),
    ];
    let correlation = parse_correlation_environment(&environment).map_err(|_| 5u32)?;

    wait_readable(parent, 6)?;
    let mut init = [0u8; PROBE_INIT_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 2];
    let counts = receive_channel(parent, &mut init, &mut handles).map_err(|_| 7u32)?;
    if counts.bytes != init.len() || counts.handles != 2 {
        close_received(&handles, counts.handles);
        return Err(8);
    }
    let parsed = match parse_init(LaunchProfile::RegistryClient, &init, &handles) {
        Ok(parsed) => parsed,
        Err(_) => {
            close_received(&handles, 2);
            return Err(9);
        }
    };
    if !valid_received(handles[0], DW_OBJECT_TYPE_ADDRESS_REGION, SELF_ROOT_RIGHTS)
        || !valid_received(handles[1], DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS)
    {
        close_received(&handles, 2);
        return Err(10);
    }
    let registry = handles[1].handle;
    close_handle(handles[0].handle).map_err(|_| 11u32)?;
    let mut ready = [0; WRLP_HEADER_BYTES];
    let ready_size = encode_ready_for_profile(
        LaunchProfile::RegistryClient,
        parsed.transaction_id,
        &mut ready,
    )
    .map_err(|_| 12u32)?;
    send_channel(parent, &ready[..ready_size], &[]).map_err(|_| 13u32)?;

    let nonce = dw1e3_build_nonce().map_err(|_| 14u32)?;
    let configure = receive_controller(parent, 16)?;
    let ControllerMessage::Configure {
        nonce: configured_nonce,
        publication_generation,
        challenge_generation,
        expected_length,
        expected_hash,
    } = configure
    else {
        return Err(17);
    };
    if configured_nonce != nonce {
        return Err(18);
    }

    let (direct, service) = create_channel(BROAD_CHANNEL_RIGHTS).map_err(|_| 19u32)?;
    let registry_header = RegistryHeader {
        message_type: RegistryMessageType::LookupConnect,
        registry_generation: correlation.registry_generation,
        endpoint_id: correlation.endpoint_id,
        endpoint_generation: correlation.endpoint_generation,
        transaction_id: CLIENT_TRANSACTION_ID,
    };
    let policy = SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY;
    let lookup = Lookup {
        protocol_id: policy.protocol_id,
        version: ProtocolVersion {
            major: policy.protocol_major,
            minor: policy.protocol_minor,
        },
        service_name: policy.service_name,
    };
    let mut lookup_bytes = [0u8; 256];
    let lookup_size =
        encode_lookup(registry_header, lookup, &mut lookup_bytes).map_err(|_| 20u32)?;
    let transfer = DwHandleTransferV1 {
        handle: service,
        requested_rights: BROAD_CHANNEL_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if send_channel(registry, &lookup_bytes[..lookup_size], &[transfer]).is_err() {
        let _ = close_handle(service);
        let _ = close_handle(direct);
        return Err(21);
    }
    wait_readable(registry, 22)?;
    let mut connected_bytes = [0; REGISTRY_HEADER_BYTES];
    let mut no_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts =
        receive_channel(registry, &mut connected_bytes, &mut no_handles).map_err(|_| 23u32)?;
    if counts.bytes != connected_bytes.len() || counts.handles != 0 {
        close_received(&no_handles, counts.handles);
        return Err(24);
    }
    let connected = parse_registry(&connected_bytes, 0).map_err(|_| 25u32)?;
    if connected.header
        != (RegistryHeader {
            message_type: RegistryMessageType::Connected,
            ..registry_header
        })
        || connected.message != RegistryMessage::Connected
    {
        return Err(26);
    }
    close_handle(registry).map_err(|_| 27u32)?;

    let request = ConnectorMessage::ConnectStream {
        publication_generation,
        client_transaction_id: CONNECT_TRANSACTION_ID,
    };
    let mut connector = [0; CONNECTOR_BYTES];
    encode_connector(request, &mut connector).map_err(|_| 28u32)?;
    send_channel(direct, &connector, &[]).map_err(|_| 29u32)?;
    wait_readable(direct, 30)?;
    let mut stream_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(direct, &mut connector, &mut stream_handles).map_err(|_| 31u32)?;
    if counts.bytes != connector.len()
        || counts.handles != 1
        || !valid_received(
            stream_handles[0],
            DW_OBJECT_TYPE_CHANNEL,
            CHILD_CHANNEL_RIGHTS,
        )
    {
        close_received(&stream_handles, counts.handles);
        return Err(32);
    }
    let ConnectorMessage::Connected { identity } =
        parse_connector(&connector).map_err(|_| 33u32)?
    else {
        close_received(&stream_handles, 1);
        return Err(34);
    };
    if identity.publication_generation != publication_generation
        || identity.client_transaction_id != CONNECT_TRANSACTION_ID
    {
        close_received(&stream_handles, 1);
        return Err(35);
    }
    close_handle(direct).map_err(|_| 36u32)?;
    let stream = stream_handles[0].handle;

    send_controller(
        parent,
        ControllerMessage::Attached {
            nonce,
            publication_generation,
            stream_generation: identity.stream_generation,
            challenge_generation,
        },
    )?;
    let permit = receive_controller(parent, 37)?;
    if permit
        != (ControllerMessage::ArmPermit {
            nonce,
            publication_generation,
            stream_generation: identity.stream_generation,
            challenge_generation,
            expected_length,
            expected_hash,
        })
    {
        let _ = close_handle(stream);
        return Err(38);
    }

    let mut challenge = [0u8; CHALLENGE_BYTES];
    receive_exact_stream(stream, &mut challenge)?;
    // The selector build/evidence nonce is deliberately distinct from either
    // frozen raw challenge nonce in E3B. The controller's exact commitment is
    // therefore the only payload authority here; COM2 carries no control tag.
    if !challenge_matches_commitment(&challenge, expected_length, expected_hash) {
        let _ = close_handle(stream);
        return Err(39);
    }
    let response = response(&challenge);
    send_stream(stream, &response)?;
    let report_event = if challenge_generation == CHALLENGE_GENERATION {
        Dw1e3ReportEvent::Challenge1Response
    } else {
        Dw1e3ReportEvent::Challenge2Response
    };
    dw1e3_report(
        report_event,
        response.len() as u64,
        fnv1a64(&response),
        nonce,
    )
    .map_err(|_| 40u32)?;
    send_controller(
        parent,
        ControllerMessage::ResponseCommitted {
            nonce,
            publication_generation,
            stream_generation: identity.stream_generation,
            challenge_generation,
            response_length: response.len() as u64,
            response_hash: fnv1a64(&response),
        },
    )?;
    if challenge_generation == CHALLENGE_GENERATION {
        await_stream_peer_closed(stream)?;
        send_controller(
            parent,
            ControllerMessage::StreamPeerClosed {
                nonce,
                publication_generation,
                stream_generation: identity.stream_generation,
                challenge_generation,
            },
        )?;
        wait_peer_closed(parent, 41)?;
    }
    close_handle(stream).map_err(|_| 41u32)?;
    close_handle(parent).map_err(|_| 42u32)?;
    Ok(0)
}

/// A peer-close is not sufficient: consume any queued records first and only
/// report closure after a fresh receive proves the transport queue empty.
fn await_stream_peer_closed(stream: DwHandle) -> Result<(), u32> {
    loop {
        let observed = wait_one(
            stream,
            DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
            deepwyrm_syscall::DW_DEADLINE_INFINITE,
        )
        .map_err(|_| 54u32)?;
        if observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 {
            let mut wire = [0; MAX_RECORD_BYTES];
            let mut handles = [DwReceivedHandleInfoV1::default(); 1];
            let counts = receive_channel(stream, &mut wire, &mut handles).map_err(|_| 55u32)?;
            if counts.bytes > wire.len() || counts.handles != 0 {
                close_received(&handles, counts.handles);
                return Err(56);
            }
            let data = decode_data(&wire[..counts.bytes]).map_err(|_| 57u32)?;
            if !data.payload().is_empty() {
                return Err(57);
            }
            continue;
        }
        if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
            let mut wire = [0; MAX_RECORD_BYTES];
            let mut handles = [DwReceivedHandleInfoV1::default(); 1];
            match receive_channel(stream, &mut wire, &mut handles) {
                Err(NativeError::Status(status))
                    if status == deepwyrm_syscall::DW_STATUS_PEER_CLOSED =>
                {
                    return Ok(());
                }
                Ok(counts) => {
                    if counts.handles != 0 || counts.bytes > wire.len() {
                        close_received(&handles, counts.handles);
                        return Err(58);
                    }
                    // `PEER_CLOSED` can coexist with one final queued record.
                    // Decode and drain it before the next fresh receive proves
                    // the queue empty; silently accepting that record would
                    // make peer-close evidence weaker than the contract.
                    let data = decode_data(&wire[..counts.bytes]).map_err(|_| 58u32)?;
                    if !data.payload().is_empty() {
                        return Err(58);
                    }
                    continue;
                }
                Err(_) => return Err(59),
            }
        }
    }
}

fn wait_peer_closed(handle: DwHandle, stage: u32) -> Result<(), u32> {
    let observed = wait_one(
        handle,
        DwSignals(DW_SIGNAL_PEER_CLOSED.0),
        deepwyrm_syscall::DW_DEADLINE_INFINITE,
    )
    .map_err(|_| stage)?;
    if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 == 0 {
        return Err(stage);
    }
    Ok(())
}

fn receive_controller(parent: DwHandle, stage: u32) -> Result<ControllerMessage, u32> {
    wait_readable(parent, stage)?;
    let mut bytes = [0; CONTROL_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(parent, &mut bytes, &mut handles).map_err(|_| stage)?;
    if counts.bytes != bytes.len() || counts.handles != 0 {
        close_received(&handles, counts.handles);
        return Err(stage);
    }
    parse_controller(&bytes).map_err(|_| stage)
}

fn send_controller(parent: DwHandle, message: ControllerMessage) -> Result<(), u32> {
    let mut bytes = [0; CONTROL_BYTES];
    encode_controller(message, &mut bytes).map_err(|_| 43u32)?;
    send_channel(parent, &bytes, &[]).map_err(|_| 44u32)
}

fn receive_exact_stream(stream: DwHandle, output: &mut [u8]) -> Result<(), u32> {
    let mut used = 0;
    while used != output.len() {
        wait_readable(stream, 45)?;
        let mut wire = [0; MAX_RECORD_BYTES];
        let mut handles = [DwReceivedHandleInfoV1::default(); 1];
        let counts = receive_channel(stream, &mut wire, &mut handles).map_err(|_| 46u32)?;
        if counts.bytes > wire.len() || counts.handles != 0 {
            close_received(&handles, counts.handles);
            return Err(47);
        }
        let payload = decode_data(&wire[..counts.bytes])
            .map_err(|_| 48u32)?
            .payload();
        // WRST permits zero-length DATA as a no-op.  It must neither advance
        // nor invalidate the exact fixed challenge accumulation.
        if payload.is_empty() {
            continue;
        }
        if payload.len() > output.len() - used {
            return Err(49);
        }
        output[used..used + payload.len()].copy_from_slice(payload);
        used += payload.len();
    }
    Ok(())
}

fn send_stream(stream: DwHandle, payload: &[u8]) -> Result<(), u32> {
    let mut wire = [0; MAX_RECORD_BYTES];
    let size = encode_data(payload, &mut wire).map_err(|_| 50u32)?;
    loop {
        match send_channel(stream, &wire[..size], &[]) {
            Ok(()) => return Ok(()),
            Err(NativeError::Status(status)) if status == DW_STATUS_WOULD_BLOCK => {
                let observed = wait_one(
                    stream,
                    DwSignals(DW_SIGNAL_WRITABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
                    deepwyrm_syscall::DW_DEADLINE_INFINITE,
                )
                .map_err(|_| 51u32)?;
                if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0
                    || observed.observed.0 & DW_SIGNAL_WRITABLE.0 == 0
                {
                    return Err(52);
                }
            }
            Err(_) => return Err(53),
        }
    }
}

fn wait_readable(handle: DwHandle, stage: u32) -> Result<(), u32> {
    let observed = wait_one(
        handle,
        DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        deepwyrm_syscall::DW_DEADLINE_INFINITE,
    )
    .map_err(|_| stage)?;
    if observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(stage);
    }
    Ok(())
}

fn valid_received(
    info: DwReceivedHandleInfoV1,
    object_type: DwObjectType,
    rights: DwRights,
) -> bool {
    info.handle.0 != 0
        && info.object_type == object_type
        && info.rights == rights
        && info.reserved0 == 0
        && info.reserved == [0; 2]
}

fn close_received(handles: &[DwReceivedHandleInfoV1], count: usize) {
    for info in handles.iter().take(count) {
        let _ = close_handle(info.handle);
    }
}

wyrmroot_runtime::native_entry!(crate::probe_main);

const _: () = assert!(PROBE_INIT_BYTES == WRLP_HEADER_BYTES + 2 * 8);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    panic_abort()
}
