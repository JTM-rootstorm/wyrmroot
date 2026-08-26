#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL,
    DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DwHandle, DwObjectType, DwReceivedHandleInfoV1,
    DwRights,
};
use wyrmroot_launch_proto as _;
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, HEADER_BYTES as WRLP_BYTES, LaunchProfile, SELF_ROOT_RIGHTS,
    encode_ready_for_profile, parse_init,
};
use wyrmroot_registry_proto::{
    HEADER_BYTES as WRRG_BYTES, Message, MessageType as RegistryType, encode_empty, parse,
    parse_correlation_environment,
};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, StartupBlock, close_handle, panic_abort, query_capability_info,
    receive_channel, send_channel, validate_bootstrap_channel, wait_one,
};
use wyrmroot_wyr1b_gate::{Publisher, PublisherAction};
use wyrmroot_wyr1b_gate_proto::{
    Direction, ECHO_PROTOCOL_ID, ECHO_SERVICE_NAME, ECHO_VERSION_MAJOR, ECHO_VERSION_MINOR,
    MessageType, RECORD_BYTES, Record, encode, parse_for,
};

const PUB_ERROR_BASE: u32 = 0xB102_0000;

fn publisher_main(startup: StartupBlock<'_>) -> u32 {
    match run(startup) {
        Ok(code) => code,
        Err(code) => {
            if let Some(registry_generation) = startup_registry_generation(startup) {
                let _ = send_failure(
                    startup.bootstrap_channel().as_abi(),
                    None,
                    registry_generation,
                    code,
                );
            }
            code
        }
    }
}

fn run(startup: StartupBlock<'_>) -> Result<u32, u32> {
    if startup.envc() != 3 {
        return Err(PUB_ERROR_BASE + 0x0001);
    }
    let environment = [
        startup.env(0).ok_or(PUB_ERROR_BASE + 0x0002)?.as_str(),
        startup.env(1).ok_or(PUB_ERROR_BASE + 0x0002)?.as_str(),
        startup.env(2).ok_or(PUB_ERROR_BASE + 0x0002)?.as_str(),
    ];
    let mut actor =
        Publisher::from_environment(&environment).map_err(|_| PUB_ERROR_BASE + 0x0003)?;
    let (parent, publication) = ready(startup, LaunchProfile::BootstrapService)?;

    let configure = receive_record(parent, Direction::InitToChild, PUB_ERROR_BASE + 0x0010)?;
    if actor
        .parent(configure)
        .map_err(|_| PUB_ERROR_BASE + 0x0011)?
        != PublisherAction::Publish
    {
        return Err(PUB_ERROR_BASE + 0x0012);
    }
    let outcome = (|| {
        request_empty(
            &actor,
            publication,
            RegistryType::Publish,
            RegistryType::Published,
            PUB_ERROR_BASE + 0x0020,
        )?;
        send_record(
            parent,
            actor.published().map_err(|_| PUB_ERROR_BASE + 0x0021)?,
            PUB_ERROR_BASE + 0x0022,
        )?;

        wait_readable(publication, PUB_ERROR_BASE + 0x0030)?;
        let mut offer_bytes = [0u8; 256];
        let mut offered = [DwReceivedHandleInfoV1::default(); 1];
        let counts = receive_channel(publication, &mut offer_bytes, &mut offered)
            .map_err(|_| PUB_ERROR_BASE + 0x0031)?;
        if counts.bytes > offer_bytes.len() || counts.handles != 1 {
            if counts.handles == 1 {
                let _ = close_handle(offered[0].handle);
            }
            return Err(PUB_ERROR_BASE + 0x0032);
        }
        let parsed = match parse(&offer_bytes[..counts.bytes], counts.handles) {
            Ok(parsed) => parsed,
            Err(_) => {
                let _ = close_handle(offered[0].handle);
                return Err(PUB_ERROR_BASE + 0x0033);
            }
        };
        let Message::ConnectOffer(lookup) = parsed.message else {
            let _ = close_handle(offered[0].handle);
            return Err(PUB_ERROR_BASE + 0x0034);
        };
        let expected = actor
            .registry_header(RegistryType::ConnectOffer)
            .map_err(|_| PUB_ERROR_BASE + 0x0035)?;
        if parsed.header != expected
            || lookup.protocol_id != ECHO_PROTOCOL_ID
            || lookup.version.major != ECHO_VERSION_MAJOR
            || lookup.version.minor != ECHO_VERSION_MINOR
            || lookup.service_name != ECHO_SERVICE_NAME
            || validate_fresh(offered[0], DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS).is_err()
        {
            let _ = close_handle(offered[0].handle);
            return Err(PUB_ERROR_BASE + 0x0036);
        }
        actor.connected().map_err(|_| PUB_ERROR_BASE + 0x0037)?;
        let direct = offered[0].handle;
        let challenge = receive_record(direct, Direction::ClientToDirect, PUB_ERROR_BASE + 0x0038)?;
        let PublisherAction::Echo {
            direct: echo,
            report,
        } = actor
            .direct(challenge)
            .map_err(|_| PUB_ERROR_BASE + 0x0039)?
        else {
            return Err(PUB_ERROR_BASE + 0x003A);
        };
        send_record(direct, echo, PUB_ERROR_BASE + 0x003B)?;
        send_record(parent, report, PUB_ERROR_BASE + 0x003C)?;
        close_handle(direct).map_err(|_| PUB_ERROR_BASE + 0x003D)?;

        if configure.operation_id == 2 {
            let done = receive_record(parent, Direction::InitToChild, PUB_ERROR_BASE + 0x003E)?;
            if actor.parent(done).map_err(|_| PUB_ERROR_BASE + 0x003F)? != PublisherAction::Done {
                return Err(PUB_ERROR_BASE + 0x0040);
            }
            close_handle(publication).map_err(|_| PUB_ERROR_BASE + 0x0041)?;
            close_handle(parent).map_err(|_| PUB_ERROR_BASE + 0x0042)?;
            return Ok(0);
        }

        let retire = receive_record(parent, Direction::InitToChild, PUB_ERROR_BASE + 0x0043)?;
        if actor.parent(retire).map_err(|_| PUB_ERROR_BASE + 0x0041)? != PublisherAction::Retire {
            return Err(PUB_ERROR_BASE + 0x0042);
        }
        request_empty(
            &actor,
            publication,
            RegistryType::Retire,
            RegistryType::Retired,
            PUB_ERROR_BASE + 0x0043,
        )?;
        send_record(
            parent,
            actor.retired().map_err(|_| PUB_ERROR_BASE + 0x0044)?,
            PUB_ERROR_BASE + 0x0045,
        )?;

        let observed = wait_one(publication, DW_SIGNAL_PEER_CLOSED, DW_DEADLINE_INFINITE)
            .map_err(|_| PUB_ERROR_BASE + 0x0050)?;
        if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 == 0 {
            return Err(PUB_ERROR_BASE + 0x0051);
        }
        actor
            .publication_peer_closed(true)
            .map_err(|_| PUB_ERROR_BASE + 0x0052)?;
        let stale = receive_record(parent, Direction::InitToChild, PUB_ERROR_BASE + 0x0053)?;
        let PublisherAction::Report(stale) =
            actor.parent(stale).map_err(|_| PUB_ERROR_BASE + 0x0054)?
        else {
            return Err(PUB_ERROR_BASE + 0x0055);
        };
        if stale.message_type != MessageType::StaleRejected {
            return Err(PUB_ERROR_BASE + 0x0056);
        }
        send_record(parent, stale, PUB_ERROR_BASE + 0x0057)?;
        let done = receive_record(parent, Direction::InitToChild, PUB_ERROR_BASE + 0x0058)?;
        if actor.parent(done).map_err(|_| PUB_ERROR_BASE + 0x0059)? != PublisherAction::Done {
            return Err(PUB_ERROR_BASE + 0x005A);
        }
        close_handle(publication).map_err(|_| PUB_ERROR_BASE + 0x005B)?;
        close_handle(parent).map_err(|_| PUB_ERROR_BASE + 0x005C)?;
        Ok(0)
    })();
    if let Err(code) = outcome {
        let _ = send_failure(parent, Some(configure), configure.registry_generation, code);
        let _ = close_handle(publication);
        let _ = close_handle(parent);
    }
    outcome
}

fn ready(startup: StartupBlock<'_>, profile: LaunchProfile) -> Result<(DwHandle, DwHandle), u32> {
    let parent = startup.bootstrap_channel().as_abi();
    validate_bootstrap_channel(
        query_capability_info(parent).map_err(|_| PUB_ERROR_BASE + 0x0060)?,
        BOOTSTRAP_CHANNEL_EXPECTATION,
    )
    .map_err(|_| PUB_ERROR_BASE + 0x0061)?;
    wait_readable(parent, PUB_ERROR_BASE + 0x0062)?;
    let mut init = [0u8; 64];
    let mut handles = [DwReceivedHandleInfoV1::default(); 2];
    let counts =
        receive_channel(parent, &mut init, &mut handles).map_err(|_| PUB_ERROR_BASE + 0x0063)?;
    if counts.bytes > init.len() || counts.handles != 2 {
        close_received(&handles, counts.handles);
        return Err(PUB_ERROR_BASE + 0x0064);
    }
    let parsed = match parse_init(profile, &init[..counts.bytes], &handles) {
        Ok(parsed) => parsed,
        Err(_) => {
            close_received(&handles, 2);
            return Err(PUB_ERROR_BASE + 0x0065);
        }
    };
    if validate_fresh(handles[0], DW_OBJECT_TYPE_ADDRESS_REGION, SELF_ROOT_RIGHTS).is_err()
        || validate_fresh(handles[1], DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS).is_err()
    {
        close_received(&handles, 2);
        return Err(PUB_ERROR_BASE + 0x0069);
    }
    let mut ready = [0u8; WRLP_BYTES];
    let size = match encode_ready_for_profile(profile, parsed.transaction_id, &mut ready) {
        Ok(size) => size,
        Err(_) => {
            close_received(&handles, 2);
            return Err(PUB_ERROR_BASE + 0x0066);
        }
    };
    if send_channel(parent, &ready[..size], &[]).is_err() {
        close_received(&handles, 2);
        return Err(PUB_ERROR_BASE + 0x0067);
    }
    if close_handle(handles[0].handle).is_err() {
        let _ = close_handle(handles[1].handle);
        return Err(PUB_ERROR_BASE + 0x0068);
    }
    Ok((parent, handles[1].handle))
}

fn request_empty(
    actor: &Publisher,
    channel: DwHandle,
    request: RegistryType,
    response: RegistryType,
    code: u32,
) -> Result<(), u32> {
    let mut bytes = [0u8; WRRG_BYTES];
    let header = actor.registry_header(request).map_err(|_| code)?;
    let size = encode_empty(header, &mut bytes).map_err(|_| code + 1)?;
    send_channel(channel, &bytes[..size], &[]).map_err(|_| code + 2)?;
    wait_readable(channel, code + 3)?;
    let mut reply = [0u8; 72];
    let counts = receive_channel(channel, &mut reply, &mut []).map_err(|_| code + 4)?;
    let parsed = parse(&reply[..counts.bytes], counts.handles).map_err(|_| code + 5)?;
    let exact_message = matches!(
        (response, parsed.message),
        (RegistryType::Published, Message::Published) | (RegistryType::Retired, Message::Retired)
    );
    if parsed.header
        != (wyrmroot_registry_proto::Header {
            message_type: response,
            ..header
        })
        || !exact_message
    {
        return Err(if matches!(parsed.message, Message::Error { .. }) {
            code + 7
        } else {
            code + 6
        });
    }
    Ok(())
}

fn receive_record(channel: DwHandle, direction: Direction, code: u32) -> Result<Record, u32> {
    wait_readable(channel, code)?;
    let mut bytes = [0u8; RECORD_BYTES];
    let counts = receive_channel(channel, &mut bytes, &mut []).map_err(|_| code + 1)?;
    if counts.bytes != RECORD_BYTES || counts.handles != 0 {
        return Err(code + 2);
    }
    parse_for(&bytes, direction).map_err(|_| code + 3)
}

fn send_record(channel: DwHandle, record: Record, code: u32) -> Result<(), u32> {
    let mut bytes = [0u8; RECORD_BYTES];
    encode(record, &mut bytes).map_err(|_| code)?;
    send_channel(channel, &bytes, &[]).map_err(|_| code + 1)
}

fn wait_readable(channel: DwHandle, code: u32) -> Result<(), u32> {
    let observed = wait_one(channel, DW_SIGNAL_READABLE, DW_DEADLINE_INFINITE).map_err(|_| code)?;
    if observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(code + 1);
    }
    Ok(())
}

fn validate_fresh(
    received: DwReceivedHandleInfoV1,
    object_type: DwObjectType,
    rights: DwRights,
) -> Result<(), ()> {
    if received.object_type != object_type || received.rights != rights {
        return Err(());
    }
    let fresh = query_capability_info(received.handle).map_err(|_| ())?;
    if fresh.object_type != object_type || fresh.rights != rights {
        return Err(());
    }
    Ok(())
}

fn close_received(handles: &[DwReceivedHandleInfoV1; 2], initialized: usize) {
    for info in &handles[..initialized.min(handles.len())] {
        let _ = close_handle(info.handle);
    }
}

fn startup_registry_generation(startup: StartupBlock<'_>) -> Option<u64> {
    if startup.envc() != 3 {
        return None;
    }
    let entries = [
        startup.env(0)?.as_str(),
        startup.env(1)?.as_str(),
        startup.env(2)?.as_str(),
    ];
    Some(
        parse_correlation_environment(&entries)
            .ok()?
            .registry_generation,
    )
}

fn send_failure(
    parent: DwHandle,
    configured: Option<Record>,
    registry_generation: u64,
    code: u32,
) -> Result<(), ()> {
    let value = match u64::from(code & 0xFFFF) {
        0 => 1,
        value => value,
    };
    let record = configured.map_or(
        Record {
            message_type: MessageType::Failure,
            nonce: 1,
            registry_generation,
            actor_id: 0,
            actor_generation: 0,
            object_id: 0,
            object_generation: 0,
            operation_id: 1,
            value,
        },
        |config| Record {
            message_type: MessageType::Failure,
            object_id: 0,
            object_generation: 0,
            value,
            ..config
        },
    );
    let mut bytes = [0; RECORD_BYTES];
    encode(record, &mut bytes).map_err(|_| ())?;
    send_channel(parent, &bytes, &[]).map_err(|_| ())
}

wyrmroot_runtime::native_entry!(crate::publisher_main);

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    panic_abort()
}
