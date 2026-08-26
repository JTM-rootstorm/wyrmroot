#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_HANDLE_TRANSFER_MOVE, DW_OBJECT_TYPE_ADDRESS_REGION,
    DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_INSPECT, DW_RIGHT_READ, DW_RIGHT_TRANSFER, DW_RIGHT_WAIT,
    DW_RIGHT_WRITE, DW_SIGNAL_READABLE, DwHandle, DwHandleTransferV1, DwObjectType,
    DwReceivedHandleInfoV1, DwRights,
};
use wyrmroot_launch_proto::{
    ErrorCode as LaunchErrorCode, Message as LaunchMessage, MessageType as LaunchType,
    Reservation as LaunchReservation, encode_job_message, encode_launch, parse_message,
};
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, HEADER_BYTES as WRLP_BYTES, LaunchProfile, SELF_ROOT_RIGHTS,
    encode_ready_for_profile, parse_init,
};
use wyrmroot_registry_proto::{
    Lookup, Message, MessageType as RegistryType, ProtocolVersion, encode_lookup, parse,
    parse_correlation_environment,
};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, StartupBlock, close_handle, create_channel, panic_abort,
    query_capability_info, receive_channel, send_channel, validate_bootstrap_channel, wait_one,
};
use wyrmroot_wyr1b_gate::{Client, ClientAction, FailureTracker};
use wyrmroot_wyr1b_gate_proto::{
    Direction, ECHO_PROTOCOL_ID, ECHO_SERVICE_NAME, ECHO_VERSION_MAJOR, ECHO_VERSION_MINOR,
    MessageType, RECORD_BYTES, Record, encode, parse_for,
};

const BROAD_CHANNEL_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_TRANSFER.0,
);
const CLIENT_ERROR_BASE: u32 = 0xB103_0000;

fn client_main(startup: StartupBlock<'_>) -> u32 {
    let mut failure = FailureTracker::new(startup_registry_generation(startup));
    match run(startup, &mut failure) {
        Ok(code) => code,
        Err(code) => {
            if let Some(record) = failure.take(code) {
                let _ = send_failure(startup.bootstrap_channel().as_abi(), record);
            }
            code
        }
    }
}

fn run(startup: StartupBlock<'_>, failure: &mut FailureTracker) -> Result<u32, u32> {
    let parent = startup.bootstrap_channel().as_abi();
    validate_bootstrap_channel(
        query_capability_info(parent).map_err(|_| CLIENT_ERROR_BASE + 0x0001)?,
        BOOTSTRAP_CHANNEL_EXPECTATION,
    )
    .map_err(|_| CLIENT_ERROR_BASE + 0x0002)?;
    wait_readable(parent, CLIENT_ERROR_BASE + 0x0003)?;
    let mut init = [0u8; 64];
    let mut handles = [DwReceivedHandleInfoV1::default(); 2];
    let counts =
        receive_channel(parent, &mut init, &mut handles).map_err(|_| CLIENT_ERROR_BASE + 0x0004)?;
    if counts.bytes > init.len() || counts.handles != 2 {
        close_received(&handles, counts.handles);
        return Err(CLIENT_ERROR_BASE + 0x0005);
    }
    let bytes = &init[..counts.bytes];
    let profile = if parse_init(LaunchProfile::RegistryClient, bytes, &handles).is_ok() {
        LaunchProfile::RegistryClient
    } else if parse_init(LaunchProfile::LaunchClient, bytes, &handles).is_ok() {
        LaunchProfile::LaunchClient
    } else {
        close_received(&handles, 2);
        return Err(CLIENT_ERROR_BASE + 0x0006);
    };
    let parsed = match parse_init(profile, bytes, &handles) {
        Ok(parsed) => parsed,
        Err(_) => {
            close_received(&handles, 2);
            return Err(CLIENT_ERROR_BASE + 0x0007);
        }
    };
    if validate_fresh(handles[0], DW_OBJECT_TYPE_ADDRESS_REGION, SELF_ROOT_RIGHTS).is_err()
        || validate_fresh(handles[1], DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS).is_err()
    {
        close_received(&handles, 2);
        return Err(CLIENT_ERROR_BASE + 0x0018);
    }

    let mut actor = if profile == LaunchProfile::RegistryClient {
        if startup.envc() != 3 {
            close_received(&handles, 2);
            return Err(CLIENT_ERROR_BASE + 0x0008);
        }
        let environment = [
            startup.env(0).ok_or(CLIENT_ERROR_BASE + 0x0009)?.as_str(),
            startup.env(1).ok_or(CLIENT_ERROR_BASE + 0x0009)?.as_str(),
            startup.env(2).ok_or(CLIENT_ERROR_BASE + 0x0009)?.as_str(),
        ];
        match Client::registry_from_environment(&environment) {
            Ok(actor) => actor,
            Err(_) => {
                close_received(&handles, 2);
                return Err(CLIENT_ERROR_BASE + 0x000A);
            }
        }
    } else {
        if startup.envc() != 0 {
            close_received(&handles, 2);
            return Err(CLIENT_ERROR_BASE + 0x000B);
        }
        Client::launch()
    };

    let mut ready = [0u8; WRLP_BYTES];
    let size = match encode_ready_for_profile(profile, parsed.transaction_id, &mut ready) {
        Ok(size) => size,
        Err(_) => {
            close_received(&handles, 2);
            return Err(CLIENT_ERROR_BASE + 0x000C);
        }
    };
    if send_channel(parent, &ready[..size], &[]).is_err() {
        close_received(&handles, 2);
        return Err(CLIENT_ERROR_BASE + 0x000D);
    }
    failure
        .mark_ready()
        .map_err(|_| CLIENT_ERROR_BASE + 0x001B)?;
    if close_handle(handles[0].handle).is_err() {
        let _ = close_handle(handles[1].handle);
        return Err(CLIENT_ERROR_BASE + 0x000E);
    }
    let authority = handles[1].handle;

    if profile == LaunchProfile::RegistryClient {
        if let Err(code) = registry_cycles(parent, authority, &mut actor, failure) {
            let _ = close_handle(authority);
            return Err(code);
        }
    } else {
        let configure = receive_record(parent, Direction::InitToChild, CLIENT_ERROR_BASE + 0x0010)?;
        let action = actor
            .configure(configure)
            .map_err(|_| CLIENT_ERROR_BASE + 0x0011)?;
        failure
            .update(configure)
            .map_err(|_| CLIENT_ERROR_BASE + 0x001C)?;
        match action {
            ClientAction::Launch => {
                launch_job_cycle(parent, authority, &mut actor, configure, failure)?
            }
            ClientAction::Configured => {
                foreign_job_cycle(parent, authority, &mut actor, configure)?
            }
            _ => return Err(CLIENT_ERROR_BASE + 0x0012),
        }
    }
    close_handle(authority).map_err(|_| CLIENT_ERROR_BASE + 0x0016)?;
    close_handle(parent).map_err(|_| CLIENT_ERROR_BASE + 0x0017)?;
    Ok(0)
}

fn launch_reservation(configure: Record, transaction_id: u64) -> Result<LaunchReservation, u32> {
    if configure.actor_id == 0 || configure.actor_generation == 0 || transaction_id == 0 {
        return Err(CLIENT_ERROR_BASE + 0x0040);
    }
    Ok(LaunchReservation {
        connection_id: configure.actor_id,
        generation: configure.actor_generation,
        transaction_id,
    })
}

fn launch_job_cycle(
    parent: DwHandle,
    session: DwHandle,
    actor: &mut Client,
    configure: Record,
    _failure: &mut FailureTracker,
) -> Result<(), u32> {
    let reservation = launch_reservation(configure, 1)?;
    let mut bytes = [0u8; 416];
    let launch_len = encode_launch(
        reservation,
        "bin/hello",
        &["bin/hello"],
        &[],
        false,
        &mut bytes,
    )
    .map_err(|_| CLIENT_ERROR_BASE + 0x0041)?;
    send_channel(session, &bytes[..launch_len], &[]).map_err(|_| CLIENT_ERROR_BASE + 0x0042)?;
    let accepted = receive_launch(session, reservation, CLIENT_ERROR_BASE + 0x0043)?;
    let LaunchMessage::LaunchAccepted { job_id } = accepted else {
        return Err(CLIENT_ERROR_BASE + 0x0044);
    };
    match actor
        .job_accepted(job_id)
        .map_err(|_| CLIENT_ERROR_BASE + 0x0045)?
    {
        ClientAction::Report(record) => send_record(parent, record, CLIENT_ERROR_BASE + 0x0046)?,
        ClientAction::Disconnect(record) => {
            send_record(parent, record, CLIENT_ERROR_BASE + 0x0047)?;
            return Ok(());
        }
        _ => return Err(CLIENT_ERROR_BASE + 0x0048),
    }
    let wait_reservation = launch_reservation(configure, 2)?;
    let wait_len = encode_job_message(wait_reservation, LaunchType::Wait, job_id, &mut bytes)
        .map_err(|_| CLIENT_ERROR_BASE + 0x0049)?;
    send_channel(session, &bytes[..wait_len], &[]).map_err(|_| CLIENT_ERROR_BASE + 0x004A)?;
    let result = receive_launch(session, wait_reservation, CLIENT_ERROR_BASE + 0x004B)?;
    let LaunchMessage::JobResult {
        job_id: result_job,
        result,
    } = result
    else {
        return Err(CLIENT_ERROR_BASE + 0x004C);
    };
    if result_job != job_id {
        return Err(CLIENT_ERROR_BASE + 0x004D);
    }
    let report = actor
        .job_result(
            result.classification == 1
                && result.application_code == 0
                && result.exception_class == 0
                && result.exception_detail == 0
                && result.exception_address == 0
                && result.cleanup_result == 0,
        )
        .map_err(|_| CLIENT_ERROR_BASE + 0x004E)?;
    send_record(parent, report, CLIENT_ERROR_BASE + 0x004F)
}

fn foreign_job_cycle(
    parent: DwHandle,
    session: DwHandle,
    actor: &mut Client,
    configure: Record,
) -> Result<(), u32> {
    let probe = receive_record(parent, Direction::InitToChild, CLIENT_ERROR_BASE + 0x0050)?;
    if actor
        .probe_foreign(probe)
        .map_err(|_| CLIENT_ERROR_BASE + 0x0051)?
        != ClientAction::ProbeForeign
    {
        return Err(CLIENT_ERROR_BASE + 0x0052);
    }
    let reservation = launch_reservation(configure, 1)?;
    let mut bytes = [0u8; 416];
    let size = encode_job_message(reservation, LaunchType::Query, probe.object_id, &mut bytes)
        .map_err(|_| CLIENT_ERROR_BASE + 0x0053)?;
    send_channel(session, &bytes[..size], &[]).map_err(|_| CLIENT_ERROR_BASE + 0x0054)?;
    let response = receive_launch(session, reservation, CLIENT_ERROR_BASE + 0x0055)?;
    if response
        != (LaunchMessage::Error {
            code: LaunchErrorCode::ForeignOrUnknownJob as u32,
        })
    {
        return Err(CLIENT_ERROR_BASE + 0x0056);
    }
    let report = actor
        .foreign_error(probe.object_id, true)
        .map_err(|_| CLIENT_ERROR_BASE + 0x0057)?;
    send_record(parent, report, CLIENT_ERROR_BASE + 0x0058)
}

fn receive_launch(
    channel: DwHandle,
    reservation: LaunchReservation,
    code: u32,
) -> Result<LaunchMessage<'static>, u32> {
    wait_readable(channel, code)?;
    let mut bytes = [0u8; 416];
    let mut handles = [DwReceivedHandleInfoV1::default(); 16];
    let counts = receive_channel(channel, &mut bytes, &mut handles).map_err(|_| code + 1)?;
    if counts.bytes > bytes.len() || counts.handles > handles.len() {
        close_launch_handles(&handles, counts.handles);
        return Err(code + 2);
    }
    let parsed = match parse_message(&bytes[..counts.bytes], counts.handles) {
        Ok(parsed) => parsed,
        Err(_) => {
            close_launch_handles(&handles, counts.handles);
            return Err(code + 3);
        }
    };
    if parsed.reservation != reservation {
        close_launch_handles(&handles, counts.handles);
        return Err(code + 4);
    }
    if counts.handles != 0 {
        close_launch_handles(&handles, counts.handles);
        return Err(code + 5);
    }
    // All response variants borrow only the input packet. Copying into a
    // fixed owned representation keeps the native client allocation-free.
    match parsed.message {
        LaunchMessage::LaunchAccepted { job_id } => Ok(LaunchMessage::LaunchAccepted { job_id }),
        LaunchMessage::JobResult { job_id, result } => {
            Ok(LaunchMessage::JobResult { job_id, result })
        }
        LaunchMessage::Error { code } => Ok(LaunchMessage::Error { code }),
        _ => Err(code + 6),
    }
}

fn close_launch_handles(handles: &[DwReceivedHandleInfoV1], count: usize) {
    for handle in &handles[..count.min(handles.len())] {
        let _ = close_handle(handle.handle);
    }
}

fn registry_cycles(
    parent: DwHandle,
    registry: DwHandle,
    actor: &mut Client,
    failure: &mut FailureTracker,
) -> Result<(), u32> {
    for operation in 1..=2 {
        let configure = receive_record(parent, Direction::InitToChild, CLIENT_ERROR_BASE + 0x0020)?;
        if configure.operation_id != operation
            || actor
                .configure(configure)
                .map_err(|_| CLIENT_ERROR_BASE + 0x0021)?
                != ClientAction::Lookup
        {
            return Err(CLIENT_ERROR_BASE + 0x0022);
        }
        failure
            .update(configure)
            .map_err(|_| CLIENT_ERROR_BASE + 0x0038)?;
        let (direct, service) = match create_channel(BROAD_CHANNEL_RIGHTS) {
            Ok(pair) => pair,
            Err(_) => {
                let code = CLIENT_ERROR_BASE + 0x0023;
                return Err(code);
            }
        };
        let header = match actor.registry_header(RegistryType::LookupConnect) {
            Ok(header) => header,
            Err(_) => {
                let _ = close_handle(service);
                let _ = close_handle(direct);
                let code = CLIENT_ERROR_BASE + 0x0024;
                return Err(code);
            }
        };
        let lookup = Lookup {
            protocol_id: ECHO_PROTOCOL_ID,
            version: ProtocolVersion {
                major: ECHO_VERSION_MAJOR,
                minor: ECHO_VERSION_MINOR,
            },
            service_name: ECHO_SERVICE_NAME,
        };
        let mut bytes = [0u8; 256];
        let size = match encode_lookup(header, lookup, &mut bytes) {
            Ok(size) => size,
            Err(_) => {
                let _ = close_handle(service);
                let _ = close_handle(direct);
                let code = CLIENT_ERROR_BASE + 0x0025;
                return Err(code);
            }
        };
        let transfer = DwHandleTransferV1 {
            handle: service,
            requested_rights: BROAD_CHANNEL_RIGHTS,
            operation: DW_HANDLE_TRANSFER_MOVE,
            reserved0: 0,
            reserved: [0; 2],
        };
        if send_channel(registry, &bytes[..size], &[transfer]).is_err() {
            let first = close_handle(service);
            let second = close_handle(direct);
            let code = if first.is_err() || second.is_err() {
                CLIENT_ERROR_BASE + 0x0035
            } else {
                CLIENT_ERROR_BASE + 0x0026
            };
            return Err(code);
        }

        let cycle = (|| {
            wait_readable(registry, CLIENT_ERROR_BASE + 0x0027)?;
            let mut connected_bytes = [0u8; 72];
            let counts = receive_channel(registry, &mut connected_bytes, &mut [])
                .map_err(|_| CLIENT_ERROR_BASE + 0x0028)?;
            let connected = parse(&connected_bytes[..counts.bytes], counts.handles)
                .map_err(|_| CLIENT_ERROR_BASE + 0x0029)?;
            if matches!(connected.message, Message::Error { .. }) {
                return Err(CLIENT_ERROR_BASE + 0x0036);
            }
            if connected.header
                != (wyrmroot_registry_proto::Header {
                    message_type: RegistryType::Connected,
                    ..header
                })
                || connected.message != Message::Connected
            {
                return Err(CLIENT_ERROR_BASE + 0x002A);
            }
            let (report, challenge) = actor.connected().map_err(|_| CLIENT_ERROR_BASE + 0x002B)?;
            send_record(parent, report, CLIENT_ERROR_BASE + 0x002C)?;
            send_record(direct, challenge, CLIENT_ERROR_BASE + 0x002D)?;
            let echo = receive_record(
                direct,
                Direction::PublisherToDirect,
                CLIENT_ERROR_BASE + 0x002E,
            )?;
            let exchanged = actor
                .direct_echo(echo)
                .map_err(|_| CLIENT_ERROR_BASE + 0x002F)?;
            send_record(parent, exchanged, CLIENT_ERROR_BASE + 0x0030)
        })();
        let close = close_handle(direct);
        if let Err(code) = cycle {
            return Err(code);
        }
        close.map_err(|_| CLIENT_ERROR_BASE + 0x0031)?;
        if operation == 2 {
            let done =
                match receive_record(parent, Direction::InitToChild, CLIENT_ERROR_BASE + 0x0032) {
                    Ok(done) => done,
                    Err(code) => return Err(code),
                };
            if done.message_type != MessageType::Done
                || actor.done(done).map_err(|_| CLIENT_ERROR_BASE + 0x0033)
                    != Ok(ClientAction::Done)
            {
                return Err(CLIENT_ERROR_BASE + 0x0034);
            }
            return Ok(());
        }
    }
    Err(CLIENT_ERROR_BASE + 0x0037)
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

fn send_failure(parent: DwHandle, record: Record) -> Result<(), ()> {
    let mut bytes = [0; RECORD_BYTES];
    encode(record, &mut bytes).map_err(|_| ())?;
    send_channel(parent, &bytes, &[]).map_err(|_| ())
}

wyrmroot_runtime::native_entry!(crate::client_main);

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    panic_abort()
}
