//! The service helpers against the in-memory Channel model; the test plays
//! init and the registry.

extern crate std;

use std::vec::Vec;

use deepwyrm_syscall::{
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DwDeadline, DwHandle, DwRights,
};
use wyrmroot_channel_model::{Object, World};
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, CHILD_CHANNEL_TRANSFER_RIGHTS, DEVICE_DRIVER_BYTES, SELF_ROOT_RIGHTS,
    encode_device_driver_init,
};
use wyrmroot_registry_proto::{
    Header as RegistryHeader, Message as RegistryMessage, MessageType as RegistryMessageType,
    encode_empty, encode_generation_changed, encode_lookup, parse as parse_registry,
};
use wyrmroot_runtime::ChannelPlatform;
use wyrmroot_service_proto::{
    self as wrsv, CHANNEL_READ_ONLY, Channel, Client, Publication, Stage,
};

use crate::*;

const ROLE: u64 = 0x101;
const ATTEMPT: u64 = 7;
const LATER: DwDeadline = DwDeadline(u64::MAX);
const SERVICE: ServiceName = ServiceName {
    name: b"volume.boot0",
    protocol_id: 0x4442_5257,
    major: 1,
    minor: 0,
};
const GRANT: Publication = Publication {
    registry_generation: 3,
    endpoint_id: 40,
    endpoint_generation: 1,
    transaction_id: 77,
    service_generation: 9,
};
const CLIENT: Client = Client {
    registry_generation: 3,
    endpoint_id: 41,
    endpoint_generation: 1,
};

/// Launches a role: returns (init's control end, init's bootstrap end, the
/// role's bootstrap end) with INIT already queued.
fn launch(world: &mut World) -> (DwHandle, DwHandle) {
    let (init_bootstrap, role_bootstrap) = world.create_channel(CHILD_CHANNEL_RIGHTS).unwrap();
    let self_root = world.install(
        Object::Other(DW_OBJECT_TYPE_ADDRESS_REGION),
        DwRights(SELF_ROOT_RIGHTS.0 | DW_RIGHT_TRANSFER.0),
    );
    let (control, role_control) = world.create_channel(CHILD_CHANNEL_TRANSFER_RIGHTS).unwrap();
    let mut init = [0u8; DEVICE_DRIVER_BYTES];
    encode_device_driver_init(1, 2, ROLE, ATTEMPT, 4, 5, 6, &mut init).unwrap();
    send_reduced(
        world,
        init_bootstrap,
        &init,
        &[
            (self_root, SELF_ROOT_RIGHTS),
            (role_control, CHILD_CHANNEL_RIGHTS),
        ],
    );
    (control, role_bootstrap)
}

fn send_reduced(
    world: &mut World,
    channel: DwHandle,
    bytes: &[u8],
    handles: &[(DwHandle, DwRights)],
) {
    let transfers: Vec<_> = handles
        .iter()
        .map(|&(handle, requested_rights)| DwHandleTransferV1 {
            handle,
            requested_rights,
            operation: DW_HANDLE_TRANSFER_MOVE,
            reserved0: 0,
            reserved: [0; 2],
        })
        .collect();
    world.send_channel(channel, bytes, &transfers).unwrap();
}

/// A fresh Channel pair whose far end init would stage; returns (near, far).
fn pair(world: &mut World) -> (DwHandle, DwHandle) {
    world.create_channel(CHILD_CHANNEL_TRANSFER_RIGHTS).unwrap()
}

fn stage_bytes(stage: &Stage<'_>) -> Vec<u8> {
    let mut out = [0u8; wrsv::MAX_BYTES];
    let size = wrsv::encode(stage, &mut out).unwrap();
    out[..size].to_vec()
}

#[test]
fn a_role_starts_and_receives_its_publication_client_and_channels_in_order() {
    let mut world = World::new();
    let (control, bootstrap) = launch(&mut world);
    let launch_info = startup(&mut world, bootstrap).unwrap();
    assert_eq!(
        (launch_info.role_id, launch_info.attempt_generation),
        (ROLE, ATTEMPT)
    );

    let (registry_publication, publication) = pair(&mut world);
    let (registry_client, client) = pair(&mut world);
    let (fs_far, fs_root) = pair(&mut world);
    let bytes = stage_bytes(&Stage {
        transaction_id: 5,
        role_id: ROLE,
        attempt_generation: ATTEMPT,
        publication: Some(GRANT),
        client: Some(CLIENT),
        channels: &[Channel {
            slot: 2,
            flags: CHANNEL_READ_ONLY,
            label: b"/boot",
        }],
    });
    send_reduced(
        &mut world,
        control,
        &bytes,
        &[
            (publication, CHILD_CHANNEL_RIGHTS),
            (client, CHILD_CHANNEL_RIGHTS),
            (fs_root, CHILD_CHANNEL_RIGHTS),
        ],
    );
    let staged = receive_stage(&mut world, &launch_info, LATER).unwrap();
    let (publication, grant) = staged.publication.unwrap();
    assert_eq!(grant, GRANT);
    let (client, identity) = staged.client.unwrap();
    assert_eq!(identity, CLIENT);
    let channel = staged.slot(2).unwrap();
    assert_eq!(
        (channel.flags, channel.label()),
        (CHANNEL_READ_ONLY, &b"/boot"[..])
    );
    assert!(staged.slot(3).is_none());
    // Each staged handle is the far end of the pair init made for it.
    for (near, far) in [
        (registry_publication, publication),
        (registry_client, client),
        (fs_far, channel.handle),
    ] {
        world.send(near, b"ping", &[]);
        assert_eq!(world.receive(far).0, b"ping");
    }
}

#[test]
fn a_stage_for_another_attempt_or_with_wrong_rights_is_refused_and_closed() {
    for (attempt, rights) in [
        (ATTEMPT + 1, CHILD_CHANNEL_RIGHTS),
        (ATTEMPT, CHILD_CHANNEL_TRANSFER_RIGHTS),
    ] {
        let mut world = World::new();
        let (control, bootstrap) = launch(&mut world);
        let launch_info = startup(&mut world, bootstrap).unwrap();
        let (near, far) = pair(&mut world);
        let bytes = stage_bytes(&Stage {
            transaction_id: 5,
            role_id: ROLE,
            attempt_generation: attempt,
            publication: None,
            client: None,
            channels: &[Channel {
                slot: 1,
                flags: 0,
                label: b"",
            }],
        });
        send_reduced(&mut world, control, &bytes, &[(far, rights)]);
        assert!(receive_stage(&mut world, &launch_info, LATER).is_err());
        assert!(world.peer_closed(near), "the staged handle was closed");
    }
    // No STAGE before the deadline.
    let mut world = World::new();
    let (_control, bootstrap) = launch(&mut world);
    let launch_info = startup(&mut world, bootstrap).unwrap();
    assert_eq!(receive_stage(&mut world, &launch_info, LATER), Err(10));
}

fn registry_reply(world: &mut World, endpoint: DwHandle, header: RegistryHeader) {
    let mut out = [0u8; 128];
    let size = match header.message_type {
        RegistryMessageType::GenerationChanged => {
            encode_generation_changed(header, 9, &mut out).unwrap()
        }
        _ => encode_empty(header, &mut out).unwrap(),
    };
    world.send(endpoint, &out[..size], &[]);
}

#[test]
fn publish_sends_publish_and_requires_the_matching_published() {
    let mut world = World::new();
    let (registry, endpoint) = pair(&mut world);
    // The registry answers before the publisher looks: the reply is queued.
    let header = RegistryHeader {
        message_type: RegistryMessageType::Published,
        registry_generation: GRANT.registry_generation,
        endpoint_id: GRANT.endpoint_id,
        endpoint_generation: GRANT.endpoint_generation,
        transaction_id: GRANT.transaction_id,
    };
    registry_reply(&mut world, registry, header);
    assert_eq!(publish(&mut world, endpoint, GRANT, LATER), Ok(()));
    let (bytes, _) = world.receive(registry);
    let request = parse_registry(&bytes, 0).unwrap();
    assert_eq!(request.message, RegistryMessage::Publish);
    assert_eq!(request.header.transaction_id, GRANT.transaction_id);

    registry_reply(
        &mut world,
        registry,
        RegistryHeader {
            transaction_id: 1,
            ..header
        },
    );
    assert_eq!(publish(&mut world, endpoint, GRANT, LATER), Err(26));
}

#[test]
fn offers_for_this_service_are_accepted_and_others_closed() {
    let mut world = World::new();
    let (registry, endpoint) = pair(&mut world);
    let offer = |world: &mut World, service: ServiceName, rights: DwRights| {
        let (client_end, offered) = world.create_channel(CHILD_CHANNEL_TRANSFER_RIGHTS).unwrap();
        let mut bytes = [0u8; 256];
        let size = encode_lookup(
            RegistryHeader {
                message_type: RegistryMessageType::ConnectOffer,
                registry_generation: GRANT.registry_generation,
                endpoint_id: GRANT.endpoint_id,
                endpoint_generation: GRANT.endpoint_generation,
                transaction_id: 3,
            },
            service.lookup(),
            &mut bytes,
        )
        .unwrap();
        send_reduced(world, registry, &bytes[..size], &[(offered, rights)]);
        client_end
    };
    let client_end = offer(&mut world, SERVICE, CHILD_CHANNEL_RIGHTS);
    let accepted = accept_offer(&mut world, endpoint, GRANT, SERVICE)
        .unwrap()
        .unwrap();
    world.send(client_end, b"hi", &[]);
    assert_eq!(world.receive(accepted).0, b"hi");

    let other = ServiceName {
        name: b"volume.other",
        ..SERVICE
    };
    for (service, rights) in [
        (other, CHILD_CHANNEL_RIGHTS),
        (SERVICE, CHILD_CHANNEL_TRANSFER_RIGHTS),
    ] {
        let client_end = offer(&mut world, service, rights);
        assert_eq!(accept_offer(&mut world, endpoint, GRANT, SERVICE), Ok(None));
        assert!(world.peer_closed(client_end));
    }
}

#[test]
fn connect_waits_for_publication_then_looks_up_with_a_fresh_channel() {
    let mut world = World::new();
    let (registry, endpoint) = pair(&mut world);
    let mut client = Registry::new(endpoint, CLIENT);
    let header = |message_type, transaction_id| RegistryHeader {
        message_type,
        registry_generation: CLIENT.registry_generation,
        endpoint_id: CLIENT.endpoint_id,
        endpoint_generation: CLIENT.endpoint_generation,
        transaction_id,
    };
    registry_reply(
        &mut world,
        registry,
        header(RegistryMessageType::GenerationChanged, 1),
    );
    registry_reply(
        &mut world,
        registry,
        header(RegistryMessageType::Connected, 2),
    );
    let direct = client.connect(&mut world, SERVICE, LATER).unwrap();

    let (bytes, handles) = world.receive(registry);
    match parse_registry(&bytes, handles.len()).unwrap().message {
        RegistryMessage::Watch(watch) => {
            assert_eq!(watch.service_name, SERVICE.name);
            assert_eq!(watch.last_observed_generation, 0);
        }
        other => panic!("expected WATCH, got {other:?}"),
    }
    let (bytes, handles) = world.receive(registry);
    let lookup = parse_registry(&bytes, handles.len()).unwrap();
    assert_eq!(
        lookup.message,
        RegistryMessage::LookupConnect(SERVICE.lookup())
    );
    assert_eq!(handles[0].rights, CONNECT_RIGHTS);
    assert_eq!(handles[0].object_type, DW_OBJECT_TYPE_CHANNEL);
    world.send(handles[0].handle, b"served", &[]);
    assert_eq!(world.receive(direct).0, b"served");

    // A registry that never answers the watch: the deadline ends it.
    let (_registry, endpoint) = pair(&mut world);
    let mut client = Registry::new(endpoint, CLIENT);
    assert_eq!(client.connect(&mut world, SERVICE, LATER), Err(42));
    // A refused lookup closes the client's end.
    let (registry, endpoint) = pair(&mut world);
    let mut client = Registry::new(endpoint, CLIENT);
    registry_reply(
        &mut world,
        registry,
        header(RegistryMessageType::GenerationChanged, 1),
    );
    let before = world.live_handles();
    assert_eq!(client.connect(&mut world, SERVICE, LATER), Err(53));
    // Its end of the new Channel is closed; the other end waits, unanswered,
    // in the registry's queue.
    assert_eq!(world.live_handles(), before);
    let _watch = world.receive(registry);
    let (_, lookup) = world.receive(registry);
    assert!(world.peer_closed(lookup[0].handle));
}
