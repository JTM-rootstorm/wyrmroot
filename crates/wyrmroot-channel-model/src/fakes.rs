//! Scripted stand-ins for the processes around a service role: init's
//! launch and stage, a registry, and a WRBD disk. Each runs as a model
//! [`Peer`](crate::Peer) and shares its state with the test through `Rc`.

use std::cell::RefCell;
use std::rc::Rc;

use deepwyrm_syscall::{
    DW_HANDLE_TRANSFER_MOVE, DW_OBJECT_TYPE_ADDRESS_REGION, DwHandle, DwHandleTransferV1, DwRights,
};
use wyrmroot_block_proto::{self as wrbd, Body, Info, Status};
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, CHILD_CHANNEL_TRANSFER_RIGHTS, DEVICE_DRIVER_BYTES, SELF_ROOT_RIGHTS,
    encode_device_driver_init,
};
use wyrmroot_registry_proto::{
    Header, Lookup, Message, MessageType, encode_empty, encode_error, encode_generation_changed,
    encode_lookup, parse,
};
use wyrmroot_runtime::ChannelPlatform;
use wyrmroot_service_proto::roles::ServiceName;
use wyrmroot_service_proto::{self as wrsv, Channel, Client, Publication, Stage};

use crate::{Memory, Object, World};

pub const REGISTRY_GENERATION: u64 = 3;

impl World {
    /// Sends with each handle moved at the rights given.
    pub fn send_with(&mut self, channel: DwHandle, bytes: &[u8], handles: &[(DwHandle, DwRights)]) {
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
        self.send_channel(channel, bytes, &transfers).unwrap();
    }

    /// A Channel pair whose ends may be moved on; returns (near, far).
    pub fn pair(&mut self) -> (DwHandle, DwHandle) {
        self.create_channel(CHILD_CHANNEL_TRANSFER_RIGHTS).unwrap()
    }
}

/// What init holds of a launched role.
pub struct Launched {
    /// Init's end of the control Channel.
    pub control: DwHandle,
    /// The role's bootstrap Channel, for its main function.
    pub bootstrap: DwHandle,
    pub role_id: u64,
    pub attempt_generation: u64,
}

/// Queues the loader's INIT for a role: a self root and the control Channel.
pub fn launch(world: &mut World, role_id: u64, attempt_generation: u64) -> Launched {
    let (init_bootstrap, bootstrap) = world.create_channel(CHILD_CHANNEL_RIGHTS).unwrap();
    let self_root = world.install(
        Object::Other(DW_OBJECT_TYPE_ADDRESS_REGION),
        DwRights(SELF_ROOT_RIGHTS.0 | deepwyrm_syscall::DW_RIGHT_TRANSFER.0),
    );
    let (control, role_control) = world.pair();
    let mut init = [0u8; DEVICE_DRIVER_BYTES];
    encode_device_driver_init(1, 2, role_id, attempt_generation, 4, 5, 6, &mut init).unwrap();
    world.send_with(
        init_bootstrap,
        &init,
        &[
            (self_root, SELF_ROOT_RIGHTS),
            (role_control, CHILD_CHANNEL_RIGHTS),
        ],
    );
    Launched {
        control,
        bootstrap,
        role_id,
        attempt_generation,
    }
}

/// Queues the role's STAGE: an optional publication, an optional client
/// and role Channels as (slot, flags, label, handle to move).
pub fn stage(
    world: &mut World,
    launched: &Launched,
    publication: Option<(DwHandle, Publication)>,
    client: Option<(DwHandle, Client)>,
    channels: &[(u32, u32, &[u8], DwHandle)],
) {
    let described: Vec<Channel<'_>> = channels
        .iter()
        .map(|&(slot, flags, label, _)| Channel { slot, flags, label })
        .collect();
    let mut bytes = [0u8; wrsv::MAX_BYTES];
    let size = wrsv::encode(
        &Stage {
            transaction_id: 1,
            role_id: launched.role_id,
            attempt_generation: launched.attempt_generation,
            publication: publication.map(|(_, grant)| grant),
            client: client.map(|(_, identity)| identity),
            channels: &described,
        },
        &mut bytes,
    )
    .unwrap();
    let handles: Vec<_> = publication
        .map(|(handle, _)| handle)
        .into_iter()
        .chain(client.map(|(handle, _)| handle))
        .chain(channels.iter().map(|&(_, _, _, handle)| handle))
        .map(|handle| (handle, CHILD_CHANNEL_RIGHTS))
        .collect();
    world.send_with(launched.control, &bytes[..size], &handles);
}

struct Publisher {
    endpoint: DwHandle,
    grant: Publication,
    service: ServiceName,
    published: bool,
}

struct Watcher {
    endpoint: DwHandle,
    header: Header,
    name: Vec<u8>,
}

#[derive(Default)]
pub struct RegistryState {
    clients: Vec<DwHandle>,
    publishers: Vec<Publisher>,
    watches: Vec<Watcher>,
    next_endpoint: u64,
    next_offer: u64,
    /// Lookups the registry refused because nothing was published.
    pub refused_lookups: usize,
}

impl RegistryState {
    pub fn published(&self, name: &[u8]) -> bool {
        self.publishers
            .iter()
            .any(|publisher| publisher.published && publisher.service.name == name)
    }
}

/// A registry that installs endpoints on request and routes lookups to
/// publishers as connection offers.
#[derive(Clone)]
pub struct FakeRegistry {
    pub state: Rc<RefCell<RegistryState>>,
}

impl FakeRegistry {
    pub fn install(world: &mut World) -> Self {
        let state = Rc::new(RefCell::new(RegistryState {
            next_endpoint: 40,
            next_offer: 1000,
            ..RegistryState::default()
        }));
        let peer_state = state.clone();
        world.add_peer(move |world| serve_registry(world, &mut peer_state.borrow_mut()));
        Self { state }
    }

    /// A client endpoint: the role's end and its identity.
    pub fn client(&self, world: &mut World) -> (DwHandle, Client) {
        let (ours, theirs) = world.pair();
        let mut state = self.state.borrow_mut();
        state.next_endpoint += 1;
        state.clients.push(ours);
        (
            theirs,
            Client {
                registry_generation: REGISTRY_GENERATION,
                endpoint_id: state.next_endpoint,
                endpoint_generation: 1,
            },
        )
    }

    /// A publication endpoint for `service`: the role's end and its grant.
    pub fn publication(&self, world: &mut World, service: ServiceName) -> (DwHandle, Publication) {
        let (ours, theirs) = world.pair();
        let mut state = self.state.borrow_mut();
        state.next_endpoint += 1;
        let grant = Publication {
            registry_generation: REGISTRY_GENERATION,
            endpoint_id: state.next_endpoint,
            endpoint_generation: 1,
            transaction_id: 900 + state.next_endpoint,
            service_generation: 7,
        };
        state.publishers.push(Publisher {
            endpoint: ours,
            grant,
            service,
            published: false,
        });
        (theirs, grant)
    }
}

fn reply(world: &mut World, endpoint: DwHandle, header: Header, message_type: MessageType) {
    let mut out = [0u8; 128];
    let header = Header {
        message_type,
        ..header
    };
    let size = match message_type {
        MessageType::GenerationChanged => encode_generation_changed(header, 7, &mut out).unwrap(),
        _ => encode_empty(header, &mut out).unwrap(),
    };
    let _ = world.send_channel(endpoint, &out[..size], &[]);
}

fn serve_registry(world: &mut World, state: &mut RegistryState) -> bool {
    let mut progressed = false;
    for index in 0..state.publishers.len() {
        let endpoint = state.publishers[index].endpoint;
        while world.readable(endpoint) {
            progressed = true;
            let (bytes, handles) = world.receive(endpoint);
            if let Ok(message) = parse(&bytes, handles.len())
                && message.header.message_type == MessageType::Publish
            {
                state.publishers[index].published = true;
                reply(world, endpoint, message.header, MessageType::Published);
            }
        }
    }
    // Watches answer once their service is published.
    let mut index = 0;
    while index < state.watches.len() {
        if state.published(&state.watches[index].name) {
            let watch = state.watches.remove(index);
            reply(
                world,
                watch.endpoint,
                watch.header,
                MessageType::GenerationChanged,
            );
            progressed = true;
        } else {
            index += 1;
        }
    }
    for index in 0..state.clients.len() {
        let endpoint = state.clients[index];
        while world.readable(endpoint) {
            progressed = true;
            let (bytes, handles) = world.receive(endpoint);
            let Ok(message) = parse(&bytes, handles.len()) else {
                continue;
            };
            match message.message {
                Message::Watch(watch) => {
                    let watcher = Watcher {
                        endpoint,
                        header: message.header,
                        name: watch.service_name.to_vec(),
                    };
                    if state.published(watch.service_name) {
                        reply(
                            world,
                            endpoint,
                            watcher.header,
                            MessageType::GenerationChanged,
                        );
                    } else {
                        state.watches.push(watcher);
                    }
                }
                Message::LookupConnect(lookup) => {
                    route_lookup(
                        world,
                        state,
                        endpoint,
                        message.header,
                        lookup,
                        handles[0].handle,
                    );
                }
                _ => {}
            }
        }
    }
    progressed
}

fn route_lookup(
    world: &mut World,
    state: &mut RegistryState,
    client: DwHandle,
    header: Header,
    lookup: Lookup<'_>,
    channel: DwHandle,
) {
    let publisher = state.publishers.iter().find(|publisher| {
        publisher.published
            && publisher.service.name == lookup.service_name
            && publisher.service.protocol_id == lookup.protocol_id
    });
    let Some(publisher) = publisher else {
        state.refused_lookups += 1;
        let _ = world.close_handle_quiet(channel);
        let mut out = [0u8; 128];
        let size = encode_error(
            Header {
                message_type: MessageType::Error,
                ..header
            },
            wyrmroot_registry_proto::ErrorCode::NotPublished,
            &mut out,
        )
        .unwrap();
        world.send(client, &out[..size], &[]);
        return;
    };
    let mut out = [0u8; 256];
    state.next_offer += 1;
    let size = encode_lookup(
        Header {
            message_type: MessageType::ConnectOffer,
            registry_generation: publisher.grant.registry_generation,
            endpoint_id: publisher.grant.endpoint_id,
            endpoint_generation: publisher.grant.endpoint_generation,
            transaction_id: state.next_offer,
        },
        lookup,
        &mut out,
    )
    .unwrap();
    let endpoint = publisher.endpoint;
    world.send_with(endpoint, &out[..size], &[(channel, CHILD_CHANNEL_RIGHTS)]);
    reply(world, client, header, MessageType::Connected);
}

impl World {
    fn close_handle_quiet(&mut self, handle: DwHandle) -> bool {
        wyrmroot_runtime::HandlePlatform::close_handle(self, handle).is_ok()
    }
}

/// A WRBD disk of `block_size`-byte blocks over shared bytes.
pub struct DiskState {
    pub image: Vec<u8>,
    pub block_size: u32,
    pub max_transfer_blocks: u32,
    connections: Vec<(DwHandle, Option<Memory>)>,
    publication: DwHandle,
    grant: Publication,
    service: ServiceName,
    published: bool,
    /// Every READ the disk served: (lba, blocks).
    pub reads: Vec<(u64, u32)>,
    /// Rights each ATTACH's MemoryObject arrived with.
    pub attach_rights: Vec<DwRights>,
}

/// Publishes a disk as `service` through `registry` and serves it.
pub fn serve_disk(
    world: &mut World,
    registry: &FakeRegistry,
    service: ServiceName,
    image: Vec<u8>,
    block_size: u32,
) -> Rc<RefCell<DiskState>> {
    let (publication, grant) = registry.publication(world, service);
    let state = Rc::new(RefCell::new(DiskState {
        image,
        block_size,
        max_transfer_blocks: 256,
        connections: Vec::new(),
        publication,
        grant,
        service,
        published: false,
        reads: Vec::new(),
        attach_rights: Vec::new(),
    }));
    let peer_state = state.clone();
    world.add_peer(move |world| serve_disk_step(world, &mut peer_state.borrow_mut()));
    state
}

fn serve_disk_step(world: &mut World, disk: &mut DiskState) -> bool {
    let mut progressed = false;
    if !disk.published {
        disk.published = true;
        let mut out = [0u8; 64];
        let size = encode_empty(
            Header {
                message_type: MessageType::Publish,
                registry_generation: disk.grant.registry_generation,
                endpoint_id: disk.grant.endpoint_id,
                endpoint_generation: disk.grant.endpoint_generation,
                transaction_id: disk.grant.transaction_id,
            },
            &mut out,
        )
        .unwrap();
        world.send(disk.publication, &out[..size], &[]);
        progressed = true;
    }
    while world.readable(disk.publication) {
        progressed = true;
        let (bytes, handles) = world.receive(disk.publication);
        if let Ok(message) = parse(&bytes, handles.len())
            && let Message::ConnectOffer(lookup) = message.message
            && lookup.service_name == disk.service.name
        {
            disk.connections.push((handles[0].handle, None));
        }
    }
    let mut index = 0;
    while index < disk.connections.len() {
        let channel = disk.connections[index].0;
        if world.readable(channel) {
            progressed = true;
            let (bytes, handles) = world.receive(channel);
            let Ok(request) = wrbd::parse(&bytes, handles.len()) else {
                disk.connections.remove(index);
                let _ = world.close_handle_quiet(channel);
                continue;
            };
            let reply = disk_request(world, disk, index, request.body, &handles);
            let mut out = [0u8; wrbd::MAX_BYTES];
            let size = wrbd::encode(
                wrbd::Message {
                    transaction_id: request.transaction_id,
                    body: reply,
                },
                &mut out,
            )
            .unwrap();
            let _ = world.send_channel(channel, &out[..size], &[]);
        } else if world.peer_closed(channel) {
            progressed = true;
            disk.connections.remove(index);
            let _ = world.close_handle_quiet(channel);
            continue;
        }
        index += 1;
    }
    progressed
}

fn disk_request(
    world: &mut World,
    disk: &mut DiskState,
    index: usize,
    body: Body,
    handles: &[deepwyrm_syscall::DwReceivedHandleInfoV1],
) -> Body {
    let blocks = disk.image.len() as u64 / u64::from(disk.block_size);
    match body {
        Body::GetInfo => Body::Info(Info {
            block_size: disk.block_size,
            flags: 0,
            block_count: blocks,
            max_transfer_blocks: disk.max_transfer_blocks,
        }),
        Body::Attach { .. } => {
            disk.attach_rights.push(handles[0].rights);
            disk.connections[index].1 = world.memory(handles[0].handle);
            Body::Complete(Status::Ok)
        }
        Body::Read(transfer) | Body::Write(transfer) => {
            let Some(memory) = disk.connections[index].1.clone() else {
                return Body::Complete(Status::NoBuffer);
            };
            let size = u64::from(disk.block_size);
            let bytes = u64::from(transfer.block_count) * size;
            if transfer.lba + u64::from(transfer.block_count) > blocks
                || transfer.buffer_offset + bytes > memory.borrow().len() as u64
            {
                return Body::Complete(Status::OutOfRange);
            }
            let disk_at = (transfer.lba * size) as usize;
            let buffer_at = transfer.buffer_offset as usize;
            let bytes = bytes as usize;
            if matches!(body, Body::Read(_)) {
                disk.reads.push((transfer.lba, transfer.block_count));
                memory.borrow_mut()[buffer_at..buffer_at + bytes]
                    .copy_from_slice(&disk.image[disk_at..disk_at + bytes]);
            } else {
                disk.image[disk_at..disk_at + bytes]
                    .copy_from_slice(&memory.borrow()[buffer_at..buffer_at + bytes]);
            }
            Body::Complete(Status::Ok)
        }
        Body::Flush => Body::Complete(Status::Ok),
        Body::Info(_) | Body::Complete(_) => Body::Complete(Status::Invalid),
    }
}
