//! blockmgr run to completion against the Channel model, with a fake
//! registry, a fake disk driver, and a client and init played as peers.

use std::cell::RefCell;
use std::rc::Rc;
use std::vec;
use std::vec::Vec;

use deepwyrm_syscall::DwHandle;
use wyrmroot_block_proto::{self as wrbd, Body, Message, Status, Transfer};
use wyrmroot_channel_model::fakes::{DiskState, FakeRegistry, Launched, launch, serve_disk, stage};
use wyrmroot_channel_model::{Memory, World};
use wyrmroot_registry_proto::{
    Header as RegistryHeader, Lookup, MessageType as RegistryMessageType, ProtocolVersion,
    encode_lookup,
};
use wyrmroot_runtime::{HandlePlatform, NativeError};
use wyrmroot_service::memory::{LEND_RIGHTS, Mapper, View};
use wyrmroot_service_proto::roles::{BLOCKMGR_ROLE_ID, BOOT_VOLUME};

use crate::*;

/// Maps a model MemoryObject by sharing its bytes.
struct ModelMapper;

struct ModelView(Memory);

impl View for ModelView {
    fn len(&self) -> u64 {
        self.0.borrow().len() as u64
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> bool {
        let memory = self.0.borrow();
        let Some(source) = memory.get(offset as usize..offset as usize + out.len()) else {
            return false;
        };
        out.copy_from_slice(source);
        true
    }
    fn write(&mut self, offset: u64, data: &[u8]) -> bool {
        let mut memory = self.0.borrow_mut();
        let Some(target) = memory.get_mut(offset as usize..offset as usize + data.len()) else {
            return false;
        };
        target.copy_from_slice(data);
        true
    }
}

impl Mapper<World> for ModelMapper {
    type View = ModelView;
    fn map(
        &mut self,
        platform: &mut World,
        _: DwHandle,
        memory: DwHandle,
        _: u64,
    ) -> Result<ModelView, NativeError> {
        platform
            .memory(memory)
            .map(ModelView)
            .ok_or(NativeError::Status(
                deepwyrm_syscall::DW_STATUS_INVALID_ARGUMENT,
            ))
    }
    fn unmap(&mut self, _: &mut World, _: ModelView) -> bool {
        true
    }
}

const BLOCK: usize = 512;

/// A disk of `blocks` blocks where each block starts with its own LBA.
fn numbered(blocks: usize) -> Vec<u8> {
    let mut image = vec![0u8; blocks * BLOCK];
    for (lba, block) in image.chunks_mut(BLOCK).enumerate() {
        block[..8].copy_from_slice(&(lba as u64).to_le_bytes());
    }
    image
}

fn superfloppy(blocks: usize) -> Vec<u8> {
    let mut image = numbered(blocks);
    let boot = &mut image[..BLOCK];
    boot[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
    boot[11..13].copy_from_slice(&512u16.to_le_bytes());
    boot[13] = 1;
    boot[14..16].copy_from_slice(&32u16.to_le_bytes());
    boot[16] = 2;
    boot[21] = 0xf8;
    boot[510] = 0x55;
    boot[511] = 0xaa;
    image
}

fn mbr(blocks: usize, os_type: u8, first: u32, count: u32) -> Vec<u8> {
    let mut image = numbered(blocks);
    let entry = &mut image[446..462];
    entry.fill(0);
    entry[4] = os_type;
    entry[8..12].copy_from_slice(&first.to_le_bytes());
    entry[12..16].copy_from_slice(&count.to_le_bytes());
    image[510] = 0x55;
    image[511] = 0xaa;
    image
}

struct System {
    world: World,
    registry: FakeRegistry,
    disk: Rc<RefCell<DiskState>>,
    launched: Launched,
}

fn system(image: Vec<u8>) -> System {
    let mut world = World::new();
    let registry = FakeRegistry::install(&mut world);
    let disk = serve_disk(&mut world, &registry, BOOT_DISK, image, BLOCK as u32);
    let launched = launch(&mut world, BLOCKMGR_ROLE_ID, 1);
    let publication = registry.publication(&mut world, BOOT_VOLUME);
    let client = registry.client(&mut world);
    stage(&mut world, &launched, Some(publication), Some(client), &[]);
    System {
        world,
        registry,
        disk,
        launched,
    }
}

/// What the scripted client saw, step by step.
#[derive(Default)]
struct Seen {
    info: Option<wrbd::Info>,
    statuses: Vec<Status>,
    block: Option<Vec<u8>>,
    done: bool,
}

/// A client that connects to `volume.boot0`, reads `lba` and one block past
/// the volume's end, then has init retire blockmgr.
fn client(system: &mut System, lba: u64, extra: Vec<Body>) -> Rc<RefCell<Seen>> {
    let seen = Rc::new(RefCell::new(Seen::default()));
    let (endpoint, _) = system.registry.client(&mut system.world);
    let registry = system.registry.clone();
    let control = system.launched.control;
    let peer_seen = seen.clone();
    let mut step = 0;
    let mut direct = DwHandle(0);
    let mut buffer: Option<Memory> = None;
    let mut queue = extra;
    system.world.add_peer(move |world| {
        let mut seen = peer_seen.borrow_mut();
        let request = |world: &mut World, direct, body, handle: Option<DwHandle>| {
            let mut out = [0u8; wrbd::MAX_BYTES];
            let size = wrbd::encode(
                Message {
                    transaction_id: 5,
                    body,
                },
                &mut out,
            )
            .unwrap();
            let handles: Vec<_> = handle.map(|h| (h, LEND_RIGHTS)).into_iter().collect();
            world.send_with(direct, &out[..size], &handles);
        };
        let reply = |world: &mut World, direct| {
            let (bytes, handles) = world.receive(direct);
            let message = wrbd::parse(&bytes, handles.len()).unwrap();
            assert_eq!(message.transaction_id, 5);
            message.body
        };
        match step {
            0 if registry.state.borrow().published(BOOT_VOLUME.name) => {
                let (ours, theirs) = world.pair();
                direct = ours;
                let mut out = [0u8; 256];
                let size = encode_lookup(
                    RegistryHeader {
                        message_type: RegistryMessageType::LookupConnect,
                        registry_generation: 3,
                        endpoint_id: 1,
                        endpoint_generation: 1,
                        transaction_id: 1,
                    },
                    Lookup {
                        protocol_id: BOOT_VOLUME.protocol_id,
                        version: ProtocolVersion { major: 1, minor: 0 },
                        service_name: BOOT_VOLUME.name,
                    },
                    &mut out,
                )
                .unwrap();
                world.send(endpoint, &out[..size], &[theirs]);
            }
            1 if world.readable(endpoint) => {
                world.receive(endpoint);
                request(world, direct, Body::GetInfo, None);
            }
            2 if world.readable(direct) => {
                let Body::Info(info) = reply(world, direct) else {
                    panic!("expected INFO")
                };
                seen.info = Some(info);
                let (memory, bytes) = world.memory_object(4096, LEND_RIGHTS);
                buffer = Some(bytes);
                request(world, direct, Body::Attach { byte_len: 4096 }, Some(memory));
            }
            3 if world.readable(direct) => {
                let Body::Complete(status) = reply(world, direct) else {
                    panic!()
                };
                seen.statuses.push(status);
                request(
                    world,
                    direct,
                    Body::Read(Transfer {
                        lba,
                        block_count: 1,
                        buffer_offset: 0,
                    }),
                    None,
                );
            }
            4 if world.readable(direct) => {
                let Body::Complete(status) = reply(world, direct) else {
                    panic!()
                };
                seen.statuses.push(status);
                seen.block = Some(buffer.as_ref().unwrap().borrow()[..BLOCK].to_vec());
                let past = seen.info.unwrap().block_count;
                request(
                    world,
                    direct,
                    Body::Read(Transfer {
                        lba: past,
                        block_count: 1,
                        buffer_offset: 0,
                    }),
                    None,
                );
            }
            5.. if world.readable(direct) => {
                let Body::Complete(status) = reply(world, direct) else {
                    panic!()
                };
                seen.statuses.push(status);
                match queue.pop() {
                    Some(body) => {
                        request(world, direct, body, None);
                        return true;
                    }
                    None => {
                        seen.done = true;
                        let _ = world.close_handle(control);
                    }
                }
            }
            _ => return false,
        }
        step += 1;
        true
    });
    seen
}

#[test]
fn a_superfloppy_disk_is_served_whole() {
    let mut system = system(superfloppy(2048));
    let seen = client(&mut system, 1000, vec![]);
    let code = blockmgr_main(
        &mut system.world,
        &mut ModelMapper,
        system.launched.bootstrap,
    );
    assert_eq!(code, 0);
    let seen = seen.borrow();
    assert!(seen.done);
    assert_eq!(seen.info.unwrap().block_count, 2048);
    assert_eq!(seen.statuses, [Status::Ok, Status::Ok, Status::OutOfRange]);
    assert_eq!(&seen.block.as_ref().unwrap()[..8], &1000u64.to_le_bytes());
    let disk = system.disk.borrow();
    // The client's buffer reached the driver with exactly the attach rights.
    assert_eq!(disk.attach_rights.last(), Some(&DRIVER_ATTACH_RIGHTS));
    assert!(system.registry.state.borrow().published(BOOT_VOLUME.name));
}

#[test]
fn an_mbr_efi_partition_is_served_shifted_and_bounded() {
    let mut system = system(mbr(4096, 0xef, 2048, 1024));
    let seen = client(&mut system, 10, vec![]);
    let code = blockmgr_main(
        &mut system.world,
        &mut ModelMapper,
        system.launched.bootstrap,
    );
    assert_eq!(code, 0);
    let seen = seen.borrow();
    assert_eq!(seen.info.unwrap().block_count, 1024);
    assert_eq!(&seen.block.as_ref().unwrap()[..8], &2058u64.to_le_bytes());
    assert_eq!(seen.statuses[2], Status::OutOfRange);
    // Discovery read LBA 0; the client's read reached LBA 2048 + 10.
    let reads = &system.disk.borrow().reads;
    assert_eq!(reads.first(), Some(&(0, 1)));
    assert_eq!(reads.last(), Some(&(2058, 1)));
}

#[test]
fn a_disk_without_a_boot_volume_is_not_published() {
    let mut system = system(mbr(4096, 0x83, 2048, 1024));
    let code = blockmgr_main(
        &mut system.world,
        &mut ModelMapper,
        system.launched.bootstrap,
    );
    assert_eq!(code, FAILURE_BASE | 85);
    assert!(!system.registry.state.borrow().published(BOOT_VOLUME.name));
}

#[test]
fn a_misbehaving_client_loses_only_its_own_link() {
    let mut system = system(superfloppy(2048));
    // After the scripted reads, a reply-typed message: blockmgr drops the
    // link, and the client sees its Channel close instead of an answer.
    let seen = client(&mut system, 1, vec![Body::Complete(Status::Ok)]);
    let control = system.launched.control;
    let watcher_seen = seen.clone();
    system.world.add_peer(move |world| {
        // Once the client is stuck with a closed link, retire blockmgr.
        if !watcher_seen.borrow().done
            && world.is_live(control)
            && watcher_seen.borrow().statuses.len() == 3
        {
            let _ = world.close_handle(control);
            return true;
        }
        false
    });
    let code = blockmgr_main(
        &mut system.world,
        &mut ModelMapper,
        system.launched.bootstrap,
    );
    assert_eq!(code, 0);
    assert!(
        !seen.borrow().done,
        "the dropped client never got an answer"
    );
}
