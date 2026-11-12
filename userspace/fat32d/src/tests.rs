//! fat32d against the Channel model: a fake registry and a fake volume
//! serving a FAT32 image, with the test playing vfsd and init.

use std::cell::RefCell;
use std::format;
use std::rc::Rc;
use std::string::String;
use std::vec;
use std::vec::Vec;

use deepwyrm_syscall::{DW_DEADLINE_INFINITE, DwHandle};
use wyrmroot_channel_model::fakes::{DiskState, FakeRegistry, Launched, launch, serve_disk, stage};
use wyrmroot_channel_model::fat_image::{Entry, FatImage, MIN_CLUSTERS};
use wyrmroot_channel_model::{Memory, World};
use wyrmroot_fs_proto::node::{self, Attr, Body, Kind, Lock, LockMode};
use wyrmroot_fs_proto::{
    OPEN_CREATE, OPEN_DIRECTORY, OPEN_FILE, OPEN_READ, OPEN_TRUNCATE, OPEN_WRITE, Status,
};
use wyrmroot_runtime::{HandlePlatform, NativeError};
use wyrmroot_service::OPEN_CHANNEL_RIGHTS;
use wyrmroot_service::memory::{Mapper, View};
use wyrmroot_service_proto::roles::{BOOT_VOLUME, FAT32D_ROLE_ID, SLOT_FS_ROOT};

use crate::*;

struct ModelMapper;
struct ModelView(Memory);

impl View for ModelView {
    fn len(&self) -> u64 {
        self.0.borrow().len() as u64
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> bool {
        let memory = self.0.borrow();
        match memory.get(offset as usize..offset as usize + out.len()) {
            Some(source) => {
                out.copy_from_slice(source);
                true
            }
            None => false,
        }
    }
    fn write(&mut self, _: u64, _: &[u8]) -> bool {
        false
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

fn kernel_bytes() -> Vec<u8> {
    (0..40_000u32).map(|i| (i ^ (i >> 8)) as u8).collect()
}

struct Fs {
    world: World,
    disk: Rc<RefCell<DiskState>>,
    launched: Launched,
    server: Server<ModelView>,
    root: DwHandle,
    transaction: u64,
}

fn fs(root: &[Entry<'_>]) -> Fs {
    let mut world = World::new();
    let registry = FakeRegistry::install(&mut world);
    let image = FatImage::build(MIN_CLUSTERS + 300, root);
    let disk = serve_disk(&mut world, &registry, BOOT_VOLUME, image, 512);
    let launched = launch(&mut world, FAT32D_ROLE_ID, 1);
    let client = registry.client(&mut world);
    let (root_near, root_far) = world.pair();
    stage(
        &mut world,
        &launched,
        None,
        Some(client),
        &[(SLOT_FS_ROOT, 0, b"", root_far)],
    );
    let server = Server::start(&mut world, &mut ModelMapper, launched.bootstrap).unwrap();
    Fs {
        world,
        disk,
        launched,
        server,
        root: root_near,
        transaction: 1,
    }
}

fn sample() -> Fs {
    let kernel = kernel_bytes();
    let kernel: &'static [u8] = Vec::leak(kernel);
    fs(&[
        Entry::Directory(
            "EFI",
            vec![
                Entry::Directory("BOOT", vec![Entry::File("BOOTX64.EFI", b"MZ loader")]),
                Entry::Directory(
                    "wyrmroot",
                    vec![
                        Entry::File("deepwyrm.elf", kernel),
                        Entry::File("empty", b""),
                    ],
                ),
            ],
        ),
        Entry::File("readme.txt", b"hello from the ESP\n"),
    ])
}

impl Fs {
    fn step(&mut self) {
        assert_eq!(
            self.server.step(&mut self.world, DW_DEADLINE_INFINITE),
            Ok(true)
        );
    }

    fn request(&mut self, channel: DwHandle, body: Body<'_>) -> Vec<u8> {
        self.transaction += 1;
        let mut bytes = vec![0u8; node::MAX_BYTES];
        let size = node::encode(
            &node::Message {
                transaction_id: self.transaction,
                body,
            },
            &mut bytes,
        )
        .unwrap();
        self.world.send(channel, &bytes[..size], &[]);
        self.step();
        let (reply, _) = self.world.receive(channel);
        assert_eq!(
            node::parse(&reply, 0).unwrap().transaction_id,
            self.transaction
        );
        reply
    }

    /// OPEN on `dir`: the client end, and what ON_OPEN said.
    fn open(&mut self, dir: DwHandle, flags: u32, path: &[u8]) -> (DwHandle, Status, Option<Attr>) {
        self.transaction += 1;
        let (near, far) = self.world.pair();
        assert_eq!(self.world.rights(far), Some(OPEN_CHANNEL_RIGHTS));
        let mut bytes = vec![0u8; node::MAX_BYTES];
        let size = node::encode(
            &node::Message {
                transaction_id: self.transaction,
                body: Body::Open { flags, path },
            },
            &mut bytes,
        )
        .unwrap();
        self.world.send(dir, &bytes[..size], &[far]);
        self.step();
        let (reply, _) = self.world.receive(near);
        match node::parse(&reply, 0).unwrap().body {
            Body::OnOpen { status, attr } => (near, status, attr),
            other => panic!("expected ON_OPEN, got {other:?}"),
        }
    }

    fn list(&mut self, dir: DwHandle) -> Vec<(Kind, String)> {
        let mut names = Vec::new();
        let mut cookie = 0;
        loop {
            let reply = self.request(dir, Body::ReadDir { cookie });
            let Body::Dirents {
                next_cookie,
                entries,
            } = node::parse(&reply, 0).unwrap().body
            else {
                panic!("expected DIRENTS");
            };
            for (kind, name) in entries.iter() {
                names.push((kind, String::from_utf8(name.to_vec()).unwrap()));
            }
            if next_cookie == 0 {
                return names;
            }
            cookie = next_cookie;
        }
    }

    fn read_all(&mut self, file: DwHandle, size: usize) -> Vec<u8> {
        let mut out = Vec::new();
        while out.len() < size + 1 {
            let reply = self.request(
                file,
                Body::Read {
                    offset: out.len() as u64,
                    length: 8192,
                },
            );
            let Body::Data(data) = node::parse(&reply, 0).unwrap().body else {
                panic!("expected DATA");
            };
            if data.is_empty() {
                break;
            }
            out.extend_from_slice(data);
        }
        out
    }
}

#[test]
fn the_root_lists_and_files_read_back_byte_for_byte() {
    let mut fs = sample();
    let root = fs.root;
    assert_eq!(
        fs.list(root),
        [
            (Kind::Directory, String::from("EFI")),
            (Kind::File, String::from("readme.txt"))
        ]
    );
    let (readme, status, attr) = fs.open(root, OPEN_READ | OPEN_FILE, b"readme.txt");
    assert_eq!(status, Status::Ok);
    assert_eq!(attr.unwrap().size, 19);
    assert_eq!(attr.unwrap().access, ACCESS_READ);
    assert_eq!(fs.read_all(readme, 19), b"hello from the ESP\n");

    // A 40000-byte file spans two cache windows and several READs.
    let (kernel, status, attr) = fs.open(root, OPEN_READ, b"efi/wyrmroot/deepwyrm.elf");
    assert_eq!((status, attr.unwrap().kind), (Status::Ok, Kind::File));
    let before = fs.disk.borrow().reads.len();
    assert_eq!(fs.read_all(kernel, 40_000), kernel_bytes());
    let device_reads = fs.disk.borrow().reads.len() - before;
    assert!(device_reads <= 6, "{device_reads} device reads for 40 KB");

    let (empty, status, _) = fs.open(root, OPEN_READ, b"EFI/wyrmroot/empty");
    assert_eq!(status, Status::Ok);
    assert!(fs.read_all(empty, 0).is_empty());

    let (efi, status, attr) = fs.open(root, OPEN_READ | OPEN_DIRECTORY, b"EFI");
    assert_eq!((status, attr.unwrap().kind), (Status::Ok, Kind::Directory));
    assert_eq!(
        fs.list(efi),
        [
            (Kind::Directory, String::from("BOOT")),
            (Kind::Directory, String::from("wyrmroot"))
        ]
    );
    let (loader, status, _) = fs.open(efi, OPEN_READ, b"BOOT/BOOTX64.EFI");
    assert_eq!(status, Status::Ok);
    assert_eq!(fs.read_all(loader, 9), b"MZ loader");
    let reply = fs.request(efi, Body::QueryFilesystem);
    let Body::FsInfo(info) = node::parse(&reply, 0).unwrap().body else {
        panic!()
    };
    assert_eq!(info.flags, FS_READ_ONLY);
}

#[test]
fn opens_report_missing_wrong_kind_and_mutation() {
    let mut fs = sample();
    let root = fs.root;
    for (flags, path, status) in [
        (OPEN_READ, &b"missing"[..], Status::NotFound),
        (OPEN_READ, b"readme.txt/inner", Status::NotDirectory),
        (
            OPEN_READ | OPEN_DIRECTORY,
            b"readme.txt",
            Status::NotDirectory,
        ),
        (OPEN_READ | OPEN_FILE, b"EFI", Status::IsDirectory),
        (OPEN_READ | OPEN_WRITE, b"readme.txt", Status::ReadOnly),
        (OPEN_WRITE | OPEN_TRUNCATE, b"readme.txt", Status::ReadOnly),
        (
            OPEN_WRITE | OPEN_FILE | OPEN_CREATE,
            b"new.txt",
            Status::ReadOnly,
        ),
    ] {
        let (channel, got, attr) = fs.open(root, flags, path);
        assert_eq!((got, attr), (status, None), "{path:?}");
        assert!(fs.world.peer_closed(channel), "a failed open closes");
    }
    let (readme, _, _) = fs.open(root, OPEN_READ, b"readme.txt");
    for (body, status) in [
        (
            Body::Write {
                offset: 0,
                data: b"x",
            },
            Status::ReadOnly,
        ),
        (Body::Truncate { size: 0 }, Status::ReadOnly),
        (Body::ReadDir { cookie: 0 }, Status::NotDirectory),
        (Body::Sync, Status::Ok),
        // No locks on FAT; the node stays open (W10).
        (
            Body::Lock {
                lock: Lock {
                    start: 0,
                    length: 0,
                    mode: LockMode::Shared,
                },
                flags: 0,
                group: 0,
            },
            Status::NotSupported,
        ),
        (
            Body::TestLock(Lock {
                start: 0,
                length: 0,
                mode: LockMode::Shared,
            }),
            Status::NotSupported,
        ),
    ] {
        let reply = fs.request(readme, body);
        assert_eq!(
            node::parse(&reply, 0).unwrap().body,
            Body::Status { status, value: 0 },
            "{body:?}"
        );
    }
    let reply = fs.request(
        root,
        Body::Read {
            offset: 0,
            length: 1,
        },
    );
    assert_eq!(
        node::parse(&reply, 0).unwrap().body,
        Body::Status {
            status: Status::IsDirectory,
            value: 0
        }
    );
}

#[test]
fn long_directories_page_with_cookies() {
    let names: Vec<String> = (0..150)
        .map(|i| format!("a fairly long file name {i:03}.txt"))
        .collect();
    let entries: Vec<Entry<'_>> = names
        .iter()
        .map(|name| Entry::File(name.as_str(), b"x"))
        .collect();
    let mut fs = fs(&entries);
    let root = fs.root;
    let listed: Vec<String> = fs.list(root).into_iter().map(|(_, name)| name).collect();
    assert_eq!(listed, names);
}

#[test]
fn nodes_outlive_the_root_and_init_retires_the_role() {
    let mut fs = sample();
    let root = fs.root;
    let (readme, _, _) = fs.open(root, OPEN_READ, b"readme.txt");
    fs.world.close_handle(root).unwrap();
    fs.step();
    assert_eq!(fs.read_all(readme, 19).len(), 19);
    // A node peer that sends garbage loses its node only.
    fs.world.send(readme, &[1, 2, 3], &[]);
    fs.step();
    assert!(fs.world.peer_closed(readme));
    fs.world.close_handle(fs.launched.control).unwrap();
    assert_eq!(
        fs.server.step(&mut fs.world, DW_DEADLINE_INFINITE),
        Ok(false)
    );
}
