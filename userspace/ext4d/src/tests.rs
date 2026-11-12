//! ext4d against the Channel model: a fake registry and a fake volume
//! serving an ext4 image made by `wyrmroot-ext4`, with the test playing vfsd
//! and init. What ext4d writes is read back from the image afterwards with
//! the library directly, so the bytes on the disk are checked, not ext4d's
//! cache.

use std::cell::RefCell;
use std::rc::Rc;
use std::string::String;
use std::vec;
use std::vec::Vec;

use deepwyrm_syscall::{DW_DEADLINE_INFINITE, DwHandle};
use wyrmroot_channel_model::fakes::{DiskState, FakeRegistry, Launched, launch, serve_disk, stage};
use wyrmroot_channel_model::{Memory, World};
use wyrmroot_ext4::{FormatParams, Kind as Ext4Kind};
use wyrmroot_fs_proto::node::{self, Attr, Body, Kind};
use wyrmroot_fs_proto::{
    OPEN_CREATE, OPEN_DIRECTORY, OPEN_EXCLUSIVE, OPEN_FILE, OPEN_READ, OPEN_TRUNCATE, OPEN_WRITE,
    Status,
};
use wyrmroot_runtime::{HandlePlatform, NativeError};
use wyrmroot_service::OPEN_CHANNEL_RIGHTS;
use wyrmroot_service::memory::{Mapper, View};
use wyrmroot_service_proto::roles::{EXT4D_ROLE_ID, ROOT_VOLUME, SLOT_FS_ROOT};

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
    fn write(&mut self, offset: u64, data: &[u8]) -> bool {
        let mut memory = self.0.borrow_mut();
        match memory.get_mut(offset as usize..offset as usize + data.len()) {
            Some(target) => {
                target.copy_from_slice(data);
                true
            }
            None => false,
        }
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

/// A byte image as a `wyrmroot-ext4` device.
struct Image<'a>(&'a mut Vec<u8>);

impl wyrmroot_ext4::Device for Image<'_> {
    fn read(&mut self, offset: u64, out: &mut [u8]) -> Result<(), DeviceError> {
        let at = offset as usize;
        out.copy_from_slice(self.0.get(at..at + out.len()).ok_or(DeviceError(1))?);
        Ok(())
    }
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), DeviceError> {
        let at = offset as usize;
        self.0
            .get_mut(at..at + data.len())
            .ok_or(DeviceError(2))?
            .copy_from_slice(data);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), DeviceError> {
        Ok(())
    }
}

const IMAGE_BYTES: usize = 4 << 20;

/// An ext4 volume holding `etc/motd`.
fn ext4_image() -> Vec<u8> {
    let mut bytes = vec![0u8; IMAGE_BYTES];
    let mut image = Image(&mut bytes);
    wyrmroot_ext4::format(
        &mut image,
        IMAGE_BYTES as u64,
        &FormatParams {
            block_size: 4096,
            uuid: *b"ext4d-test-image",
            label: [0; 16],
            time: 1_700_000_000,
        },
    )
    .unwrap();
    let mut volume = Volume::mount(&mut image, IMAGE_BYTES as u64, true).unwrap();
    let etc = volume
        .create(&mut image, ROOT_INODE, b"etc", Ext4Kind::Directory)
        .unwrap();
    let motd = volume
        .create(&mut image, etc.inode, b"motd", Ext4Kind::File)
        .unwrap();
    volume
        .write(&mut image, motd.inode, 0, b"welcome\n")
        .unwrap();
    bytes
}

struct Fs {
    world: World,
    disk: Rc<RefCell<DiskState>>,
    launched: Launched,
    server: Server<ModelView>,
    root: DwHandle,
    transaction: u64,
}

/// The model after init stages ext4d: the world, the disk, the launch,
/// vfsd's end of the root, and what `Server::start` returned.
type Started = (
    World,
    Rc<RefCell<DiskState>>,
    Launched,
    DwHandle,
    Result<Server<ModelView>, u32>,
);

fn start(image: Vec<u8>) -> Started {
    let mut world = World::new();
    let registry = FakeRegistry::install(&mut world);
    let disk = serve_disk(&mut world, &registry, ROOT_VOLUME, image, 512);
    let launched = launch(&mut world, EXT4D_ROLE_ID, 1);
    let client = registry.client(&mut world);
    let (root_near, root_far) = world.pair();
    stage(
        &mut world,
        &launched,
        None,
        Some(client),
        &[(SLOT_FS_ROOT, 0, b"", root_far)],
    );
    let server = Server::start(&mut world, &mut ModelMapper, launched.bootstrap);
    (world, disk, launched, root_near, server)
}

fn fs() -> Fs {
    let (world, disk, launched, root, server) = start(ext4_image());
    Fs {
        world,
        disk,
        launched,
        server: server.unwrap_or_else(|step| panic!("ext4d did not start: {step}")),
        root,
        transaction: 1,
    }
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

    fn status(&mut self, channel: DwHandle, body: Body<'_>) -> (Status, u64) {
        let reply = self.request(channel, body);
        match node::parse(&reply, 0).unwrap().body {
            Body::Status { status, value } => (status, value),
            other => panic!("expected STATUS, got {other:?}"),
        }
    }

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
                names.sort_by(|a, b| a.1.cmp(&b.1));
                return names;
            }
            cookie = next_cookie;
        }
    }

    fn read_all(&mut self, file: DwHandle) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
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
                return out;
            }
            out.extend_from_slice(data);
        }
    }

    /// The disk's bytes read directly with `wyrmroot-ext4`: `path`'s data.
    fn on_disk(&self, path: &[u8]) -> Option<Vec<u8>> {
        let mut bytes = self.disk.borrow().image.clone();
        let mut image = Image(&mut bytes);
        let volume = Volume::mount(&mut image, IMAGE_BYTES as u64, false).unwrap();
        let stat = volume.resolve(&mut image, ROOT_INODE, path).ok()?;
        let mut data = vec![0u8; stat.size as usize];
        let mut done = 0;
        while done < data.len() {
            done += volume
                .read(&mut image, stat.inode, done as u64, &mut data[done..])
                .unwrap();
        }
        Some(data)
    }
}

fn pattern(length: usize) -> Vec<u8> {
    (0..length as u32)
        .map(|i| (i * 31 + (i >> 9)) as u8)
        .collect()
}

#[test]
fn files_are_created_written_and_reach_the_disk() {
    let mut fs = fs();
    let root = fs.root;
    assert_eq!(
        fs.list(root),
        [
            (Kind::Directory, String::from("etc")),
            (Kind::Directory, String::from("lost+found"))
        ]
    );
    let (motd, status, attr) = fs.open(root, OPEN_READ, b"etc/motd");
    assert_eq!((status, attr.unwrap().size), (Status::Ok, 8));
    assert_eq!(fs.read_all(motd), b"welcome\n");

    let (file, status, attr) = fs.open(
        root,
        OPEN_READ | OPEN_WRITE | OPEN_FILE | OPEN_CREATE,
        b"etc/notes.txt",
    );
    assert_eq!(status, Status::Ok);
    let attr = attr.unwrap();
    assert_eq!(
        (attr.kind, attr.size, attr.access),
        (Kind::File, 0, ACCESS_READ | ACCESS_WRITE)
    );
    let data = pattern(20_000);
    for (index, chunk) in data.chunks(MAX_IO_BYTES).enumerate() {
        let written = fs.status(
            file,
            Body::Write {
                offset: (index * MAX_IO_BYTES) as u64,
                data: chunk,
            },
        );
        assert_eq!(written, (Status::Ok, chunk.len() as u64));
    }
    assert_eq!(fs.read_all(file), data);
    // Write-through: the bytes are on the disk before SYNC.
    assert_eq!(fs.on_disk(b"etc/notes.txt").as_deref(), Some(&data[..]));
    let flushes_before = fs.disk.borrow().flushes;
    assert_eq!(fs.status(file, Body::Sync), (Status::Ok, 0));
    assert_eq!(fs.disk.borrow().flushes, flushes_before + 1);

    // OPEN_TRUNCATE empties it; OPEN_EXCLUSIVE refuses it.
    let (_, status, attr) = fs.open(root, OPEN_WRITE | OPEN_TRUNCATE, b"etc/notes.txt");
    assert_eq!((status, attr.unwrap().size), (Status::Ok, 0));
    assert_eq!(fs.on_disk(b"etc/notes.txt").as_deref(), Some(&[][..]));
    let (_, status, _) = fs.open(
        root,
        OPEN_WRITE | OPEN_FILE | OPEN_CREATE | OPEN_EXCLUSIVE,
        b"etc/notes.txt",
    );
    assert_eq!(status, Status::Exists);

    let reply = fs.request(root, Body::QueryFilesystem);
    let Body::FsInfo(info) = node::parse(&reply, 0).unwrap().body else {
        panic!()
    };
    assert_eq!(info.flags, FS_DURABLE_SYNC | FS_HARD_LINKS);
    assert!(info.free_bytes > 0 && info.free_bytes < info.total_bytes);
}

#[test]
fn directories_are_made_listed_and_removed() {
    let mut fs = fs();
    let root = fs.root;
    let (dir, status, attr) = fs.open(
        root,
        OPEN_READ | OPEN_WRITE | OPEN_DIRECTORY | OPEN_CREATE,
        b"home",
    );
    assert_eq!((status, attr.unwrap().kind), (Status::Ok, Kind::Directory));
    let (inner, status, _) = fs.open(dir, OPEN_WRITE | OPEN_FILE | OPEN_CREATE, b"a.txt");
    assert_eq!(status, Status::Ok);
    fs.status(
        inner,
        Body::Write {
            offset: 0,
            data: b"a",
        },
    );
    assert_eq!(fs.list(dir), [(Kind::File, String::from("a.txt"))]);
    // Both are open, so both stay.
    assert_eq!(
        fs.status(root, Body::Unlink { name: b"home" }).0,
        Status::Busy
    );
    assert_eq!(
        fs.status(dir, Body::Unlink { name: b"a.txt" }).0,
        Status::Busy
    );
    fs.world.close_handle(inner).unwrap();
    fs.step();
    assert_eq!(
        fs.status(dir, Body::Unlink { name: b"a.txt" }).0,
        Status::Ok
    );
    assert_eq!(fs.on_disk(b"home/a.txt"), None);
    fs.world.close_handle(dir).unwrap();
    fs.step();
    assert_eq!(
        fs.status(root, Body::Unlink { name: b"home" }).0,
        Status::Ok
    );
    assert_eq!(
        fs.status(root, Body::Unlink { name: b"home" }).0,
        Status::NotFound
    );
    assert_eq!(
        fs.status(root, Body::Unlink { name: b"etc" }).0,
        Status::NotEmpty
    );
}

#[test]
fn a_handle_writes_only_with_write_access() {
    let mut fs = fs();
    let root = fs.root;
    let (motd, _, attr) = fs.open(root, OPEN_READ, b"etc/motd");
    assert_eq!(attr.unwrap().access, ACCESS_READ);
    assert_eq!(
        fs.status(
            motd,
            Body::Write {
                offset: 0,
                data: b"x"
            }
        )
        .0,
        Status::AccessDenied
    );
    assert_eq!(
        fs.status(motd, Body::Truncate { size: 0 }).0,
        Status::AccessDenied
    );
    // A read-only directory handle cannot create beneath it either.
    let (etc, _, _) = fs.open(root, OPEN_READ | OPEN_DIRECTORY, b"etc");
    let (_, status, _) = fs.open(etc, OPEN_WRITE | OPEN_FILE | OPEN_CREATE, b"x");
    assert_eq!(status, Status::AccessDenied);
    assert_eq!(
        fs.status(etc, Body::Unlink { name: b"motd" }).0,
        Status::AccessDenied
    );
    assert_eq!(fs.on_disk(b"etc/motd").as_deref(), Some(&b"welcome\n"[..]));
    // Wrong kinds and missing paths.
    for (flags, path, status) in [
        (OPEN_READ, &b"missing"[..], Status::NotFound),
        (
            OPEN_READ | OPEN_DIRECTORY,
            b"etc/motd",
            Status::NotDirectory,
        ),
        (OPEN_READ | OPEN_FILE, b"etc", Status::IsDirectory),
        (
            OPEN_WRITE | OPEN_FILE | OPEN_CREATE,
            b"etc/motd/x",
            Status::NotDirectory,
        ),
    ] {
        let (channel, got, attr) = fs.open(root, flags, path);
        assert_eq!((got, attr), (status, None), "{path:?}");
        assert!(fs.world.peer_closed(channel));
    }
}

#[test]
fn a_volume_without_ext4_ends_the_role() {
    let (_, _, _, _, server) = start(vec![0u8; IMAGE_BYTES]);
    assert_eq!(server.err(), Some(85));
}

#[test]
fn nodes_outlive_the_root_and_init_retires_the_role() {
    let mut fs = fs();
    let root = fs.root;
    let (motd, _, _) = fs.open(root, OPEN_READ, b"etc/motd");
    fs.world.close_handle(root).unwrap();
    fs.step();
    assert_eq!(fs.read_all(motd), b"welcome\n");
    fs.world.send(motd, &[1, 2, 3], &[]);
    fs.step();
    assert!(fs.world.peer_closed(motd));
    fs.world.close_handle(fs.launched.control).unwrap();
    assert_eq!(
        fs.server.step(&mut fs.world, DW_DEADLINE_INFINITE),
        Ok(false)
    );
}

/// Access never grows: a write-only handle neither reads nor lists, and
/// cannot open anything for reading (review D4, 2026-11-11).
#[test]
fn a_write_only_handle_neither_reads_nor_opens_for_reading() {
    let mut fs = fs();
    let root = fs.root;
    let (etc, status, _) = fs.open(root, OPEN_WRITE | OPEN_DIRECTORY, b"etc");
    assert_eq!(status, Status::Ok);
    assert_eq!(
        fs.status(etc, Body::ReadDir { cookie: 0 }).0,
        Status::AccessDenied
    );
    let (_, status, _) = fs.open(etc, OPEN_READ, b"motd");
    assert_eq!(status, Status::AccessDenied);
    let (motd, status, _) = fs.open(etc, OPEN_WRITE, b"motd");
    assert_eq!(status, Status::Ok);
    assert_eq!(
        fs.status(
            motd,
            Body::Read {
                offset: 0,
                length: 8
            }
        )
        .0,
        Status::AccessDenied
    );
}
