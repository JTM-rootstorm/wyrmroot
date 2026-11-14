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
use wyrmroot_fs_proto::node::{self, Attr, Body, Kind, LOCK_WAIT, Lock, LockMode};
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

const IMAGE_BYTES: usize = 8 << 20;

/// An ext4 volume holding `etc/motd`.
fn ext4_image() -> Vec<u8> {
    image_with_journal(0)
}

fn image_with_journal(journal_blocks: u32) -> Vec<u8> {
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
            journal_blocks,
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
        self.open_as(dir, flags, path, 0)
    }

    /// OPEN naming `client`, as vfsd does on the root Channel.
    fn open_as(
        &mut self,
        dir: DwHandle,
        flags: u32,
        path: &[u8],
        client: u64,
    ) -> (DwHandle, Status, Option<Attr>) {
        self.transaction += 1;
        let (near, far) = self.world.pair();
        assert_eq!(self.world.rights(far), Some(OPEN_CHANNEL_RIGHTS));
        let mut bytes = vec![0u8; node::MAX_BYTES];
        let size = node::encode(
            &node::Message {
                transaction_id: self.transaction,
                body: Body::Open {
                    flags,
                    path,
                    client,
                },
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

    /// The disk's bytes read directly with `wyrmroot-ext4`: `path`'s data,
    /// as a crash now would leave it (the journal replayed on a copy).
    fn on_disk(&self, path: &[u8]) -> Option<Vec<u8>> {
        let mut bytes = self.disk.borrow().image.clone();
        let mut image = Image(&mut bytes);
        wyrmroot_ext4::recover(&mut image, IMAGE_BYTES as u64).unwrap();
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
    // An open directory stays, empty or not.
    assert_eq!(
        fs.status(root, Body::Unlink { name: b"home" }).0,
        Status::Busy
    );
    fs.world.close_handle(inner).unwrap();
    fs.step();
    assert_eq!(
        fs.status(dir, Body::Unlink { name: b"a.txt" }).0,
        Status::Ok
    );
    assert_eq!(fs.on_disk(b"home/a.txt"), None);
    assert_eq!(
        fs.status(root, Body::Unlink { name: b"home" }).0,
        Status::Busy
    );
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

#[test]
fn a_journaled_volume_commits_on_sync_and_retires_clean() {
    let (world, disk, launched, root, server) = start(image_with_journal(1024));
    let mut fs = Fs {
        world,
        disk,
        launched,
        server: server.unwrap_or_else(|step| panic!("ext4d did not start: {step}")),
        root,
        transaction: 1,
    };
    let (file, status, _) = fs.open(
        root,
        OPEN_READ | OPEN_WRITE | OPEN_FILE | OPEN_CREATE,
        b"etc/journaled.txt",
    );
    assert_eq!(status, Status::Ok);
    let data = pattern(20_000);
    for (index, chunk) in data.chunks(8192).enumerate() {
        let (status, written) = fs.status(
            file,
            Body::Write {
                offset: (index * 8192) as u64,
                data: chunk,
            },
        );
        assert_eq!((status, written), (Status::Ok, chunk.len() as u64));
    }
    assert_eq!(fs.read_all(file), data);
    // Uncommitted: a crash now leaves the volume as it was.
    assert_eq!(fs.on_disk(b"etc/journaled.txt"), None);
    assert_eq!(fs.on_disk(b"etc/motd").unwrap(), b"welcome\n");
    assert_eq!(fs.status(file, Body::Sync).0, Status::Ok);
    assert_eq!(fs.on_disk(b"etc/journaled.txt"), Some(data.clone()));

    fs.server.retire(&mut fs.world);
    // Clean: it mounts without recovery.
    let mut bytes = fs.disk.borrow().image.clone();
    let mut image = Image(&mut bytes);
    assert_eq!(
        wyrmroot_ext4::recover(&mut image, IMAGE_BYTES as u64),
        Ok(false)
    );
    Volume::mount(&mut image, IMAGE_BYTES as u64, false).unwrap();
}

#[test]
fn space_freed_since_the_last_commit_is_used_after_committing() {
    // W11 review R7: the allocator passes over blocks freed in the running
    // transaction, so a full volume whose space was just freed reported
    // NoSpace until the next commit.
    let (world, disk, launched, root, server) = start(image_with_journal(1024));
    let mut fs = Fs {
        world,
        disk,
        launched,
        server: server.unwrap_or_else(|step| panic!("ext4d did not start: {step}")),
        root,
        transaction: 1,
    };
    let flags = OPEN_READ | OPEN_WRITE | OPEN_FILE | OPEN_CREATE;
    let (big, status, _) = fs.open(root, flags, b"big");
    assert_eq!(status, Status::Ok);
    let chunk = pattern(8192);
    let mut offset = 0u64;
    loop {
        match fs.status(
            big,
            Body::Write {
                offset,
                data: &chunk,
            },
        ) {
            (Status::Ok, written) if written > 0 => offset += written,
            (Status::NoSpace, _) => break,
            other => panic!("filling the volume: {other:?}"),
        }
    }
    assert!(offset > 1 << 20, "the volume held only {offset} bytes");
    assert_eq!(fs.status(big, Body::Sync).0, Status::Ok);
    // Freed in the running transaction, not yet committed.
    assert_eq!(fs.status(big, Body::Truncate { size: 0 }).0, Status::Ok);
    let (small, status, _) = fs.open(root, flags, b"small");
    assert_eq!(status, Status::Ok);
    let data = pattern(64 << 10);
    for (index, part) in data.chunks(8192).enumerate() {
        assert_eq!(
            fs.status(
                small,
                Body::Write {
                    offset: (index * 8192) as u64,
                    data: part,
                },
            ),
            (Status::Ok, part.len() as u64)
        );
    }
    assert_eq!(fs.read_all(small), data);
    assert_eq!(fs.status(small, Body::Sync).0, Status::Ok);
    assert_eq!(fs.on_disk(b"small"), Some(data));
    assert_eq!(fs.on_disk(b"big"), Some(Vec::new()));
}

fn lock(start: u64, length: u64, mode: LockMode) -> Lock {
    Lock {
        start,
        length,
        mode,
    }
}

impl Fs {
    fn test_lock(&mut self, channel: DwHandle, lock: Lock) -> Option<Lock> {
        let reply = self.request(channel, Body::TestLock(lock));
        match node::parse(&reply, 0).unwrap().body {
            Body::LockInfo(held) => held,
            other => panic!("expected LOCK_INFO, got {other:?}"),
        }
    }
}

#[test]
fn locks_belong_to_their_channel_and_go_with_it() {
    let mut fs = fs();
    let root = fs.root;
    let (first, _, first_attr) = fs.open(root, OPEN_READ | OPEN_WRITE, b"etc/motd");
    let (second, _, second_attr) = fs.open(root, OPEN_READ, b"etc/motd");
    let (other, _, other_attr) = fs.open(root, OPEN_READ, b"etc");
    let (first_attr, second_attr) = (first_attr.unwrap(), second_attr.unwrap());
    assert_ne!(first_attr.filesystem, 0);
    assert_eq!(first_attr.filesystem, other_attr.unwrap().filesystem);
    assert_eq!(first_attr.id, second_attr.id);

    // Any access may lock; another Channel on the same file conflicts.
    assert_eq!(
        fs.status(
            second,
            Body::Lock {
                lock: lock(0, 0, LockMode::Exclusive),
                flags: 0,
            }
        )
        .0,
        Status::Ok
    );
    assert_eq!(
        fs.status(
            first,
            Body::Lock {
                lock: lock(10, 1, LockMode::Shared),
                flags: 0,
            }
        )
        .0,
        Status::Busy
    );
    assert_eq!(
        fs.test_lock(first, lock(10, 1, LockMode::Shared)),
        Some(lock(0, 0, LockMode::Exclusive))
    );
    assert_eq!(fs.test_lock(second, lock(10, 1, LockMode::Exclusive)), None);
    // Another node is not affected.
    assert_eq!(
        fs.status(
            other,
            Body::Lock {
                lock: lock(0, 0, LockMode::Exclusive),
                flags: 0,
            }
        )
        .0,
        Status::Ok
    );
    // Unlocking part leaves the rest; closing the Channel releases it all.
    assert_eq!(
        fs.status(
            second,
            Body::Lock {
                lock: lock(0, 100, LockMode::Unlock),
                flags: 0,
            }
        )
        .0,
        Status::Ok
    );
    assert_eq!(
        fs.status(
            first,
            Body::Lock {
                lock: lock(10, 1, LockMode::Exclusive),
                flags: 0,
            }
        )
        .0,
        Status::Ok
    );
    assert_eq!(
        fs.status(
            first,
            Body::Lock {
                lock: lock(100, 1, LockMode::Shared),
                flags: 0,
            }
        )
        .0,
        Status::Busy
    );
    fs.world.close_handle(second).unwrap();
    fs.step();
    assert_eq!(fs.test_lock(first, lock(0, 0, LockMode::Exclusive)), None);
    assert_eq!(
        fs.status(
            first,
            Body::Lock {
                lock: lock(0, 0, LockMode::Exclusive),
                flags: 0,
            }
        )
        .0,
        Status::Ok
    );
}

#[test]
fn one_channel_cannot_take_the_lock_table_from_the_others() {
    // W10 review D1: the table holds every Channel's limit, so one that
    // fills its own share leaves the others theirs.
    let mut fs = fs();
    let root = fs.root;
    let (greedy, _, _) = fs.open(root, OPEN_READ, b"etc/motd");
    let (other, _, _) = fs.open(root, OPEN_READ, b"etc/motd");
    for index in 0..LOCKS_PER_NODE as u64 {
        assert_eq!(
            fs.status(
                greedy,
                Body::Lock {
                    lock: lock(index * 2, 1, LockMode::Shared),
                    flags: 0,
                }
            )
            .0,
            Status::Ok
        );
    }
    assert_eq!(
        fs.status(
            greedy,
            Body::Lock {
                lock: lock(1_000_000, 1, LockMode::Shared),
                flags: 0,
            }
        )
        .0,
        Status::NoResources
    );
    assert_eq!(fs.read_all(greedy), b"welcome\n");
    for index in 0..LOCKS_PER_NODE as u64 {
        assert_eq!(
            fs.status(
                other,
                Body::Lock {
                    lock: lock(index * 2, 1, LockMode::Shared),
                    flags: 0,
                }
            )
            .0,
            Status::Ok
        );
    }
}

#[test]
fn a_file_opened_again_is_another_lock_owner() {
    // What the POSIX layer's lock Channels are (W10 review Q1).
    let mut fs = fs();
    let root = fs.root;
    let (file, _, attr) = fs.open(root, OPEN_READ, b"etc/motd");
    let (again, status, again_attr) = fs.open(file, OPEN_READ, b"");
    assert_eq!(status, Status::Ok);
    assert_eq!(attr.unwrap().id, again_attr.unwrap().id);
    let (_, status, _) = fs.open(file, OPEN_READ | OPEN_WRITE, b"");
    assert_eq!(status, Status::AccessDenied, "access never grows");
    assert_eq!(
        fs.status(
            again,
            Body::Lock {
                lock: lock(0, 0, LockMode::Exclusive),
                flags: 0,
            }
        )
        .0,
        Status::Ok
    );
    assert_eq!(
        fs.status(
            file,
            Body::Lock {
                lock: lock(0, 1, LockMode::Shared),
                flags: 0,
            }
        )
        .0,
        Status::Busy
    );
}

#[test]
fn a_request_after_a_close_sees_the_close() {
    // The root's wakeup comes before every node's, so without reaping the
    // closed node, UNLINK of a file whose last handle just closed answered
    // BUSY (SQLite's journal delete, dev-boot 2026-11-12), and a lock the
    // close released still conflicted.
    let mut fs = fs();
    let root = fs.root;
    let (file, status, _) = fs.open(
        root,
        OPEN_READ | OPEN_WRITE | OPEN_FILE | OPEN_CREATE,
        b"journal",
    );
    assert_eq!(status, Status::Ok);
    let (holder, _, _) = fs.open(root, OPEN_READ, b"etc/motd");
    let (other, _, _) = fs.open(root, OPEN_READ, b"etc/motd");
    assert_eq!(
        fs.status(
            holder,
            Body::Lock {
                lock: lock(0, 0, LockMode::Exclusive),
                flags: 0,
            }
        )
        .0,
        Status::Ok
    );
    fs.world.close_handle(file).unwrap();
    fs.world.close_handle(holder).unwrap();
    assert_eq!(
        fs.status(root, Body::Unlink { name: b"journal" }).0,
        Status::Ok
    );
    assert_eq!(
        fs.status(
            other,
            Body::Lock {
                lock: lock(0, 0, LockMode::Exclusive),
                flags: 0,
            }
        )
        .0,
        Status::Ok
    );
    // A directory that is still open is still BUSY.
    let (home, status, _) = fs.open(
        root,
        OPEN_READ | OPEN_WRITE | OPEN_DIRECTORY | OPEN_CREATE,
        b"home",
    );
    assert_eq!(status, Status::Ok);
    assert_eq!(
        fs.status(root, Body::Unlink { name: b"home" }).0,
        Status::Busy
    );
    let _ = home;
}

impl Fs {
    /// Sends a LOCK and lets the server run once; its transaction.
    fn lock_send(&mut self, channel: DwHandle, lock: Lock, flags: u32) -> u64 {
        self.transaction += 1;
        let mut bytes = vec![0u8; node::MAX_BYTES];
        let size = node::encode(
            &node::Message {
                transaction_id: self.transaction,
                body: Body::Lock { lock, flags },
            },
            &mut bytes,
        )
        .unwrap();
        self.world.send(channel, &bytes[..size], &[]);
        self.step();
        self.transaction
    }

    /// The STATUS answering `transaction` on `channel`.
    fn answer(&mut self, channel: DwHandle, transaction: u64) -> (Status, u64) {
        let (reply, _) = self.world.receive(channel);
        let message = node::parse(&reply, 0).unwrap();
        assert_eq!(message.transaction_id, transaction);
        match message.body {
            Body::Status { status, value } => (status, value),
            other => panic!("expected STATUS, got {other:?}"),
        }
    }
}

#[test]
fn a_waiting_lock_is_answered_when_the_holder_closes() {
    let mut fs = fs();
    let root = fs.root;
    let (holder, _, _) = fs.open(root, OPEN_READ, b"etc/motd");
    let (waiter, _, _) = fs.open(root, OPEN_READ, b"etc/motd");
    let taken = fs.lock_send(holder, lock(0, 0, LockMode::Exclusive), 0);
    assert_eq!(fs.answer(holder, taken).0, Status::Ok);
    let waiting = fs.lock_send(waiter, lock(0, 1, LockMode::Shared), LOCK_WAIT);
    assert!(!fs.world.readable(waiter), "no answer while it waits");
    // Its other requests are refused while it waits.
    assert_eq!(fs.status(waiter, Body::GetAttr).0, Status::Invalid);
    fs.world.close_handle(holder).unwrap();
    fs.step();
    assert_eq!(fs.answer(waiter, waiting), (Status::Ok, 0));
    assert_eq!(fs.read_all(waiter), b"welcome\n");
}

#[test]
fn a_wait_that_would_close_a_cycle_between_clients_is_a_deadlock() {
    // Clients 1 and 2 are two jobs' vfsd connections; each has one Channel
    // per file.
    let mut fs = fs();
    let root = fs.root;
    let open = |fs: &mut Fs, path: &[u8], client| fs.open_as(root, OPEN_READ, path, client).0;
    let (a_motd, a_etc, b_motd, b_etc) = (
        open(&mut fs, b"etc/motd", 1),
        open(&mut fs, b"etc", 1),
        open(&mut fs, b"etc/motd", 2),
        open(&mut fs, b"etc", 2),
    );
    let whole = lock(0, 0, LockMode::Exclusive);
    let sent = fs.lock_send(a_motd, whole, 0);
    assert_eq!(fs.answer(a_motd, sent).0, Status::Ok);
    let sent = fs.lock_send(b_etc, whole, 0);
    assert_eq!(fs.answer(b_etc, sent).0, Status::Ok);
    let a_waits = fs.lock_send(a_etc, whole, LOCK_WAIT);
    assert!(!fs.world.readable(a_etc));
    let sent = fs.lock_send(b_motd, whole, LOCK_WAIT);
    assert_eq!(fs.answer(b_motd, sent).0, Status::Deadlock);
    // B gives up its lock; A's wait ends.
    fs.world.close_handle(b_etc).unwrap();
    fs.step();
    assert_eq!(fs.answer(a_etc, a_waits), (Status::Ok, 0));
}

#[test]
fn a_node_s_client_is_inherited_and_never_named_by_a_client() {
    let mut fs = fs();
    let root = fs.root;
    let (etc, _, _) = fs.open_as(root, OPEN_READ, b"etc", 1);
    // Opened through client 1's directory: client 1's, so its wait on
    // client 1's own lock is a deadlock.
    let (motd, status, _) = fs.open(etc, OPEN_READ, b"motd");
    assert_eq!(status, Status::Ok);
    let (held, _, _) = fs.open_as(root, OPEN_READ, b"etc/motd", 1);
    let sent = fs.lock_send(held, lock(0, 0, LockMode::Exclusive), 0);
    assert_eq!(fs.answer(held, sent).0, Status::Ok);
    let sent = fs.lock_send(motd, lock(0, 0, LockMode::Exclusive), LOCK_WAIT);
    assert_eq!(fs.answer(motd, sent).0, Status::Deadlock);
    // Only the root Channel (vfsd) names a client.
    let (forged, status, _) = fs.open_as(etc, OPEN_READ, b"motd", 2);
    assert_eq!(status, Status::Invalid);
    assert!(fs.world.peer_closed(forged));
    // OPEN is one-way: the directory's Channel hears nothing (review D1).
    assert!(!fs.world.readable(etc));
    assert_eq!(fs.list(etc), [(Kind::File, "motd".into())]);
}

impl Fs {
    /// Sends CLOSE on `channel` and lets the server run once.
    fn send_close(&mut self, channel: DwHandle) {
        self.transaction += 1;
        let mut bytes = vec![0u8; node::MAX_BYTES];
        let size = node::encode(
            &node::Message {
                transaction_id: self.transaction,
                body: Body::Close,
            },
            &mut bytes,
        )
        .unwrap();
        self.world.send(channel, &bytes[..size], &[]);
        self.step();
    }
}

#[test]
fn close_drops_the_node_and_its_locks_with_no_reply() {
    // WRFS 1.3: the server's end closing is the client's sign that its close
    // is complete, so its charge for the pair is gone before it opens again
    // (dev-boot 2026-11-12: SQLite's journal delete got EMFILE).
    let mut fs = fs();
    let root = fs.root;
    let (holder, _, _) = fs.open(root, OPEN_READ, b"etc/motd");
    let (other, _, _) = fs.open(root, OPEN_READ, b"etc/motd");
    let taken = fs.lock_send(holder, lock(0, 0, LockMode::Exclusive), 0);
    assert_eq!(fs.answer(holder, taken).0, Status::Ok);
    fs.send_close(holder);
    assert!(fs.world.peer_closed(holder), "the server closed its end");
    assert!(!fs.world.readable(holder), "CLOSE has no reply");
    // The lock went with it, while the client still holds its end.
    let free = fs.lock_send(other, lock(0, 0, LockMode::Exclusive), 0);
    assert_eq!(fs.answer(other, free).0, Status::Ok);
}

#[test]
fn close_ends_a_node_whose_lock_is_waiting() {
    let mut fs = fs();
    let root = fs.root;
    let (holder, _, _) = fs.open(root, OPEN_READ, b"etc/motd");
    let (waiter, _, _) = fs.open(root, OPEN_READ, b"etc/motd");
    let taken = fs.lock_send(holder, lock(0, 0, LockMode::Exclusive), 0);
    assert_eq!(fs.answer(holder, taken).0, Status::Ok);
    let _waiting = fs.lock_send(waiter, lock(0, 0, LockMode::Exclusive), LOCK_WAIT);
    fs.send_close(waiter);
    assert!(fs.world.peer_closed(waiter));
    assert!(
        !fs.world.readable(waiter),
        "neither CLOSE nor the wait is answered"
    );
    // The holder's unlock grants nothing to the closed waiter.
    let unlock = fs.lock_send(holder, lock(0, 0, LockMode::Unlock), 0);
    assert_eq!(fs.answer(holder, unlock).0, Status::Ok);
}

// Open nodes outlive their names (platform conventions 5.3).

fn journaled_fs(image: Vec<u8>) -> Fs {
    let (world, disk, launched, root, server) = start(image);
    Fs {
        world,
        disk,
        launched,
        server: server.unwrap_or_else(|step| panic!("ext4d did not start: {step}")),
        root,
        transaction: 1,
    }
}

/// What a volume's superblock says is free, and the first inode on its
/// orphan list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Counts {
    free_blocks: u64,
    free_inodes: u32,
    first_orphan: u32,
}

/// `image` as a crash now would leave it (the journal replayed on a copy).
fn counts_of(image: &[u8]) -> Counts {
    let mut bytes = image.to_vec();
    let mut image = Image(&mut bytes);
    wyrmroot_ext4::recover(&mut image, IMAGE_BYTES as u64).unwrap();
    let volume = Volume::mount(&mut image, IMAGE_BYTES as u64, false).unwrap();
    let word = |at: usize| u32::from_le_bytes(bytes[1024 + at..1024 + at + 4].try_into().unwrap());
    Counts {
        free_blocks: volume.usage().free_blocks,
        free_inodes: word(0x10),
        first_orphan: word(0xE8),
    }
}

impl Fs {
    fn counts(&self) -> Counts {
        counts_of(&self.disk.borrow().image)
    }

    fn free_bytes(&mut self) -> u64 {
        let root = self.root;
        let reply = self.request(root, Body::QueryFilesystem);
        let Body::FsInfo(info) = node::parse(&reply, 0).unwrap().body else {
            panic!("expected FS_INFO")
        };
        info.free_bytes
    }

    fn attr(&mut self, channel: DwHandle) -> Attr {
        let reply = self.request(channel, Body::GetAttr);
        match node::parse(&reply, 0).unwrap().body {
            Body::Attr(attr) => attr,
            other => panic!("expected ATTR, got {other:?}"),
        }
    }

    fn write_all(&mut self, file: DwHandle, offset: u64, data: &[u8]) {
        for (index, chunk) in data.chunks(MAX_IO_BYTES).enumerate() {
            assert_eq!(
                self.status(
                    file,
                    Body::Write {
                        offset: offset + (index * MAX_IO_BYTES) as u64,
                        data: chunk,
                    },
                ),
                (Status::Ok, chunk.len() as u64)
            );
        }
    }
}

const CREATE: u32 = OPEN_READ | OPEN_WRITE | OPEN_FILE | OPEN_CREATE;

#[test]
fn a_file_unlinked_while_open_lives_until_its_last_close() {
    for journal_blocks in [0, 1024] {
        let mut fs = journaled_fs(image_with_journal(journal_blocks));
        let root = fs.root;
        assert_eq!(fs.status(root, Body::Sync).0, Status::Ok);
        let before = fs.counts();
        let free = fs.free_bytes();

        let (writer, status, attr) = fs.open(root, CREATE, b"temp");
        assert_eq!(status, Status::Ok);
        let id = attr.unwrap().id;
        let data = pattern(20_000);
        fs.write_all(writer, 0, &data);
        let (reader, status, _) = fs.open(root, OPEN_READ, b"temp");
        assert_eq!(status, Status::Ok);

        // The name goes at once, and durably with the next commit.
        assert_eq!(
            fs.status(root, Body::Unlink { name: b"temp" }).0,
            Status::Ok
        );
        assert!(!fs.list(root).iter().any(|(_, name)| name == "temp"));
        assert_eq!(fs.open(root, OPEN_READ, b"temp").1, Status::NotFound);
        assert_eq!(
            fs.status(root, Body::Unlink { name: b"temp" }).0,
            Status::NotFound
        );
        assert_eq!(fs.status(root, Body::Sync).0, Status::Ok);
        assert_eq!(fs.on_disk(b"temp"), None);
        let held = fs.counts();
        assert_eq!(u64::from(held.first_orphan), id);
        assert_eq!(held.free_inodes, before.free_inodes - 1);
        assert!(fs.free_bytes() < free);

        // Both handles go on as before.
        let attr = fs.attr(writer);
        assert_eq!((attr.id, attr.size, attr.kind), (id, 20_000, Kind::File));
        assert_eq!(fs.read_all(reader), data);
        fs.write_all(writer, 20_000, &data);
        assert_eq!(fs.attr(reader).size, 40_000);
        assert_eq!(
            fs.status(writer, Body::Truncate { size: 30_000 }).0,
            Status::Ok
        );
        let mut expected = data.clone();
        expected.extend_from_slice(&data[..10_000]);
        assert_eq!(fs.read_all(reader), expected);
        // The file opened again through its own handle is the same file.
        let (again, status, attr) = fs.open(reader, OPEN_READ, b"");
        assert_eq!((status, attr.unwrap().id), (Status::Ok, id));

        // The name is free for another file.
        let (other, status, attr) = fs.open(root, CREATE | OPEN_EXCLUSIVE, b"temp");
        assert_eq!(status, Status::Ok);
        assert_ne!(attr.unwrap().id, id);
        fs.write_all(other, 0, b"another");
        assert_eq!(fs.read_all(reader), expected);

        // Not the first close, nor the second: the last.
        fs.send_close(writer);
        assert_eq!(fs.read_all(reader), expected);
        fs.world.close_handle(reader).unwrap();
        fs.step();
        assert_eq!(fs.read_all(again), expected);
        assert_eq!(fs.status(root, Body::Sync).0, Status::Ok);
        assert_eq!(u64::from(fs.counts().first_orphan), id);
        fs.send_close(again);
        assert_eq!(fs.status(root, Body::Sync).0, Status::Ok);
        let closed = fs.counts();
        assert_eq!(
            (closed.first_orphan, closed.free_inodes),
            (0, before.free_inodes - 1)
        );
        assert_eq!(fs.on_disk(b"temp").as_deref(), Some(&b"another"[..]));

        // The second file goes the same way, and everything is free again.
        assert_eq!(
            fs.status(root, Body::Unlink { name: b"temp" }).0,
            Status::Ok
        );
        assert_eq!(fs.read_all(other), b"another");
        fs.send_close(other);
        assert_eq!(fs.status(root, Body::Sync).0, Status::Ok);
        assert_eq!(fs.counts(), before);
        assert_eq!(fs.free_bytes(), free);
    }
}

#[test]
fn a_file_whose_handles_are_closed_is_freed_with_its_name() {
    // The control for the test above: with no handle left nothing is kept.
    let mut fs = journaled_fs(image_with_journal(1024));
    let root = fs.root;
    assert_eq!(fs.status(root, Body::Sync).0, Status::Ok);
    let before = fs.counts();
    let (file, status, _) = fs.open(root, CREATE, b"temp");
    assert_eq!(status, Status::Ok);
    fs.write_all(file, 0, &pattern(20_000));
    fs.send_close(file);
    assert_eq!(
        fs.status(root, Body::Unlink { name: b"temp" }).0,
        Status::Ok
    );
    assert_eq!(fs.status(root, Body::Sync).0, Status::Ok);
    assert_eq!(fs.counts(), before);
}

#[test]
fn a_start_frees_the_files_a_dead_server_left_unlinked() {
    let mut fs = journaled_fs(image_with_journal(1024));
    let root = fs.root;
    assert_eq!(fs.status(root, Body::Sync).0, Status::Ok);
    let before = fs.counts();
    let free = fs.free_bytes();
    let mut open = Vec::new();
    for name in [&b"one"[..], b"two", b"three"] {
        let (file, status, _) = fs.open(root, CREATE, name);
        assert_eq!(status, Status::Ok);
        fs.write_all(file, 0, &pattern(30_000));
        assert_eq!(fs.status(root, Body::Unlink { name }).0, Status::Ok);
        fs.write_all(file, 30_000, &pattern(5000));
        open.push(file);
    }
    assert_eq!(fs.status(root, Body::Sync).0, Status::Ok);
    // The server dies here with all three open: what the disk holds now is
    // what the next one finds.
    let crashed = fs.disk.borrow().image.clone();
    let left = counts_of(&crashed);
    assert_ne!(left.first_orphan, 0);
    assert_eq!(left.free_inodes, before.free_inodes - 3);
    assert!(left.free_blocks < before.free_blocks);

    let mut next = journaled_fs(crashed.clone());
    let root = next.root;
    assert_eq!(next.free_bytes(), free);
    assert_eq!(next.counts(), before);
    assert_eq!(next.list(root).len(), 2);
    // It takes changes, and holds unlinked files again.
    let (file, status, _) = next.open(root, CREATE, b"one");
    assert_eq!(status, Status::Ok);
    next.write_all(file, 0, b"new");
    assert_eq!(
        next.status(root, Body::Unlink { name: b"one" }).0,
        Status::Ok
    );
    assert_eq!(next.read_all(file), b"new");
    // Init retires the role with the file still open: nothing is left.
    next.server.retire(&mut next.world);
    let mut bytes = next.disk.borrow().image.clone();
    assert_eq!(
        wyrmroot_ext4::recover(&mut Image(&mut bytes), IMAGE_BYTES as u64),
        Ok(false)
    );
    assert_eq!(counts_of(&bytes), before);

    // A crash before the unlinks commit leaves the files named.
    let mut fs = journaled_fs(image_with_journal(1024));
    let root = fs.root;
    let (file, status, _) = fs.open(root, CREATE, b"named");
    assert_eq!(status, Status::Ok);
    fs.write_all(file, 0, &pattern(9000));
    assert_eq!(fs.status(root, Body::Sync).0, Status::Ok);
    assert_eq!(
        fs.status(root, Body::Unlink { name: b"named" }).0,
        Status::Ok
    );
    let crashed = fs.disk.borrow().image.clone();
    let mut next = journaled_fs(crashed);
    let root = next.root;
    let (named, status, _) = next.open(root, OPEN_READ, b"named");
    assert_eq!(status, Status::Ok);
    assert_eq!(next.read_all(named), pattern(9000));
}

/// Sets superblock word `at` of `image`, with the superblock's checksum.
fn patch_superblock(image: &mut [u8], at: usize, value: u32) {
    let sb = &mut image[1024..2048];
    sb[at..at + 4].copy_from_slice(&value.to_le_bytes());
    let sum = wyrmroot_ext4::crc::update(!0, &sb[..0x3FC]);
    sb[0x3FC..].copy_from_slice(&sum.to_le_bytes());
}

#[test]
fn a_volume_with_an_orphan_file_keeps_an_open_file_s_name() {
    let mut image = ext4_image();
    let compat = u32::from_le_bytes(image[1024 + 0x5C..1024 + 0x60].try_into().unwrap());
    patch_superblock(&mut image, 0x5C, compat | 0x1000);
    let mut fs = journaled_fs(image);
    let root = fs.root;
    let (etc, _, _) = fs.open(root, OPEN_READ | OPEN_WRITE, b"etc");
    let (motd, status, _) = fs.open(root, OPEN_READ, b"etc/motd");
    assert_eq!(status, Status::Ok);
    assert_eq!(
        fs.status(etc, Body::Unlink { name: b"motd" }).0,
        Status::Busy
    );
    assert_eq!(fs.on_disk(b"etc/motd").unwrap(), b"welcome\n");
    assert_eq!(fs.counts().first_orphan, 0);
    fs.send_close(motd);
    assert_eq!(fs.status(etc, Body::Unlink { name: b"motd" }).0, Status::Ok);
    assert_eq!(fs.on_disk(b"etc/motd"), None);
}

#[test]
fn an_orphan_list_that_cannot_be_processed_leaves_the_volume_read_only() {
    for journal_blocks in [0, 1024] {
        let mut image = image_with_journal(journal_blocks);
        let motd = {
            let mut device = Image(&mut image);
            let volume = Volume::mount(&mut device, IMAGE_BYTES as u64, false).unwrap();
            volume
                .resolve(&mut device, ROOT_INODE, b"etc/motd")
                .unwrap()
                .inode
        };
        // A listed inode that still has its name: not this role's to free.
        patch_superblock(&mut image, 0xE8, motd);
        let before = counts_of(&image);
        let mut fs = journaled_fs(image);
        let root = fs.root;
        assert_eq!(fs.open(root, CREATE, b"new").1, Status::ReadOnly);
        let (file, status, _) = fs.open(root, OPEN_READ, b"etc/motd");
        assert_eq!(status, Status::Ok);
        assert_eq!(fs.read_all(file), b"welcome\n");
        fs.server.retire(&mut fs.world);
        assert_eq!(fs.counts(), before);
    }
}

#[test]
fn freeing_an_unlinked_file_starts_with_what_is_pending_committed() {
    // Its blocks are freed in a transaction of their own, so the changes
    // of earlier requests cannot overflow with them (and be lost).
    let mut fs = journaled_fs(image_with_journal(1024));
    let root = fs.root;
    let (temp, status, attr) = fs.open(root, CREATE, b"temp");
    assert_eq!(status, Status::Ok);
    let id = attr.unwrap().id;
    fs.write_all(temp, 0, &pattern(20_000));
    assert_eq!(
        fs.status(root, Body::Unlink { name: b"temp" }).0,
        Status::Ok
    );
    assert_eq!(fs.status(root, Body::Sync).0, Status::Ok);
    let (later, status, _) = fs.open(root, CREATE, b"later");
    assert_eq!(status, Status::Ok);
    fs.write_all(later, 0, b"pending");
    assert_eq!(fs.on_disk(b"later"), None);

    fs.send_close(temp);
    // What was pending is on the disk; the free itself is the next commit.
    assert_eq!(fs.on_disk(b"later").as_deref(), Some(&b"pending"[..]));
    assert_eq!(u64::from(fs.counts().first_orphan), id);
    assert_eq!(fs.status(root, Body::Sync).0, Status::Ok);
    assert_eq!(fs.counts().first_orphan, 0);
}

/// Rewrites the flags of inode `number` in `image` (4 KiB blocks, one
/// group, 256-byte inodes, `metadata_csum`), with the inode's checksum.
fn patch_inode_flags(image: &mut [u8], number: u32, patch: impl FnOnce(u32) -> u32) {
    use wyrmroot_ext4::crc;
    let word = |bytes: &[u8], at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    let seed = crc::update(!0, &image[1024 + 0x68..1024 + 0x78]);
    let table = word(image, 4096 + 0x8) as usize;
    let at = table * 4096 + (number as usize - 1) * 256;
    let raw = &mut image[at..at + 256];
    let flags = patch(word(raw, 0x20));
    raw[0x20..0x24].copy_from_slice(&flags.to_le_bytes());
    let sum = crc::update(seed, &number.to_le_bytes());
    let sum = crc::update(sum, &raw[0x64..0x68]);
    let sum = crc::update(sum, &raw[..0x7C]);
    let sum = crc::update_zeros(sum, 2);
    let sum = crc::update(sum, &raw[0x7E..0x82]);
    let sum = crc::update_zeros(sum, 2);
    let sum = crc::update(sum, &raw[0x84..]);
    raw[0x7C..0x7E].copy_from_slice(&(sum as u16).to_le_bytes());
    raw[0x82..0x84].copy_from_slice(&((sum >> 16) as u16).to_le_bytes());
}

#[test]
fn a_file_this_role_cannot_free_is_not_supported_open_or_closed() {
    // A block-mapped file: UNLINK cannot free its blocks, so its name
    // stays, whether or not a handle is open (not BUSY: closing the handle
    // would not change the answer).
    let mut image = ext4_image();
    let motd = {
        let mut device = Image(&mut image);
        let volume = Volume::mount(&mut device, IMAGE_BYTES as u64, false).unwrap();
        volume
            .resolve(&mut device, ROOT_INODE, b"etc/motd")
            .unwrap()
            .inode
    };
    patch_inode_flags(&mut image, motd, |flags| flags & !0x80000);
    let mut fs = journaled_fs(image);
    let root = fs.root;
    let (etc, _, _) = fs.open(root, OPEN_READ | OPEN_WRITE, b"etc");
    let (file, status, attr) = fs.open(root, OPEN_READ, b"etc/motd");
    assert_eq!((status, attr.unwrap().size), (Status::Ok, 8));
    assert_eq!(
        fs.status(etc, Body::Unlink { name: b"motd" }).0,
        Status::NotSupported
    );
    fs.send_close(file);
    assert_eq!(
        fs.status(etc, Body::Unlink { name: b"motd" }).0,
        Status::NotSupported
    );
    assert_eq!(fs.list(etc), [(Kind::File, String::from("motd"))]);
    assert_eq!(fs.counts().first_orphan, 0);
    // The volume still takes changes.
    assert_eq!(fs.open(root, CREATE, b"new").1, Status::Ok);
}

/// Shortens the journal of `image` (4 KiB blocks, v3 checksums) to
/// `blocks`, found by its superblock's magic and block type.
fn shorten_journal(image: &mut [u8], blocks: u32) {
    use wyrmroot_ext4::crc;
    let at = (0..image.len())
        .step_by(4096)
        .find(|&at| image[at..at + 8] == [0xC0, 0x3B, 0x39, 0x98, 0, 0, 0, 4])
        .expect("a journal superblock");
    let sb = &mut image[at..at + 1024];
    sb[0x10..0x14].copy_from_slice(&blocks.to_be_bytes());
    let sum = crc::update(!0, &sb[..0xFC]);
    let sum = crc::update_zeros(sum, 4);
    let sum = crc::update(sum, &sb[0x100..]);
    sb[0xFC..0x100].copy_from_slice(&sum.to_be_bytes());
}

#[test]
fn a_journal_too_small_to_free_an_orphan_keeps_names_and_leaves_orphans() {
    // A transaction of this journal holds fewer blocks than one freeing
    // step may write, so no unlinked file could ever be freed.
    let mut image = image_with_journal(1024);
    shorten_journal(&mut image, 16);
    let mut fs = journaled_fs(image);
    let root = fs.root;
    let (etc, _, _) = fs.open(root, OPEN_READ | OPEN_WRITE, b"etc");
    let (motd, status, _) = fs.open(root, OPEN_READ, b"etc/motd");
    assert_eq!(status, Status::Ok);
    assert_eq!(
        fs.status(etc, Body::Unlink { name: b"motd" }).0,
        Status::Busy
    );
    assert_eq!(fs.status(root, Body::Sync).0, Status::Ok);
    assert_eq!(fs.on_disk(b"etc/motd").unwrap(), b"welcome\n");
    assert_eq!(fs.counts().first_orphan, 0);
    // Closed, it goes as any file does, and the volume still takes changes.
    fs.send_close(motd);
    assert_eq!(fs.status(etc, Body::Unlink { name: b"motd" }).0, Status::Ok);
    assert_eq!(fs.status(root, Body::Sync).0, Status::Ok);
    assert_eq!(fs.on_disk(b"etc/motd"), None);

    // An orphan list on such a volume: the role starts, the volume is
    // read-only, and the list is as it was found.
    let mut image = image_with_journal(1024);
    let orphan = {
        let mut device = Image(&mut image);
        let mut volume = Volume::mount(&mut device, IMAGE_BYTES as u64, true).unwrap();
        let stat = volume
            .resolve(&mut device, ROOT_INODE, b"etc/motd")
            .unwrap();
        let etc = volume.resolve(&mut device, ROOT_INODE, b"etc").unwrap();
        volume.unlink_held(&mut device, etc.inode, b"motd").unwrap();
        stat.inode
    };
    shorten_journal(&mut image, 16);
    let before = counts_of(&image);
    assert_eq!(before.first_orphan, orphan);
    let mut fs = journaled_fs(image);
    let root = fs.root;
    assert_eq!(fs.open(root, CREATE, b"new").1, Status::ReadOnly);
    assert_eq!(fs.list(root).len(), 2);
    fs.server.retire(&mut fs.world);
    assert_eq!(fs.counts(), before);
}

// ------------------------------------------------------------ versions (X1)

impl Fs {
    /// Sends `body` on `channel` in `minor`, with `extra` trailing bytes,
    /// and lets the server run once; its transaction.
    fn send_in_minor(
        &mut self,
        channel: DwHandle,
        body: Body<'_>,
        minor: u16,
        extra: &[u8],
        handles: &[DwHandle],
    ) -> u64 {
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
        bytes.truncate(size);
        bytes.extend_from_slice(extra);
        bytes[6..8].copy_from_slice(&minor.to_le_bytes());
        let total = bytes.len() as u32;
        bytes[12..16].copy_from_slice(&total.to_le_bytes());
        self.world.send(channel, &bytes, handles);
        self.step();
        self.transaction
    }
}

fn minor_of(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[6], bytes[7]])
}

#[test]
fn answers_follow_the_request_minor_even_when_a_lock_waits() {
    use wyrmroot_fs_proto::{MIN_MINOR, MINOR};
    let mut fs = fs();
    let root = fs.root;
    // A 1.3 OPEN is answered with a 1.3 ON_OPEN.
    let (waiter, far) = fs.world.pair();
    let open = Body::Open {
        flags: OPEN_READ,
        path: b"etc/motd",
        client: 0,
    };
    fs.send_in_minor(root, open, MIN_MINOR, &[], &[far]);
    let (reply, _) = fs.world.receive(waiter);
    assert_eq!(minor_of(&reply), MIN_MINOR);
    assert!(matches!(
        node::parse(&reply, 0).unwrap().body,
        Body::OnOpen {
            status: Status::Ok,
            ..
        }
    ));
    let (holder, _, _) = fs.open(root, OPEN_READ, b"etc/motd");
    let taken = fs.lock_send(holder, lock(0, 0, LockMode::Exclusive), 0);
    assert_eq!(fs.answer(holder, taken).0, Status::Ok);
    // A 1.3 LOCK that waits ...
    let waiting = fs.send_in_minor(
        waiter,
        Body::Lock {
            lock: lock(0, 1, LockMode::Shared),
            flags: LOCK_WAIT,
        },
        MIN_MINOR,
        &[],
        &[],
    );
    assert!(!fs.world.readable(waiter));
    // ... while a later request, trailing bytes and all, is refused in its
    // own minor ...
    let refused = fs.send_in_minor(waiter, Body::GetAttr, MINOR + 1, &[3; 16], &[]);
    let (reply, _) = fs.world.receive(waiter);
    assert_eq!(minor_of(&reply), MINOR);
    let message = node::parse(&reply, 0).unwrap();
    assert_eq!(message.transaction_id, refused);
    // ... is answered in 1.3 once granted.
    fs.world.close_handle(holder).unwrap();
    fs.step();
    let (reply, _) = fs.world.receive(waiter);
    assert_eq!(minor_of(&reply), MIN_MINOR);
    let message = node::parse(&reply, 0).unwrap();
    assert_eq!(message.transaction_id, waiting);
    assert_eq!(
        message.body,
        Body::Status {
            status: Status::Ok,
            value: 0
        }
    );
}

#[test]
fn ext4d_reports_its_version_with_locks() {
    use wyrmroot_fs_proto::Version;
    use wyrmroot_fs_proto::node::FEATURE_LOCKS;
    let mut fs = fs();
    let root = fs.root;
    let reply = fs.request(root, Body::QueryVersion);
    assert_eq!(
        node::parse(&reply, 0).unwrap().body,
        Body::Version(Version::current(FEATURE_LOCKS))
    );
}
