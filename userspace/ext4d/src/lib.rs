//! ext4d: the persistent root's ext4, read-write, served as WRFS (root
//! `STORAGE_PLAN.md` W7).
//!
//! Init stages it a registry client and the server end of its root
//! directory's Channel, whose client end init mounts in vfsd at `/`. ext4d
//! connects to `volume.root0`, attaches one buffer it keeps mapped, mounts
//! the volume with `wyrmroot-ext4` and serves the root and every node opened
//! beneath it. A volume that does not mount ends the role: its root Channel
//! closes, vfsd drops the mount, and `/` falls back to vfsd's own directory
//! with `/boot` beneath it.
//!
//! The buffer is a cache of [`LINES`] 4 KiB lines with write-through: every
//! write reaches the device before its request is answered, and SYNC flushes
//! the device. A handle's access is what it was opened with; writing,
//! creating, truncating and unlinking need WRITE. A node that is open
//! somewhere cannot be unlinked (BUSY), so no inode is freed under a handle.
//! A filesystem inconsistency or device error answers the one request with
//! IO_ERROR; a peer that breaks WRFS loses its own node.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;
#[cfg(any(test, feature = "native-ext4d"))]
use wyrmroot_loader as _;

use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_HANDLE_INVALID, DW_OBJECT_TYPE_CHANNEL, DW_SIGNAL_PEER_CLOSED,
    DW_SIGNAL_READABLE, DwHandle, DwReceivedHandleInfoV1, DwRights, DwSignals, DwWaitItemV1,
};
use wyrmroot_ext4::{DeviceError, Error as Ext4Error, Kind as Ext4Kind, ROOT_INODE, Stat, Volume};
use wyrmroot_fs_proto::node::{
    self, ACCESS_READ, ACCESS_WRITE, Attr, Body, EntryWriter, FS_DURABLE_SYNC, FS_HARD_LINKS,
    FS_READ_ONLY, FsInfo, Kind, MAX_DIRENT_BYTES, MAX_IO_BYTES,
};
use wyrmroot_fs_proto::{
    MAX_HANDLES, MAX_NAME_BYTES, OPEN_CREATE, OPEN_DIRECTORY, OPEN_EXCLUSIVE, OPEN_FILE,
    OPEN_MUTATING, OPEN_READ, OPEN_TRUNCATE, OPEN_WRITE, Status,
};
use wyrmroot_runtime::{MemoryPlatform, WYR0_I_SUPERVISION_POLICY};
use wyrmroot_service::block::BlockClient;
use wyrmroot_service::memory::{Mapper, View, create_buffer};
use wyrmroot_service::{
    Launch, OPEN_CHANNEL_RIGHTS, Registry, ServicePlatform, receive_stage, startup,
};
use wyrmroot_service_proto::roles::{EXT4D_ROLE_ID, ROOT_VOLUME, SLOT_FS_ROOT};

pub const FAILURE_BASE: u32 = 0xE470_0000;
/// Nodes open at once besides the root.
pub const MAX_NODES: usize = 32;
/// One cache line: the largest block size `wyrmroot-ext4` mounts.
pub const LINE_BYTES: u64 = 4096;
/// Cache lines in the attached buffer.
pub const LINES: usize = 16;
/// The attached buffer.
pub const BUFFER_BYTES: u64 = LINE_BYTES * LINES as u64;
/// How long the root volume may take to appear.
pub const VOLUME_TIMEOUT_NS: u64 = 60_000_000_000;
const LEND_TO_VOLUME: DwRights = wyrmroot_service::memory::LEND_RIGHTS;
const READABLE_OR_CLOSED: DwSignals = DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0);

pub trait Ext4Platform: ServicePlatform + MemoryPlatform {}
impl<P: ServicePlatform + MemoryPlatform + ?Sized> Ext4Platform for P {}

/// Which 4 KiB of the volume each line holds, and when it was last used.
#[derive(Clone, Copy, Default)]
struct Line {
    /// Line-sized chunk number; meaningful when `valid`.
    chunk: u64,
    valid: bool,
    used: u64,
}

#[derive(Clone, Copy, Default)]
struct Cache {
    lines: [Line; LINES],
    clock: u64,
}

/// The volume as `wyrmroot-ext4` sees it: byte access through the cache,
/// writing through to the device.
struct VolumeDevice<'a, P: ?Sized, V> {
    platform: &'a mut P,
    client: &'a mut BlockClient,
    view: &'a mut V,
    cache: &'a mut Cache,
}

impl<P: Ext4Platform + ?Sized, V: View> VolumeDevice<'_, P, V> {
    fn deadline(&mut self) -> Result<deepwyrm_syscall::DwDeadline, DeviceError> {
        self.platform
            .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .map_err(|_| DeviceError(1))
    }

    /// Device blocks per line, and how many of them chunk `chunk` has (the
    /// volume's last chunk may be short).
    fn chunk_blocks(&self, chunk: u64) -> Result<(u64, u32), DeviceError> {
        let size = u64::from(self.client.info.block_size);
        let per_line = LINE_BYTES / size;
        let first = chunk.checked_mul(per_line).ok_or(DeviceError(2))?;
        if first >= self.client.info.block_count {
            return Err(DeviceError(2));
        }
        let count = per_line.min(self.client.info.block_count - first);
        Ok((first, count as u32))
    }

    /// The line holding `chunk`, loaded unless `whole` (about to be
    /// overwritten entirely).
    fn line(&mut self, chunk: u64, whole: bool) -> Result<usize, DeviceError> {
        self.cache.clock += 1;
        let clock = self.cache.clock;
        if let Some(index) = self
            .cache
            .lines
            .iter()
            .position(|line| line.valid && line.chunk == chunk)
        {
            self.cache.lines[index].used = clock;
            return Ok(index);
        }
        let index = (0..LINES)
            .min_by_key(|&index| {
                let line = self.cache.lines[index];
                if line.valid { line.used } else { 0 }
            })
            .unwrap_or(0);
        self.cache.lines[index].valid = false;
        if !whole {
            let (lba, count) = self.chunk_blocks(chunk)?;
            let deadline = self.deadline()?;
            match self.client.read(
                self.platform,
                lba,
                count,
                index as u64 * LINE_BYTES,
                deadline,
            ) {
                Ok(wyrmroot_block_proto::Status::Ok) => {}
                Ok(status) => return Err(DeviceError(0x100 | status as u32)),
                Err(step) => return Err(DeviceError(step)),
            }
        }
        self.cache.lines[index] = Line {
            chunk,
            valid: true,
            used: clock,
        };
        Ok(index)
    }
}

impl<P: Ext4Platform + ?Sized, V: View> wyrmroot_ext4::Device for VolumeDevice<'_, P, V> {
    fn read(&mut self, offset: u64, out: &mut [u8]) -> Result<(), DeviceError> {
        let mut done = 0;
        while done < out.len() {
            let at = offset.checked_add(done as u64).ok_or(DeviceError(3))?;
            let chunk = at / LINE_BYTES;
            let within = at % LINE_BYTES;
            let take = ((LINE_BYTES - within) as usize).min(out.len() - done);
            let index = self.line(chunk, false)?;
            if !self.view.read(
                index as u64 * LINE_BYTES + within,
                &mut out[done..done + take],
            ) {
                return Err(DeviceError(4));
            }
            done += take;
        }
        Ok(())
    }

    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), DeviceError> {
        let size = u64::from(self.client.info.block_size);
        let mut done = 0;
        while done < data.len() {
            let at = offset.checked_add(done as u64).ok_or(DeviceError(3))?;
            let chunk = at / LINE_BYTES;
            let within = at % LINE_BYTES;
            let take = ((LINE_BYTES - within) as usize).min(data.len() - done);
            let (_, count) = self.chunk_blocks(chunk)?;
            let whole = within == 0 && take as u64 == u64::from(count) * size;
            let index = self.line(chunk, whole)?;
            let base = index as u64 * LINE_BYTES;
            if !self.view.write(base + within, &data[done..done + take]) {
                self.cache.lines[index].valid = false;
                return Err(DeviceError(5));
            }
            // Only the device blocks this write touched go out.
            let first = within / size;
            let last = (within + take as u64 - 1) / size;
            let (lba, _) = self.chunk_blocks(chunk)?;
            let deadline = self.deadline()?;
            let written = self.client.write(
                self.platform,
                lba + first,
                (last - first + 1) as u32,
                base + first * size,
                deadline,
            );
            if written != Ok(wyrmroot_block_proto::Status::Ok) {
                // What the device holds is unknown now.
                self.cache.lines[index].valid = false;
                return Err(match written {
                    Ok(status) => DeviceError(0x100 | status as u32),
                    Err(step) => DeviceError(step),
                });
            }
            done += take;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), DeviceError> {
        let deadline = self.deadline()?;
        match self.client.flush(self.platform, deadline) {
            Ok(wyrmroot_block_proto::Status::Ok) => Ok(()),
            Ok(status) => Err(DeviceError(0x100 | status as u32)),
            Err(step) => Err(DeviceError(step)),
        }
    }
}

#[derive(Clone, Copy)]
struct OpenNode {
    channel: DwHandle,
    inode: u32,
    access: u32,
}

pub struct Server<V> {
    launch: Launch,
    root: DwHandle,
    volume: Volume,
    client: BlockClient,
    view: V,
    cache: Cache,
    nodes: [Option<OpenNode>; MAX_NODES],
}

#[derive(Clone, Copy)]
enum Target {
    Control,
    Root,
    Node(usize),
}

/// Runs ext4d; returns its exit code (0 when init asks it to retire).
pub fn ext4d_main<P: Ext4Platform, M: Mapper<P>>(
    platform: &mut P,
    mapper: &mut M,
    bootstrap: DwHandle,
) -> u32 {
    let mut server = match Server::start(platform, mapper, bootstrap) {
        Ok(server) => server,
        Err(step) => return FAILURE_BASE | step,
    };
    loop {
        match server.step(platform, DW_DEADLINE_INFINITE) {
            Ok(true) => {}
            Ok(false) => return 0,
            Err(step) => return FAILURE_BASE | step,
        }
    }
}

fn status_of(error: Ext4Error) -> Status {
    match error {
        Ext4Error::NotFound => Status::NotFound,
        Ext4Error::NotDirectory => Status::NotDirectory,
        Ext4Error::IsDirectory => Status::IsDirectory,
        Ext4Error::Exists => Status::Exists,
        Ext4Error::NotEmpty => Status::NotEmpty,
        Ext4Error::NoSpace | Ext4Error::TooLarge => Status::NoSpace,
        Ext4Error::ReadOnly => Status::ReadOnly,
        Ext4Error::InvalidName => Status::InvalidPath,
        Ext4Error::Unsupported | Ext4Error::NotFileOrDirectory => Status::NotSupported,
        Ext4Error::Corrupt | Ext4Error::Device(_) | Ext4Error::NotExt4 => Status::IoError,
    }
}

impl<V: View> Server<V> {
    /// Starts the role, connects to the root volume and mounts it.
    pub fn start<P: Ext4Platform, M: Mapper<P, View = V>>(
        platform: &mut P,
        mapper: &mut M,
        bootstrap: DwHandle,
    ) -> Result<Self, u32> {
        let launch = startup(platform, bootstrap)?;
        if launch.role_id != EXT4D_ROLE_ID {
            return Err(6);
        }
        let deadline = platform
            .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .map_err(|_| 7u32)?;
        let staged = receive_stage(platform, &launch, deadline)?;
        let (Some((endpoint, identity)), None) = (staged.client, staged.publication) else {
            return Err(16);
        };
        let root = staged.slot(SLOT_FS_ROOT).ok_or(17u32)?.handle;
        if staged.channels().count() != 1 {
            return Err(17);
        }
        let mut registry = Registry::new(endpoint, identity);
        let deadline = platform
            .monotonic_deadline_after(VOLUME_TIMEOUT_NS)
            .map_err(|_| 80u32)?;
        let channel = registry.connect(platform, ROOT_VOLUME, deadline)?;
        let _ = platform.close_handle(endpoint);
        let deadline = platform
            .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .map_err(|_| 81u32)?;
        let mut client = BlockClient::open(platform, channel, deadline)?;
        let size = client.info.block_size;
        if size == 0 || !size.is_power_of_two() || u64::from(size) > LINE_BYTES {
            return Err(88);
        }
        let (keep, lend) = create_buffer(platform, BUFFER_BYTES).map_err(|_| 82u32)?;
        let mut view = mapper
            .map(platform, launch.self_root, keep, BUFFER_BYTES)
            .map_err(|_| 83u32)?;
        client.attach(platform, lend, LEND_TO_VOLUME, BUFFER_BYTES, deadline)?;
        let mut cache = Cache::default();
        let volume_bytes = client
            .info
            .block_count
            .checked_mul(u64::from(size))
            .ok_or(84u32)?;
        let read_only_device = client.info.flags & wyrmroot_block_proto::INFO_READ_ONLY != 0;
        let volume = Volume::mount(
            &mut VolumeDevice {
                platform: &mut *platform,
                client: &mut client,
                view: &mut view,
                cache: &mut cache,
            },
            volume_bytes,
            !read_only_device,
        )
        .map_err(|error| match error {
            Ext4Error::NotExt4 => 85u32,
            Ext4Error::Device(_) => 86,
            Ext4Error::Unsupported => 89,
            _ => 87,
        })?;
        Ok(Self {
            launch,
            root,
            volume,
            client,
            view,
            cache,
            nodes: [const { None }; MAX_NODES],
        })
    }

    /// Waits once and handles what woke it; `Ok(false)` once init asks the
    /// role to retire.
    pub fn step<P: Ext4Platform>(
        &mut self,
        platform: &mut P,
        deadline: deepwyrm_syscall::DwDeadline,
    ) -> Result<bool, u32> {
        let mut items = [DwWaitItemV1::default(); 2 + MAX_NODES];
        let mut targets = [Target::Control; 2 + MAX_NODES];
        items[0] = DwWaitItemV1 {
            handle: self.launch.control,
            signals: READABLE_OR_CLOSED,
        };
        let mut count = 1;
        if self.root != DW_HANDLE_INVALID {
            items[1] = DwWaitItemV1 {
                handle: self.root,
                signals: READABLE_OR_CLOSED,
            };
            targets[1] = Target::Root;
            count = 2;
        }
        for (slot, node) in self.nodes.iter().enumerate() {
            if let Some(node) = node {
                items[count] = DwWaitItemV1 {
                    handle: node.channel,
                    signals: READABLE_OR_CLOSED,
                };
                targets[count] = Target::Node(slot);
                count += 1;
            }
        }
        let observed = platform
            .wait_many(&items[..count], deadline)
            .map_err(|_| 100u32)?;
        let index = observed.index as usize;
        if index >= count {
            return Err(101);
        }
        let readable = observed.observed.0 & DW_SIGNAL_READABLE.0 != 0;
        match targets[index] {
            Target::Control if readable => return Err(102),
            Target::Control => return Ok(false),
            Target::Root => {
                let here = OpenNode {
                    channel: self.root,
                    inode: ROOT_INODE,
                    access: self.root_access(),
                };
                if !readable || !self.serve(platform, here) {
                    // Unmounted, or vfsd broke WRFS: no new path opens, but
                    // the open nodes keep working.
                    let _ = platform.close_handle(self.root);
                    self.root = DW_HANDLE_INVALID;
                }
            }
            Target::Node(slot) => {
                // The node stays in its slot while it is served, so an OPEN
                // through it cannot be given the same slot.
                let Some(node) = self.nodes[slot] else {
                    return Err(103);
                };
                if !readable || !self.serve(platform, node) {
                    self.nodes[slot] = None;
                    let _ = platform.close_handle(node.channel);
                }
            }
        }
        Ok(true)
    }

    fn root_access(&self) -> u32 {
        if self.volume.read_only() {
            ACCESS_READ
        } else {
            ACCESS_READ | ACCESS_WRITE
        }
    }

    fn device<'a, P: Ext4Platform>(
        platform: &'a mut P,
        client: &'a mut BlockClient,
        view: &'a mut V,
        cache: &'a mut Cache,
    ) -> VolumeDevice<'a, P, V> {
        VolumeDevice {
            platform,
            client,
            view,
            cache,
        }
    }

    fn attr(stat: Stat, access: u32) -> Attr {
        Attr {
            kind: match stat.kind {
                Ext4Kind::Directory => Kind::Directory,
                Ext4Kind::File => Kind::File,
            },
            access,
            size: stat.size,
            id: u64::from(stat.inode),
        }
    }

    /// Serves one WRFS request on the node `here`; `false` drops the node.
    fn serve<P: Ext4Platform>(&mut self, platform: &mut P, here: OpenNode) -> bool {
        let mut bytes = [0u8; node::MAX_BYTES];
        let mut handles = [DwReceivedHandleInfoV1::default(); MAX_HANDLES];
        let Ok(counts) = platform.receive_channel(here.channel, &mut bytes, &mut handles) else {
            return false;
        };
        let received = &handles[..counts.handles.min(MAX_HANDLES)];
        let message = node::parse(&bytes[..counts.bytes.min(bytes.len())], counts.handles)
            .ok()
            .filter(|message| message.body.is_request());
        let Some(message) = message else {
            for info in received {
                let _ = platform.close_handle(info.handle);
            }
            return false;
        };
        let transaction_id = message.transaction_id;
        let status = |status| Body::Status { status, value: 0 };
        let writable = here.access & ACCESS_WRITE != 0;
        let readable = here.access & ACCESS_READ != 0;
        let mut listing = [0u8; MAX_DIRENT_BYTES];
        let mut data = [0u8; MAX_IO_BYTES];
        let mut device = Self::device(platform, &mut self.client, &mut self.view, &mut self.cache);
        let reply = match message.body {
            Body::Open { flags, path } => {
                let server = received[0];
                if server.object_type != DW_OBJECT_TYPE_CHANNEL
                    || server.rights != OPEN_CHANNEL_RIGHTS
                    || server.reserved0 != 0
                    || server.reserved != [0; 2]
                {
                    let _ = platform.close_handle(server.handle);
                    return false;
                }
                self.open(platform, transaction_id, here, flags, path, server.handle);
                return true;
            }
            Body::GetAttr => match self.volume.stat(&mut device, here.inode) {
                Ok(stat) => Body::Attr(Self::attr(stat, here.access)),
                Err(error) => status(status_of(error)),
            },
            Body::ReadDir { cookie } if readable => {
                let mut writer = EntryWriter::new(&mut listing);
                let listed = self
                    .volume
                    .read_dir(&mut device, here.inode, cookie, |entry| {
                        let kind = match entry.kind {
                            Ext4Kind::Directory => Kind::Directory,
                            Ext4Kind::File => Kind::File,
                        };
                        // A name WRFS cannot carry is skipped, not a full page.
                        writer.push(kind, entry.name)
                            || wyrmroot_fs_proto::check_name(entry.name).is_err()
                    });
                let used = writer.entries().as_bytes().len();
                match listed {
                    Ok(next) => match node::Entries::new(&listing[..used]) {
                        Ok(entries) => Body::Dirents {
                            next_cookie: next.unwrap_or(0),
                            entries,
                        },
                        Err(_) => status(Status::IoError),
                    },
                    Err(error) => status(status_of(error)),
                }
            }
            Body::Read { offset, length } if readable => {
                let out = &mut data[..length as usize];
                match self.volume.read(&mut device, here.inode, offset, out) {
                    Ok(read) => Body::Data(&data[..read]),
                    Err(error) => status(status_of(error)),
                }
            }
            Body::Write { offset, data } if writable => {
                match self.volume.write(&mut device, here.inode, offset, data) {
                    Ok(written) => Body::Status {
                        status: Status::Ok,
                        value: written as u64,
                    },
                    Err(error) => status(status_of(error)),
                }
            }
            Body::Truncate { size } if writable => {
                status(match self.volume.truncate(&mut device, here.inode, size) {
                    Ok(()) => Status::Ok,
                    Err(error) => status_of(error),
                })
            }
            Body::Unlink { name } if writable => {
                let found = self.volume.lookup(&mut device, here.inode, name);
                status(match found {
                    Ok(stat) if is_open(&self.nodes, stat.inode) => Status::Busy,
                    Ok(_) => match self.volume.unlink(&mut device, here.inode, name) {
                        Ok(()) => Status::Ok,
                        Err(error) => status_of(error),
                    },
                    Err(error) => status_of(error),
                })
            }
            Body::ReadDir { .. } | Body::Read { .. } => status(Status::AccessDenied),
            Body::Write { .. } | Body::Truncate { .. } | Body::Unlink { .. } => {
                status(if self.volume.read_only() {
                    Status::ReadOnly
                } else {
                    Status::AccessDenied
                })
            }
            Body::Sync => status(match self.volume.sync(&mut device) {
                Ok(()) => Status::Ok,
                Err(error) => status_of(error),
            }),
            Body::QueryFilesystem => {
                let usage = self.volume.usage();
                let mut flags = FS_DURABLE_SYNC | FS_HARD_LINKS;
                if self.volume.read_only() {
                    flags |= FS_READ_ONLY;
                }
                Body::FsInfo(FsInfo {
                    flags,
                    name_max: MAX_NAME_BYTES as u32,
                    block_size: usage.block_size,
                    total_bytes: usage.blocks * u64::from(usage.block_size),
                    free_bytes: usage.free_blocks * u64::from(usage.block_size),
                })
            }
            _ => return false,
        };
        send(platform, here.channel, transaction_id, reply)
    }

    /// Resolves, and with OPEN_CREATE creates, `path` below `dir`.
    fn resolve_for_open<P: Ext4Platform>(
        &mut self,
        platform: &mut P,
        dir: OpenNode,
        flags: u32,
        path: &[u8],
    ) -> Result<Stat, Status> {
        // Access never grows (WRFS): reading below needs a readable handle.
        if flags & OPEN_READ != 0 && dir.access & ACCESS_READ == 0 {
            return Err(Status::AccessDenied);
        }
        if flags & OPEN_MUTATING != 0 {
            if self.volume.read_only() {
                return Err(Status::ReadOnly);
            }
            if dir.access & ACCESS_WRITE == 0 {
                return Err(Status::AccessDenied);
            }
        }
        let mut device = Self::device(platform, &mut self.client, &mut self.view, &mut self.cache);
        let found = if flags & OPEN_CREATE != 0 {
            let (parent_path, name) = match path.iter().rposition(|&byte| byte == b'/') {
                Some(at) => (&path[..at], &path[at + 1..]),
                None => (&path[..0], path),
            };
            let parent = self
                .volume
                .resolve(&mut device, dir.inode, parent_path)
                .map_err(status_of)?;
            if parent.kind != Ext4Kind::Directory {
                return Err(Status::NotDirectory);
            }
            match self.volume.lookup(&mut device, parent.inode, name) {
                Ok(_) if flags & OPEN_EXCLUSIVE != 0 => return Err(Status::Exists),
                Ok(stat) => stat,
                Err(Ext4Error::NotFound) => {
                    let kind = if flags & OPEN_DIRECTORY != 0 {
                        Ext4Kind::Directory
                    } else {
                        Ext4Kind::File
                    };
                    self.volume
                        .create(&mut device, parent.inode, name, kind)
                        .map_err(status_of)?
                }
                Err(error) => return Err(status_of(error)),
            }
        } else {
            self.volume
                .resolve(&mut device, dir.inode, path)
                .map_err(status_of)?
        };
        match found.kind {
            Ext4Kind::File if flags & OPEN_DIRECTORY != 0 => return Err(Status::NotDirectory),
            Ext4Kind::Directory if flags & OPEN_FILE != 0 => return Err(Status::IsDirectory),
            _ => {}
        }
        if flags & OPEN_TRUNCATE != 0 {
            self.volume
                .truncate(&mut device, found.inode, 0)
                .map_err(status_of)?;
            return Ok(Stat { size: 0, ..found });
        }
        Ok(found)
    }

    /// Opens `path` below `dir` onto `server`: a new node, or a failed
    /// ON_OPEN and the Channel's closure.
    fn open<P: Ext4Platform>(
        &mut self,
        platform: &mut P,
        transaction_id: u64,
        dir: OpenNode,
        flags: u32,
        path: &[u8],
        server: DwHandle,
    ) {
        let slot = self.nodes.iter().position(Option::is_none);
        let found = match slot {
            Some(_) => self.resolve_for_open(platform, dir, flags, path),
            None => Err(Status::NoResources),
        };
        let access = (if flags & OPEN_READ != 0 {
            ACCESS_READ
        } else {
            0
        }) | (if flags & OPEN_WRITE != 0 {
            ACCESS_WRITE
        } else {
            0
        });
        let (status, attr) = match found {
            Ok(stat) => (Status::Ok, Some(Self::attr(stat, access))),
            Err(status) => (status, None),
        };
        let sent = send(
            platform,
            server,
            transaction_id,
            Body::OnOpen { status, attr },
        );
        match (found, slot) {
            (Ok(stat), Some(slot)) if sent => {
                self.nodes[slot] = Some(OpenNode {
                    channel: server,
                    inode: stat.inode,
                    access,
                });
            }
            _ => {
                let _ = platform.close_handle(server);
            }
        }
    }
}

/// Whether some handle, the root included, has `inode` open.
fn is_open(nodes: &[Option<OpenNode>], inode: u32) -> bool {
    inode == ROOT_INODE || nodes.iter().flatten().any(|node| node.inode == inode)
}

fn send<P: Ext4Platform>(
    platform: &mut P,
    channel: DwHandle,
    transaction_id: u64,
    body: Body<'_>,
) -> bool {
    let mut bytes = [0u8; node::MAX_BYTES];
    node::encode(
        &node::Message {
            transaction_id,
            body,
        },
        &mut bytes,
    )
    .is_ok_and(|size| platform.send_channel(channel, &bytes[..size], &[]).is_ok())
}

#[cfg(test)]
mod tests;
