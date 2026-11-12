//! fat32d: the boot volume's FAT32, read-only, served as WRFS (root
//! `STORAGE_PLAN.md` W6).
//!
//! Init stages it a registry client and the server end of its root
//! directory's Channel, whose client end init mounts in vfsd at `/boot`.
//! fat32d connects to `volume.boot0`, attaches one buffer it keeps mapped,
//! mounts the volume with `wyrmroot-fat` and serves the root and every node
//! opened beneath it.
//!
//! Reads go through a one-window block cache in the attached buffer, so a
//! file read sequentially costs one device request per window. Every
//! mutation (WRITE, TRUNCATE, UNLINK, and opens with WRITE, CREATE or
//! TRUNCATE) is refused with READ_ONLY. A FAT inconsistency or device error
//! answers the one request with IO_ERROR; a peer that breaks WRFS loses its
//! own node. Opened nodes outlive the root: unmounting stops new path opens
//! only.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;
#[cfg(any(test, feature = "native-fat32d"))]
use wyrmroot_loader as _;

use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_HANDLE_INVALID, DW_OBJECT_TYPE_CHANNEL, DW_SIGNAL_PEER_CLOSED,
    DW_SIGNAL_READABLE, DwHandle, DwReceivedHandleInfoV1, DwRights, DwSignals, DwWaitItemV1,
};
use wyrmroot_fat::{Cursor, DeviceError, Disk, Error as FatError, Kind as FatKind, Node, Volume};
use wyrmroot_fs_proto::node::{
    self, ACCESS_READ, Attr, Body, EntryWriter, FS_READ_ONLY, FsInfo, Kind, MAX_DIRENT_BYTES,
    MAX_IO_BYTES,
};
use wyrmroot_fs_proto::{
    MAX_HANDLES, MAX_NAME_BYTES, OPEN_DIRECTORY, OPEN_FILE, OPEN_MUTATING, Status,
};
use wyrmroot_runtime::{MemoryPlatform, WYR0_I_SUPERVISION_POLICY};
use wyrmroot_service::block::BlockClient;
use wyrmroot_service::memory::{Mapper, View, create_buffer};
use wyrmroot_service::{
    Launch, OPEN_CHANNEL_RIGHTS, Registry, ServicePlatform, receive_stage, startup,
};
use wyrmroot_service_proto::roles::{BOOT_VOLUME, FAT32D_ROLE_ID, SLOT_FS_ROOT};

pub const FAILURE_BASE: u32 = 0xFA70_0000;
/// Nodes open at once besides the root.
pub const MAX_NODES: usize = 32;
/// The attached buffer, which is also the read cache's window.
pub const BUFFER_BYTES: u64 = 32 * 1024;
/// How long the boot volume may take to appear.
pub const VOLUME_TIMEOUT_NS: u64 = 60_000_000_000;
const LEND_TO_VOLUME: DwRights = wyrmroot_service::memory::LEND_RIGHTS;
const READABLE_OR_CLOSED: DwSignals = DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0);

pub trait Fat32Platform: ServicePlatform + MemoryPlatform {}
impl<P: ServicePlatform + MemoryPlatform + ?Sized> Fat32Platform for P {}

/// Which device blocks each half of the buffer holds. Two windows keep the
/// FAT and a file's data from evicting each other on every cluster.
#[derive(Clone, Copy, Default)]
struct Cache {
    windows: [Window; WINDOWS],
    /// The window used most recently.
    recent: usize,
}

#[derive(Clone, Copy, Default)]
struct Window {
    first: u64,
    blocks: u64,
}

const WINDOWS: usize = 2;
const WINDOW_BYTES: u64 = BUFFER_BYTES / WINDOWS as u64;

/// The FAT reader's view of the volume: byte reads through the cache.
struct VolumeDisk<'a, P: ?Sized, V> {
    platform: &'a mut P,
    client: &'a mut BlockClient,
    view: &'a V,
    cache: &'a mut Cache,
}

impl<P: Fat32Platform + ?Sized, V: View> Disk for VolumeDisk<'_, P, V> {
    fn read(&mut self, offset: u64, out: &mut [u8]) -> Result<(), DeviceError> {
        if out.is_empty() {
            return Ok(());
        }
        let size = u64::from(self.client.info.block_size);
        let end = offset.checked_add(out.len() as u64).ok_or(DeviceError(1))?;
        let first = offset / size;
        let last = (end - 1) / size;
        if last >= self.client.info.block_count {
            return Err(DeviceError(2));
        }
        let hit = self.cache.windows.iter().position(|window| {
            window.blocks != 0 && first >= window.first && last < window.first + window.blocks
        });
        let index = match hit {
            Some(index) => index,
            None => {
                let index = (self.cache.recent + 1) % WINDOWS;
                let blocks = (WINDOW_BYTES / size)
                    .min(u64::from(self.client.info.max_transfer_blocks))
                    .min(self.client.info.block_count - first);
                if last - first + 1 > blocks {
                    return Err(DeviceError(3));
                }
                self.cache.windows[index] = Window::default();
                let deadline = self
                    .platform
                    .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
                    .map_err(|_| DeviceError(4))?;
                let buffer_offset = index as u64 * WINDOW_BYTES;
                match self
                    .client
                    .read(self.platform, first, blocks as u32, buffer_offset, deadline)
                {
                    Ok(wyrmroot_block_proto::Status::Ok) => {}
                    Ok(status) => return Err(DeviceError(0x100 | status as u32)),
                    Err(step) => return Err(DeviceError(step)),
                }
                self.cache.windows[index] = Window { first, blocks };
                index
            }
        };
        self.cache.recent = index;
        let window = self.cache.windows[index];
        let at = index as u64 * WINDOW_BYTES + (offset - window.first * size);
        if self.view.read(at, out) {
            Ok(())
        } else {
            Err(DeviceError(5))
        }
    }
}

#[derive(Clone, Copy)]
struct OpenNode {
    channel: DwHandle,
    cursor: Cursor,
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

/// Runs fat32d; returns its exit code (0 when init asks it to retire).
pub fn fat32d_main<P: Fat32Platform, M: Mapper<P>>(
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

impl<V: View> Server<V> {
    /// Starts the role, connects to the boot volume and mounts it.
    pub fn start<P: Fat32Platform, M: Mapper<P, View = V>>(
        platform: &mut P,
        mapper: &mut M,
        bootstrap: DwHandle,
    ) -> Result<Self, u32> {
        let launch = startup(platform, bootstrap)?;
        if launch.role_id != FAT32D_ROLE_ID {
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
        let channel = registry.connect(platform, BOOT_VOLUME, deadline)?;
        // The registry is not needed again.
        let _ = platform.close_handle(endpoint);
        let deadline = platform
            .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .map_err(|_| 81u32)?;
        let mut client = BlockClient::open(platform, channel, deadline)?;
        let (keep, lend) = create_buffer(platform, BUFFER_BYTES).map_err(|_| 82u32)?;
        let view = mapper
            .map(platform, launch.self_root, keep, BUFFER_BYTES)
            .map_err(|_| 83u32)?;
        // The volume service moves the lent handle on to the device.
        client.attach(platform, lend, LEND_TO_VOLUME, BUFFER_BYTES, deadline)?;
        let mut cache = Cache::default();
        let volume_bytes = client
            .info
            .block_count
            .checked_mul(u64::from(client.info.block_size))
            .ok_or(84u32)?;
        let volume = Volume::mount(
            &mut VolumeDisk {
                platform: &mut *platform,
                client: &mut client,
                view: &view,
                cache: &mut cache,
            },
            Some(volume_bytes),
        )
        .map_err(|error| match error {
            FatError::NotFat32 => 85u32,
            FatError::Device(_) => 86,
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
    pub fn step<P: Fat32Platform>(
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
                let root = self.volume.root();
                let mut cursor = Cursor::new(root);
                if !readable || !self.serve(platform, self.root, &mut cursor) {
                    // Unmounted, or vfsd broke WRFS: no new path opens, but
                    // the open nodes keep working.
                    let _ = platform.close_handle(self.root);
                    self.root = DW_HANDLE_INVALID;
                }
            }
            Target::Node(slot) => {
                // The node stays in its slot while it is served, so an OPEN
                // through it cannot be given the same slot.
                let Some(OpenNode {
                    channel,
                    mut cursor,
                }) = self.nodes[slot]
                else {
                    return Err(103);
                };
                if readable && self.serve(platform, channel, &mut cursor) {
                    if let Some(node) = self.nodes[slot].as_mut() {
                        node.cursor = cursor;
                    }
                } else {
                    self.nodes[slot] = None;
                    let _ = platform.close_handle(channel);
                }
            }
        }
        Ok(true)
    }

    fn disk<'a, P: Fat32Platform>(
        platform: &'a mut P,
        client: &'a mut BlockClient,
        view: &'a V,
        cache: &'a mut Cache,
    ) -> VolumeDisk<'a, P, V> {
        VolumeDisk {
            platform,
            client,
            view,
            cache,
        }
    }

    fn attr(node: Node) -> Attr {
        Attr {
            kind: match node.kind {
                FatKind::Directory => Kind::Directory,
                FatKind::File => Kind::File,
            },
            access: ACCESS_READ,
            size: u64::from(node.size),
            id: u64::from(node.first_cluster),
            filesystem: 0,
        }
    }

    /// Serves one WRFS request on `channel` for the node under `cursor`;
    /// `false` drops the node.
    fn serve<P: Fat32Platform>(
        &mut self,
        platform: &mut P,
        channel: DwHandle,
        cursor: &mut Cursor,
    ) -> bool {
        let mut bytes = [0u8; node::MAX_BYTES];
        let mut handles = [DwReceivedHandleInfoV1::default(); MAX_HANDLES];
        let Ok(counts) = platform.receive_channel(channel, &mut bytes, &mut handles) else {
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
        let here = cursor.node();
        let status = |status| Body::Status { status, value: 0 };
        let mut listing = [0u8; MAX_DIRENT_BYTES];
        let mut data = [0u8; MAX_IO_BYTES];
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
            Body::GetAttr => Body::Attr(Self::attr(here)),
            Body::ReadDir { cookie } => match self.list(platform, here, cookie, &mut listing) {
                Ok((next_cookie, used)) => match node::Entries::new(&listing[..used]) {
                    Ok(entries) => Body::Dirents {
                        next_cookie,
                        entries,
                    },
                    Err(_) => status(Status::IoError),
                },
                Err(error) => status(error),
            },
            Body::Read { offset, length } => {
                let out = &mut data[..length as usize];
                let read = self.volume.read(
                    &mut Self::disk(platform, &mut self.client, &self.view, &mut self.cache),
                    cursor,
                    offset,
                    out,
                );
                match read {
                    Ok(read) => Body::Data(&data[..read]),
                    Err(FatError::NotFile) => status(Status::IsDirectory),
                    Err(_) => status(Status::IoError),
                }
            }
            Body::Write { .. } | Body::Truncate { .. } | Body::Unlink { .. } => {
                status(Status::ReadOnly)
            }
            Body::Sync => status(Status::Ok),
            // FAT has no stable file identity to hang a lock on (an empty
            // file has no cluster), and this volume never changes.
            Body::Lock(_) | Body::TestLock(_) => status(Status::NotSupported),
            Body::QueryFilesystem => Body::FsInfo(FsInfo {
                flags: FS_READ_ONLY,
                name_max: MAX_NAME_BYTES as u32,
                block_size: self.volume.bytes_per_sector(),
                total_bytes: self.volume.total_bytes(),
                free_bytes: 0,
            }),
            _ => return false,
        };
        send(platform, channel, transaction_id, reply)
    }

    /// One page of directory `dir` from `cookie`: (next cookie, bytes).
    fn list<P: Fat32Platform>(
        &mut self,
        platform: &mut P,
        dir: Node,
        cookie: u64,
        out: &mut [u8],
    ) -> Result<(u64, usize), Status> {
        if dir.kind != FatKind::Directory {
            return Err(Status::NotDirectory);
        }
        let start = u32::try_from(cookie).map_err(|_| Status::Invalid)?;
        let mut writer = EntryWriter::new(out);
        let next = self
            .volume
            .read_dir(
                &mut Self::disk(platform, &mut self.client, &self.view, &mut self.cache),
                dir,
                start,
                |entry| {
                    let kind = match entry.node.kind {
                        FatKind::Directory => Kind::Directory,
                        FatKind::File => Kind::File,
                    };
                    // A name WRFS cannot carry is skipped, not a full page.
                    writer.push(kind, entry.name)
                        || wyrmroot_fs_proto::check_name(entry.name).is_err()
                },
            )
            .map_err(|_| Status::IoError)?;
        let used = writer.entries().as_bytes().len();
        Ok((u64::from(next.unwrap_or(0)), used))
    }

    /// Opens `path` below `dir` onto `server`: a new node, or a failed
    /// ON_OPEN and the Channel's closure.
    fn open<P: Fat32Platform>(
        &mut self,
        platform: &mut P,
        transaction_id: u64,
        dir: Node,
        flags: u32,
        path: &[u8],
        server: DwHandle,
    ) {
        let found = if flags & OPEN_MUTATING != 0 {
            Err(Status::ReadOnly)
        } else {
            self.volume
                .resolve(
                    &mut Self::disk(platform, &mut self.client, &self.view, &mut self.cache),
                    dir,
                    path,
                )
                .map_err(|error| match error {
                    FatError::NotFound => Status::NotFound,
                    FatError::NotDirectory => Status::NotDirectory,
                    _ => Status::IoError,
                })
                .and_then(|node| match node.kind {
                    FatKind::File if flags & OPEN_DIRECTORY != 0 => Err(Status::NotDirectory),
                    FatKind::Directory if flags & OPEN_FILE != 0 => Err(Status::IsDirectory),
                    _ => Ok(node),
                })
        };
        let slot = self.nodes.iter().position(Option::is_none);
        let (status, attr) = match (found, slot) {
            (Ok(node), Some(_)) => (Status::Ok, Some(Self::attr(node))),
            (Ok(_), None) => (Status::NoResources, None),
            (Err(status), _) => (status, None),
        };
        let sent = send(
            platform,
            server,
            transaction_id,
            Body::OnOpen { status, attr },
        );
        match (found, slot) {
            (Ok(node), Some(slot)) if sent => {
                self.nodes[slot] = Some(OpenNode {
                    channel: server,
                    cursor: Cursor::new(node),
                });
            }
            _ => {
                let _ = platform.close_handle(server);
            }
        }
    }
}

fn send<P: Fat32Platform>(
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
