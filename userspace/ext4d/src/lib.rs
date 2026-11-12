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
//! The buffer is a cache of [`LINES`] 4 KiB lines with write-through. A
//! volume with a journal is replayed before it mounts and then journaled
//! (`wyrmroot_ext4::journal`, `data=ordered`): file data is written before
//! its request is answered, and metadata collects in a transaction of up to
//! [`TRANSACTION_SLOTS`] blocks in a second buffer, committed on SYNC, once
//! it is half full, [`COMMIT_INTERVAL_NS`] after its first change, and when
//! the role retires. A crash loses at most the uncommitted transaction.
//! Space freed in the running transaction is reused only after it commits,
//! so a write, create or truncate that runs out of space commits and tries
//! once more. An
//! operation that would overflow the transaction, or a failed commit, turns
//! the volume read-only with the last commit on disk. Without a journal
//! every write reaches the device before its request is answered, and SYNC
//! flushes the device. A handle's access is what it was opened with; writing,
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
    DW_DEADLINE_INFINITE, DW_DEADLINE_NOW, DW_HANDLE_INVALID, DW_OBJECT_TYPE_CHANNEL,
    DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DW_STATUS_TIMED_OUT, DwDeadline, DwHandle,
    DwReceivedHandleInfoV1, DwRights, DwSignals, DwWaitItemV1,
};
use wyrmroot_ext4::journal::TRANSACTION_FULL;
use wyrmroot_ext4::{
    DeviceError, Error as Ext4Error, Journal, Journaled, Kind as Ext4Kind, ROOT_INODE, Stat, Store,
    Transaction, Volume,
};
use wyrmroot_fs_lock::{LockServer, Outcome};
use wyrmroot_fs_proto::node::{
    self, ACCESS_READ, ACCESS_WRITE, Attr, Body, EntryWriter, FS_DURABLE_SYNC, FS_HARD_LINKS,
    FS_READ_ONLY, FsInfo, Kind, MAX_DIRENT_BYTES, MAX_IO_BYTES,
};
use wyrmroot_fs_proto::{
    MAX_HANDLES, MAX_NAME_BYTES, OPEN_CREATE, OPEN_DIRECTORY, OPEN_EXCLUSIVE, OPEN_FILE,
    OPEN_MUTATING, OPEN_READ, OPEN_TRUNCATE, OPEN_WRITE, Status,
};
use wyrmroot_runtime::{MemoryPlatform, NativeError, WYR0_I_SUPERVISION_POLICY};
use wyrmroot_service::block::BlockClient;
use wyrmroot_service::memory::{Mapper, View, create_buffer};
use wyrmroot_service::{
    Launch, OPEN_CHANNEL_RIGHTS, Registry, ServicePlatform, receive_stage, startup,
};
use wyrmroot_service_proto::roles::{EXT4D_ROLE_ID, ROOT_VOLUME, SLOT_FS_ROOT};

pub const FAILURE_BASE: u32 = 0xE470_0000;
/// Nodes open at once besides the root.
pub const MAX_NODES: usize = 32;
/// The most advisory locks one Channel holds (WRFS 1.1).
pub const LOCKS_PER_NODE: usize = 8;
/// Room for every node and the root at their limit, so no client can fill
/// the table for the others (W10 review D1).
pub const MAX_LOCKS: usize = (MAX_NODES + 1) * LOCKS_PER_NODE;
/// One cache line: the largest block size `wyrmroot-ext4` mounts.
pub const LINE_BYTES: u64 = 4096;
/// Cache lines in the attached buffer.
pub const LINES: usize = 16;
/// The attached buffer.
pub const BUFFER_BYTES: u64 = LINE_BYTES * LINES as u64;
/// Journal transaction blocks held in memory.
pub const TRANSACTION_SLOTS: usize = 256;
/// The transaction's buffer.
pub const TRANSACTION_BYTES: u64 = LINE_BYTES * TRANSACTION_SLOTS as u64;
/// How long a change may wait for its commit.
pub const COMMIT_INTERVAL_NS: u64 = 5_000_000_000;
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

/// The transaction's blocks, in a mapped buffer.
pub struct ViewStore<V>(V);

impl<V: View> Store for ViewStore<V> {
    fn load(&mut self, offset: usize, out: &mut [u8]) -> bool {
        self.0.read(offset as u64, out)
    }
    fn save(&mut self, offset: usize, data: &[u8]) -> bool {
        self.0.write(offset as u64, data)
    }
}

type Running<V> = Transaction<ViewStore<V>, TRANSACTION_SLOTS>;

/// What requests see: the volume, through the running transaction when it
/// is journaled. A write that overflows the transaction sets `full`.
struct ServerDevice<'a, P: ?Sized, V> {
    volume: VolumeDevice<'a, P, V>,
    transaction: Option<&'a mut Running<V>>,
    full: &'a mut bool,
}

impl<P: Ext4Platform + ?Sized, V: View> ServerDevice<'_, P, V> {
    fn noting<T>(&mut self, result: Result<T, DeviceError>) -> Result<T, DeviceError> {
        if result.as_ref().err() == Some(&TRANSACTION_FULL) {
            *self.full = true;
        }
        result
    }
}

impl<P: Ext4Platform + ?Sized, V: View> wyrmroot_ext4::Device for ServerDevice<'_, P, V> {
    fn read(&mut self, offset: u64, out: &mut [u8]) -> Result<(), DeviceError> {
        match self.transaction.as_deref_mut() {
            Some(transaction) => Journaled {
                device: &mut self.volume,
                transaction,
            }
            .read(offset, out),
            None => self.volume.read(offset, out),
        }
    }
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), DeviceError> {
        let result = match self.transaction.as_deref_mut() {
            Some(transaction) => Journaled {
                device: &mut self.volume,
                transaction,
            }
            .write(offset, data),
            None => self.volume.write(offset, data),
        };
        self.noting(result)
    }
    fn write_data(&mut self, offset: u64, data: &[u8]) -> Result<(), DeviceError> {
        let result = match self.transaction.as_deref_mut() {
            Some(transaction) => Journaled {
                device: &mut self.volume,
                transaction,
            }
            .write_data(offset, data),
            None => self.volume.write(offset, data),
        };
        self.noting(result)
    }
    fn read_committed(&mut self, offset: u64, out: &mut [u8]) -> Result<(), DeviceError> {
        self.volume.read(offset, out)
    }
    fn flush(&mut self) -> Result<(), DeviceError> {
        self.volume.flush()
    }
}

#[derive(Clone, Copy)]
struct OpenNode {
    channel: DwHandle,
    inode: u32,
    access: u32,
    /// The `vfsd` client connection it was opened through, or 0 (WRFS 1.2).
    client: u64,
}

impl OpenNode {
    /// Whose waits this node's locks belong to when deadlocks are looked
    /// for: its client, or the node alone when it has none.
    fn lock_group(&self) -> u64 {
        if self.client != 0 {
            self.client
        } else {
            (1 << 63) | self.channel.0
        }
    }
}

pub struct Server<V> {
    launch: Launch,
    root: DwHandle,
    volume: Volume,
    client: BlockClient,
    view: V,
    cache: Cache,
    nodes: [Option<OpenNode>; MAX_NODES],
    journal: Option<(Journal, Running<V>)>,
    /// When the running transaction must commit, in monotonic nanoseconds.
    commit_due: Option<u64>,
    full: bool,
    /// A commit failed: no more are tried, and SYNC fails (W11 review R4).
    failed: bool,
    /// Advisory locks, owned by the Channel each was taken on (W10).
    locks: LockServer<MAX_LOCKS, { MAX_NODES + 1 }>,
    /// The filesystem identity every Attr carries, from the volume's UUID.
    filesystem: u64,
}

/// A nonzero filesystem identity folded from a volume UUID.
fn filesystem_identity(uuid: [u8; 16]) -> u64 {
    let (high, low) = uuid.split_at(8);
    let folded = u64::from_le_bytes(high.try_into().unwrap_or([0; 8]))
        ^ u64::from_le_bytes(low.try_into().unwrap_or([0; 8]));
    folded.max(1)
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
            Ok(false) => {
                server.retire(platform);
                return 0;
            }
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
        let mut device = VolumeDevice {
            platform: &mut *platform,
            client: &mut client,
            view: &mut view,
            cache: &mut cache,
        };
        let mount_error = |error| match error {
            Ext4Error::NotExt4 => 85u32,
            Ext4Error::Device(_) => 86,
            Ext4Error::Unsupported => 89,
            _ => 87,
        };
        if !read_only_device {
            wyrmroot_ext4::recover(&mut device, volume_bytes).map_err(mount_error)?;
        }
        let mut volume =
            Volume::mount(&mut device, volume_bytes, !read_only_device).map_err(mount_error)?;
        let journal = match Journal::open(&mut volume, &mut device) {
            Ok(journal) => journal,
            Err(Ext4Error::Unsupported) => {
                // A journal this role cannot write: the volume stays as it is.
                volume.set_read_only();
                None
            }
            Err(error) => return Err(mount_error(error)),
        };
        let journal = match journal {
            Some(journal) => {
                let (keep, lend) = create_buffer(platform, TRANSACTION_BYTES).map_err(|_| 90u32)?;
                let _ = platform.close_handle(lend);
                let store = mapper
                    .map(platform, launch.self_root, keep, TRANSACTION_BYTES)
                    .map_err(|_| 91u32)?;
                let transaction = Transaction::new(ViewStore(store), &journal);
                Some((journal, transaction))
            }
            None => None,
        };
        let filesystem = filesystem_identity(volume.uuid());
        Ok(Self {
            launch,
            root,
            volume,
            client,
            view,
            cache,
            nodes: [const { None }; MAX_NODES],
            journal,
            commit_due: None,
            full: false,
            failed: false,
            locks: LockServer::with_owner_limit(LOCKS_PER_NODE),
            filesystem,
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
        let now = platform.monotonic_active_now().map_err(|_| 104u32)?;
        if self.commit_due.is_some_and(|due| due <= now) {
            let _ = self.commit(platform);
        }
        let deadline = match self.commit_due {
            Some(due) if due < deadline.0 => DwDeadline(due),
            _ => deadline,
        };
        let observed = match platform.wait_many(&items[..count], deadline) {
            Ok(observed) => observed,
            Err(NativeError::Status(status))
                if status == DW_STATUS_TIMED_OUT && self.commit_due.is_some() =>
            {
                let _ = self.commit(platform);
                return Ok(true);
            }
            Err(_) => return Err(100),
        };
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
                    client: 0,
                };
                if !readable || !self.serve(platform, here) {
                    // Unmounted, or vfsd broke WRFS: no new path opens, but
                    // the open nodes keep working.
                    self.locks.release(self.root.0);
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
                    // A closed node releases its locks, so a job that ends
                    // releases all of its own.
                    self.nodes[slot] = None;
                    self.locks.release(node.channel.0);
                    let _ = platform.close_handle(node.channel);
                }
            }
        }
        // Whatever was served or closed may have released a lock.
        self.grant_waiters(platform);
        Ok(true)
    }

    /// Answers every waiting LOCK that can now be granted.
    fn grant_waiters<P: Ext4Platform>(&mut self, platform: &mut P) {
        while let Some((owner, transaction_id, outcome)) = self.locks.take_granted() {
            let channel = DwHandle(owner);
            if send(platform, channel, transaction_id, lock_reply(outcome)) {
                continue;
            }
            // A Channel that cannot be answered is dropped, as a failed
            // reply drops it in `serve`, with what it was just granted.
            self.locks.release(owner);
            if channel == self.root {
                let _ = platform.close_handle(self.root);
                self.root = DW_HANDLE_INVALID;
            } else if let Some(slot) = self
                .nodes
                .iter()
                .position(|node| node.is_some_and(|node| node.channel == channel))
            {
                self.nodes[slot] = None;
                let _ = platform.close_handle(channel);
            }
        }
    }

    /// Drops the nodes, other than `serving`, whose client closed its end
    /// and left nothing to read, releasing their locks. A client's close
    /// completes before it can send anything else, so a request that
    /// follows a close (UNLINK of a file just closed, a lock a close just
    /// released) sees it, however this server has ordered its wakeups.
    fn reap_closed<P: Ext4Platform>(&mut self, platform: &mut P, serving: DwHandle) {
        for slot in &mut self.nodes {
            let Some(node) = *slot else {
                continue;
            };
            if node.channel == serving {
                continue;
            }
            let closed = platform
                .wait_one(node.channel, READABLE_OR_CLOSED, DW_DEADLINE_NOW)
                .is_ok_and(|result| {
                    result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0
                        && result.observed.0 & DW_SIGNAL_READABLE.0 == 0
                });
            if closed {
                *slot = None;
                self.locks.release(node.channel.0);
                let _ = platform.close_handle(node.channel);
            }
        }
    }

    /// Commits the running transaction (or flushes an unjournaled volume).
    /// A failed commit leaves the volume read-only.
    fn commit<P: Ext4Platform>(&mut self, platform: &mut P) -> Result<(), Ext4Error> {
        let mut device = VolumeDevice {
            platform,
            client: &mut self.client,
            view: &mut self.view,
            cache: &mut self.cache,
        };
        self.commit_due = None;
        if self.failed {
            return Err(Ext4Error::Corrupt);
        }
        let result = match self.journal.as_mut() {
            Some((journal, transaction)) => journal.commit(&self.volume, &mut device, transaction),
            None => self.volume.sync(&mut device),
        };
        if result.is_err() {
            self.failed = self.journal.is_some();
            self.volume.set_read_only();
        }
        result
    }

    /// Commits so a request that ran out of space can try once more. The
    /// allocator passes over blocks freed in the running transaction until
    /// it commits, so a volume whose free space was all freed since the last
    /// commit reports NoSpace early (W11 review R7). Whether a retry may help.
    fn commit_for_space<P: Ext4Platform>(&mut self, platform: &mut P) -> bool {
        let pending = matches!(&self.journal, Some((_, transaction)) if !transaction.is_empty());
        pending && self.commit(platform).is_ok()
    }

    /// After a request: a transaction that overflowed is dropped (the volume
    /// turns read-only on its last commit); one half full commits; one with
    /// changes gets a commit deadline.
    fn settle<P: Ext4Platform>(&mut self, platform: &mut P) {
        let Some((_, transaction)) = self.journal.as_mut() else {
            return;
        };
        if self.failed {
            return;
        }
        if core::mem::take(&mut self.full) {
            transaction.discard();
            self.commit_due = None;
            self.volume.set_read_only();
            return;
        }
        if transaction.len() > transaction.limit() / 2 {
            let _ = self.commit(platform);
        } else if !transaction.is_empty() && self.commit_due.is_none() {
            self.commit_due = platform
                .monotonic_active_now()
                .ok()
                .and_then(|now| now.checked_add(COMMIT_INTERVAL_NS));
            if self.commit_due.is_none() {
                let _ = self.commit(platform);
            }
        }
    }

    /// Commits what is left and marks the volume clean.
    pub fn retire<P: Ext4Platform>(&mut self, platform: &mut P) {
        let mut device = VolumeDevice {
            platform,
            client: &mut self.client,
            view: &mut self.view,
            cache: &mut self.cache,
        };
        if let Some((journal, transaction)) = self.journal.as_mut()
            && !self.volume.read_only()
        {
            let _ = journal.close(&mut self.volume, &mut device, transaction);
        }
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
        journal: &'a mut Option<(Journal, Running<V>)>,
        full: &'a mut bool,
    ) -> ServerDevice<'a, P, V> {
        ServerDevice {
            volume: VolumeDevice {
                platform,
                client,
                view,
                cache,
            },
            transaction: journal.as_mut().map(|(_, transaction)| transaction),
            full,
        }
    }

    fn attr(stat: Stat, access: u32, filesystem: u64) -> Attr {
        Attr {
            kind: match stat.kind {
                Ext4Kind::Directory => Kind::Directory,
                Ext4Kind::File => Kind::File,
            },
            access,
            size: stat.size,
            id: u64::from(stat.inode),
            filesystem,
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
        // CLOSE (WRFS 1.3) drops the node with no reply, whatever it was
        // doing: its locks and a waiting LOCK go with it, and closing this end
        // tells the client its close is complete.
        if message.body == Body::Close {
            return false;
        }
        let transaction_id = message.transaction_id;
        let status = |status| Body::Status { status, value: 0 };
        let writable = here.access & ACCESS_WRITE != 0;
        let readable = here.access & ACCESS_READ != 0;
        let mut listing = [0u8; MAX_DIRENT_BYTES];
        let mut data = [0u8; MAX_IO_BYTES];
        let mut device = Self::device(
            platform,
            &mut self.client,
            &mut self.view,
            &mut self.cache,
            &mut self.journal,
            &mut self.full,
        );
        // A Channel whose LOCK waits has nothing else to ask (WRFS 1.2).
        if self.locks.is_waiting(here.channel.0) {
            for info in received {
                let _ = platform.close_handle(info.handle);
            }
            return send(
                platform,
                here.channel,
                transaction_id,
                status(Status::Invalid),
            );
        }
        let reply = match message.body {
            Body::Open {
                flags,
                path,
                client,
            } => {
                let server = received[0];
                if server.object_type != DW_OBJECT_TYPE_CHANNEL
                    || server.rights != OPEN_CHANNEL_RIGHTS
                    || server.reserved0 != 0
                    || server.reserved != [0; 2]
                {
                    let _ = platform.close_handle(server.handle);
                    return false;
                }
                // Only vfsd, on the root Channel, names a client; a node
                // opened through another node is that node's client's.
                let client = if here.channel == self.root {
                    client
                } else if client == 0 {
                    here.client
                } else {
                    let _ = send(
                        platform,
                        server.handle,
                        transaction_id,
                        Body::OnOpen {
                            status: Status::Invalid,
                            attr: None,
                        },
                    );
                    // OPEN is one-way: only the new Channel hears of it.
                    let _ = platform.close_handle(server.handle);
                    return true;
                };
                // The node opened through `here` belongs to `client`.
                let dir = OpenNode { client, ..here };
                self.open(platform, transaction_id, dir, flags, path, server.handle);
                self.settle(platform);
                return true;
            }
            Body::GetAttr => match self.volume.stat(&mut device, here.inode) {
                Ok(stat) => Body::Attr(Self::attr(stat, here.access, self.filesystem)),
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
                let mut written = self.volume.write(&mut device, here.inode, offset, data);
                if matches!(written, Err(Ext4Error::NoSpace)) && self.commit_for_space(platform) {
                    let mut device = Self::device(
                        platform,
                        &mut self.client,
                        &mut self.view,
                        &mut self.cache,
                        &mut self.journal,
                        &mut self.full,
                    );
                    written = self.volume.write(&mut device, here.inode, offset, data);
                }
                match written {
                    Ok(written) => Body::Status {
                        status: Status::Ok,
                        value: written as u64,
                    },
                    Err(error) => status(status_of(error)),
                }
            }
            Body::Truncate { size } if writable => {
                let mut truncated = self.volume.truncate(&mut device, here.inode, size);
                if matches!(truncated, Err(Ext4Error::NoSpace)) && self.commit_for_space(platform) {
                    let mut device = Self::device(
                        platform,
                        &mut self.client,
                        &mut self.view,
                        &mut self.cache,
                        &mut self.journal,
                        &mut self.full,
                    );
                    truncated = self.volume.truncate(&mut device, here.inode, size);
                }
                status(match truncated {
                    Ok(()) => Status::Ok,
                    Err(error) => status_of(error),
                })
            }
            Body::Unlink { name } if writable => {
                let mut found = self.volume.lookup(&mut device, here.inode, name);
                if found
                    .as_ref()
                    .is_ok_and(|stat| is_open(&self.nodes, stat.inode))
                {
                    self.reap_closed(platform, here.channel);
                    device = Self::device(
                        platform,
                        &mut self.client,
                        &mut self.view,
                        &mut self.cache,
                        &mut self.journal,
                        &mut self.full,
                    );
                    found = self.volume.lookup(&mut device, here.inode, name);
                }
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
            Body::Lock { lock, flags } => {
                let group = here.lock_group();
                let node = u64::from(here.inode);
                let owner = here.channel.0;
                let mut outcome =
                    self.locks
                        .request(owner, group, node, lock, flags, transaction_id);
                if matches!(outcome, Outcome::Busy | Outcome::Deadlock | Outcome::NoRoom) {
                    self.reap_closed(platform, here.channel);
                    outcome = self
                        .locks
                        .request(owner, group, node, lock, flags, transaction_id);
                }
                match outcome {
                    // Answered when it is granted (`grant_waiters`).
                    Outcome::Waiting => {
                        self.grant_waiters(platform);
                        return true;
                    }
                    outcome => lock_reply(outcome),
                }
            }
            Body::TestLock(lock) => {
                let node = u64::from(here.inode);
                let mut held = self.locks.conflict(node, here.channel.0, lock);
                if held.is_some() {
                    self.reap_closed(platform, here.channel);
                    held = self.locks.conflict(node, here.channel.0, lock);
                }
                Body::LockInfo(held.map(|held| held.lock()))
            }
            Body::Sync => status(match self.commit(platform) {
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
        self.settle(platform);
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
        let mut device = Self::device(
            platform,
            &mut self.client,
            &mut self.view,
            &mut self.cache,
            &mut self.journal,
            &mut self.full,
        );
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
            Some(_) => match self.resolve_for_open(platform, dir, flags, path) {
                Err(Status::NoSpace) if self.commit_for_space(platform) => {
                    self.resolve_for_open(platform, dir, flags, path)
                }
                found => found,
            },
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
            Ok(stat) => (Status::Ok, Some(Self::attr(stat, access, self.filesystem))),
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
                    client: dir.client,
                });
            }
            _ => {
                let _ = platform.close_handle(server);
            }
        }
    }
}

/// LOCK's answer for an outcome other than waiting.
fn lock_reply(outcome: Outcome) -> Body<'static> {
    match outcome {
        Outcome::Granted => Body::Status {
            status: Status::Ok,
            value: 0,
        },
        outcome => Body::Status {
            status: match outcome {
                Outcome::Busy => Status::Busy,
                Outcome::Deadlock => Status::Deadlock,
                Outcome::NoRoom => Status::NoResources,
                _ => Status::Invalid,
            },
            value: 0,
        },
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
