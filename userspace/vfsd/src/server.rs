//! The vfsd service state and its event loop step.

use deepwyrm_syscall::{
    DW_HANDLE_INVALID, DW_HANDLE_TRANSFER_MOVE, DW_OBJECT_TYPE_CHANNEL, DW_SIGNAL_PEER_CLOSED,
    DW_SIGNAL_READABLE, DW_STATUS_PEER_CLOSED, DW_STATUS_WOULD_BLOCK, DwDeadline, DwHandle,
    DwHandleTransferV1, DwReceivedHandleInfoV1, DwRights, DwSignals, DwWaitItemV1,
};
use wyrmroot_fs_proto::namespace::{self, MOUNT_READ_ONLY};
use wyrmroot_fs_proto::node::{
    self, ACCESS_READ, Attr, Body as NodeBody, EntryWriter, FS_READ_ONLY, FsInfo, Kind,
    MAX_DIRENT_BYTES,
};
use wyrmroot_fs_proto::{
    MAX_HANDLES, MAX_NAME_BYTES, OPEN_CREATE, OPEN_EXCLUSIVE, OPEN_FILE, OPEN_MUTATING, Status,
};
use wyrmroot_runtime::{ChannelPlatform, HandlePlatform, NativeError, WaitPlatform};

use crate::mounts::{MAX_MOUNTS, MountTable, PathBuf, Resolution};
use crate::{
    MAX_CLIENTS, MAX_EXTRA_WAITS, MAX_NODES, MAX_NODES_PER_CONNECTION, OPEN_CHANNEL_RIGHTS,
    ROOT_CHANNEL_RIGHTS,
};

/// The platform traits vfsd uses.
pub trait VfsPlatform: HandlePlatform + ChannelPlatform + WaitPlatform {}

impl<P> VfsPlatform for P where P: HandlePlatform + ChannelPlatform + WaitPlatform + ?Sized {}

const READABLE_OR_CLOSED: DwSignals = DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0);
const WAIT_ITEMS: usize = 1 + MAX_CLIENTS + MAX_NODES + MAX_MOUNTS + MAX_EXTRA_WAITS;
// One wait_many covers every slot.
const _: () = assert!(WAIT_ITEMS <= deepwyrm_syscall::DW_WAIT_MANY_MAX_ITEMS as usize);

/// What one step saw that is the caller's to handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    /// Caller wait item `index` is ready with the full `observed` signals.
    Extra { index: usize, observed: DwSignals },
    /// The administrative connection closed; vfsd keeps serving opens.
    AdminClosed,
}

/// A synthetic directory node vfsd serves itself.
struct Node {
    channel: DwHandle,
    path: PathBuf,
    /// The connection that opened it.
    owner: u64,
}

/// The admin connection's identity; clients are numbered from 1 and never
/// reuse a number.
const ADMIN_ID: u64 = 0;

#[derive(Clone, Copy)]
enum Target {
    Admin,
    Client(usize),
    Node(usize),
    Mount(usize),
    Extra(usize),
}

pub struct Vfs {
    admin: DwHandle,
    clients: [DwHandle; MAX_CLIENTS],
    client_ids: [u64; MAX_CLIENTS],
    next_client_id: u64,
    nodes: [Option<Node>; MAX_NODES],
    mounts: MountTable,
}

impl Vfs {
    /// Serves WRNS with MOUNT/UNMOUNT authority on `admin`, a Channel the
    /// caller admitted.
    pub const fn new(admin: DwHandle) -> Self {
        Self {
            admin,
            clients: [DW_HANDLE_INVALID; MAX_CLIENTS],
            client_ids: [ADMIN_ID; MAX_CLIENTS],
            next_client_id: ADMIN_ID + 1,
            nodes: [const { None }; MAX_NODES],
            mounts: MountTable::new(),
        }
    }

    pub fn mounts(&self) -> &MountTable {
        &self.mounts
    }

    /// Mounts the filesystem root `root` at the checked absolute `path`;
    /// on refusal the caller still owns `root`.
    pub fn mount(&mut self, path: &[u8], root: DwHandle, read_only: bool) -> Result<(), Status> {
        wyrmroot_fs_proto::check_absolute(path).map_err(|_| Status::InvalidPath)?;
        self.mounts.add(path, root, read_only).map(|_| ())
    }

    /// Adds one WRNS client connection, a Channel the caller admitted. With
    /// every slot taken the Channel is closed and `false` returned.
    pub fn accept_client<P: VfsPlatform>(&mut self, platform: &mut P, channel: DwHandle) -> bool {
        match self
            .clients
            .iter()
            .position(|slot| *slot == DW_HANDLE_INVALID)
        {
            Some(slot) => {
                // Ids are never reused, and id 0 is the admin's: refuse
                // rather than wrap (review 2026-11-12, I1).
                let Some(next) = self.next_client_id.checked_add(1) else {
                    let _ = platform.close_handle(channel);
                    return false;
                };
                self.clients[slot] = channel;
                self.client_ids[slot] = self.next_client_id;
                self.next_client_id = next;
                true
            }
            None => {
                let _ = platform.close_handle(channel);
                false
            }
        }
    }

    /// Waits once on every connection, node and mount plus the caller's
    /// `extra` items (at most [`MAX_EXTRA_WAITS`]) and handles what woke it.
    /// Only a failed wait is an error; a misbehaving peer only loses its own
    /// connection, node or mount.
    pub fn step<P: VfsPlatform>(
        &mut self,
        platform: &mut P,
        extra: &[DwWaitItemV1],
        deadline: DwDeadline,
    ) -> Result<Option<Event>, NativeError> {
        let mut items = [DwWaitItemV1::default(); WAIT_ITEMS];
        let mut targets = [Target::Admin; WAIT_ITEMS];
        let mut count = 0;
        let mut add = |handle: DwHandle, signals: DwSignals, target: Target| {
            items[count] = DwWaitItemV1 { handle, signals };
            targets[count] = target;
            count += 1;
        };
        if self.admin != DW_HANDLE_INVALID {
            add(self.admin, READABLE_OR_CLOSED, Target::Admin);
        }
        for (slot, &client) in self.clients.iter().enumerate() {
            if client != DW_HANDLE_INVALID {
                add(client, READABLE_OR_CLOSED, Target::Client(slot));
            }
        }
        for (slot, node) in self.nodes.iter().enumerate() {
            if let Some(node) = node {
                add(node.channel, READABLE_OR_CLOSED, Target::Node(slot));
            }
        }
        // vfsd only ever sends OPEN on a root, so anything readable there is
        // a fault too.
        for (index, mount) in self.mounts.iter() {
            add(mount.root, READABLE_OR_CLOSED, Target::Mount(index));
        }
        for (index, item) in extra.iter().take(MAX_EXTRA_WAITS).enumerate() {
            add(item.handle, item.signals, Target::Extra(index));
        }
        let result = platform.wait_many(&items[..count], deadline)?;
        let index = result.index as usize;
        let target = *targets[..count].get(index).ok_or(NativeError::Output(
            wyrmroot_runtime::NativeOutputError::InvalidObjectInfo,
        ))?;
        let readable = result.observed.0 & DW_SIGNAL_READABLE.0 != 0;
        match target {
            Target::Extra(index) => {
                return Ok(Some(Event::Extra {
                    index,
                    observed: result.observed,
                }));
            }
            Target::Admin if readable => {
                if !self.serve_namespace(platform, self.admin, ADMIN_ID) {
                    let _ = platform.close_handle(self.admin);
                    self.admin = DW_HANDLE_INVALID;
                    return Ok(Some(Event::AdminClosed));
                }
            }
            Target::Admin => {
                let _ = platform.close_handle(self.admin);
                self.admin = DW_HANDLE_INVALID;
                return Ok(Some(Event::AdminClosed));
            }
            Target::Client(slot) => {
                let (channel, owner) = (self.clients[slot], self.client_ids[slot]);
                if !readable || !self.serve_namespace(platform, channel, owner) {
                    let _ = platform.close_handle(channel);
                    self.clients[slot] = DW_HANDLE_INVALID;
                }
            }
            Target::Node(slot) => {
                if !readable || !self.serve_node(platform, slot) {
                    self.close_node(platform, slot);
                }
            }
            Target::Mount(index) => {
                if let Some(root) = self.mounts.remove(index) {
                    let _ = platform.close_handle(root);
                }
            }
        }
        Ok(None)
    }

    /// Closes every handle vfsd holds; `false` if any close failed. Nodes
    /// already opened on a filesystem live on: vfsd never held them.
    pub fn shutdown<P: VfsPlatform>(&mut self, platform: &mut P) -> bool {
        let mut clean = true;
        let mut close = |handle: &mut DwHandle| {
            if *handle != DW_HANDLE_INVALID {
                clean &= platform.close_handle(*handle).is_ok();
                *handle = DW_HANDLE_INVALID;
            }
        };
        close(&mut self.admin);
        self.clients.iter_mut().for_each(&mut close);
        for node in self.nodes.iter_mut().filter_map(Option::take) {
            close(&mut { node.channel });
        }
        for index in 0..MAX_MOUNTS {
            if let Some(mut root) = self.mounts.remove(index) {
                close(&mut root);
            }
        }
        clean
    }

    /// Serves one WRNS request; `false` drops the connection.
    fn serve_namespace<P: VfsPlatform>(
        &mut self,
        platform: &mut P,
        channel: DwHandle,
        owner: u64,
    ) -> bool {
        let admin = owner == ADMIN_ID;
        let mut bytes = [0u8; namespace::MAX_BYTES];
        let mut handles = [DwReceivedHandleInfoV1::default(); MAX_HANDLES];
        let Ok(counts) = platform.receive_channel(channel, &mut bytes, &mut handles) else {
            // Too large for any WRNS message, or the peer went away.
            return false;
        };
        let received = &handles[..counts.handles.min(MAX_HANDLES)];
        let message = namespace::parse(&bytes[..counts.bytes.min(bytes.len())], counts.handles)
            .ok()
            .filter(|message| message.body.is_request());
        let Some(message) = message else {
            close_all(platform, received);
            return false;
        };
        let status = match message.body {
            namespace::Body::Open { flags, path } => {
                if !admitted(received[0], OPEN_CHANNEL_RIGHTS) {
                    close_all(platform, received);
                    return false;
                }
                self.open(
                    platform,
                    owner,
                    message.transaction_id,
                    flags,
                    path,
                    received[0].handle,
                );
                return true;
            }
            namespace::Body::Mount { flags, path } => {
                let root = received[0];
                if !admin {
                    close_all(platform, received);
                    Status::AccessDenied
                } else if !admitted(root, ROOT_CHANNEL_RIGHTS) {
                    close_all(platform, received);
                    Status::Invalid
                } else {
                    match self
                        .mounts
                        .add(path, root.handle, flags & MOUNT_READ_ONLY != 0)
                    {
                        Ok(_) => Status::Ok,
                        Err(status) => {
                            close_all(platform, received);
                            status
                        }
                    }
                }
            }
            namespace::Body::Unmount { path } => {
                if !admin {
                    Status::AccessDenied
                } else if let Some(root) = self.mounts.remove_path(path) {
                    // Nodes already open on it live on (platform conventions
                    // §5.3); only new path opens stop reaching it.
                    let _ = platform.close_handle(root);
                    Status::Ok
                } else {
                    Status::NotFound
                }
            }
            namespace::Body::Status(_) => return false,
        };
        let mut reply = [0u8; namespace::MAX_BYTES];
        let Ok(size) = namespace::encode(
            &namespace::Message {
                transaction_id: message.transaction_id,
                body: namespace::Body::Status(status),
            },
            &mut reply,
        ) else {
            return false;
        };
        platform.send_channel(channel, &reply[..size], &[]).is_ok()
    }

    /// Opens a checked absolute `path` onto the node Channel `server`, which
    /// this call always either passes on, keeps as a synthetic node, or
    /// answers with a failed ON_OPEN and closes.
    fn open<P: VfsPlatform>(
        &mut self,
        platform: &mut P,
        owner: u64,
        transaction_id: u64,
        flags: u32,
        path: &[u8],
        server: DwHandle,
    ) {
        let status = match self.mounts.resolve(path) {
            Resolution::Mount { index, rest } => {
                match self.forward(platform, owner, transaction_id, flags, index, rest, server) {
                    Ok(()) => return,
                    Err(status) => status,
                }
            }
            Resolution::Synthetic => {
                if flags & OPEN_FILE != 0 {
                    Status::NotDirectory
                } else if flags & OPEN_CREATE != 0 && flags & OPEN_EXCLUSIVE != 0 {
                    Status::Exists
                } else if flags & OPEN_MUTATING != 0 {
                    Status::ReadOnly
                } else {
                    match self.add_node(platform, owner, transaction_id, path, server) {
                        Ok(()) => return,
                        Err(status) => status,
                    }
                }
            }
            Resolution::NotFound => Status::NotFound,
        };
        fail_open(platform, transaction_id, server, status);
    }

    /// Passes an open on to mount `index`, naming the client connection
    /// `owner` it came through (WRFS 1.2); on `Err` the caller still owns
    /// `server`.
    fn forward<P: VfsPlatform>(
        &mut self,
        platform: &mut P,
        owner: u64,
        transaction_id: u64,
        mut flags: u32,
        index: usize,
        rest: &[u8],
        server: DwHandle,
    ) -> Result<(), Status> {
        let mount = self.mounts.get(index).ok_or(Status::NotFound)?;
        if mount.read_only && flags & OPEN_MUTATING != 0 {
            return Err(Status::ReadOnly);
        }
        // The mount point itself exists: CREATE there either opens it or,
        // exclusive, is refused.
        if rest.is_empty() && flags & OPEN_CREATE != 0 {
            if flags & OPEN_EXCLUSIVE != 0 {
                return Err(Status::Exists);
            }
            flags &= !OPEN_CREATE;
        }
        let mut bytes = [0u8; node::MAX_BYTES];
        let size = node::encode(
            &node::Message {
                transaction_id,
                body: NodeBody::Open {
                    flags,
                    path: rest,
                    client: owner,
                },
            },
            &mut bytes,
        )
        .map_err(|_| Status::Invalid)?;
        let transfer = DwHandleTransferV1 {
            handle: server,
            requested_rights: OPEN_CHANNEL_RIGHTS,
            operation: DW_HANDLE_TRANSFER_MOVE,
            reserved0: 0,
            reserved: [0; 2],
        };
        match platform.send_channel(mount.root, &bytes[..size], &[transfer]) {
            Ok(()) => Ok(()),
            Err(NativeError::Status(DW_STATUS_WOULD_BLOCK)) => Err(Status::Busy),
            Err(NativeError::Status(DW_STATUS_PEER_CLOSED)) => {
                // The filesystem is gone; so is its mount.
                if let Some(root) = self.mounts.remove(index) {
                    let _ = platform.close_handle(root);
                }
                Err(Status::IoError)
            }
            Err(_) => Err(Status::IoError),
        }
    }

    /// Keeps `server` as a synthetic directory at `path` and answers its
    /// ON_OPEN; on `Err` the caller still owns `server`.
    fn add_node<P: VfsPlatform>(
        &mut self,
        platform: &mut P,
        owner: u64,
        transaction_id: u64,
        path: &[u8],
        server: DwHandle,
    ) -> Result<(), Status> {
        let path = PathBuf::new(path).ok_or(Status::InvalidPath)?;
        let held = self
            .nodes
            .iter()
            .flatten()
            .filter(|node| node.owner == owner)
            .count();
        if held >= MAX_NODES_PER_CONNECTION {
            return Err(Status::NoResources);
        }
        let slot = self
            .nodes
            .iter()
            .position(Option::is_none)
            .ok_or(Status::NoResources)?;
        let sent = send_node(
            platform,
            server,
            transaction_id,
            NodeBody::OnOpen {
                status: Status::Ok,
                attr: Some(SYNTHETIC_ATTR),
            },
        );
        if sent {
            self.nodes[slot] = Some(Node {
                channel: server,
                path,
                owner,
            });
        } else {
            // The client went away before its ON_OPEN arrived.
            let _ = platform.close_handle(server);
        }
        Ok(())
    }

    fn close_node<P: VfsPlatform>(&mut self, platform: &mut P, slot: usize) {
        if let Some(node) = self.nodes[slot].take() {
            let _ = platform.close_handle(node.channel);
        }
    }

    /// Serves one WRFS request on synthetic node `slot`; `false` drops it.
    fn serve_node<P: VfsPlatform>(&mut self, platform: &mut P, slot: usize) -> bool {
        let Some(node) = self.nodes[slot].as_ref() else {
            return false;
        };
        // Opens through a node count against the connection that opened it.
        let (channel, base, owner) = (node.channel, node.path, node.owner);
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
            close_all(platform, received);
            return false;
        };
        let transaction_id = message.transaction_id;
        let status = |status| NodeBody::Status { status, value: 0 };
        let mut listing = [0u8; MAX_DIRENT_BYTES];
        let reply = match message.body {
            NodeBody::Open {
                flags,
                path,
                client,
            } => {
                let server = received[0];
                if !admitted(server, OPEN_CHANNEL_RIGHTS) {
                    close_all(platform, received);
                    return false;
                }
                // Only vfsd names a client connection (WRFS 1.2).
                if client != 0 {
                    fail_open(platform, transaction_id, server.handle, Status::Invalid);
                    return true;
                }
                // A synthetic directory is only listed, so nothing opened
                // through it may be written (access never grows).
                if flags & OPEN_MUTATING != 0 {
                    fail_open(
                        platform,
                        transaction_id,
                        server.handle,
                        Status::AccessDenied,
                    );
                } else if let Some(full) = PathBuf::join(base.as_bytes(), path) {
                    self.open(
                        platform,
                        owner,
                        transaction_id,
                        flags,
                        full.as_bytes(),
                        server.handle,
                    );
                } else {
                    fail_open(platform, transaction_id, server.handle, Status::InvalidPath);
                }
                return true;
            }
            NodeBody::GetAttr => NodeBody::Attr(SYNTHETIC_ATTR),
            NodeBody::ReadDir { cookie } => {
                match self.list(base.as_bytes(), cookie, &mut listing) {
                    Some((next_cookie, used)) => NodeBody::Dirents {
                        next_cookie,
                        // `list` wrote only checked names.
                        entries: match node::Entries::new(&listing[..used]) {
                            Ok(entries) => entries,
                            Err(_) => return false,
                        },
                    },
                    None => status(Status::Invalid),
                }
            }
            NodeBody::Read { .. } | NodeBody::Write { .. } | NodeBody::Truncate { .. } => {
                status(Status::IsDirectory)
            }
            NodeBody::Unlink { .. } => status(Status::AccessDenied),
            NodeBody::Sync => status(Status::Ok),
            NodeBody::Lock { .. } | NodeBody::TestLock(_) => status(Status::NotSupported),
            NodeBody::QueryFilesystem => NodeBody::FsInfo(FsInfo {
                flags: FS_READ_ONLY,
                name_max: MAX_NAME_BYTES as u32,
                block_size: 4096,
                total_bytes: 0,
                free_bytes: 0,
            }),
            _ => return false,
        };
        send_node(platform, channel, transaction_id, reply)
    }

    /// Writes the page of synthetic directory `dir` that starts at `cookie`
    /// into `out`: `(next_cookie, bytes used)`, or `None` for a cookie past
    /// the end.
    fn list(&self, dir: &[u8], cookie: u64, out: &mut [u8]) -> Option<(u64, usize)> {
        let mut names = [&[][..]; MAX_MOUNTS];
        let count = self.mounts.listing(dir, &mut names);
        let start = usize::try_from(cookie)
            .ok()
            .filter(|&start| start <= count)?;
        let mut writer = EntryWriter::new(out);
        let mut next = start;
        while next < count && writer.push(Kind::Directory, names[next]) {
            next += 1;
        }
        let used = writer.entries().as_bytes().len();
        Some((if next < count { next as u64 } else { 0 }, used))
    }
}

/// Every synthetic directory looks the same: listable, never writable, with
/// no identity of its own.
const SYNTHETIC_ATTR: Attr = Attr {
    kind: Kind::Directory,
    access: ACCESS_READ,
    size: 0,
    id: 0,
    filesystem: 0,
};

fn admitted(info: DwReceivedHandleInfoV1, rights: DwRights) -> bool {
    info.handle != DW_HANDLE_INVALID
        && info.object_type == DW_OBJECT_TYPE_CHANNEL
        && info.rights == rights
        && info.reserved0 == 0
        && info.reserved == [0; 2]
}

fn close_all<P: VfsPlatform>(platform: &mut P, received: &[DwReceivedHandleInfoV1]) {
    for info in received {
        let _ = platform.close_handle(info.handle);
    }
}

/// Sends one WRFS message; `false` if it could not be encoded or sent.
fn send_node<P: VfsPlatform>(
    platform: &mut P,
    channel: DwHandle,
    transaction_id: u64,
    body: NodeBody<'_>,
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

/// Answers a failed open on its node Channel and closes it.
fn fail_open<P: VfsPlatform>(
    platform: &mut P,
    transaction_id: u64,
    server: DwHandle,
    status: Status,
) {
    let _ = send_node(
        platform,
        server,
        transaction_id,
        NodeBody::OnOpen { status, attr: None },
    );
    let _ = platform.close_handle(server);
}
