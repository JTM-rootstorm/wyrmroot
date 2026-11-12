//! vfsd against the in-memory Channel model (`wyrmroot-channel-model`); the
//! test plays every other process.

use std::vec;
use std::vec::Vec;

use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_HANDLE_TRANSFER_MOVE, DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_TRANSFER,
    DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DW_STATUS_TIMED_OUT, DwHandle, DwHandleTransferV1,
    DwReceivedHandleInfoV1, DwRights, DwSignals, DwWaitItemV1,
};
use wyrmroot_channel_model::World;
use wyrmroot_fs_proto::namespace::{self, MOUNT_READ_ONLY};
use wyrmroot_fs_proto::node::{self, ACCESS_READ, Attr, Body, FS_READ_ONLY, Kind};
use wyrmroot_fs_proto::{
    OPEN_CREATE, OPEN_DIRECTORY, OPEN_EXCLUSIVE, OPEN_FILE, OPEN_READ, OPEN_TRUNCATE, OPEN_WRITE,
    Status,
};
use wyrmroot_runtime::{ChannelPlatform, HandlePlatform, NativeError, WaitPlatform};

use crate::mounts::MAX_MOUNTS;
use crate::server::{Event, Vfs};
use crate::{
    MAX_CLIENTS, MAX_NODES, MAX_NODES_PER_CONNECTION, OPEN_CHANNEL_RIGHTS, ROOT_CHANNEL_RIGHTS,
};

// ---------------------------------------------------------------- harness

struct Harness {
    world: World,
    vfs: Vfs,
    admin: DwHandle,
    client: DwHandle,
    next_transaction: u64,
}

impl Harness {
    fn new() -> Self {
        let mut world = World::new();
        let (admin, admin_server) = world.create_channel(ROOT_CHANNEL_RIGHTS).unwrap();
        let (client, client_server) = world.create_channel(ROOT_CHANNEL_RIGHTS).unwrap();
        let mut vfs = Vfs::new(admin_server);
        assert!(vfs.accept_client(&mut world, client_server));
        Self {
            world,
            vfs,
            admin,
            client,
            next_transaction: 1,
        }
    }

    fn transaction(&mut self) -> u64 {
        self.next_transaction += 1;
        self.next_transaction
    }

    /// Runs vfsd until nothing is ready.
    fn settle(&mut self) -> Vec<Event> {
        let mut events = Vec::new();
        loop {
            match self.vfs.step(&mut self.world, &[], DW_DEADLINE_INFINITE) {
                Ok(Some(event)) => events.push(event),
                Ok(None) => {}
                Err(NativeError::Status(DW_STATUS_TIMED_OUT)) => return events,
                Err(error) => panic!("vfsd wait failed: {error:?}"),
            }
        }
    }

    fn send(&mut self, channel: DwHandle, bytes: &[u8], handle: Option<(DwHandle, DwRights)>) {
        let transfers: Vec<_> = handle
            .into_iter()
            .map(|(handle, requested_rights)| DwHandleTransferV1 {
                handle,
                requested_rights,
                operation: DW_HANDLE_TRANSFER_MOVE,
                reserved0: 0,
                reserved: [0; 2],
            })
            .collect();
        self.world.send_channel(channel, bytes, &transfers).unwrap();
    }

    fn receive(&mut self, channel: DwHandle) -> (Vec<u8>, Vec<DwReceivedHandleInfoV1>) {
        let mut bytes = vec![0u8; 65536];
        let mut handles = [DwReceivedHandleInfoV1::default(); 4];
        let counts = self
            .world
            .receive_channel(channel, &mut bytes, &mut handles)
            .unwrap();
        bytes.truncate(counts.bytes);
        (bytes, handles[..counts.handles].to_vec())
    }

    fn signals(&self, channel: DwHandle) -> DwSignals {
        self.world.signals(channel).unwrap()
    }

    fn peer_closed(&self, channel: DwHandle) -> bool {
        self.signals(channel).0 & DW_SIGNAL_PEER_CLOSED.0 != 0
    }

    fn ns_message(&mut self, body: namespace::Body<'_>) -> Vec<u8> {
        let mut bytes = vec![0u8; namespace::MAX_BYTES];
        let size = namespace::encode(
            &namespace::Message {
                transaction_id: self.transaction(),
                body,
            },
            &mut bytes,
        )
        .unwrap();
        bytes.truncate(size);
        bytes
    }

    fn node_message(&mut self, body: Body<'_>) -> Vec<u8> {
        let mut bytes = vec![0u8; node::MAX_BYTES];
        let size = node::encode(
            &node::Message {
                transaction_id: self.transaction(),
                body,
            },
            &mut bytes,
        )
        .unwrap();
        bytes.truncate(size);
        bytes
    }

    /// Sends WRNS OPEN on `connection` and returns the client end of the
    /// node Channel, before vfsd has run.
    fn open_on(&mut self, connection: DwHandle, flags: u32, path: &[u8]) -> DwHandle {
        let (node, server) = self.world.create_channel(OPEN_CHANNEL_RIGHTS).unwrap();
        let bytes = self.ns_message(namespace::Body::Open { flags, path });
        self.send(connection, &bytes, Some((server, OPEN_CHANNEL_RIGHTS)));
        node
    }

    /// WRNS OPEN on the client connection, then vfsd runs.
    fn open(&mut self, flags: u32, path: &[u8]) -> DwHandle {
        let client = self.client;
        let node = self.open_on(client, flags, path);
        self.settle();
        node
    }

    /// WRFS OPEN relative to `dir`, then vfsd runs.
    fn open_at(&mut self, dir: DwHandle, flags: u32, path: &[u8]) -> DwHandle {
        let (node, server) = self.world.create_channel(OPEN_CHANNEL_RIGHTS).unwrap();
        let bytes = self.node_message(Body::Open {
            flags,
            path,
            client: 0,
        });
        self.send(dir, &bytes, Some((server, OPEN_CHANNEL_RIGHTS)));
        self.settle();
        node
    }

    /// Reads the ON_OPEN vfsd itself sent on a node.
    fn on_open(&mut self, node_channel: DwHandle) -> (Status, Option<Attr>) {
        let (bytes, handles) = self.receive(node_channel);
        let message = node::parse(&bytes, handles.len()).unwrap();
        match message.body {
            Body::OnOpen { status, attr } => (status, attr),
            other => panic!("expected ON_OPEN, got {other:?}"),
        }
    }

    /// Asserts a failed open: ON_OPEN with `status`, then closure.
    fn assert_refused(&mut self, node_channel: DwHandle, status: Status) {
        assert_eq!(self.on_open(node_channel), (status, None));
        assert!(self.peer_closed(node_channel));
        self.world.close_handle(node_channel).unwrap();
    }

    /// MOUNT through `connection`: returns vfsd's status and the
    /// filesystem's end of the root Channel.
    fn mount_on(&mut self, connection: DwHandle, path: &[u8], flags: u32) -> (Status, DwHandle) {
        let (root, filesystem) = self.world.create_channel(OPEN_CHANNEL_RIGHTS).unwrap();
        let bytes = self.ns_message(namespace::Body::Mount { flags, path });
        self.send(connection, &bytes, Some((root, ROOT_CHANNEL_RIGHTS)));
        self.settle();
        (self.ns_status(connection), filesystem)
    }

    fn mount(&mut self, path: &[u8], flags: u32) -> DwHandle {
        let admin = self.admin;
        let (status, filesystem) = self.mount_on(admin, path, flags);
        assert_eq!(status, Status::Ok);
        filesystem
    }

    fn unmount(&mut self, connection: DwHandle, path: &[u8]) -> Status {
        let bytes = self.ns_message(namespace::Body::Unmount { path });
        self.send(connection, &bytes, None);
        self.settle();
        self.ns_status(connection)
    }

    fn ns_status(&mut self, connection: DwHandle) -> Status {
        let (bytes, handles) = self.receive(connection);
        match namespace::parse(&bytes, handles.len()).unwrap().body {
            namespace::Body::Status(status) => status,
            other => panic!("expected STATUS, got {other:?}"),
        }
    }

    /// What a filesystem receives for one forwarded open: flags, the rest
    /// of the path, the transaction and the node Channel's server end.
    fn forwarded(&mut self, filesystem: DwHandle) -> (u32, Vec<u8>, u64, DwReceivedHandleInfoV1) {
        let (bytes, handles) = self.receive(filesystem);
        let message = node::parse(&bytes, handles.len()).unwrap();
        let Body::Open {
            flags,
            path,
            client,
        } = message.body
        else {
            panic!("expected OPEN, got {:?}", message.body);
        };
        // Every forwarded open names the client connection it came
        // through (WRFS 1.2); clients are numbered from 1.
        assert_ne!(client, 0);
        (flags, path.to_vec(), message.transaction_id, handles[0])
    }

    /// One WRFS request on `node_channel` to vfsd; returns its reply body
    /// as owned bytes for [`node::parse`].
    fn request(&mut self, node_channel: DwHandle, body: Body<'_>) -> Vec<u8> {
        let bytes = self.node_message(body);
        let transaction = self.next_transaction;
        self.send(node_channel, &bytes, None);
        self.settle();
        let (reply, handles) = self.receive(node_channel);
        assert!(handles.is_empty());
        assert_eq!(
            node::parse(&reply, 0).unwrap().transaction_id,
            transaction,
            "replies echo the transaction"
        );
        reply
    }

    fn list(&mut self, dir: DwHandle) -> Vec<Vec<u8>> {
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
                assert_eq!(kind, Kind::Directory);
                names.push(name.to_vec());
            }
            if next_cookie == 0 {
                return names;
            }
            cookie = next_cookie;
        }
    }
}

const SYNTHETIC: Attr = Attr {
    kind: Kind::Directory,
    access: ACCESS_READ,
    size: 0,
    id: 0,
    filesystem: 0,
};

// ---------------------------------------------------------------- tests

#[test]
fn an_empty_namespace_has_an_empty_synthetic_root_and_nothing_else() {
    let mut h = Harness::new();
    let root = h.open(OPEN_READ | OPEN_DIRECTORY, b"/");
    assert_eq!(h.on_open(root), (Status::Ok, Some(SYNTHETIC)));
    assert_eq!(h.list(root), Vec::<Vec<u8>>::new());
    let reply = h.request(root, Body::GetAttr);
    assert_eq!(node::parse(&reply, 0).unwrap().body, Body::Attr(SYNTHETIC));
    let reply = h.request(root, Body::QueryFilesystem);
    let Body::FsInfo(info) = node::parse(&reply, 0).unwrap().body else {
        panic!("expected FS_INFO");
    };
    assert_eq!(info.flags, FS_READ_ONLY);

    let missing = h.open(OPEN_READ, b"/boot");
    h.assert_refused(missing, Status::NotFound);
}

#[test]
fn opens_reach_the_longest_covering_mount_with_the_rest_of_the_path() {
    let mut h = Harness::new();
    let root_fs = h.mount(b"/", 0);
    let boot_fs = h.mount(b"/boot", MOUNT_READ_ONLY);
    let efi_fs = h.mount(b"/boot/efi", 0);

    let cases: [(&[u8], DwHandle, &[u8]); 6] = [
        (b"/", root_fs, b""),
        (b"/bootx", root_fs, b"bootx"),
        (b"/state/log", root_fs, b"state/log"),
        (b"/boot", boot_fs, b""),
        (b"/boot/kernel.elf", boot_fs, b"kernel.elf"),
        (b"/boot/efi/EFI/BOOT", efi_fs, b"EFI/BOOT"),
    ];
    for (path, filesystem, rest) in cases {
        let node_channel = h.open(OPEN_READ, path);
        let transaction = h.next_transaction;
        let (flags, forwarded_path, forwarded_transaction, server) = h.forwarded(filesystem);
        assert_eq!(flags, OPEN_READ);
        assert_eq!(forwarded_path, rest, "{path:?}");
        assert_eq!(forwarded_transaction, transaction);
        assert_eq!(server.object_type, DW_OBJECT_TYPE_CHANNEL);
        assert_eq!(server.rights, OPEN_CHANNEL_RIGHTS);

        // The filesystem answers the client directly; vfsd is not on the path.
        let ok = h.node_message(Body::OnOpen {
            status: Status::Ok,
            attr: Some(Attr {
                kind: Kind::File,
                access: ACCESS_READ,
                size: 3,
                id: 9,
                filesystem: 0,
            }),
        });
        h.send(server.handle, &ok, None);
        assert_eq!(h.on_open(node_channel).0, Status::Ok);
        let data = h.node_message(Body::Data(b"abc"));
        h.send(server.handle, &data, None);
        let (bytes, _) = h.receive(node_channel);
        assert_eq!(node::parse(&bytes, 0).unwrap().body, Body::Data(b"abc"));
        h.world.close_handle(server.handle).unwrap();
        h.world.close_handle(node_channel).unwrap();
    }
    assert!(h.settle().is_empty());
}

#[test]
fn synthetic_directories_list_mount_points_and_open_through_to_them() {
    let mut h = Harness::new();
    let boot_fs = h.mount(b"/boot", 0);
    let _data_fs = h.mount(b"/srv/data", 0);
    let _web_fs = h.mount(b"/srv/web", 0);
    let _alpha_fs = h.mount(b"/alpha", 0);

    let root = h.open(OPEN_READ | OPEN_DIRECTORY, b"/");
    assert_eq!(h.on_open(root).0, Status::Ok);
    assert_eq!(h.list(root), [&b"alpha"[..], b"boot", b"srv"]);
    // On the admin connection: each connection holds at most two
    // synthetic nodes, and this test holds three at once.
    let admin = h.admin;
    let srv = h.open_on(admin, OPEN_READ, b"/srv");
    h.settle();
    assert_eq!(h.on_open(srv), (Status::Ok, Some(SYNTHETIC)));
    assert_eq!(h.list(srv), [&b"data"[..], b"web"]);

    // A relative open on a synthetic directory goes through the namespace.
    let file = h.open_at(root, OPEN_READ | OPEN_FILE, b"boot/EFI/x");
    let (flags, rest, _, server) = h.forwarded(boot_fs);
    assert_eq!(
        (flags, rest.as_slice()),
        (OPEN_READ | OPEN_FILE, &b"EFI/x"[..])
    );
    h.world.close_handle(server.handle).unwrap();
    assert!(h.peer_closed(file));
    let same = h.open_at(srv, OPEN_READ, b"");
    assert_eq!(h.on_open(same), (Status::Ok, Some(SYNTHETIC)));

    // Nothing opened through a read-only directory may write.
    let denied = h.open_at(root, OPEN_READ | OPEN_WRITE, b"boot/x");
    h.assert_refused(denied, Status::AccessDenied);
    for (flags, status) in [
        (OPEN_READ | OPEN_FILE, Status::NotDirectory),
        (OPEN_WRITE, Status::ReadOnly),
        (OPEN_WRITE | OPEN_DIRECTORY | OPEN_CREATE, Status::ReadOnly),
        (
            OPEN_WRITE | OPEN_DIRECTORY | OPEN_CREATE | OPEN_EXCLUSIVE,
            Status::Exists,
        ),
    ] {
        let refused = h.open(flags, b"/srv");
        h.assert_refused(refused, status);
    }
    for (body, status) in [
        (
            Body::Read {
                offset: 0,
                length: 1,
            },
            Status::IsDirectory,
        ),
        (
            Body::Write {
                offset: 0,
                data: b"x",
            },
            Status::IsDirectory,
        ),
        (Body::Truncate { size: 0 }, Status::IsDirectory),
        (Body::Unlink { name: b"boot" }, Status::AccessDenied),
        (Body::Sync, Status::Ok),
        (Body::ReadDir { cookie: 4 }, Status::Invalid),
    ] {
        let reply = h.request(srv, body);
        assert_eq!(
            node::parse(&reply, 0).unwrap().body,
            Body::Status { status, value: 0 },
            "{body:?}"
        );
    }
}

#[test]
fn read_only_mounts_refuse_mutation_before_the_filesystem_sees_it() {
    let mut h = Harness::new();
    let boot_fs = h.mount(b"/boot", MOUNT_READ_ONLY);
    for flags in [
        OPEN_WRITE,
        OPEN_READ | OPEN_WRITE | OPEN_FILE,
        OPEN_WRITE | OPEN_FILE | OPEN_CREATE,
        OPEN_WRITE | OPEN_TRUNCATE,
    ] {
        let refused = h.open(flags, b"/boot/x");
        h.assert_refused(refused, Status::ReadOnly);
    }
    assert_eq!(h.signals(boot_fs).0 & DW_SIGNAL_READABLE.0, 0);

    // CREATE at a mount point: it exists.
    let rw_fs = h.mount(b"/state", 0);
    let exclusive = h.open(
        OPEN_WRITE | OPEN_DIRECTORY | OPEN_CREATE | OPEN_EXCLUSIVE,
        b"/state",
    );
    h.assert_refused(exclusive, Status::Exists);
    let _plain = h.open(OPEN_WRITE | OPEN_DIRECTORY | OPEN_CREATE, b"/state");
    let (flags, rest, _, _) = h.forwarded(rw_fs);
    assert_eq!((flags, rest.len()), (OPEN_WRITE | OPEN_DIRECTORY, 0));
}

#[test]
fn only_the_admin_connection_mounts_and_the_table_is_bounded() {
    let mut h = Harness::new();
    let client = h.client;
    let (status, refused_fs) = h.mount_on(client, b"/boot", 0);
    assert_eq!(status, Status::AccessDenied);
    assert!(h.peer_closed(refused_fs), "the refused root is closed");
    assert_eq!(h.unmount(client, b"/boot"), Status::AccessDenied);

    let first = h.mount(b"/boot", 0);
    let admin = h.admin;
    let (status, duplicate) = h.mount_on(admin, b"/boot", 0);
    assert_eq!(status, Status::Exists);
    assert!(h.peer_closed(duplicate));
    let mut filesystems = vec![first];
    for index in 1..MAX_MOUNTS {
        let path = std::format!("/m{index}");
        filesystems.push(h.mount(path.as_bytes(), 0));
    }
    let (status, extra) = h.mount_on(admin, b"/full", 0);
    assert_eq!(status, Status::NoResources);
    assert!(h.peer_closed(extra));

    // A root with the wrong rights is refused and closed.
    let (root, filesystem) = h.world.create_channel(OPEN_CHANNEL_RIGHTS).unwrap();
    assert_eq!(h.unmount(admin, b"/m1"), Status::Ok);
    let bytes = h.ns_message(namespace::Body::Mount {
        flags: 0,
        path: b"/wide",
    });
    h.send(admin, &bytes, Some((root, OPEN_CHANNEL_RIGHTS)));
    h.settle();
    assert_eq!(h.ns_status(admin), Status::Invalid);
    assert!(h.peer_closed(filesystem));
}

#[test]
fn unmount_and_filesystem_exit_stop_new_opens_but_not_open_nodes() {
    let mut h = Harness::new();
    let boot_fs = h.mount(b"/boot", 0);
    let state_fs = h.mount(b"/state", 0);

    // A node opened before the unmount stays connected to its filesystem.
    let node_channel = h.open(OPEN_READ, b"/boot/a");
    let (_, _, _, server) = h.forwarded(boot_fs);
    let admin = h.admin;
    assert_eq!(h.unmount(admin, b"/boot"), Status::Ok);
    assert!(h.peer_closed(boot_fs), "vfsd closed its root Channel");
    assert!(!h.peer_closed(node_channel));
    let data = h.node_message(Body::Data(b"still here"));
    h.send(server.handle, &data, None);
    assert_eq!(h.receive(node_channel).0.len(), 40 + 10);
    assert_eq!(h.unmount(admin, b"/boot"), Status::NotFound);
    let after = h.open(OPEN_READ, b"/boot/a");
    h.assert_refused(after, Status::NotFound);

    // A filesystem that exits loses its mount.
    h.world.close_handle(state_fs).unwrap();
    h.settle();
    assert_eq!(h.vfs.mounts().iter().count(), 0);
    let gone = h.open(OPEN_READ, b"/state/x");
    h.assert_refused(gone, Status::NotFound);

    // So does one that sends anything on its root.
    let chatty_fs = h.mount(b"/chatty", 0);
    let noise = h.node_message(Body::Sync);
    h.send(chatty_fs, &noise, None);
    h.settle();
    assert!(h.peer_closed(chatty_fs));
    assert_eq!(h.vfs.mounts().iter().count(), 0);
}

#[test]
fn a_busy_filesystem_reports_busy_and_the_open_can_be_retried() {
    let mut h = Harness::new();
    let boot_fs = h.mount(b"/boot", 0);
    h.world.capacity = 1;
    let first = h.open(OPEN_READ, b"/boot/a");
    let second = h.open(OPEN_READ, b"/boot/b");
    h.assert_refused(second, Status::Busy);
    let _ = h.forwarded(boot_fs);
    let retry = h.open(OPEN_READ, b"/boot/b");
    assert_eq!(h.forwarded(boot_fs).1, b"b");
    assert!(!h.peer_closed(first) && !h.peer_closed(retry));
}

#[test]
fn malformed_requests_cost_the_sender_its_own_connection_only() {
    let mut h = Harness::new();
    let boot_fs = h.mount(b"/boot", 0);
    let (second, second_server) = h.world.create_channel(ROOT_CHANNEL_RIGHTS).unwrap();
    assert!(h.vfs.accept_client(&mut h.world, second_server));

    // An OPEN whose node Channel lacks TRANSFER: vfsd could not pass it on.
    let (node_channel, server) = h.world.create_channel(OPEN_CHANNEL_RIGHTS).unwrap();
    let bytes = h.ns_message(namespace::Body::Open {
        flags: OPEN_READ,
        path: b"/boot/x",
    });
    let narrow = DwRights(OPEN_CHANNEL_RIGHTS.0 & !DW_RIGHT_TRANSFER.0);
    h.send(second, &bytes, Some((server, narrow)));
    h.settle();
    assert!(h.peer_closed(second), "the sender's connection is dropped");
    assert!(h.peer_closed(node_channel), "the node handle is closed");

    // Garbage, a reply type, and a message too large for any WRNS buffer.
    let client = h.client;
    for bytes in [
        vec![0u8; 40],
        h.ns_message(namespace::Body::Status(Status::Ok)),
        vec![0u8; namespace::MAX_BYTES + 1],
    ] {
        let (connection, connection_server) = h.world.create_channel(ROOT_CHANNEL_RIGHTS).unwrap();
        assert!(h.vfs.accept_client(&mut h.world, connection_server));
        h.send(connection, &bytes, None);
        h.settle();
        assert!(h.peer_closed(connection));
    }

    // Everyone else is unaffected.
    let fine = h.open_on(client, OPEN_READ, b"/boot/y");
    h.settle();
    assert_eq!(h.forwarded(boot_fs).1, b"y");
    assert!(!h.peer_closed(fine));
    assert!(!h.peer_closed(h.client));
    assert!(!h.peer_closed(h.admin));

    // A synthetic node with garbage on it is dropped alone.
    let root = h.open(OPEN_READ, b"/");
    assert_eq!(h.on_open(root).0, Status::Ok);
    h.send(root, &[1, 2, 3], None);
    h.settle();
    assert!(h.peer_closed(root));
}

#[test]
fn connections_and_synthetic_nodes_are_bounded() {
    let mut h = Harness::new();
    let mut connections = Vec::new();
    for _ in 1..MAX_CLIENTS {
        let (connection, server) = h.world.create_channel(ROOT_CHANNEL_RIGHTS).unwrap();
        assert!(h.vfs.accept_client(&mut h.world, server));
        connections.push(connection);
    }
    let (spare, server) = h.world.create_channel(ROOT_CHANNEL_RIGHTS).unwrap();
    assert!(!h.vfs.accept_client(&mut h.world, server));
    assert!(h.peer_closed(spare));

    // Each connection holds at most its own share of synthetic nodes.
    let mut nodes = Vec::new();
    for _ in 0..MAX_NODES_PER_CONNECTION {
        let node_channel = h.open(OPEN_READ, b"/");
        assert_eq!(h.on_open(node_channel).0, Status::Ok);
        nodes.push(node_channel);
    }
    let refused = h.open(OPEN_READ, b"/");
    h.assert_refused(refused, Status::NoResources);
    // Closing one frees its share.
    h.world.close_handle(nodes.pop().unwrap()).unwrap();
    h.settle();
    let again = h.open(OPEN_READ, b"/");
    assert_eq!(h.on_open(again).0, Status::Ok);
    nodes.push(again);

    // Every other connection, the admin's included, still gets its full
    // share: one client cannot starve another (security review M2).
    let admin = h.admin;
    for &connection in connections.iter().chain([&admin]) {
        for _ in 0..MAX_NODES_PER_CONNECTION {
            let node_channel = h.open_on(connection, OPEN_READ, b"/");
            h.settle();
            assert_eq!(h.on_open(node_channel).0, Status::Ok);
            nodes.push(node_channel);
        }
        let refused = h.open_on(connection, OPEN_READ, b"/");
        h.settle();
        h.assert_refused(refused, Status::NoResources);
    }
    assert_eq!(nodes.len(), MAX_NODES);

    // A closed connection's nodes keep their slots: its successor in the
    // same slot is refused while the table is full of them (review L1),
    // and gets its own share once other nodes close.
    let first = connections[0];
    h.world.close_handle(first).unwrap();
    h.settle();
    let (successor, server) = h.world.create_channel(ROOT_CHANNEL_RIGHTS).unwrap();
    assert!(h.vfs.accept_client(&mut h.world, server));
    let refused = h.open_on(successor, OPEN_READ, b"/");
    h.settle();
    h.assert_refused(refused, Status::NoResources);
    h.world.close_handle(nodes.pop().unwrap()).unwrap();
    h.world.close_handle(nodes.pop().unwrap()).unwrap();
    h.settle();
    for _ in 0..MAX_NODES_PER_CONNECTION {
        let node_channel = h.open_on(successor, OPEN_READ, b"/");
        h.settle();
        assert_eq!(h.on_open(node_channel).0, Status::Ok);
    }
}

#[test]
fn extra_waits_and_admin_closure_are_returned_to_the_caller() {
    let mut h = Harness::new();
    let (outside, outside_peer) = h.world.create_channel(ROOT_CHANNEL_RIGHTS).unwrap();
    h.send(outside_peer, b"wake", None);
    let extra = [DwWaitItemV1 {
        handle: outside,
        signals: DW_SIGNAL_READABLE,
    }];
    assert_eq!(
        h.vfs.step(&mut h.world, &extra, DW_DEADLINE_INFINITE),
        Ok(Some(Event::Extra {
            index: 0,
            observed: DW_SIGNAL_READABLE,
        }))
    );

    let boot_fs = h.mount(b"/boot", 0);
    h.world.close_handle(h.admin).unwrap();
    assert_eq!(h.settle(), [Event::AdminClosed]);
    // Opens still work without an administrator.
    let _ = h.open(OPEN_READ, b"/boot/x");
    assert_eq!(h.forwarded(boot_fs).1, b"x");

    // Shutdown closes everything vfsd holds and nothing else.
    let root = h.open(OPEN_READ, b"/");
    assert!(h.vfs.shutdown(&mut h.world));
    assert!(h.peer_closed(boot_fs));
    assert!(h.peer_closed(root));
    assert!(h.peer_closed(h.client));
}

#[test]
fn a_wrong_type_handle_in_open_is_closed_with_the_connection() {
    let mut h = Harness::new();
    let event = h.world.create_event(OPEN_CHANNEL_RIGHTS).unwrap();
    let before = h.world.live_handles();
    let bytes = h.ns_message(namespace::Body::Open {
        flags: OPEN_READ,
        path: b"/",
    });
    let client = h.client;
    h.send(client, &bytes, Some((event, OPEN_CHANNEL_RIGHTS)));
    h.settle();
    assert!(h.peer_closed(client));
    // vfsd's ends of the client and the received event are both gone.
    assert_eq!(h.world.live_handles(), before - 2);
}

mod role {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::vec;
    use std::vec::Vec;

    use deepwyrm_syscall::DwHandle;
    use wyrmroot_channel_model::World;
    use wyrmroot_channel_model::fakes::{FakeRegistry, launch, stage};
    use wyrmroot_fs_proto::namespace;
    use wyrmroot_fs_proto::node::{self, ACCESS_READ, Attr, Body, Kind};
    use wyrmroot_fs_proto::{OPEN_READ, OPEN_WRITE, Status};
    use wyrmroot_registry_proto::{Header, Lookup, MessageType, ProtocolVersion, encode_lookup};
    use wyrmroot_runtime::HandlePlatform;
    use wyrmroot_service_proto::CHANNEL_READ_ONLY;
    use wyrmroot_service_proto::roles::{SLOT_MOUNT, SYSTEM_VFS, VFSD_ROLE_ID};

    use crate::role::{FAILURE_BASE, vfsd_main};

    #[derive(Default)]
    struct Seen {
        forwarded: Vec<(u32, Vec<u8>)>,
        opened: Vec<Status>,
    }

    fn ns(world: &mut World, channel: DwHandle, body: namespace::Body<'_>, handle: DwHandle) {
        let mut out = [0u8; namespace::MAX_BYTES];
        let size = namespace::encode(
            &namespace::Message {
                transaction_id: 4,
                body,
            },
            &mut out,
        )
        .unwrap();
        world.send(channel, &out[..size], &[handle]);
    }

    #[test]
    fn vfsd_mounts_what_init_stages_publishes_and_forwards_opens() {
        let mut world = World::new();
        let registry = FakeRegistry::install(&mut world);
        let launched = launch(&mut world, VFSD_ROLE_ID, 1);
        let publication = registry.publication(&mut world, SYSTEM_VFS);
        let (fs_root, mount_end) = world.pair();
        stage(
            &mut world,
            &launched,
            Some(publication),
            None,
            &[(SLOT_MOUNT, CHANNEL_READ_ONLY, b"/boot", mount_end)],
        );
        let seen = Rc::new(RefCell::new(Seen::default()));

        // The filesystem behind /boot answers every forwarded open.
        let fs_seen = seen.clone();
        world.add_peer(move |world| {
            if !world.readable(fs_root) {
                return false;
            }
            let (bytes, handles) = world.receive(fs_root);
            let message = node::parse(&bytes, handles.len()).unwrap();
            let Body::Open { flags, path, .. } = message.body else {
                panic!("vfsd sends only OPEN on a root");
            };
            fs_seen.borrow_mut().forwarded.push((flags, path.to_vec()));
            let mut out = [0u8; node::MAX_BYTES];
            let size = node::encode(
                &node::Message {
                    transaction_id: message.transaction_id,
                    body: Body::OnOpen {
                        status: Status::Ok,
                        attr: Some(Attr {
                            kind: Kind::File,
                            access: ACCESS_READ,
                            size: 1,
                            id: 2,
                            filesystem: 0,
                        }),
                    },
                },
                &mut out,
            )
            .unwrap();
            world.send(handles[0].handle, &out[..size], &[]);
            true
        });

        // A client: connect, open /boot/x, try a write, then retire vfsd.
        let (endpoint, _) = registry.client(&mut world);
        let control = launched.control;
        let client_seen = seen.clone();
        let mut step = 0;
        let mut direct = DwHandle(0);
        let mut nodes = vec![];
        world.add_peer(move |world| {
            let mut seen = client_seen.borrow_mut();
            match step {
                0 if registry.state.borrow().published(SYSTEM_VFS.name) => {
                    let (ours, theirs) = world.pair();
                    direct = ours;
                    let mut out = [0u8; 256];
                    let size = encode_lookup(
                        Header {
                            message_type: MessageType::LookupConnect,
                            registry_generation: 3,
                            endpoint_id: 1,
                            endpoint_generation: 1,
                            transaction_id: 1,
                        },
                        Lookup {
                            protocol_id: SYSTEM_VFS.protocol_id,
                            version: ProtocolVersion { major: 1, minor: 0 },
                            service_name: SYSTEM_VFS.name,
                        },
                        &mut out,
                    )
                    .unwrap();
                    world.send(endpoint, &out[..size], &[theirs]);
                }
                1 if world.readable(endpoint) => {
                    world.receive(endpoint);
                    for (flags, path) in [
                        (OPEN_READ, &b"/boot/x"[..]),
                        (OPEN_READ | OPEN_WRITE, b"/boot/x"),
                    ] {
                        let (node, server) = world.pair();
                        nodes.push(node);
                        ns(world, direct, namespace::Body::Open { flags, path }, server);
                    }
                }
                2 if nodes.iter().all(|&node| world.readable(node)) => {
                    for &node in &nodes {
                        let (bytes, _) = world.receive(node);
                        let Body::OnOpen { status, .. } = node::parse(&bytes, 0).unwrap().body
                        else {
                            panic!()
                        };
                        seen.opened.push(status);
                    }
                    let _ = world.close_handle(control);
                }
                _ => return false,
            }
            step += 1;
            true
        });

        assert_eq!(vfsd_main(&mut world, launched.bootstrap), 0);
        let seen = seen.borrow();
        assert_eq!(seen.forwarded, [(OPEN_READ, b"x".to_vec())]);
        assert_eq!(seen.opened, [Status::Ok, Status::ReadOnly]);
    }

    #[test]
    fn a_mount_label_that_is_not_an_absolute_path_is_refused() {
        let mut world = World::new();
        let registry = FakeRegistry::install(&mut world);
        let launched = launch(&mut world, VFSD_ROLE_ID, 1);
        let publication = registry.publication(&mut world, SYSTEM_VFS);
        let (_fs_root, mount_end) = world.pair();
        stage(
            &mut world,
            &launched,
            Some(publication),
            None,
            &[(SLOT_MOUNT, 0, b"boot", mount_end)],
        );
        assert_eq!(vfsd_main(&mut world, launched.bootstrap), FAILURE_BASE | 17);
        assert!(!registry.state.borrow().published(SYSTEM_VFS.name));
    }
}
