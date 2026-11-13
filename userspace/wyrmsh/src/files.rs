// SPDX-License-Identifier: GPL-3.0-or-later

//! `ls`, `cat` (root `STORAGE_PLAN.md` W6) and `write`, `mkdir`, `rm` (W7)
//! over the VFS namespace. Each change is followed by SYNC, so it is durable
//! when the prompt returns.
//!
//! Each command connects to `system.vfs` through the shell's registry
//! client, opens its path with WRNS and then talks WRFS to whichever
//! filesystem serves the node. A missing service, a refused open or a
//! failed read is reported on stderr as one line and the shell carries on;
//! only a failure of the shell's own console streams is an error.

use deepwyrm_syscall::{DW_HANDLE_TRANSFER_MOVE, DW_RIGHT_TRANSFER, DW_STATUS_TIMED_OUT};
use wyrmroot_fs_proto::namespace;
use wyrmroot_fs_proto::node::{self, Attr, Body, Kind, MAX_IO_BYTES};
use wyrmroot_fs_proto::{
    OPEN_CREATE, OPEN_DIRECTORY, OPEN_EXCLUSIVE, OPEN_FILE, OPEN_READ, OPEN_TRUNCATE, OPEN_WRITE,
    Status,
};
use wyrmroot_registry_proto::{
    Header as RegistryHeader, Lookup, Message as RegistryMessage,
    MessageType as RegistryMessageType, ProtocolVersion, encode_lookup, parse as parse_registry,
};
use wyrmroot_service_proto::roles::SYSTEM_VFS;
use wyrmroot_wyrmsh_core::{Arguments, MAX_FS_PATH_BYTES, normalize_fs_path};

use crate::*;

/// A node or connection end that is moved on once more: the registry moves
/// the connection to vfsd, and vfsd moves an open to the filesystem.
const PASS_ON_RIGHTS: DwRights = DwRights(CHILD_CHANNEL_RIGHTS.0 | DW_RIGHT_TRANSFER.0);

/// What went wrong, as the line the user sees.
type Failure = &'static [u8];

fn status_text(status: Status) -> Failure {
    match status {
        Status::Ok => b"ok",
        Status::NotFound => b"not found",
        Status::Exists => b"already exists",
        Status::NotDirectory => b"not a directory",
        Status::IsDirectory => b"is a directory",
        Status::AccessDenied => b"access denied",
        Status::ReadOnly => b"read-only",
        Status::NoSpace => b"no space",
        Status::InvalidPath => b"invalid path",
        Status::Invalid => b"invalid request",
        Status::NotSupported => b"not supported",
        Status::IoError => b"I/O error",
        Status::NotEmpty => b"not empty",
        Status::NoResources => b"no resources",
        Status::Busy => b"busy",
        Status::Deadlock => b"deadlock",
    }
}

/// The shell's outputs, for the helpers below.
pub(crate) struct Console<'a> {
    pub(crate) stdout: &'a mut NativeOutput,
    pub(crate) stderr: &'a mut NativeOutput,
    pub(crate) controls: Controls,
}

impl Console<'_> {
    fn out<System: WyrmshSystem>(
        &mut self,
        system: &mut System,
        bytes: &[u8],
    ) -> Result<(), ShellError> {
        write_stdout(
            system,
            self.stdout,
            self.stderr.endpoint().handle(),
            self.controls,
            bytes,
        )
    }

    fn fail<System: WyrmshSystem>(
        &mut self,
        system: &mut System,
        command: &str,
        path: &[u8],
        reason: Failure,
    ) -> Result<(), ShellError> {
        let stdout = self.stdout.endpoint().handle();
        for part in [command.as_bytes(), b": ", path, b": ", reason, b"\n"] {
            write_stderr(system, self.stderr, stdout, self.controls, part)?;
        }
        Ok(())
    }
}

/// Connects to `system.vfs`; the client end of the new connection.
fn connect<System: WyrmshSystem>(
    system: &mut System,
    console: &mut Console<'_>,
    identity: ShellIdentity,
    transactions: &mut TransactionIds,
) -> Result<Result<DwHandle, Failure>, ShellError> {
    let Ok(transaction) = transactions.registry() else {
        return Ok(Err(b"no registry transaction left"));
    };
    let (direct, remote) = system
        .create_channel(PASS_ON_RIGHTS)
        .map_err(|cause| native(NativeOperation::ControlSend, cause))?;
    let header = RegistryHeader {
        message_type: RegistryMessageType::LookupConnect,
        registry_generation: identity.registry_generation,
        endpoint_id: identity.registry_endpoint_id,
        endpoint_generation: identity.registry_endpoint_generation,
        transaction_id: transaction,
    };
    let mut bytes = [0u8; 256];
    let Ok(size) = encode_lookup(
        header,
        Lookup {
            protocol_id: SYSTEM_VFS.protocol_id,
            version: ProtocolVersion {
                major: SYSTEM_VFS.major,
                minor: SYSTEM_VFS.minor,
            },
            service_name: SYSTEM_VFS.name,
        },
        &mut bytes,
    ) else {
        let _ = system.close_handle(direct);
        let _ = system.close_handle(remote);
        return Ok(Err(b"cannot encode the lookup"));
    };
    let transfer = DwHandleTransferV1 {
        handle: remote,
        requested_rights: PASS_ON_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if system
        .send_channel_with_handles(console.controls.registry, &bytes[..size], &[transfer])
        .is_err()
    {
        let _ = system.close_handle(direct);
        let _ = system.close_handle(remote);
        return Ok(Err(b"the registry is unavailable"));
    }
    let deadline = control_deadline(system)?;
    let used = receive_control(
        system,
        console.controls.registry,
        EndpointRole::Registry,
        console.controls,
        console.stdout.endpoint().handle(),
        console.stderr.endpoint().handle(),
        &mut bytes,
        deadline,
    );
    let reply = used
        .ok()
        .and_then(|used| parse_registry(&bytes[..used], 0).ok());
    match reply {
        Some(reply)
            if reply.message == RegistryMessage::Connected
                && reply.header
                    == (RegistryHeader {
                        message_type: RegistryMessageType::Connected,
                        ..header
                    }) =>
        {
            Ok(Ok(direct))
        }
        _ => {
            let _ = system.close_handle(direct);
            Ok(Err(b"system.vfs is not available"))
        }
    }
}

/// How long [`close_node`] waits for the server to close its end.
const CLOSE_WAIT_NS: u64 = 1_000_000_000;

/// Ends an opened node with WRFS 1.3 CLOSE and closes its Channel.
///
/// The server drops the node, with its locks, and closes its end; waiting
/// for that means the job's charge for both ends is gone when this returns,
/// so a command that opens again straight after cannot run out of Channels.
/// A server that has not closed its end by [`CLOSE_WAIT_NS`] still drops
/// the node once it sees this end close. The POSIX layer's `node::close`
/// does the same.
fn close_node<System: WyrmshSystem>(system: &mut System, channel: DwHandle) {
    let mut bytes = [0u8; node::MAX_BYTES];
    let sent = node::encode(
        &node::Message {
            transaction_id: 1,
            body: Body::Close,
        },
        &mut bytes,
    )
    .ok()
    .is_some_and(|size| system.send_channel(channel, &bytes[..size]).is_ok());
    if sent && let Ok(now) = system.monotonic_active_now() {
        let item = DwWaitItemV1 {
            handle: channel,
            signals: DW_SIGNAL_PEER_CLOSED,
        };
        let _ = system.wait_many(
            core::slice::from_ref(&item),
            DwDeadline(now.saturating_add(CLOSE_WAIT_NS)),
        );
    }
    let _ = system.close_handle(channel);
}

/// Waits for one message on `channel` and returns its length.
fn receive<System: WyrmshSystem>(
    system: &mut System,
    channel: DwHandle,
    bytes: &mut [u8],
) -> Result<Result<usize, Failure>, ShellError> {
    let deadline = control_deadline(system)?;
    let item = DwWaitItemV1 {
        handle: channel,
        signals: DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
    };
    match system.wait_many(core::slice::from_ref(&item), deadline) {
        Ok(result) if result.observed.0 & DW_SIGNAL_READABLE.0 != 0 => {}
        Ok(_) => return Ok(Err(b"the filesystem went away")),
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {
            return Ok(Err(b"timed out"));
        }
        Err(cause) => return Err(native(NativeOperation::Wait, cause)),
    }
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    match system.receive_channel(channel, bytes, &mut handles) {
        Ok(counts) if counts.handles == 0 && counts.bytes <= bytes.len() => Ok(Ok(counts.bytes)),
        Ok(counts) => {
            for info in &handles[..counts.handles.min(1)] {
                let _ = system.close_handle(info.handle);
            }
            Ok(Err(b"malformed reply"))
        }
        Err(_) => Ok(Err(b"the filesystem went away")),
    }
}

/// Opens `path` through vfsd; the node's Channel and attributes.
fn open<System: WyrmshSystem>(
    system: &mut System,
    vfs: DwHandle,
    flags: u32,
    path: &[u8],
) -> Result<Result<(DwHandle, Attr), Failure>, ShellError> {
    let (node, server) = system
        .create_channel(PASS_ON_RIGHTS)
        .map_err(|cause| native(NativeOperation::ControlSend, cause))?;
    let mut bytes = [0u8; namespace::MAX_BYTES];
    let Ok(size) = namespace::encode(
        &namespace::Message {
            transaction_id: 1,
            body: namespace::Body::Open { flags, path },
        },
        &mut bytes,
    ) else {
        let _ = system.close_handle(node);
        let _ = system.close_handle(server);
        return Ok(Err(b"invalid path"));
    };
    let transfer = DwHandleTransferV1 {
        handle: server,
        requested_rights: PASS_ON_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if system
        .send_channel_with_handles(vfs, &bytes[..size], &[transfer])
        .is_err()
    {
        let _ = system.close_handle(node);
        let _ = system.close_handle(server);
        return Ok(Err(b"system.vfs went away"));
    }
    let mut reply = [0u8; node::MAX_BYTES];
    let outcome = match receive(system, node, &mut reply)? {
        Ok(used) => match node::parse(&reply[..used], 0).map(|message| message.body) {
            Ok(Body::OnOpen {
                status: Status::Ok,
                attr: Some(attr),
            }) => Ok((node, attr)),
            Ok(Body::OnOpen { status, .. }) => Err(status_text(status)),
            _ => Err(&b"malformed reply"[..]),
        },
        Err(failure) => Err(failure),
    };
    if outcome.is_err() {
        let _ = system.close_handle(node);
    }
    Ok(outcome)
}

/// Sends one WRFS request and receives its reply into `reply`.
fn request<System: WyrmshSystem>(
    system: &mut System,
    channel: DwHandle,
    transaction_id: u64,
    body: Body<'_>,
    reply: &mut [u8; node::MAX_BYTES],
) -> Result<Result<usize, Failure>, ShellError> {
    let mut bytes = [0u8; node::MAX_BYTES];
    let Ok(size) = node::encode(
        &node::Message {
            transaction_id,
            body,
        },
        &mut bytes,
    ) else {
        return Ok(Err(b"cannot encode the request"));
    };
    if system.send_channel(channel, &bytes[..size]).is_err() {
        return Ok(Err(b"the filesystem went away"));
    }
    let used = match receive(system, channel, reply)? {
        Ok(used) => used,
        Err(failure) => return Ok(Err(failure)),
    };
    match node::parse(&reply[..used], 0) {
        Ok(message) if message.transaction_id == transaction_id => Ok(Ok(used)),
        _ => Ok(Err(b"malformed reply")),
    }
}

/// Normalizes, connects and opens; the node, or a reported failure.
#[allow(
    clippy::too_many_arguments,
    reason = "explicit shell capability custody"
)]
fn open_path<System: WyrmshSystem>(
    system: &mut System,
    console: &mut Console<'_>,
    identity: ShellIdentity,
    transactions: &mut TransactionIds,
    command: &str,
    typed: &str,
    flags: u32,
    canonical: &mut [u8; MAX_FS_PATH_BYTES],
) -> Result<Option<(DwHandle, Attr, usize)>, ShellError> {
    let opened = open_path_keeping_vfs(
        system,
        console,
        identity,
        transactions,
        command,
        typed,
        flags,
        canonical,
    )?;
    Ok(opened.map(|(node, attr, length, vfs)| {
        // The node is now the filesystem's; vfsd is not needed again.
        let _ = system.close_handle(vfs);
        (node, attr, length)
    }))
}

/// [`open_path`], but the `system.vfs` connection stays open and is
/// returned after the node.
#[allow(
    clippy::too_many_arguments,
    reason = "explicit shell capability custody"
)]
fn open_path_keeping_vfs<System: WyrmshSystem>(
    system: &mut System,
    console: &mut Console<'_>,
    identity: ShellIdentity,
    transactions: &mut TransactionIds,
    command: &str,
    typed: &str,
    flags: u32,
    canonical: &mut [u8; MAX_FS_PATH_BYTES],
) -> Result<Option<(DwHandle, Attr, usize, DwHandle)>, ShellError> {
    let Ok(length) = normalize_fs_path(typed, canonical) else {
        console.fail(system, command, typed.as_bytes(), b"not an absolute path")?;
        return Ok(None);
    };
    let vfs = match connect(system, console, identity, transactions)? {
        Ok(vfs) => vfs,
        Err(failure) => {
            console.fail(system, command, typed.as_bytes(), failure)?;
            return Ok(None);
        }
    };
    let opened = match open(system, vfs, flags, &canonical[..length]) {
        Ok(opened) => opened,
        Err(error) => {
            let _ = system.close_handle(vfs);
            return Err(error);
        }
    };
    match opened {
        Ok((node, attr)) => Ok(Some((node, attr, length, vfs))),
        Err(failure) => {
            let _ = system.close_handle(vfs);
            console.fail(system, command, &canonical[..length], failure)?;
            Ok(None)
        }
    }
}

/// `ls [path]`: one name per line, directories with a trailing `/`.
pub(crate) fn list<System: WyrmshSystem>(
    system: &mut System,
    mut console: Console<'_>,
    identity: ShellIdentity,
    transactions: &mut TransactionIds,
    typed: &str,
) -> Result<(), ShellError> {
    let mut canonical = [0u8; MAX_FS_PATH_BYTES];
    let Some((node, attr, length)) = open_path(
        system,
        &mut console,
        identity,
        transactions,
        "ls",
        typed,
        OPEN_READ,
        &mut canonical,
    )?
    else {
        return Ok(());
    };
    let result = (|| {
        if attr.kind == Kind::File {
            console.out(system, &canonical[..length])?;
            return console.out(system, b"\n");
        }
        let mut reply = [0u8; node::MAX_BYTES];
        let mut cookie = 0;
        for transaction in 1u64.. {
            let used = match request(
                system,
                node,
                transaction,
                Body::ReadDir { cookie },
                &mut reply,
            )? {
                Ok(used) => used,
                Err(failure) => return console.fail(system, "ls", &canonical[..length], failure),
            };
            let (next_cookie, entries) = match node::parse(&reply[..used], 0).map(|m| m.body) {
                Ok(Body::Dirents {
                    next_cookie,
                    entries,
                }) => (next_cookie, entries),
                Ok(Body::Status { status, .. }) => {
                    return console.fail(system, "ls", &canonical[..length], status_text(status));
                }
                _ => return console.fail(system, "ls", &canonical[..length], b"malformed reply"),
            };
            for (kind, name) in entries.iter() {
                console.out(system, name)?;
                console.out(
                    system,
                    if kind == Kind::Directory {
                        b"/\n"
                    } else {
                        b"\n"
                    },
                )?;
            }
            if next_cookie == 0 {
                break;
            }
            cookie = next_cookie;
        }
        Ok(())
    })();
    close_node(system, node);
    result
}

/// `cat path`: the file's bytes, unchanged, on stdout.
pub(crate) fn cat<System: WyrmshSystem>(
    system: &mut System,
    mut console: Console<'_>,
    identity: ShellIdentity,
    transactions: &mut TransactionIds,
    typed: &str,
) -> Result<(), ShellError> {
    let mut canonical = [0u8; MAX_FS_PATH_BYTES];
    let Some((node, _, length)) = open_path(
        system,
        &mut console,
        identity,
        transactions,
        "cat",
        typed,
        OPEN_READ | OPEN_FILE,
        &mut canonical,
    )?
    else {
        return Ok(());
    };
    let result = (|| {
        let mut reply = [0u8; node::MAX_BYTES];
        let mut offset = 0u64;
        for transaction in 1u64.. {
            let body = Body::Read {
                offset,
                length: MAX_IO_BYTES as u32,
            };
            let used = match request(system, node, transaction, body, &mut reply)? {
                Ok(used) => used,
                Err(failure) => return console.fail(system, "cat", &canonical[..length], failure),
            };
            match node::parse(&reply[..used], 0).map(|m| m.body) {
                Ok(Body::Data([])) => break,
                Ok(Body::Data(data)) => {
                    console.out(system, data)?;
                    offset += data.len() as u64;
                }
                Ok(Body::Status { status, .. }) => {
                    return console.fail(system, "cat", &canonical[..length], status_text(status));
                }
                _ => return console.fail(system, "cat", &canonical[..length], b"malformed reply"),
            }
        }
        Ok(())
    })();
    close_node(system, node);
    result
}

/// `run /path`: opens the file for a LAUNCH_IMAGE. Returns the node, the
/// `system.vfs` connection it was opened through, which the job receives as
/// its namespace (root `TOOLCHAIN_POSIX_LAYER_DESIGN.md` W5), and the length
/// of the canonical path in `canonical`; or `None` once a failure has been
/// reported. The launch names the file by its canonical path without the
/// leading slash, so that path must fit WRLJ: ASCII and at most 256 bytes.
pub(crate) fn open_for_run<System: WyrmshSystem>(
    system: &mut System,
    mut console: Console<'_>,
    identity: ShellIdentity,
    transactions: &mut TransactionIds,
    typed: &str,
    canonical: &mut [u8; MAX_FS_PATH_BYTES],
) -> Result<Option<(DwHandle, DwHandle, usize)>, ShellError> {
    let Some((node, _, length, vfs)) = open_path_keeping_vfs(
        system,
        &mut console,
        identity,
        transactions,
        "run",
        typed,
        OPEN_READ | OPEN_FILE,
        canonical,
    )?
    else {
        return Ok(None);
    };
    let display = &canonical[1..length];
    if display.is_empty()
        || display.len() > wyrmroot_launch_proto::MAX_PATH_BYTES
        || !display.is_ascii()
    {
        close_node(system, node);
        let _ = system.close_handle(vfs);
        console.fail(
            system,
            "run",
            &canonical[..length],
            b"path is not launchable",
        )?;
        return Ok(None);
    }
    Ok(Some((node, vfs, length)))
}

/// Sends `body` and expects STATUS: its status and value.
fn status_request<System: WyrmshSystem>(
    system: &mut System,
    channel: DwHandle,
    transaction_id: u64,
    body: Body<'_>,
) -> Result<Result<(Status, u64), Failure>, ShellError> {
    let mut reply = [0u8; node::MAX_BYTES];
    let used = match request(system, channel, transaction_id, body, &mut reply)? {
        Ok(used) => used,
        Err(failure) => return Ok(Err(failure)),
    };
    Ok(match node::parse(&reply[..used], 0).map(|m| m.body) {
        Ok(Body::Status { status, value }) => Ok((status, value)),
        _ => Err(b"malformed reply"),
    })
}

/// Makes the node's filesystem durable; a failure is reported.
fn sync<System: WyrmshSystem>(
    system: &mut System,
    console: &mut Console<'_>,
    command: &str,
    node: DwHandle,
    transaction_id: u64,
    path: &[u8],
) -> Result<(), ShellError> {
    match status_request(system, node, transaction_id, Body::Sync)? {
        Ok((Status::Ok, _)) => Ok(()),
        Ok((status, _)) => console.fail(system, command, path, status_text(status)),
        Err(failure) => console.fail(system, command, path, failure),
    }
}

/// `write path [text...]`: replaces the file's contents with the text, its
/// words joined by spaces and ended by a newline, creating the file if need
/// be.
pub(crate) fn write<System: WyrmshSystem>(
    system: &mut System,
    mut console: Console<'_>,
    identity: ShellIdentity,
    transactions: &mut TransactionIds,
    typed: &str,
    text: Arguments<'_>,
) -> Result<(), ShellError> {
    let mut contents = [0u8; MAX_IO_BYTES];
    let mut used = 0;
    for (index, word) in text.iter().enumerate() {
        let separator = usize::from(index > 0);
        if used + separator + word.len() + 1 > contents.len() {
            return console.fail(system, "write", typed.as_bytes(), b"text too long");
        }
        if separator == 1 {
            contents[used] = b' ';
        }
        contents[used + separator..used + separator + word.len()].copy_from_slice(word.as_bytes());
        used += separator + word.len();
    }
    contents[used] = b'\n';
    used += 1;
    let mut canonical = [0u8; MAX_FS_PATH_BYTES];
    let Some((node, _, length)) = open_path(
        system,
        &mut console,
        identity,
        transactions,
        "write",
        typed,
        OPEN_WRITE | OPEN_FILE | OPEN_CREATE | OPEN_TRUNCATE,
        &mut canonical,
    )?
    else {
        return Ok(());
    };
    let path = &canonical[..length];
    let result = (|| {
        let body = Body::Write {
            offset: 0,
            data: &contents[..used],
        };
        match status_request(system, node, 1, body)? {
            Ok((Status::Ok, written)) if written == used as u64 => {}
            Ok((Status::Ok, _)) => return console.fail(system, "write", path, b"short write"),
            Ok((status, _)) => return console.fail(system, "write", path, status_text(status)),
            Err(failure) => return console.fail(system, "write", path, failure),
        }
        sync(system, &mut console, "write", node, 2, path)
    })();
    close_node(system, node);
    result
}

/// `mkdir path`: creates the directory; it must not exist.
pub(crate) fn mkdir<System: WyrmshSystem>(
    system: &mut System,
    mut console: Console<'_>,
    identity: ShellIdentity,
    transactions: &mut TransactionIds,
    typed: &str,
) -> Result<(), ShellError> {
    let mut canonical = [0u8; MAX_FS_PATH_BYTES];
    let Some((node, _, length)) = open_path(
        system,
        &mut console,
        identity,
        transactions,
        "mkdir",
        typed,
        OPEN_READ | OPEN_DIRECTORY | OPEN_CREATE | OPEN_EXCLUSIVE,
        &mut canonical,
    )?
    else {
        return Ok(());
    };
    let result = sync(system, &mut console, "mkdir", node, 1, &canonical[..length]);
    close_node(system, node);
    result
}

/// `rm path`: removes a file, or a directory that is empty, through its
/// parent directory.
pub(crate) fn remove<System: WyrmshSystem>(
    system: &mut System,
    mut console: Console<'_>,
    identity: ShellIdentity,
    transactions: &mut TransactionIds,
    typed: &str,
) -> Result<(), ShellError> {
    let mut canonical = [0u8; MAX_FS_PATH_BYTES];
    let Ok(length) = normalize_fs_path(typed, &mut canonical) else {
        return console.fail(system, "rm", typed.as_bytes(), b"not an absolute path");
    };
    if length == 1 {
        return console.fail(system, "rm", b"/", b"cannot remove the root");
    }
    // The parent is everything before the last slash, or `/`.
    let slash = canonical[..length]
        .iter()
        .rposition(|&byte| byte == b'/')
        .unwrap_or(0);
    let mut name = [0u8; 255];
    let name_length = length - slash - 1;
    name[..name_length].copy_from_slice(&canonical[slash + 1..length]);
    let mut parent_text = [0u8; MAX_FS_PATH_BYTES];
    let parent_length = slash.max(1);
    parent_text[..parent_length].copy_from_slice(&canonical[..parent_length]);
    let Ok(parent) = core::str::from_utf8(&parent_text[..parent_length]) else {
        return console.fail(system, "rm", &canonical[..length], b"invalid path");
    };
    let mut parent_canonical = [0u8; MAX_FS_PATH_BYTES];
    let Some((node, _, _)) = open_path(
        system,
        &mut console,
        identity,
        transactions,
        "rm",
        parent,
        OPEN_READ | OPEN_WRITE | OPEN_DIRECTORY,
        &mut parent_canonical,
    )?
    else {
        return Ok(());
    };
    let path = &canonical[..length];
    let result = (|| {
        let body = Body::Unlink {
            name: &name[..name_length],
        };
        match status_request(system, node, 1, body)? {
            Ok((Status::Ok, _)) => {}
            Ok((status, _)) => return console.fail(system, "rm", path, status_text(status)),
            Err(failure) => return console.fail(system, "rm", path, failure),
        }
        sync(system, &mut console, "rm", node, 2, path)
    })();
    close_node(system, node);
    result
}
