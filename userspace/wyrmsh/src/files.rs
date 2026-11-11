// SPDX-License-Identifier: GPL-3.0-or-later

//! `ls` and `cat` over the VFS namespace (root `STORAGE_PLAN.md` W6).
//!
//! Each command connects to `system.vfs` through the shell's registry
//! client, opens its path with WRNS and then talks WRFS to whichever
//! filesystem serves the node. A missing service, a refused open or a
//! failed read is reported on stderr as one line and the shell carries on;
//! only a failure of the shell's own console streams is an error.

use deepwyrm_syscall::{DW_HANDLE_TRANSFER_MOVE, DW_RIGHT_TRANSFER, DW_STATUS_TIMED_OUT};
use wyrmroot_fs_proto::namespace;
use wyrmroot_fs_proto::node::{self, Attr, Body, Kind, MAX_IO_BYTES};
use wyrmroot_fs_proto::{OPEN_FILE, OPEN_READ, Status};
use wyrmroot_registry_proto::{
    Header as RegistryHeader, Lookup, Message as RegistryMessage,
    MessageType as RegistryMessageType, ProtocolVersion, encode_lookup, parse as parse_registry,
};
use wyrmroot_service_proto::roles::SYSTEM_VFS;
use wyrmroot_wyrmsh_core::{MAX_FS_PATH_BYTES, normalize_fs_path};

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
    let mut bytes = [0u8; 64];
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
    let opened = open(system, vfs, flags, &canonical[..length])?;
    // The node is now the filesystem's; vfsd is not needed again.
    let _ = system.close_handle(vfs);
    match opened {
        Ok((node, attr)) => Ok(Some((node, attr, length))),
        Err(failure) => {
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
    let _ = system.close_handle(node);
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
    let _ = system.close_handle(node);
    result
}
