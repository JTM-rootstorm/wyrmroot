//! The VFS namespace core (root `STORAGE_PLAN.md` W5).
//!
//! `vfsd` owns one namespace: a table of mounts, each a WRFS Channel to a
//! filesystem service's root directory. A client sends WRNS OPEN with an
//! absolute path and the server end of a fresh Channel. `vfsd` picks the
//! mount whose path is the longest component-wise prefix and moves the open
//! on to that filesystem with the rest of the path; from then on the client
//! talks to the filesystem directly and `vfsd` is not on the data path
//! (platform conventions §2.4). For `/` and for directories above a mount
//! point that no mount covers, `vfsd` itself serves a read-only synthetic
//! directory that lists the names leading to mount points.
//!
//! Rules this core keeps:
//!
//! - Only the administrative connection may MOUNT or UNMOUNT.
//! - A read-only mount refuses every write, create or truncate before the
//!   filesystem sees it.
//! - UNMOUNT and a filesystem's exit stop new path opens only: nodes already
//!   open on that filesystem stay usable (platform conventions §5.3).
//! - A misbehaving client, node peer or filesystem loses only its own
//!   connection, node or mount.
//! - Every table is fixed-size; a full table answers NO_RESOURCES.
//!
//! As a service role ([`role`], storage W6) init stages vfsd its mounts as
//! labelled Channels and a publication for `system.vfs`; it has no
//! administrative connection yet, so its mounts are the boot generation's.

#![no_std]
#![forbid(unsafe_code)]

pub mod mounts;
pub mod role;
pub mod server;

pub use wyrmroot_service::{OPEN_CHANNEL_RIGHTS, ROOT_CHANNEL_RIGHTS};

#[cfg(test)]
extern crate std;
#[cfg(any(test, feature = "native-vfsd"))]
use wyrmroot_loader as _;

/// The most WRNS client connections served at once.
pub const MAX_CLIENTS: usize = wyrmroot_service_proto::roles::SYSTEM_VFS_MAX_CLIENTS;
/// The synthetic directory nodes one connection may hold open, counted
/// for as long as the nodes live, even after the connection closes.
/// Connections are never renumbered, so no client can take more than its
/// share (security review M2, 2026-11-12: jobs can now open nodes).
pub const MAX_NODES_PER_CONNECTION: usize = 2;
/// The most synthetic directory nodes open at once: one full share per
/// client slot, the admin connection's included. Nodes a closed connection
/// left open keep their slots until they close, so a new connection in a
/// refilled slot is guaranteed its share only when no such nodes are held.
/// Only resident roles can open connections, and each job has one for life
/// (2 nodes at most), so jobs alone can never fill the table (review
/// 2026-11-12, L1).
pub const MAX_NODES: usize = MAX_NODES_PER_CONNECTION * (MAX_CLIENTS + 1);
/// The most caller wait items [`server::Vfs::step`] adds to its own.
pub const MAX_EXTRA_WAITS: usize = 4;

#[cfg(test)]
mod tests;
