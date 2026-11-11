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
//! The service's launch, registry publication and admin wiring come with
//! its first live use (storage W6).

#![no_std]
#![forbid(unsafe_code)]

use deepwyrm_syscall::{
    DW_RIGHT_INSPECT, DW_RIGHT_READ, DW_RIGHT_TRANSFER, DW_RIGHT_WAIT, DW_RIGHT_WRITE, DwRights,
};

pub mod mounts;
pub mod server;

#[cfg(test)]
extern crate std;

/// The most WRNS client connections served at once.
pub const MAX_CLIENTS: usize = 8;
/// The most synthetic directory nodes open at once.
pub const MAX_NODES: usize = 8;
/// The most caller wait items [`server::Vfs::step`] adds to its own.
pub const MAX_EXTRA_WAITS: usize = 4;

/// The rights a node Channel's server end carries in every OPEN, WRNS or
/// WRFS: a Channel endpoint's rights plus TRANSFER, so that whoever receives
/// it can pass it on unchanged. A forwarder requests exactly these again.
pub const OPEN_CHANNEL_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_TRANSFER.0,
);
/// The rights of a filesystem root Channel that MOUNT carries; vfsd keeps it.
pub const ROOT_CHANNEL_RIGHTS: DwRights =
    DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0);

#[cfg(test)]
mod tests;
