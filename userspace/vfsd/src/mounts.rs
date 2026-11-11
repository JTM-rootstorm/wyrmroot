//! The mount table and path resolution. Pure: no handles are opened or
//! closed here, only stored.

use deepwyrm_syscall::DwHandle;
use wyrmroot_fs_proto::{MAX_PATH_BYTES, Status};

/// The most filesystems mounted at once.
pub const MAX_MOUNTS: usize = 8;

/// One canonical absolute path, stored inline.
#[derive(Clone, Copy)]
pub struct PathBuf {
    len: usize,
    bytes: [u8; MAX_PATH_BYTES],
}

impl PathBuf {
    /// Copies a path the caller has already checked; `None` if too long.
    pub fn new(path: &[u8]) -> Option<Self> {
        let mut bytes = [0; MAX_PATH_BYTES];
        bytes.get_mut(..path.len())?.copy_from_slice(path);
        Some(Self {
            len: path.len(),
            bytes,
        })
    }

    /// `base` followed by the canonical relative `rest`: `base` itself when
    /// `rest` is empty, `None` if the result is too long.
    pub fn join(base: &[u8], rest: &[u8]) -> Option<Self> {
        if rest.is_empty() {
            return Self::new(base);
        }
        let separator: &[u8] = if base == b"/" { b"" } else { b"/" };
        let len = base.len() + separator.len() + rest.len();
        let mut bytes = [0; MAX_PATH_BYTES];
        let out = bytes.get_mut(..len)?;
        out[..base.len()].copy_from_slice(base);
        out[base.len()..base.len() + separator.len()].copy_from_slice(separator);
        out[base.len() + separator.len()..].copy_from_slice(rest);
        Some(Self { len, bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// The part of `path` below `prefix` if `prefix` is `path` or one of its
/// ancestors, component-wise: `/boot` covers `/boot/x` but not `/bootx`.
fn below<'p>(prefix: &[u8], path: &'p [u8]) -> Option<&'p [u8]> {
    if prefix == b"/" {
        return path.get(1..);
    }
    let rest = path.strip_prefix(prefix)?;
    match rest {
        [] => Some(rest),
        [b'/', rest @ ..] => Some(rest),
        _ => None,
    }
}

pub struct Mount {
    pub path: PathBuf,
    /// A WRFS Channel to the filesystem's root directory.
    pub root: DwHandle,
    pub read_only: bool,
}

/// Where an absolute path leads.
#[derive(Debug, Eq, PartialEq)]
pub enum Resolution<'p> {
    /// Into mount `index`, `rest` below its root.
    Mount {
        index: usize,
        rest: &'p [u8],
    },
    /// To `/` or to a directory above a mount point, with no mount covering
    /// it: `vfsd` serves it.
    Synthetic,
    NotFound,
}

pub struct MountTable {
    mounts: [Option<Mount>; MAX_MOUNTS],
}

impl Default for MountTable {
    fn default() -> Self {
        Self::new()
    }
}

impl MountTable {
    pub const fn new() -> Self {
        Self {
            mounts: [const { None }; MAX_MOUNTS],
        }
    }

    pub fn get(&self, index: usize) -> Option<&Mount> {
        self.mounts.get(index)?.as_ref()
    }

    /// The live mounts with their indices.
    pub fn iter(&self) -> impl Iterator<Item = (usize, &Mount)> {
        self.mounts
            .iter()
            .enumerate()
            .filter_map(|(index, mount)| Some((index, mount.as_ref()?)))
    }

    /// Adds a mount at a checked absolute `path`. On refusal the caller
    /// still owns `root`.
    pub fn add(&mut self, path: &[u8], root: DwHandle, read_only: bool) -> Result<usize, Status> {
        if self.iter().any(|(_, mount)| mount.path.as_bytes() == path) {
            return Err(Status::Exists);
        }
        let path = PathBuf::new(path).ok_or(Status::InvalidPath)?;
        let (index, slot) = self
            .mounts
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.is_none())
            .ok_or(Status::NoResources)?;
        *slot = Some(Mount {
            path,
            root,
            read_only,
        });
        Ok(index)
    }

    /// Removes the mount at `path`, returning its root for the caller to close.
    pub fn remove_path(&mut self, path: &[u8]) -> Option<DwHandle> {
        let slot = self
            .mounts
            .iter_mut()
            .find(|slot| slot.as_ref().is_some_and(|m| m.path.as_bytes() == path))?;
        slot.take().map(|mount| mount.root)
    }

    /// Removes mount `index`, returning its root for the caller to close.
    pub fn remove(&mut self, index: usize) -> Option<DwHandle> {
        self.mounts.get_mut(index)?.take().map(|mount| mount.root)
    }

    /// Resolves a checked absolute path: the longest covering mount wins.
    pub fn resolve<'p>(&self, path: &'p [u8]) -> Resolution<'p> {
        let best = self
            .iter()
            .filter_map(|(index, mount)| {
                let rest = below(mount.path.as_bytes(), path)?;
                Some((mount.path.len, index, rest))
            })
            .max_by_key(|&(len, _, _)| len);
        if let Some((_, index, rest)) = best {
            Resolution::Mount { index, rest }
        } else if path == b"/" || self.children(path).next().is_some() {
            Resolution::Synthetic
        } else {
            Resolution::NotFound
        }
    }

    /// The names directly below the synthetic directory `dir` that lead to
    /// mount points, unsorted and possibly repeated.
    fn children<'a>(&'a self, dir: &[u8]) -> impl Iterator<Item = &'a [u8]> {
        self.iter().filter_map(move |(_, mount)| {
            let rest = below(dir, mount.path.as_bytes())?;
            let name = rest.split(|&byte| byte == b'/').next()?;
            (!name.is_empty()).then_some(name)
        })
    }

    /// The listing of synthetic directory `dir`: distinct names in byte
    /// order. Positions in it are READ_DIR cookies, so a listing that spans
    /// a MOUNT or UNMOUNT may skip or repeat a name.
    pub fn listing<'a>(&'a self, dir: &[u8], out: &mut [&'a [u8]; MAX_MOUNTS]) -> usize {
        let mut count = 0;
        for name in self.children(dir) {
            if !out[..count].contains(&name) {
                out[count] = name;
                count += 1;
            }
        }
        out[..count].sort_unstable();
        count
    }
}
