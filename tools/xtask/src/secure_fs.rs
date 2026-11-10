//! Small Linux descriptor-relative filesystem boundary for immutable products.

use std::{
    ffi::{CString, c_char, c_int, c_uint},
    fs::{File, Metadata},
    io::{Read, Seek, SeekFrom, Write},
    os::fd::{AsRawFd, FromRawFd},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Component, Path, PathBuf},
};

use crate::{error::Failure, sha256};

const O_RDONLY: c_int = 0;
const O_CLOEXEC: c_int = 0o2_000_000;
const O_DIRECTORY: c_int = 0o200_000;
pub(crate) const O_NOFOLLOW: c_int = 0o400_000;
pub(crate) const O_NONBLOCK: c_int = 0o4_000;
const O_PATH: c_int = 0o10_000_000;
const F_DUPFD: c_int = 0;
const F_GETFD: c_int = 1;
const F_SETFD: c_int = 2;
const FD_CLOEXEC: c_int = 1;
const F_ADD_SEALS: c_int = 1033;
const F_GET_SEALS: c_int = 1034;
const F_SEAL_SEAL: c_int = 0x0001;
const F_SEAL_SHRINK: c_int = 0x0002;
const F_SEAL_GROW: c_int = 0x0004;
const F_SEAL_WRITE: c_int = 0x0008;
const REQUIRED_SEALS: c_int = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
const MFD_CLOEXEC: c_uint = 0x0001;
const MFD_ALLOW_SEALING: c_uint = 0x0002;

unsafe extern "C" {
    fn openat(dirfd: c_int, pathname: *const c_char, flags: c_int, ...) -> c_int;
    fn mkdirat(dirfd: c_int, pathname: *const c_char, mode: c_uint) -> c_int;
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    fn memfd_create(name: *const c_char, flags: c_uint) -> c_int;
}

pub(crate) struct Directory {
    file: File,
}

impl Directory {
    pub(crate) fn open_exact(path: &Path, label: &str) -> Result<Self, Failure> {
        if !path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err(Failure::task(format!(
                "{label} path is not canonical absolute"
            )));
        }
        let mut file = open_directory_at(None, b"/", "filesystem root")?;
        for part in path.components() {
            let Component::Normal(name) = part else {
                continue;
            };
            file = open_directory_at(Some(file.as_raw_fd()), name.as_bytes(), label)?;
        }
        Ok(Self { file })
    }

    pub(crate) fn read_producer(
        &self,
        relative: &Path,
        maximum: u64,
        label: &str,
    ) -> Result<Vec<u8>, Failure> {
        read_producer_at(self.file.as_raw_fd(), relative, maximum, label, || {})
    }
}

pub(crate) struct InheritableDirectory {
    file: File,
    anchor: PathBuf,
    identity: (u64, u64),
}

impl InheritableDirectory {
    pub(crate) fn path(&self) -> &Path {
        &self.anchor
    }

    pub(crate) fn verify_unchanged(&self, label: &str) -> Result<(), Failure> {
        let metadata = self
            .file
            .metadata()
            .map_err(|error| Failure::task(format!("could not recheck {label}: {error}")))?;
        if !metadata.is_dir() || object_identity(&metadata) != self.identity {
            return Err(Failure::task(format!(
                "{label} retained directory identity changed"
            )));
        }
        Ok(())
    }

    pub(crate) fn read_producer(
        &self,
        relative: &Path,
        maximum: u64,
        label: &str,
    ) -> Result<Vec<u8>, Failure> {
        self.verify_unchanged(label)?;
        read_producer_at(self.file.as_raw_fd(), relative, maximum, label, || {})
    }

    pub(crate) fn with_inheritance_disabled<T>(
        &self,
        label: &str,
        operation: impl FnOnce() -> Result<T, Failure>,
    ) -> Result<T, Failure> {
        // SAFETY: fcntl only reads or updates descriptor flags on this live fd.
        let original = unsafe { fcntl(self.file.as_raw_fd(), F_GETFD) };
        if original < 0
            || unsafe { fcntl(self.file.as_raw_fd(), F_SETFD, original | FD_CLOEXEC) } != 0
        {
            return Err(Failure::task(format!(
                "could not restrict {label} inheritance: {}",
                std::io::Error::last_os_error()
            )));
        }
        let result = operation();
        // SAFETY: restore the exact descriptor flags observed above.
        let restored = unsafe { fcntl(self.file.as_raw_fd(), F_SETFD, original) };
        if restored != 0 {
            return Err(Failure::task(format!(
                "could not restore {label} inheritance: {}",
                std::io::Error::last_os_error()
            )));
        }
        self.verify_unchanged(label)?;
        result
    }

    pub(crate) fn create_inheritable_child(
        &self,
        path: &Path,
        label: &str,
    ) -> Result<InheritableDirectory, Failure> {
        if path.parent() != Some(self.anchor.as_path()) {
            return Err(Failure::task(format!(
                "{label} is not a direct child of the retained scratch directory"
            )));
        }
        let name = path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| Failure::task(format!("{label} name is not UTF-8")))?;
        let name = component(name, label)?;
        // SAFETY: name is NUL-terminated and the inherited scratch fd remains
        // live for this call and subsequent child execution.
        if unsafe { mkdirat(self.file.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(Failure::task(format!(
                "could not create {label}: {}",
                std::io::Error::last_os_error()
            )));
        }
        let child = open_directory_at(Some(self.file.as_raw_fd()), name.as_bytes(), label)?;
        let child_metadata = child
            .metadata()
            .map_err(|error| Failure::task(format!("could not stat {label}: {error}")))?;
        if !child_metadata.is_dir() {
            return Err(Failure::task(format!("{label} is not a real directory")));
        }
        // SAFETY: fcntl borrows the live child fd and returns a fresh fd. The
        // non-CLOEXEC duplicate is intentionally scoped to the returned
        // authority so spawned build tools can traverse its procfd anchor.
        let duplicate = unsafe { fcntl(child.as_raw_fd(), F_DUPFD, 3) };
        if duplicate < 0 {
            return Err(Failure::task(format!(
                "could not retain {label}: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: F_DUPFD returned a fresh owned descriptor without CLOEXEC.
        let inherited = unsafe { File::from_raw_fd(duplicate) };
        let inherited_metadata = inherited
            .metadata()
            .map_err(|error| Failure::task(format!("could not recheck {label}: {error}")))?;
        if object_identity(&child_metadata) != object_identity(&inherited_metadata) {
            return Err(Failure::task(format!("{label} changed while retaining it")));
        }
        Ok(InheritableDirectory {
            file: inherited,
            anchor: PathBuf::from(format!("/proc/self/fd/{duplicate}")),
            identity: object_identity(&inherited_metadata),
        })
    }
}

pub(crate) struct SealedFile {
    file: File,
    length: u64,
}

impl SealedFile {
    pub(crate) fn from_bytes(bytes: &[u8], label: &str) -> Result<Self, Failure> {
        if bytes.is_empty() {
            return Err(Failure::task(format!("{label} cannot be sealed empty")));
        }
        let name =
            CString::new("wyrmroot-inspection").expect("static memfd name contains no NUL byte");
        // SAFETY: name is live and NUL-terminated; flags are Linux memfd flags.
        let fd = unsafe { memfd_create(name.as_ptr(), MFD_CLOEXEC | MFD_ALLOW_SEALING) };
        if fd < 0 {
            return Err(Failure::task(format!(
                "could not create sealed {label}: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: memfd_create returned a fresh owned descriptor.
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| {
                Failure::task(format!("could not populate sealed {label}: {error}"))
            })?;
        // SAFETY: fcntl applies the fixed seal set to the live memfd.
        if unsafe { fcntl(file.as_raw_fd(), F_ADD_SEALS, REQUIRED_SEALS) } != 0 {
            return Err(Failure::task(format!(
                "could not seal {label}: {}",
                std::io::Error::last_os_error()
            )));
        }
        let sealed = Self {
            file,
            length: bytes.len() as u64,
        };
        sealed.verify(label)?;
        Ok(sealed)
    }

    fn verify(&self, label: &str) -> Result<(), Failure> {
        let metadata = self
            .file
            .metadata()
            .map_err(|error| Failure::task(format!("could not stat sealed {label}: {error}")))?;
        // SAFETY: fcntl reads the active seals from the live memfd.
        let seals = unsafe { fcntl(self.file.as_raw_fd(), F_GET_SEALS) };
        if !metadata.is_file() || metadata.len() != self.length || seals != REQUIRED_SEALS {
            return Err(Failure::task(format!("sealed {label} identity changed")));
        }
        Ok(())
    }

    pub(crate) fn with_inheritable_path<T>(
        &self,
        label: &str,
        operation: impl FnOnce(&Path) -> Result<T, Failure>,
    ) -> Result<T, Failure> {
        self.verify(label)?;
        // SAFETY: fcntl borrows the sealed memfd and returns a fresh descriptor.
        let duplicate = unsafe { fcntl(self.file.as_raw_fd(), F_DUPFD, 3) };
        if duplicate < 0 {
            return Err(Failure::task(format!(
                "could not inherit sealed {label}: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: F_DUPFD returned a fresh owned descriptor without CLOEXEC.
        let inherited = unsafe { File::from_raw_fd(duplicate) };
        let path = PathBuf::from(format!("/proc/self/fd/{duplicate}"));
        let result = operation(&path);
        drop(inherited);
        self.verify(label)?;
        result
    }
}

fn read_producer_at(
    root: c_int,
    relative: &Path,
    maximum: u64,
    label: &str,
    before_read: impl FnOnce(),
) -> Result<Vec<u8>, Failure> {
    let ProducerFile {
        mut file,
        metadata: before,
        directory_identities: path_before,
    } = open_producer_at(root, relative, maximum, label)?;
    before_read();
    let capacity = usize::try_from(before.len())
        .map_err(|_| Failure::task(format!("{label} length exceeds host address space")))?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| Failure::task(format!("could not read {label}: {error}")))?;
    let after = file
        .metadata()
        .map_err(|error| Failure::task(format!("could not recheck {label}: {error}")))?;
    if stable_identity(&before) != stable_identity(&after) || bytes.len() as u64 != before.len() {
        return Err(Failure::task(format!(
            "{label} changed while reading producer output"
        )));
    }
    let ProducerFile {
        file: reopened,
        metadata: named_after,
        directory_identities: path_after,
    } = open_producer_at(root, relative, maximum, label)?;
    drop(reopened);
    if stable_identity(&before) != stable_identity(&named_after) || path_before != path_after {
        return Err(Failure::task(format!("{label} producer pathname changed")));
    }
    Ok(bytes)
}

struct ProducerFile {
    file: File,
    metadata: Metadata,
    directory_identities: Vec<(u64, u64)>,
}

fn open_producer_at(
    root: c_int,
    relative: &Path,
    maximum: u64,
    label: &str,
) -> Result<ProducerFile, Failure> {
    if relative.is_absolute()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        || relative.components().count() == 0
    {
        return Err(Failure::task(format!(
            "{label} producer path is not strictly relative"
        )));
    }
    let components = relative
        .components()
        .map(|part| match part {
            Component::Normal(name) => Ok(name),
            _ => Err(Failure::task(format!(
                "{label} producer path contains traversal"
            ))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (final_name, directories) = components
        .split_last()
        .ok_or_else(|| Failure::task(format!("{label} producer path is empty")))?;
    let mut retained_directories = Vec::with_capacity(directories.len());
    let mut directory_identities = Vec::with_capacity(directories.len());
    let mut parent = root;
    for name in directories {
        let directory = open_directory_at(Some(parent), name.as_bytes(), label)?;
        let metadata = directory.metadata().map_err(|error| {
            Failure::task(format!(
                "could not stat {label} producer directory: {error}"
            ))
        })?;
        directory_identities.push(object_identity(&metadata));
        parent = directory.as_raw_fd();
        retained_directories.push(directory);
    }
    let final_name = CString::new(final_name.as_bytes())
        .map_err(|_| Failure::task(format!("{label} producer name contains NUL")))?;
    let path_fd = openat_fd(
        parent,
        &final_name,
        O_PATH | O_CLOEXEC | O_NOFOLLOW,
        0,
        label,
    )?;
    // SAFETY: openat_fd returned a fresh owned descriptor.
    let path_file = unsafe { File::from_raw_fd(path_fd) };
    let before = path_file
        .metadata()
        .map_err(|error| Failure::task(format!("could not stat {label}: {error}")))?;
    if !producer_bounded_regular(&before, maximum) {
        return Err(Failure::task(format!(
            "{label} is not a bounded producer regular file"
        )));
    }
    let data_fd = openat_fd(
        parent,
        &final_name,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
        0,
        label,
    )?;
    // SAFETY: openat_fd returned a fresh owned descriptor.
    let file = unsafe { File::from_raw_fd(data_fd) };
    let opened = file
        .metadata()
        .map_err(|error| Failure::task(format!("could not stat opened {label}: {error}")))?;
    if stable_identity(&before) != stable_identity(&opened)
        || !producer_bounded_regular(&opened, maximum)
    {
        return Err(Failure::task(format!(
            "{label} changed before producer data open"
        )));
    }
    drop(retained_directories);
    Ok(ProducerFile {
        file,
        metadata: opened,
        directory_identities,
    })
}

pub(crate) fn hash_open_file_exact(
    file: &mut File,
    exact: u64,
    label: &str,
) -> Result<String, Failure> {
    let before = file
        .metadata()
        .map_err(|error| Failure::task(format!("could not stat {label}: {error}")))?;
    if !bounded_regular(&before, exact, Some(exact)) {
        return Err(Failure::task(format!(
            "{label} has the wrong exact size or type"
        )));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| Failure::task(format!("could not rewind {label}: {error}")))?;
    let digest = sha256::reader_digest(&mut *file)
        .map_err(|error| Failure::task(format!("could not hash {label}: {error}")))?;
    let after = file
        .metadata()
        .map_err(|error| Failure::task(format!("could not recheck {label}: {error}")))?;
    if stable_identity(&before) != stable_identity(&after) {
        return Err(Failure::task(format!("{label} changed while hashing")));
    }
    Ok(digest)
}

fn open_directory_at(parent: Option<c_int>, bytes: &[u8], label: &str) -> Result<File, Failure> {
    let path =
        CString::new(bytes).map_err(|_| Failure::task(format!("{label} contains a NUL byte")))?;
    let fd = openat_fd(
        parent.unwrap_or(-100),
        &path,
        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW,
        0,
        label,
    )?;
    // SAFETY: `openat_fd` returned a fresh owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn openat_fd(
    parent: c_int,
    path: &CString,
    flags: c_int,
    mode: u32,
    label: &str,
) -> Result<c_int, Failure> {
    // SAFETY: `path` is a live NUL-terminated string. The descriptor is either
    // AT_FDCWD or borrowed for the duration of this call.
    let fd = unsafe { openat(parent, path.as_ptr(), flags, mode as c_uint) };
    if fd < 0 {
        Err(Failure::task(format!(
            "could not open {label}: {}",
            std::io::Error::last_os_error()
        )))
    } else {
        Ok(fd)
    }
}

fn component(name: &str, label: &str) -> Result<CString, Failure> {
    let path = Path::new(name);
    if name.is_empty()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        || path.components().count() != 1
    {
        return Err(Failure::task(format!(
            "{label} name is not one normal component"
        )));
    }
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Failure::task(format!("{label} contains a NUL byte")))
}

fn bounded_regular(metadata: &Metadata, maximum: u64, exact: Option<u64>) -> bool {
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.nlink() == 1
        && metadata.len() != 0
        && metadata.len() <= maximum
        && exact.is_none_or(|expected| metadata.len() == expected)
}

fn producer_bounded_regular(metadata: &Metadata, maximum: u64) -> bool {
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.nlink() >= 1
        && metadata.len() != 0
        && metadata.len() <= maximum
}

fn object_identity(metadata: &Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

fn stable_identity(metadata: &Metadata) -> (u64, u64, u64, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.nlink(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self};
    use std::os::unix::fs::symlink;

    use std::process::Command;

    fn temporary(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "wyrmroot-secure-fs-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn component_walk_rejects_symlink_ancestry() {
        let parent = temporary("symlink");
        let real = parent.join("real");
        fs::create_dir(&real).unwrap();
        symlink(&real, parent.join("alias")).unwrap();
        assert!(Directory::open_exact(&parent.join("alias"), "alias").is_err());
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn producer_reader_rejects_links_special_empty_oversize_and_mutation() {
        let parent = temporary("producer-rejections");
        let nested = parent.join("nested");
        let outside = parent.join("outside");
        fs::create_dir(&nested).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(nested.join("valid"), b"aaaa").unwrap();
        fs::write(nested.join("empty"), b"").unwrap();
        fs::write(nested.join("oversize"), b"12345").unwrap();
        symlink(nested.join("valid"), nested.join("final-link")).unwrap();
        symlink(&nested, parent.join("intermediate-link")).unwrap();
        let status = Command::new("mkfifo")
            .arg(nested.join("fifo"))
            .status()
            .unwrap();
        assert!(status.success());
        let directory = Directory::open_exact(&parent, "producer root").unwrap();
        for path in [
            "nested/empty",
            "nested/oversize",
            "nested/final-link",
            "intermediate-link/valid",
            "nested/fifo",
            "../outside",
        ] {
            assert!(
                directory
                    .read_producer(Path::new(path), 4, "invalid producer")
                    .is_err(),
                "producer reader admitted {path}"
            );
        }

        assert!(
            read_producer_at(
                directory.file.as_raw_fd(),
                Path::new("nested/valid"),
                4,
                "mutated producer",
                || fs::write(nested.join("valid"), b"bbbb").unwrap(),
            )
            .is_err()
        );
        fs::write(nested.join("valid"), b"cccc").unwrap();
        assert!(
            read_producer_at(
                directory.file.as_raw_fd(),
                Path::new("nested/valid"),
                4,
                "replaced ancestor",
                || {
                    fs::rename(&nested, parent.join("moved")).unwrap();
                    symlink(&outside, &nested).unwrap();
                },
            )
            .is_err()
        );

        let hardlink_parent = parent.join("hardlink-parent");
        fs::create_dir(&hardlink_parent).unwrap();
        fs::write(hardlink_parent.join("valid"), b"dddd").unwrap();
        assert!(
            read_producer_at(
                directory.file.as_raw_fd(),
                Path::new("hardlink-parent/valid"),
                4,
                "hard-linked ancestor replacement",
                || {
                    fs::rename(&hardlink_parent, parent.join("hardlink-moved")).unwrap();
                    fs::create_dir(&hardlink_parent).unwrap();
                    fs::hard_link(
                        parent.join("hardlink-moved/valid"),
                        hardlink_parent.join("valid"),
                    )
                    .unwrap();
                },
            )
            .is_err()
        );
        fs::remove_dir_all(parent).unwrap();
    }
}
