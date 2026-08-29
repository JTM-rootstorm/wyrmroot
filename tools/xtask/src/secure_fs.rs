//! Small Linux descriptor-relative filesystem boundary for immutable products.

use std::{
    ffi::{CString, c_char, c_int, c_uint},
    fs::{File, Metadata, Permissions},
    io::{Read, Seek, SeekFrom, Write},
    ops::Deref,
    os::fd::{AsRawFd, FromRawFd},
    os::unix::{ffi::OsStrExt, fs::MetadataExt, fs::PermissionsExt},
    path::{Component, Path, PathBuf},
};

use crate::{error::Failure, sha256};

const O_RDONLY: c_int = 0;
const O_RDWR: c_int = 2;
const O_CREAT: c_int = 0o100;
const O_EXCL: c_int = 0o200;
const O_CLOEXEC: c_int = 0o2_000_000;
const O_DIRECTORY: c_int = 0o200_000;
const O_NOFOLLOW: c_int = 0o400_000;
const O_NONBLOCK: c_int = 0o4_000;
const O_PATH: c_int = 0o10_000_000;
const F_DUPFD: c_int = 0;
const AT_REMOVEDIR: c_int = 0x200;

unsafe extern "C" {
    fn openat(dirfd: c_int, pathname: *const c_char, flags: c_int, ...) -> c_int;
    fn mkdirat(dirfd: c_int, pathname: *const c_char, mode: c_uint) -> c_int;
    fn unlinkat(dirfd: c_int, pathname: *const c_char, flags: c_int) -> c_int;
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
}

pub(crate) struct Directory {
    file: File,
    display_path: PathBuf,
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
        Ok(Self {
            file,
            display_path: path.to_path_buf(),
        })
    }

    pub(crate) fn create_child(&self, name: &str, mode: u32, label: &str) -> Result<Self, Failure> {
        let name = component(name, label)?;
        // SAFETY: `name` is a live NUL-terminated string and `self.file` owns a
        // directory descriptor for the duration of the call.
        let result = unsafe { mkdirat(self.file.as_raw_fd(), name.as_ptr(), mode) };
        if result != 0 {
            return Err(Failure::task(format!(
                "could not create {label}: {}",
                std::io::Error::last_os_error()
            )));
        }
        let directory = self.open_child_cstr(&name, label)?;
        directory
            .file
            .set_permissions(Permissions::from_mode(mode))
            .map_err(|error| {
                Failure::task(format!("could not set {label} permissions: {error}"))
            })?;
        Ok(directory)
    }

    pub(crate) fn create_scratch<'a>(
        &'a self,
        name: &str,
        label: &str,
    ) -> Result<ScratchDirectory<'a>, Failure> {
        let directory = self.create_child(name, 0o700, label)?;
        Ok(ScratchDirectory {
            parent: self,
            name: name.to_owned(),
            label: label.to_owned(),
            directory,
            armed: true,
        })
    }

    pub(crate) fn open_child(&self, name: &str, label: &str) -> Result<Self, Failure> {
        let name = component(name, label)?;
        self.open_child_cstr(&name, label)
    }

    fn open_child_cstr(&self, name: &CString, label: &str) -> Result<Self, Failure> {
        let file = open_directory_at(Some(self.file.as_raw_fd()), name.as_bytes(), label)?;
        Ok(Self {
            file,
            display_path: self
                .display_path
                .join(std::ffi::OsStr::from_bytes(name.as_bytes())),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.display_path
    }

    fn anchor_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }

    pub(crate) fn with_inheritable_anchor<T>(
        &self,
        label: &str,
        operation: impl FnOnce(&InheritableDirectory) -> Result<T, Failure>,
    ) -> Result<T, Failure> {
        // SAFETY: fcntl borrows the live directory fd and returns a fresh fd.
        let duplicate = unsafe { fcntl(self.file.as_raw_fd(), F_DUPFD, 3) };
        if duplicate < 0 {
            return Err(Failure::task(format!(
                "could not duplicate {label}: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: F_DUPFD returned a fresh owned descriptor without CLOEXEC.
        let inherited = unsafe { File::from_raw_fd(duplicate) };
        let before = inherited
            .metadata()
            .map_err(|error| Failure::task(format!("could not stat {label}: {error}")))?;
        if object_identity(&before)
            != object_identity(
                &self
                    .file
                    .metadata()
                    .map_err(|error| Failure::task(format!("could not stat {label}: {error}")))?,
            )
        {
            return Err(Failure::task(format!("{label} duplicate changed identity")));
        }
        let inherited = InheritableDirectory {
            anchor: PathBuf::from(format!("/proc/self/fd/{duplicate}")),
            file: inherited,
        };
        let result = operation(&inherited);
        let after = inherited
            .file
            .metadata()
            .map_err(|error| Failure::task(format!("could not recheck {label}: {error}")))?;
        drop(inherited);
        if object_identity(&before) != object_identity(&after) {
            return Err(Failure::task(format!("{label} changed during subprocess")));
        }
        result
    }

    pub(crate) fn create_file(&self, name: &str, mode: u32, label: &str) -> Result<File, Failure> {
        let name = component(name, label)?;
        let fd = openat_fd(
            self.file.as_raw_fd(),
            &name,
            O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            mode,
            label,
        )?;
        // SAFETY: `openat_fd` returned a fresh owned descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        file.set_permissions(Permissions::from_mode(mode))
            .map_err(|error| {
                Failure::task(format!("could not set {label} permissions: {error}"))
            })?;
        Ok(file)
    }

    pub(crate) fn write_new(
        &self,
        name: &str,
        bytes: &[u8],
        mode: u32,
        label: &str,
    ) -> Result<(), Failure> {
        let mut file = self.create_file(name, mode, label)?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| Failure::task(format!("could not write {label}: {error}")))?;
        let opened = file
            .metadata()
            .map_err(|error| Failure::task(format!("could not stat {label}: {error}")))?;
        if !bounded_regular(&opened, bytes.len() as u64, Some(bytes.len() as u64)) {
            return Err(Failure::task(format!("{label} changed while writing")));
        }
        self.verify_file_identity(name, &opened, label)
    }

    pub(crate) fn read(&self, name: &str, maximum: u64, label: &str) -> Result<Vec<u8>, Failure> {
        let (mut file, before) = self.open_bounded(name, maximum, None, label)?;
        let mut bytes = Vec::with_capacity(before.len() as usize);
        Read::by_ref(&mut file)
            .take(maximum + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| Failure::task(format!("could not read {label}: {error}")))?;
        let after = file
            .metadata()
            .map_err(|error| Failure::task(format!("could not recheck {label}: {error}")))?;
        if stable_identity(&before) != stable_identity(&after) || bytes.len() as u64 != before.len()
        {
            return Err(Failure::task(format!("{label} changed while reading")));
        }
        self.verify_file_identity(name, &after, label)?;
        Ok(bytes)
    }

    pub(crate) fn open_exact_file(
        &self,
        name: &str,
        exact: u64,
        label: &str,
    ) -> Result<File, Failure> {
        let (file, _) = self.open_bounded(name, exact, Some(exact), label)?;
        Ok(file)
    }

    pub(crate) fn verify_file(&self, name: &str, file: &File, label: &str) -> Result<(), Failure> {
        let metadata = file
            .metadata()
            .map_err(|error| Failure::task(format!("could not stat {label}: {error}")))?;
        self.verify_file_identity(name, &metadata, label)
    }

    pub(crate) fn exists(&self, name: &str, label: &str) -> Result<bool, Failure> {
        let name = component(name, label)?;
        let fd = unsafe {
            openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                O_PATH | O_CLOEXEC | O_NOFOLLOW,
                0,
            )
        };
        if fd >= 0 {
            // SAFETY: the successful open returned an owned descriptor.
            let object = unsafe { File::from_raw_fd(fd) };
            let metadata = object
                .metadata()
                .map_err(|error| Failure::task(format!("could not stat {label}: {error}")))?;
            if !metadata.is_file() && !metadata.is_dir() {
                return Err(Failure::task(format!("{label} has an unsafe special type")));
            }
            return Ok(true);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(Failure::task(format!("could not inspect {label}: {error}")))
        }
    }

    fn open_bounded(
        &self,
        name: &str,
        maximum: u64,
        exact: Option<u64>,
        label: &str,
    ) -> Result<(File, Metadata), Failure> {
        let name = component(name, label)?;
        let path_fd = openat_fd(
            self.file.as_raw_fd(),
            &name,
            O_PATH | O_CLOEXEC | O_NOFOLLOW,
            0,
            label,
        )?;
        // SAFETY: `openat_fd` returned a fresh owned descriptor.
        let path_file = unsafe { File::from_raw_fd(path_fd) };
        let metadata = path_file
            .metadata()
            .map_err(|error| Failure::task(format!("could not stat {label}: {error}")))?;
        if !bounded_regular(&metadata, maximum, exact) {
            return Err(Failure::task(format!(
                "{label} is not a bounded single-link regular file"
            )));
        }
        let proc_path = CString::new(format!("/proc/self/fd/{path_fd}"))
            .expect("decimal file descriptor contains no NUL");
        let fd = openat_fd(
            -100,
            &proc_path,
            O_RDONLY | O_CLOEXEC | O_NONBLOCK,
            0,
            label,
        )?;
        // SAFETY: `openat_fd` returned a fresh owned descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        let opened = file
            .metadata()
            .map_err(|error| Failure::task(format!("could not stat opened {label}: {error}")))?;
        if object_identity(&metadata) != object_identity(&opened)
            || !bounded_regular(&opened, maximum, exact)
        {
            return Err(Failure::task(format!("{label} changed before data open")));
        }
        Ok((file, opened))
    }

    fn verify_file_identity(
        &self,
        name: &str,
        expected: &Metadata,
        label: &str,
    ) -> Result<(), Failure> {
        let (file, actual) =
            self.open_bounded(name, expected.len(), Some(expected.len()), label)?;
        drop(file);
        if object_identity(expected) != object_identity(&actual) {
            return Err(Failure::task(format!("{label} pathname changed")));
        }
        Ok(())
    }

    fn remove_child_tree_exact(
        &self,
        name: &str,
        expected: &Directory,
        label: &str,
    ) -> Result<(), Failure> {
        let named = self.open_child(name, label)?;
        if directory_identity(&named)? != directory_identity(expected)? {
            return Err(Failure::task(format!(
                "{label} pathname changed before retirement"
            )));
        }
        remove_directory_contents(expected, label)?;
        let named = self.open_child(name, label)?;
        if directory_identity(&named)? != directory_identity(expected)? {
            return Err(Failure::task(format!(
                "{label} pathname changed during retirement"
            )));
        }
        unlink_component(self.file.as_raw_fd(), name.as_bytes(), AT_REMOVEDIR, label)
    }
}

pub(crate) struct InheritableDirectory {
    file: File,
    anchor: PathBuf,
}

impl InheritableDirectory {
    pub(crate) fn path(&self) -> &Path {
        &self.anchor
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
        })
    }
}

pub(crate) struct ScratchDirectory<'a> {
    parent: &'a Directory,
    name: String,
    label: String,
    directory: Directory,
    armed: bool,
}

impl ScratchDirectory<'_> {
    pub(crate) fn finish<T>(mut self, result: Result<T, Failure>) -> Result<T, Failure> {
        let cleanup = self
            .parent
            .remove_child_tree_exact(&self.name, &self.directory, &self.label);
        if cleanup.is_ok() {
            self.armed = false;
        }
        match (result, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Err(primary), Err(cleanup)) => Err(Failure::task(format!(
                "{}; scratch cleanup also failed: {}",
                primary.message, cleanup.message
            ))),
        }
    }
}

impl Deref for ScratchDirectory<'_> {
    type Target = Directory;

    fn deref(&self) -> &Self::Target {
        &self.directory
    }
}

impl Drop for ScratchDirectory<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self
                .parent
                .remove_child_tree_exact(&self.name, &self.directory, &self.label);
        }
    }
}

fn directory_identity(directory: &Directory) -> Result<(u64, u64), Failure> {
    directory
        .file
        .metadata()
        .map(|metadata| object_identity(&metadata))
        .map_err(|error| Failure::task(format!("could not stat scratch directory: {error}")))
}

fn remove_directory_contents(directory: &Directory, label: &str) -> Result<(), Failure> {
    loop {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(directory.anchor_path())
            .map_err(|error| Failure::task(format!("could not enumerate {label}: {error}")))?
        {
            let entry = entry
                .map_err(|error| Failure::task(format!("could not enumerate {label}: {error}")))?;
            names.push(entry.file_name());
        }
        if names.is_empty() {
            return Ok(());
        }
        for name in names {
            let c_name = CString::new(name.as_bytes())
                .map_err(|_| Failure::task(format!("{label} contains a NUL name")))?;
            let path_fd = openat_fd(
                directory.file.as_raw_fd(),
                &c_name,
                O_PATH | O_CLOEXEC | O_NOFOLLOW,
                0,
                label,
            )?;
            // SAFETY: openat_fd returned a fresh owned descriptor.
            let path_file = unsafe { File::from_raw_fd(path_fd) };
            let expected = path_file
                .metadata()
                .map_err(|error| Failure::task(format!("could not stat {label} entry: {error}")))?;
            if expected.is_dir() {
                let child_file =
                    open_directory_at(Some(directory.file.as_raw_fd()), name.as_bytes(), label)?;
                let child = Directory {
                    file: child_file,
                    display_path: directory.display_path.join(&name),
                };
                if directory_identity(&child)? != object_identity(&expected) {
                    return Err(Failure::task(format!(
                        "{label} entry changed before cleanup"
                    )));
                }
                remove_directory_contents(&child, label)?;
                let rechecked =
                    open_directory_at(Some(directory.file.as_raw_fd()), name.as_bytes(), label)?;
                let rechecked = rechecked.metadata().map_err(|error| {
                    Failure::task(format!("could not recheck {label} entry: {error}"))
                })?;
                if object_identity(&expected) != object_identity(&rechecked) {
                    return Err(Failure::task(format!(
                        "{label} entry changed during cleanup"
                    )));
                }
                unlink_component(
                    directory.file.as_raw_fd(),
                    name.as_bytes(),
                    AT_REMOVEDIR,
                    label,
                )?;
            } else {
                let rechecked_fd = openat_fd(
                    directory.file.as_raw_fd(),
                    &c_name,
                    O_PATH | O_CLOEXEC | O_NOFOLLOW,
                    0,
                    label,
                )?;
                // SAFETY: openat_fd returned a fresh owned descriptor.
                let rechecked = unsafe { File::from_raw_fd(rechecked_fd) };
                let rechecked = rechecked.metadata().map_err(|error| {
                    Failure::task(format!("could not recheck {label} entry: {error}"))
                })?;
                if object_identity(&expected) != object_identity(&rechecked) {
                    return Err(Failure::task(format!(
                        "{label} entry changed during cleanup"
                    )));
                }
                unlink_component(directory.file.as_raw_fd(), name.as_bytes(), 0, label)?;
            }
        }
    }
}

fn unlink_component(parent: c_int, name: &[u8], flags: c_int, label: &str) -> Result<(), Failure> {
    let name =
        CString::new(name).map_err(|_| Failure::task(format!("{label} contains a NUL name")))?;
    // SAFETY: name is NUL-terminated and parent is borrowed for this call.
    if unsafe { unlinkat(parent, name.as_ptr(), flags) } != 0 {
        return Err(Failure::task(format!(
            "could not retire {label}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
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
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;
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
    fn retained_directory_stays_on_original_inode_after_rename() {
        let parent = temporary("rename");
        let original = parent.join("root");
        let moved = parent.join("moved");
        let attacker = parent.join("attacker");
        fs::create_dir(&original).unwrap();
        fs::create_dir(&attacker).unwrap();
        let directory = Directory::open_exact(&original, "test root").unwrap();
        fs::rename(&original, &moved).unwrap();
        symlink(&attacker, &original).unwrap();
        directory
            .write_new("sentinel", b"anchored", 0o400, "sentinel")
            .unwrap();
        assert_eq!(fs::read(moved.join("sentinel")).unwrap(), b"anchored");
        assert!(!attacker.join("sentinel").exists());
        fs::remove_dir_all(parent).unwrap();
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
    fn child_directory_symlinks_and_hard_linked_files_are_rejected() {
        let parent = temporary("child-links");
        let real = parent.join("real");
        fs::create_dir(&real).unwrap();
        let directory = Directory::open_exact(&parent, "parent").unwrap();
        symlink(&real, parent.join("product")).unwrap();
        assert!(directory.open_child("product", "product").is_err());
        fs::write(parent.join("artifact"), b"bytes").unwrap();
        fs::hard_link(parent.join("artifact"), parent.join("alias")).unwrap();
        assert!(directory.read("artifact", 16, "artifact").is_err());
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn exact_stream_hash_accepts_128_mib_and_rejects_growth() {
        let parent = temporary("hash");
        let directory = Directory::open_exact(&parent, "hash root").unwrap();
        let mut file = directory.create_file("image", 0o600, "image").unwrap();
        file.set_len(crate::g3_image::IMAGE_BYTES).unwrap();
        let first = hash_open_file_exact(&mut file, crate::g3_image::IMAGE_BYTES, "image").unwrap();
        file.set_len(crate::g3_image::IMAGE_BYTES + 1).unwrap();
        assert!(hash_open_file_exact(&mut file, crate::g3_image::IMAGE_BYTES, "image").is_err());
        assert_eq!(first.len(), 64);
        drop(file);
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn inheritable_scratch_anchor_survives_rename_without_redirecting() {
        let parent = temporary("subprocess-anchor");
        let original = parent.join("scratch");
        let moved = parent.join("moved");
        let outside = parent.join("outside");
        fs::create_dir(&original).unwrap();
        fs::create_dir(&outside).unwrap();
        let scratch = Directory::open_exact(&original, "scratch").unwrap();
        fs::rename(&original, &moved).unwrap();
        symlink(&outside, &original).unwrap();
        scratch
            .with_inheritable_anchor("scratch", |scratch| {
                let status = Command::new("sh")
                    .args(["-c", "printf child > \"$1/child\"", "sh"])
                    .arg(scratch.path())
                    .status()
                    .map_err(|error| {
                        Failure::task(format!("could not spawn test child: {error}"))
                    })?;
                if !status.success() {
                    return Err(Failure::task("test child failed"));
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(fs::read(moved.join("child")).unwrap(), b"child");
        assert!(!outside.join("child").exists());
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn scratch_raii_retires_nested_outputs_on_success_and_error() {
        let parent = temporary("scratch-cleanup");
        let directory = Directory::open_exact(&parent, "parent").unwrap();
        for (name, succeed) in [("success", true), ("failure", false)] {
            let scratch = directory.create_scratch(name, "scratch").unwrap();
            scratch
                .with_inheritable_anchor("scratch", |scratch| {
                    let status = Command::new("sh")
                        .args(["-c", "mkdir \"$1/nested\" && printf x > \"$1/nested/file\" && ln -s file \"$1/nested/link\"", "sh"])
                        .arg(scratch.path())
                        .status()
                        .map_err(|error| Failure::task(format!("could not spawn test child: {error}")))?;
                    if status.success() { Ok(()) } else { Err(Failure::task("test child failed")) }
                })
                .unwrap();
            let result = if succeed {
                Ok(())
            } else {
                Err(Failure::task("expected primary failure"))
            };
            assert_eq!(scratch.finish(result).is_ok(), succeed);
            assert!(!directory.exists(name, "retired scratch").unwrap());
        }
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn existence_and_bounded_open_reject_special_files_without_opening_data() {
        let parent = temporary("special-files");
        let fifo = parent.join("fifo");
        let status = Command::new("mkfifo").arg(&fifo).status().unwrap();
        assert!(status.success());
        let socket = match UnixListener::bind(parent.join("socket")) {
            Ok(socket) => Some(socket),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
            Err(error) => panic!("could not create test socket: {error}"),
        };
        let directory = Directory::open_exact(&parent, "special root").unwrap();
        let mut names = vec!["fifo"];
        if socket.is_some() {
            names.push("socket");
        }
        for name in names {
            assert!(directory.exists(name, name).is_err());
            assert!(directory.read(name, 16, name).is_err());
        }
        let devices = Directory::open_exact(Path::new("/dev"), "device root").unwrap();
        assert!(devices.exists("null", "device").is_err());
        assert!(devices.read("null", 16, "device").is_err());
        drop(socket);
        fs::remove_dir_all(parent).unwrap();
    }
}
