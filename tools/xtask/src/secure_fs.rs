//! Linux-host descriptor-relative filesystem access for acceptance evidence.
//!
//! Acceptance inputs are adversarial names.  Every traversal is therefore
//! performed by `openat2(2)` with no symlink or magic-link resolution, and
//! every output is created relative to a held directory descriptor.  This is
//! intentionally small first-party host FFI rather than a new dependency.

use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crate::error::Failure;

const AT_FDCWD: RawFd = -100;
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_CLOEXEC: u64 = 0o2_000_000;
const O_DIRECTORY: u64 = 0o200_000;
const O_NOFOLLOW: u64 = 0o400_000;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
#[cfg(target_arch = "x86_64")]
const SYS_OPENAT2: i64 = 437;
#[cfg(target_arch = "aarch64")]
const SYS_OPENAT2: i64 = 437;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

unsafe extern "C" {
    fn syscall(number: i64, ...) -> i64;
    fn mkdirat(dirfd: RawFd, path: *const i8, mode: u32) -> i32;
    fn unlinkat(dirfd: RawFd, path: *const i8, flags: i32) -> i32;
    fn fcntl(fd: RawFd, command: i32, ...) -> i32;
}

#[derive(Clone, Debug)]
pub(crate) struct Root {
    directory: Arc<File>,
    display: PathBuf,
    identity: (u64, u64),
}

impl PartialEq for Root {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity && self.display == other.display
    }
}

impl Eq for Root {}

impl Root {
    pub(crate) fn open(path: &Path, label: &str) -> Result<Self, Failure> {
        let directory = open_path(
            AT_FDCWD,
            path.as_os_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW,
            0,
            RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        )
        .map_err(|error| Failure::task(format!("could not securely open {label}: {error}")))?;
        let metadata = directory
            .metadata()
            .map_err(|error| Failure::task(format!("could not inspect {label}: {error}")))?;
        Ok(Self {
            directory: Arc::new(directory),
            display: path.to_path_buf(),
            identity: (metadata.dev(), metadata.ino()),
        })
    }

    #[cfg(test)]
    pub(crate) fn placeholder(display: &Path) -> Self {
        let directory = File::open("/").expect("open test placeholder root");
        let metadata = directory.metadata().expect("inspect test placeholder root");
        Self {
            directory: Arc::new(directory),
            display: display.to_path_buf(),
            identity: (metadata.dev(), metadata.ino()),
        }
    }

    pub(crate) fn relative<'a>(&self, path: &'a Path, label: &str) -> Result<&'a Path, Failure> {
        let relative = path
            .strip_prefix(&self.display)
            .map_err(|_| Failure::task(format!("{label} escapes the admitted request root")))?;
        validate_relative(relative, label)?;
        Ok(relative)
    }

    pub(crate) fn read(
        &self,
        path: &Path,
        label: &str,
        max_bytes: u64,
        allow_empty: bool,
    ) -> Result<Vec<u8>, Failure> {
        let relative = self.relative(path, label)?;
        let mut input = self.open_regular(relative, label)?;
        read_bounded(&mut input, label, max_bytes, allow_empty)
    }

    pub(crate) fn open_regular(&self, relative: &Path, label: &str) -> Result<File, Failure> {
        validate_relative(relative, label)?;
        let file = open_path(
            self.directory.as_raw_fd(),
            relative.as_os_str(),
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW,
            0,
            RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        )
        .map_err(|error| Failure::task(format!("could not securely open {label}: {error}")))?;
        let metadata = file
            .metadata()
            .map_err(|error| Failure::task(format!("could not inspect {label}: {error}")))?;
        if !metadata.is_file() {
            return Err(Failure::task(format!("{label} must be a regular file")));
        }
        Ok(file)
    }

    pub(crate) fn exists(&self, path: &Path, label: &str) -> Result<bool, Failure> {
        let relative = self.relative(path, label)?;
        match self.open_regular(relative, label) {
            Ok(_) => Ok(true),
            Err(error) if error.message.contains("No such file or directory") => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn create_dir(&self, path: &Path, label: &str) -> Result<(), Failure> {
        let relative = self.relative(path, label)?;
        let (parent, leaf) = split_parent(relative, label)?;
        let parent = self.open_directory(parent, label)?;
        let leaf = c_string(leaf, label)?;
        // SAFETY: `parent` and `leaf` remain alive for the call.
        if unsafe { mkdirat(parent.as_raw_fd(), leaf.as_ptr(), 0o700) } != 0 {
            return Err(Failure::task(format!(
                "could not securely create {label}: {}",
                std::io::Error::last_os_error()
            )));
        }
        parent
            .sync_all()
            .map_err(|error| Failure::task(format!("could not durably create {label}: {error}")))
    }

    pub(crate) fn validate_parent(&self, path: &Path, label: &str) -> Result<(), Failure> {
        let relative = self.relative(path, label)?;
        let parent = relative
            .parent()
            .ok_or_else(|| Failure::task(format!("{label} has no parent")))?;
        self.open_directory(parent, label).map(|_| ())
    }

    pub(crate) fn validate_existing_ancestor(
        &self,
        path: &Path,
        label: &str,
    ) -> Result<(), Failure> {
        let relative = self.relative(path, label)?;
        let mut parent = relative
            .parent()
            .ok_or_else(|| Failure::task(format!("{label} has no parent")))?;
        loop {
            match self.open_directory(parent, label) {
                Ok(_) => return Ok(()),
                Err(error) if error.message.contains("No such file or directory") => {
                    parent = parent.parent().unwrap_or_else(|| Path::new(""));
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) fn validate_directory_if_present(
        &self,
        path: &Path,
        label: &str,
    ) -> Result<(), Failure> {
        let relative = self.relative(path, label)?;
        match self.open_directory(relative, label) {
            Ok(_) => Ok(()),
            Err(error) if error.message.contains("No such file or directory") => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn write_new(&self, path: &Path, bytes: &[u8], label: &str) -> Result<(), Failure> {
        let relative = self.relative(path, label)?;
        let (parent_path, leaf) = split_parent(relative, label)?;
        let parent = self.open_directory(parent_path, label)?;
        let mut output = open_path(
            parent.as_raw_fd(),
            leaf,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0o600,
            RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        )
        .map_err(|error| Failure::task(format!("could not securely create {label}: {error}")))?;
        if let Err(error) = output.write_all(bytes).and_then(|()| output.sync_all()) {
            drop(output);
            let leaf = c_string(leaf, label)?;
            // SAFETY: held parent descriptor and NUL-terminated leaf are valid.
            let _ = unsafe { unlinkat(parent.as_raw_fd(), leaf.as_ptr(), 0) };
            return Err(Failure::task(format!("could not write {label}: {error}")));
        }
        parent
            .sync_all()
            .map_err(|error| Failure::task(format!("could not durably publish {label}: {error}")))
    }

    pub(crate) fn open_new(&self, path: &Path, label: &str) -> Result<File, Failure> {
        let relative = self.relative(path, label)?;
        let (parent_path, leaf) = split_parent(relative, label)?;
        let parent = self.open_directory(parent_path, label)?;
        open_path(
            parent.as_raw_fd(),
            leaf,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0o600,
            RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        )
        .map_err(|error| Failure::task(format!("could not securely create {label}: {error}")))
    }

    pub(crate) fn open_read_write(&self, path: &Path, label: &str) -> Result<File, Failure> {
        let relative = self.relative(path, label)?;
        open_path(
            self.directory.as_raw_fd(),
            relative.as_os_str(),
            O_RDWR | O_CLOEXEC | O_NOFOLLOW,
            0,
            RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        )
        .map_err(|error| Failure::task(format!("could not securely open {label}: {error}")))
    }

    pub(crate) fn open_inherited_read(&self, path: &Path, label: &str) -> Result<File, Failure> {
        let relative = self.relative(path, label)?;
        let file = self.open_regular(relative, label)?;
        clear_close_on_exec(&file, label)?;
        Ok(file)
    }

    pub(crate) fn open_inherited_read_write(
        &self,
        path: &Path,
        label: &str,
    ) -> Result<File, Failure> {
        let file = self.open_read_write(path, label)?;
        clear_close_on_exec(&file, label)?;
        Ok(file)
    }

    pub(crate) fn remove_file(&self, path: &Path, label: &str) -> Result<(), Failure> {
        let relative = self.relative(path, label)?;
        let (parent_path, leaf) = split_parent(relative, label)?;
        let parent = self.open_directory(parent_path, label)?;
        let leaf = c_string(leaf, label)?;
        // SAFETY: held parent descriptor and NUL-terminated leaf are valid.
        if unsafe { unlinkat(parent.as_raw_fd(), leaf.as_ptr(), 0) } != 0 {
            return Err(Failure::task(format!(
                "could not securely remove {label}: {}",
                std::io::Error::last_os_error()
            )));
        }
        parent
            .sync_all()
            .map_err(|error| Failure::task(format!("could not durably remove {label}: {error}")))
    }

    fn open_directory(&self, relative: &Path, label: &str) -> Result<File, Failure> {
        if relative.as_os_str().is_empty() {
            return self.directory.try_clone().map_err(|error| {
                Failure::task(format!("could not retain {label} parent: {error}"))
            });
        }
        open_path(
            self.directory.as_raw_fd(),
            relative.as_os_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW,
            0,
            RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        )
        .map_err(|error| Failure::task(format!("could not securely open {label} parent: {error}")))
    }
}

pub(crate) fn inherited_path(file: &File) -> String {
    format!("/proc/self/fd/{}", file.as_raw_fd())
}

fn clear_close_on_exec(file: &File, label: &str) -> Result<(), Failure> {
    const F_GETFD: i32 = 1;
    const F_SETFD: i32 = 2;
    const FD_CLOEXEC: i32 = 1;
    // SAFETY: fcntl is called on a live owned descriptor.
    let flags = unsafe { fcntl(file.as_raw_fd(), F_GETFD) };
    if flags < 0 {
        return Err(Failure::task(format!(
            "could not inspect {label} descriptor flags: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: fcntl is called on a live owned descriptor with integer flags.
    if unsafe { fcntl(file.as_raw_fd(), F_SETFD, flags & !FD_CLOEXEC) } < 0 {
        return Err(Failure::task(format!(
            "could not retain {label} descriptor across exec: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

pub(crate) fn read_path(
    path: &Path,
    label: &str,
    max_bytes: u64,
    allow_empty: bool,
) -> Result<Vec<u8>, Failure> {
    let mut file = open_path(
        AT_FDCWD,
        path.as_os_str(),
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW,
        0,
        RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
    )
    .map_err(|error| Failure::task(format!("could not securely open {label}: {error}")))?;
    read_bounded(&mut file, label, max_bytes, allow_empty)
}

fn read_bounded(
    file: &mut File,
    label: &str,
    max_bytes: u64,
    allow_empty: bool,
) -> Result<Vec<u8>, Failure> {
    let before = file
        .metadata()
        .map_err(|error| Failure::task(format!("could not inspect {label}: {error}")))?;
    if !before.is_file() || before.len() > max_bytes || (!allow_empty && before.len() == 0) {
        return Err(Failure::task(format!(
            "{label} must be a bounded {}regular file",
            if allow_empty { "" } else { "nonempty " }
        )));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| Failure::task(format!("could not read {label}: {error}")))?;
    if bytes.len() as u64 > max_bytes || (!allow_empty && bytes.is_empty()) {
        return Err(Failure::task(format!(
            "{label} changed size while being admitted"
        )));
    }
    let after = file
        .metadata()
        .map_err(|error| Failure::task(format!("could not re-inspect {label}: {error}")))?;
    if before.len() != after.len() || bytes.len() as u64 != before.len() {
        return Err(Failure::task(format!(
            "{label} changed while being admitted"
        )));
    }
    Ok(bytes)
}

fn validate_relative(path: &Path, label: &str) -> Result<(), Failure> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Failure::task(format!(
            "{label} must be a nonempty normal path beneath the admitted root"
        )));
    }
    Ok(())
}

fn split_parent<'a>(path: &'a Path, label: &str) -> Result<(&'a Path, &'a OsStr), Failure> {
    let leaf = path
        .file_name()
        .ok_or_else(|| Failure::task(format!("{label} has no final component")))?;
    Ok((path.parent().unwrap_or_else(|| Path::new("")), leaf))
}

fn c_string(value: &OsStr, label: &str) -> Result<CString, Failure> {
    CString::new(value.as_bytes())
        .map_err(|_| Failure::task(format!("{label} path contains a NUL byte")))
}

fn open_path(
    dirfd: RawFd,
    path: &OsStr,
    flags: u64,
    mode: u64,
    resolve: u64,
) -> std::io::Result<File> {
    let path = CString::new(path.as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let how = OpenHow {
        flags,
        mode,
        resolve,
    };
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("secure acceptance tooling requires a supported Linux host architecture");
    // SAFETY: the kernel receives valid pointers and the exact structure size.
    let fd = unsafe {
        syscall(
            SYS_OPENAT2,
            dirfd,
            path.as_ptr(),
            &how,
            size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: a successful openat2 returns a new owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd as RawFd) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn descriptor_relative_access_rejects_symlink_components() {
        let root_path = std::env::temp_dir().join(format!(
            "wyrmroot-secure-fs-{}-{}",
            std::process::id(),
            "nofollow"
        ));
        fs::create_dir(&root_path).expect("create root");
        fs::create_dir(root_path.join("real")).expect("create real");
        fs::write(root_path.join("real/input"), b"bound").expect("write input");
        std::os::unix::fs::symlink("real", root_path.join("alias")).expect("create symlink");
        let root = Root::open(&root_path, "fixture root").expect("open root");
        assert_eq!(
            root.read(&root_path.join("real/input"), "input", 16, false)
                .expect("read input"),
            b"bound"
        );
        assert!(
            root.read(&root_path.join("alias/input"), "alias", 16, false)
                .is_err()
        );
        fs::remove_dir_all(root_path).expect("remove fixture");
    }

    #[test]
    fn held_root_is_not_redirected_by_a_name_swap() {
        let base = std::env::temp_dir().join(format!(
            "wyrmroot-secure-fs-{}-root-swap",
            std::process::id()
        ));
        let root_path = base.join("root");
        let moved = base.join("held-root");
        let hostile = base.join("hostile");
        fs::create_dir(&base).expect("create base");
        fs::create_dir(&root_path).expect("create root");
        fs::create_dir(&hostile).expect("create hostile");
        fs::write(root_path.join("input"), b"admitted").expect("write admitted input");
        fs::write(hostile.join("input"), b"redirected").expect("write hostile input");
        let root = Root::open(&root_path, "fixture root").expect("hold root");
        fs::rename(&root_path, &moved).expect("rename held root");
        std::os::unix::fs::symlink(&hostile, &root_path).expect("replace name with symlink");
        assert_eq!(
            root.read(&root_path.join("input"), "held input", 32, false)
                .expect("read through held descriptor"),
            b"admitted"
        );
        fs::remove_file(&root_path).expect("remove redirect");
        fs::remove_dir_all(base).expect("remove fixture");
    }
}
