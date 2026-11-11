//! Interoperability with e2fsprogs: what this crate formats and writes must
//! pass `e2fsck -fn` and read back through `debugfs`, and what `mke2fs`
//! makes must mount and accept writes. The host tools are a test
//! dependency (`/usr/bin/e2fsck`, `debugfs`, `mke2fs`); a missing tool fails
//! the test rather than skipping it.

use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use wyrmroot_ext4::{Device, DeviceError, FormatParams, Kind, ROOT_INODE, Volume, format};

struct Image(File);

impl Device for Image {
    fn read(&mut self, offset: u64, out: &mut [u8]) -> Result<(), DeviceError> {
        self.0
            .read_exact_at(out, offset)
            .map_err(|_| DeviceError(1))
    }
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), DeviceError> {
        self.0
            .write_all_at(data, offset)
            .map_err(|_| DeviceError(2))
    }
    fn flush(&mut self) -> Result<(), DeviceError> {
        self.0.sync_data().map_err(|_| DeviceError(3))
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("wyrmroot-ext4");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    let _ = fs::remove_file(&path);
    path
}

fn image(path: &Path, bytes: u64) -> Image {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .unwrap();
    file.set_len(bytes).unwrap();
    Image(file)
}

fn tool(name: &str) -> Command {
    let path = Path::new("/usr/bin").join(name);
    assert!(
        path.exists(),
        "{name} (e2fsprogs) is required by these tests"
    );
    let mut command = Command::new(path);
    command
        .env("LC_ALL", "C")
        .env("E2FSPROGS_FAKE_TIME", "1700000000");
    command
}

/// `e2fsck -fn` must find nothing to fix.
fn fsck_clean(path: &Path) {
    let output = tool("e2fsck").arg("-fn").arg(path).output().unwrap();
    assert!(
        output.status.success(),
        "e2fsck -fn {}:\n{}{}",
        path.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn debugfs(path: &Path, request: &str) -> Vec<u8> {
    let output = tool("debugfs")
        .arg("-R")
        .arg(request)
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "debugfs {request}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

const PARAMS: FormatParams = FormatParams {
    block_size: 4096,
    uuid: *b"\x5e\x10\x0d\x2a\x91\x44\x4c\x0b\x83\x1e\x6f\x50\x22\x13\x77\x01",
    label: *b"wyrmroot\0\0\0\0\0\0\0\0",
    time: 1_700_000_000,
};

#[test]
fn a_formatted_volume_passes_e2fsck() {
    for (block_size, bytes) in [(4096, 64 << 20), (1024, 24 << 20), (2048, 3 << 20)] {
        let path = scratch(&format!("fresh-{block_size}.img"));
        let mut disk = image(&path, bytes);
        format(
            &mut disk,
            bytes,
            &FormatParams {
                block_size,
                ..PARAMS
            },
        )
        .unwrap();
        drop(disk);
        fsck_clean(&path);
        let listing = String::from_utf8(debugfs(&path, "ls -l /")).unwrap();
        assert!(listing.contains("lost+found"), "{listing}");
    }
}

fn pattern(length: usize, seed: u32) -> Vec<u8> {
    (0..length as u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13 ^ seed) as u8)
        .collect()
}

#[test]
fn a_written_volume_passes_e2fsck_and_reads_back_through_debugfs() {
    for (block_size, bytes) in [(4096u32, 32u64 << 20), (1024, 16 << 20)] {
        let path = scratch(&format!("written-{block_size}.img"));
        let mut disk = image(&path, bytes);
        format(
            &mut disk,
            bytes,
            &FormatParams {
                block_size,
                ..PARAMS
            },
        )
        .unwrap();
        let mut volume = Volume::mount(&mut disk, bytes, true).unwrap();
        let etc = volume
            .create(&mut disk, ROOT_INODE, b"etc", Kind::Directory)
            .unwrap();
        let motd = volume
            .create(&mut disk, etc.inode, b"motd", Kind::File)
            .unwrap();
        volume
            .write(&mut disk, motd.inode, 0, b"persistent hello\n")
            .unwrap();
        let big = volume
            .create(&mut disk, ROOT_INODE, b"big.bin", Kind::File)
            .unwrap();
        let big_data = pattern(300_000, 1);
        for (index, chunk) in big_data.chunks(8192).enumerate() {
            volume
                .write(&mut disk, big.inode, (index * 8192) as u64, chunk)
                .unwrap();
        }
        // Two files written in turn fragment into a depth-one tree.
        let one = volume
            .create(&mut disk, ROOT_INODE, b"one", Kind::File)
            .unwrap();
        let two = volume
            .create(&mut disk, ROOT_INODE, b"two", Kind::File)
            .unwrap();
        let bs = block_size as usize;
        for index in 0..40 {
            volume
                .write(
                    &mut disk,
                    one.inode,
                    (index * bs) as u64,
                    &pattern(bs, index as u32),
                )
                .unwrap();
            volume
                .write(
                    &mut disk,
                    two.inode,
                    (index * bs) as u64,
                    &pattern(bs, 100 + index as u32),
                )
                .unwrap();
        }
        volume
            .truncate(&mut disk, two.inode, (7 * bs + 3) as u64)
            .unwrap();
        let sparse = volume
            .create(&mut disk, ROOT_INODE, b"sparse", Kind::File)
            .unwrap();
        volume
            .write(&mut disk, sparse.inode, 10 * bs as u64, b"after a hole")
            .unwrap();
        let many = volume
            .create(&mut disk, ROOT_INODE, b"many", Kind::Directory)
            .unwrap();
        for index in 0..150 {
            let name = format!("entry-number-{index:03}");
            volume
                .create(&mut disk, many.inode, name.as_bytes(), Kind::File)
                .unwrap();
        }
        for index in (0..150).step_by(3) {
            let name = format!("entry-number-{index:03}");
            volume
                .unlink(&mut disk, many.inode, name.as_bytes())
                .unwrap();
        }
        let gone = volume
            .create(&mut disk, ROOT_INODE, b"gone", Kind::Directory)
            .unwrap();
        let inner = volume
            .create(&mut disk, gone.inode, b"inner", Kind::File)
            .unwrap();
        volume
            .write(&mut disk, inner.inode, 0, &pattern(50_000, 9))
            .unwrap();
        volume.unlink(&mut disk, gone.inode, b"inner").unwrap();
        volume.unlink(&mut disk, ROOT_INODE, b"gone").unwrap();
        volume.sync(&mut disk).unwrap();
        drop(disk);

        fsck_clean(&path);
        assert_eq!(debugfs(&path, "cat /etc/motd"), b"persistent hello\n");
        assert_eq!(debugfs(&path, "cat /big.bin"), big_data);
        let mut one_data = Vec::new();
        let mut two_data = Vec::new();
        for index in 0..40 {
            one_data.extend(pattern(bs, index));
            two_data.extend(pattern(bs, 100 + index));
        }
        two_data.truncate(7 * bs + 3);
        assert_eq!(debugfs(&path, "cat /one"), one_data);
        assert_eq!(debugfs(&path, "cat /two"), two_data);
        let mut sparse_data = vec![0u8; 10 * bs];
        sparse_data.extend_from_slice(b"after a hole");
        assert_eq!(debugfs(&path, "cat /sparse"), sparse_data);
        let listing = String::from_utf8(debugfs(&path, "ls /many")).unwrap();
        assert!(listing.contains("entry-number-001") && !listing.contains("entry-number-003"));
    }
}

/// `mke2fs -t ext4` with this host's defaults (journal, flex_bg, orphan
/// file, resize inode, metadata_csum_seed) populated from a directory.
fn mke2fs_image(name: &str, extra: &[&str]) -> PathBuf {
    let source = scratch(&format!("{name}-source"));
    let _ = fs::remove_dir_all(&source);
    fs::create_dir_all(source.join("docs/deep")).unwrap();
    fs::write(source.join("docs/readme.txt"), b"made by mke2fs\n").unwrap();
    fs::write(source.join("docs/deep/blob"), pattern(123_457, 4)).unwrap();
    let path = scratch(&format!("{name}.img"));
    let output = tool("mke2fs")
        .args([
            "-q",
            "-F",
            "-t",
            "ext4",
            "-E",
            "lazy_itable_init=1",
            "-U",
            "5e100d2a-9144-4c0b-831e-6f5022137701",
        ])
        .args(extra)
        .arg("-d")
        .arg(&source)
        .arg(&path)
        .arg("32M")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "mke2fs: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    path
}

#[test]
fn a_mke2fs_volume_mounts_reads_and_accepts_writes() {
    for (name, extra) in [
        ("mke2fs-default", &[][..]),
        ("mke2fs-4k", &["-b", "4096", "-I", "128"][..]),
    ] {
        let path = mke2fs_image(name, extra);
        let bytes = fs::metadata(&path).unwrap().len();
        let mut disk = Image(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap(),
        );
        let mut volume = Volume::mount(&mut disk, bytes, true).unwrap();
        assert!(!volume.read_only(), "{name}");
        let blob = volume
            .resolve(&mut disk, ROOT_INODE, b"docs/deep/blob")
            .unwrap();
        let mut data = vec![0u8; blob.size as usize];
        let mut done = 0;
        while done < data.len() {
            done += volume
                .read(&mut disk, blob.inode, done as u64, &mut data[done..])
                .unwrap();
        }
        assert_eq!(data, pattern(123_457, 4));
        let docs = volume.resolve(&mut disk, ROOT_INODE, b"docs").unwrap();
        let mut names = Vec::new();
        volume
            .read_dir(&mut disk, docs.inode, 0, |entry| {
                names.push(String::from_utf8(entry.name.to_vec()).unwrap());
                true
            })
            .unwrap();
        names.sort();
        assert_eq!(names, ["deep", "readme.txt"]);
        let new = volume
            .create(&mut disk, docs.inode, b"written.txt", Kind::File)
            .unwrap();
        volume
            .write(&mut disk, new.inode, 0, &pattern(20_000, 5))
            .unwrap();
        volume
            .create(&mut disk, ROOT_INODE, b"newdir", Kind::Directory)
            .unwrap();
        volume.unlink(&mut disk, docs.inode, b"readme.txt").unwrap();
        volume.sync(&mut disk).unwrap();
        drop(disk);
        fsck_clean(&path);
        assert_eq!(debugfs(&path, "cat /docs/written.txt"), pattern(20_000, 5));
        let listing = String::from_utf8(debugfs(&path, "ls /docs")).unwrap();
        assert!(!listing.contains("readme.txt"), "{listing}");
    }
}
