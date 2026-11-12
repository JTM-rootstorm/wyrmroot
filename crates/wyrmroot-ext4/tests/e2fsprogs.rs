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
    journal_blocks: 0,
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

// The journal (`src/journal.rs`).

use wyrmroot_ext4::journal::TRANSACTION_FULL;
use wyrmroot_ext4::{Journal, Journaled, Store, Transaction, recover};

const SLOTS: usize = 64;

struct VecStore(Vec<u8>);

impl Store for VecStore {
    fn load(&mut self, offset: usize, out: &mut [u8]) -> bool {
        match self.0.get(offset..offset + out.len()) {
            Some(bytes) => {
                out.copy_from_slice(bytes);
                true
            }
            None => false,
        }
    }
    fn save(&mut self, offset: usize, data: &[u8]) -> bool {
        match self.0.get_mut(offset..offset + data.len()) {
            Some(bytes) => {
                bytes.copy_from_slice(data);
                true
            }
            None => false,
        }
    }
}

/// The image, with power lost after `flushes` more flushes: every later
/// write fails and never lands.
struct Crashing {
    image: Image,
    flushes: Option<usize>,
}

impl Device for Crashing {
    fn read(&mut self, offset: u64, out: &mut [u8]) -> Result<(), DeviceError> {
        self.image.read(offset, out)
    }
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), DeviceError> {
        if self.flushes == Some(0) {
            return Err(DeviceError(99));
        }
        self.image.write(offset, data)
    }
    fn flush(&mut self) -> Result<(), DeviceError> {
        if self.flushes == Some(0) {
            return Err(DeviceError(99));
        }
        self.flushes = self.flushes.map(|left| left - 1);
        self.image.flush()
    }
}

fn open_image(path: &Path) -> Image {
    Image(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap(),
    )
}

fn journaled_format(name: &str, block_size: u32, bytes: u64) -> PathBuf {
    let path = scratch(name);
    let mut disk = image(&path, bytes);
    format(
        &mut disk,
        bytes,
        &FormatParams {
            block_size,
            journal_blocks: 1024,
            ..PARAMS
        },
    )
    .unwrap();
    path
}

/// A mounted volume with its journal open and an empty transaction.
fn journaled(
    path: &Path,
    flushes: Option<usize>,
) -> (Crashing, Volume, Journal, Transaction<VecStore, SLOTS>) {
    let bytes = fs::metadata(path).unwrap().len();
    let mut disk = Crashing {
        image: open_image(path),
        flushes: None,
    };
    recover(&mut disk, bytes).unwrap();
    let mut volume = Volume::mount(&mut disk, bytes, true).unwrap();
    let journal = Journal::open(&mut volume, &mut disk).unwrap().unwrap();
    let store = VecStore(vec![0; SLOTS * volume.block_size() as usize]);
    let transaction = Transaction::new(store, &journal);
    disk.flushes = flushes;
    (disk, volume, journal, transaction)
}

fn dumpe2fs(path: &Path) -> String {
    let output = tool("dumpe2fs").arg("-h").arg(path).output().unwrap();
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// `e2fsck -fy` on a copy: replays the journal, then must leave the copy
/// clean.
fn e2fsck_replayed(path: &Path, name: &str) -> PathBuf {
    let copy = scratch(name);
    fs::copy(path, &copy).unwrap();
    let output = tool("e2fsck").arg("-fy").arg(&copy).output().unwrap();
    assert!(
        output.status.code().is_some_and(|code| code <= 1),
        "e2fsck -fy:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    fsck_clean(&copy);
    copy
}

fn block_of(path: &Path, block: u64, size: usize) -> Vec<u8> {
    let mut out = vec![0; size];
    open_image(path)
        .0
        .read_exact_at(&mut out, block * size as u64)
        .unwrap();
    out
}

#[test]
fn a_journaled_volume_commits_and_passes_e2fsck() {
    for (block_size, bytes) in [(4096u32, 32u64 << 20), (1024, 16 << 20)] {
        let path = journaled_format(&format!("journaled-{block_size}.img"), block_size, bytes);
        fsck_clean(&path);
        let header = dumpe2fs(&path);
        assert!(header.contains("has_journal"), "{header}");
        assert!(
            header.contains("journal_64bit journal_checksum_v3"),
            "{header}"
        );

        let (mut disk, mut volume, mut journal, mut transaction) = journaled(&path, None);
        assert!(dumpe2fs(&path).contains("needs_recovery"));
        let mut view = Journaled {
            device: &mut disk,
            transaction: &mut transaction,
        };
        let etc = volume
            .create(&mut view, ROOT_INODE, b"etc", Kind::Directory)
            .unwrap();
        let motd = volume
            .create(&mut view, etc.inode, b"motd", Kind::File)
            .unwrap();
        volume
            .write(&mut view, motd.inode, 0, b"journaled hello\n")
            .unwrap();
        assert!(!transaction.is_empty());
        journal
            .commit(&volume, &mut disk, &mut transaction)
            .unwrap();
        assert!(transaction.is_empty());
        let mut view = Journaled {
            device: &mut disk,
            transaction: &mut transaction,
        };
        let big = volume
            .create(&mut view, ROOT_INODE, b"big", Kind::File)
            .unwrap();
        let data = pattern(200_000, 3);
        for (index, chunk) in data.chunks(8192).enumerate() {
            volume
                .write(&mut view, big.inode, (index * 8192) as u64, chunk)
                .unwrap();
        }
        volume.unlink(&mut view, etc.inode, b"motd").unwrap();
        journal
            .close(&mut volume, &mut disk, &mut transaction)
            .unwrap();
        drop(disk);

        fsck_clean(&path);
        assert!(!dumpe2fs(&path).contains("needs_recovery"));
        assert_eq!(debugfs(&path, "cat /big"), data);
        let listing = String::from_utf8(debugfs(&path, "ls /etc")).unwrap();
        assert!(!listing.contains("motd"), "{listing}");
        let log = String::from_utf8(debugfs(&path, "logdump")).unwrap();
        assert!(log.contains("Journal starts at block 0"), "{log}");
    }
}

#[test]
fn a_crash_after_the_commit_block_is_replayed_by_e2fsck_and_by_recover() {
    let path = journaled_format("crash-committed.img", 4096, 32 << 20);
    let (mut disk, mut volume, mut journal, mut transaction) = journaled(&path, Some(3));
    let mut view = Journaled {
        device: &mut disk,
        transaction: &mut transaction,
    };
    let note = volume
        .create(&mut view, ROOT_INODE, b"note", Kind::File)
        .unwrap();
    volume
        .write(&mut view, note.inode, 0, &pattern(10_000, 7))
        .unwrap();
    volume
        .create(&mut view, ROOT_INODE, b"dir", Kind::Directory)
        .unwrap();
    // The checkpoint's first write is lost.
    assert!(
        journal
            .commit(&volume, &mut disk, &mut transaction)
            .is_err()
    );
    drop(disk);
    let header = dumpe2fs(&path);
    assert!(header.contains("needs_recovery"), "{header}");
    assert!(!header.contains("Journal start:            0"), "{header}");

    let by_e2fsck = e2fsck_replayed(&path, "crash-committed-e2fsck.img");
    assert_eq!(debugfs(&by_e2fsck, "cat /note"), pattern(10_000, 7));

    let bytes = fs::metadata(&path).unwrap().len();
    let mut disk = open_image(&path);
    assert_eq!(recover(&mut disk, bytes), Ok(true));
    assert_eq!(recover(&mut disk, bytes), Ok(false));
    drop(disk);
    fsck_clean(&path);
    assert_eq!(debugfs(&path, "cat /note"), pattern(10_000, 7));
    assert!(
        String::from_utf8(debugfs(&path, "ls /"))
            .unwrap()
            .contains("dir")
    );
}

#[test]
fn a_crash_before_the_commit_block_leaves_the_last_commit() {
    let path = journaled_format("crash-uncommitted.img", 4096, 32 << 20);
    let (mut disk, mut volume, mut journal, mut transaction) = journaled(&path, Some(2));
    let mut view = Journaled {
        device: &mut disk,
        transaction: &mut transaction,
    };
    let uncommitted = volume
        .create(&mut view, ROOT_INODE, b"uncommitted", Kind::File)
        .unwrap();
    volume
        .write(&mut view, uncommitted.inode, 0, &pattern(10_000, 8))
        .unwrap();
    assert!(
        journal
            .commit(&volume, &mut disk, &mut transaction)
            .is_err()
    );
    drop(disk);

    let by_e2fsck = e2fsck_replayed(&path, "crash-uncommitted-e2fsck.img");
    let listing = String::from_utf8(debugfs(&by_e2fsck, "ls /")).unwrap();
    assert!(!listing.contains("uncommitted"), "{listing}");

    let bytes = fs::metadata(&path).unwrap().len();
    let mut disk = open_image(&path);
    assert_eq!(recover(&mut disk, bytes), Ok(false));
    drop(disk);
    fsck_clean(&path);
    let listing = String::from_utf8(debugfs(&path, "ls /")).unwrap();
    assert!(!listing.contains("uncommitted"), "{listing}");
}

#[test]
fn blocks_freed_in_a_transaction_are_not_reused_before_it_commits() {
    let path = journaled_format("no-reuse.img", 4096, 32 << 20);
    let (mut disk, mut volume, mut journal, mut transaction) = journaled(&path, None);
    let mut view = Journaled {
        device: &mut disk,
        transaction: &mut transaction,
    };
    let old = volume
        .create(&mut view, ROOT_INODE, b"old", Kind::File)
        .unwrap();
    volume
        .write(&mut view, old.inode, 0, &pattern(8 * 4096, 1))
        .unwrap();
    journal
        .commit(&volume, &mut disk, &mut transaction)
        .unwrap();
    let old_blocks = String::from_utf8(debugfs(&path, "blocks /old")).unwrap();
    let mut view = Journaled {
        device: &mut disk,
        transaction: &mut transaction,
    };
    volume.unlink(&mut view, ROOT_INODE, b"old").unwrap();
    let new = volume
        .create(&mut view, ROOT_INODE, b"new", Kind::File)
        .unwrap();
    volume
        .write(&mut view, new.inode, 0, &pattern(8 * 4096, 2))
        .unwrap();
    journal
        .close(&mut volume, &mut disk, &mut transaction)
        .unwrap();
    drop(disk);
    fsck_clean(&path);
    let new_blocks = String::from_utf8(debugfs(&path, "blocks /new")).unwrap();
    for block in new_blocks.split_whitespace() {
        assert!(
            !old_blocks.split_whitespace().any(|old| old == block),
            "block {block} of /new was /old's: {old_blocks}"
        );
    }
}

#[test]
fn a_full_transaction_refuses_the_write() {
    let path = journaled_format("full.img", 1024, 16 << 20);
    let (mut disk, mut volume, _journal, mut transaction) = journaled(&path, None);
    let mut view = Journaled {
        device: &mut disk,
        transaction: &mut transaction,
    };
    let mut result = Ok(());
    for index in 0..10_000 {
        let name = format!("file-{index}");
        if let Err(error) = volume.create(&mut view, ROOT_INODE, name.as_bytes(), Kind::File) {
            result = Err(error);
            break;
        }
    }
    assert_eq!(result, Err(wyrmroot_ext4::Error::Device(TRANSACTION_FULL)));
}

/// Writes `transactions` with debugfs's own journal writer (`jo -c`, `jw`).
fn debugfs_journal(path: &Path, requests: &[&str]) {
    let commands = scratch("debugfs-journal.cmds");
    let mut script = String::from("jo -c\n");
    for request in requests {
        script.push_str(request);
        script.push('\n');
    }
    script.push_str("jc\n");
    fs::write(&commands, script).unwrap();
    let output = tool("debugfs")
        .arg("-w")
        .arg("-f")
        .arg(&commands)
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_journal_written_by_debugfs_replays_as_e2fsck_replays_it() {
    let path = journaled_format("debugfs-journal.img", 4096, 32 << 20);
    let mut payload = pattern(3 * 4096, 11);
    // The second block starts with the journal magic, so it is escaped.
    payload[4096..4100].copy_from_slice(&0xC03B_3998u32.to_be_bytes());
    let blocks = scratch("debugfs-journal.bin");
    fs::write(&blocks, &payload).unwrap();
    let blocks = blocks.display().to_string();
    debugfs_journal(
        &path,
        &[
            &format!("jw -b 3000,3001 {blocks}"),
            &format!("jw -b 3002 {blocks}"),
            "jw -r 3002",
        ],
    );
    assert!(dumpe2fs(&path).contains("needs_recovery"));
    let by_e2fsck = e2fsck_replayed(&path, "debugfs-journal-e2fsck.img");

    let bytes = fs::metadata(&path).unwrap().len();
    let mut disk = open_image(&path);
    assert_eq!(recover(&mut disk, bytes), Ok(true));
    drop(disk);
    fsck_clean(&path);
    for block in 3000..3003 {
        assert_eq!(
            block_of(&path, block, 4096),
            block_of(&by_e2fsck, block, 4096),
            "block {block}"
        );
    }
    assert_eq!(block_of(&path, 3000, 4096), payload[..4096]);
    assert_eq!(block_of(&path, 3001, 4096), payload[4096..8192]);
    // Logged in the second transaction, revoked in the third.
    assert_eq!(block_of(&path, 3002, 4096), vec![0; 4096]);
}

#[test]
fn an_escaped_block_this_journal_wrote_is_replayed_by_e2fsck() {
    let path = journaled_format("escaped.img", 4096, 32 << 20);
    let (mut disk, volume, mut journal, mut transaction) = journaled(&path, Some(3));
    let mut block = pattern(4096, 12);
    block[..4].copy_from_slice(&0xC03B_3998u32.to_be_bytes());
    Journaled {
        device: &mut disk,
        transaction: &mut transaction,
    }
    .write(3000 * 4096, &block)
    .unwrap();
    assert!(
        journal
            .commit(&volume, &mut disk, &mut transaction)
            .is_err()
    );
    drop(disk);
    let by_e2fsck = e2fsck_replayed(&path, "escaped-e2fsck.img");
    assert_eq!(block_of(&by_e2fsck, 3000, 4096), block);
    let bytes = fs::metadata(&path).unwrap().len();
    let mut disk = open_image(&path);
    assert_eq!(recover(&mut disk, bytes), Ok(true));
    drop(disk);
    assert_eq!(block_of(&path, 3000, 4096), block);
}

#[test]
fn a_mke2fs_journal_takes_commits_that_e2fsck_replays() {
    let path = mke2fs_image("mke2fs-journal", &[]);
    let (mut disk, mut volume, mut journal, mut transaction) = journaled(&path, Some(3));
    let mut view = Journaled {
        device: &mut disk,
        transaction: &mut transaction,
    };
    let docs = volume.resolve(&mut view, ROOT_INODE, b"docs").unwrap();
    let new = volume
        .create(&mut view, docs.inode, b"journaled.txt", Kind::File)
        .unwrap();
    volume
        .write(&mut view, new.inode, 0, &pattern(30_000, 6))
        .unwrap();
    volume.unlink(&mut view, docs.inode, b"readme.txt").unwrap();
    assert!(
        journal
            .commit(&volume, &mut disk, &mut transaction)
            .is_err()
    );
    drop(disk);
    let by_e2fsck = e2fsck_replayed(&path, "mke2fs-journal-e2fsck.img");
    assert_eq!(
        debugfs(&by_e2fsck, "cat /docs/journaled.txt"),
        pattern(30_000, 6)
    );
    let bytes = fs::metadata(&path).unwrap().len();
    let mut disk = open_image(&path);
    assert_eq!(recover(&mut disk, bytes), Ok(true));
    drop(disk);
    fsck_clean(&path);
    assert_eq!(
        debugfs(&path, "cat /docs/journaled.txt"),
        pattern(30_000, 6)
    );
}
