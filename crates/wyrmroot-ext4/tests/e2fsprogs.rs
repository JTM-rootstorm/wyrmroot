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

fn debugfs_write(path: &Path, request: &str) {
    let output = tool("debugfs")
        .arg("-w")
        .arg("-R")
        .arg(request)
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn first_number(text: &[u8]) -> u64 {
    String::from_utf8_lossy(text)
        .split(|c: char| !c.is_ascii_digit())
        .find(|word| !word.is_empty())
        .unwrap()
        .parse()
        .unwrap()
}

/// What opening the journal of `path` (made writable) reports.
fn open_journal(path: &Path) -> Result<(), wyrmroot_ext4::Error> {
    let bytes = fs::metadata(path).unwrap().len();
    let mut disk = open_image(path);
    recover(&mut disk, bytes)?;
    let mut volume = Volume::mount(&mut disk, bytes, true)?;
    Journal::open(&mut volume, &mut disk).map(|_| ())
}

#[test]
fn a_hostile_journal_is_refused() {
    // A journal superblock claiming more blocks than the file maps (W11
    // review D1: the walk's bound came from the image).
    let path = journaled_format("hostile-maxlen.img", 4096, 32 << 20);
    let at = first_number(&debugfs(&path, "bmap <8> 0"));
    let mut sb = block_of(&path, at, 4096);
    sb.truncate(1024);
    sb[0x10..0x14].copy_from_slice(&u32::MAX.to_be_bytes());
    sb[0xFC..0x100].fill(0);
    let sum = wyrmroot_ext4::crc::update(!0, &sb);
    sb[0xFC..0x100].copy_from_slice(&sum.to_be_bytes());
    open_image(&path).write(at * 4096, &sb).unwrap();
    assert_eq!(open_journal(&path), Err(wyrmroot_ext4::Error::Corrupt));

    // A journal extent over the inode table (D2).
    let path = journaled_format("hostile-extent.img", 4096, 32 << 20);
    let header = dumpe2fs(&path);
    let output = tool("dumpe2fs").arg(&path).output().unwrap();
    let groups = String::from_utf8_lossy(&output.stdout).into_owned();
    let table = groups
        .lines()
        .find_map(|line| line.trim().strip_prefix("Inode table at "))
        .map(|rest| first_number(rest.as_bytes()))
        .unwrap_or_else(|| panic!("{header}{groups}"));
    debugfs_write(&path, &format!("sif <8> block[5] {table}"));
    assert_eq!(open_journal(&path), Err(wyrmroot_ext4::Error::Corrupt));

    // A journal inode that is the root directory (D2).
    let path = journaled_format("hostile-inum.img", 4096, 32 << 20);
    debugfs_write(&path, "ssv journal_inum 2");
    assert_eq!(open_journal(&path), Err(wyrmroot_ext4::Error::Corrupt));
}

#[test]
fn a_journal_without_checksums_or_64bit_takes_commits_that_e2fsck_replays() {
    let path = mke2fs_image("mke2fs-plain", &["-O", "^metadata_csum,^64bit"]);
    let header = dumpe2fs(&path);
    assert!(
        !header.contains("metadata_csum") && !header.contains("64bit"),
        "{header}"
    );
    let (mut disk, mut volume, mut journal, mut transaction) = journaled(&path, Some(3));
    let mut view = Journaled {
        device: &mut disk,
        transaction: &mut transaction,
    };
    let new = volume
        .create(&mut view, ROOT_INODE, b"plain.txt", Kind::File)
        .unwrap();
    volume
        .write(&mut view, new.inode, 0, &pattern(9_000, 13))
        .unwrap();
    assert!(
        journal
            .commit(&volume, &mut disk, &mut transaction)
            .is_err()
    );
    drop(disk);
    assert!(!dumpe2fs(&path).contains("journal_checksum"));
    let by_e2fsck = e2fsck_replayed(&path, "mke2fs-plain-e2fsck.img");
    assert_eq!(debugfs(&by_e2fsck, "cat /plain.txt"), pattern(9_000, 13));
    let bytes = fs::metadata(&path).unwrap().len();
    let mut disk = open_image(&path);
    assert_eq!(recover(&mut disk, bytes), Ok(true));
    drop(disk);
    fsck_clean(&path);
    assert_eq!(debugfs(&path, "cat /plain.txt"), pattern(9_000, 13));
}

// Files unlinked while held: the orphan list (`src/orphan.rs`).

/// The superblock's free block and inode counts, as `dumpe2fs` prints them.
fn free_counts(path: &Path) -> (u64, u64) {
    let header = dumpe2fs(path);
    let field = |name: &str| {
        let line = header
            .lines()
            .find(|line| line.starts_with(name))
            .unwrap_or_else(|| panic!("{name} in {header}"));
        first_number(line.as_bytes())
    };
    (field("Free blocks:"), field("Free inodes:"))
}

/// Mounts `path` and frees the orphans a crash left; returns how many.
fn mount_recovering(path: &Path) -> u32 {
    let bytes = fs::metadata(path).unwrap().len();
    let mut disk = open_image(path);
    recover(&mut disk, bytes).unwrap();
    let mut volume = Volume::mount(&mut disk, bytes, true).unwrap();
    let mut freed = 0;
    while volume.orphans_pending() {
        volume.recover_orphan(&mut disk, usize::MAX).unwrap();
        freed += 1;
    }
    volume.sync(&mut disk).unwrap();
    freed
}

#[test]
fn held_unlinked_files_leave_a_volume_e2fsck_accepts() {
    for (block_size, bytes) in [(4096u32, 32u64 << 20), (1024, 16 << 20)] {
        let path = scratch(&format!("held-{block_size}.img"));
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
        let keep = volume
            .create(&mut disk, ROOT_INODE, b"keep", Kind::File)
            .unwrap();
        volume
            .write(&mut disk, keep.inode, 0, &pattern(5000, 1))
            .unwrap();
        volume.sync(&mut disk).unwrap();
        let free = free_counts(&path);

        // Two files written in turn, so each has a depth-one extent tree.
        let bs = block_size as usize;
        let one = volume
            .create(&mut disk, ROOT_INODE, b"one", Kind::File)
            .unwrap();
        let two = volume
            .create(&mut disk, ROOT_INODE, b"two", Kind::File)
            .unwrap();
        for index in 0..40 {
            for (inode, seed) in [(one.inode, 0), (two.inode, 100)] {
                volume
                    .write(
                        &mut disk,
                        inode,
                        (index * bs) as u64,
                        &pattern(bs, seed + index as u32),
                    )
                    .unwrap();
            }
        }
        volume.unlink_held(&mut disk, ROOT_INODE, b"one").unwrap();
        volume.unlink_held(&mut disk, ROOT_INODE, b"two").unwrap();
        volume
            .write(&mut disk, two.inode, (60 * bs) as u64, &pattern(bs, 7))
            .unwrap();
        volume.sync(&mut disk).unwrap();
        let listing = String::from_utf8(debugfs(&path, "ls /")).unwrap();
        assert!(
            !listing.contains("one") && !listing.contains("two"),
            "{listing}"
        );

        // The holders gone without a close: e2fsck frees what is on the
        // list, and so does the next mount, to the same counts.
        let crashed = scratch(&format!("held-{block_size}-crashed.img"));
        fs::copy(&path, &crashed).unwrap();
        let by_e2fsck = e2fsck_replayed(&crashed, &format!("held-{block_size}-e2fsck.img"));
        assert_eq!(free_counts(&by_e2fsck), free);
        assert_eq!(mount_recovering(&crashed), 2);
        fsck_clean(&crashed);
        assert_eq!(free_counts(&crashed), free);
        assert_eq!(debugfs(&crashed, "cat /keep"), pattern(5000, 1));

        // The last close of each: the same again.
        volume.release(&mut disk, one.inode, usize::MAX).unwrap();
        volume.sync(&mut disk).unwrap();
        // One still held is one orphan to e2fsck, not damage.
        e2fsck_replayed(&path, &format!("held-{block_size}-one.img"));
        volume.release(&mut disk, two.inode, usize::MAX).unwrap();
        volume.sync(&mut disk).unwrap();
        drop(disk);
        fsck_clean(&path);
        assert_eq!(free_counts(&path), free);
    }
}

#[test]
fn a_hard_linked_file_is_held_only_with_its_last_name() {
    let source = scratch("links-source");
    let _ = fs::remove_dir_all(&source);
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("first"), pattern(40_000, 9)).unwrap();
    fs::hard_link(source.join("first"), source.join("second")).unwrap();
    let path = scratch("links.img");
    let output = tool("mke2fs")
        .args(["-q", "-F", "-t", "ext4", "-O", "^orphan_file", "-d"])
        .arg(&source)
        .arg(&path)
        .arg("32M")
        .output()
        .unwrap();
    assert!(output.status.success());
    let free = free_counts(&path);
    let bytes = fs::metadata(&path).unwrap().len();
    let mut disk = open_image(&path);
    let mut volume = Volume::mount(&mut disk, bytes, true).unwrap();
    let file = volume.lookup(&mut disk, ROOT_INODE, b"first").unwrap();
    assert_eq!(
        volume.lookup(&mut disk, ROOT_INODE, b"second").unwrap(),
        file
    );
    // One name of two: nothing to hold.
    volume.unlink_held(&mut disk, ROOT_INODE, b"first").unwrap();
    assert!(volume.held().is_empty());
    volume.sync(&mut disk).unwrap();
    fsck_clean(&path);
    assert_eq!(free_counts(&path), free);
    assert_eq!(debugfs(&path, "cat /second"), pattern(40_000, 9));
    // The last name.
    volume
        .unlink_held(&mut disk, ROOT_INODE, b"second")
        .unwrap();
    assert_eq!(volume.held(), [file.inode]);
    let mut out = vec![0u8; 40_000];
    let mut done = 0;
    while done < out.len() {
        done += volume
            .read(&mut disk, file.inode, done as u64, &mut out[done..])
            .unwrap();
    }
    assert_eq!(out, pattern(40_000, 9));
    volume.release(&mut disk, file.inode, usize::MAX).unwrap();
    volume.sync(&mut disk).unwrap();
    drop(disk);
    fsck_clean(&path);
    let after = free_counts(&path);
    assert!(
        after.0 > free.0 && after.1 == free.1 + 1,
        "{free:?} {after:?}"
    );
}

#[test]
fn a_volume_with_an_orphan_file_is_given_no_orphans() {
    let path = mke2fs_image("orphan-file", &["-O", "orphan_file"]);
    assert!(dumpe2fs(&path).contains("orphan_file"));
    let bytes = fs::metadata(&path).unwrap().len();
    let mut disk = open_image(&path);
    let mut volume = Volume::mount(&mut disk, bytes, true).unwrap();
    assert!(!volume.read_only() && !volume.keeps_unlinked());
    let docs = volume.resolve(&mut disk, ROOT_INODE, b"docs").unwrap();
    assert_eq!(
        volume.unlink_held(&mut disk, docs.inode, b"readme.txt"),
        Err(wyrmroot_ext4::Error::Busy)
    );
    assert!(volume.held().is_empty());
    // Without a holder the name and the node go together, as before.
    volume.unlink(&mut disk, docs.inode, b"readme.txt").unwrap();
    volume.sync(&mut disk).unwrap();
    drop(disk);
    fsck_clean(&path);
    assert_eq!(debugfs(&path, "cat /docs/deep/blob"), pattern(123_457, 4));

    // The control: the same volume without the feature takes the orphan.
    let path = mke2fs_image("no-orphan-file", &["-O", "^orphan_file"]);
    assert!(!dumpe2fs(&path).contains("orphan_file"));
    let mut disk = open_image(&path);
    let mut volume = Volume::mount(&mut disk, bytes, true).unwrap();
    let docs = volume.resolve(&mut disk, ROOT_INODE, b"docs").unwrap();
    let readme = volume.lookup(&mut disk, docs.inode, b"readme.txt").unwrap();
    assert_eq!(
        volume.unlink_held(&mut disk, docs.inode, b"readme.txt"),
        Ok(())
    );
    assert_eq!(volume.held(), [readme.inode]);
    volume.release(&mut disk, readme.inode, usize::MAX).unwrap();
    volume.sync(&mut disk).unwrap();
    drop(disk);
    fsck_clean(&path);
}

/// A journaled volume holding `/temp` (unlinked while held, in a
/// transaction whose commit loses power after `flushes` flushes) and
/// `/keep`. Returns the free counts before `/temp` existed.
fn crashed_holding(path: &Path, flushes: usize) -> (u64, u64) {
    let (mut disk, mut volume, mut journal, mut transaction) = journaled(path, None);
    let mut view = Journaled {
        device: &mut disk,
        transaction: &mut transaction,
    };
    let keep = volume
        .create(&mut view, ROOT_INODE, b"keep", Kind::File)
        .unwrap();
    volume
        .write(&mut view, keep.inode, 0, &pattern(5000, 1))
        .unwrap();
    journal
        .commit(&volume, &mut disk, &mut transaction)
        .unwrap();
    let free = free_counts(path);
    let mut view = Journaled {
        device: &mut disk,
        transaction: &mut transaction,
    };
    let temp = volume
        .create(&mut view, ROOT_INODE, b"temp", Kind::File)
        .unwrap();
    volume
        .write(&mut view, temp.inode, 0, &pattern(30_000, 2))
        .unwrap();
    journal
        .commit(&volume, &mut disk, &mut transaction)
        .unwrap();
    assert_eq!(debugfs(path, "cat /temp"), pattern(30_000, 2));

    disk.flushes = Some(flushes);
    let mut view = Journaled {
        device: &mut disk,
        transaction: &mut transaction,
    };
    volume.unlink_held(&mut view, ROOT_INODE, b"temp").unwrap();
    // Held: it still reads, and takes a write after its name is gone.
    assert_eq!(
        volume.write(&mut view, temp.inode, 30_000, &pattern(9000, 3)),
        Ok(9000)
    );
    assert_eq!(volume.stat(&mut view, temp.inode).unwrap().size, 39_000);
    assert!(
        journal
            .commit(&volume, &mut disk, &mut transaction)
            .is_err()
    );
    free
}

#[test]
fn a_crash_while_a_file_is_held_leaves_it_named_or_on_the_orphan_list() {
    // Power lost before the commit block: the unlink never happened.
    let path = journaled_format("held-uncommitted.img", 4096, 32 << 20);
    let free = crashed_holding(&path, 2);
    let by_e2fsck = e2fsck_replayed(&path, "held-uncommitted-e2fsck.img");
    assert_eq!(
        debugfs(&by_e2fsck, "cat /temp")[..30_000],
        pattern(30_000, 2)
    );
    assert_eq!(mount_recovering(&path), 0);
    fsck_clean(&path);
    assert_eq!(debugfs(&path, "cat /temp")[..30_000], pattern(30_000, 2));
    assert!(free_counts(&path).1 == free.1 - 1);

    // Power lost after it: the name is gone and the file is an orphan,
    // which e2fsck and the next mount free alike.
    let path = journaled_format("held-committed.img", 4096, 32 << 20);
    let free = crashed_holding(&path, 3);
    let by_e2fsck = e2fsck_replayed(&path, "held-committed-e2fsck.img");
    assert_eq!(free_counts(&by_e2fsck), free);
    let listing = String::from_utf8(debugfs(&by_e2fsck, "ls /")).unwrap();
    assert!(!listing.contains("temp"), "{listing}");
    assert_eq!(mount_recovering(&path), 1);
    fsck_clean(&path);
    assert_eq!(free_counts(&path), free);
    let listing = String::from_utf8(debugfs(&path, "ls /")).unwrap();
    assert!(!listing.contains("temp"), "{listing}");
    assert_eq!(debugfs(&path, "cat /keep"), pattern(5000, 1));
}

#[test]
fn a_crash_while_a_held_file_is_released_frees_it_at_the_next_mount() {
    for flushes in [2, 3] {
        let path = journaled_format(&format!("release-crash-{flushes}.img"), 4096, 32 << 20);
        let (mut disk, mut volume, mut journal, mut transaction) = journaled(&path, None);
        let free = free_counts(&path);
        let mut view = Journaled {
            device: &mut disk,
            transaction: &mut transaction,
        };
        let temp = volume
            .create(&mut view, ROOT_INODE, b"temp", Kind::File)
            .unwrap();
        volume
            .write(&mut view, temp.inode, 0, &pattern(30_000, 2))
            .unwrap();
        volume.unlink_held(&mut view, ROOT_INODE, b"temp").unwrap();
        journal
            .commit(&volume, &mut disk, &mut transaction)
            .unwrap();
        disk.flushes = Some(flushes);
        let mut view = Journaled {
            device: &mut disk,
            transaction: &mut transaction,
        };
        volume.release(&mut view, temp.inode, usize::MAX).unwrap();
        assert!(
            journal
                .commit(&volume, &mut disk, &mut transaction)
                .is_err()
        );
        drop(disk);
        let by_e2fsck = e2fsck_replayed(&path, &format!("release-crash-{flushes}-e2fsck.img"));
        assert_eq!(free_counts(&by_e2fsck), free);
        // Before the commit block the orphan is still listed; after it the
        // replay has already freed it.
        assert_eq!(mount_recovering(&path), if flushes == 2 { 1 } else { 0 });
        fsck_clean(&path);
        assert_eq!(free_counts(&path), free);
    }
}

// Freeing an orphan in steps that each fit one transaction.

/// A transaction this small holds the changes of three block groups.
const FEW: usize = 24;
type Small = Transaction<VecStore, FEW>;

/// A journaled volume of many small block groups (512 blocks of 1 KiB),
/// mounted with a transaction of [`FEW`] blocks.
fn many_groups(name: &str) -> PathBuf {
    let path = scratch(name);
    let output = tool("mke2fs")
        .args(["-q", "-F", "-t", "ext4", "-b", "1024", "-g", "512"])
        .args([
            "-O",
            "^orphan_file,^resize_inode,^metadata_csum,^uninit_bg",
            "-J",
            "size=1",
        ])
        .arg(&path)
        .arg("16M")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "mke2fs: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    path
}

fn open_small(path: &Path) -> (Image, Volume, Journal, Small) {
    let bytes = fs::metadata(path).unwrap().len();
    let mut disk = open_image(path);
    recover(&mut disk, bytes).unwrap();
    let mut volume = Volume::mount(&mut disk, bytes, true).unwrap();
    let journal = Journal::open(&mut volume, &mut disk).unwrap().unwrap();
    let store = VecStore(vec![0; FEW * volume.block_size() as usize]);
    let transaction = Transaction::new(store, &journal);
    assert_eq!(transaction.limit(), FEW);
    (disk, volume, journal, transaction)
}

/// One freeing step as a server takes it: what is pending commits first.
/// `inode` is a held inode, or `None` for the first orphan a mount found.
/// Returns whether that inode is freed, or no orphan is left.
fn free_step(
    disk: &mut Image,
    volume: &mut Volume,
    journal: &mut Journal,
    transaction: &mut Small,
    inode: Option<u32>,
) -> bool {
    journal.commit(volume, disk, transaction).unwrap();
    let room = transaction.limit();
    let mut view = Journaled {
        device: disk,
        transaction,
    };
    match inode {
        Some(inode) => volume.release(&mut view, inode, room).unwrap(),
        None => !volume.recover_orphan(&mut view, room).unwrap(),
    }
}

#[test]
fn orphans_larger_than_a_transaction_are_freed_in_steps() {
    let path = many_groups("steps.img");
    // Two files of 5 MiB written in turn: each lies in most block groups
    // and has a depth-one extent tree.
    let free = {
        let (mut disk, mut volume, mut journal, mut transaction) = journaled(&path, None);
        let free = free_counts(&path);
        for chunk in 0..320u32 {
            for (index, name) in [&b"one"[..], b"two"].into_iter().enumerate() {
                let mut view = Journaled {
                    device: &mut disk,
                    transaction: &mut transaction,
                };
                let inode = match volume.lookup(&mut view, ROOT_INODE, name) {
                    Ok(stat) => stat.inode,
                    Err(_) => {
                        volume
                            .create(&mut view, ROOT_INODE, name, Kind::File)
                            .unwrap()
                            .inode
                    }
                };
                let data = pattern(16 << 10, chunk * 2 + index as u32);
                assert_eq!(
                    volume.write(&mut view, inode, u64::from(chunk) << 14, &data),
                    Ok(data.len())
                );
                journal
                    .commit(&volume, &mut disk, &mut transaction)
                    .unwrap();
            }
        }
        journal
            .close(&mut volume, &mut disk, &mut transaction)
            .unwrap();
        free
    };
    fsck_clean(&path);
    let (mut disk, mut volume, mut journal, mut transaction) = open_small(&path);
    let files =
        [&b"one"[..], b"two"].map(|name| volume.lookup(&mut disk, ROOT_INODE, name).unwrap().inode);
    for name in [&b"one"[..], b"two"] {
        let mut view = Journaled {
            device: &mut disk,
            transaction: &mut transaction,
        };
        volume.unlink_held(&mut view, ROOT_INODE, name).unwrap();
    }
    journal
        .commit(&volume, &mut disk, &mut transaction)
        .unwrap();
    let held = scratch("steps-held.img");
    fs::copy(&path, &held).unwrap();

    // The control: all of one file at once does not fit the transaction.
    {
        let (mut disk, mut volume, _journal, mut transaction) = open_small(&held);
        let inode = {
            // Nothing holds them after a mount; recovery is the same free.
            let mut view = Journaled {
                device: &mut disk,
                transaction: &mut transaction,
            };
            volume.recover_orphan(&mut view, usize::MAX)
        };
        assert_eq!(inode, Err(wyrmroot_ext4::Error::Device(TRANSACTION_FULL)));
        assert!(volume.read_only());
    }
    fs::copy(&path, &held).unwrap();

    // In steps it does, and a step leaves the file listed until the last.
    let mut steps = 0;
    while !free_step(
        &mut disk,
        &mut volume,
        &mut journal,
        &mut transaction,
        Some(files[0]),
    ) {
        steps += 1;
        assert!(volume.is_held(files[0]));
        if steps == 2 {
            // Power is lost here, between two steps of one file.
            journal
                .commit(&volume, &mut disk, &mut transaction)
                .unwrap();
            let crashed = scratch("steps-crashed.img");
            fs::copy(&path, &crashed).unwrap();
            // e2fsck finishes both orphans, to the counts before them.
            let by_e2fsck = e2fsck_replayed(&crashed, "steps-crashed-e2fsck.img");
            assert_eq!(free_counts(&by_e2fsck), free);
            // So does the next mount: the half-freed one and the whole one,
            // which together exceed a transaction many times over.
            let (mut disk, mut volume, mut journal, mut transaction) = open_small(&crashed);
            assert!(volume.orphans_pending());
            let mut calls = 0;
            while !free_step(&mut disk, &mut volume, &mut journal, &mut transaction, None) {
                calls += 1;
            }
            assert!(calls > 4, "{calls} calls freed two files");
            assert!(!volume.read_only() && !volume.orphans_pending());
            journal
                .close(&mut volume, &mut disk, &mut transaction)
                .unwrap();
            drop(disk);
            fsck_clean(&crashed);
            assert_eq!(free_counts(&crashed), free);
        }
    }
    assert!(steps > 2, "one file was freed in {steps} steps");
    assert_eq!(volume.held(), [files[1]]);
    // The other still reads, and goes the same way.
    let mut out = vec![0u8; 16 << 10];
    let mut view = Journaled {
        device: &mut disk,
        transaction: &mut transaction,
    };
    assert_eq!(
        volume.read(&mut view, files[1], 5 << 14, &mut out),
        Ok(out.len())
    );
    assert_eq!(out, pattern(16 << 10, 11));
    while !free_step(
        &mut disk,
        &mut volume,
        &mut journal,
        &mut transaction,
        Some(files[1]),
    ) {}
    journal
        .close(&mut volume, &mut disk, &mut transaction)
        .unwrap();
    drop(disk);
    fsck_clean(&path);
    assert_eq!(free_counts(&path), free);
}

#[test]
fn an_unlink_frees_blocks_preallocated_past_an_empty_file() {
    let path = scratch("past-end.img");
    let bytes = 32 << 20;
    let mut disk = image(&path, bytes);
    format(&mut disk, bytes, &PARAMS).unwrap();
    let mut volume = Volume::mount(&mut disk, bytes, true).unwrap();
    volume.sync(&mut disk).unwrap();
    let free = free_counts(&path);
    let file = volume
        .create(&mut disk, ROOT_INODE, b"file", Kind::File)
        .unwrap();
    volume.sync(&mut disk).unwrap();
    drop(disk);
    // As fallocate leaves a file: unwritten blocks, and a size of zero.
    debugfs_write(&path, "fallocate /file 0 19");
    fsck_clean(&path);
    assert!(free_counts(&path).0 < free.0);

    let mut disk = open_image(&path);
    let mut volume = Volume::mount(&mut disk, bytes, true).unwrap();
    assert_eq!(volume.stat(&mut disk, file.inode).unwrap().size, 0);
    volume.unlink(&mut disk, ROOT_INODE, b"file").unwrap();
    volume.sync(&mut disk).unwrap();
    drop(disk);
    fsck_clean(&path);
    assert_eq!(free_counts(&path), free);
}
