use std::vec;
use std::vec::Vec;

use super::*;

/// An in-memory volume.
struct Memory {
    bytes: Vec<u8>,
    flushes: usize,
}

impl Memory {
    fn new(size: usize) -> Self {
        // Non-zero garbage, so nothing relies on a zeroed device.
        Self {
            bytes: vec![0xA5; size],
            flushes: 0,
        }
    }
}

impl Device for Memory {
    fn read(&mut self, offset: u64, out: &mut [u8]) -> Result<(), DeviceError> {
        let start = offset as usize;
        let source = self
            .bytes
            .get(start..start + out.len())
            .ok_or(DeviceError(1))?;
        out.copy_from_slice(source);
        Ok(())
    }
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), DeviceError> {
        let start = offset as usize;
        let target = self
            .bytes
            .get_mut(start..start + data.len())
            .ok_or(DeviceError(2))?;
        target.copy_from_slice(data);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), DeviceError> {
        self.flushes += 1;
        Ok(())
    }
}

const SIZE: usize = 8 << 20;

fn params(block_size: u32) -> FormatParams {
    FormatParams {
        block_size,
        uuid: *b"wyrmroot-ext4-ut",
        label: *b"test\0\0\0\0\0\0\0\0\0\0\0\0",
        time: 1_700_000_000,
    }
}

fn formatted(block_size: u32) -> (Memory, Volume) {
    let mut disk = Memory::new(SIZE);
    format(&mut disk, SIZE as u64, &params(block_size)).unwrap();
    let volume = Volume::mount(&mut disk, SIZE as u64, true).unwrap();
    (disk, volume)
}

fn names(volume: &Volume, disk: &mut Memory, dir: u32) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let next = volume
        .read_dir(disk, dir, 0, |entry| {
            out.push(entry.name.to_vec());
            true
        })
        .unwrap();
    assert_eq!(next, None);
    out.sort();
    out
}

#[test]
fn crc32c_matches_the_castagnoli_check_value() {
    // CRC-32C("123456789") is 0xE3069283 with the usual final inversion.
    assert_eq!(!crc::update(!0, b"123456789"), 0xE306_9283);
    assert_eq!(crc::update_zeros(7, 5), crc::update(7, &[0; 5]));
}

#[test]
fn sparse_super_backups_are_groups_zero_one_and_powers_of_three_five_seven() {
    let groups: Vec<u32> = (0..60).filter(|&group| format::backup(group)).collect();
    assert_eq!(groups, [0, 1, 3, 5, 7, 9, 25, 27, 49]);
}

#[test]
fn a_formatted_volume_mounts_with_an_empty_root_and_lost_found() {
    for block_size in [1024, 2048, 4096] {
        let (mut disk, volume) = formatted(block_size);
        assert!(!volume.read_only());
        assert_eq!(volume.block_size(), block_size);
        assert_eq!(
            names(&volume, &mut disk, ROOT_INODE),
            [b"lost+found".to_vec()]
        );
        let lost = volume.lookup(&mut disk, ROOT_INODE, b"lost+found").unwrap();
        assert_eq!(lost.kind, Kind::Directory);
        assert!(names(&volume, &mut disk, lost.inode).is_empty());
        let usage = volume.usage();
        assert!(usage.free_blocks > 0 && usage.free_blocks < usage.blocks);
    }
}

#[test]
fn files_written_read_back_after_a_remount() {
    for block_size in [1024, 4096] {
        let (mut disk, mut volume) = formatted(block_size);
        let file = volume
            .create(&mut disk, ROOT_INODE, b"hello.txt", Kind::File)
            .unwrap();
        assert_eq!(
            volume
                .write(&mut disk, file.inode, 0, b"hello, disk\n")
                .unwrap(),
            12
        );
        let volume = Volume::mount(&mut disk, SIZE as u64, true).unwrap();
        let found = volume.resolve(&mut disk, ROOT_INODE, b"hello.txt").unwrap();
        assert_eq!(found.size, 12);
        let mut out = [0u8; 64];
        assert_eq!(
            volume.read(&mut disk, found.inode, 0, &mut out).unwrap(),
            12
        );
        assert_eq!(&out[..12], b"hello, disk\n");
        assert_eq!(
            volume.read(&mut disk, found.inode, 12, &mut out).unwrap(),
            0
        );
    }
}

#[test]
fn large_sparse_and_partial_writes_read_back_exactly() {
    let (mut disk, mut volume) = formatted(1024);
    let file = volume
        .create(&mut disk, ROOT_INODE, b"data", Kind::File)
        .unwrap();
    let pattern: Vec<u8> = (0..70_000u32).map(|i| (i * 7 + i / 251) as u8).collect();
    let mut at = 0;
    while at < pattern.len() {
        let end = (at + 3000).min(pattern.len());
        assert_eq!(
            volume
                .write(&mut disk, file.inode, at as u64, &pattern[at..end])
                .unwrap(),
            end - at
        );
        at = end;
    }
    // A hole, then data past it; then a partial overwrite in the middle.
    volume
        .write(&mut disk, file.inode, 200_000, b"tail")
        .unwrap();
    volume.write(&mut disk, file.inode, 1500, b"XYZ").unwrap();
    let stat = volume.stat(&mut disk, file.inode).unwrap();
    assert_eq!(stat.size, 200_004);
    let mut out = vec![0u8; 200_004];
    let mut done = 0;
    while done < out.len() {
        let read = volume
            .read(
                &mut disk,
                file.inode,
                done as u64,
                &mut out[done..(done + 5000).min(200_004)],
            )
            .unwrap();
        assert!(read > 0);
        done += read;
    }
    let mut expected = pattern.clone();
    expected[1500..1503].copy_from_slice(b"XYZ");
    expected.resize(200_000, 0);
    expected.extend_from_slice(b"tail");
    assert_eq!(out, expected);
}

#[test]
fn fragmented_files_grow_their_extent_tree_and_shrink_back() {
    let (mut disk, mut volume) = formatted(1024);
    let a = volume
        .create(&mut disk, ROOT_INODE, b"a", Kind::File)
        .unwrap();
    let b = volume
        .create(&mut disk, ROOT_INODE, b"b", Kind::File)
        .unwrap();
    let before = volume.usage().free_blocks;
    // Interleaved one-block writes keep every extent one block long. A
    // depth-one tree holds four full 1 KiB leaves of 84 extents; the next
    // fragment is refused.
    for index in 0..336u64 {
        let block = [index as u8; 1024];
        volume
            .write(&mut disk, a.inode, index * 1024, &block)
            .unwrap();
        volume
            .write(&mut disk, b.inode, index * 1024, &block)
            .unwrap();
    }
    volume
        .write(&mut disk, b.inode, 336 * 1024, &[1; 1024])
        .unwrap();
    assert_eq!(
        volume.write(&mut disk, a.inode, 336 * 1024, &[1; 1024]),
        Err(Error::NoSpace)
    );
    assert_eq!(volume.stat(&mut disk, a.inode).unwrap().size, 336 * 1024);
    let node = volume.inode(&mut disk, a.inode).unwrap();
    assert_eq!(extent::root_depth(node.root()), 1);
    let mut out = [0u8; 1024];
    for index in [0u64, 3, 4, 83, 84, 200, 335] {
        volume
            .read(&mut disk, a.inode, index * 1024, &mut out)
            .unwrap();
        assert!(out.iter().all(|&byte| byte == index as u8), "block {index}");
    }
    volume.truncate(&mut disk, a.inode, 2 * 1024 + 10).unwrap();
    let node = volume.inode(&mut disk, a.inode).unwrap();
    assert_eq!(volume.stat(&mut disk, a.inode).unwrap().size, 2 * 1024 + 10);
    assert_eq!(node.sectors(), 3 * 2 + 2, "three data blocks and one leaf");
    // Growing again reads zeros past the old end.
    volume.write(&mut disk, a.inode, 4000, b"z").unwrap();
    let mut out = [9u8; 30];
    volume.read(&mut disk, a.inode, 2 * 1024, &mut out).unwrap();
    assert_eq!(out[..10], [2u8; 10]);
    assert!(out[10..].iter().all(|&byte| byte == 0));
    volume.unlink(&mut disk, ROOT_INODE, b"a").unwrap();
    volume.unlink(&mut disk, ROOT_INODE, b"b").unwrap();
    assert_eq!(volume.usage().free_blocks, before);
}

#[test]
fn directories_nest_list_in_pages_and_grow_past_one_block() {
    let (mut disk, mut volume) = formatted(1024);
    let dir = volume
        .create(&mut disk, ROOT_INODE, b"etc", Kind::Directory)
        .unwrap();
    let sub = volume
        .create(&mut disk, dir.inode, b"conf.d", Kind::Directory)
        .unwrap();
    volume
        .create(&mut disk, sub.inode, b"x", Kind::File)
        .unwrap();
    assert_eq!(
        volume
            .resolve(&mut disk, ROOT_INODE, b"etc/conf.d/x")
            .unwrap()
            .kind,
        Kind::File
    );
    assert_eq!(
        volume.resolve(&mut disk, ROOT_INODE, b"etc/conf.d/x/y"),
        Err(Error::NotDirectory)
    );
    assert_eq!(
        volume.resolve(&mut disk, ROOT_INODE, b"etc/nope"),
        Err(Error::NotFound)
    );
    assert_eq!(volume.inode(&mut disk, dir.inode).unwrap().links(), 3);
    let mut expected = Vec::new();
    for index in 0..120 {
        let name = std::format!("file-with-a-long-name-{index:04}");
        volume
            .create(&mut disk, dir.inode, name.as_bytes(), Kind::File)
            .unwrap();
        expected.push(name.into_bytes());
    }
    expected.push(b"conf.d".to_vec());
    expected.sort();
    assert!(volume.stat(&mut disk, dir.inode).unwrap().size > 1024);
    // Pages of seven, resumed by cookie.
    let mut seen = Vec::new();
    let mut cookie = 0;
    loop {
        let mut page = 0;
        let next = volume
            .read_dir(&mut disk, dir.inode, cookie, |entry| {
                if page == 7 {
                    return false;
                }
                page += 1;
                seen.push(entry.name.to_vec());
                true
            })
            .unwrap();
        match next {
            Some(next) => cookie = next,
            None => break,
        }
    }
    seen.sort();
    assert_eq!(seen, expected);
}

#[test]
fn unlink_frees_everything_and_refuses_full_directories() {
    let (mut disk, mut volume) = formatted(4096);
    let blocks = volume.usage().free_blocks;
    let dir = volume
        .create(&mut disk, ROOT_INODE, b"d", Kind::Directory)
        .unwrap();
    let file = volume
        .create(&mut disk, dir.inode, b"f", Kind::File)
        .unwrap();
    volume
        .write(&mut disk, file.inode, 0, &[1u8; 9000])
        .unwrap();
    assert_eq!(
        volume.unlink(&mut disk, ROOT_INODE, b"d"),
        Err(Error::NotEmpty)
    );
    assert_eq!(
        volume.create(&mut disk, dir.inode, b"f", Kind::File),
        Err(Error::Exists)
    );
    volume.unlink(&mut disk, dir.inode, b"f").unwrap();
    assert_eq!(volume.stat(&mut disk, file.inode), Err(Error::NotFound));
    volume.unlink(&mut disk, ROOT_INODE, b"d").unwrap();
    assert_eq!(volume.usage().free_blocks, blocks);
    assert_eq!(volume.inode(&mut disk, ROOT_INODE).unwrap().links(), 3);
    assert_eq!(
        names(&volume, &mut disk, ROOT_INODE),
        [b"lost+found".to_vec()]
    );
    // The freed inode and blocks are reused.
    let again = volume
        .create(&mut disk, ROOT_INODE, b"again", Kind::File)
        .unwrap();
    assert_eq!(again.inode, file.inode.min(dir.inode));
}

#[test]
fn names_and_kinds_are_checked() {
    let (mut disk, mut volume) = formatted(4096);
    for name in [&b""[..], b".", b"..", b"a/b", b"nul\0", &[b'x'; 256]] {
        assert_eq!(
            volume.create(&mut disk, ROOT_INODE, name, Kind::File),
            Err(Error::InvalidName)
        );
    }
    let file = volume
        .create(&mut disk, ROOT_INODE, b"f", Kind::File)
        .unwrap();
    assert_eq!(
        volume.create(&mut disk, file.inode, b"g", Kind::File),
        Err(Error::NotDirectory)
    );
    assert_eq!(
        volume.write(&mut disk, ROOT_INODE, 0, b"x"),
        Err(Error::IsDirectory)
    );
    let mut out = [0u8; 4];
    assert_eq!(
        volume.read(&mut disk, ROOT_INODE, 0, &mut out),
        Err(Error::IsDirectory)
    );
    assert_eq!(
        volume.write(&mut disk, file.inode, u64::from(u32::MAX) * 4096, b"x"),
        Err(Error::TooLarge)
    );
}

#[test]
fn a_full_volume_answers_no_space_and_keeps_its_counts() {
    let mut disk = Memory::new(1 << 20);
    format(&mut disk, 1 << 20, &params(1024)).unwrap();
    let mut volume = Volume::mount(&mut disk, 1 << 20, true).unwrap();
    let file = volume
        .create(&mut disk, ROOT_INODE, b"big", Kind::File)
        .unwrap();
    let chunk = [7u8; 8192];
    let mut offset = 0u64;
    loop {
        match volume.write(&mut disk, file.inode, offset, &chunk) {
            Ok(written) if written == chunk.len() => offset += written as u64,
            Ok(written) => {
                offset += written as u64;
                break;
            }
            Err(error) => {
                assert_eq!(error, Error::NoSpace);
                break;
            }
        }
    }
    assert_eq!(volume.usage().free_blocks, 0);
    assert_eq!(volume.stat(&mut disk, file.inode).unwrap().size, offset);
    volume.unlink(&mut disk, ROOT_INODE, b"big").unwrap();
    let remounted = Volume::mount(&mut disk, 1 << 20, true).unwrap();
    assert!(remounted.usage().free_blocks > 900);
}

#[test]
fn checksum_damage_is_corruption() {
    let (mut disk, mut volume) = formatted(4096);
    let file = volume
        .create(&mut disk, ROOT_INODE, b"f", Kind::File)
        .unwrap();
    volume.write(&mut disk, file.inode, 0, b"data").unwrap();
    // The superblock.
    let mut damaged = Memory {
        bytes: disk.bytes.clone(),
        flushes: 0,
    };
    damaged.bytes[1024 + 0x78] ^= 1;
    assert!(matches!(
        Volume::mount(&mut damaged, SIZE as u64, true),
        Err(Error::Corrupt)
    ));
    // The file's inode: find its bytes through the volume.
    let offset = volume.inode_offset(&mut disk, file.inode).unwrap() as usize;
    let mut damaged = Memory {
        bytes: disk.bytes.clone(),
        flushes: 0,
    };
    damaged.bytes[offset + 0x10] ^= 1;
    let volume2 = Volume::mount(&mut damaged, SIZE as u64, true).unwrap();
    assert_eq!(volume2.stat(&mut damaged, file.inode), Err(Error::Corrupt));
    // The root directory block.
    let root = volume.inode(&mut disk, ROOT_INODE).unwrap();
    let block = volume.map(&mut disk, &root, 0).unwrap().unwrap().physical as usize * 4096;
    let mut damaged = Memory {
        bytes: disk.bytes.clone(),
        flushes: 0,
    };
    damaged.bytes[block + 30] ^= 1;
    let volume3 = Volume::mount(&mut damaged, SIZE as u64, true).unwrap();
    assert_eq!(
        volume3.lookup(&mut damaged, ROOT_INODE, b"f"),
        Err(Error::Corrupt)
    );
}

fn patch_superblock(disk: &mut Memory, at: usize, value: u32) {
    let sb = &mut disk.bytes[1024..2048];
    put32(sb, at, value);
    let sum = crc::update(!0, &sb[..0x3FC]);
    put32(sb, 0x3FC, sum);
}

#[test]
fn features_decide_between_refusal_read_only_and_read_write() {
    let (disk, _) = formatted(4096);
    let incompat = get32(&disk.bytes[1024..], 0x60);
    let ro_compat = get32(&disk.bytes[1024..], 0x64);
    let mut case = Memory {
        bytes: disk.bytes.clone(),
        flushes: 0,
    };
    patch_superblock(&mut case, 0x60, incompat | 0x8000);
    assert!(matches!(
        Volume::mount(&mut case, SIZE as u64, true),
        Err(Error::Unsupported)
    ));
    let mut case = Memory {
        bytes: disk.bytes.clone(),
        flushes: 0,
    };
    patch_superblock(&mut case, 0x60, incompat | INCOMPAT_RECOVER);
    assert!(matches!(
        Volume::mount(&mut case, SIZE as u64, true),
        Err(Error::Unsupported)
    ));
    // An unknown read-only-compatible feature: read, never write.
    let mut case = Memory {
        bytes: disk.bytes.clone(),
        flushes: 0,
    };
    patch_superblock(&mut case, 0x64, ro_compat | 0x10000);
    let mut volume = Volume::mount(&mut case, SIZE as u64, true).unwrap();
    assert!(volume.read_only());
    assert_eq!(
        names(&volume, &mut case, ROOT_INODE),
        [b"lost+found".to_vec()]
    );
    assert_eq!(
        volume.create(&mut case, ROOT_INODE, b"x", Kind::File),
        Err(Error::ReadOnly)
    );
    // Asking for read-only is honoured too, and a device too small is refused.
    let mut case = Memory {
        bytes: disk.bytes.clone(),
        flushes: 0,
    };
    assert!(
        Volume::mount(&mut case, SIZE as u64, false)
            .unwrap()
            .read_only()
    );
    assert!(matches!(
        Volume::mount(&mut case, SIZE as u64 / 2, true),
        Err(Error::Corrupt)
    ));
    let mut blank = Memory::new(SIZE);
    assert!(matches!(
        Volume::mount(&mut blank, SIZE as u64, true),
        Err(Error::NotExt4)
    ));
}

#[test]
fn sync_flushes_the_device() {
    let (mut disk, volume) = formatted(4096);
    let before = disk.flushes;
    volume.sync(&mut disk).unwrap();
    assert_eq!(disk.flushes, before + 1);
}

/// A deleted entry's stale name length may run past its record and the
/// block; walking it must not read the name (review D1, 2026-11-11).
#[test]
fn a_deleted_entry_with_a_stale_long_name_is_skipped() {
    let mut disk = Memory::new(SIZE);
    format(&mut disk, SIZE as u64, &params(4096)).unwrap();
    // Drop metadata_csum (ro_compat bit 0x400) so the edit needs no checksum.
    let ro_compat = 1024 + 0x64;
    let flags = u32::from_le_bytes(disk.bytes[ro_compat..ro_compat + 4].try_into().unwrap());
    disk.bytes[ro_compat..ro_compat + 4].copy_from_slice(&(flags & !0x400).to_le_bytes());
    let bs = 4096;
    let root = (0..SIZE / bs)
        .map(|block| block * bs)
        .find(|&at| {
            let d = &disk.bytes[at..at + 24];
            d[0..4] == 2u32.to_le_bytes() && d[8] == b'.' && d[12..16] == 2u32.to_le_bytes()
        })
        .expect("the root directory block");
    let limit = bs - 12;
    let mut offset = 0;
    let last = loop {
        let rec_len = usize::from(u16::from_le_bytes(
            disk.bytes[root + offset + 4..root + offset + 6]
                .try_into()
                .unwrap(),
        ));
        if offset + rec_len == limit {
            break (offset, rec_len);
        }
        offset += rec_len;
    };
    let field = root + last.0 + 4;
    disk.bytes[field..field + 2].copy_from_slice(&((last.1 - 8) as u16).to_le_bytes());
    let deleted = root + limit - 8;
    disk.bytes[deleted..deleted + 8].copy_from_slice(&[0, 0, 0, 0, 8, 0, 255, 0]);

    let mut volume = Volume::mount(&mut disk, SIZE as u64, true).unwrap();
    assert_eq!(
        volume
            .lookup(&mut disk, ROOT_INODE, b"x")
            .map(|stat| stat.inode),
        Err(Error::NotFound)
    );
    assert_eq!(
        names(&volume, &mut disk, ROOT_INODE),
        [b"lost+found".to_vec()]
    );
    volume
        .create(&mut disk, ROOT_INODE, b"after", Kind::File)
        .unwrap();
    assert!(volume.lookup(&mut disk, ROOT_INODE, b"after").is_ok());
}
