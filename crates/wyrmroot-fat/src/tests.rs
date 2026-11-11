//! The reader against volumes built here byte by byte, following the same
//! specification sections, in a sparse in-memory disk.

extern crate std;

use std::collections::BTreeMap;
use std::string::String;
use std::vec;
use std::vec::Vec;

use super::*;

const SECTOR: u64 = 512;

#[derive(Default)]
struct Image {
    sectors: BTreeMap<u64, [u8; 512]>,
    reads: usize,
}

impl Image {
    fn write(&mut self, offset: u64, bytes: &[u8]) {
        for (i, &byte) in bytes.iter().enumerate() {
            let at = offset + i as u64;
            self.sectors.entry(at / SECTOR).or_insert([0; 512])[(at % SECTOR) as usize] = byte;
        }
    }

    fn get(&self, at: u64) -> u8 {
        self.sectors
            .get(&(at / SECTOR))
            .map_or(0, |sector| sector[(at % SECTOR) as usize])
    }
}

impl Disk for Image {
    fn read(&mut self, offset: u64, out: &mut [u8]) -> Result<(), DeviceError> {
        self.reads += 1;
        assert!(
            out.is_empty() || offset / SECTOR == (offset + out.len() as u64 - 1) / SECTOR,
            "a read crossed a sector"
        );
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = self.get(offset + i as u64);
        }
        Ok(())
    }
}

/// Builds a 512-byte-sector, one-sector-per-cluster FAT32 volume.
struct Builder {
    image: Image,
    total_sectors: u32,
    fat_sectors: u32,
    reserved: u32,
    next_cluster: u32,
}

const RESERVED: u32 = 32;
const CLUSTER: usize = 512;

impl Builder {
    fn new(clusters: u32) -> Self {
        let mut fat_sectors = 1;
        loop {
            let needed = ((u64::from(clusters) + 2) * 4).div_ceil(SECTOR) as u32;
            if needed == fat_sectors {
                break;
            }
            fat_sectors = needed;
        }
        let total_sectors = RESERVED + 2 * fat_sectors + clusters;
        let mut builder = Self {
            image: Image::default(),
            total_sectors,
            fat_sectors,
            reserved: RESERVED,
            next_cluster: 3,
        };
        let mut boot = [0u8; 512];
        boot[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        boot[3..11].copy_from_slice(b"WYRMTEST");
        boot[11..13].copy_from_slice(&512u16.to_le_bytes());
        boot[13] = 1;
        boot[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
        boot[16] = 2;
        boot[21] = 0xf8;
        boot[32..36].copy_from_slice(&total_sectors.to_le_bytes());
        boot[36..40].copy_from_slice(&fat_sectors.to_le_bytes());
        boot[44..48].copy_from_slice(&2u32.to_le_bytes());
        boot[66] = 0x29;
        boot[82..90].copy_from_slice(b"FAT32   ");
        boot[510] = 0x55;
        boot[511] = 0xaa;
        builder.image.write(0, &boot);
        builder.set_fat(0, 0x0fff_fff8);
        builder.set_fat(1, 0x0fff_ffff);
        builder.set_fat(2, 0x0fff_ffff);
        builder
    }

    fn set_fat(&mut self, cluster: u32, value: u32) {
        for copy in 0..2 {
            let offset = (u64::from(self.reserved) + u64::from(copy * self.fat_sectors)) * SECTOR
                + u64::from(cluster) * 4;
            self.image.write(offset, &value.to_le_bytes());
        }
    }

    fn cluster_offset(&self, cluster: u32) -> u64 {
        (u64::from(self.reserved) + 2 * u64::from(self.fat_sectors) + u64::from(cluster - 2))
            * SECTOR
    }

    /// Allocates `count` clusters, every other one when `fragmented`, and
    /// links them.
    fn chain(&mut self, count: usize, fragmented: bool) -> Vec<u32> {
        let mut clusters = Vec::new();
        for _ in 0..count {
            clusters.push(self.next_cluster);
            self.next_cluster += if fragmented { 2 } else { 1 };
        }
        for pair in clusters.windows(2) {
            self.set_fat(pair[0], pair[1]);
        }
        if let Some(&last) = clusters.last() {
            self.set_fat(last, 0x0fff_ffff);
        }
        clusters
    }

    fn write_data(&mut self, clusters: &[u32], data: &[u8]) {
        for (cluster, chunk) in clusters.iter().zip(data.chunks(CLUSTER)) {
            let offset = self.cluster_offset(*cluster);
            self.image.write(offset, chunk);
        }
    }

    fn file(&mut self, data: &[u8], fragmented: bool) -> u32 {
        let clusters = self.chain(data.len().div_ceil(CLUSTER), fragmented);
        self.write_data(&clusters, data);
        clusters.first().copied().unwrap_or(0)
    }

    /// Writes `entries` as directory `cluster`'s contents (root is 2),
    /// growing it into further clusters as needed.
    fn directory_at(&mut self, cluster: u32, entries: &[[u8; 32]]) {
        let bytes: Vec<u8> = entries.iter().flatten().copied().collect();
        let mut clusters = vec![cluster];
        let extra = bytes.len().div_ceil(CLUSTER).max(1) - 1;
        clusters.extend(self.chain(extra, false));
        if extra > 0 {
            self.set_fat(cluster, clusters[1]);
        }
        self.write_data(&clusters, &bytes);
    }

    fn directory(&mut self, entries: &[[u8; 32]]) -> u32 {
        let cluster = self.chain(1, false)[0];
        self.directory_at(cluster, entries);
        cluster
    }
}

fn short(name: &[u8; 11], attributes: u8, cluster: u32, size: u32) -> [u8; 32] {
    let mut entry = [0u8; 32];
    entry[..11].copy_from_slice(name);
    entry[11] = attributes;
    entry[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
    entry[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
    entry[28..32].copy_from_slice(&size.to_le_bytes());
    entry
}

/// The long-name entries for `name` (stored last-first), then the short one.
fn long(name: &str, short_entry: [u8; 32]) -> Vec<[u8; 32]> {
    let mut units: Vec<u16> = name.encode_utf16().collect();
    if !units.len().is_multiple_of(13) {
        units.push(0);
        while !units.len().is_multiple_of(13) {
            units.push(0xffff);
        }
    }
    let sum = checksum(&short_entry[..11]);
    let count = units.len() / 13;
    let mut entries = Vec::new();
    for number in (1..=count).rev() {
        let mut entry = [0u8; 32];
        entry[0] = number as u8 | if number == count { 0x40 } else { 0 };
        entry[11] = 0x0f;
        entry[13] = sum;
        for (i, offset) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
            .into_iter()
            .enumerate()
        {
            entry[offset..offset + 2].copy_from_slice(&units[(number - 1) * 13 + i].to_le_bytes());
        }
        entries.push(entry);
    }
    entries.push(short_entry);
    entries
}

fn names(volume: &Volume, image: &mut Image, dir: Node) -> Vec<(String, Node)> {
    let mut out = Vec::new();
    let end = volume
        .read_dir(image, dir, 0, |entry| {
            out.push((String::from_utf8_lossy(entry.name).into_owned(), entry.node));
            true
        })
        .unwrap();
    assert_eq!(end, None);
    out
}

/// A volume with a root holding a label, a deleted file, short and long
/// names and a subdirectory with a fragmented file in it.
fn sample() -> (Builder, Vec<u8>) {
    let mut builder = Builder::new(MIN_FAT32_CLUSTERS + 100);
    let data: Vec<u8> = (0..3000u32).map(|i| (i * 7 + i / 512) as u8).collect();
    let big = builder.file(&data, true);
    let readme = builder.file(b"hello\n", false);
    let sub = builder.directory(&[]);
    builder.directory_at(
        sub,
        &[
            short(b".          ", 0x10, sub, 0),
            short(b"..         ", 0x10, 0, 0),
            short(b"KERNEL  ELF", 0x20, big, data.len() as u32),
        ],
    );
    let mut root = vec![short(b"WYRMESP    ", 0x08, 0, 0)];
    let mut deleted = short(b"OLD     TXT", 0x20, readme, 6);
    deleted[0] = 0xe5;
    root.push(deleted);
    root.extend(long("Read Me.txt", short(b"README~1TXT", 0x20, readme, 6)));
    let mut lower = short(b"NOTES   MD ", 0x20, 0, 0);
    lower[12] = NT_LOWER_BASE | NT_LOWER_EXTENSION;
    root.push(lower);
    root.push(short(b"EFI        ", 0x10, sub, 0));
    builder.directory_at(2, &root);
    (builder, data)
}

#[test]
fn listing_uses_long_names_then_short_names_and_skips_labels_deleted_and_dots() {
    let (mut builder, _) = sample();
    let volume = Volume::mount(
        &mut builder.image,
        Some(u64::from(builder.total_sectors) * 512),
    )
    .unwrap();
    let listing = names(&volume, &mut builder.image, volume.root());
    let listed: Vec<_> = listing.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(listed, ["Read Me.txt", "notes.md", "EFI"]);
    assert_eq!(listing[1].1.size, 0);
    assert_eq!(listing[2].1.kind, Kind::Directory);
    let inner = names(&volume, &mut builder.image, listing[2].1);
    assert_eq!(inner.len(), 1);
    assert_eq!(inner[0].0, "KERNEL.ELF");
}

#[test]
fn lookups_ignore_ascii_case_and_paths_resolve_through_directories() {
    let (mut builder, data) = sample();
    let image = &mut builder.image;
    let volume = Volume::mount(image, None).unwrap();
    let root = volume.root();
    for name in [&b"read me.TXT"[..], b"READ ME.TXT", b"Read Me.txt"] {
        assert_eq!(volume.lookup(image, root, name).unwrap().size, 6);
    }
    // The short alias of a long name is not listed and does not match.
    assert_eq!(
        volume.lookup(image, root, b"README~1.TXT"),
        Err(Error::NotFound)
    );
    let kernel = volume.resolve(image, root, b"efi/kernel.elf").unwrap();
    assert_eq!(kernel.size as usize, data.len());
    assert_eq!(volume.resolve(image, root, b""), Ok(root));
    assert_eq!(
        volume.resolve(image, root, b"efi/missing"),
        Err(Error::NotFound)
    );
    assert_eq!(
        volume.resolve(image, root, b"notes.md/x"),
        Err(Error::NotDirectory)
    );
}

#[test]
fn reads_follow_fragmented_chains_at_any_offset_and_stop_at_the_end() {
    let (mut builder, data) = sample();
    let image = &mut builder.image;
    let volume = Volume::mount(image, None).unwrap();
    let kernel = volume
        .resolve(image, volume.root(), b"EFI/KERNEL.ELF")
        .unwrap();
    let mut cursor = Cursor::new(kernel);
    let mut whole = vec![0u8; 4096];
    assert_eq!(
        volume.read(image, &mut cursor, 0, &mut whole),
        Ok(data.len())
    );
    assert_eq!(&whole[..data.len()], &data[..]);
    for (offset, length) in [(0, 1), (511, 2), (1000, 1500), (2999, 10), (513, 512)] {
        let mut out = vec![0u8; length];
        let read = volume.read(image, &mut cursor, offset, &mut out).unwrap();
        let end = (offset as usize + length).min(data.len());
        assert_eq!(
            &out[..read],
            &data[offset as usize..end],
            "{offset}+{length}"
        );
    }
    let mut out = [0u8; 8];
    assert_eq!(volume.read(image, &mut cursor, 3000, &mut out), Ok(0));
    assert_eq!(volume.read(image, &mut cursor, u64::MAX, &mut out), Ok(0));
    let notes = volume.lookup(image, volume.root(), b"NOTES.MD").unwrap();
    assert_eq!(
        volume.read(image, &mut Cursor::new(notes), 0, &mut out),
        Ok(0)
    );
    let efi = volume.lookup(image, volume.root(), b"efi").unwrap();
    assert_eq!(
        volume.read(image, &mut Cursor::new(efi), 0, &mut out),
        Err(Error::NotFile)
    );

    // Sequential reads move the cursor forward instead of rewalking.
    let mut cursor = Cursor::new(kernel);
    let mut chunk = [0u8; 512];
    volume.read(image, &mut cursor, 0, &mut chunk).unwrap();
    let before = image.reads;
    volume.read(image, &mut cursor, 512, &mut chunk).unwrap();
    assert_eq!(image.reads - before, 2, "one FAT entry and one data read");
}

#[test]
fn listings_resume_from_cookies_across_directory_clusters() {
    let mut builder = Builder::new(MIN_FAT32_CLUSTERS + 50);
    let mut root = Vec::new();
    let mut expected = Vec::new();
    for index in 0..40 {
        let name = std::format!("file number {index:02}.dat");
        let mut short_name = *b"FILE~   DAT";
        short_name[5] = b'0' + (index / 10) as u8;
        short_name[6] = b'0' + (index % 10) as u8;
        root.extend(long(&name, short(&short_name, 0x20, 0, 0)));
        expected.push(name);
    }
    // 40 names of 3 slots each fill several 16-slot clusters.
    builder.directory_at(2, &root);
    let image = &mut builder.image;
    let volume = Volume::mount(image, None).unwrap();
    assert_eq!(
        names(&volume, image, volume.root())
            .into_iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>(),
        expected
    );
    let mut paged = Vec::new();
    let mut cookie = 0;
    loop {
        let mut taken = 0;
        let next = volume
            .read_dir(image, volume.root(), cookie, |entry| {
                if taken == 3 {
                    return false;
                }
                taken += 1;
                paged.push(String::from_utf8(entry.name.to_vec()).unwrap());
                true
            })
            .unwrap();
        match next {
            Some(next) => cookie = next,
            None => break,
        }
    }
    assert_eq!(paged, expected);
}

#[test]
fn damaged_long_names_fall_back_to_the_short_name() {
    let mut builder = Builder::new(MIN_FAT32_CLUSTERS + 10);
    let mut bad_sum = long("Long Name One", short(b"LONGNA~1   ", 0x20, 0, 0));
    bad_sum[0][13] ^= 1;
    let mut out_of_order = long(
        "A name that needs two entries",
        short(b"ANAMET~1   ", 0x20, 0, 0),
    );
    out_of_order.swap(0, 1);
    // The only long entry lacks the LAST_LONG_ENTRY flag.
    let mut orphan = long("orphan", short(b"ORPHAN     ", 0x20, 0, 0));
    orphan[0][0] = 1;
    let mut surrogate = long("ab", short(b"SURROG~1   ", 0x20, 0, 0));
    surrogate[0][1..3].copy_from_slice(&0xd800u16.to_le_bytes());
    let mut root = Vec::new();
    root.extend(bad_sum);
    root.extend(out_of_order);
    root.extend(orphan);
    root.extend(surrogate);
    builder.directory_at(2, &root);
    let image = &mut builder.image;
    let volume = Volume::mount(image, None).unwrap();
    let listed: Vec<_> = names(&volume, image, volume.root())
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert_eq!(listed, ["LONGNA~1", "ANAMET~1", "ORPHAN", "SURROG~1"]);
}

#[test]
fn small_or_malformed_boot_sectors_are_not_fat32() {
    // A FAT16-sized volume: the cluster count alone decides (§3.5).
    let mut small = Builder::new(MIN_FAT32_CLUSTERS - 1);
    assert_eq!(Volume::mount(&mut small.image, None), Err(Error::NotFat32));
    let ok = Builder::new(MIN_FAT32_CLUSTERS);
    let mut image = ok.image;
    assert!(Volume::mount(&mut image, None).is_ok());

    let patches: [(usize, &[u8]); 10] = [
        (0, &[0x00]),         // no jump
        (11, &[0x00, 0x03]),  // 768-byte sectors
        (13, &[3]),           // non-power-of-two cluster
        (14, &[0, 0]),        // no reserved sectors
        (16, &[0]),           // no FAT
        (17, &[0, 2]),        // FAT16 root entries
        (22, &[1, 0]),        // FAT16 FAT size
        (42, &[0, 1]),        // unknown FAT32 version
        (21, &[0x12]),        // media byte
        (510, &[0x55, 0x00]), // signature
    ];
    for (offset, bytes) in patches {
        let mut builder = Builder::new(MIN_FAT32_CLUSTERS);
        builder.image.write(offset as u64, bytes);
        assert_eq!(
            Volume::mount(&mut builder.image, None),
            Err(Error::NotFat32),
            "patch at {offset}"
        );
    }
    let mut builder = Builder::new(MIN_FAT32_CLUSTERS);
    builder.image.write(44, &0u32.to_le_bytes());
    assert_eq!(Volume::mount(&mut builder.image, None), Err(Error::Corrupt));
    let mut builder = Builder::new(MIN_FAT32_CLUSTERS);
    builder.image.write(40, &[0x83, 0]); // mirroring off, FAT 3 of 2
    assert_eq!(Volume::mount(&mut builder.image, None), Err(Error::Corrupt));
    let builder = Builder::new(MIN_FAT32_CLUSTERS);
    let mut image = builder.image;
    let claimed = u64::from(builder.total_sectors) * 512;
    assert_eq!(
        Volume::mount(&mut image, Some(claimed - 1)),
        Err(Error::Corrupt)
    );
}

#[test]
fn broken_chains_and_entries_are_corruption_and_loops_end() {
    let (mut builder, data) = sample();
    let kernel_first = {
        let volume = Volume::mount(&mut builder.image, None).unwrap();
        volume
            .resolve(&mut builder.image, volume.root(), b"efi/kernel.elf")
            .unwrap()
            .first_cluster
    };
    // A chain that ends early for the file's size.
    builder.set_fat(kernel_first, 0x0fff_ffff);
    let image = &mut builder.image;
    let volume = Volume::mount(image, None).unwrap();
    let kernel = volume
        .resolve(image, volume.root(), b"efi/kernel.elf")
        .unwrap();
    let mut out = vec![0u8; data.len()];
    assert_eq!(
        volume.read(image, &mut Cursor::new(kernel), 0, &mut out),
        Err(Error::Corrupt)
    );
    // A chain through a free cluster, and through a bad one.
    for value in [0u32, FAT_BAD, 1] {
        builder.set_fat(kernel_first, value);
        let image = &mut builder.image;
        assert_eq!(
            volume.read(image, &mut Cursor::new(kernel), 600, &mut out[..10]),
            Err(Error::Corrupt),
            "{value:#x}"
        );
    }

    // A directory chain that loops on itself ends at the 2 MiB bound.
    let mut looped = Builder::new(MIN_FAT32_CLUSTERS + 10);
    let entries: Vec<[u8; 32]> = (0..16)
        .map(|i| {
            let mut name = *b"LOOP       ";
            name[4] = b'A' + i;
            short(&name, 0x20, 0, 0)
        })
        .collect();
    looped.directory_at(2, &entries);
    looped.set_fat(2, 2);
    let image = &mut looped.image;
    let volume = Volume::mount(image, None).unwrap();
    let mut count = 0;
    let end = volume
        .read_dir(image, volume.root(), 0, |_| {
            count += 1;
            true
        })
        .unwrap();
    assert_eq!(end, None);
    assert_eq!(count, MAX_DIRECTORY_ENTRIES as usize);

    // A nonempty file with no cluster, and a directory with a bad one.
    for entry in [
        short(b"EMPTY   BIN", 0x20, 0, 10),
        short(b"SUBDIR     ", 0x10, 0, 0),
        short(b"FAR     BIN", 0x20, 0x0fff_0000, 10),
    ] {
        let mut builder = Builder::new(MIN_FAT32_CLUSTERS + 10);
        builder.directory_at(2, &[entry]);
        let image = &mut builder.image;
        let volume = Volume::mount(image, None).unwrap();
        assert_eq!(
            volume.read_dir(image, volume.root(), 0, |_| true),
            Err(Error::Corrupt)
        );
    }
}

#[test]
fn the_checksum_matches_the_specification_example_shape() {
    // §7.2: rotate right, then add; checked against a hand computation.
    let mut sum = 0u8;
    for &byte in b"THEQUI~1FOX" {
        sum = (if sum & 1 != 0 { 0x80u8 } else { 0 })
            .wrapping_add(sum >> 1)
            .wrapping_add(byte);
    }
    assert_eq!(checksum(b"THEQUI~1FOX"), sum);
}
