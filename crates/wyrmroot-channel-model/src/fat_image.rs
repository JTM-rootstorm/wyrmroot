//! A dense FAT32 image builder for service tests: 512-byte sectors, one
//! sector per cluster, two FATs, every name stored with a long-name set.

const SECTOR: usize = 512;
const RESERVED: u32 = 32;
/// The fewest clusters a FAT32 volume may have.
pub const MIN_CLUSTERS: u32 = 65_525;

pub enum Entry<'a> {
    File(&'a str, &'a [u8]),
    Directory(&'a str, Vec<Entry<'a>>),
}

pub struct FatImage {
    bytes: Vec<u8>,
    fat_sectors: u32,
    next_cluster: u32,
    next_alias: u32,
}

impl FatImage {
    /// A formatted volume of `clusters` clusters holding `root`.
    pub fn build(clusters: u32, root: &[Entry<'_>]) -> Vec<u8> {
        let fat_sectors = ((clusters as usize + 2) * 4).div_ceil(SECTOR) as u32;
        let total = RESERVED + 2 * fat_sectors + clusters;
        let mut image = Self {
            bytes: vec![0; total as usize * SECTOR],
            fat_sectors,
            next_cluster: 3,
            next_alias: 1,
        };
        let boot = &mut image.bytes[..SECTOR];
        boot[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        boot[3..11].copy_from_slice(b"WYRMTEST");
        boot[11..13].copy_from_slice(&512u16.to_le_bytes());
        boot[13] = 1;
        boot[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
        boot[16] = 2;
        boot[21] = 0xf8;
        boot[32..36].copy_from_slice(&total.to_le_bytes());
        boot[36..40].copy_from_slice(&fat_sectors.to_le_bytes());
        boot[44..48].copy_from_slice(&2u32.to_le_bytes());
        boot[82..90].copy_from_slice(b"FAT32   ");
        boot[510] = 0x55;
        boot[511] = 0xaa;
        image.set_fat(0, 0x0fff_fff8);
        image.set_fat(1, 0x0fff_ffff);
        image.write_directory(2, root);
        image.bytes
    }

    fn set_fat(&mut self, cluster: u32, value: u32) {
        for copy in 0..2 {
            let at = (RESERVED + copy * self.fat_sectors) as usize * SECTOR + cluster as usize * 4;
            self.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
    }

    fn offset(&self, cluster: u32) -> usize {
        (RESERVED + 2 * self.fat_sectors + cluster - 2) as usize * SECTOR
    }

    /// Links `count` new clusters after `first` (already allocated).
    fn chain_from(&mut self, first: u32, count: usize) -> Vec<u32> {
        let mut clusters = vec![first];
        for _ in 1..count {
            clusters.push(self.next_cluster);
            self.next_cluster += 1;
        }
        for pair in clusters.windows(2) {
            self.set_fat(pair[0], pair[1]);
        }
        self.set_fat(*clusters.last().unwrap(), 0x0fff_ffff);
        clusters
    }

    fn allocate(&mut self) -> u32 {
        let cluster = self.next_cluster;
        self.next_cluster += 1;
        cluster
    }

    fn write_chain(&mut self, first: u32, data: &[u8]) {
        let clusters = self.chain_from(first, data.len().div_ceil(SECTOR).max(1));
        for (cluster, chunk) in clusters.iter().zip(data.chunks(SECTOR)) {
            let at = self.offset(*cluster);
            self.bytes[at..at + chunk.len()].copy_from_slice(chunk);
        }
    }

    fn write_directory(&mut self, cluster: u32, entries: &[Entry<'_>]) {
        let mut slots: Vec<[u8; 32]> = Vec::new();
        for entry in entries {
            let (name, attributes, first, size) = match entry {
                Entry::File(name, data) => {
                    let first = if data.is_empty() { 0 } else { self.allocate() };
                    if first != 0 {
                        self.write_chain(first, data);
                    }
                    (*name, 0x20, first, data.len() as u32)
                }
                Entry::Directory(name, children) => {
                    let first = self.allocate();
                    self.write_directory(first, children);
                    (*name, 0x10, first, 0)
                }
            };
            let mut short = *b"ENTRY~     ";
            let alias = format!("{:02}", self.next_alias % 100);
            self.next_alias += 1;
            short[6..8].copy_from_slice(alias.as_bytes());
            slots.extend(long_entries(name, &short));
            let mut slot = [0u8; 32];
            slot[..11].copy_from_slice(&short);
            slot[11] = attributes;
            slot[20..22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
            slot[26..28].copy_from_slice(&(first as u16).to_le_bytes());
            slot[28..32].copy_from_slice(&size.to_le_bytes());
            slots.push(slot);
        }
        let bytes: Vec<u8> = slots.concat();
        self.write_chain(cluster, &bytes);
    }
}

fn long_entries(name: &str, short: &[u8; 11]) -> Vec<[u8; 32]> {
    let mut units: Vec<u16> = name.encode_utf16().collect();
    if !units.len().is_multiple_of(13) {
        units.push(0);
        while !units.len().is_multiple_of(13) {
            units.push(0xffff);
        }
    }
    let sum = short
        .iter()
        .fold(0u8, |sum, &byte| sum.rotate_right(1).wrapping_add(byte));
    let count = units.len() / 13;
    (1..=count)
        .rev()
        .map(|number| {
            let mut entry = [0u8; 32];
            entry[0] = number as u8 | if number == count { 0x40 } else { 0 };
            entry[11] = 0x0f;
            entry[13] = sum;
            for (i, at) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
                .into_iter()
                .enumerate()
            {
                entry[at..at + 2].copy_from_slice(&units[(number - 1) * 13 + i].to_le_bytes());
            }
            entry
        })
        .collect()
}
