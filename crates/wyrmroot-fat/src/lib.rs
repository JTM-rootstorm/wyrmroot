//! Allocation-free, read-only FAT32 (root `STORAGE_PLAN.md` W6).
//!
//! Written from the Microsoft FAT Specification (August 30 2005, the SD
//! Association contribution of `fatgen103`): §3 boot sector and BPB, §3.5
//! FAT type determination, §4 the FAT, §6 directory entries, §7 long names.
//! No implementation source was copied; the `fatfs` crate (MIT) was
//! considered and not adopted because it needs `alloc` and a writable,
//! std-style I/O model this no-allocation service does not have.
//!
//! Only FAT32 mounts: a volume with fewer than 65525 clusters is FAT12 or
//! FAT16 and is refused. Every on-disk value is checked and every walk is
//! bounded: cluster chains by the cluster count, directories by the
//! specification's 2 MiB limit, long names by 20 entries.
//!
//! Names come back as bytes. A valid long name is decoded from UTF-16 to
//! UTF-8; otherwise the 8.3 short name is used, with its NT lower-case bits
//! honoured and its bytes passed through unchanged (they are in an unknown
//! OEM code page). Lookup ignores ASCII case, as FAT itself does (§7.4);
//! other characters compare exactly. `.` and `..` are never listed.

#![no_std]
#![forbid(unsafe_code)]

/// A failed read, carrying a source-defined code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceError(pub u32);

/// Byte-addressed reads from the volume. A read never spans more than one
/// sector of the volume, so a source may serve it from a sector cache.
pub trait Disk {
    fn read(&mut self, offset: u64, out: &mut [u8]) -> Result<(), DeviceError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Device(DeviceError),
    /// Sector 0 is not a FAT32 boot sector.
    NotFat32,
    /// The volume's metadata contradicts itself or the specification.
    Corrupt,
    NotFound,
    NotDirectory,
    NotFile,
}

impl From<DeviceError> for Error {
    fn from(error: DeviceError) -> Self {
        Self::Device(error)
    }
}

/// The longest name [`Volume::read_dir`] reports, in bytes.
pub const MAX_NAME_BYTES: usize = 255;
/// A directory holds at most this many 32-byte entries (§6.4: 2 MiB).
pub const MAX_DIRECTORY_ENTRIES: u32 = 1 << 16;
const ENTRY_BYTES: u32 = 32;
const MIN_FAT32_CLUSTERS: u32 = 65_525;
const FAT_ENTRY_MASK: u32 = 0x0fff_ffff;
const FAT_BAD: u32 = 0x0fff_fff7;
const FAT_EOC_MIN: u32 = 0x0fff_fff8;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_LONG_NAME: u8 = 0x0f;
const ATTR_LONG_NAME_MASK: u8 = 0x3f;
const LAST_LONG_ENTRY: u8 = 0x40;
const MAX_LONG_ENTRIES: usize = 20;
const NT_LOWER_BASE: u8 = 0x08;
const NT_LOWER_EXTENSION: u8 = 0x10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Directory,
    File,
}

/// One file or directory on the volume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Node {
    pub kind: Kind,
    /// Zero only for an empty file.
    pub first_cluster: u32,
    /// Bytes, for a file; zero for a directory.
    pub size: u32,
}

/// A mounted FAT32 volume's geometry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Volume {
    bytes_per_sector: u32,
    cluster_bytes: u32,
    fat_offset: u64,
    data_offset: u64,
    cluster_count: u32,
    root_cluster: u32,
    total_sectors: u32,
}

/// A position in one file's cluster chain, so that sequential reads do not
/// walk the chain from its start every time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cursor {
    node: Node,
    index: u32,
    cluster: u32,
}

impl Cursor {
    pub const fn new(node: Node) -> Self {
        Self {
            node,
            index: 0,
            cluster: node.first_cluster,
        }
    }

    pub const fn node(&self) -> Node {
        self.node
    }
}

/// One directory entry, borrowed from the reader's name buffer.
#[derive(Clone, Copy, Debug)]
pub struct Entry<'a> {
    pub name: &'a [u8],
    pub node: Node,
}

fn le16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn le32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

impl Volume {
    /// Reads and checks the boot sector. `volume_bytes`, if known, bounds
    /// the sectors the BPB may claim.
    pub fn mount<D: Disk + ?Sized>(disk: &mut D, volume_bytes: Option<u64>) -> Result<Self, Error> {
        let mut boot = [0u8; 512];
        disk.read(0, &mut boot)?;
        let bytes_per_sector = u32::from(le16(&boot, 11));
        let sectors_per_cluster = u32::from(boot[13]);
        let reserved = u32::from(le16(&boot, 14));
        let fat_count = u32::from(boot[16]);
        let total_sectors = le32(&boot, 32);
        let fat_sectors = le32(&boot, 36);
        let ext_flags = le16(&boot, 40);
        let root_cluster = le32(&boot, 44);
        let jump = (boot[0] == 0xeb && boot[2] == 0x90) || boot[0] == 0xe9;
        let valid = jump
            && matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096)
            && sectors_per_cluster.is_power_of_two()
            && sectors_per_cluster <= 128
            && reserved != 0
            && (1..=4).contains(&fat_count)
            && le16(&boot, 17) == 0
            && le16(&boot, 19) == 0
            && matches!(boot[21], 0xf0 | 0xf8..=0xff)
            && le16(&boot, 22) == 0
            && total_sectors != 0
            && fat_sectors != 0
            && le16(&boot, 42) == 0
            && boot[510..512] == [0x55, 0xaa];
        if !valid {
            return Err(Error::NotFat32);
        }
        // §3.3: with mirroring off, only the FAT named in bits 0..3 is live.
        let active_fat = if ext_flags & 0x80 != 0 {
            u32::from(ext_flags & 0x0f)
        } else {
            0
        };
        if active_fat >= fat_count {
            return Err(Error::Corrupt);
        }
        let metadata = u64::from(reserved) + u64::from(fat_count) * u64::from(fat_sectors);
        let data_sectors = u64::from(total_sectors)
            .checked_sub(metadata)
            .ok_or(Error::NotFat32)?;
        let cluster_count = u32::try_from(data_sectors / u64::from(sectors_per_cluster))
            .map_err(|_| Error::NotFat32)?;
        // §3.5: the cluster count alone decides the FAT type. §4: no FAT32
        // cluster number may reach 0x0FFFFFF7.
        if !(MIN_FAT32_CLUSTERS..=FAT_BAD - 2).contains(&cluster_count) {
            return Err(Error::NotFat32);
        }
        let fat_bytes = u64::from(fat_sectors) * u64::from(bytes_per_sector);
        if fat_bytes / 4 < u64::from(cluster_count) + 2
            || !(2..=cluster_count + 1).contains(&root_cluster)
        {
            return Err(Error::Corrupt);
        }
        let sector = u64::from(bytes_per_sector);
        if volume_bytes.is_some_and(|bytes| u64::from(total_sectors) * sector > bytes) {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            bytes_per_sector,
            cluster_bytes: bytes_per_sector * sectors_per_cluster,
            fat_offset: (u64::from(reserved) + u64::from(active_fat) * u64::from(fat_sectors))
                * sector,
            data_offset: metadata * sector,
            cluster_count,
            root_cluster,
            total_sectors,
        })
    }

    pub const fn root(&self) -> Node {
        Node {
            kind: Kind::Directory,
            first_cluster: self.root_cluster,
            size: 0,
        }
    }

    pub const fn cluster_bytes(&self) -> u32 {
        self.cluster_bytes
    }

    pub const fn bytes_per_sector(&self) -> u32 {
        self.bytes_per_sector
    }

    pub fn total_bytes(&self) -> u64 {
        u64::from(self.total_sectors) * u64::from(self.bytes_per_sector)
    }

    const fn valid_cluster(&self, cluster: u32) -> bool {
        cluster >= 2 && cluster <= self.cluster_count + 1
    }

    /// The cluster after `cluster`, or `None` at the end of the chain.
    fn next<D: Disk + ?Sized>(&self, disk: &mut D, cluster: u32) -> Result<Option<u32>, Error> {
        let mut entry = [0u8; 4];
        disk.read(self.fat_offset + u64::from(cluster) * 4, &mut entry)?;
        let value = u32::from_le_bytes(entry) & FAT_ENTRY_MASK;
        if value >= FAT_EOC_MIN {
            Ok(None)
        } else if self.valid_cluster(value) {
            Ok(Some(value))
        } else {
            // Free, reserved or bad clusters never appear inside a chain.
            Err(Error::Corrupt)
        }
    }

    /// The cluster `steps` links after `start`; running out is corruption.
    fn advance<D: Disk + ?Sized>(
        &self,
        disk: &mut D,
        start: u32,
        steps: u32,
    ) -> Result<u32, Error> {
        if steps > self.cluster_count {
            return Err(Error::Corrupt);
        }
        let mut cluster = start;
        for _ in 0..steps {
            cluster = self.next(disk, cluster)?.ok_or(Error::Corrupt)?;
        }
        Ok(cluster)
    }

    fn cluster_offset(&self, cluster: u32) -> u64 {
        self.data_offset + u64::from(cluster - 2) * u64::from(self.cluster_bytes)
    }

    /// Reads up to `out.len()` bytes of a file from `offset`; fewer at the
    /// end of the file, none past it.
    pub fn read<D: Disk + ?Sized>(
        &self,
        disk: &mut D,
        cursor: &mut Cursor,
        offset: u64,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let node = cursor.node;
        if node.kind != Kind::File {
            return Err(Error::NotFile);
        }
        let size = u64::from(node.size);
        if offset >= size || out.is_empty() {
            return Ok(0);
        }
        if !self.valid_cluster(node.first_cluster) {
            return Err(Error::Corrupt);
        }
        let wanted = (size - offset).min(out.len() as u64) as usize;
        let cluster_bytes = u64::from(self.cluster_bytes);
        let mut done = 0;
        while done < wanted {
            let position = offset + done as u64;
            let index = u32::try_from(position / cluster_bytes).map_err(|_| Error::Corrupt)?;
            if index < cursor.index {
                *cursor = Cursor::new(node);
            }
            cursor.cluster = self.advance(disk, cursor.cluster, index - cursor.index)?;
            cursor.index = index;
            let within = position % cluster_bytes;
            // Stay inside one sector per read.
            let sector = u64::from(self.bytes_per_sector);
            let take = (wanted - done)
                .min((cluster_bytes - within) as usize)
                .min((sector - within % sector) as usize);
            disk.read(
                self.cluster_offset(cursor.cluster) + within,
                &mut out[done..done + take],
            )?;
            done += take;
        }
        Ok(done)
    }

    /// Calls `visit` for each entry of `dir` from position `cookie` (0 at
    /// the start) until it returns `false` or the directory ends. Returns
    /// the cookie of the entry `visit` refused, or `None` at the end. The
    /// first entry offered on each call must be accepted.
    pub fn read_dir<D: Disk + ?Sized>(
        &self,
        disk: &mut D,
        dir: Node,
        cookie: u32,
        mut visit: impl FnMut(Entry<'_>) -> bool,
    ) -> Result<Option<u32>, Error> {
        if dir.kind != Kind::Directory {
            return Err(Error::NotDirectory);
        }
        let mut walker = Walker::new(self, dir, cookie)?;
        let mut name = [0u8; MAX_NAME_BYTES];
        let mut first = true;
        while let Some((start, length, node)) = walker.next(disk, &mut name)? {
            if !visit(Entry {
                name: &name[..length],
                node,
            }) {
                if first {
                    return Err(Error::Corrupt);
                }
                return Ok(Some(start));
            }
            first = false;
        }
        Ok(None)
    }

    /// Finds `name` in `dir`, ignoring ASCII case.
    pub fn lookup<D: Disk + ?Sized>(
        &self,
        disk: &mut D,
        dir: Node,
        name: &[u8],
    ) -> Result<Node, Error> {
        if dir.kind != Kind::Directory {
            return Err(Error::NotDirectory);
        }
        let mut walker = Walker::new(self, dir, 0)?;
        let mut buffer = [0u8; MAX_NAME_BYTES];
        while let Some((_, length, node)) = walker.next(disk, &mut buffer)? {
            if buffer[..length].eq_ignore_ascii_case(name) {
                return Ok(node);
            }
        }
        Err(Error::NotFound)
    }

    /// Resolves a `/`-separated relative path from `dir`; empty is `dir`.
    pub fn resolve<D: Disk + ?Sized>(
        &self,
        disk: &mut D,
        dir: Node,
        path: &[u8],
    ) -> Result<Node, Error> {
        let mut node = dir;
        if path.is_empty() {
            return Ok(node);
        }
        for component in path.split(|&byte| byte == b'/') {
            node = self.lookup(disk, node, component)?;
        }
        Ok(node)
    }
}

/// Steps through one directory's 32-byte slots, assembling long names.
struct Walker<'v> {
    volume: &'v Volume,
    first_cluster: u32,
    slot: u32,
    cluster_index: u32,
    cluster: u32,
}

/// Long-name entries gathered so far, last-first as stored.
struct LongName {
    units: [u16; MAX_LONG_ENTRIES * 13],
    count: usize,
    expected: u8,
    checksum: u8,
    start: u32,
}

impl LongName {
    const fn new() -> Self {
        Self {
            units: [0; MAX_LONG_ENTRIES * 13],
            count: 0,
            expected: 0,
            checksum: 0,
            start: 0,
        }
    }

    fn reset(&mut self) {
        self.count = 0;
        self.expected = 0;
    }

    /// Takes one long entry at `slot`; an entry out of sequence restarts
    /// or abandons the set (§7.1: such a set is corrupt and is ignored).
    fn push(&mut self, entry: &[u8], slot: u32) {
        let ordinal = entry[0];
        let number = ordinal & !LAST_LONG_ENTRY;
        if ordinal & LAST_LONG_ENTRY != 0 {
            if number == 0 || usize::from(number) > MAX_LONG_ENTRIES {
                self.reset();
                return;
            }
            self.count = usize::from(number);
            self.checksum = entry[13];
            self.start = slot;
        } else if self.expected == 0 || number != self.expected || entry[13] != self.checksum {
            self.reset();
            return;
        }
        let base = (usize::from(number) - 1) * 13;
        for (i, offset) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
            .into_iter()
            .enumerate()
        {
            self.units[base + i] = le16(entry, offset);
        }
        self.expected = number - 1;
    }

    /// The UTF-8 name if a complete set matches `short`, written to `out`.
    fn finish(&self, short: &[u8], out: &mut [u8; MAX_NAME_BYTES]) -> Option<usize> {
        if self.count == 0 || self.expected != 0 || checksum(short) != self.checksum {
            return None;
        }
        let units = &self.units[..self.count * 13];
        let end = units
            .iter()
            .position(|&unit| unit == 0)
            .unwrap_or(units.len());
        let mut length = 0;
        for character in char::decode_utf16(units[..end].iter().copied()) {
            let character = character.ok()?;
            if character == '/' || character == '\0' {
                return None;
            }
            let mut encoded = [0u8; 4];
            let bytes = character.encode_utf8(&mut encoded).as_bytes();
            out.get_mut(length..length + bytes.len())?
                .copy_from_slice(bytes);
            length += bytes.len();
        }
        (length != 0 && &out[..length] != b"." && &out[..length] != b"..").then_some(length)
    }
}

/// §7.2's rotate-right-and-add over the 11 short-name bytes.
fn checksum(short: &[u8]) -> u8 {
    short
        .iter()
        .fold(0u8, |sum, &byte| sum.rotate_right(1).wrapping_add(byte))
}

/// The display form of an 8.3 name; `None` for `.`, `..` or an empty name.
fn short_name(entry: &[u8], out: &mut [u8; MAX_NAME_BYTES]) -> Option<usize> {
    let lower_base = entry[12] & NT_LOWER_BASE != 0;
    let lower_extension = entry[12] & NT_LOWER_EXTENSION != 0;
    let mut length = 0;
    let mut push = |byte: u8, lower: bool| {
        out[length] = if lower {
            byte.to_ascii_lowercase()
        } else {
            byte
        };
        length += 1;
    };
    let base = entry[..8].trim_ascii_end();
    let extension = entry[8..11].trim_ascii_end();
    for (index, &byte) in base.iter().enumerate() {
        // §6.1: 0x05 stands for a leading 0xE5.
        push(
            if index == 0 && byte == 0x05 {
                0xe5
            } else {
                byte
            },
            lower_base,
        );
    }
    if !extension.is_empty() {
        push(b'.', false);
        for &byte in extension {
            push(byte, lower_extension);
        }
    }
    let name = &out[..length];
    (length != 0 && name != b"." && name != b".." && !name.contains(&b'/') && !name.contains(&0))
        .then_some(length)
}

impl<'v> Walker<'v> {
    fn new(volume: &'v Volume, dir: Node, slot: u32) -> Result<Self, Error> {
        if !volume.valid_cluster(dir.first_cluster) {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            volume,
            first_cluster: dir.first_cluster,
            slot,
            cluster_index: 0,
            cluster: dir.first_cluster,
        })
    }

    /// Reads the slot at `self.slot`; `None` past the end of the chain.
    fn read_slot<D: Disk + ?Sized>(
        &mut self,
        disk: &mut D,
        entry: &mut [u8; 32],
    ) -> Result<bool, Error> {
        if self.slot >= MAX_DIRECTORY_ENTRIES {
            return Ok(false);
        }
        let per_cluster = self.volume.cluster_bytes / ENTRY_BYTES;
        let index = self.slot / per_cluster;
        if index < self.cluster_index {
            self.cluster_index = 0;
            self.cluster = self.first_cluster;
        }
        while self.cluster_index < index {
            match self.volume.next(disk, self.cluster)? {
                Some(next) => self.cluster = next,
                None => return Ok(false),
            }
            self.cluster_index += 1;
        }
        let offset = self.volume.cluster_offset(self.cluster)
            + u64::from(self.slot % per_cluster * ENTRY_BYTES);
        disk.read(offset, entry)?;
        Ok(true)
    }

    /// The next listed entry: its starting slot, name length and node.
    fn next<D: Disk + ?Sized>(
        &mut self,
        disk: &mut D,
        name: &mut [u8; MAX_NAME_BYTES],
    ) -> Result<Option<(u32, usize, Node)>, Error> {
        let mut long = LongName::new();
        let mut entry = [0u8; 32];
        loop {
            if !self.read_slot(disk, &mut entry)? {
                return Ok(None);
            }
            let slot = self.slot;
            self.slot += 1;
            match entry[0] {
                // §6.1: this and every later slot are free.
                0x00 => return Ok(None),
                0xe5 => {
                    long.reset();
                    continue;
                }
                _ => {}
            }
            let attributes = entry[11];
            if attributes & ATTR_LONG_NAME_MASK == ATTR_LONG_NAME {
                long.push(&entry, slot);
                continue;
            }
            let start = if long.count != 0 && long.expected == 0 {
                long.start
            } else {
                slot
            };
            let length = long.finish(&entry[..11], name);
            long.reset();
            if attributes & ATTR_VOLUME_ID != 0 {
                continue;
            }
            let Some(length) = length.or_else(|| short_name(&entry, name)) else {
                continue;
            };
            let first_cluster = u32::from(le16(&entry, 20)) << 16 | u32::from(le16(&entry, 26));
            let size = le32(&entry, 28);
            let node = if attributes & ATTR_DIRECTORY != 0 {
                if !self.volume.valid_cluster(first_cluster) {
                    return Err(Error::Corrupt);
                }
                Node {
                    kind: Kind::Directory,
                    first_cluster,
                    size: 0,
                }
            } else {
                // §6.7: an empty file has no cluster; any other has a valid one.
                let consistent = if size == 0 {
                    first_cluster == 0 || self.volume.valid_cluster(first_cluster)
                } else {
                    self.volume.valid_cluster(first_cluster)
                };
                if !consistent {
                    return Err(Error::Corrupt);
                }
                Node {
                    kind: Kind::File,
                    first_cluster,
                    size,
                }
            };
            return Ok(Some((start, length, node)));
        }
    }
}

#[cfg(test)]
mod tests;
