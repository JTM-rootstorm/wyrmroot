// SPDX-License-Identifier: GPL-3.0-or-later

//! In-memory disks and image builders for the discovery tests.

#![allow(dead_code)]

use wyrmroot_partition::{BlockSource, DeviceError, Guid};

/// A disk backed by `data`; blocks past the end of `data` read as zeros.
pub struct MemDisk {
    pub block_bytes: u32,
    pub blocks: u64,
    pub data: Vec<u8>,
    pub fail_lba: Option<u64>,
    pub reads: usize,
}

impl MemDisk {
    pub fn new(block_bytes: u32, blocks: u64, data: Vec<u8>) -> Self {
        Self {
            block_bytes,
            blocks,
            data,
            fail_lba: None,
            reads: 0,
        }
    }
}

impl BlockSource for MemDisk {
    fn block_size(&self) -> u32 {
        self.block_bytes
    }

    fn block_count(&self) -> u64 {
        self.blocks
    }

    fn read_block(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), DeviceError> {
        assert_eq!(
            buffer.len(),
            self.block_bytes as usize,
            "partial-block read"
        );
        assert!(lba < self.blocks, "read beyond the device: {lba}");
        self.reads += 1;
        if self.fail_lba == Some(lba) {
            return Err(DeviceError(0x5eed));
        }
        let start = lba as usize * self.block_bytes as usize;
        buffer.fill(0);
        if start < self.data.len() {
            let end = (start + buffer.len()).min(self.data.len());
            buffer[..end - start].copy_from_slice(&self.data[start..end]);
        }
        Ok(())
    }
}

/// Bitwise CRC-32 (IEEE, reflected), independent of the crate's table.
pub fn reference_crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

pub fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

pub fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

pub const DISK_GUID: Guid = Guid::from_fields(
    0x1234_5678,
    0x9abc,
    0xdef0,
    [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
);

pub fn unique(seed: u8) -> Guid {
    Guid::from_bytes([seed; 16])
}

#[derive(Clone)]
pub struct Entry {
    pub index: usize,
    pub type_guid: Guid,
    pub unique_guid: Guid,
    pub first: u64,
    pub last: u64,
    pub attributes: u64,
    pub name: &'static str,
}

impl Entry {
    pub fn new(index: usize, type_guid: Guid, first: u64, last: u64, name: &'static str) -> Self {
        Self {
            index,
            type_guid,
            unique_guid: unique(index as u8 + 1),
            first,
            last,
            attributes: 0,
            name,
        }
    }
}

#[derive(Clone, Copy)]
pub struct Layout {
    pub block_bytes: usize,
    pub blocks: u64,
    pub entry_count: u32,
    pub entry_bytes: u32,
}

impl Layout {
    pub fn standard(block_bytes: usize, blocks: u64) -> Self {
        Self {
            block_bytes,
            blocks,
            entry_count: 128,
            entry_bytes: 128,
        }
    }

    pub fn array_blocks(&self) -> u64 {
        (u64::from(self.entry_count) * u64::from(self.entry_bytes))
            .div_ceil(self.block_bytes as u64)
    }

    pub fn first_usable(&self) -> u64 {
        2 + self.array_blocks()
    }

    pub fn last_usable(&self) -> u64 {
        self.blocks - 2 - self.array_blocks()
    }

    pub fn backup_lba(&self) -> u64 {
        self.blocks - 1
    }

    pub fn backup_array_lba(&self) -> u64 {
        self.last_usable() + 1
    }
}

/// Writes the protective MBR record into LBA 0.
pub fn write_protective_mbr(image: &mut [u8], blocks: u64) {
    image[446] = 0x00;
    image[450] = 0xee;
    put_u32(image, 454, 1);
    put_u32(image, 458, u32::try_from(blocks - 1).unwrap_or(u32::MAX));
    image[510] = 0x55;
    image[511] = 0xaa;
}

/// A complete protective-MBR + GPT disk with valid CRCs and both headers.
pub fn gpt_image(layout: Layout, entries: &[Entry]) -> Vec<u8> {
    let bs = layout.block_bytes;
    let mut image = vec![0_u8; layout.blocks as usize * bs];
    write_protective_mbr(&mut image, layout.blocks);

    let array_bytes = layout.entry_count as usize * layout.entry_bytes as usize;
    let mut array = vec![0_u8; layout.array_blocks() as usize * bs];
    for entry in entries {
        let base = entry.index * layout.entry_bytes as usize;
        array[base..base + 16].copy_from_slice(&entry.type_guid.to_bytes());
        array[base + 16..base + 32].copy_from_slice(&entry.unique_guid.to_bytes());
        put_u64(&mut array, base + 32, entry.first);
        put_u64(&mut array, base + 40, entry.last);
        put_u64(&mut array, base + 48, entry.attributes);
        for (unit, value) in entry.name.encode_utf16().enumerate() {
            put_u16(&mut array, base + 56 + unit * 2, value);
        }
    }
    let array_crc = reference_crc32(&array[..array_bytes]);

    let primary_array = 2 * bs;
    image[primary_array..primary_array + array.len()].copy_from_slice(&array);
    let backup_array = layout.backup_array_lba() as usize * bs;
    image[backup_array..backup_array + array.len()].copy_from_slice(&array);

    let primary = header(layout, 1, layout.backup_lba(), 2, array_crc);
    image[bs..bs + primary.len()].copy_from_slice(&primary);
    let backup = header(
        layout,
        layout.backup_lba(),
        1,
        layout.backup_array_lba(),
        array_crc,
    );
    let backup_at = layout.backup_lba() as usize * bs;
    image[backup_at..backup_at + backup.len()].copy_from_slice(&backup);
    image
}

fn header(layout: Layout, my_lba: u64, alternate: u64, entry_lba: u64, array_crc: u32) -> Vec<u8> {
    let mut header = vec![0_u8; 92];
    header[..8].copy_from_slice(b"EFI PART");
    put_u32(&mut header, 8, 0x0001_0000);
    put_u32(&mut header, 12, 92);
    put_u64(&mut header, 24, my_lba);
    put_u64(&mut header, 32, alternate);
    put_u64(&mut header, 40, layout.first_usable());
    put_u64(&mut header, 48, layout.last_usable());
    header[56..72].copy_from_slice(&DISK_GUID.to_bytes());
    put_u64(&mut header, 72, entry_lba);
    put_u32(&mut header, 80, layout.entry_count);
    put_u32(&mut header, 84, layout.entry_bytes);
    put_u32(&mut header, 88, array_crc);
    let crc = reference_crc32(&header);
    put_u32(&mut header, 16, crc);
    header
}

/// Applies `edit` to the header at `lba` and recomputes its CRC over the
/// (possibly edited) header size, clamped to the block.
pub fn edit_header(image: &mut [u8], block_bytes: usize, lba: u64, edit: impl FnOnce(&mut [u8])) {
    let start = lba as usize * block_bytes;
    let block = &mut image[start..start + block_bytes];
    edit(block);
    let size =
        (u32::from_le_bytes(block[12..16].try_into().unwrap()) as usize).clamp(92, block_bytes);
    put_u32(block, 16, 0);
    let crc = reference_crc32(&block[..size]);
    put_u32(block, 16, crc);
}

/// Applies `edit` to both headers, recomputing each CRC.
pub fn edit_both_headers(image: &mut [u8], layout: Layout, edit: impl Fn(&mut [u8])) {
    edit_header(image, layout.block_bytes, 1, &edit);
    edit_header(image, layout.block_bytes, layout.backup_lba(), &edit);
}

/// Writes one MBR record into LBA 0 and the boot signature.
pub fn write_mbr_record(
    image: &mut [u8],
    slot: usize,
    boot: u8,
    os_type: u8,
    start: u32,
    count: u32,
) {
    let base = 446 + slot * 16;
    image[base] = boot;
    image[base + 4] = os_type;
    put_u32(image, base + 8, start);
    put_u32(image, base + 12, count);
    image[510] = 0x55;
    image[511] = 0xaa;
}
