// SPDX-License-Identifier: GPL-3.0-or-later

mod common;

use common::*;
use wyrmroot_partition::{
    BlockSource, DeviceError, EFI_SYSTEM_PARTITION, Error, GptDefect, GptPartition, Guid,
    HeaderSource, LINUX_FILESYSTEM_DATA, MAX_GPT_PARTITIONS, MbrDefect, PartitionTable,
    PartitionType, Scheme, crc32, discover,
};

fn run(disk: &mut MemDisk) -> Result<PartitionTable, Error> {
    let mut table = PartitionTable::new();
    discover(disk, &mut table).map(|()| table)
}

fn esp_and_root(layout: Layout) -> Vec<Entry> {
    let split = layout.first_usable() + (layout.last_usable() - layout.first_usable()) / 4;
    let mut esp = Entry::new(
        0,
        EFI_SYSTEM_PARTITION,
        layout.first_usable(),
        split,
        "EFI system",
    );
    esp.attributes = 1;
    let root = Entry::new(
        1,
        LINUX_FILESYSTEM_DATA,
        split + 1,
        layout.last_usable(),
        "root",
    );
    vec![esp, root]
}

fn utf16(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn assert_matches(partitions: &[GptPartition], entries: &[Entry]) {
    assert_eq!(partitions.len(), entries.len());
    for (partition, entry) in partitions.iter().zip(entries) {
        assert_eq!(partition.index() as usize, entry.index);
        assert_eq!(partition.type_guid(), entry.type_guid);
        assert_eq!(partition.unique_guid(), entry.unique_guid);
        assert_eq!(partition.first_lba(), entry.first);
        assert_eq!(partition.last_lba(), entry.last);
        assert_eq!(partition.block_count(), entry.last - entry.first + 1);
        assert_eq!(partition.attributes(), entry.attributes);
        assert_eq!(partition.name(), utf16(entry.name).as_slice());
    }
}

fn gpt_disk(layout: Layout, entries: &[Entry]) -> MemDisk {
    MemDisk::new(
        layout.block_bytes as u32,
        layout.blocks,
        gpt_image(layout, entries),
    )
}

fn expect_gpt_error(layout: Layout, image: Vec<u8>, primary: GptDefect, backup: GptDefect) {
    let mut disk = MemDisk::new(layout.block_bytes as u32, layout.blocks, image);
    assert_eq!(run(&mut disk).unwrap_err(), Error::Gpt { primary, backup });
}

fn expect_both_headers_rejected(layout: Layout, defect: GptDefect, edit: impl Fn(&mut [u8])) {
    let mut image = gpt_image(layout, &esp_and_root(layout));
    edit_both_headers(&mut image, layout, edit);
    expect_gpt_error(layout, image, defect, defect);
}

#[test]
fn crc32_matches_the_ieee_check_value_and_a_bitwise_reference() {
    assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    assert_eq!(crc32(b""), 0);
    let data: Vec<u8> = (0..4096_u32).map(|value| (value * 31 + 7) as u8).collect();
    for length in [0, 1, 91, 92, 512, 4096] {
        assert_eq!(crc32(&data[..length]), reference_crc32(&data[..length]));
    }
}

#[test]
fn known_type_guids_have_their_uefi_on_disk_bytes() {
    assert_eq!(
        EFI_SYSTEM_PARTITION.to_bytes(),
        [
            0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e,
            0xc9, 0x3b
        ]
    );
    assert_eq!(
        LINUX_FILESYSTEM_DATA.to_bytes(),
        [
            0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47,
            0x7d, 0xe4
        ]
    );
    assert_eq!(
        EFI_SYSTEM_PARTITION.partition_type(),
        PartitionType::EfiSystem
    );
    assert_eq!(
        LINUX_FILESYSTEM_DATA.partition_type(),
        PartitionType::LinuxFilesystemData
    );
    assert_eq!(unique(9).partition_type(), PartitionType::Other);
}

#[test]
fn gpt_with_esp_and_linux_root_on_512_byte_blocks() {
    let layout = Layout::standard(512, 4096);
    let entries = esp_and_root(layout);
    let mut disk = gpt_disk(layout, &entries);
    let table = run(&mut disk).unwrap();
    let Scheme::Gpt(info) = table.scheme() else {
        panic!("expected GPT, got {:?}", table.scheme());
    };
    assert_eq!(info.header, HeaderSource::Primary);
    assert_eq!(info.disk_guid, DISK_GUID);
    assert_eq!(info.first_usable_lba, 34);
    assert_eq!(info.last_usable_lba, 4062);
    assert_matches(table.gpt_partitions(), &entries);
    assert_eq!(
        table.gpt_partitions()[0].partition_type(),
        PartitionType::EfiSystem
    );
    assert_eq!(
        table.gpt_partitions()[1].partition_type(),
        PartitionType::LinuxFilesystemData
    );
    assert!(table.mbr_partitions().is_empty());
    // LBA 0, the header, and the 32-block array; the backup is never read.
    assert_eq!(disk.reads, 34);
}

#[test]
fn gpt_on_4096_byte_blocks() {
    let layout = Layout::standard(4096, 256);
    let entries = esp_and_root(layout);
    let mut disk = gpt_disk(layout, &entries);
    let table = run(&mut disk).unwrap();
    let Scheme::Gpt(info) = table.scheme() else {
        panic!("expected GPT");
    };
    assert_eq!(info.header, HeaderSource::Primary);
    assert_eq!(info.first_usable_lba, 6);
    assert_eq!(info.last_usable_lba, 250);
    assert_matches(table.gpt_partitions(), &entries);
}

#[test]
fn gpt_with_wider_entries_and_sparse_slots() {
    for (block_bytes, entry_bytes) in [(512, 256), (512, 1024), (4096, 512), (4096, 8192)] {
        let layout = Layout {
            block_bytes,
            blocks: 8192,
            entry_count: 16,
            entry_bytes,
        };
        let first = layout.first_usable();
        let entries = vec![
            Entry::new(3, EFI_SYSTEM_PARTITION, first, first + 99, "ESP"),
            Entry::new(
                15,
                LINUX_FILESYSTEM_DATA,
                first + 100,
                layout.last_usable(),
                "root",
            ),
        ];
        let mut disk = gpt_disk(layout, &entries);
        let table = run(&mut disk).unwrap();
        assert!(matches!(table.scheme(), Scheme::Gpt(_)));
        assert_matches(table.gpt_partitions(), &entries);
    }
}

#[test]
fn every_primary_header_byte_flip_falls_back_to_the_backup() {
    let layout = Layout::standard(512, 4096);
    let entries = esp_and_root(layout);
    let clean = gpt_image(layout, &entries);
    for offset in 0..92 {
        let mut image = clean.clone();
        image[512 + offset] ^= 0x01;
        let mut disk = MemDisk::new(512, layout.blocks, image);
        let table = run(&mut disk).unwrap();
        let Scheme::Gpt(info) = table.scheme() else {
            panic!("offset {offset}: expected GPT");
        };
        let HeaderSource::Backup { primary_defect } = info.header else {
            panic!("offset {offset}: primary accepted");
        };
        // Signature, revision and size are checked before the CRC; a size
        // flip yields HeaderSize when it leaves the block, else HeaderCrc.
        match offset {
            0..8 => assert_eq!(primary_defect, GptDefect::Signature),
            8..12 => assert_eq!(primary_defect, GptDefect::Revision),
            12..16 => assert!(
                matches!(primary_defect, GptDefect::HeaderSize | GptDefect::HeaderCrc),
                "offset {offset}: {primary_defect:?}"
            ),
            _ => assert_eq!(primary_defect, GptDefect::HeaderCrc, "offset {offset}"),
        }
        assert_matches(table.gpt_partitions(), &entries);
    }
}

#[test]
fn corrupt_primary_entry_array_falls_back_to_the_backup() {
    let layout = Layout::standard(4096, 256);
    let entries = esp_and_root(layout);
    let mut image = gpt_image(layout, &entries);
    image[2 * 4096 + 40] ^= 0x80;
    let mut disk = MemDisk::new(4096, layout.blocks, image);
    let table = run(&mut disk).unwrap();
    let Scheme::Gpt(info) = table.scheme() else {
        panic!("expected GPT");
    };
    assert_eq!(
        info.header,
        HeaderSource::Backup {
            primary_defect: GptDefect::EntryArrayCrc
        }
    );
    assert_matches(table.gpt_partitions(), &entries);
}

#[test]
fn backup_is_validated_like_the_primary() {
    let layout = Layout::standard(512, 4096);
    let entries = esp_and_root(layout);

    let mut image = gpt_image(layout, &entries);
    image[512 + 30] ^= 1;
    image[layout.backup_lba() as usize * 512 + 70] ^= 1;
    expect_gpt_error(layout, image, GptDefect::HeaderCrc, GptDefect::HeaderCrc);

    let mut image = gpt_image(layout, &entries);
    image[512] = b'X';
    image[layout.backup_array_lba() as usize * 512 + 3] ^= 1;
    expect_gpt_error(
        layout,
        image,
        GptDefect::Signature,
        GptDefect::EntryArrayCrc,
    );

    // A valid primary header copied to the last LBA has the wrong MyLBA.
    let mut image = gpt_image(layout, &entries);
    let primary: Vec<u8> = image[512..1024].to_vec();
    image[2 * 512] ^= 1;
    image[layout.backup_lba() as usize * 512..][..512].copy_from_slice(&primary);
    expect_gpt_error(layout, image, GptDefect::EntryArrayCrc, GptDefect::MyLba);
}

#[test]
fn bad_entry_array_crc_in_both_headers_is_rejected() {
    let layout = Layout::standard(512, 4096);
    expect_both_headers_rejected(layout, GptDefect::EntryArrayCrc, |header| {
        header[88] ^= 0xff;
    });
}

#[test]
fn overlapping_entries_are_rejected() {
    let layout = Layout::standard(512, 4096);
    let first = layout.first_usable();
    let entries = vec![
        Entry::new(0, EFI_SYSTEM_PARTITION, first, first + 100, "a"),
        Entry::new(2, LINUX_FILESYSTEM_DATA, first + 200, first + 300, "b"),
        Entry::new(5, LINUX_FILESYSTEM_DATA, first + 100, first + 150, "c"),
    ];
    let overlap = GptDefect::Overlap {
        first: 0,
        second: 5,
    };
    expect_gpt_error(layout, gpt_image(layout, &entries), overlap, overlap);

    let entries = vec![
        Entry::new(0, EFI_SYSTEM_PARTITION, first + 10, first + 20, "inner"),
        Entry::new(1, LINUX_FILESYSTEM_DATA, first, first + 50, "outer"),
    ];
    let overlap = GptDefect::Overlap {
        first: 0,
        second: 1,
    };
    expect_gpt_error(layout, gpt_image(layout, &entries), overlap, overlap);
}

#[test]
fn entries_outside_the_usable_range_or_inverted_are_rejected() {
    let layout = Layout::standard(512, 4096);
    let (first, last) = (layout.first_usable(), layout.last_usable());
    for (start, end) in [
        (first - 1, first + 10),
        (first, last + 1),
        (first + 10, first + 9),
        (0, 0),
        (last + 1, u64::MAX),
        (u64::MAX, u64::MAX),
    ] {
        let entries = vec![
            Entry::new(0, EFI_SYSTEM_PARTITION, first, first, "ok"),
            Entry::new(1, LINUX_FILESYSTEM_DATA, start, end, "bad"),
        ];
        let defect = GptDefect::EntryRange { index: 1 };
        expect_gpt_error(layout, gpt_image(layout, &entries), defect, defect);
    }
}

#[test]
fn absurd_entry_counts_and_sizes_fail_without_reading_the_array() {
    let layout = Layout::standard(512, 4096);
    let cases: [(u32, u32, GptDefect); 9] = [
        (u32::MAX, 128, GptDefect::EntryCount),
        (0, 128, GptDefect::EntryCount),
        (2049, 128, GptDefect::EntryCount),
        (2, 0x8000_0000, GptDefect::EntryCount),
        (u32::MAX, u32::MAX, GptDefect::EntrySize),
        (128, 0, GptDefect::EntrySize),
        (128, 64, GptDefect::EntrySize),
        (128, 384, GptDefect::EntrySize),
        (128, 129, GptDefect::EntrySize),
    ];
    for (count, size, defect) in cases {
        let mut image = gpt_image(layout, &esp_and_root(layout));
        edit_both_headers(&mut image, layout, |header| {
            put_u32(header, 80, count);
            put_u32(header, 84, size);
        });
        let mut disk = MemDisk::new(512, layout.blocks, image);
        assert_eq!(
            run(&mut disk).unwrap_err(),
            Error::Gpt {
                primary: defect,
                backup: defect
            },
            "count {count} size {size}"
        );
        // LBA 0 and the two headers only.
        assert_eq!(disk.reads, 3, "count {count} size {size}");
    }
}

#[test]
fn largest_admitted_entry_array_is_read_once_per_block() {
    let layout = Layout {
        block_bytes: 512,
        blocks: 4096,
        entry_count: 2048,
        entry_bytes: 128,
    };
    let entries = esp_and_root(layout);
    let mut disk = gpt_disk(layout, &entries);
    let table = run(&mut disk).unwrap();
    assert_matches(table.gpt_partitions(), &entries);
    assert_eq!(disk.reads, 2 + 512);
}

#[test]
fn header_field_defects_are_rejected_in_both_headers() {
    let layout = Layout::standard(512, 4096);
    let blocks = layout.blocks;
    let first = layout.first_usable();
    let last = layout.last_usable();
    expect_both_headers_rejected(layout, GptDefect::Revision, |h| put_u32(h, 8, 0x0002_0000));
    expect_both_headers_rejected(layout, GptDefect::HeaderSize, |h| put_u32(h, 12, 91));
    expect_both_headers_rejected(layout, GptDefect::HeaderSize, |h| put_u32(h, 12, 513));
    expect_both_headers_rejected(layout, GptDefect::HeaderSize, |h| put_u32(h, 12, u32::MAX));
    expect_both_headers_rejected(layout, GptDefect::Reserved, |h| put_u32(h, 20, 1));
    expect_both_headers_rejected(layout, GptDefect::MyLba, |h| put_u64(h, 24, 2));
    expect_both_headers_rejected(layout, GptDefect::AlternateLba, |h| put_u64(h, 32, blocks));
    expect_both_headers_rejected(layout, GptDefect::UsableRange, |h| put_u64(h, 40, last + 1));
    expect_both_headers_rejected(layout, GptDefect::UsableRange, |h| put_u64(h, 40, 1));
    expect_both_headers_rejected(layout, GptDefect::UsableRange, |h| {
        put_u64(h, 48, blocks - 1)
    });
    expect_both_headers_rejected(layout, GptDefect::UsableRange, |h| put_u64(h, 48, u64::MAX));
    expect_both_headers_rejected(layout, GptDefect::EntryArrayLocation, |h| {
        put_u64(h, 72, first)
    });
    expect_both_headers_rejected(layout, GptDefect::EntryArrayLocation, |h| put_u64(h, 72, 1));
    expect_both_headers_rejected(layout, GptDefect::EntryArrayLocation, |h| {
        put_u64(h, 72, blocks - 2)
    });
    expect_both_headers_rejected(layout, GptDefect::EntryArrayLocation, |h| {
        put_u64(h, 72, u64::MAX)
    });
}

#[test]
fn header_larger_than_92_bytes_is_covered_by_its_crc() {
    let layout = Layout::standard(4096, 256);
    let entries = esp_and_root(layout);
    let mut image = gpt_image(layout, &entries);
    edit_header(&mut image, 4096, 1, |h| {
        put_u32(h, 12, 4096);
        h[4000] = 0x5a;
    });
    let mut disk = MemDisk::new(4096, layout.blocks, image.clone());
    let table = run(&mut disk).unwrap();
    assert_eq!(
        table.scheme(),
        Scheme::Gpt(wyrmroot_partition::GptInfo {
            header: HeaderSource::Primary,
            disk_guid: DISK_GUID,
            first_usable_lba: 6,
            last_usable_lba: 250,
        })
    );
    image[4096 + 4000] ^= 1;
    let mut disk = MemDisk::new(4096, layout.blocks, image);
    let Scheme::Gpt(info) = run(&mut disk).unwrap().scheme() else {
        panic!("expected GPT");
    };
    assert_eq!(
        info.header,
        HeaderSource::Backup {
            primary_defect: GptDefect::HeaderCrc
        }
    );
}

#[test]
fn partition_count_is_bounded() {
    let layout = Layout {
        block_bytes: 512,
        blocks: 4096,
        entry_count: 256,
        entry_bytes: 128,
    };
    let first = layout.first_usable();
    let build = |count: usize| -> Vec<Entry> {
        (0..count)
            .map(|index| {
                let lba = first + index as u64;
                Entry::new(index, LINUX_FILESYSTEM_DATA, lba, lba, "p")
            })
            .collect()
    };
    let entries = build(MAX_GPT_PARTITIONS);
    let mut disk = gpt_disk(layout, &entries);
    assert_matches(run(&mut disk).unwrap().gpt_partitions(), &entries);

    let image = gpt_image(layout, &build(MAX_GPT_PARTITIONS + 1));
    expect_gpt_error(
        layout,
        image,
        GptDefect::TooManyPartitions,
        GptDefect::TooManyPartitions,
    );
}

#[test]
fn device_errors_propagate_without_fallback() {
    let layout = Layout::standard(512, 4096);
    for lba in [0, 1, 2, 33] {
        let mut disk = gpt_disk(layout, &esp_and_root(layout));
        disk.fail_lba = Some(lba);
        assert_eq!(
            run(&mut disk).unwrap_err(),
            Error::Read {
                lba,
                error: DeviceError(0x5eed)
            }
        );
    }
    let mut image = gpt_image(layout, &esp_and_root(layout));
    image[512] ^= 1;
    let mut disk = MemDisk::new(512, layout.blocks, image);
    disk.fail_lba = Some(layout.backup_lba());
    assert_eq!(
        run(&mut disk).unwrap_err(),
        Error::Read {
            lba: layout.backup_lba(),
            error: DeviceError(0x5eed)
        }
    );
}

#[test]
fn unsupported_geometry_is_rejected() {
    for block_bytes in [0, 256, 1024, 2048, 8192] {
        let mut disk = MemDisk::new(block_bytes, 100, Vec::new());
        assert_eq!(
            run(&mut disk).unwrap_err(),
            Error::UnsupportedBlockSize(block_bytes)
        );
        assert_eq!(disk.reads, 0);
    }
    let mut disk = MemDisk::new(512, 0, Vec::new());
    assert_eq!(run(&mut disk).unwrap_err(), Error::EmptyDevice);
}

#[test]
fn a_failed_discovery_leaves_the_table_empty() {
    let layout = Layout::standard(512, 4096);
    let mut table = PartitionTable::new();
    let mut disk = gpt_disk(layout, &esp_and_root(layout));
    discover(&mut disk, &mut table).unwrap();
    assert_eq!(table.gpt_partitions().len(), 2);

    let mut image = gpt_image(layout, &esp_and_root(layout));
    edit_both_headers(&mut image, layout, |h| h[88] ^= 1);
    let mut disk = MemDisk::new(512, layout.blocks, image);
    assert!(discover(&mut disk, &mut table).is_err());
    assert!(table.gpt_partitions().is_empty());
    assert_eq!(
        table.scheme(),
        Scheme::None {
            fat_boot_sector: false
        }
    );
}

#[test]
fn gpt_signature_without_protective_mbr_is_rejected() {
    let layout = Layout::standard(512, 4096);
    let mut image = gpt_image(layout, &esp_and_root(layout));
    image[510] = 0;
    let mut disk = MemDisk::new(512, layout.blocks, image);
    assert_eq!(run(&mut disk).unwrap_err(), Error::GptWithoutProtectiveMbr);
}

#[test]
fn protective_record_must_start_at_lba_1() {
    let layout = Layout::standard(512, 4096);
    let mut image = gpt_image(layout, &esp_and_root(layout));
    put_u32(&mut image, 454, 2);
    let mut disk = MemDisk::new(512, layout.blocks, image);
    assert_eq!(run(&mut disk).unwrap_err(), Error::InvalidProtectiveMbr);
}

#[test]
fn protective_mbr_on_a_disk_too_small_for_gpt() {
    for blocks in [1, 2, 3, 40] {
        let mut image = vec![0_u8; 512];
        write_protective_mbr(&mut image, blocks);
        let mut disk = MemDisk::new(512, blocks, image);
        let error = run(&mut disk).unwrap_err();
        assert!(matches!(error, Error::Gpt { .. }), "{blocks}: {error:?}");
    }
}

#[test]
fn plain_mbr_with_primary_and_extended_partitions() {
    let mut image = vec![0_u8; 512];
    write_mbr_record(&mut image, 0, 0x80, 0x0c, 2048, 204_800);
    write_mbr_record(&mut image, 2, 0x00, 0x83, 206_848, 1_000_000);
    write_mbr_record(&mut image, 3, 0x00, 0x05, 1_206_848, 50_000);
    let mut disk = MemDisk::new(512, 2_000_000, image);
    let table = run(&mut disk).unwrap();
    assert_eq!(table.scheme(), Scheme::Mbr);
    assert!(table.gpt_partitions().is_empty());
    let partitions = table.mbr_partitions();
    assert_eq!(partitions.len(), 3);
    assert_eq!(partitions[0].slot(), 0);
    assert!(partitions[0].bootable());
    assert_eq!(partitions[0].os_type(), 0x0c);
    assert_eq!(partitions[0].first_lba(), 2048);
    assert_eq!(partitions[0].block_count(), 204_800);
    assert_eq!(partitions[0].last_lba(), 2048 + 204_800 - 1);
    assert!(!partitions[0].is_extended());
    assert_eq!(partitions[1].slot(), 2);
    assert!(!partitions[1].bootable());
    assert_eq!(partitions[1].os_type(), 0x83);
    assert_eq!(partitions[2].slot(), 3);
    assert!(partitions[2].is_extended());
    assert_eq!(disk.reads, 1);
}

#[test]
fn plain_mbr_on_4096_byte_blocks_is_bounded_in_device_blocks() {
    let mut image = vec![0_u8; 4096];
    write_mbr_record(&mut image, 0, 0x00, 0x83, 1, 99);
    let mut disk = MemDisk::new(4096, 100, image.clone());
    let table = run(&mut disk).unwrap();
    assert_eq!(table.mbr_partitions()[0].last_lba(), 99);

    write_mbr_record(&mut image, 0, 0x00, 0x83, 1, 100);
    let mut disk = MemDisk::new(4096, 100, image);
    assert_eq!(
        run(&mut disk).unwrap_err(),
        Error::Mbr(MbrDefect::BeyondDisk { slot: 0 })
    );
}

/// (slot, boot indicator, type, start LBA, block count)
type MbrRecord = (usize, u8, u8, u32, u32);

#[test]
fn malformed_plain_mbrs_are_rejected() {
    let cases: [(&[MbrRecord], MbrDefect); 6] = [
        (
            &[(1, 0x7f, 0x83, 1, 10)],
            MbrDefect::BootIndicator { slot: 1 },
        ),
        (&[(0, 0x00, 0x83, 1, 0)], MbrDefect::Empty { slot: 0 }),
        (
            &[(2, 0x00, 0x83, 0, 10)],
            MbrDefect::StartsAtMbr { slot: 2 },
        ),
        (
            &[(3, 0x00, 0x83, 900, 101)],
            MbrDefect::BeyondDisk { slot: 3 },
        ),
        (
            &[(0, 0x00, 0x83, u32::MAX, u32::MAX)],
            MbrDefect::BeyondDisk { slot: 0 },
        ),
        (
            &[(0, 0x00, 0x83, 10, 10), (3, 0x00, 0x07, 19, 5)],
            MbrDefect::Overlap {
                first: 0,
                second: 3,
            },
        ),
    ];
    for (records, defect) in cases {
        let mut image = vec![0_u8; 512];
        for &(slot, boot, os_type, start, count) in records {
            write_mbr_record(&mut image, slot, boot, os_type, start, count);
        }
        let mut disk = MemDisk::new(512, 1000, image);
        assert_eq!(run(&mut disk).unwrap_err(), Error::Mbr(defect));
    }
}

#[test]
fn a_disk_without_a_table_is_reported_as_such() {
    let mut disk = MemDisk::new(512, 1000, Vec::new());
    let table = run(&mut disk).unwrap();
    assert_eq!(
        table.scheme(),
        Scheme::None {
            fat_boot_sector: false
        }
    );
    assert!(table.gpt_partitions().is_empty());
    assert!(table.mbr_partitions().is_empty());

    let mut disk = MemDisk::new(4096, 1, vec![0xa5; 4096]);
    assert_eq!(
        run(&mut disk).unwrap().scheme(),
        Scheme::None {
            fat_boot_sector: false
        }
    );
}

#[test]
fn an_mbr_signature_with_no_entries_is_an_empty_mbr() {
    let mut image = vec![0_u8; 512];
    image[510] = 0x55;
    image[511] = 0xaa;
    let mut disk = MemDisk::new(512, 1000, image);
    let table = run(&mut disk).unwrap();
    assert_eq!(table.scheme(), Scheme::Mbr);
    assert!(table.mbr_partitions().is_empty());
}

/// LBA 0 of the product ESP as `xtask`'s fixed FAT32 builder writes it
/// (`tools/xtask/src/g3_image.rs`, `boot_sector`): an unpartitioned 128 MiB
/// FAT32 volume of 262,144 512-byte sectors. The FAT size is a stand-in;
/// discovery does not read it.
fn product_esp_boot_sector() -> Vec<u8> {
    let mut sector = vec![0_u8; 512];
    sector[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
    sector[3..11].copy_from_slice(b"WYRMG3  ");
    put_u16(&mut sector, 11, 512);
    sector[13] = 2;
    put_u16(&mut sector, 14, 32);
    sector[16] = 2;
    sector[21] = 0xf8;
    put_u16(&mut sector, 24, 63);
    put_u16(&mut sector, 26, 255);
    put_u32(&mut sector, 32, 262_144);
    put_u32(&mut sector, 36, 1016);
    put_u32(&mut sector, 44, 2);
    put_u16(&mut sector, 48, 1);
    put_u16(&mut sector, 50, 6);
    sector[64] = 0x80;
    sector[66] = 0x29;
    put_u32(&mut sector, 67, 0x5733_4730);
    sector[71..82].copy_from_slice(b"WYRMG3 ESP ");
    sector[82..90].copy_from_slice(b"FAT32   ");
    sector[510..512].copy_from_slice(&[0x55, 0xaa]);
    sector
}

#[test]
fn the_product_esp_is_an_unpartitioned_fat_volume() {
    let mut disk = MemDisk::new(512, 262_144, product_esp_boot_sector());
    let table = run(&mut disk).unwrap();
    assert_eq!(
        table.scheme(),
        Scheme::None {
            fat_boot_sector: true
        }
    );
    assert_eq!(disk.reads, 1);

    // Boot code spilling into the record area does not make it an MBR.
    let mut sector = product_esp_boot_sector();
    sector[446..510].fill(0x41);
    let mut disk = MemDisk::new(512, 262_144, sector);
    assert_eq!(
        run(&mut disk).unwrap().scheme(),
        Scheme::None {
            fat_boot_sector: true
        }
    );
}

#[test]
fn the_product_esp_wrapped_in_gpt_is_found_as_the_esp() {
    // The layout the plan's later system disk would use: the same FAT32 volume
    // as partition 0 of a GPT disk, followed by an ext4 root.
    let layout = Layout::standard(512, 300_000);
    let esp_first = 2048;
    let esp_last = esp_first + 262_144 - 1;
    let entries = vec![
        Entry::new(
            0,
            EFI_SYSTEM_PARTITION,
            esp_first,
            esp_last,
            "EFI System Partition",
        ),
        Entry::new(
            1,
            LINUX_FILESYSTEM_DATA,
            esp_last + 1,
            layout.last_usable(),
            "wyrmroot",
        ),
    ];
    let mut image = gpt_image(layout, &entries);
    let at = esp_first as usize * 512;
    image[at..at + 512].copy_from_slice(&product_esp_boot_sector());
    let mut disk = MemDisk::new(512, layout.blocks, image);
    let table = run(&mut disk).unwrap();
    let esp = table
        .gpt_partitions()
        .iter()
        .find(|partition| partition.partition_type() == PartitionType::EfiSystem)
        .unwrap();
    assert_eq!(esp.first_lba(), esp_first);
    assert_eq!(esp.block_count(), 262_144);
    assert_eq!(esp.name(), utf16("EFI System Partition").as_slice());

    // The partition's first block is the FAT boot sector, which discovery on
    // the partition alone reports as an unpartitioned FAT volume.
    let mut partition = Offset {
        disk,
        first: esp.first_lba(),
        blocks: esp.block_count(),
    };
    assert_eq!(
        run_on(&mut partition).scheme(),
        Scheme::None {
            fat_boot_sector: true
        }
    );
}

struct Offset {
    disk: MemDisk,
    first: u64,
    blocks: u64,
}

impl BlockSource for Offset {
    fn block_size(&self) -> u32 {
        self.disk.block_size()
    }
    fn block_count(&self) -> u64 {
        self.blocks
    }
    fn read_block(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), DeviceError> {
        assert!(lba < self.blocks);
        self.disk.read_block(self.first + lba, buffer)
    }
}

fn run_on(device: &mut dyn BlockSource) -> PartitionTable {
    let mut table = PartitionTable::new();
    discover(device, &mut table).unwrap();
    table
}

#[test]
fn guid_round_trips_its_bytes() {
    let bytes: [u8; 16] = core::array::from_fn(|index| index as u8);
    assert_eq!(Guid::from_bytes(bytes).to_bytes(), bytes);
    assert!(Guid::ZERO.is_zero());
    assert!(!Guid::from_bytes(bytes).is_zero());
}

#[test]
fn a_header_whose_alternate_is_itself_is_rejected() {
    let layout = Layout::standard(512, 4096);
    let mut image = gpt_image(layout, &esp_and_root(layout));
    edit_header(&mut image, 512, 1, |h| put_u64(h, 32, 1));
    let backup = layout.backup_lba();
    edit_header(&mut image, 512, backup, |h| put_u64(h, 32, backup));
    expect_gpt_error(
        layout,
        image,
        GptDefect::AlternateLba,
        GptDefect::AlternateLba,
    );
}
