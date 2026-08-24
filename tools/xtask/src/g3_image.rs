//! Narrow deterministic FAT32 ESP construction and inspection for WYR0-G3.
//!
//! This is deliberately not a general image builder. It emits one fixed layout
//! containing only the paired loader, kernel, bootstrap, and bootfs artifacts.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::cli::G3ImageArguments;
use crate::error::Failure;
use crate::sha256;

const SECTOR_BYTES: u64 = 512;
const SECTOR_BYTES_USIZE: usize = 512;
const SECTORS_PER_CLUSTER: u32 = 2;
const CLUSTER_BYTES: usize = SECTOR_BYTES_USIZE * SECTORS_PER_CLUSTER as usize;
const TOTAL_SECTORS: u32 = 262_144;
pub(crate) const IMAGE_BYTES: u64 = TOTAL_SECTORS as u64 * SECTOR_BYTES;
const RESERVED_SECTORS: u32 = 32;
const FAT_COUNT: u32 = 2;
const ROOT_CLUSTER: u32 = 2;
const EFI_CLUSTER: u32 = 3;
const BOOT_CLUSTER: u32 = 4;
const WYRMROOT_CLUSTER: u32 = 5;
const FIRST_FILE_CLUSTER: u32 = 6;
const FAT_END: u32 = 0x0fff_ffff;
const MEDIA: u8 = 0xf8;
const FIXED_DATE: u16 = 0x0021; // 1980-01-01
const VOLUME_ID: u32 = 0x5733_4730;

const LOADER_SHORT: [u8; 11] = *b"BOOTX64 EFI";
const KERNEL_SHORT: [u8; 11] = *b"DEEPWYRMELF";
const BOOTSTRAP_SHORT: [u8; 11] = *b"BOOTST~1ELF";
const BOOTFS_SHORT: [u8; 11] = *b"BOOTFS  IMG";

struct Geometry {
    fat_sectors: u32,
    data_start_sector: u32,
    cluster_count: u32,
}

impl Geometry {
    fn fixed() -> Self {
        let mut fat_sectors = 1;
        loop {
            let data_sectors = TOTAL_SECTORS - RESERVED_SECTORS - FAT_COUNT * fat_sectors;
            let cluster_count = data_sectors / SECTORS_PER_CLUSTER;
            let needed = (u64::from(cluster_count + 2) * 4).div_ceil(SECTOR_BYTES) as u32;
            if needed == fat_sectors {
                assert!(cluster_count >= 65_525, "fixed image is not FAT32");
                return Self {
                    fat_sectors,
                    data_start_sector: RESERVED_SECTORS + FAT_COUNT * fat_sectors,
                    cluster_count,
                };
            }
            fat_sectors = needed;
        }
    }

    fn cluster_offset(&self, cluster: u32) -> Result<u64, Failure> {
        if cluster < ROOT_CLUSTER || cluster >= self.cluster_count + 2 {
            return Err(Failure::task("FAT32 cluster is outside the data region"));
        }
        Ok((u64::from(self.data_start_sector)
            + u64::from(cluster - ROOT_CLUSTER) * u64::from(SECTORS_PER_CLUSTER))
            * SECTOR_BYTES)
    }
}

struct Inputs {
    loader: Vec<u8>,
    kernel: Vec<u8>,
    bootstrap: Vec<u8>,
    bootfs: Vec<u8>,
}

impl Inputs {
    fn load(arguments: &G3ImageArguments) -> Result<Self, Failure> {
        Ok(Self {
            loader: read_artifact(&arguments.loader, "loader")?,
            kernel: read_artifact(&arguments.kernel, "kernel")?,
            bootstrap: read_artifact(&arguments.bootstrap, "bootstrap")?,
            bootfs: read_artifact(&arguments.bootfs, "bootfs")?,
        })
    }

    fn total_clusters(&self) -> Result<u32, Failure> {
        [&self.loader, &self.kernel, &self.bootstrap, &self.bootfs]
            .into_iter()
            .try_fold(0_u32, |total, bytes| {
                total
                    .checked_add(cluster_count(bytes.len())?)
                    .ok_or_else(|| Failure::task("G3 artifact cluster count overflowed"))
            })
    }
}

#[derive(Clone, Copy)]
struct FileLayout<'a> {
    short_name: [u8; 11],
    long_name: Option<&'static str>,
    bytes: &'a [u8],
    first_cluster: u32,
    clusters: u32,
}

pub(crate) fn build(arguments: &G3ImageArguments) -> Result<String, Failure> {
    build_in_root(arguments, None)
}

pub(crate) fn build_in_root(
    arguments: &G3ImageArguments,
    output_root: Option<&Path>,
) -> Result<String, Failure> {
    let inputs = Inputs::load(arguments)?;
    let geometry = Geometry::fixed();
    let total_file_clusters = inputs.total_clusters()?;
    let used_clusters = 4_u32
        .checked_add(total_file_clusters)
        .ok_or_else(|| Failure::task("G3 image allocation overflowed"))?;
    if used_clusters > geometry.cluster_count {
        return Err(Failure::task("G3 artifacts do not fit the fixed FAT32 ESP"));
    }
    let layouts = layouts(&inputs)?;
    validate_output_path(arguments, Path::new(&arguments.image), output_root)?;
    let output_path = PathBuf::from(&arguments.image);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_path)
        .map_err(|error| Failure::task(format!("could not create G3 ESP: {error}")))?;
    let result = (|| {
        output
            .set_len(IMAGE_BYTES)
            .map_err(|error| Failure::task(format!("could not size G3 ESP: {error}")))?;
        write_boot_regions(&mut output, &geometry, used_clusters)?;
        write_fats(&mut output, &geometry, &layouts)?;
        write_directories(&mut output, &geometry, &layouts)?;
        for layout in layouts {
            write_file(&mut output, &geometry, layout)?;
        }
        output
            .sync_all()
            .map_err(|error| Failure::task(format!("could not sync G3 ESP: {error}")))?;
        Ok(())
    })();
    drop(output);
    if let Err(error) = result {
        let _ = fs::remove_file(&output_path);
        return Err(error);
    }
    inspect_created_or_remove(arguments, &output_path)
}

fn inspect_created_or_remove(
    arguments: &G3ImageArguments,
    output_path: &Path,
) -> Result<String, Failure> {
    match inspect(arguments) {
        Ok(report) => Ok(report),
        Err(error) => {
            let _ = fs::remove_file(output_path);
            Err(error)
        }
    }
}

pub(crate) fn inspect(arguments: &G3ImageArguments) -> Result<String, Failure> {
    let inputs = Inputs::load(arguments)?;
    let mut image = File::open(&arguments.image)
        .map_err(|error| Failure::task(format!("could not open G3 ESP: {error}")))?;
    let metadata = image
        .metadata()
        .map_err(|error| Failure::task(format!("could not stat G3 ESP: {error}")))?;
    if !metadata.file_type().is_file() || metadata.len() != IMAGE_BYTES {
        return Err(Failure::task(
            "G3 ESP has the wrong type or fixed byte length",
        ));
    }
    let geometry = inspect_boot_regions(&mut image)?;
    inspect_fat_copies(&mut image, &geometry)?;
    let root = read_cluster(&mut image, &geometry, ROOT_CLUSTER)?;
    let efi = directory_cluster(&root, *b"EFI        ")?;
    if efi != EFI_CLUSTER {
        return Err(Failure::task("G3 ESP EFI directory cluster drifted"));
    }
    let efi_directory = read_cluster(&mut image, &geometry, efi)?;
    let boot = directory_cluster(&efi_directory, *b"BOOT       ")?;
    let wyrmroot = directory_cluster(&efi_directory, *b"WYRMROOT   ")?;
    if boot != BOOT_CLUSTER || wyrmroot != WYRMROOT_CLUSTER {
        return Err(Failure::task("G3 ESP canonical directory layout drifted"));
    }
    let boot_directory = read_cluster(&mut image, &geometry, boot)?;
    let wyrmroot_directory = read_cluster(&mut image, &geometry, wyrmroot)?;
    let expected_lfn = lfn_entry("bootstrap.elf", &BOOTSTRAP_SHORT)?;
    if wyrmroot_directory[3 * 32..4 * 32] != expected_lfn {
        return Err(Failure::task(
            "G3 ESP bootstrap long filename entry is missing or noncanonical",
        ));
    }
    let extracted = [
        extract_file(&mut image, &geometry, &boot_directory, LOADER_SHORT)?,
        extract_file(&mut image, &geometry, &wyrmroot_directory, KERNEL_SHORT)?,
        extract_file(&mut image, &geometry, &wyrmroot_directory, BOOTSTRAP_SHORT)?,
        extract_file(&mut image, &geometry, &wyrmroot_directory, BOOTFS_SHORT)?,
    ];
    let expected = [
        inputs.loader.as_slice(),
        inputs.kernel.as_slice(),
        inputs.bootstrap.as_slice(),
        inputs.bootfs.as_slice(),
    ];
    for (actual, expected) in extracted.iter().zip(expected) {
        if actual.as_slice() != expected {
            return Err(Failure::task(
                "G3 ESP guest-consumed artifact bytes do not match the supplied input",
            ));
        }
    }
    let image_hash = sha256::file_digest(Path::new(&arguments.image))
        .map_err(|error| Failure::task(format!("could not hash G3 ESP: {error}")))?;
    Ok(format!(
        concat!(
            "{{\"schema_version\":1,\"phase\":\"WYR0-G3\",",
            "\"image_bytes\":{},\"image_sha256\":\"{}\",",
            "\"loader_sha256\":\"{}\",\"kernel_sha256\":\"{}\",",
            "\"bootstrap_sha256\":\"{}\",\"bootfs_sha256\":\"{}\"}}\n"
        ),
        IMAGE_BYTES,
        image_hash,
        sha256::bytes_digest(&inputs.loader),
        sha256::bytes_digest(&inputs.kernel),
        sha256::bytes_digest(&inputs.bootstrap),
        sha256::bytes_digest(&inputs.bootfs),
    ))
}

fn layouts(inputs: &Inputs) -> Result<[FileLayout<'_>; 4], Failure> {
    let mut next = FIRST_FILE_CLUSTER;
    Ok([
        allocate_layout(&mut next, LOADER_SHORT, None, &inputs.loader)?,
        allocate_layout(&mut next, KERNEL_SHORT, None, &inputs.kernel)?,
        allocate_layout(
            &mut next,
            BOOTSTRAP_SHORT,
            Some("bootstrap.elf"),
            &inputs.bootstrap,
        )?,
        allocate_layout(&mut next, BOOTFS_SHORT, None, &inputs.bootfs)?,
    ])
}

fn allocate_layout<'a>(
    next: &mut u32,
    short_name: [u8; 11],
    long_name: Option<&'static str>,
    bytes: &'a [u8],
) -> Result<FileLayout<'a>, Failure> {
    let clusters = cluster_count(bytes.len())?;
    let first_cluster = *next;
    *next = next
        .checked_add(clusters)
        .ok_or_else(|| Failure::task("G3 image cluster allocation overflowed"))?;
    Ok(FileLayout {
        short_name,
        long_name,
        bytes,
        first_cluster,
        clusters,
    })
}

fn read_artifact(path: &str, label: &str) -> Result<Vec<u8>, Failure> {
    let path = Path::new(path);
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Failure::task(format!("could not stat {label} artifact: {error}")))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 {
        return Err(Failure::task(format!(
            "{label} artifact must be a nonempty regular file"
        )));
    }
    fs::read(path)
        .map_err(|error| Failure::task(format!("could not read {label} artifact: {error}")))
}

fn validate_output_path(
    arguments: &G3ImageArguments,
    output: &Path,
    output_root: Option<&Path>,
) -> Result<(), Failure> {
    if fs::symlink_metadata(output).is_ok() {
        return Err(Failure::task("G3 ESP output already exists"));
    }
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent)
        .map_err(|error| Failure::task(format!("could not resolve ESP output parent: {error}")))?;
    if let Some(root) = output_root {
        let root = fs::canonicalize(root).map_err(|error| {
            Failure::task(format!("could not resolve ESP output root: {error}"))
        })?;
        if !parent.starts_with(&root) {
            return Err(Failure::task(
                "G3 ESP output parent escapes the WYR0-H request root",
            ));
        }
    }
    let output = parent.join(
        output
            .file_name()
            .ok_or_else(|| Failure::task("G3 ESP output has no file name"))?,
    );
    for input in [
        &arguments.loader,
        &arguments.kernel,
        &arguments.bootstrap,
        &arguments.bootfs,
    ] {
        let input = fs::canonicalize(input)
            .map_err(|error| Failure::task(format!("could not resolve G3 input: {error}")))?;
        if input == output {
            return Err(Failure::task("G3 ESP output aliases an input artifact"));
        }
    }
    Ok(())
}

fn cluster_count(byte_len: usize) -> Result<u32, Failure> {
    u32::try_from(byte_len.div_ceil(CLUSTER_BYTES))
        .map_err(|_| Failure::task("G3 artifact is too large for the fixed ESP"))
}

fn write_boot_regions(
    image: &mut File,
    geometry: &Geometry,
    used_clusters: u32,
) -> Result<(), Failure> {
    let boot = boot_sector(geometry);
    write_at(image, 0, &boot)?;
    write_at(image, 6 * SECTOR_BYTES, &boot)?;
    let free = geometry.cluster_count - used_clusters;
    let next = FIRST_FILE_CLUSTER + used_clusters - 4;
    let info = fs_info(free, next);
    write_at(image, SECTOR_BYTES, &info)?;
    write_at(image, 7 * SECTOR_BYTES, &info)
}

fn boot_sector(geometry: &Geometry) -> [u8; SECTOR_BYTES_USIZE] {
    let mut sector = [0_u8; SECTOR_BYTES_USIZE];
    sector[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
    sector[3..11].copy_from_slice(b"WYRMG3  ");
    put_u16(&mut sector, 11, SECTOR_BYTES as u16);
    sector[13] = SECTORS_PER_CLUSTER as u8;
    put_u16(&mut sector, 14, RESERVED_SECTORS as u16);
    sector[16] = FAT_COUNT as u8;
    sector[21] = MEDIA;
    put_u16(&mut sector, 24, 63);
    put_u16(&mut sector, 26, 255);
    put_u32(&mut sector, 32, TOTAL_SECTORS);
    put_u32(&mut sector, 36, geometry.fat_sectors);
    put_u32(&mut sector, 44, ROOT_CLUSTER);
    put_u16(&mut sector, 48, 1);
    put_u16(&mut sector, 50, 6);
    sector[64] = 0x80;
    sector[66] = 0x29;
    put_u32(&mut sector, 67, VOLUME_ID);
    sector[71..82].copy_from_slice(b"WYRMG3 ESP ");
    sector[82..90].copy_from_slice(b"FAT32   ");
    sector[510..512].copy_from_slice(&[0x55, 0xaa]);
    sector
}

fn fs_info(free_clusters: u32, next_free: u32) -> [u8; SECTOR_BYTES_USIZE] {
    let mut sector = [0_u8; SECTOR_BYTES_USIZE];
    put_u32(&mut sector, 0, 0x4161_5252);
    put_u32(&mut sector, 484, 0x6141_7272);
    put_u32(&mut sector, 488, free_clusters);
    put_u32(&mut sector, 492, next_free);
    put_u32(&mut sector, 508, 0xaa55_0000);
    sector
}

fn write_fats(
    image: &mut File,
    geometry: &Geometry,
    layouts: &[FileLayout<'_>; 4],
) -> Result<(), Failure> {
    let mut fat = vec![0_u8; geometry.fat_sectors as usize * SECTOR_BYTES_USIZE];
    set_fat(&mut fat, 0, 0x0fff_ff00 | u32::from(MEDIA));
    set_fat(&mut fat, 1, FAT_END);
    for cluster in ROOT_CLUSTER..=WYRMROOT_CLUSTER {
        set_fat(&mut fat, cluster, FAT_END);
    }
    for layout in layouts {
        for offset in 0..layout.clusters {
            let cluster = layout.first_cluster + offset;
            let next = if offset + 1 == layout.clusters {
                FAT_END
            } else {
                cluster + 1
            };
            set_fat(&mut fat, cluster, next);
        }
    }
    for index in 0..FAT_COUNT {
        let offset = u64::from(RESERVED_SECTORS + index * geometry.fat_sectors) * SECTOR_BYTES;
        write_at(image, offset, &fat)?;
    }
    Ok(())
}

fn write_directories(
    image: &mut File,
    geometry: &Geometry,
    layouts: &[FileLayout<'_>; 4],
) -> Result<(), Failure> {
    let root = directory_bytes(&[
        short_entry(*b"WYRMG3 ESP ", 0x08, 0, 0),
        short_entry(*b"EFI        ", 0x10, EFI_CLUSTER, 0),
    ]);
    let efi = directory_bytes(&[
        dot_entry(*b".          ", EFI_CLUSTER),
        dot_entry(*b"..         ", 0),
        short_entry(*b"BOOT       ", 0x10, BOOT_CLUSTER, 0),
        short_entry(*b"WYRMROOT   ", 0x10, WYRMROOT_CLUSTER, 0),
    ]);
    let boot = directory_bytes(&[
        dot_entry(*b".          ", BOOT_CLUSTER),
        dot_entry(*b"..         ", EFI_CLUSTER),
        short_entry(
            layouts[0].short_name,
            0x20,
            layouts[0].first_cluster,
            layouts[0].bytes.len() as u32,
        ),
    ]);
    let wyrmroot = directory_bytes(&[
        dot_entry(*b".          ", WYRMROOT_CLUSTER),
        dot_entry(*b"..         ", EFI_CLUSTER),
        short_entry(
            layouts[1].short_name,
            0x20,
            layouts[1].first_cluster,
            layouts[1].bytes.len() as u32,
        ),
        lfn_entry(
            layouts[2].long_name.expect("bootstrap has a long name"),
            &layouts[2].short_name,
        )?,
        short_entry(
            layouts[2].short_name,
            0x20,
            layouts[2].first_cluster,
            layouts[2].bytes.len() as u32,
        ),
        short_entry(
            layouts[3].short_name,
            0x20,
            layouts[3].first_cluster,
            layouts[3].bytes.len() as u32,
        ),
    ]);
    for (cluster, bytes) in [
        (ROOT_CLUSTER, root),
        (EFI_CLUSTER, efi),
        (BOOT_CLUSTER, boot),
        (WYRMROOT_CLUSTER, wyrmroot),
    ] {
        write_at(image, geometry.cluster_offset(cluster)?, &bytes)?;
    }
    Ok(())
}

fn directory_bytes(entries: &[[u8; 32]]) -> [u8; CLUSTER_BYTES] {
    let mut directory = [0_u8; CLUSTER_BYTES];
    for (index, entry) in entries.iter().enumerate() {
        directory[index * 32..(index + 1) * 32].copy_from_slice(entry);
    }
    directory
}

fn dot_entry(name: [u8; 11], cluster: u32) -> [u8; 32] {
    short_entry(name, 0x10, cluster, 0)
}

fn short_entry(name: [u8; 11], attributes: u8, cluster: u32, byte_len: u32) -> [u8; 32] {
    let mut entry = [0_u8; 32];
    entry[..11].copy_from_slice(&name);
    entry[11] = attributes;
    put_u16(&mut entry, 16, FIXED_DATE);
    put_u16(&mut entry, 18, FIXED_DATE);
    put_u16(&mut entry, 20, (cluster >> 16) as u16);
    put_u16(&mut entry, 24, FIXED_DATE);
    put_u16(&mut entry, 26, cluster as u16);
    put_u32(&mut entry, 28, byte_len);
    entry
}

fn lfn_entry(name: &str, short_name: &[u8; 11]) -> Result<[u8; 32], Failure> {
    let units: Vec<u16> = name.encode_utf16().collect();
    if units.len() != 13 {
        return Err(Failure::task(
            "G3 bootstrap long name no longer fits its fixed VFAT entry",
        ));
    }
    let mut entry = [0xff_u8; 32];
    entry[0] = 0x41;
    entry[11] = 0x0f;
    entry[12] = 0;
    entry[13] = short_checksum(short_name);
    entry[26] = 0;
    entry[27] = 0;
    for (unit, offset) in units
        .into_iter()
        .zip([1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30])
    {
        entry[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
    }
    Ok(entry)
}

fn short_checksum(name: &[u8; 11]) -> u8 {
    name.iter().fold(0_u8, |sum, byte| {
        ((sum & 1) << 7).wrapping_add(sum >> 1).wrapping_add(*byte)
    })
}

fn write_file(
    image: &mut File,
    geometry: &Geometry,
    layout: FileLayout<'_>,
) -> Result<(), Failure> {
    write_at(
        image,
        geometry.cluster_offset(layout.first_cluster)?,
        layout.bytes,
    )
}

fn inspect_boot_regions(image: &mut File) -> Result<Geometry, Failure> {
    let geometry = Geometry::fixed();
    let boot = read_at::<SECTOR_BYTES_USIZE>(image, 0)?;
    if boot != boot_sector(&geometry)
        || read_at::<SECTOR_BYTES_USIZE>(image, 6 * SECTOR_BYTES)? != boot
    {
        return Err(Failure::task("G3 ESP boot or backup boot sector drifted"));
    }
    let expected_used = fat_used_clusters(image, &geometry)?;
    let info = fs_info(
        geometry.cluster_count - expected_used,
        FIRST_FILE_CLUSTER + expected_used - 4,
    );
    if read_at::<SECTOR_BYTES_USIZE>(image, SECTOR_BYTES)? != info
        || read_at::<SECTOR_BYTES_USIZE>(image, 7 * SECTOR_BYTES)? != info
    {
        return Err(Failure::task("G3 ESP FSInfo or backup FSInfo drifted"));
    }
    Ok(geometry)
}

fn fat_used_clusters(image: &mut File, geometry: &Geometry) -> Result<u32, Failure> {
    let fat = read_fat(image, geometry, 0)?;
    let mut used = 0;
    for cluster in ROOT_CLUSTER..geometry.cluster_count + 2 {
        if fat_value(&fat, cluster) != 0 {
            used += 1;
        }
    }
    Ok(used)
}

fn inspect_fat_copies(image: &mut File, geometry: &Geometry) -> Result<(), Failure> {
    if read_fat(image, geometry, 0)? != read_fat(image, geometry, 1)? {
        return Err(Failure::task("G3 ESP FAT copies differ"));
    }
    Ok(())
}

fn read_fat(image: &mut File, geometry: &Geometry, index: u32) -> Result<Vec<u8>, Failure> {
    let mut fat = vec![0_u8; geometry.fat_sectors as usize * SECTOR_BYTES_USIZE];
    let offset = u64::from(RESERVED_SECTORS + index * geometry.fat_sectors) * SECTOR_BYTES;
    read_exact_at(image, offset, &mut fat)?;
    Ok(fat)
}

fn read_cluster(image: &mut File, geometry: &Geometry, cluster: u32) -> Result<Vec<u8>, Failure> {
    let mut bytes = vec![0_u8; CLUSTER_BYTES];
    read_exact_at(image, geometry.cluster_offset(cluster)?, &mut bytes)?;
    Ok(bytes)
}

fn directory_cluster(directory: &[u8], name: [u8; 11]) -> Result<u32, Failure> {
    let entry = directory
        .chunks_exact(32)
        .find(|entry| entry[..11] == name && entry[11] == 0x10)
        .ok_or_else(|| Failure::task("G3 ESP canonical directory is missing"))?;
    Ok(u32::from(u16::from_le_bytes([entry[26], entry[27]]))
        | (u32::from(u16::from_le_bytes([entry[20], entry[21]])) << 16))
}

fn extract_file(
    image: &mut File,
    geometry: &Geometry,
    directory: &[u8],
    name: [u8; 11],
) -> Result<Vec<u8>, Failure> {
    let entry = directory
        .chunks_exact(32)
        .find(|entry| entry[..11] == name && entry[11] == 0x20)
        .ok_or_else(|| Failure::task("G3 ESP canonical artifact is missing"))?;
    let first = u32::from(u16::from_le_bytes([entry[26], entry[27]]))
        | (u32::from(u16::from_le_bytes([entry[20], entry[21]])) << 16);
    let byte_len = u32::from_le_bytes(entry[28..32].try_into().expect("directory file size"));
    let fat = read_fat(image, geometry, 0)?;
    let mut output = Vec::with_capacity(byte_len as usize);
    let mut cluster = first;
    let mut remaining = byte_len as usize;
    let mut visits = 0_u32;
    while remaining != 0 {
        if visits >= geometry.cluster_count {
            return Err(Failure::task("G3 ESP FAT chain is cyclic"));
        }
        let bytes = read_cluster(image, geometry, cluster)?;
        let take = remaining.min(CLUSTER_BYTES);
        output.extend_from_slice(&bytes[..take]);
        remaining -= take;
        visits += 1;
        let next = fat_value(&fat, cluster);
        if remaining == 0 {
            if next < 0x0fff_fff8 {
                return Err(Failure::task("G3 ESP file chain has trailing clusters"));
            }
        } else if !(ROOT_CLUSTER..0x0fff_fff8).contains(&next) {
            return Err(Failure::task("G3 ESP file chain terminates early"));
        } else {
            cluster = next;
        }
    }
    Ok(output)
}

fn set_fat(fat: &mut [u8], cluster: u32, value: u32) {
    let offset = cluster as usize * 4;
    fat[offset..offset + 4].copy_from_slice(&(value & FAT_END).to_le_bytes());
}

fn fat_value(fat: &[u8], cluster: u32) -> u32 {
    let offset = cluster as usize * 4;
    u32::from_le_bytes(fat[offset..offset + 4].try_into().expect("FAT entry")) & FAT_END
}

fn write_at(file: &mut File, offset: u64, bytes: &[u8]) -> Result<(), Failure> {
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.write_all(bytes))
        .map_err(|error| Failure::task(format!("could not write G3 ESP: {error}")))
}

fn read_exact_at(file: &mut File, offset: u64, bytes: &mut [u8]) -> Result<(), Failure> {
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.read_exact(bytes))
        .map_err(|error| Failure::task(format!("could not read G3 ESP: {error}")))
}

fn read_at<const BYTES: usize>(file: &mut File, offset: u64) -> Result<[u8; BYTES], Failure> {
    let mut bytes = [0_u8; BYTES];
    read_exact_at(file, offset, &mut bytes)?;
    Ok(bytes)
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn fixture() -> (PathBuf, G3ImageArguments) {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!(
                "g3-image-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(&root).expect("create G3 image fixture");
        for (name, bytes) in [
            ("loader.efi", b"loader".as_slice()),
            ("deepwyrm.elf", b"kernel".as_slice()),
            ("bootstrap.elf", b"bootstrap".as_slice()),
            ("bootfs.img", b"bootfs".as_slice()),
        ] {
            fs::write(root.join(name), bytes).expect("write G3 image fixture");
        }
        let arguments = G3ImageArguments {
            image: root.join("esp.img").display().to_string(),
            loader: root.join("loader.efi").display().to_string(),
            kernel: root.join("deepwyrm.elf").display().to_string(),
            bootstrap: root.join("bootstrap.elf").display().to_string(),
            bootfs: root.join("bootfs.img").display().to_string(),
        };
        (root, arguments)
    }

    #[test]
    fn fixed_geometry_is_fat32_and_directory_names_are_canonical() {
        let geometry = Geometry::fixed();
        assert!(geometry.cluster_count >= 65_525);
        assert_eq!(
            lfn_entry("bootstrap.elf", &BOOTSTRAP_SHORT).unwrap()[0],
            0x41
        );
        assert_eq!(IMAGE_BYTES, 128 * 1024 * 1024);
    }

    #[test]
    fn build_and_inspect_bind_every_guest_consumed_byte() {
        let (root, arguments) = fixture();
        let report = build(&arguments).expect("build and inspect G3 image");
        assert!(report.contains("\"phase\":\"WYR0-G3\""));
        assert_eq!(inspect(&arguments).unwrap(), report);
        let error = build(&arguments).expect_err("existing image was overwritten");
        assert!(error.message.contains("already exists"));
        fs::remove_dir_all(root).expect("remove G3 image fixture");
    }

    #[test]
    fn failed_post_build_inspection_removes_the_new_output() {
        let (root, arguments) = fixture();
        build(&arguments).expect("build initial G3 image");
        OpenOptions::new()
            .write(true)
            .open(&arguments.image)
            .expect("open G3 image for corruption")
            .set_len(1)
            .expect("truncate G3 image");
        let image = Path::new(&arguments.image);
        let error = inspect_created_or_remove(&arguments, image)
            .expect_err("corrupt post-build image unexpectedly passed inspection");
        assert!(error.message.contains("wrong type or fixed byte length"));
        assert!(
            !image.exists(),
            "failed inspection left a poisoned G3 output"
        );
        fs::remove_dir_all(root).expect("remove G3 image fixture");
    }

    #[cfg(unix)]
    #[test]
    fn build_in_root_rejects_an_escaping_output_parent() {
        use std::os::unix::fs::symlink;

        let (root, mut arguments) = fixture();
        let outside = std::env::temp_dir().join(format!(
            "g3-image-outside-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&outside).expect("create outside directory");
        symlink(&outside, root.join("escape")).expect("create escaping parent link");
        arguments.image = root.join("escape/esp.img").display().to_string();
        let error = build_in_root(&arguments, Some(&root))
            .expect_err("escaping request-root output accepted");
        assert!(error.message.contains("escapes the WYR0-H request root"));
        fs::remove_dir_all(root).expect("remove G3 image fixture");
        fs::remove_dir_all(outside).expect("remove outside directory");
    }
}
