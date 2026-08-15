use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use crate::error::Failure;

const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const MAX_PROGRAM_HEADERS: usize = 128;
const MAX_INTERPRETER_BYTES: usize = 4096;
const MAX_DYNAMIC_BYTES: usize = 1024 * 1024;
const MAX_DYNAMIC_STRING_BYTES: usize = 4 * 1024 * 1024;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;
const DT_RPATH: u64 = 15;
const DT_RUNPATH: u64 = 29;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RuntimeMetadata {
    pub(crate) interpreter: Option<String>,
    pub(crate) runpath: String,
    pub(crate) needed: Vec<String>,
}

#[derive(Clone, Copy)]
struct LoadSegment {
    offset: u64,
    virtual_address: u64,
    file_size: u64,
}

pub(crate) fn inspect(file: &mut File, label: &str) -> Result<RuntimeMetadata, Failure> {
    let file_size = file
        .metadata()
        .map_err(|error| Failure::task(format!("could not inspect {label} ELF: {error}")))?
        .len();
    let header = read_at(file, 0, ELF_HEADER_SIZE, file_size, label)?;
    if &header[..4] != b"\x7fELF"
        || header[4] != 2
        || header[5] != 1
        || u16_at(&header, 18) != 62
        || u16_at(&header, 52) as usize != ELF_HEADER_SIZE
    {
        return Err(Failure::task(format!(
            "{label} is not a supported ELF64 little-endian x86_64 executable"
        )));
    }
    let program_offset = u64_at(&header, 32);
    let entry_size = usize::from(u16_at(&header, 54));
    let entry_count = usize::from(u16_at(&header, 56));
    if entry_size < PROGRAM_HEADER_SIZE || !(1..=MAX_PROGRAM_HEADERS).contains(&entry_count) {
        return Err(Failure::task(format!(
            "{label} has an invalid ELF program-header table"
        )));
    }

    let mut loads = Vec::new();
    let mut dynamic = None;
    let mut interpreter = None;
    for index in 0..entry_count {
        let offset = program_offset
            .checked_add(
                u64::try_from(index)
                    .expect("bounded program-header index")
                    .checked_mul(u64::try_from(entry_size).expect("program-header size fits u64"))
                    .ok_or_else(|| Failure::task(format!("{label} program headers overflow")))?,
            )
            .ok_or_else(|| Failure::task(format!("{label} program headers overflow")))?;
        let entry = read_at(file, offset, PROGRAM_HEADER_SIZE, file_size, label)?;
        let kind = u32_at(&entry, 0);
        let segment_offset = u64_at(&entry, 8);
        let virtual_address = u64_at(&entry, 16);
        let segment_file_size = u64_at(&entry, 32);
        match kind {
            PT_LOAD => loads.push(LoadSegment {
                offset: segment_offset,
                virtual_address,
                file_size: segment_file_size,
            }),
            PT_DYNAMIC => {
                if dynamic
                    .replace((segment_offset, segment_file_size))
                    .is_some()
                {
                    return Err(Failure::task(format!(
                        "{label} contains multiple PT_DYNAMIC segments"
                    )));
                }
            }
            PT_INTERP => {
                if interpreter.is_some()
                    || segment_file_size == 0
                    || segment_file_size > MAX_INTERPRETER_BYTES as u64
                {
                    return Err(Failure::task(format!(
                        "{label} contains an invalid PT_INTERP segment"
                    )));
                }
                let bytes = read_at(
                    file,
                    segment_offset,
                    usize::try_from(segment_file_size)
                        .map_err(|_| Failure::task(format!("{label} interpreter is too large")))?,
                    file_size,
                    label,
                )?;
                interpreter = Some(exact_c_string(&bytes, label, "interpreter")?);
            }
            _ => {}
        }
    }
    let (dynamic_offset, dynamic_size) =
        dynamic.ok_or_else(|| Failure::task(format!("{label} has no PT_DYNAMIC segment")))?;
    if dynamic_size == 0 || dynamic_size > MAX_DYNAMIC_BYTES as u64 || dynamic_size % 16 != 0 {
        return Err(Failure::task(format!(
            "{label} has an invalid PT_DYNAMIC size"
        )));
    }
    let dynamic_bytes = read_at(
        file,
        dynamic_offset,
        usize::try_from(dynamic_size)
            .map_err(|_| Failure::task(format!("{label} dynamic table is too large")))?,
        file_size,
        label,
    )?;
    let mut string_address = None;
    let mut string_size = None;
    let mut needed_offsets = Vec::new();
    let mut runpath_offset = None;
    let mut terminated = false;
    for entry in dynamic_bytes.chunks_exact(16) {
        let tag = u64_at(entry, 0);
        let value = u64_at(entry, 8);
        match tag {
            DT_NULL => {
                terminated = true;
                break;
            }
            DT_NEEDED => needed_offsets.push(value),
            DT_STRTAB => set_once(&mut string_address, value, label, "DT_STRTAB")?,
            DT_STRSZ => set_once(&mut string_size, value, label, "DT_STRSZ")?,
            DT_RUNPATH => set_once(&mut runpath_offset, value, label, "DT_RUNPATH")?,
            DT_RPATH => {
                return Err(Failure::task(format!(
                    "{label} uses unsupported legacy DT_RPATH"
                )));
            }
            _ => {}
        }
    }
    if !terminated {
        return Err(Failure::task(format!(
            "{label} dynamic table has no DT_NULL terminator"
        )));
    }
    let string_address =
        string_address.ok_or_else(|| Failure::task(format!("{label} has no DT_STRTAB")))?;
    let string_size =
        string_size.ok_or_else(|| Failure::task(format!("{label} has no DT_STRSZ")))?;
    if string_size == 0 || string_size > MAX_DYNAMIC_STRING_BYTES as u64 {
        return Err(Failure::task(format!(
            "{label} has an invalid dynamic string-table size"
        )));
    }
    let string_offset = virtual_to_file_offset(&loads, string_address, string_size, label)?;
    let strings = read_at(
        file,
        string_offset,
        usize::try_from(string_size)
            .map_err(|_| Failure::task(format!("{label} string table is too large")))?,
        file_size,
        label,
    )?;
    let runpath = dynamic_string(
        &strings,
        runpath_offset.ok_or_else(|| Failure::task(format!("{label} has no DT_RUNPATH")))?,
        label,
        "RUNPATH",
    )?;
    let mut seen = BTreeSet::new();
    let mut needed = Vec::new();
    for offset in needed_offsets {
        let name = dynamic_string(&strings, offset, label, "DT_NEEDED")?;
        if name.contains('/') || !seen.insert(name.clone()) {
            return Err(Failure::task(format!(
                "{label} contains an invalid or duplicate DT_NEEDED entry '{name}'"
            )));
        }
        needed.push(name);
    }
    if needed.is_empty() {
        return Err(Failure::task(format!("{label} has no DT_NEEDED entries")));
    }
    Ok(RuntimeMetadata {
        interpreter,
        runpath,
        needed,
    })
}

fn set_once(slot: &mut Option<u64>, value: u64, label: &str, field: &str) -> Result<(), Failure> {
    if slot.replace(value).is_some() {
        Err(Failure::task(format!(
            "{label} contains multiple {field} entries"
        )))
    } else {
        Ok(())
    }
}

fn virtual_to_file_offset(
    loads: &[LoadSegment],
    address: u64,
    size: u64,
    label: &str,
) -> Result<u64, Failure> {
    let end = address
        .checked_add(size)
        .ok_or_else(|| Failure::task(format!("{label} dynamic string table overflows")))?;
    for load in loads {
        let load_end = load
            .virtual_address
            .checked_add(load.file_size)
            .ok_or_else(|| Failure::task(format!("{label} PT_LOAD range overflows")))?;
        if address >= load.virtual_address && end <= load_end {
            return load
                .offset
                .checked_add(address - load.virtual_address)
                .ok_or_else(|| Failure::task(format!("{label} string-table offset overflows")));
        }
    }
    Err(Failure::task(format!(
        "{label} dynamic string table is not contained in a file-backed PT_LOAD"
    )))
}

fn exact_c_string(bytes: &[u8], label: &str, field: &str) -> Result<String, Failure> {
    let Some(value) = bytes.strip_suffix(&[0]) else {
        return Err(Failure::task(format!(
            "{label} {field} is not exactly NUL-terminated"
        )));
    };
    if value.contains(&0) {
        return Err(Failure::task(format!(
            "{label} {field} contains an embedded NUL"
        )));
    }
    std::str::from_utf8(value)
        .map(str::to_owned)
        .map_err(|_| Failure::task(format!("{label} {field} is not UTF-8")))
}

fn dynamic_string(bytes: &[u8], offset: u64, label: &str, field: &str) -> Result<String, Failure> {
    let offset = usize::try_from(offset)
        .ok()
        .filter(|offset| *offset < bytes.len())
        .ok_or_else(|| Failure::task(format!("{label} {field} offset is out of bounds")))?;
    let rest = &bytes[offset..];
    let end = rest
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| Failure::task(format!("{label} {field} is not NUL-terminated")))?;
    let value = std::str::from_utf8(&rest[..end])
        .map_err(|_| Failure::task(format!("{label} {field} is not UTF-8")))?;
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(Failure::task(format!("{label} {field} is invalid")));
    }
    Ok(value.to_owned())
}

fn read_at(
    file: &mut File,
    offset: u64,
    length: usize,
    file_size: u64,
    label: &str,
) -> Result<Vec<u8>, Failure> {
    let end = offset
        .checked_add(u64::try_from(length).expect("usize fits u64 on supported host"))
        .filter(|end| *end <= file_size)
        .ok_or_else(|| Failure::task(format!("{label} ELF range is out of bounds")))?;
    let _ = end;
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| {
            let mut bytes = vec![0; length];
            file.read_exact(&mut bytes).map(|()| bytes)
        })
        .map_err(|error| Failure::task(format!("could not read {label} ELF metadata: {error}")))
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("checked ELF u16"),
    )
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("checked ELF u32"),
    )
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("checked ELF u64"),
    )
}

#[cfg(test)]
mod tests {
    use super::inspect;
    use std::fs::{self, File};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn parses_bounded_runtime_metadata_and_rejects_bad_string_mapping() {
        let path = temporary_file("valid");
        fs::write(&path, fixture(false)).expect("write ELF fixture");
        let mut file = File::open(&path).expect("open ELF fixture");
        let runtime = inspect(&mut file, "fixture").expect("valid ELF runtime metadata rejected");
        assert_eq!(
            runtime.interpreter.as_deref(),
            Some("/lib64/ld-linux-x86-64.so.2")
        );
        assert_eq!(runtime.runpath, "$ORIGIN/../lib");
        assert_eq!(runtime.needed, ["libtrusted.so"]);
        fs::remove_file(&path).expect("remove ELF fixture");

        let path = temporary_file("bad-string-map");
        fs::write(&path, fixture(true)).expect("write malformed ELF fixture");
        let mut file = File::open(&path).expect("open malformed ELF fixture");
        assert!(inspect(&mut file, "fixture").is_err());
        fs::remove_file(path).expect("remove malformed ELF fixture");
    }

    fn fixture(bad_string_address: bool) -> Vec<u8> {
        const BASE: u64 = 0x400000;
        const DYNAMIC_OFFSET: usize = 240;
        const INTERPRETER_OFFSET: usize = 320;
        const STRINGS_OFFSET: usize = 352;
        let interpreter = b"/lib64/ld-linux-x86-64.so.2\0";
        let strings = b"\0libtrusted.so\0$ORIGIN/../lib\0";
        let mut bytes = vec![0_u8; STRINGS_OFFSET + strings.len()];
        let file_size = bytes.len() as u64;
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        put_u16(&mut bytes, 18, 62);
        put_u64(&mut bytes, 32, 64);
        put_u16(&mut bytes, 52, 64);
        put_u16(&mut bytes, 54, 56);
        put_u16(&mut bytes, 56, 3);

        program_header(&mut bytes, 64, 1, 0, BASE, file_size);
        program_header(
            &mut bytes,
            120,
            2,
            DYNAMIC_OFFSET as u64,
            BASE + DYNAMIC_OFFSET as u64,
            80,
        );
        program_header(
            &mut bytes,
            176,
            3,
            INTERPRETER_OFFSET as u64,
            BASE + INTERPRETER_OFFSET as u64,
            interpreter.len() as u64,
        );
        bytes[INTERPRETER_OFFSET..INTERPRETER_OFFSET + interpreter.len()]
            .copy_from_slice(interpreter);
        bytes[STRINGS_OFFSET..].copy_from_slice(strings);
        dynamic_entry(&mut bytes, DYNAMIC_OFFSET, 1, 1);
        dynamic_entry(
            &mut bytes,
            DYNAMIC_OFFSET + 16,
            5,
            if bad_string_address {
                BASE + file_size + 1
            } else {
                BASE + STRINGS_OFFSET as u64
            },
        );
        dynamic_entry(&mut bytes, DYNAMIC_OFFSET + 32, 10, strings.len() as u64);
        dynamic_entry(&mut bytes, DYNAMIC_OFFSET + 48, 29, 15);
        dynamic_entry(&mut bytes, DYNAMIC_OFFSET + 64, 0, 0);
        bytes
    }

    fn program_header(
        bytes: &mut [u8],
        offset: usize,
        kind: u32,
        file_offset: u64,
        virtual_address: u64,
        file_size: u64,
    ) {
        put_u32(bytes, offset, kind);
        put_u64(bytes, offset + 8, file_offset);
        put_u64(bytes, offset + 16, virtual_address);
        put_u64(bytes, offset + 32, file_size);
        put_u64(bytes, offset + 40, file_size);
    }

    fn dynamic_entry(bytes: &mut [u8], offset: usize, tag: u64, value: u64) {
        put_u64(bytes, offset, tag);
        put_u64(bytes, offset + 8, value);
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn temporary_file(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "wyrmroot-elf-runtime-{label}-{}-{nonce}",
            std::process::id()
        ))
    }
}
