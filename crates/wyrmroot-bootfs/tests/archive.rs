use wyrmroot_bootfs::{
    WYR0_LIMITS,
    archive::{Archive, LookupError, ParseError},
    path::ArchivePathError,
};

fn record(name: &[u8], data: &[u8], filesize_override: Option<u32>) -> Vec<u8> {
    let namesize = u32::try_from(name.len() + 1).unwrap();
    let filesize = filesize_override.unwrap_or_else(|| u32::try_from(data.len()).unwrap());
    let mut header = [b'0'; 110];
    header[..6].copy_from_slice(b"070701");
    for start in [6, 14, 22, 30, 38, 46] {
        header[start..start + 8].copy_from_slice(b"00000000");
    }
    write_hex(&mut header[54..62], filesize);
    for start in [62, 70, 78, 86] {
        header[start..start + 8].copy_from_slice(b"00000000");
    }
    if name != b"TRAILER!!!" {
        write_hex(&mut header[14..22], 0x8124);
        write_hex(&mut header[38..46], 1);
    }
    write_hex(&mut header[94..102], namesize);
    header[102..110].copy_from_slice(b"00000000");

    let mut output = header.to_vec();
    output.extend_from_slice(name);
    output.push(0);
    pad(&mut output);
    output.extend_from_slice(data);
    pad(&mut output);
    output
}

fn archive(records: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut output = Vec::new();
    for &(name, data) in records {
        output.extend(record(name, data, None));
    }
    output.extend(record(b"TRAILER!!!", &[], None));
    output
}

fn pad(bytes: &mut Vec<u8>) {
    while !bytes.len().is_multiple_of(4) {
        bytes.push(0);
    }
}

fn write_hex(field: &mut [u8], value: u32) {
    assert_eq!(field.len(), 8);
    for (index, slot) in field.iter_mut().enumerate() {
        let shift = 4 * (7 - index);
        *slot = b"0123456789abcdef"[((value >> shift) & 0xf) as usize];
    }
}

#[test]
fn parses_zero_copy_entries_and_trailer() {
    let bytes = archive(&[(b"bin/hello", b"hello"), (b"system/init0", b"init")]);
    let parsed = Archive::new(&bytes).unwrap();
    let entries: Vec<_> = parsed.entries().collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name(), b"bin/hello");
    assert_eq!(entries[0].data(), b"hello");
    assert_eq!(entries[1].name(), b"system/init0");
    assert_eq!(entries[1].data(), b"init");
}

#[test]
fn public_lookup_is_canonical_zero_copy_and_byte_safe() {
    let bytes = archive(&[(b"bin/\xffhello", b"hello"), (b"system/init0", b"init")]);
    let parsed = Archive::new(&bytes).unwrap();

    let entry = parsed.lookup(b"system/init0").unwrap();
    assert_eq!(entry.data(), b"init");
    assert!(entry.data().as_ptr() >= bytes.as_ptr());
    assert!(entry.data().as_ptr() < bytes.as_ptr_range().end);

    let byte_name = parsed.lookup(b"bin/\xffhello").unwrap();
    assert!(byte_name.name_utf8().is_err());
    assert_eq!(parsed.lookup(b"missing"), Err(LookupError::NotFound));
    assert_eq!(
        parsed.lookup(b"system//init0"),
        Err(LookupError::InvalidPath(ArchivePathError::EmptyComponent))
    );
}

#[test]
fn parser_observes_only_the_declared_archive_slice() {
    let encoded = archive(&[(b"bin/hello", b"hello")]);
    let mut backing = encoded.clone();
    backing.extend_from_slice(&record(b"hidden", b"payload", None));

    let parsed = Archive::new(&backing[..encoded.len()]).unwrap();
    assert_eq!(parsed.lookup(b"hidden"), Err(LookupError::NotFound));
    assert!(Archive::new(&backing[..encoded.len() - 1]).is_err());
}

#[test]
fn rejects_truncated_header_name_data_and_padding() {
    let bytes = archive(&[(b"file", b"data")]);
    for end in [0, 1, 109, 110, 114, bytes.len() - 1] {
        assert!(
            Archive::new(&bytes[..end]).is_err(),
            "accepted length {end}"
        );
    }

    let mut nonzero_padding = archive(&[(b"file", b"x")]);
    nonzero_padding[117] = 1;
    assert!(matches!(
        Archive::new(&nonzero_padding),
        Err(ParseError::InvalidPadding { .. })
    ));
}

#[test]
fn rejects_invalid_magic_numeric_name_and_trailer() {
    let mut invalid_magic = archive(&[(b"file", b"data")]);
    invalid_magic[0] = b'X';
    assert!(matches!(
        Archive::new(&invalid_magic),
        Err(ParseError::InvalidMagic { .. })
    ));

    let mut invalid_numeric = archive(&[(b"file", b"data")]);
    invalid_numeric[54] = b'G';
    assert!(matches!(
        Archive::new(&invalid_numeric),
        Err(ParseError::InvalidNumeric { .. })
    ));

    for offset in [6, 14, 22, 30, 38, 46, 54, 62, 70, 78, 86, 94, 102] {
        let mut malformed = archive(&[(b"file", b"data")]);
        malformed[offset] = b'G';
        assert!(
            matches!(
                Archive::new(&malformed),
                Err(ParseError::InvalidNumeric { .. })
            ),
            "numeric field at {offset} was accepted"
        );
    }

    let mut huge_name = archive(&[(b"file", b"data")]);
    huge_name[94..102].copy_from_slice(b"ffffffff");
    assert!(matches!(
        Archive::new(&huge_name),
        Err(ParseError::NameTooLarge { .. })
    ));

    let mut huge_data = archive(&[(b"file", b"data")]);
    huge_data[54..62].copy_from_slice(b"ffffffff");
    assert!(matches!(
        Archive::new(&huge_data),
        Err(ParseError::TruncatedData { .. })
    ));

    let mut invalid_name = archive(&[(b"file", b"data")]);
    invalid_name[101] = b'0';
    invalid_name[100] = b'0';
    invalid_name[99] = b'0';
    invalid_name[98] = b'0';
    invalid_name[97] = b'0';
    invalid_name[96] = b'0';
    invalid_name[95] = b'0';
    invalid_name[94] = b'0';
    assert!(Archive::new(&invalid_name).is_err());

    let mut invalid_trailer = archive(&[(b"file", b"data")]);
    let trailer = invalid_trailer.len() - 124;
    invalid_trailer[trailer + 45] = b'1';
    assert!(matches!(
        Archive::new(&invalid_trailer),
        Err(ParseError::InvalidTrailer { .. })
    ));
}

#[test]
fn rejects_duplicate_names_and_missing_or_extra_trailer() {
    let duplicate = archive(&[(b"same", b"one"), (b"same", b"two")]);
    assert!(matches!(
        Archive::new(&duplicate),
        Err(ParseError::DuplicateName { .. })
    ));

    let mut missing = record(b"file", b"data", None);
    assert!(matches!(
        Archive::new(&missing),
        Err(ParseError::TruncatedHeader { .. })
    ));

    let mut extra = archive(&[(b"file", b"data")]);
    extra.extend_from_slice(b"x");
    assert!(matches!(
        Archive::new(&extra),
        Err(ParseError::TrailingBytes { .. })
    ));

    missing.clear();
}

#[test]
fn rejects_embedded_name_nul_and_preserves_byte_names_for_path_policy() {
    let mut malformed = record(b"file\0tail", b"data", None);
    malformed.extend_from_slice(&record(b"TRAILER!!!", &[], None));
    assert!(matches!(
        Archive::new(&malformed),
        Err(ParseError::InvalidName { .. })
    ));

    let bytes = archive(&[(b"../untrusted", b"data")]);
    assert!(matches!(
        Archive::new(&bytes),
        Err(ParseError::InvalidPath { .. })
    ));
}

#[test]
fn rejects_unsorted_names_and_corrupt_name_padding() {
    let unsorted = archive(&[(b"system/init0", b"init"), (b"bin/hello", b"hello")]);
    assert!(matches!(
        Archive::new(&unsorted),
        Err(ParseError::UnsortedName { .. })
    ));

    let mut corrupt = archive(&[(b"file", b"data")]);
    // Header (110) + name (4) + terminating NUL; the next byte is alignment padding.
    corrupt[115] = 0x5a;
    assert!(matches!(
        Archive::new(&corrupt),
        Err(ParseError::InvalidPadding { .. })
    ));
}

#[test]
fn rejects_nonzero_metadata_file_types_and_special_permissions() {
    let mut uid = archive(&[(b"file", b"data")]);
    uid[29] = b'1';
    assert!(matches!(
        Archive::new(&uid),
        Err(ParseError::InvalidMetadata { .. })
    ));

    let mut directory = archive(&[(b"file", b"data")]);
    directory[14..22].copy_from_slice(b"00004000");
    assert!(matches!(
        Archive::new(&directory),
        Err(ParseError::UnsupportedFileType { .. })
    ));

    for mode in [0x81a4, 0x8124 | 0x800, 0x8124 | 0x400] {
        let mut special = archive(&[(b"file", b"data")]);
        write_hex(&mut special[14..22], mode);
        assert!(matches!(
            Archive::new(&special),
            Err(ParseError::UnsupportedPermissions { .. })
        ));
    }
}

fn many_records(count: usize) -> Vec<u8> {
    let mut output = Vec::new();
    for index in 0..count {
        let name = format!("file/{index:04}");
        output.extend(record(name.as_bytes(), b"x", None));
    }
    output.extend(record(b"TRAILER!!!", &[], None));
    output
}

#[test]
fn enforces_exact_record_limit_and_rejects_one_more() {
    let exact = many_records(WYR0_LIMITS.max_records);
    assert!(Archive::new(&exact).is_ok());

    let over = many_records(WYR0_LIMITS.max_records + 1);
    assert!(matches!(
        Archive::new(&over),
        Err(ParseError::TooManyRecords { .. })
    ));
}

#[test]
fn enforces_encoded_name_limit() {
    let exact_name = vec![b'a'; WYR0_LIMITS.max_encoded_name_bytes - 1];
    let exact = archive(&[(&exact_name, b"x")]);
    assert!(Archive::new(&exact).is_ok());

    let over_name = vec![b'a'; WYR0_LIMITS.max_encoded_name_bytes];
    let over = archive(&[(&over_name, b"x")]);
    assert!(matches!(
        Archive::new(&over),
        Err(ParseError::NameTooLarge { .. })
    ));
}

#[test]
fn enforces_exact_archive_length_limit() {
    // One regular record with a four-byte name has 116 bytes before payload; the trailer is
    // 124 bytes. Choose a four-byte-aligned payload so the encoded archive lands exactly on cap.
    let payload = vec![b'x'; WYR0_LIMITS.max_archive_bytes - 240];
    let exact = archive(&[(b"file", payload.as_slice())]);
    assert_eq!(exact.len(), WYR0_LIMITS.max_archive_bytes);
    assert!(Archive::new(&exact).is_ok());

    let mut over = exact;
    over.push(0);
    assert!(matches!(
        Archive::new(&over),
        Err(ParseError::ArchiveTooLarge { .. })
    ));
}

#[test]
fn malformed_mutations_never_panic_and_successes_remain_canonical() {
    let original = archive(&[(b"bin/hello", b"hello"), (b"system/init0", b"init")]);
    for index in 0..original.len() {
        let mut mutated = original.clone();
        mutated[index] ^= 0xa5;
        let result = std::panic::catch_unwind(|| Archive::new(&mutated));
        assert!(result.is_ok(), "mutation at {index} panicked");
        if let Ok(Ok(parsed)) = result {
            for entry in parsed.entries() {
                assert!(!entry.name().is_empty());
                assert!(entry.name().len() < WYR0_LIMITS.max_encoded_name_bytes);
                assert_ne!(entry.name()[0], b'/');
                assert!(!entry.name().windows(2).any(|part| part == b"//"));
            }
        }
    }
}
