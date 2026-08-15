#![cfg(feature = "builder")]

use wyrmroot_bootfs::{
    WYR0_LIMITS,
    archive::Archive,
    builder::{BuildError, Builder, FileMode},
};

fn build(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut builder = Builder::new();
    for &(path, data) in entries {
        builder.add(path, data, FileMode::Executable).unwrap();
    }
    builder.build().unwrap()
}

#[test]
fn canonical_order_and_metadata_make_output_deterministic() {
    let first = build(&[(b"system/init0", b"init"), (b"bin/hello", b"hello")]);
    let second = build(&[(b"bin/hello", b"hello"), (b"system/init0", b"init")]);
    assert_eq!(first, second);

    assert_eq!(&first[..6], b"070701");
    assert_eq!(&first[6..14], b"00000000");
    assert_eq!(&first[14..22], b"0000816d");
    assert_eq!(&first[22..38], b"0000000000000000");
    assert_eq!(&first[38..46], b"00000001");
    assert_eq!(&first[46..54], b"00000000");
    assert_eq!(&first[62..94], b"00000000000000000000000000000000");
    assert_eq!(&first[102..110], b"00000000");
}

#[test]
fn serializes_names_payloads_padding_and_exact_trailer() {
    let bytes = build(&[(b"bin/hello", b"hello"), (b"system/init0", b"init")]);
    assert_eq!(&bytes[94..102], b"0000000a");
    assert_eq!(&bytes[110..120], b"bin/hello\0");
    assert_eq!(&bytes[120..125], b"hello");
    assert_eq!(&bytes[125..128], &[0, 0, 0]);

    let trailer = bytes.len() - 124;
    assert_eq!(&bytes[trailer..trailer + 6], b"070701");
    assert_eq!(&bytes[trailer + 6..trailer + 14], b"00000000");
    assert_eq!(&bytes[trailer + 14..trailer + 22], b"00000000");
    assert_eq!(&bytes[trailer + 38..trailer + 46], b"00000000");
    assert_eq!(&bytes[trailer + 54..trailer + 62], b"00000000");
    assert_eq!(&bytes[trailer + 94..trailer + 102], b"0000000b");
    assert_eq!(&bytes[trailer + 110..trailer + 121], b"TRAILER!!!\0");
    assert_eq!(trailer + 124, bytes.len());
}

#[test]
fn rejects_noncanonical_and_duplicate_paths_without_filesystem_access() {
    let mut builder = Builder::new();
    assert_eq!(
        builder.add(b"../system/init0", b"init", FileMode::Executable),
        Err(BuildError::InvalidPath)
    );
    assert_eq!(
        builder.add(b"TRAILER!!!", b"not a trailer", FileMode::ReadOnly),
        Err(BuildError::InvalidPath)
    );
    builder
        .add(b"system/init0", b"init", FileMode::Executable)
        .unwrap();
    builder
        .add(b"system/init0", b"other", FileMode::ReadOnly)
        .unwrap();
    assert_eq!(builder.build(), Err(BuildError::DuplicatePath));
}

#[test]
fn modes_are_explicit_immutable_regular_files_and_round_trip() {
    let mut builder = Builder::new();
    builder
        .add(b"config/default", b"config", FileMode::ReadOnly)
        .unwrap();
    builder
        .add(b"bin/hello", b"hello", FileMode::Executable)
        .unwrap();
    let bytes = builder.build().unwrap();

    assert_eq!(&bytes[14..22], b"0000816d");
    let second_header = 128;
    assert_eq!(&bytes[second_header + 14..second_header + 22], b"00008124");

    let archive = Archive::new(&bytes).unwrap();
    let entries: Vec<_> = archive.entries().collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name(), b"bin/hello");
    assert_eq!(entries[0].data(), b"hello");
    assert_eq!(entries[1].name(), b"config/default");
    assert_eq!(entries[1].data(), b"config");
}

#[test]
fn enforces_exact_record_and_encoded_name_caps() {
    let mut names = Vec::with_capacity(WYR0_LIMITS.max_records);
    for number in 0..WYR0_LIMITS.max_records {
        names.push(format!("entry/{number:04x}").into_bytes());
    }

    let mut builder = Builder::new();
    for name in &names {
        builder
            .add(name, &[], FileMode::ReadOnly)
            .expect("exact record cap must be accepted");
    }
    assert_eq!(
        builder.add(b"one-too-many", &[], FileMode::ReadOnly),
        Err(BuildError::RecordLimit)
    );

    let exact_name = vec![b'a'; WYR0_LIMITS.max_encoded_name_bytes - 1];
    let one_too_long = vec![b'a'; WYR0_LIMITS.max_encoded_name_bytes];
    let mut names = Builder::new();
    names
        .add(&exact_name, &[], FileMode::ReadOnly)
        .expect("name cap includes the trailing NUL");
    assert_eq!(
        names.add(&one_too_long, &[], FileMode::ReadOnly),
        Err(BuildError::NameTooLong)
    );
}
