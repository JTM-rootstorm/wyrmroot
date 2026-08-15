use wyrmroot_bootfs::path::{ArchivePath, ArchivePathError};

#[test]
fn accepts_one_relative_byte_canonical_form() {
    let path = ArchivePath::new(b"system/init0").unwrap();

    assert_eq!(path.as_bytes(), b"system/init0");
    assert!(path.matches(b"system/init0").unwrap());
    assert!(!path.matches(b"bin/hello").unwrap());
}

#[test]
fn accepts_non_utf8_archive_names_but_text_conversion_is_explicit() {
    let path = ArchivePath::new(b"system/\xffinit0").unwrap();

    assert_eq!(path.as_bytes(), b"system/\xffinit0");
    assert!(path.as_utf8().is_err());
}

#[test]
fn exposes_utf8_without_rewriting_the_path() {
    let path = ArchivePath::new("system/\u{00e9}".as_bytes()).unwrap();

    assert_eq!(path.as_utf8().unwrap(), "system/\u{00e9}");
}

#[test]
fn rejects_every_alias_or_navigation_spelling() {
    for (path, error) in [
        (b"".as_slice(), ArchivePathError::EmptyPath),
        (b"/system/init0".as_slice(), ArchivePathError::AbsolutePath),
        (
            b"system//init0".as_slice(),
            ArchivePathError::EmptyComponent,
        ),
        (
            b"system/init0/".as_slice(),
            ArchivePathError::EmptyComponent,
        ),
        (
            b"./system/init0".as_slice(),
            ArchivePathError::CurrentDirectoryComponent,
        ),
        (
            b"system/./init0".as_slice(),
            ArchivePathError::CurrentDirectoryComponent,
        ),
        (
            b"../system/init0".as_slice(),
            ArchivePathError::ParentDirectoryComponent,
        ),
        (
            b"system/../init0".as_slice(),
            ArchivePathError::ParentDirectoryComponent,
        ),
        (b"system\\init0".as_slice(), ArchivePathError::Backslash),
        (b"system/\0init0".as_slice(), ArchivePathError::NulByte),
        (
            b"TRAILER!!!".as_slice(),
            ArchivePathError::ReservedTrailerName,
        ),
    ] {
        assert_eq!(ArchivePath::new(path), Err(error), "{path:?}");
    }
}

#[test]
fn lookup_rejects_noncanonical_candidate_spelling() {
    let path = ArchivePath::new(b"bin/hello").unwrap();

    assert_eq!(
        path.matches(b"bin//hello"),
        Err(ArchivePathError::EmptyComponent)
    );
}

#[test]
fn enforces_the_encoded_name_limit_including_the_nul() {
    let maximum = vec![b'a'; 4095];
    let over_limit = vec![b'a'; 4096];

    assert!(ArchivePath::new(&maximum).is_ok());
    assert_eq!(
        ArchivePath::new(&over_limit),
        Err(ArchivePathError::PathTooLong)
    );
}
