#![cfg(feature = "builder")]

use wyrmroot_bootfs::content::{
    ArchiveMode, ArtifactKind, HELLO_ARCHIVE_PATH, INIT0_ARCHIVE_PATH, InputArtifact,
    ManifestError, build_manifest,
};

fn artifact<'a>(kind: ArtifactKind, source_path: &'a str, bytes: &'a [u8]) -> InputArtifact<'a> {
    InputArtifact {
        kind,
        source_path,
        bytes,
    }
}

#[test]
fn maps_real_inputs_to_exact_paths_in_deterministic_order() {
    let manifest = build_manifest(&[
        artifact(ArtifactKind::Hello, "build/hello", b"hello"),
        artifact(ArtifactKind::Init0, "target/init0", b"init0"),
    ])
    .unwrap();
    let entries = manifest.entries();

    assert_eq!(entries[0].archive_path, HELLO_ARCHIVE_PATH);
    assert_eq!(entries[0].mode, ArchiveMode::ExecutableReadOnly);
    assert_eq!(entries[0].source_path, "build/hello");
    assert_eq!(entries[0].bytes, b"hello");
    assert_eq!(entries[1].archive_path, INIT0_ARCHIVE_PATH);
    assert_eq!(entries[1].mode, ArchiveMode::ExecutableReadOnly);
    assert_eq!(entries[1].source_path, "target/init0");
    assert_eq!(entries[1].bytes, b"init0");
}

#[test]
fn rejects_missing_duplicate_extra_and_empty_artifacts() {
    let err = build_manifest(&[artifact(ArtifactKind::Init0, "init0", b"x")]).unwrap_err();
    assert!(matches!(
        err,
        ManifestError::MissingArtifact {
            kind: ArtifactKind::Hello
        }
    ));

    let err = build_manifest(&[
        artifact(ArtifactKind::Init0, "init0-a", b"a"),
        artifact(ArtifactKind::Init0, "init0-b", b"b"),
        artifact(ArtifactKind::Hello, "hello", b"h"),
    ])
    .unwrap_err();
    assert!(matches!(err, ManifestError::DuplicateArtifact { .. }));

    let err = build_manifest(&[
        artifact(ArtifactKind::Init0, "init0", b"i"),
        artifact(ArtifactKind::Hello, "hello", b"h"),
        artifact(ArtifactKind::Other, "extra", b"x"),
    ])
    .unwrap_err();
    assert_eq!(err, ManifestError::ExtraArtifact);

    let err = build_manifest(&[
        artifact(ArtifactKind::Init0, "init0", b""),
        artifact(ArtifactKind::Hello, "hello", b"h"),
    ])
    .unwrap_err();
    assert!(matches!(err, ManifestError::EmptyPayload { .. }));
}

#[test]
fn rejects_absolute_traversal_and_noncanonical_source_paths() {
    for path in [
        "/init0",
        "../init0",
        "build/../init0",
        "build//init0",
        "build/./init0",
        "build\\init0",
    ] {
        let err = build_manifest(&[
            artifact(ArtifactKind::Init0, path, b"i"),
            artifact(ArtifactKind::Hello, "hello", b"h"),
        ])
        .unwrap_err();
        assert_eq!(err, ManifestError::InvalidSourcePath { path });
    }
}
