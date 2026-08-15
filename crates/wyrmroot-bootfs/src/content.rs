//! Source-neutral WYR0-C bootfs content manifest rules.
//!
//! This module describes the logical content contract only. It does not build
//! an archive, parse bootfs bytes, inspect ELF files, or provide placeholder
//! binaries. Future image tooling supplies the real artifact bytes here.

/// Canonical archive-internal path for the temporary init process.
pub const INIT0_ARCHIVE_PATH: &str = "system/init0";
/// Canonical archive-internal path for the WYR0 smoke process.
pub const HELLO_ARCHIVE_PATH: &str = "bin/hello";

/// The only artifacts admitted to the WYR0-C content manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactKind {
    Init0,
    Hello,
    Other,
}

/// A future build artifact supplied to the manifest rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputArtifact<'a> {
    pub kind: ArtifactKind,
    /// Host-side provenance label. It is not copied into the archive path.
    pub source_path: &'a str,
    pub bytes: &'a [u8],
}

/// Archive permission intent for a future deterministic builder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveMode {
    /// The entry may be executed but must not be writable by the guest.
    ExecutableReadOnly,
}

/// One deterministic archive entry planned by the content rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestEntry<'a> {
    pub archive_path: &'static str,
    pub mode: ArchiveMode,
    pub source_path: &'a str,
    pub bytes: &'a [u8],
}

/// Exactly the two WYR0-C entries, in canonical lexical archive order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentManifest<'a> {
    entries: [ManifestEntry<'a>; 2],
}

impl<'a> ContentManifest<'a> {
    pub fn entries(self) -> [ManifestEntry<'a>; 2] {
        self.entries
    }
}

/// Build the deterministic logical manifest from future artifact inputs.
pub fn build_manifest<'a>(
    inputs: &[InputArtifact<'a>],
) -> Result<ContentManifest<'a>, ManifestError<'a>> {
    let mut init0 = None;
    let mut hello = None;

    for input in inputs {
        validate_source_path(input.source_path)?;
        if input.bytes.is_empty() {
            return Err(ManifestError::EmptyPayload { kind: input.kind });
        }
        let entry = match input.kind {
            ArtifactKind::Init0 => ManifestEntry {
                archive_path: INIT0_ARCHIVE_PATH,
                mode: ArchiveMode::ExecutableReadOnly,
                source_path: input.source_path,
                bytes: input.bytes,
            },
            ArtifactKind::Hello => ManifestEntry {
                archive_path: HELLO_ARCHIVE_PATH,
                mode: ArchiveMode::ExecutableReadOnly,
                source_path: input.source_path,
                bytes: input.bytes,
            },
            ArtifactKind::Other => return Err(ManifestError::ExtraArtifact),
        };

        match input.kind {
            ArtifactKind::Init0 if init0.replace(entry).is_some() => {
                return Err(ManifestError::DuplicateArtifact { kind: input.kind });
            }
            ArtifactKind::Hello if hello.replace(entry).is_some() => {
                return Err(ManifestError::DuplicateArtifact { kind: input.kind });
            }
            ArtifactKind::Init0 | ArtifactKind::Hello | ArtifactKind::Other => {}
        }
    }

    let init0 = init0.ok_or(ManifestError::MissingArtifact {
        kind: ArtifactKind::Init0,
    })?;
    let hello = hello.ok_or(ManifestError::MissingArtifact {
        kind: ArtifactKind::Hello,
    })?;
    Ok(ContentManifest {
        entries: [hello, init0],
    })
}

fn validate_source_path<'a>(path: &'a str) -> Result<(), ManifestError<'a>> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains('\0')
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(ManifestError::InvalidSourcePath { path });
    }
    Ok(())
}

/// Fail-closed content-manifest errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestError<'a> {
    MissingArtifact { kind: ArtifactKind },
    DuplicateArtifact { kind: ArtifactKind },
    ExtraArtifact,
    EmptyPayload { kind: ArtifactKind },
    InvalidSourcePath { path: &'a str },
}
