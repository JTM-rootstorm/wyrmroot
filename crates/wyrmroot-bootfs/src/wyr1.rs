//! Deterministic WYR1-A bootfs product construction.
//!
//! WYR0 content admission remains in [`crate::content`].  This module is a
//! separate, fixed product surface: callers provide the exact immutable bytes
//! selected by the integration request and the builder emits the seven
//! canonical WYR1 entries in the existing `cpio newc` format.

#![cfg(feature = "builder")]

extern crate alloc;

use alloc::vec::Vec;

use crate::builder::{BuildError, Builder, FileMode};

/// Permanent supervisor executable.
pub const INIT_PATH: &str = "system/init";
pub const REGISTRYD_PATH: &str = "system/registryd";
pub const DEVMGR_PATH: &str = "system/devmgr";
/// Retained immutable UART source; WYR1-A does not activate it.
pub const UART16550D_PATH: &str = "system/uart16550d";
pub const CONSOLED_PATH: &str = "system/consoled";
pub const WYRMSH_PATH: &str = "system/wyrmsh";
pub const RRC_MANIFEST_PATH: &str = "system/bootstrap/rrc-a-v1";

/// Canonical WYR1-A role paths, in product order.
pub const ROLE_PATHS: [&str; 5] = [
    REGISTRYD_PATH,
    DEVMGR_PATH,
    UART16550D_PATH,
    CONSOLED_PATH,
    WYRMSH_PATH,
];

/// One explicitly supplied immutable WYR1 artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Artifact<'a> {
    pub path: &'static str,
    pub bytes: &'a [u8],
    pub executable: bool,
}

impl<'a> Artifact<'a> {
    pub const fn executable(path: &'static str, bytes: &'a [u8]) -> Self {
        Self {
            path,
            bytes,
            executable: true,
        }
    }

    pub const fn read_only(path: &'static str, bytes: &'a [u8]) -> Self {
        Self {
            path,
            bytes,
            executable: false,
        }
    }
}

/// Exact seven-entry WYR1-A bootfs input.  Artifact hashes are intentionally
/// computed by the host receipt layer over these same byte slices; this crate
/// never derives identity from host metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Product<'a> {
    pub init: &'a [u8],
    pub registryd: &'a [u8],
    pub devmgr: &'a [u8],
    pub uart16550d: &'a [u8],
    pub consoled: &'a [u8],
    pub wyrmsh: &'a [u8],
    pub rrc_manifest: &'a [u8],
}

impl<'a> Product<'a> {
    pub const fn artifacts(self) -> [Artifact<'a>; 7] {
        [
            Artifact::executable(INIT_PATH, self.init),
            Artifact::executable(REGISTRYD_PATH, self.registryd),
            Artifact::executable(DEVMGR_PATH, self.devmgr),
            Artifact::executable(UART16550D_PATH, self.uart16550d),
            Artifact::executable(CONSOLED_PATH, self.consoled),
            Artifact::executable(WYRMSH_PATH, self.wyrmsh),
            Artifact::read_only(RRC_MANIFEST_PATH, self.rrc_manifest),
        ]
    }
}

/// Build the exact WYR1 product archive.  The existing builder sorts paths,
/// fixes metadata, and rejects duplicate/invalid entries, so WYR0 archive
/// bytes and limits remain unchanged.
pub fn build(product: Product<'_>) -> Result<Vec<u8>, BuildError> {
    let mut builder = Builder::new();
    for artifact in product.artifacts() {
        if artifact.bytes.is_empty() {
            return Err(BuildError::EmptyArtifact);
        }
        builder.add(
            artifact.path.as_bytes(),
            artifact.bytes,
            if artifact.executable {
                FileMode::Executable
            } else {
                FileMode::ReadOnly
            },
        )?;
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::Archive;
    use alloc::vec;

    #[test]
    fn product_is_deterministic_and_has_exact_paths() {
        let product = Product {
            init: b"init",
            registryd: b"registry",
            devmgr: b"devmgr",
            uart16550d: b"uart",
            consoled: b"console",
            wyrmsh: b"shell",
            rrc_manifest: b"WRRM",
        };
        let first = build(product).unwrap();
        let second = build(product).unwrap();
        assert_eq!(first, second);
        let archive = Archive::new(&first).unwrap();
        let names: Vec<_> = archive.entries().map(|entry| entry.name()).collect();
        assert_eq!(
            names,
            vec![
                b"system/bootstrap/rrc-a-v1".as_slice(),
                b"system/consoled".as_slice(),
                b"system/devmgr".as_slice(),
                b"system/init".as_slice(),
                b"system/registryd".as_slice(),
                b"system/uart16550d".as_slice(),
                b"system/wyrmsh".as_slice(),
            ]
        );
    }
}
