//! Deterministic WYR1-A bootfs product construction.
//!
//! WYR0 content admission remains in [`crate::content`].  This module is a
//! separate, fixed product surface: callers provide the exact immutable bytes
//! selected by the integration request and the builder emits the eight
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
pub const GATE_CONFIG_PATH: &str = "system/bootstrap/wyr1-a-gate-v1";
pub const LAUNCH_POLICY_PATH: &str = "system/bootstrap/launch-policy-v1";
pub const WYR1_B_GATE_PATH: &str = "system/bootstrap/wyr1-b-gate-v1";
pub const HELLO_PATH: &str = "bin/hello";
pub const WYR1_B_PUBLISHER_PATH: &str = "test/wyr1-b/publisher";
pub const WYR1_B_CLIENT_PATH: &str = "test/wyr1-b/client";

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

/// Exact eight-entry WYR1-A bootfs input.  Artifact hashes are intentionally
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
    pub gate_config: &'a [u8],
}

impl<'a> Product<'a> {
    pub const fn artifacts(self) -> [Artifact<'a>; 8] {
        [
            Artifact::executable(INIT_PATH, self.init),
            Artifact::executable(REGISTRYD_PATH, self.registryd),
            Artifact::executable(DEVMGR_PATH, self.devmgr),
            Artifact::executable(UART16550D_PATH, self.uart16550d),
            Artifact::executable(CONSOLED_PATH, self.consoled),
            Artifact::executable(WYRMSH_PATH, self.wyrmsh),
            Artifact::read_only(RRC_MANIFEST_PATH, self.rrc_manifest),
            Artifact::read_only(GATE_CONFIG_PATH, self.gate_config),
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

/// Exact WYR1-B product inputs. Gate publisher/client binaries are explicit
/// test content and do not enter the RRC-A manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductB<'a> {
    pub base: Product<'a>,
    pub launch_policy: &'a [u8],
    pub gate_config: &'a [u8],
    pub hello: &'a [u8],
    pub publisher: &'a [u8],
    pub client: &'a [u8],
}

impl<'a> ProductB<'a> {
    pub fn artifacts(self) -> [Artifact<'a>; 13] {
        let base = self.base.artifacts();
        [
            base[0],
            base[1],
            base[2],
            base[3],
            base[4],
            base[5],
            base[6],
            base[7],
            Artifact::read_only(LAUNCH_POLICY_PATH, self.launch_policy),
            Artifact::read_only(WYR1_B_GATE_PATH, self.gate_config),
            Artifact::executable(HELLO_PATH, self.hello),
            Artifact::executable(WYR1_B_PUBLISHER_PATH, self.publisher),
            Artifact::executable(WYR1_B_CLIENT_PATH, self.client),
        ]
    }
}

pub fn build_b(product: ProductB<'_>) -> Result<Vec<u8>, BuildError> {
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
            gate_config: b"config",
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
                b"system/bootstrap/wyr1-a-gate-v1".as_slice(),
                b"system/consoled".as_slice(),
                b"system/devmgr".as_slice(),
                b"system/init".as_slice(),
                b"system/registryd".as_slice(),
                b"system/uart16550d".as_slice(),
                b"system/wyrmsh".as_slice(),
            ]
        );
    }

    #[test]
    fn wyr1_b_adds_policy_hello_and_independent_gate_processes() {
        let base = Product {
            init: b"init",
            registryd: b"registry",
            devmgr: b"devmgr",
            uart16550d: b"uart",
            consoled: b"console",
            wyrmsh: b"shell",
            rrc_manifest: b"WRRM",
            gate_config: b"a",
        };
        let bytes = build_b(ProductB {
            base,
            launch_policy: b"WRJP",
            gate_config: b"b",
            hello: b"hello",
            publisher: b"publisher",
            client: b"client",
        })
        .unwrap();
        let archive = Archive::new(&bytes).unwrap();
        for path in [
            LAUNCH_POLICY_PATH,
            WYR1_B_GATE_PATH,
            HELLO_PATH,
            WYR1_B_PUBLISHER_PATH,
            WYR1_B_CLIENT_PATH,
        ] {
            assert!(archive.lookup(path.as_bytes()).is_ok());
        }
        assert!(
            !archive
                .lookup(LAUNCH_POLICY_PATH.as_bytes())
                .unwrap()
                .is_executable()
        );
        assert!(
            archive
                .lookup(HELLO_PATH.as_bytes())
                .unwrap()
                .is_executable()
        );
    }
}
