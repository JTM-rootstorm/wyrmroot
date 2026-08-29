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
use wyrmroot_device_proto::{Manifest as DeviceManifest, manifest::ContentIdentity};

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
/// Distinct WYR1-C product marker. This is deliberately separate from the
/// retained WYR1-A gate and WYR1-B gate entries.
pub const WYR1_C_MARKER_PATH: &str = "system/bootstrap/wyr1-c-gate-v1";
/// Fixed immutable WRDM v1 entry consumed by the resident device coordinator.
pub const WYR1_C_DEVICE_MANIFEST_PATH: &str = "system/bootstrap/wyr1-c-device-manifest-v1";
/// Short aliases for callers that name the two C1 product-surface entries by
/// their protocol/product role.
pub const WYR1_C_GATE_PATH: &str = WYR1_C_MARKER_PATH;
pub const WRDM_PATH: &str = WYR1_C_DEVICE_MANIFEST_PATH;
/// Exact, fixed content of the WYR1-C1 product marker entry.
pub const WYR1_C1_MARKER: &[u8] = b"WYR1-C1";
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

/// Exact WYR1-C1 product inputs. The base retains the complete WYR1-A
/// closure; the marker identifies this product generation and the final
/// read-only entry is the canonical WRDM v1 device-role manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductC1<'a> {
    pub base: Product<'a>,
    pub marker: &'a [u8],
    pub device_manifest: &'a [u8],
    /// Independently supplied content identity of `system/uart16550d`.
    ///
    /// The product producer derives this from the same immutable artifact
    /// identity used in the WRRM role record.  `build_c1` deliberately does
    /// not parse WRRM: `wyrmroot-rrc-manifest` already owns that format and
    /// depends on this crate for archive paths, so making bootfs parse WRRM
    /// would create a dependency cycle.  This value is the bounded, explicit
    /// cross-bind between the canonical WRDM role and that producer-owned
    /// WRRM validation.
    pub expected_uart16550d_identity: [u8; 32],
}

impl<'a> ProductC1<'a> {
    pub fn artifacts(self) -> [Artifact<'a>; 10] {
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
            Artifact::read_only(WYR1_C_MARKER_PATH, self.marker),
            Artifact::read_only(WYR1_C_DEVICE_MANIFEST_PATH, self.device_manifest),
        ]
    }
}

/// Build the deterministic WYR1-C1 archive.
///
/// This admits only the exact product marker and a structurally valid,
/// canonical q35 COM2 WRDM role whose driver identity equals the independently
/// supplied UART artifact identity.  Exact WRRM structural/profile validation
/// remains owned by the RRC manifest product producer; see
/// [`ProductC1::expected_uart16550d_identity`].
pub fn build_c1(product: ProductC1<'_>) -> Result<Vec<u8>, BuildError> {
    validate_c1_product(product)?;
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

fn validate_c1_product(product: ProductC1<'_>) -> Result<(), BuildError> {
    if product.marker != WYR1_C1_MARKER {
        return Err(BuildError::WrongC1Marker);
    }
    if product
        .expected_uart16550d_identity
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err(BuildError::C1DriverIdentityMismatch);
    }
    let manifest = DeviceManifest::parse(product.device_manifest)
        .map_err(|_| BuildError::InvalidC1DeviceManifest)?;
    manifest
        .match_com2(ContentIdentity(product.expected_uart16550d_identity))
        .map_err(|error| match error {
            wyrmroot_device_proto::ManifestError::WrongContentIdentity => {
                BuildError::C1DriverIdentityMismatch
            }
            _ => BuildError::InvalidC1DeviceManifest,
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::Archive;
    use alloc::vec;

    const UART_IDENTITY: [u8; 32] = [0xa1; 32];

    fn c1_base() -> Product<'static> {
        Product {
            init: b"init",
            registryd: b"registry",
            devmgr: b"devmgr",
            uart16550d: b"uart",
            consoled: b"console",
            wyrmsh: b"shell",
            rrc_manifest: b"WRRM",
            gate_config: b"a",
        }
    }

    fn canonical_wrdm(identity: [u8; 32]) -> [u8; 176] {
        let mut bytes = [0u8; 176];
        bytes[..4].copy_from_slice(b"WRDM");
        bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
        bytes[8..12].copy_from_slice(&176u32.to_le_bytes());
        bytes[12..14].copy_from_slice(&1u16.to_le_bytes());
        bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        let record = 32;
        bytes[record..record + 8].copy_from_slice(&1u64.to_le_bytes());
        bytes[record + 8..record + 12].copy_from_slice(&2u32.to_le_bytes());
        bytes[record + 12..record + 16].copy_from_slice(&1u32.to_le_bytes());
        bytes[record + 16..record + 18].copy_from_slice(&0x2f8u16.to_le_bytes());
        bytes[record + 18..record + 20].copy_from_slice(&8u16.to_le_bytes());
        bytes[record + 20..record + 24].copy_from_slice(&3u32.to_le_bytes());
        bytes[record + 24..record + 26]
            .copy_from_slice(&(b"system/uart16550d".len() as u16).to_le_bytes());
        bytes[record + 28..record + 60].copy_from_slice(&identity);
        bytes[record + 60..record + 64].copy_from_slice(&1u32.to_le_bytes());
        bytes[record + 72..record + 72 + b"system/uart16550d".len()]
            .copy_from_slice(b"system/uart16550d");
        bytes
    }

    fn c1_product<'a>(
        marker: &'a [u8],
        device_manifest: &'a [u8],
        expected_uart16550d_identity: [u8; 32],
    ) -> ProductC1<'a> {
        ProductC1 {
            base: c1_base(),
            marker,
            device_manifest,
            expected_uart16550d_identity,
        }
    }

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

    #[test]
    fn wyr1_c1_is_deterministic_and_retains_old_closure() {
        let device_manifest = canonical_wrdm(UART_IDENTITY);
        let product = c1_product(WYR1_C1_MARKER, &device_manifest, UART_IDENTITY);
        let first = build_c1(product).unwrap();
        assert_eq!(first, build_c1(product).unwrap());
        let archive = Archive::new(&first).unwrap();
        let names: Vec<_> = archive.entries().map(|entry| entry.name()).collect();
        assert_eq!(
            names,
            vec![
                b"system/bootstrap/rrc-a-v1".as_slice(),
                b"system/bootstrap/wyr1-a-gate-v1".as_slice(),
                b"system/bootstrap/wyr1-c-device-manifest-v1".as_slice(),
                b"system/bootstrap/wyr1-c-gate-v1".as_slice(),
                b"system/consoled".as_slice(),
                b"system/devmgr".as_slice(),
                b"system/init".as_slice(),
                b"system/registryd".as_slice(),
                b"system/uart16550d".as_slice(),
                b"system/wyrmsh".as_slice(),
            ]
        );
        assert!(
            !archive
                .lookup(WYR1_C_MARKER_PATH.as_bytes())
                .unwrap()
                .is_executable()
        );
        assert_eq!(
            archive
                .lookup(WYR1_C_DEVICE_MANIFEST_PATH.as_bytes())
                .unwrap()
                .data(),
            device_manifest
        );
    }

    #[test]
    fn wyr1_c1_rejects_wrong_marker_malformed_wrdm_policy_and_driver_identity() {
        let device_manifest = canonical_wrdm(UART_IDENTITY);
        assert_eq!(
            build_c1(c1_product(b"WYR1-C0", &device_manifest, UART_IDENTITY)),
            Err(BuildError::WrongC1Marker)
        );
        let mut malformed = device_manifest;
        malformed[..4].copy_from_slice(b"BAD!");
        assert_eq!(
            build_c1(c1_product(WYR1_C1_MARKER, &malformed, UART_IDENTITY)),
            Err(BuildError::InvalidC1DeviceManifest)
        );
        let mut wrong_policy = device_manifest;
        wrong_policy[32 + 16..32 + 18].copy_from_slice(&0x3f8u16.to_le_bytes());
        assert_eq!(
            build_c1(c1_product(WYR1_C1_MARKER, &wrong_policy, UART_IDENTITY)),
            Err(BuildError::InvalidC1DeviceManifest)
        );
        assert_eq!(
            build_c1(c1_product(WYR1_C1_MARKER, &device_manifest, [0xa2; 32])),
            Err(BuildError::C1DriverIdentityMismatch)
        );
        assert_eq!(
            build_c1(c1_product(WYR1_C1_MARKER, &device_manifest, [0; 32])),
            Err(BuildError::C1DriverIdentityMismatch)
        );
    }
}
