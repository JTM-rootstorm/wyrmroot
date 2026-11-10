//! The product's bootfs archive.
//!
//! Callers supply the exact immutable bytes of every entry; the builder checks
//! the device manifest and launch policy against the identities the producer
//! computed, then emits the twelve entries in the existing `cpio newc`
//! format. Content admission for arbitrary archives stays in
//! [`crate::content`].

#![cfg(feature = "builder")]

extern crate alloc;

use alloc::vec::Vec;

use crate::{
    builder::{BuildError, Builder, FileMode},
    launch_policy::{
        JOB_V2_PROFILE_ID, LaunchPolicy, WYRMSH_PATH as POLICY_WYRMSH_PATH, WYRMSH_PROFILE_ID,
    },
};
use wyrmroot_device_proto::{Manifest as DeviceManifest, manifest::ContentIdentity};

pub use crate::paths::*;

/// Every entry of the product archive, plus the identities the producer
/// computed for the payloads the manifests name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Product<'a> {
    pub init: &'a [u8],
    pub registryd: &'a [u8],
    pub devmgr: &'a [u8],
    pub uart16550d: &'a [u8],
    pub consoled: &'a [u8],
    pub wyrmsh: &'a [u8],
    pub hello: &'a [u8],
    pub cpu_hog: &'a [u8],
    pub rrc_manifest: &'a [u8],
    pub device_manifest: &'a [u8],
    pub launch_policy: &'a [u8],
    /// Identity of `uart16550d`, which the device manifest's COM2 role must
    /// name. Bootfs does not parse WRRM (that crate depends on this one), so
    /// the producer supplies the identity it also wrote into WRRM.
    pub uart16550d_identity: [u8; 32],
    pub wyrmsh_identity: [u8; 32],
    pub hello_identity: [u8; 32],
    pub cpu_hog_identity: [u8; 32],
}

impl Product<'_> {
    fn entries(&self) -> [(&'static str, &[u8], FileMode); 12] {
        use FileMode::{Executable, ReadOnly};
        [
            (INIT_PATH, self.init, Executable),
            (REGISTRYD_PATH, self.registryd, Executable),
            (DEVMGR_PATH, self.devmgr, Executable),
            (UART16550D_PATH, self.uart16550d, Executable),
            (CONSOLED_PATH, self.consoled, Executable),
            (WYRMSH_PATH, self.wyrmsh, Executable),
            (HELLO_PATH, self.hello, Executable),
            (CPU_HOG_PATH, self.cpu_hog, Executable),
            (RRC_MANIFEST_PATH, self.rrc_manifest, ReadOnly),
            (MARKER_PATH, MARKER, ReadOnly),
            (DEVICE_MANIFEST_PATH, self.device_manifest, ReadOnly),
            (LAUNCH_POLICY_PATH, self.launch_policy, ReadOnly),
        ]
    }
}

/// Validates the product and builds its deterministic archive.
pub fn build(product: Product<'_>) -> Result<Vec<u8>, BuildError> {
    validate(&product)?;
    let mut builder = Builder::new();
    for (path, bytes, mode) in product.entries() {
        if bytes.is_empty() {
            return Err(BuildError::EmptyArtifact);
        }
        builder.add(path.as_bytes(), bytes, mode)?;
    }
    builder.build()
}

fn validate(product: &Product<'_>) -> Result<(), BuildError> {
    if product.uart16550d_identity == [0; 32] {
        return Err(BuildError::DriverIdentityMismatch);
    }
    DeviceManifest::parse(product.device_manifest)
        .map_err(|_| BuildError::InvalidDeviceManifest)?
        .match_com2(ContentIdentity(product.uart16550d_identity))
        .map_err(|error| match error {
            wyrmroot_device_proto::ManifestError::WrongContentIdentity => {
                BuildError::DriverIdentityMismatch
            }
            _ => BuildError::InvalidDeviceManifest,
        })?;

    if product.wyrmsh_identity == [0; 32]
        || product.hello_identity == [0; 32]
        || product.cpu_hog_identity == [0; 32]
    {
        return Err(BuildError::PayloadIdentityMismatch);
    }
    let policy =
        LaunchPolicy::parse(product.launch_policy).map_err(|_| BuildError::InvalidLaunchPolicy)?;
    if policy.len() != 3 {
        return Err(BuildError::InvalidLaunchPolicy);
    }
    let entry = |path| policy.find(path).ok_or(BuildError::InvalidLaunchPolicy);
    let (hello, cpu_hog, wyrmsh) = (
        entry(HELLO_PATH)?,
        entry(CPU_HOG_PATH)?,
        entry(POLICY_WYRMSH_PATH)?,
    );
    // The hog is the one admitted payload with the opposite stream shape:
    // `spawn` launches it with zero startup stream roles, so admitting it on
    // three streams would grant a background job the foreground contract.
    if hello.startup_abi != 2
        || hello.profile_id != JOB_V2_PROFILE_ID
        || hello.allow_no_streams
        || !hello.allow_three_streams
        || cpu_hog.startup_abi != 2
        || cpu_hog.profile_id != JOB_V2_PROFILE_ID
        || !cpu_hog.allow_no_streams
        || cpu_hog.allow_three_streams
        || wyrmsh.startup_abi != 2
        || wyrmsh.profile_id != WYRMSH_PROFILE_ID
        || wyrmsh.allow_no_streams
        || !wyrmsh.allow_three_streams
    {
        return Err(BuildError::InvalidLaunchPolicy);
    }
    if wyrmsh.content_sha256 != product.wyrmsh_identity
        || hello.content_sha256 != product.hello_identity
        || cpu_hog.content_sha256 != product.cpu_hog_identity
    {
        return Err(BuildError::PayloadIdentityMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::Archive;
    use crate::launch_policy::{LaunchPolicyEntry, encode};
    use alloc::vec;

    const UART: [u8; 32] = [0xa1; 32];
    const SHELL: [u8; 32] = [0xf1; 32];
    const HELLO: [u8; 32] = [0xf2; 32];
    const HOG: [u8; 32] = [0xf3; 32];

    fn wrdm(identity: [u8; 32]) -> [u8; 176] {
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

    fn policy(hog_three_streams: bool, include_hog: bool) -> Vec<u8> {
        let hog = LaunchPolicyEntry {
            path: CPU_HOG_PATH,
            content_sha256: HOG,
            startup_abi: 2,
            profile_id: JOB_V2_PROFILE_ID,
            allow_no_streams: !hog_three_streams,
            allow_three_streams: hog_three_streams,
        };
        let hello = LaunchPolicyEntry {
            path: HELLO_PATH,
            content_sha256: HELLO,
            startup_abi: 2,
            profile_id: JOB_V2_PROFILE_ID,
            allow_no_streams: false,
            allow_three_streams: true,
        };
        let shell = LaunchPolicyEntry {
            path: WYRMSH_PATH,
            content_sha256: SHELL,
            startup_abi: 2,
            profile_id: WYRMSH_PROFILE_ID,
            allow_no_streams: false,
            allow_three_streams: true,
        };
        let mut output = vec![0; 512];
        let used = if include_hog {
            encode([0x42; 32], &[hog, hello, shell], &mut output)
        } else {
            encode([0x42; 32], &[hello, shell], &mut output)
        }
        .unwrap();
        output.truncate(used);
        output
    }

    fn product<'a>(device_manifest: &'a [u8], launch_policy: &'a [u8]) -> Product<'a> {
        Product {
            init: b"init",
            registryd: b"registry",
            devmgr: b"devmgr",
            uart16550d: b"uart",
            consoled: b"console",
            wyrmsh: b"shell",
            hello: b"hello-elf",
            cpu_hog: b"cpu-hog-elf",
            rrc_manifest: b"WRRM",
            device_manifest,
            launch_policy,
            uart16550d_identity: UART,
            wyrmsh_identity: SHELL,
            hello_identity: HELLO,
            cpu_hog_identity: HOG,
        }
    }

    #[test]
    fn builds_the_twelve_entry_product_deterministically() {
        let manifest = wrdm(UART);
        let policy = policy(false, true);
        let product = product(&manifest, &policy);
        let first = build(product).unwrap();
        assert_eq!(first, build(product).unwrap());
        let archive = Archive::new(&first).unwrap();
        let names: Vec<_> = archive.entries().map(|entry| entry.name()).collect();
        assert_eq!(
            names,
            vec![
                b"bin/cpu-hog".as_slice(),
                b"bin/hello".as_slice(),
                b"system/bootstrap/device-manifest-v1".as_slice(),
                b"system/bootstrap/launch-policy-v1".as_slice(),
                b"system/bootstrap/product-v1".as_slice(),
                b"system/bootstrap/rrc-a-v1".as_slice(),
                b"system/consoled".as_slice(),
                b"system/devmgr".as_slice(),
                b"system/init".as_slice(),
                b"system/registryd".as_slice(),
                b"system/uart16550d".as_slice(),
                b"system/wyrmsh".as_slice(),
            ]
        );
        assert_eq!(
            archive
                .entries()
                .filter(|entry| entry.is_executable())
                .count(),
            8
        );
        assert_eq!(
            archive.lookup(MARKER_PATH.as_bytes()).unwrap().data(),
            MARKER
        );
        assert_eq!(
            archive
                .lookup(DEVICE_MANIFEST_PATH.as_bytes())
                .unwrap()
                .data(),
            manifest
        );
    }

    #[test]
    fn refuses_a_malformed_or_mismatched_device_manifest() {
        let policy = policy(false, true);
        let mut malformed = wrdm(UART);
        malformed[..4].copy_from_slice(b"BAD!");
        assert_eq!(
            build(product(&malformed, &policy)),
            Err(BuildError::InvalidDeviceManifest)
        );
        let mut wrong_port = wrdm(UART);
        wrong_port[32 + 16..32 + 18].copy_from_slice(&0x3f8u16.to_le_bytes());
        assert_eq!(
            build(product(&wrong_port, &policy)),
            Err(BuildError::InvalidDeviceManifest)
        );
        let manifest = wrdm(UART);
        let mut other = product(&manifest, &policy);
        other.uart16550d_identity = [0xa2; 32];
        assert_eq!(build(other), Err(BuildError::DriverIdentityMismatch));
        other.uart16550d_identity = [0; 32];
        assert_eq!(build(other), Err(BuildError::DriverIdentityMismatch));
    }

    #[test]
    fn refuses_a_hog_on_three_streams_or_a_policy_without_it() {
        let manifest = wrdm(UART);
        for bad in [policy(true, true), policy(false, false)] {
            assert_eq!(
                build(product(&manifest, &bad)),
                Err(BuildError::InvalidLaunchPolicy)
            );
        }
    }

    #[test]
    fn binds_every_admitted_payload_to_its_own_identity() {
        let manifest = wrdm(UART);
        let policy = policy(false, true);
        for field in 0..3 {
            let mut changed = product(&manifest, &policy);
            match field {
                0 => changed.cpu_hog_identity = [0x99; 32],
                1 => changed.hello_identity = [0x99; 32],
                _ => changed.wyrmsh_identity = [0x99; 32],
            }
            assert_eq!(build(changed), Err(BuildError::PayloadIdentityMismatch));
        }
        let mut empty = product(&manifest, &policy);
        empty.cpu_hog = b"";
        assert_eq!(build(empty), Err(BuildError::EmptyArtifact));
    }
}
