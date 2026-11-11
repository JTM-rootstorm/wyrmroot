//! The product's bootfs archive.
//!
//! Callers supply the exact immutable bytes of every entry; the builder checks
//! the device manifest and launch policy against the identities the producer
//! computed, then emits the sixteen entries in the existing `cpio newc`
//! format. Content admission for arbitrary archives stays in
//! [`crate::content`].

#![cfg(feature = "builder")]

extern crate alloc;

use alloc::vec::Vec;

use crate::{
    builder::{BuildError, Builder, FileMode},
    launch_policy::{
        JOB_V2_PROFILE_ID, LaunchPolicy, SERVICE_ROLE_PROFILE_ID,
        WYRMSH_PATH as POLICY_WYRMSH_PATH, WYRMSH_PROFILE_ID,
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
    pub virtio_blkd: &'a [u8],
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
    /// Identity of `virtio-blkd`, which the boot-disk role must name.
    pub virtio_blkd_identity: [u8; 32],
    pub wyrmsh_identity: [u8; 32],
    pub hello_identity: [u8; 32],
    pub cpu_hog_identity: [u8; 32],
    /// The storage service roles, in [`SERVICE_ROLE_PATHS`] order, each with
    /// the identity its launch-policy entry must name.
    pub services: [ServiceArtifact<'a>; 4],
}

/// One service role's executable and identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceArtifact<'a> {
    pub bytes: &'a [u8],
    pub identity: [u8; 32],
}

impl Product<'_> {
    fn entries(&self) -> [(&'static str, &[u8], FileMode); 17] {
        use FileMode::{Executable, ReadOnly};
        [
            (INIT_PATH, self.init, Executable),
            (REGISTRYD_PATH, self.registryd, Executable),
            (DEVMGR_PATH, self.devmgr, Executable),
            (UART16550D_PATH, self.uart16550d, Executable),
            (VIRTIO_BLKD_PATH, self.virtio_blkd, Executable),
            (CONSOLED_PATH, self.consoled, Executable),
            (WYRMSH_PATH, self.wyrmsh, Executable),
            (HELLO_PATH, self.hello, Executable),
            (CPU_HOG_PATH, self.cpu_hog, Executable),
            (RRC_MANIFEST_PATH, self.rrc_manifest, ReadOnly),
            (MARKER_PATH, MARKER, ReadOnly),
            (DEVICE_MANIFEST_PATH, self.device_manifest, ReadOnly),
            (LAUNCH_POLICY_PATH, self.launch_policy, ReadOnly),
            (BLOCKMGR_PATH, self.services[0].bytes, Executable),
            (FAT32D_PATH, self.services[1].bytes, Executable),
            (EXT4D_PATH, self.services[2].bytes, Executable),
            (VFSD_PATH, self.services[3].bytes, Executable),
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
    if product.uart16550d_identity == [0; 32] || product.virtio_blkd_identity == [0; 32] {
        return Err(BuildError::DriverIdentityMismatch);
    }
    let manifest_error = |error| match error {
        wyrmroot_device_proto::ManifestError::WrongContentIdentity => {
            BuildError::DriverIdentityMismatch
        }
        _ => BuildError::InvalidDeviceManifest,
    };
    let manifest = DeviceManifest::parse(product.device_manifest)
        .map_err(|_| BuildError::InvalidDeviceManifest)?;
    manifest
        .match_com2(ContentIdentity(product.uart16550d_identity))
        .map_err(manifest_error)?;
    for disk in &wyrmroot_device_proto::manifest::DISK_POLICIES {
        manifest
            .match_disk(disk, ContentIdentity(product.virtio_blkd_identity))
            .map_err(manifest_error)?;
    }

    if product.wyrmsh_identity == [0; 32]
        || product.hello_identity == [0; 32]
        || product.cpu_hog_identity == [0; 32]
    {
        return Err(BuildError::PayloadIdentityMismatch);
    }
    let policy =
        LaunchPolicy::parse(product.launch_policy).map_err(|_| BuildError::InvalidLaunchPolicy)?;
    if policy.len() != 3 + SERVICE_ROLE_PATHS.len() {
        return Err(BuildError::InvalidLaunchPolicy);
    }
    for (path, service) in SERVICE_ROLE_PATHS.into_iter().zip(product.services) {
        let entry = policy.find(path).ok_or(BuildError::InvalidLaunchPolicy)?;
        if entry.profile_id != SERVICE_ROLE_PROFILE_ID {
            return Err(BuildError::InvalidLaunchPolicy);
        }
        if service.identity == [0; 32] || entry.content_sha256 != service.identity {
            return Err(BuildError::PayloadIdentityMismatch);
        }
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

    const BLOCK: [u8; 32] = [0xb1; 32];
    const SERVICES: [[u8; 32]; 4] = [[0xc1; 32], [0xc2; 32], [0xc3; 32], [0xc4; 32]];
    const WRDM_BYTES: usize = 32 + 3 * 144;

    fn wrdm(identity: [u8; 32]) -> [u8; WRDM_BYTES] {
        let mut bytes = [0u8; WRDM_BYTES];
        wyrmroot_device_proto::encode_product_manifest(
            ContentIdentity(identity),
            ContentIdentity(BLOCK),
            &mut bytes,
        )
        .unwrap();
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
        let service = |path, identity| LaunchPolicyEntry {
            path,
            content_sha256: identity,
            startup_abi: 1,
            profile_id: SERVICE_ROLE_PROFILE_ID,
            allow_no_streams: true,
            allow_three_streams: false,
        };
        let services = [
            service(BLOCKMGR_PATH, SERVICES[0]),
            service(FAT32D_PATH, SERVICES[1]),
            service(EXT4D_PATH, SERVICES[2]),
            service(VFSD_PATH, SERVICES[3]),
        ];
        let mut entries = vec![];
        if include_hog {
            entries.push(hog);
        }
        // Canonical path order: blockmgr, ext4d, fat32d, vfsd.
        entries.extend([
            hello,
            services[0],
            services[2],
            services[1],
            services[3],
            shell,
        ]);
        let mut output = vec![0; 1024];
        let used = encode([0x42; 32], &entries, &mut output).unwrap();
        output.truncate(used);
        output
    }

    fn product<'a>(device_manifest: &'a [u8], launch_policy: &'a [u8]) -> Product<'a> {
        Product {
            init: b"init",
            registryd: b"registry",
            devmgr: b"devmgr",
            uart16550d: b"uart",
            virtio_blkd: b"blk",
            consoled: b"console",
            wyrmsh: b"shell",
            hello: b"hello-elf",
            cpu_hog: b"cpu-hog-elf",
            rrc_manifest: b"WRRM",
            device_manifest,
            launch_policy,
            uart16550d_identity: UART,
            virtio_blkd_identity: BLOCK,
            wyrmsh_identity: SHELL,
            hello_identity: HELLO,
            cpu_hog_identity: HOG,
            services: [
                ServiceArtifact {
                    bytes: b"blockmgr-elf",
                    identity: SERVICES[0],
                },
                ServiceArtifact {
                    bytes: b"fat32d-elf",
                    identity: SERVICES[1],
                },
                ServiceArtifact {
                    bytes: b"ext4d-elf",
                    identity: SERVICES[2],
                },
                ServiceArtifact {
                    bytes: b"vfsd-elf",
                    identity: SERVICES[3],
                },
            ],
        }
    }

    #[test]
    fn builds_the_seventeen_entry_product_deterministically() {
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
                b"system/blockmgr".as_slice(),
                b"system/bootstrap/device-manifest-v1".as_slice(),
                b"system/bootstrap/launch-policy-v1".as_slice(),
                b"system/bootstrap/product-v1".as_slice(),
                b"system/bootstrap/rrc-a-v1".as_slice(),
                b"system/consoled".as_slice(),
                b"system/devmgr".as_slice(),
                b"system/ext4d".as_slice(),
                b"system/fat32d".as_slice(),
                b"system/init".as_slice(),
                b"system/registryd".as_slice(),
                b"system/uart16550d".as_slice(),
                b"system/vfsd".as_slice(),
                b"system/virtio-blkd".as_slice(),
                b"system/wyrmsh".as_slice(),
            ]
        );
        assert_eq!(
            archive
                .entries()
                .filter(|entry| entry.is_executable())
                .count(),
            13
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
        let mut other = product(&manifest, &policy);
        other.virtio_blkd_identity = [0xb2; 32];
        assert_eq!(build(other), Err(BuildError::DriverIdentityMismatch));
        // A manifest without the boot disk is not this product.
        let mut com2_only = [0u8; 176];
        wyrmroot_device_proto::encode_com2_manifest(ContentIdentity(UART), &mut com2_only).unwrap();
        assert_eq!(
            build(product(&com2_only, &policy)),
            Err(BuildError::InvalidDeviceManifest)
        );
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
        for service in 0..3 {
            let mut changed = product(&manifest, &policy);
            changed.services[service].identity = [0x99; 32];
            assert_eq!(build(changed), Err(BuildError::PayloadIdentityMismatch));
        }
    }
}
