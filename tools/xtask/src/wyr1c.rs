//! Unnumbered, host-only WYR1-C1 product construction.
//!
//! This producer deliberately stops at immutable native artifacts, WRRM,
//! WRDM, bootfs, and a source/toolchain-bound receipt. It does not allocate a
//! guest selector, construct an ESP, or invoke QEMU/libvirt.

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{error::Failure, metadata::BuildManifest, sha256};
use wyrmroot_bootfs::{
    archive::Archive,
    wyr1::{Product, ProductC1, WYR1_C1_MARKER, build_c1},
};
use wyrmroot_device_proto::manifest::{
    ContentIdentity, HEADER_BYTES as WRDM_HEADER_BYTES, RECORD_BYTES as WRDM_RECORD_BYTES,
    encode_com2_manifest,
};
use wyrmroot_rrc_manifest::{Manifest, RoleId, StartupProfile};

const PRODUCT_KIND: &str = "wyrmroot-wyr1-c1-host-product";
const RECEIPT_KIND: &str = "wyrmroot-wyr1-c1-host-product-receipt";
const SCHEMA_VERSION: u32 = 1;
const ACCEPTED_RUST_REVISION: &str = "a92dc7f7464ad6ddfece4402bd7b86dbfa86166d";
const ACCEPTED_TOOLCHAIN_NAME: &str = "wyrmroot-1.97.1-a92dc7f7";
const NATIVE_TARGET: &str = "x86_64-unknown-wyrmroot";
const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
const MAX_BOOTFS_BYTES: usize = crate::g3_image::IMAGE_BYTES as usize;
const MAX_REPORT_BYTES: usize = 64 * 1024;
const O_NOFOLLOW: i32 = 0o400000;
const INSPECTION_PATH: &str = "/usr/lib/llvm/22/bin:/usr/bin:/bin";
const GATE_CONFIG: &[u8] =
    b"schema = 1\nproduct = \"wyr1-c1-host-only\"\nselector = \"none\"\nevidence = \"not-produced\"\n";

#[derive(Clone, Copy)]
struct NativeSpec {
    label: &'static str,
    package: &'static str,
    binary: &'static str,
    features: &'static str,
    artifact: &'static str,
}

const NATIVE_SPECS: [NativeSpec; 6] = [
    NativeSpec {
        label: "system-init",
        package: "wyrmroot-system-init",
        binary: "system-init",
        features: "native-init",
        artifact: "system-init",
    },
    NativeSpec {
        label: "registryd",
        package: "wyrmroot-registryd",
        binary: "registryd",
        features: "native-registryd",
        artifact: "registryd",
    },
    NativeSpec {
        label: "devmgr",
        package: "wyrmroot-devmgr",
        binary: "devmgr",
        features: "native-devmgr",
        artifact: "devmgr",
    },
    NativeSpec {
        label: "uart16550d",
        package: "wyrmroot-wyr1-retained-stubs",
        binary: "uart16550d",
        features: "native-retained",
        artifact: "uart16550d",
    },
    NativeSpec {
        label: "consoled",
        package: "wyrmroot-wyr1-retained-stubs",
        binary: "consoled",
        features: "native-retained",
        artifact: "consoled",
    },
    NativeSpec {
        label: "wyrmsh",
        package: "wyrmroot-wyr1-retained-stubs",
        binary: "wyrmsh",
        features: "native-retained",
        artifact: "wyrmsh",
    },
];

struct NativeArtifact {
    spec: NativeSpec,
    bytes: Vec<u8>,
    sha256: String,
    inspection: String,
}

pub(crate) struct FrozenSnapshot {
    pub(crate) receipt: Vec<u8>,
    pub(crate) rrc_manifest: Vec<u8>,
    pub(crate) device_manifest: Vec<u8>,
    pub(crate) bootfs: Vec<u8>,
    pub(crate) artifacts: BTreeMap<String, Vec<u8>>,
    pub(crate) inspections: BTreeMap<String, Vec<u8>>,
}

pub(crate) struct ValidatedFrozenProduct {
    pub(crate) wyrmroot_revision: String,
}

pub(crate) struct BuiltFrozenProduct {
    pub(crate) snapshot: FrozenSnapshot,
    pub(crate) validated: ValidatedFrozenProduct,
}

pub(crate) fn product(output: &Path) -> Result<String, Failure> {
    reject_ambient_build_environment(env::vars_os())?;
    let repository = crate::tasks::repository_root()?;
    let project = repository
        .ancestors()
        .find(|path| path.ends_with("OS-Project"))
        .ok_or_else(|| Failure::task("WYR1-C1 source is not beneath OS-Project"))?
        .to_path_buf();
    let output = validate_fresh_output(&repository, &project, output)?;
    let parent_path = output
        .parent()
        .ok_or_else(|| Failure::task("WYR1-C1 output has no parent"))?;
    let name = output
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| Failure::task("WYR1-C1 output name is not UTF-8"))?;
    let parent = crate::secure_fs::Directory::open_exact(parent_path, "WYR1-C1 output parent")?;
    let output_directory = parent.create_child(name, 0o700, "WYR1-C1 output")?;
    let built = build_into(&output_directory)?;
    Ok(format!(
        "WYR1_C1_HOST_PRODUCT_PASS product_kind={PRODUCT_KIND} selector=none evidence=not-produced wyrmroot_revision={} rust_revision={ACCEPTED_RUST_REVISION} bootfs_sha256={} receipt={}\n",
        built.validated.wyrmroot_revision,
        sha256::bytes_digest(&built.snapshot.bootfs),
        output.join("product/build-receipt.toml").display(),
    ))
}

pub(crate) fn build_into(
    output: &crate::secure_fs::Directory,
) -> Result<BuiltFrozenProduct, Failure> {
    reject_ambient_build_environment(env::vars_os())?;
    let repository = crate::tasks::repository_root()?;
    let project = repository
        .ancestors()
        .find(|path| path.ends_with("OS-Project"))
        .ok_or_else(|| Failure::task("WYR1-C1 source is not beneath OS-Project"))?
        .to_path_buf();
    let revision = clean_repository_revision(&repository)?;
    let manifest = BuildManifest::load(&repository)?;
    if manifest.rust_revision()? != ACCEPTED_RUST_REVISION
        || manifest.rust_toolchain_name()? != ACCEPTED_TOOLCHAIN_NAME
    {
        return Err(Failure::task(
            "WYR1-C1 product metadata does not name the accepted a92dc7f Rust toolchain",
        ));
    }
    let profile = manifest.validate_loader_build_readiness(&repository)?;
    let toolchain = crate::tasks::prepare_loader_toolchain(&repository, &profile, &manifest)?;
    let cargo_home = crate::tasks::project_cargo_home(&repository, &manifest)?;
    if env::var_os("CARGO_HOME").as_deref() != Some(cargo_home.as_os_str()) {
        return Err(Failure::task(
            "WYR1-C1 product requires the pinned launcher's exact CARGO_HOME",
        ));
    }

    let project_directory = crate::secure_fs::Directory::open_exact(&project, "OS-Project root")?;
    let tmp = match project_directory.open_child(".tmp", "project temporary root") {
        Ok(directory) => directory,
        Err(_) => project_directory.create_child(".tmp", 0o700, "project temporary root")?,
    };
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
        .as_nanos();
    let scratch_name = format!("wyr1c-build-{}-{unique}", std::process::id());
    let scratch = tmp.create_scratch(&scratch_name, "WYR1-C1 build scratch")?;
    let build_result = (|| {
        let mut artifacts = Vec::with_capacity(NATIVE_SPECS.len());
        for spec in NATIVE_SPECS {
            toolchain.accepted().verify_unchanged()?;
            let artifact = scratch.with_inheritable_anchor("WYR1-C1 build scratch", |anchor| {
                let build = anchor.path();
                let mut artifact =
                    build_native(&repository, &cargo_home, toolchain.accepted(), build, spec)?;
                let built_path = build
                    .join(spec.label)
                    .join(NATIVE_TARGET)
                    .join("release")
                    .join(spec.artifact);
                artifact.inspection =
                    inspect_native(&repository, &built_path, &artifact.sha256, spec.label)?;
                Ok(artifact)
            })?;
            artifacts.push(artifact);
        }
        Ok::<_, Failure>(artifacts)
    })();
    let artifacts = scratch.finish(build_result)?;
    toolchain.accepted().verify_unchanged()?;
    verify_repository_revision(&repository, &revision)?;

    let product = assemble_product(&revision, &artifacts)?;
    let receipt = render_receipt(
        &revision,
        &manifest,
        toolchain.accepted(),
        &product,
        &artifacts,
    )?;
    if receipt.len() > MAX_REPORT_BYTES {
        return Err(Failure::task("WYR1-C1 receipt exceeds its fixed bound"));
    }
    let snapshot = FrozenSnapshot {
        receipt: receipt.into_bytes(),
        rrc_manifest: product.rrc_manifest,
        device_manifest: product.device_manifest,
        bootfs: product.bootfs,
        artifacts: artifacts
            .iter()
            .map(|artifact| (artifact.spec.label.to_owned(), artifact.bytes.clone()))
            .collect(),
        inspections: artifacts
            .iter()
            .map(|artifact| {
                (
                    artifact.spec.label.to_owned(),
                    artifact.inspection.as_bytes().to_vec(),
                )
            })
            .collect(),
    };
    let validated = validate_frozen_product(&repository, &snapshot)?;
    publish_snapshot(output, &snapshot)?;
    let published = snapshot_from_directory(output)?;
    if published.receipt != snapshot.receipt
        || published.rrc_manifest != snapshot.rrc_manifest
        || published.device_manifest != snapshot.device_manifest
        || published.bootfs != snapshot.bootfs
        || published.artifacts != snapshot.artifacts
        || published.inspections != snapshot.inspections
    {
        return Err(Failure::task("WYR1-C1 published snapshot changed"));
    }
    validate_frozen_product(&repository, &published)?;
    toolchain.accepted().verify_unchanged()?;
    verify_repository_revision(&repository, &revision)?;
    Ok(BuiltFrozenProduct {
        snapshot: published,
        validated,
    })
}

fn publish_snapshot(
    output: &crate::secure_fs::Directory,
    snapshot: &FrozenSnapshot,
) -> Result<(), Failure> {
    let artifacts = output.create_child("artifacts", 0o700, "WYR1-C1 artifacts")?;
    let inspections = output.create_child("inspections", 0o700, "WYR1-C1 inspections")?;
    let product = output.create_child("product", 0o700, "WYR1-C1 product")?;
    for spec in NATIVE_SPECS {
        artifacts.write_new(
            &format!("{}.elf", spec.label),
            snapshot
                .artifacts
                .get(spec.label)
                .ok_or_else(|| Failure::task("WYR1-C1 snapshot lacks an artifact"))?,
            0o400,
            "WYR1-C1 artifact",
        )?;
        inspections.write_new(
            &format!("{}.json", spec.label),
            snapshot
                .inspections
                .get(spec.label)
                .ok_or_else(|| Failure::task("WYR1-C1 snapshot lacks an inspection"))?,
            0o400,
            "WYR1-C1 inspection",
        )?;
    }
    for (name, bytes, maximum, label) in [
        (
            "rrc-c1-v1.bin",
            snapshot.rrc_manifest.as_slice(),
            MAX_REPORT_BYTES,
            "WYR1-C1 WRRM",
        ),
        (
            "wrdm-c1-v1.bin",
            snapshot.device_manifest.as_slice(),
            MAX_REPORT_BYTES,
            "WYR1-C1 WRDM",
        ),
        (
            "bootfs.img",
            snapshot.bootfs.as_slice(),
            MAX_BOOTFS_BYTES,
            "WYR1-C1 bootfs",
        ),
        (
            "build-receipt.toml",
            snapshot.receipt.as_slice(),
            MAX_REPORT_BYTES,
            "WYR1-C1 receipt",
        ),
    ] {
        if bytes.is_empty() || bytes.len() > maximum {
            return Err(Failure::task(format!(
                "{label} exceeds its publication bound"
            )));
        }
        product.write_new(name, bytes, 0o400, label)?;
    }
    Ok(())
}

pub(crate) fn snapshot_from_directory(
    output: &crate::secure_fs::Directory,
) -> Result<FrozenSnapshot, Failure> {
    let artifacts = output.open_child("artifacts", "WYR1-C1 artifacts")?;
    let inspections = output.open_child("inspections", "WYR1-C1 inspections")?;
    let product = output.open_child("product", "WYR1-C1 product")?;
    let mut artifact_bytes = BTreeMap::new();
    let mut inspection_bytes = BTreeMap::new();
    for spec in NATIVE_SPECS {
        artifact_bytes.insert(
            spec.label.to_owned(),
            artifacts.read(
                &format!("{}.elf", spec.label),
                MAX_ARTIFACT_BYTES as u64,
                "WYR1-C1 artifact",
            )?,
        );
        inspection_bytes.insert(
            spec.label.to_owned(),
            inspections.read(
                &format!("{}.json", spec.label),
                MAX_REPORT_BYTES as u64,
                "WYR1-C1 inspection",
            )?,
        );
    }
    Ok(FrozenSnapshot {
        receipt: product.read(
            "build-receipt.toml",
            MAX_REPORT_BYTES as u64,
            "WYR1-C1 receipt",
        )?,
        rrc_manifest: product.read("rrc-c1-v1.bin", MAX_REPORT_BYTES as u64, "WYR1-C1 WRRM")?,
        device_manifest: product.read("wrdm-c1-v1.bin", MAX_REPORT_BYTES as u64, "WYR1-C1 WRDM")?,
        bootfs: product.read("bootfs.img", MAX_BOOTFS_BYTES as u64, "WYR1-C1 bootfs")?,
        artifacts: artifact_bytes,
        inspections: inspection_bytes,
    })
}

struct ProductBytes {
    generation: [u8; 32],
    rrc_manifest: Vec<u8>,
    rrc_manifest_sha256: String,
    device_manifest: Vec<u8>,
    device_manifest_sha256: String,
    bootfs: Vec<u8>,
    bootfs_sha256: String,
}

fn assemble_product(revision: &str, artifacts: &[NativeArtifact]) -> Result<ProductBytes, Failure> {
    let [init, registryd, devmgr, uart, consoled, wyrmsh]: [&NativeArtifact; 6] = artifacts
        .iter()
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| Failure::task("WYR1-C1 product requires exactly six native artifacts"))?;
    let role_hashes = [
        digest_array(&registryd.sha256)?,
        digest_array(&devmgr.sha256)?,
        digest_array(&uart.sha256)?,
        digest_array(&consoled.sha256)?,
        digest_array(&wyrmsh.sha256)?,
    ];
    let generation = product_generation(revision, artifacts);
    let rrc_manifest = crate::wyr1::fixed_builder_for_profiles(
        &generation,
        role_hashes,
        StartupProfile::BootstrapRegistry,
        StartupProfile::DeviceCoordinator,
    )?
    .build_structural()
    .map_err(|error| Failure::task(format!("WYR1-C1 WRRM build failed: {error:?}")))?;
    validate_rrc(&rrc_manifest, &generation, role_hashes)?;

    let mut wrdm = [0u8; WRDM_HEADER_BYTES + WRDM_RECORD_BYTES];
    let wrdm_size = encode_com2_manifest(ContentIdentity(role_hashes[2]), &mut wrdm)
        .map_err(|error| Failure::task(format!("WYR1-C1 WRDM build failed: {error:?}")))?;
    let device_manifest = wrdm[..wrdm_size].to_vec();
    let bootfs = build_c1(ProductC1 {
        base: Product {
            init: &init.bytes,
            registryd: &registryd.bytes,
            devmgr: &devmgr.bytes,
            uart16550d: &uart.bytes,
            consoled: &consoled.bytes,
            wyrmsh: &wyrmsh.bytes,
            rrc_manifest: &rrc_manifest,
            gate_config: GATE_CONFIG,
        },
        marker: WYR1_C1_MARKER,
        device_manifest: &device_manifest,
        expected_uart16550d_identity: role_hashes[2],
    })
    .map_err(|error| Failure::task(format!("WYR1-C1 bootfs build failed: {error:?}")))?;
    if bootfs.len() > MAX_BOOTFS_BYTES {
        return Err(Failure::task("WYR1-C1 bootfs exceeds the image bound"));
    }
    inspect_archive(&bootfs, artifacts, &rrc_manifest, &device_manifest)?;
    Ok(ProductBytes {
        generation,
        rrc_manifest_sha256: sha256::bytes_digest(&rrc_manifest),
        device_manifest_sha256: sha256::bytes_digest(&device_manifest),
        bootfs_sha256: sha256::bytes_digest(&bootfs),
        rrc_manifest,
        device_manifest,
        bootfs,
    })
}

fn build_native(
    repository: &Path,
    cargo_home: &Path,
    toolchain: &crate::toolchain_artifact::AcceptedToolchain,
    build_directory: &Path,
    spec: NativeSpec,
) -> Result<NativeArtifact, Failure> {
    let target = build_directory.join(spec.label);
    fs::create_dir(&target)
        .map_err(|error| Failure::task(format!("could not create native target: {error}")))?;
    let flags = native_remap_flags(repository, cargo_home, &target)?;
    let arguments = [
        "build",
        "--offline",
        "--locked",
        "--release",
        "--target",
        NATIVE_TARGET,
        "--package",
        spec.package,
        "--bin",
        spec.binary,
        "--features",
        spec.features,
    ];
    let status = Command::new(&toolchain.cargo)
        .args(arguments)
        .arg("--target-dir")
        .arg(&target)
        .env("RUSTC", &toolchain.rustc)
        .env("CARGO_HOME", cargo_home)
        .env("CARGO_ENCODED_RUSTFLAGS", flags)
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_NET_OFFLINE", "true")
        .env("SOURCE_DATE_EPOCH", "0")
        .env_remove("LD_AUDIT")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD")
        .current_dir(repository)
        .stdin(Stdio::null())
        .status()
        .map_err(|error| Failure::task(format!("could not build {}: {error}", spec.label)))?;
    if !status.success() {
        return Err(Failure::task(format!(
            "WYR1-C1 canonical {} build failed",
            spec.label
        )));
    }
    let artifact = target
        .join(NATIVE_TARGET)
        .join("release")
        .join(spec.artifact);
    let bytes = read_bounded(&artifact, spec.label, MAX_ARTIFACT_BYTES, false)?;
    let sha256 = sha256::bytes_digest(&bytes);
    Ok(NativeArtifact {
        spec,
        bytes,
        sha256,
        inspection: String::new(),
    })
}

fn native_remap_flags(
    repository: &Path,
    cargo_home: &Path,
    target: &Path,
) -> Result<String, Failure> {
    let repository = fs::canonicalize(repository)
        .map_err(|error| Failure::task(format!("could not resolve source root: {error}")))?;
    let cargo_home = fs::canonicalize(cargo_home)
        .map_err(|error| Failure::task(format!("could not resolve Cargo home: {error}")))?;
    let target = fs::canonicalize(target)
        .map_err(|error| Failure::task(format!("could not resolve target root: {error}")))?;
    Ok([
        format!(
            "--remap-path-prefix={}=/source/wyrmroot",
            repository.display()
        ),
        format!("--remap-path-prefix={}=/cargo-home", cargo_home.display()),
        format!("--remap-path-prefix={}=/cargo-target", target.display()),
    ]
    .join("\u{1f}"))
}

fn inspect_native(
    repository: &Path,
    artifact: &Path,
    expected_sha256: &str,
    label: &str,
) -> Result<String, Failure> {
    let output = Command::new("sh")
        .arg(repository.join("toolchain/inspect-native-artifact.sh"))
        .arg(artifact)
        .current_dir(repository)
        .env_clear()
        .env("PATH", INSPECTION_PATH)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| Failure::task(format!("could not inspect WYR1-C1 {label}: {error}")))?;
    if !output.status.success()
        || output.stdout.is_empty()
        || output.stdout.len() > MAX_REPORT_BYTES
        || output.stderr.len() > MAX_REPORT_BYTES
    {
        return Err(Failure::task(format!(
            "WYR1-C1 canonical inspection failed for {label}"
        )));
    }
    let report = String::from_utf8(output.stdout)
        .map_err(|_| Failure::task("WYR1-C1 native inspection report is not UTF-8"))?;
    if !report.contains("\"verified\":true")
        || !report.contains(&format!("\"sha256\":\"{expected_sha256}\""))
        || !report.ends_with('\n')
    {
        return Err(Failure::task(format!(
            "WYR1-C1 native inspection did not bind the exact {label} artifact"
        )));
    }
    Ok(report)
}

fn validate_rrc(
    bytes: &[u8],
    generation: &[u8; 32],
    identities: [[u8; 32]; 5],
) -> Result<(), Failure> {
    let manifest = Manifest::parse_structural(bytes, generation)
        .map_err(|error| Failure::task(format!("WYR1-C1 WRRM inspection failed: {error:?}")))?;
    for (index, (id, profile)) in [
        (RoleId::Registryd, StartupProfile::BootstrapRegistry),
        (RoleId::Devmgr, StartupProfile::DeviceCoordinator),
        (RoleId::Uart16550d, StartupProfile::Retained),
        (RoleId::Consoled, StartupProfile::Retained),
        (RoleId::Wyrmsh, StartupProfile::Retained),
    ]
    .into_iter()
    .enumerate()
    {
        let role = manifest
            .role(id)
            .ok_or_else(|| Failure::task("WYR1-C1 WRRM lost a canonical role"))?;
        if role.startup_profile() != profile || role.executable_identity() != &identities[index] {
            return Err(Failure::task("WYR1-C1 WRRM role/profile identity drifted"));
        }
    }
    Ok(())
}

fn inspect_archive(
    bytes: &[u8],
    artifacts: &[NativeArtifact],
    rrc_manifest: &[u8],
    device_manifest: &[u8],
) -> Result<(), Failure> {
    let archive = Archive::new(bytes)
        .map_err(|error| Failure::task(format!("WYR1-C1 bootfs inspection failed: {error:?}")))?;
    let expected = [
        ("system/init", artifacts[0].bytes.as_slice()),
        ("system/registryd", artifacts[1].bytes.as_slice()),
        ("system/devmgr", artifacts[2].bytes.as_slice()),
        ("system/uart16550d", artifacts[3].bytes.as_slice()),
        ("system/consoled", artifacts[4].bytes.as_slice()),
        ("system/wyrmsh", artifacts[5].bytes.as_slice()),
        ("system/bootstrap/rrc-a-v1", rrc_manifest),
        ("system/bootstrap/wyr1-a-gate-v1", GATE_CONFIG),
        ("system/bootstrap/wyr1-c-gate-v1", WYR1_C1_MARKER),
        (
            "system/bootstrap/wyr1-c-device-manifest-v1",
            device_manifest,
        ),
    ];
    if archive.entries().count() != expected.len() {
        return Err(Failure::task("WYR1-C1 bootfs entry set drifted"));
    }
    for (path, expected_bytes) in expected {
        let entry = archive
            .lookup(path.as_bytes())
            .map_err(|_| Failure::task(format!("WYR1-C1 bootfs is missing {path}")))?;
        if entry.data() != expected_bytes {
            return Err(Failure::task(format!("WYR1-C1 bootfs changed {path}")));
        }
    }
    Ok(())
}

fn render_receipt(
    revision: &str,
    manifest: &BuildManifest,
    toolchain: &crate::toolchain_artifact::AcceptedToolchain,
    product: &ProductBytes,
    artifacts: &[NativeArtifact],
) -> Result<String, Failure> {
    let mut receipt = format!(
        "kind = \"{RECEIPT_KIND}\"\nschema_version = {SCHEMA_VERSION}\nproduct_kind = \"{PRODUCT_KIND}\"\nselector = \"none\"\nevidence = \"not-produced\"\nwyrmroot_revision = \"{revision}\"\ncargo_lock_sha256 = \"{}\"\nrust_revision = \"{}\"\nrust_toolchain_name = \"{}\"\nrustc_sha256 = \"{}\"\ncargo_sha256 = \"{}\"\nrust_lld_sha256 = \"{}\"\ntoolchain_manifest_sha256 = \"{}\"\ntoolchain_tree_sha256 = \"{}\"\nboot_generation = \"{}\"\nrrc_manifest_path = \"product/rrc-c1-v1.bin\"\nrrc_manifest_sha256 = \"{}\"\ndevice_manifest_path = \"product/wrdm-c1-v1.bin\"\ndevice_manifest_sha256 = \"{}\"\nbootfs_path = \"product/bootfs.img\"\nbootfs_sha256 = \"{}\"\nbootfs_bytes = {}\n",
        sha256::file_digest(&crate::tasks::repository_root()?.join("Cargo.lock"))
            .map_err(|error| Failure::task(format!("could not hash Cargo.lock: {error}")))?,
        manifest.rust_revision()?,
        manifest.rust_toolchain_name()?,
        sha256::file_digest(&toolchain.rustc)
            .map_err(|error| Failure::task(format!("could not hash accepted rustc: {error}")))?,
        toolchain.cargo_sha256,
        toolchain.rust_lld_sha256,
        toolchain.manifest_sha256,
        toolchain.toolchain_tree_sha256,
        hex_digest(&product.generation),
        product.rrc_manifest_sha256,
        product.device_manifest_sha256,
        product.bootfs_sha256,
        product.bootfs.len(),
    );
    for artifact in artifacts {
        receipt.push_str(&format!(
            "{}_path = \"artifacts/{}.elf\"\n{}_sha256 = \"{}\"\n{}_command = \"{}\"\n{}_inspection_sha256 = \"{}\"\n",
            artifact.spec.label,
            artifact.spec.label,
            artifact.spec.label,
            artifact.sha256,
            artifact.spec.label,
            native_command(artifact.spec),
            artifact.spec.label,
            sha256::bytes_digest(artifact.inspection.as_bytes()),
        ));
    }
    Ok(receipt)
}

pub(crate) fn validate_frozen_product(
    repository: &Path,
    snapshot: &FrozenSnapshot,
) -> Result<ValidatedFrozenProduct, Failure> {
    let receipt_text = std::str::from_utf8(&snapshot.receipt)
        .map_err(|_| Failure::task("WYR1-C1 receipt is not UTF-8"))?;
    let receipt = parse_receipt(receipt_text)?;
    let expected_keys = c1_receipt_keys();
    if receipt.keys().cloned().collect::<BTreeSet<_>>() != expected_keys {
        return Err(Failure::task("WYR1-C1 receipt key set drifted"));
    }
    for (key, expected) in [
        ("kind", RECEIPT_KIND),
        ("schema_version", "1"),
        ("product_kind", PRODUCT_KIND),
        ("selector", "none"),
        ("evidence", "not-produced"),
        ("rust_revision", ACCEPTED_RUST_REVISION),
        ("rust_toolchain_name", ACCEPTED_TOOLCHAIN_NAME),
        ("rrc_manifest_path", "product/rrc-c1-v1.bin"),
        ("device_manifest_path", "product/wrdm-c1-v1.bin"),
        ("bootfs_path", "product/bootfs.img"),
    ] {
        if receipt.get(key).map(String::as_str) != Some(expected) {
            return Err(Failure::task(format!("WYR1-C1 receipt {key} drifted")));
        }
    }

    let revision = receipt
        .get("wyrmroot_revision")
        .ok_or_else(|| Failure::task("WYR1-C1 receipt lacks Wyrmroot revision"))?
        .clone();
    validate_revision(&revision, "Wyrmroot")?;
    validate_commit(repository, &revision, "Wyrmroot")?;
    let cargo_lock = git_file(repository, &revision, "Cargo.lock")?;
    if receipt.get("cargo_lock_sha256") != Some(&sha256::bytes_digest(&cargo_lock)) {
        return Err(Failure::task(
            "WYR1-C1 receipt Cargo.lock hash is not from its declared revision",
        ));
    }

    let manifest = BuildManifest::load(repository)?;
    if manifest.rust_revision()? != ACCEPTED_RUST_REVISION
        || manifest.rust_toolchain_name()? != ACCEPTED_TOOLCHAIN_NAME
    {
        return Err(Failure::task(
            "current metadata lost the accepted C1 toolchain tuple",
        ));
    }
    let profile = manifest.validate_loader_build_readiness(repository)?;
    let toolchain = crate::tasks::prepare_loader_toolchain(repository, &profile, &manifest)?;
    toolchain.accepted().verify_unchanged()?;
    for (key, actual) in [
        ("rustc_sha256", toolchain.accepted().rustc_sha256.as_str()),
        ("cargo_sha256", toolchain.accepted().cargo_sha256.as_str()),
        (
            "rust_lld_sha256",
            toolchain.accepted().rust_lld_sha256.as_str(),
        ),
        (
            "toolchain_manifest_sha256",
            toolchain.accepted().manifest_sha256.as_str(),
        ),
        (
            "toolchain_tree_sha256",
            toolchain.accepted().toolchain_tree_sha256.as_str(),
        ),
    ] {
        if receipt.get(key).map(String::as_str) != Some(actual) {
            return Err(Failure::task(format!("WYR1-C1 receipt {key} drifted")));
        }
    }

    let mut artifacts = Vec::with_capacity(NATIVE_SPECS.len());
    for spec in NATIVE_SPECS {
        let bytes = snapshot
            .artifacts
            .get(spec.label)
            .ok_or_else(|| Failure::task("WYR1-C1 snapshot lacks a native artifact"))?
            .clone();
        let inspection_bytes = snapshot
            .inspections
            .get(spec.label)
            .ok_or_else(|| Failure::task("WYR1-C1 snapshot lacks an inspection"))?;
        let digest = sha256::bytes_digest(&bytes);
        let expected_path = format!("artifacts/{}.elf", spec.label);
        if receipt.get(&format!("{}_path", spec.label)) != Some(&expected_path)
            || receipt.get(&format!("{}_sha256", spec.label)) != Some(&digest)
            || receipt.get(&format!("{}_command", spec.label)) != Some(&native_command(spec))
            || receipt.get(&format!("{}_inspection_sha256", spec.label))
                != Some(&sha256::bytes_digest(inspection_bytes))
        {
            return Err(Failure::task(format!(
                "WYR1-C1 {} receipt binding drifted",
                spec.label
            )));
        }
        let inspection = std::str::from_utf8(inspection_bytes)
            .map_err(|_| Failure::task("WYR1-C1 inspection is not UTF-8"))?
            .to_owned();
        validate_inspection(&inspection, spec.label, &digest, bytes.len())?;
        artifacts.push(NativeArtifact {
            spec,
            bytes,
            sha256: digest,
            inspection,
        });
    }

    for (key, bytes) in [
        ("rrc_manifest_sha256", snapshot.rrc_manifest.as_slice()),
        (
            "device_manifest_sha256",
            snapshot.device_manifest.as_slice(),
        ),
        ("bootfs_sha256", snapshot.bootfs.as_slice()),
    ] {
        if receipt.get(key) != Some(&sha256::bytes_digest(bytes)) {
            return Err(Failure::task(format!("WYR1-C1 {key} drifted")));
        }
    }
    if receipt.get("bootfs_bytes") != Some(&snapshot.bootfs.len().to_string()) {
        return Err(Failure::task("WYR1-C1 bootfs byte count drifted"));
    }
    let generation = product_generation(&revision, &artifacts);
    if receipt.get("boot_generation") != Some(&hex_digest(&generation)) {
        return Err(Failure::task("WYR1-C1 boot generation was not recomputed"));
    }
    validate_rrc(
        &snapshot.rrc_manifest,
        &generation,
        [
            digest_array(&artifacts[1].sha256)?,
            digest_array(&artifacts[2].sha256)?,
            digest_array(&artifacts[3].sha256)?,
            digest_array(&artifacts[4].sha256)?,
            digest_array(&artifacts[5].sha256)?,
        ],
    )?;
    let uart_identity = digest_array(&artifacts[3].sha256)?;
    wyrmroot_device_proto::Manifest::parse(&snapshot.device_manifest)
        .and_then(|manifest| manifest.match_com2(ContentIdentity(uart_identity)))
        .map_err(|error| Failure::task(format!("WYR1-C1 WRDM failed inspection: {error:?}")))?;
    inspect_archive(
        &snapshot.bootfs,
        &artifacts,
        &snapshot.rrc_manifest,
        &snapshot.device_manifest,
    )?;
    if snapshot.receipt != canonical_c1_receipt(&receipt)?.as_bytes() {
        return Err(Failure::task("WYR1-C1 receipt is not canonically rendered"));
    }
    Ok(ValidatedFrozenProduct {
        wyrmroot_revision: revision,
    })
}

fn canonical_c1_receipt(values: &BTreeMap<String, String>) -> Result<String, Failure> {
    let mut output = String::new();
    for key in [
        "kind",
        "schema_version",
        "product_kind",
        "selector",
        "evidence",
        "wyrmroot_revision",
        "cargo_lock_sha256",
        "rust_revision",
        "rust_toolchain_name",
        "rustc_sha256",
        "cargo_sha256",
        "rust_lld_sha256",
        "toolchain_manifest_sha256",
        "toolchain_tree_sha256",
        "boot_generation",
        "rrc_manifest_path",
        "rrc_manifest_sha256",
        "device_manifest_path",
        "device_manifest_sha256",
        "bootfs_path",
        "bootfs_sha256",
        "bootfs_bytes",
    ] {
        let value = values
            .get(key)
            .ok_or_else(|| Failure::task("WYR1-C1 receipt lost a canonical field"))?;
        if matches!(key, "schema_version" | "bootfs_bytes") {
            output.push_str(&format!("{key} = {value}\n"));
        } else {
            output.push_str(&format!("{key} = \"{value}\"\n"));
        }
    }
    for spec in NATIVE_SPECS {
        for suffix in ["path", "sha256", "command", "inspection_sha256"] {
            let key = format!("{}_{suffix}", spec.label);
            let value = values
                .get(&key)
                .ok_or_else(|| Failure::task("WYR1-C1 receipt lost an artifact field"))?;
            output.push_str(&format!("{key} = \"{value}\"\n"));
        }
    }
    Ok(output)
}

fn c1_receipt_keys() -> BTreeSet<String> {
    let mut keys = [
        "kind",
        "schema_version",
        "product_kind",
        "selector",
        "evidence",
        "wyrmroot_revision",
        "cargo_lock_sha256",
        "rust_revision",
        "rust_toolchain_name",
        "rustc_sha256",
        "cargo_sha256",
        "rust_lld_sha256",
        "toolchain_manifest_sha256",
        "toolchain_tree_sha256",
        "boot_generation",
        "rrc_manifest_path",
        "rrc_manifest_sha256",
        "device_manifest_path",
        "device_manifest_sha256",
        "bootfs_path",
        "bootfs_sha256",
        "bootfs_bytes",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    for spec in NATIVE_SPECS {
        for suffix in ["path", "sha256", "command", "inspection_sha256"] {
            keys.insert(format!("{}_{suffix}", spec.label));
        }
    }
    keys
}

fn parse_receipt(text: &str) -> Result<BTreeMap<String, String>, Failure> {
    if !text.ends_with('\n') || text.contains('\r') {
        return Err(Failure::task("WYR1-C1 receipt line endings drifted"));
    }
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let (key, raw) = line
            .split_once(" = ")
            .ok_or_else(|| Failure::task("WYR1-C1 receipt line is malformed"))?;
        if key.is_empty()
            || !key.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            })
            || values.contains_key(key)
        {
            return Err(Failure::task("WYR1-C1 receipt key is invalid or duplicate"));
        }
        let value = if raw.starts_with('"') && raw.ends_with('"') && raw.len() >= 2 {
            let value = &raw[1..raw.len() - 1];
            if value.contains(['"', '\\']) || value.is_empty() {
                return Err(Failure::task("WYR1-C1 receipt string is malformed"));
            }
            value
        } else if !raw.is_empty() && raw.bytes().all(|byte| byte.is_ascii_digit()) {
            raw
        } else {
            return Err(Failure::task("WYR1-C1 receipt scalar is malformed"));
        };
        values.insert(key.to_owned(), value.to_owned());
    }
    Ok(values)
}

fn validate_inspection(
    report: &str,
    label: &str,
    digest: &str,
    size: usize,
) -> Result<(), Failure> {
    if !report.ends_with('\n') || report.contains('\r') {
        return Err(Failure::task("WYR1-C1 inspection line endings drifted"));
    }
    let body = report
        .strip_suffix('\n')
        .and_then(|value| value.strip_prefix('{'))
        .and_then(|value| value.strip_suffix('}'))
        .ok_or_else(|| Failure::task("WYR1-C1 inspection JSON is malformed"))?;
    let mut fields = BTreeMap::new();
    for field in body.split(',') {
        let (key, value) = field
            .split_once(':')
            .ok_or_else(|| Failure::task("WYR1-C1 inspection field is malformed"))?;
        let key = key
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .ok_or_else(|| Failure::task("WYR1-C1 inspection key is malformed"))?;
        if fields.insert(key, value).is_some() {
            return Err(Failure::task("WYR1-C1 inspection key is duplicate"));
        }
    }
    let expected_keys = [
        "schema_version",
        "report_kind",
        "verified",
        "artifact",
        "sha256",
        "size",
        "osabi",
        "abi_version",
        "program_headers",
        "load_segments",
        "syscall_veneers",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let expected_artifact = format!("\"{label}\"");
    let expected_digest = format!("\"{digest}\"");
    let expected_size = size.to_string();
    if fields.keys().copied().collect::<BTreeSet<_>>() != expected_keys
        || fields.get("schema_version") != Some(&"1")
        || fields.get("report_kind") != Some(&"\"wyrmroot-wyr0-native-artifact-inspection\"")
        || fields.get("verified") != Some(&"true")
        || fields.get("artifact") != Some(&expected_artifact.as_str())
        || fields.get("sha256") != Some(&expected_digest.as_str())
        || fields.get("size") != Some(&expected_size.as_str())
        || fields.get("osabi") != Some(&"0")
        || fields.get("abi_version") != Some(&"0")
        || fields.get("syscall_veneers") != Some(&"1")
        || !["program_headers", "load_segments"].into_iter().all(|key| {
            fields
                .get(key)
                .is_some_and(|value| !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
        })
    {
        return Err(Failure::task(format!(
            "WYR1-C1 inspection did not exactly bind {label}"
        )));
    }
    Ok(())
}

fn validate_revision(revision: &str, label: &str) -> Result<(), Failure> {
    if revision.len() != 40
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Failure::task(format!(
            "{label} revision is not a commit ID"
        )));
    }
    Ok(())
}

pub(crate) fn validate_commit(
    repository: &Path,
    revision: &str,
    label: &str,
) -> Result<(), Failure> {
    validate_revision(revision, label)?;
    let commit = format!("{revision}^{{commit}}");
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["rev-parse", "--verify", &commit])
        .output()
        .map_err(|error| Failure::task(format!("could not inspect {label} commit: {error}")))?;
    if !output.status.success()
        || std::str::from_utf8(&output.stdout).ok().map(str::trim) != Some(revision)
    {
        return Err(Failure::task(format!(
            "declared {label} revision is not that exact commit"
        )));
    }
    Ok(())
}

fn git_file(repository: &Path, revision: &str, path: &str) -> Result<Vec<u8>, Failure> {
    let object = format!("{revision}:{path}");
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["show", &object])
        .output()
        .map_err(|error| Failure::task(format!("could not inspect historical {path}: {error}")))?;
    if !output.status.success() {
        return Err(Failure::task(format!(
            "declared WYR1-C1 revision lacks {path}"
        )));
    }
    Ok(output.stdout)
}

fn product_generation(revision: &str, artifacts: &[NativeArtifact]) -> [u8; 32] {
    let mut material = Vec::from(b"wyrmroot-wyr1-c1-host-product-v1\0".as_slice());
    material.extend_from_slice(revision.as_bytes());
    for artifact in artifacts {
        material.extend_from_slice(artifact.spec.label.as_bytes());
        material.extend_from_slice(artifact.sha256.as_bytes());
    }
    sha256::bytes_digest_array(&material)
}

fn native_command(spec: NativeSpec) -> String {
    format!(
        "cargo build --offline --locked --release --target {NATIVE_TARGET} --package {} --bin {} --features {}",
        spec.package, spec.binary, spec.features
    )
}

fn validate_fresh_output(
    repository: &Path,
    project: &Path,
    output: &Path,
) -> Result<PathBuf, Failure> {
    if fs::symlink_metadata(output).is_ok() {
        return Err(Failure::task(
            "WYR1-C1 product refuses a pre-existing output path",
        ));
    }
    if output.is_absolute()
        && output
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(Failure::task("WYR1-C1 output path is not canonical"));
    }
    let parent = output
        .parent()
        .ok_or_else(|| Failure::task("WYR1-C1 output has no parent"))?;
    let parent = fs::canonicalize(parent)
        .map_err(|error| Failure::task(format!("could not resolve output parent: {error}")))?;
    let project = fs::canonicalize(project)
        .map_err(|error| Failure::task(format!("could not resolve OS-Project root: {error}")))?;
    let repository = fs::canonicalize(repository)
        .map_err(|error| Failure::task(format!("could not resolve Wyrmroot source: {error}")))?;
    let name = output
        .file_name()
        .ok_or_else(|| Failure::task("WYR1-C1 output has no final component"))?;
    let resolved = parent.join(name);
    if !resolved.starts_with(&project) || resolved.starts_with(&repository) {
        return Err(Failure::task(
            "WYR1-C1 output must remain inside OS-Project and outside the Wyrmroot source tree",
        ));
    }
    Ok(resolved)
}

fn reject_ambient_build_environment(
    environment: impl IntoIterator<Item = (OsString, OsString)>,
) -> Result<(), Failure> {
    let variables = environment
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
    for variable in [
        "RUSTUP_TOOLCHAIN",
        "RUSTC_BOOTSTRAP",
        "RUSTC",
        "RUSTDOC",
        "RUSTFMT",
        "RUSTFLAGS",
        "RUSTDOCFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTDOC",
        "CARGO_BUILD_TARGET",
        "CARGO_TARGET_DIR",
        "WYRMROOT_RUSTC",
        "DEEPWYRM_GUEST_TEST_SELECTOR",
        "DEEPWYRM_GUEST_TEST_ID",
    ] {
        if variables.contains_key(OsStr::new(variable)) {
            return Err(Failure::task(format!(
                "WYR1-C1 product refuses ambient {variable}"
            )));
        }
    }
    if variables
        .keys()
        .any(|key| key.as_encoded_bytes().starts_with(b"CARGO_TARGET_"))
    {
        return Err(Failure::task(
            "WYR1-C1 product refuses ambient CARGO_TARGET_*",
        ));
    }
    Ok(())
}

fn clean_repository_revision(repository: &Path) -> Result<String, Failure> {
    let revision = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|error| Failure::task(format!("could not inspect Wyrmroot HEAD: {error}")))?;
    let revision = std::str::from_utf8(&revision.stdout)
        .map_err(|_| Failure::task("Wyrmroot HEAD is not UTF-8"))?
        .trim()
        .to_owned();
    verify_repository_revision(repository, &revision)?;
    Ok(revision)
}

fn verify_repository_revision(repository: &Path, expected: &str) -> Result<(), Failure> {
    let head = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|error| Failure::task(format!("could not recheck Wyrmroot HEAD: {error}")))?;
    let status = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["status", "--porcelain=v1", "--untracked-files=all"])
        .output()
        .map_err(|error| Failure::task(format!("could not inspect Wyrmroot status: {error}")))?;
    if !head.status.success()
        || !status.status.success()
        || !status.stdout.is_empty()
        || std::str::from_utf8(&head.stdout).ok().map(str::trim) != Some(expected)
    {
        return Err(Failure::task(
            "WYR1-C1 product requires one exact clean Wyrmroot revision",
        ));
    }
    Ok(())
}

fn read_bounded(
    path: &Path,
    label: &str,
    maximum: usize,
    require_single_link: bool,
) -> Result<Vec<u8>, Failure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Failure::task(format!("could not inspect WYR1-C1 {label}: {error}")))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum as u64
        || (require_single_link && metadata.nlink() != 1)
    {
        return Err(Failure::task(format!(
            "WYR1-C1 {label} is not a bounded regular file"
        )));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|error| Failure::task(format!("could not open WYR1-C1 {label}: {error}")))?;
    let opened = file
        .metadata()
        .map_err(|error| Failure::task(format!("could not stat WYR1-C1 {label}: {error}")))?;
    if (metadata.dev(), metadata.ino()) != (opened.dev(), opened.ino()) {
        return Err(Failure::task(format!(
            "WYR1-C1 {label} changed before opening"
        )));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| Failure::task(format!("could not read WYR1-C1 {label}: {error}")))?;
    if bytes.len() != opened.len() as usize {
        return Err(Failure::task(format!(
            "WYR1-C1 {label} changed while reading"
        )));
    }
    Ok(bytes)
}

fn digest_array(value: &str) -> Result<[u8; 32], Failure> {
    crate::wyr1::decode_digest(value)
}

fn hex_digest(value: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in value {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_artifacts() -> Vec<NativeArtifact> {
        NATIVE_SPECS
            .into_iter()
            .enumerate()
            .map(|(index, spec)| {
                let bytes = vec![index as u8 + 1; index + 3];
                NativeArtifact {
                    spec,
                    sha256: sha256::bytes_digest(&bytes),
                    bytes,
                    inspection: format!("{{\"verified\":true,\"artifact\":\"{}\"}}\n", spec.label),
                }
            })
            .collect()
    }

    #[test]
    fn c1_product_is_deterministic_and_uses_real_profiles() {
        let artifacts = fixture_artifacts();
        let first = assemble_product(&"a".repeat(40), &artifacts).unwrap();
        let second = assemble_product(&"a".repeat(40), &artifacts).unwrap();
        assert_eq!(first.rrc_manifest, second.rrc_manifest);
        assert_eq!(first.device_manifest, second.device_manifest);
        assert_eq!(first.bootfs, second.bootfs);
        validate_rrc(
            &first.rrc_manifest,
            &first.generation,
            [
                digest_array(&artifacts[1].sha256).unwrap(),
                digest_array(&artifacts[2].sha256).unwrap(),
                digest_array(&artifacts[3].sha256).unwrap(),
                digest_array(&artifacts[4].sha256).unwrap(),
                digest_array(&artifacts[5].sha256).unwrap(),
            ],
        )
        .unwrap();
    }

    #[test]
    fn ambient_overrides_and_existing_outputs_are_rejected() {
        assert!(reject_ambient_build_environment([]).is_ok());
        assert!(
            reject_ambient_build_environment([(
                OsString::from("CARGO_TARGET_DIR"),
                OsString::from("elsewhere")
            )])
            .is_err()
        );
        let root = std::env::temp_dir().join(format!("wyr1c1-output-{}", std::process::id()));
        let repository = root.join("OS-Project/wyrmroot");
        fs::create_dir_all(&repository).unwrap();
        let output = root.join("OS-Project/product");
        fs::create_dir(&output).unwrap();
        assert!(validate_fresh_output(&repository, &root.join("OS-Project"), &output).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn command_is_unambiguously_host_only() {
        for spec in NATIVE_SPECS {
            let command = native_command(spec);
            assert!(command.contains("--target x86_64-unknown-wyrmroot"));
            assert!(command.contains("--offline --locked --release"));
        }
    }

    #[test]
    fn native_inspection_uses_only_the_pinned_host_tool_path() {
        assert_eq!(INSPECTION_PATH, "/usr/lib/llvm/22/bin:/usr/bin:/bin");
        assert!(!INSPECTION_PATH.contains("/usr/local"));
    }

    #[test]
    fn frozen_structure_rejects_generation_artifact_and_gate_mutation() {
        let artifacts = fixture_artifacts();
        let product = assemble_product(&"a".repeat(40), &artifacts).unwrap();
        let mut wrong_generation = product.generation;
        wrong_generation[0] ^= 1;
        assert!(
            validate_rrc(
                &product.rrc_manifest,
                &wrong_generation,
                [
                    digest_array(&artifacts[1].sha256).unwrap(),
                    digest_array(&artifacts[2].sha256).unwrap(),
                    digest_array(&artifacts[3].sha256).unwrap(),
                    digest_array(&artifacts[4].sha256).unwrap(),
                    digest_array(&artifacts[5].sha256).unwrap(),
                ],
            )
            .is_err()
        );
        let mut substituted = fixture_artifacts();
        substituted[2].bytes[0] ^= 1;
        assert!(
            inspect_archive(
                &product.bootfs,
                &substituted,
                &product.rrc_manifest,
                &product.device_manifest,
            )
            .is_err()
        );
        let mut changed_bootfs = product.bootfs.clone();
        changed_bootfs[0] ^= 1;
        assert!(
            inspect_archive(
                &changed_bootfs,
                &artifacts,
                &product.rrc_manifest,
                &product.device_manifest,
            )
            .is_err()
        );
    }

    #[test]
    fn inspection_validator_binds_utf8_name_hash_size_and_verified_state() {
        let digest = "ab".repeat(32);
        let report = format!(
            "{{\"schema_version\":1,\"report_kind\":\"wyrmroot-wyr0-native-artifact-inspection\",\"verified\":true,\"artifact\":\"devmgr\",\"sha256\":\"{digest}\",\"size\":17,\"osabi\":0,\"abi_version\":0,\"program_headers\":2,\"load_segments\":1,\"syscall_veneers\":1}}\n"
        );
        assert!(validate_inspection(&report, "devmgr", &digest, 17).is_ok());
        assert!(validate_inspection(&report, "registryd", &digest, 17).is_err());
        assert!(validate_inspection(&report, "devmgr", &digest, 18).is_err());
        assert!(
            validate_inspection(
                &report.replace("\"verified\":true", "\"verified\":false"),
                "devmgr",
                &digest,
                17,
            )
            .is_err()
        );
    }

    #[test]
    fn c1_receipt_parser_rejects_command_key_and_size_ambiguity() {
        assert!(parse_receipt("bootfs_bytes = 17\n").is_ok());
        assert!(parse_receipt("bootfs_bytes = \"17\"\n").is_ok());
        assert!(parse_receipt("system-init_command = \"x\"\n").is_ok());
        assert!(parse_receipt("a = \"x\"\na = \"y\"\n").is_err());
        assert!(parse_receipt("bootfs_bytes = +17\n").is_err());
        assert!(parse_receipt("system/init = \"x\"\n").is_err());
    }

    #[test]
    fn declared_revision_must_be_the_exact_commit_not_its_tree() {
        let root = std::env::temp_dir().join(format!(
            "wyr1c-commit-kind-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let git = |arguments: &[&str]| {
            Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(arguments)
                .env("GIT_AUTHOR_NAME", "WYR1-C test")
                .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
                .env("GIT_COMMITTER_NAME", "WYR1-C test")
                .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
                .output()
                .unwrap()
        };
        assert!(git(&["init", "--quiet"]).status.success());
        fs::write(root.join("file"), b"fixture").unwrap();
        assert!(git(&["add", "file"]).status.success());
        assert!(
            git(&[
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "-m",
                "fixture"
            ])
            .status
            .success()
        );
        let commit = String::from_utf8(git(&["rev-parse", "HEAD"]).stdout)
            .unwrap()
            .trim()
            .to_owned();
        let tree = String::from_utf8(git(&["rev-parse", "HEAD^{tree}"]).stdout)
            .unwrap()
            .trim()
            .to_owned();
        assert!(validate_commit(&root, &commit, "fixture").is_ok());
        assert!(validate_commit(&root, &tree, "fixture").is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
