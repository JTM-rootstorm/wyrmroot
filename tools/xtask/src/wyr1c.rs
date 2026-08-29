//! Unnumbered, host-only WYR1-C1 product construction.
//!
//! This producer deliberately stops at immutable native artifacts, WRRM,
//! WRDM, bootfs, and a source/toolchain-bound receipt. It does not allocate a
//! guest selector, construct an ESP, or invoke QEMU/libvirt.

use std::{
    env,
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
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

pub(crate) fn product(output: &Path) -> Result<String, Failure> {
    reject_ambient_build_environment(env::vars_os())?;
    let repository = crate::tasks::repository_root()?;
    let project = repository
        .ancestors()
        .find(|path| path.ends_with("OS-Project"))
        .ok_or_else(|| Failure::task("WYR1-C1 source is not beneath OS-Project"))?
        .to_path_buf();
    let output = validate_fresh_output(&repository, &project, output)?;
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

    fs::create_dir(&output)
        .map_err(|error| Failure::task(format!("could not create WYR1-C1 output: {error}")))?;
    let artifacts_directory = output.join("artifacts");
    let product_directory = output.join("product");
    let inspections_directory = output.join("inspections");
    let build_directory = output.join("build");
    for directory in [
        &artifacts_directory,
        &product_directory,
        &inspections_directory,
        &build_directory,
    ] {
        fs::create_dir(directory).map_err(|error| {
            Failure::task(format!(
                "could not create WYR1-C1 product directory: {error}"
            ))
        })?;
    }

    let mut artifacts = Vec::with_capacity(NATIVE_SPECS.len());
    for spec in NATIVE_SPECS {
        toolchain.accepted().verify_unchanged()?;
        let artifact = build_native(
            &repository,
            &cargo_home,
            toolchain.accepted(),
            &build_directory,
            spec,
        )?;
        let published = artifacts_directory.join(format!("{}.elf", spec.label));
        write_new_file(&published, &artifact.bytes)?;
        let inspection = inspect_native(&repository, &published, &artifact.sha256, spec.label)?;
        write_new_file(
            &inspections_directory.join(format!("{}.json", spec.label)),
            inspection.as_bytes(),
        )?;
        artifacts.push(NativeArtifact {
            inspection,
            ..artifact
        });
    }
    toolchain.accepted().verify_unchanged()?;
    verify_repository_revision(&repository, &revision)?;

    let product = assemble_product(&revision, &artifacts)?;
    let manifest_path = product_directory.join("rrc-c1-v1.bin");
    let device_manifest_path = product_directory.join("wrdm-c1-v1.bin");
    let bootfs_path = product_directory.join("bootfs.img");
    write_new_file(&manifest_path, &product.rrc_manifest)?;
    write_new_file(&device_manifest_path, &product.device_manifest)?;
    write_new_file(&bootfs_path, &product.bootfs)?;

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
    let receipt_path = product_directory.join("build-receipt.toml");
    write_new_file(&receipt_path, receipt.as_bytes())?;
    inspect_published_product(
        &product_directory,
        &artifacts_directory,
        &inspections_directory,
        &artifacts,
        &product,
        &receipt,
    )?;
    toolchain.accepted().verify_unchanged()?;
    verify_repository_revision(&repository, &revision)?;

    fs::remove_dir_all(&build_directory).map_err(|error| {
        Failure::task(format!(
            "could not retire WYR1-C1 isolated build targets: {error}"
        ))
    })?;
    Ok(format!(
        "WYR1_C1_HOST_PRODUCT_PASS product_kind={PRODUCT_KIND} selector=none evidence=not-produced wyrmroot_revision={revision} rust_revision={ACCEPTED_RUST_REVISION} bootfs_sha256={} receipt={}\n",
        product.bootfs_sha256,
        receipt_path.display(),
    ))
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

fn inspect_published_product(
    product_directory: &Path,
    artifacts_directory: &Path,
    inspections_directory: &Path,
    artifacts: &[NativeArtifact],
    product: &ProductBytes,
    receipt: &str,
) -> Result<(), Failure> {
    for artifact in artifacts {
        let path = artifacts_directory.join(format!("{}.elf", artifact.spec.label));
        let observed = read_bounded(&path, artifact.spec.label, MAX_ARTIFACT_BYTES, true)?;
        if sha256::bytes_digest(&observed) != artifact.sha256 {
            return Err(Failure::task("WYR1-C1 published artifact digest drifted"));
        }
        let inspection = read_bounded(
            &inspections_directory.join(format!("{}.json", artifact.spec.label)),
            "native inspection report",
            MAX_REPORT_BYTES,
            true,
        )?;
        if inspection != artifact.inspection.as_bytes() {
            return Err(Failure::task(
                "WYR1-C1 published native inspection report drifted",
            ));
        }
    }
    let observed_rrc = read_bounded(
        &product_directory.join("rrc-c1-v1.bin"),
        "WRRM",
        MAX_REPORT_BYTES,
        true,
    )?;
    let observed_wrdm = read_bounded(
        &product_directory.join("wrdm-c1-v1.bin"),
        "WRDM",
        MAX_REPORT_BYTES,
        true,
    )?;
    let observed_bootfs = read_bounded(
        &product_directory.join("bootfs.img"),
        "bootfs",
        MAX_BOOTFS_BYTES,
        true,
    )?;
    let observed_receipt = read_bounded(
        &product_directory.join("build-receipt.toml"),
        "receipt",
        MAX_REPORT_BYTES,
        true,
    )?;
    if observed_rrc != product.rrc_manifest
        || observed_wrdm != product.device_manifest
        || observed_bootfs != product.bootfs
        || observed_receipt != receipt.as_bytes()
    {
        return Err(Failure::task(
            "WYR1-C1 published product changed during re-read",
        ));
    }
    validate_rrc(
        &observed_rrc,
        &product.generation,
        [
            digest_array(&artifacts[1].sha256)?,
            digest_array(&artifacts[2].sha256)?,
            digest_array(&artifacts[3].sha256)?,
            digest_array(&artifacts[4].sha256)?,
            digest_array(&artifacts[5].sha256)?,
        ],
    )?;
    let uart_identity = digest_array(&artifacts[3].sha256)?;
    wyrmroot_device_proto::Manifest::parse(&observed_wrdm)
        .and_then(|manifest| manifest.match_com2(ContentIdentity(uart_identity)))
        .map_err(|error| {
            Failure::task(format!(
                "published WYR1-C1 WRDM failed inspection: {error:?}"
            ))
        })?;
    inspect_archive(&observed_bootfs, artifacts, &observed_rrc, &observed_wrdm)
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

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), Failure> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| Failure::task(format!("could not create WYR1-C1 product: {error}")))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| Failure::task(format!("could not write WYR1-C1 product: {error}")))?;
    Ok(())
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
}
