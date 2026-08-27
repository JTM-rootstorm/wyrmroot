//! Selector-28 immutable designated-VM handoff preparation.
//!
//! This is deliberately preparation-only: Wyrmroot owns deterministic product
//! identity and libvirt input manifests, while the root coordinator owns the
//! persistent-domain lifecycle and the 46-record `DW1C` verifier.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use wyrmroot_bootfs::archive::Archive;
use wyrmroot_bootfs::builder::{Builder, FileMode};

use crate::error::Failure;
use crate::metadata::BuildManifest;
use crate::sha256;

const NATIVE_TARGET: &str = "x86_64-unknown-wyrmroot";
const DW1C_INIT_FEATURES: &str = "native-init0,dw1c-preemption-integration";
const DW1C_ACTOR_FEATURES: &str = "native-payloads";
const KERNEL_TARGET: &str = "x86_64-unknown-none";
const OVMF_CODE_PATH: &str = "/usr/share/edk2/OvmfX64/OVMF_CODE.fd";
const OVMF_CODE_SHA256: &str = "f3ff7e73448ed2845ee15356f394882f5618eb5dab92c9a30ec6ee0e1468553a";
const OVMF_VARS_PATH: &str = "/usr/share/edk2/OvmfX64/OVMF_VARS.fd";
const OVMF_VARS_SHA256: &str = "6ed987af3a3c155be71665f510eae3e007eda9b8b94afd59d45e91c4a11565cc";

const SELECTOR: &str = "normal-preemption-smp";
const TEST_ID: &str = "28";
// Wyrmroot's accepted toolchain/layout is tied to this generated ABI revision.
// The product kernel is intentionally built from the explicit Deep candidate;
// DW1-B uses the same two-revision split.
const GENERATED_ABI_REVISION: &str = "cfc69bd8a49819ce1cda1a132cf56e55c93f92e4";
const DEEPWYRM_ABI_TREE: &str = "1c6a74f130e386eee95b3780c75950beefd0037d";
const MACHINE: &str = "pc-q35-10.2";
const DOMAIN_UUID: &str = "33005e22-d7c2-4b13-b1ac-b82eda95e584";
const O_NOFOLLOW: i32 = 0x2_0000;
const MAX_INPUT_BYTES: u64 = 512 * 1024 * 1024;
const ABSENT: &str = "absent";
const PASSES: [&str; 6] = [
    "smoke", "stress-1", "stress-2", "stress-3", "stress-4", "stress-5",
];
const INPUTS: [&str; 19] = [
    "loader",
    "kernel",
    "symbols",
    "bootstrap",
    "actor1",
    "actor2",
    "actor3",
    "actor4",
    "actor5",
    "actor6",
    "actor7",
    "actor8",
    "actor9",
    "actor10",
    "provenance",
    "bootfs",
    "esp",
    "ovmf_code",
    "ovmf_vars_template",
];
const REQUEST_KEYS: [&str; 52] = [
    "schema_version",
    "selector",
    "test_id",
    "timeout_seconds",
    "vcpus",
    "memory_mib",
    "deepwyrm_revision",
    "wyrmroot_revision",
    "rust_revision",
    "evidence_nonce",
    "progress_digest",
    "build_receipt",
    "build_receipt_sha256",
    "campaign_directory",
    "loader_path",
    "loader_sha256",
    "kernel_path",
    "kernel_sha256",
    "symbols_path",
    "symbols_sha256",
    "bootstrap_path",
    "bootstrap_sha256",
    "actor1_path",
    "actor1_sha256",
    "actor2_path",
    "actor2_sha256",
    "actor3_path",
    "actor3_sha256",
    "actor4_path",
    "actor4_sha256",
    "actor5_path",
    "actor5_sha256",
    "actor6_path",
    "actor6_sha256",
    "actor7_path",
    "actor7_sha256",
    "actor8_path",
    "actor8_sha256",
    "actor9_path",
    "actor9_sha256",
    "actor10_path",
    "actor10_sha256",
    "provenance_path",
    "provenance_sha256",
    "bootfs_path",
    "bootfs_sha256",
    "esp_path",
    "esp_sha256",
    "ovmf_code_path",
    "ovmf_code_sha256",
    "ovmf_vars_template_path",
    "ovmf_vars_template_sha256",
];
const BUILD_RECEIPT_KEYS: [&str; 29] = [
    "schema_version",
    "kind",
    "selector",
    "test_id",
    "deepwyrm_revision",
    "wyrmroot_revision",
    "rust_revision",
    "evidence_nonce",
    "progress_digest",
    "bootfs_max_pages",
    "loader_sha256",
    "kernel_sha256",
    "symbols_sha256",
    "bootstrap_sha256",
    "actor1_sha256",
    "actor2_sha256",
    "actor3_sha256",
    "actor4_sha256",
    "actor5_sha256",
    "actor6_sha256",
    "actor7_sha256",
    "actor8_sha256",
    "actor9_sha256",
    "actor10_sha256",
    "provenance_sha256",
    "bootfs_sha256",
    "esp_sha256",
    "ovmf_code_sha256",
    "ovmf_vars_template_sha256",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WyrBuildSpec {
    pub(crate) label: &'static str,
    pub(crate) package: &'static str,
    pub(crate) binary: &'static str,
    pub(crate) features: &'static str,
    pub(crate) requires_progress_digest: bool,
}

/// Ordered isolated native release builds for the selector-28 userspace half.
/// Loader construction remains the shared deterministic UEFI pair; the caller
/// uses these specs only after that pair and the accepted layout are prepared.
pub(crate) fn wyr_build_specs() -> [WyrBuildSpec; 12] {
    [
        WyrBuildSpec {
            label: "bootstrap",
            package: "wyrmroot-bootstrap",
            binary: "wyrmroot-bootstrap",
            features: "native-bootstrap,wyr0-init0-integration",
            requires_progress_digest: false,
        },
        WyrBuildSpec {
            label: "init0",
            package: "wyrmroot-init0",
            binary: "wyrmroot-init0",
            features: DW1C_INIT_FEATURES,
            requires_progress_digest: false,
        },
        WyrBuildSpec {
            label: "actor1",
            package: "wyrmroot-dw1c-preemption",
            binary: "wyrmroot-dw1c-actor1",
            features: DW1C_ACTOR_FEATURES,
            requires_progress_digest: true,
        },
        WyrBuildSpec {
            label: "actor2",
            package: "wyrmroot-dw1c-preemption",
            binary: "wyrmroot-dw1c-actor2",
            features: DW1C_ACTOR_FEATURES,
            requires_progress_digest: true,
        },
        WyrBuildSpec {
            label: "actor3",
            package: "wyrmroot-dw1c-preemption",
            binary: "wyrmroot-dw1c-actor3",
            features: DW1C_ACTOR_FEATURES,
            requires_progress_digest: true,
        },
        WyrBuildSpec {
            label: "actor4",
            package: "wyrmroot-dw1c-preemption",
            binary: "wyrmroot-dw1c-actor4",
            features: DW1C_ACTOR_FEATURES,
            requires_progress_digest: true,
        },
        WyrBuildSpec {
            label: "actor5",
            package: "wyrmroot-dw1c-preemption",
            binary: "wyrmroot-dw1c-actor5",
            features: DW1C_ACTOR_FEATURES,
            requires_progress_digest: true,
        },
        WyrBuildSpec {
            label: "actor6",
            package: "wyrmroot-dw1c-preemption",
            binary: "wyrmroot-dw1c-actor6",
            features: DW1C_ACTOR_FEATURES,
            requires_progress_digest: true,
        },
        WyrBuildSpec {
            label: "actor7",
            package: "wyrmroot-dw1c-preemption",
            binary: "wyrmroot-dw1c-actor7",
            features: DW1C_ACTOR_FEATURES,
            requires_progress_digest: true,
        },
        WyrBuildSpec {
            label: "actor8",
            package: "wyrmroot-dw1c-preemption",
            binary: "wyrmroot-dw1c-actor8",
            features: DW1C_ACTOR_FEATURES,
            requires_progress_digest: true,
        },
        WyrBuildSpec {
            label: "actor9",
            package: "wyrmroot-dw1c-preemption",
            binary: "wyrmroot-dw1c-actor9",
            features: DW1C_ACTOR_FEATURES,
            requires_progress_digest: true,
        },
        WyrBuildSpec {
            label: "actor10",
            package: "wyrmroot-dw1c-preemption",
            binary: "wyrmroot-dw1c-actor10",
            features: DW1C_ACTOR_FEATURES,
            requires_progress_digest: true,
        },
    ]
}

/// Bytes and provenance from the Wyrmroot-owned half of a selector-28
/// product build.  The final 29-field build-lineage receipt is deliberately
/// rendered only after Deep/kernel, bootfs, ESP, and firmware inputs exist.
pub(crate) struct WyrArtifactSet {
    pub(crate) loader: Vec<u8>,
    pub(crate) bootstrap: Vec<u8>,
    pub(crate) init0: Vec<u8>,
    pub(crate) actors: [Vec<u8>; 10],
    pub(crate) debug_loader: Vec<u8>,
    pub(crate) debug_symbols: Vec<u8>,
    pub(crate) effective_uefi_config: String,
    pub(crate) uefi_inspection_report: String,
    pub(crate) source_receipt: String,
}

/// Build the deterministic Wyrmroot artifacts which precede selector-28
/// kernel/bootfs assembly.  Each native executable has an isolated target
/// directory, so no actor can borrow an incremental or feature-selected
/// product from another invocation.
pub(crate) fn build_wyr_artifact_set(
    build_root: &Path,
    source_revision: &str,
    progress_digest: &str,
) -> Result<WyrArtifactSet, Failure> {
    validate_upper_hex(progress_digest, 16, "progress_digest")?;
    fs::create_dir(build_root).map_err(|error| {
        Failure::task(format!("could not create fresh DW1-C build root: {error}"))
    })?;
    let repository = crate::tasks::repository_root()?;
    let manifest = BuildManifest::load(&repository)?;
    let profile = manifest.validate_loader_build_readiness(&repository)?;
    let layout = crate::deep_layout::prepare(
        &repository,
        manifest.deepwyrm_repository()?,
        manifest.deepwyrm_revision()?,
    )?;
    let toolchain = crate::tasks::prepare_loader_toolchain(&repository, &profile, &manifest)?;
    let cargo_home = crate::tasks::project_cargo_home(&repository, &manifest)?;
    let uefi = crate::tasks::build_deterministic_uefi_pair(
        &repository,
        &toolchain,
        &profile,
        &layout,
        &crate::tasks::IsolatedUefiBuild {
            cargo_home: &cargo_home,
            production_target: &build_root.join("uefi-production"),
            retained_debug_target: &build_root.join("uefi-retained-debug"),
            cargo_profile: crate::tasks::UefiCargoProfile::Release,
        },
    )?;
    let loader = read_cargo_build_output(&uefi.loader, "loader", 64 * 1024 * 1024)?;
    let debug_loader = read_cargo_build_output(
        &uefi.debug_loader,
        "retained debug loader",
        64 * 1024 * 1024,
    )?;
    let debug_symbols =
        read_cargo_build_output(&uefi.debug_symbols, "loader PDB", 512 * 1024 * 1024)?;

    let mut artifacts = Vec::with_capacity(12);
    for spec in wyr_build_specs() {
        toolchain.accepted().verify_unchanged()?;
        layout.verify_unchanged()?;
        let target_dir = build_root.join(spec.label);
        fs::create_dir(&target_dir).map_err(io)?;
        let encoded_rustflags = native_remap_flags(&repository, &cargo_home, &target_dir)?;
        let mut command = Command::new(&toolchain.accepted().cargo);
        command
            .args(["build", "--offline", "--locked", "--release", "--target"])
            .arg(NATIVE_TARGET)
            .args([
                "--package",
                spec.package,
                "--bin",
                spec.binary,
                "--features",
                spec.features,
            ])
            .arg("--target-dir")
            .arg(&target_dir)
            .env("RUSTC", &toolchain.accepted().rustc)
            .env("CARGO_HOME", &cargo_home)
            .env("CARGO_ENCODED_RUSTFLAGS", encoded_rustflags)
            .env("CARGO_INCREMENTAL", "0")
            .env("SOURCE_DATE_EPOCH", "0")
            .env_remove("LD_AUDIT")
            .env_remove("LD_LIBRARY_PATH")
            .env_remove("LD_PRELOAD")
            .current_dir(&repository)
            .stdin(Stdio::null());
        if let Some((key, value)) = progress_digest_environment(spec, progress_digest) {
            command.env(key, value);
        } else {
            command.env_remove("DEEPWYRM_DW1C_PROGRESS_DIGEST");
        }
        let status = command.status().map_err(|error| {
            Failure::task(format!("could not run DW1-C {} build: {error}", spec.label))
        })?;
        if !status.success() {
            return Err(Failure::task(format!(
                "DW1-C canonical {} release build failed",
                spec.label
            )));
        }
        let source = target_dir
            .join(NATIVE_TARGET)
            .join("release")
            .join(spec.binary);
        artifacts.push(read_cargo_build_output(
            &source,
            spec.label,
            64 * 1024 * 1024,
        )?);
    }
    let [
        bootstrap,
        init0,
        actor1,
        actor2,
        actor3,
        actor4,
        actor5,
        actor6,
        actor7,
        actor8,
        actor9,
        actor10,
    ]: [Vec<u8>; 12] = artifacts
        .try_into()
        .map_err(|_| Failure::task("DW1-C build produced the wrong artifact count"))?;
    verify_clean_repository(&repository, "Wyrmroot", source_revision)?;
    toolchain.accepted().verify_unchanged()?;
    layout.verify_unchanged()?;
    let actors = [
        actor1, actor2, actor3, actor4, actor5, actor6, actor7, actor8, actor9, actor10,
    ];
    let source_receipt = render_wyr_source_receipt(
        source_revision,
        progress_digest,
        toolchain.accepted(),
        &layout,
        &uefi,
        &loader,
        &bootstrap,
        &init0,
        &actors,
        &toolchain.validation_report_sha256(),
    )?;
    Ok(WyrArtifactSet {
        loader,
        bootstrap,
        init0,
        actors,
        debug_loader,
        debug_symbols,
        effective_uefi_config: uefi.effective_config,
        uefi_inspection_report: uefi.inspection_report,
        source_receipt,
    })
}

fn progress_digest_environment<'a>(
    spec: WyrBuildSpec,
    progress_digest: &'a str,
) -> Option<(&'static str, &'a str)> {
    spec.requires_progress_digest
        .then_some(("DEEPWYRM_DW1C_PROGRESS_DIGEST", progress_digest))
}

fn render_wyr_source_receipt(
    source_revision: &str,
    progress_digest: &str,
    toolchain: &crate::toolchain_artifact::AcceptedToolchain,
    layout: &crate::deep_layout::DeepLayoutBuild,
    uefi: &crate::tasks::DeterministicUefiArtifacts,
    loader: &[u8],
    bootstrap: &[u8],
    init0: &[u8],
    actors: &[Vec<u8>; 10],
    toolchain_validation_report_sha256: &str,
) -> Result<String, Failure> {
    let repository = crate::tasks::repository_root()?;
    let cargo_lock_sha256 = sha256::file_digest(&repository.join("Cargo.lock"))
        .map_err(|error| Failure::task(format!("could not hash Cargo.lock: {error}")))?;
    let mut fields = BTreeMap::new();
    for (key, value) in [
        ("schema_version", "1".to_owned()),
        ("kind", "wyrmroot-dw1-c-wyr-source-build".to_owned()),
        ("wyrmroot_revision", source_revision.to_owned()),
        ("progress_digest", progress_digest.to_owned()),
        ("profile", "release-separate-invocations".to_owned()),
        (
            "rustc_sha256",
            sha256::file_digest(&toolchain.rustc).map_err(io)?,
        ),
        ("cargo_sha256", toolchain.cargo_sha256.clone()),
        ("rust_lld_sha256", toolchain.rust_lld_sha256.clone()),
        (
            "toolchain_manifest_sha256",
            toolchain.manifest_sha256.clone(),
        ),
        (
            "toolchain_tree_sha256",
            toolchain.toolchain_tree_sha256.clone(),
        ),
        ("cargo_lock_sha256", cargo_lock_sha256),
        ("deep_layout_sha256", layout.layout_sha256.clone()),
        (
            "generated_layout_policy_sha256",
            layout.policy_sha256.clone(),
        ),
        (
            "uefi_effective_config_sha256",
            uefi.effective_config_sha256.clone(),
        ),
        (
            "uefi_inspection_report_sha256",
            uefi.inspection_report_sha256.clone(),
        ),
        (
            "toolchain_validation_report_sha256",
            toolchain_validation_report_sha256.to_owned(),
        ),
        ("loader_sha256", sha256::bytes_digest(loader)),
        ("bootstrap_sha256", sha256::bytes_digest(bootstrap)),
        ("init0_sha256", sha256::bytes_digest(init0)),
    ] {
        fields.insert(key.to_owned(), value);
    }
    for (index, actor) in actors.iter().enumerate() {
        fields.insert(
            format!("actor{}_sha256", index + 1),
            sha256::bytes_digest(actor),
        );
    }
    for spec in wyr_build_specs() {
        fields.insert(
            format!("{}_command", spec.label),
            native_build_command(spec),
        );
    }
    render(&fields)
}

fn native_build_command(spec: WyrBuildSpec) -> String {
    format!(
        "cargo build --offline --locked --release --target {NATIVE_TARGET} --package {} --bin {} --features {}",
        spec.package, spec.binary, spec.features
    )
}

fn native_remap_flags(
    repository: &Path,
    cargo_home: &Path,
    target: &Path,
) -> Result<String, Failure> {
    let repository = fs::canonicalize(repository).map_err(io)?;
    let cargo_home = fs::canonicalize(cargo_home).map_err(io)?;
    let target = fs::canonicalize(target).map_err(io)?;
    for path in [&repository, &cargo_home, &target] {
        if path.to_string_lossy().contains('\u{1f}') {
            return Err(Failure::task(
                "DW1-C build path contains Cargo's encoded-rustflags separator",
            ));
        }
    }
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

fn read_cargo_build_output(path: &Path, label: &str, maximum: u64) -> Result<Vec<u8>, Failure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Failure::task(format!("could not inspect DW1-C {label}: {error}")))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(Failure::task(format!(
            "DW1-C {label} is not a bounded regular Cargo build output"
        )));
    }
    read_regular(path, label)
}

/// Creates a fresh six-pass campaign containing immutable all-string TOML
/// handoffs and exact q35/OVMF domain XML.  It never invokes QEMU or libvirt.
pub fn prepare(request_path: &Path) -> Result<String, Failure> {
    let request = Request::load(request_path)?;
    let campaign = create_fresh_directory(&request.campaign_directory, "DW1-C campaign directory")?;
    let immutable =
        create_fresh_directory(&campaign.join("immutable"), "DW1-C immutable directory")?;
    let request_snapshot = snapshot(request_path, &immutable.join("request.toml"))?;
    let receipt_snapshot = snapshot_expected(
        &request.build_receipt,
        &request.values["build_receipt_sha256"],
        &immutable.join("build-receipt.toml"),
    )?;
    verify_build_receipt(&request, &receipt_snapshot.path)?;
    let mut inputs = BTreeMap::new();
    for label in INPUTS {
        let source = request.path(label)?;
        inputs.insert(
            label,
            snapshot_expected(
                &source,
                &request.values[&format!("{label}_sha256")],
                &immutable.join(file_name(label)),
            )?,
        );
    }
    let mut campaign_fields = base_fields(&request, &request_snapshot, &receipt_snapshot, &inputs)?;
    campaign_fields.insert("kind".into(), "wyrmroot-dw1-c-vm-campaign".into());
    campaign_fields.insert("campaign_pass_count".into(), PASSES.len().to_string());
    for pass in PASSES {
        let directory = create_fresh_directory(&campaign.join(pass), "DW1-C pass directory")?;
        let vars_source = request.path("ovmf_vars_template")?;
        let vars = snapshot_with_mode(&vars_source, &directory.join("OVMF_VARS.fd"), 0o600)?;
        let xml = domain_xml(&inputs, &vars)?;
        let xml_snapshot = write_new(&directory.join("domain.xml"), xml.as_bytes(), 0o444)?;
        let mut fields = base_fields(&request, &request_snapshot, &receipt_snapshot, &inputs)?;
        fields.insert("kind".into(), "wyrmroot-dw1-c-vm-handoff".into());
        fields.insert("campaign_pass".into(), pass.into());
        fields.insert("domain_xml_path".into(), text_path(&xml_snapshot.path)?);
        fields.insert("domain_xml_sha256".into(), xml_snapshot.sha256);
        fields.insert("ovmf_vars_path".into(), text_path(&vars.path)?);
        fields.insert("ovmf_vars_initial_sha256".into(), vars.sha256);
        let serial = directory.join("serial.log");
        let evidence = directory.join("evidence.log");
        let result = directory.join("result.json");
        fields.insert("serial_log_path".into(), text_path(&serial)?);
        fields.insert("evidence_log_path".into(), text_path(&evidence)?);
        fields.insert("result_json_path".into(), text_path(&result)?);
        // The root-owned runner exclusively creates this path.  The alias is
        // intentional and explicit; all other pass outputs are distinct.
        fields.insert("run_receipt_path".into(), text_path(&result)?);
        fields.insert("run_receipt_sha256".into(), ABSENT.into());
        ensure_absent_outputs(&[&serial, &evidence, &result])?;
        let handoff = render(&fields)?;
        let handoff_snapshot =
            write_new(&directory.join("handoff.toml"), handoff.as_bytes(), 0o444)?;
        campaign_fields.insert(
            format!("{pass}_handoff_path"),
            text_path(&handoff_snapshot.path)?,
        );
        campaign_fields.insert(format!("{pass}_handoff_sha256"), handoff_snapshot.sha256);
    }
    let campaign_handoff = render(&campaign_fields)?;
    let output = write_new(
        &campaign.join("campaign.toml"),
        campaign_handoff.as_bytes(),
        0o444,
    )?;
    Ok(format!(
        "DW1_C_PREPARE_PASS selector={SELECTOR} test_id={TEST_ID} passes=6 campaign={} sha256={}\n",
        output.path.display(),
        output.sha256
    ))
}

/// Build the deterministic FAT ESP from a fully-qualified selector request.
/// Artifact compilation is intentionally owned by the request's isolated
/// build lane; this operation only assembles and verifies immutable inputs.
pub fn image(request_path: &Path) -> Result<String, Failure> {
    let request = Request::load(request_path)?;
    let bootfs = read_regular(&request.path("bootfs")?, "DW1-C bootfs")?;
    let pages = bootfs.len().div_ceil(4096);
    let receipt = request.build_receipt.clone();
    verify_build_receipt(&request, &receipt)?;
    let receipt_values = scalars(
        core::str::from_utf8(&read_regular(&receipt, "DW1-C build receipt")?)
            .map_err(|_| Failure::task("DW1-C build receipt is not UTF-8"))?,
    )?;
    if request.values["bootfs_sha256"] != sha256::bytes_digest(&bootfs)
        || receipt_values.get("bootfs_max_pages") != Some(&pages.to_string())
    {
        return Err(Failure::task("DW1-C bootfs identity or page count drifted"));
    }
    let args = crate::cli::G3ImageArguments {
        image: request.path("esp")?.display().to_string(),
        loader: request.path("loader")?.display().to_string(),
        kernel: request.path("kernel")?.display().to_string(),
        bootstrap: request.path("bootstrap")?.display().to_string(),
        bootfs: request.path("bootfs")?.display().to_string(),
    };
    let result = crate::g3_image::build(&args)?;
    Ok(format!("DW1_C_IMAGE_PASS pages={pages} {result}"))
}

pub fn inspect(request_path: &Path) -> Result<String, Failure> {
    let request = Request::load(request_path)?;
    for label in INPUTS {
        let path = request.path(label)?;
        let bytes = read_regular(&path, "DW1-C artifact")?;
        if sha256::bytes_digest(&bytes) != request.values[&format!("{label}_sha256")] {
            return Err(Failure::task(format!("DW1-C {label} hash mismatch")));
        }
    }
    verify_build_receipt(&request, &request.build_receipt)?;
    let args = crate::cli::G3ImageArguments {
        image: request.path("esp")?.display().to_string(),
        loader: request.path("loader")?.display().to_string(),
        kernel: request.path("kernel")?.display().to_string(),
        bootstrap: request.path("bootstrap")?.display().to_string(),
        bootfs: request.path("bootfs")?.display().to_string(),
    };
    let result = crate::g3_image::inspect(&args)?;
    Ok(format!("DW1_C_INSPECTION_PASS {result}"))
}

pub fn freeze(
    output: &Path,
    deep_repository: &Path,
    deep_revision: &str,
    evidence_nonce: &str,
    progress_digest: &str,
) -> Result<String, Failure> {
    if output.exists() {
        return Err(Failure::task("DW1-C freeze output already exists"));
    }
    if !deep_repository.is_absolute()
        || deep_repository
            .components()
            .any(|c| matches!(c, Component::ParentDir))
        || deep_repository.is_symlink()
    {
        return Err(Failure::task("DW1-C Deep repository path is not canonical"));
    }
    verify_clean_repository(deep_repository, "Deepwyrm", deep_revision)?;
    verify_clean_repository(
        &crate::tasks::repository_root()?,
        "Wyrmroot",
        &current_revision(&crate::tasks::repository_root()?)?,
    )?;
    // The generated ABI/layout identity belongs to the accepted Wyrmroot
    // consumer.  It need not equal the later product-kernel revision, but the
    // candidate must expose the identical ABI tree before any build starts.
    let abi_tree = git_output(
        deep_repository,
        &["rev-parse", &format!("{deep_revision}:abi")],
    )?;
    let generated_tree = git_output(
        deep_repository,
        &["rev-parse", &format!("{GENERATED_ABI_REVISION}:abi")],
    )?;
    if abi_tree != DEEPWYRM_ABI_TREE || generated_tree != DEEPWYRM_ABI_TREE {
        return Err(Failure::task(
            "DW1-C product Deep candidate does not match the accepted generated ABI tree",
        ));
    }
    for (label, value) in [
        ("deep_revision", deep_revision),
        ("evidence_nonce", evidence_nonce),
        ("progress_digest", progress_digest),
    ] {
        let expected = if label == "deep_revision" { 40 } else { 16 };
        let valid_case = if label == "deep_revision" {
            value.bytes().all(|b| !b.is_ascii_uppercase())
        } else {
            value.bytes().all(|b| !b.is_ascii_lowercase())
        };
        if value.len() != expected || !value.bytes().all(|b| b.is_ascii_hexdigit()) || !valid_case {
            return Err(Failure::task(format!(
                "DW1-C {label} has invalid hexadecimal form"
            )));
        }
    }
    validate_upper_hex(evidence_nonce, 16, "evidence_nonce")?;
    validate_upper_hex(progress_digest, 16, "progress_digest")?;
    if evidence_nonce == "0000000000000000" || progress_digest == "0000000000000000" {
        return Err(Failure::task(
            "DW1-C nonce and progress digest must be nonzero",
        ));
    }
    let parent = output
        .parent()
        .ok_or_else(|| Failure::task("DW1-C freeze output has no parent"))?;
    let parent = fs::canonicalize(parent).map_err(io)?;
    let name = output
        .file_name()
        .ok_or_else(|| Failure::task("DW1-C freeze output has no final component"))?;
    let output = parent.join(name);
    fs::create_dir(&output).map_err(io)?;
    let result = freeze_product(
        &output,
        deep_repository,
        deep_revision,
        evidence_nonce,
        progress_digest,
    );
    if result.is_err() {
        // This directory was just created with `create_dir`; never retain a
        // partial product which another command could mistake for a freeze.
        fs::remove_dir_all(&output).map_err(io)?;
    }
    result
}

fn freeze_product(
    output: &Path,
    deep_repository: &Path,
    deep_revision: &str,
    evidence_nonce: &str,
    progress_digest: &str,
) -> Result<String, Failure> {
    let repository = crate::tasks::repository_root()?;
    let wyrmroot_revision = current_revision(&repository)?;
    let manifest = BuildManifest::load(&repository)?;
    let rust_revision = manifest.rust_revision()?.to_owned();
    let build_root = output.join("build");
    fs::create_dir(&build_root).map_err(io)?;
    let artifacts = build_wyr_artifact_set(
        &build_root.join("wyrmroot"),
        &wyrmroot_revision,
        progress_digest,
    )?;
    let bootfs = build_bootfs(&artifacts.init0, &artifacts.actors)?;
    let pages = bootfs.len().div_ceil(4096);
    if !(1..=8192).contains(&pages) {
        return Err(Failure::task(
            "DW1-C measured bootfs page count is out of range",
        ));
    }
    let kernel = build_kernel(
        deep_repository,
        &build_root.join("deepwyrm"),
        evidence_nonce,
        progress_digest,
        pages,
    )?;
    let symbols = kernel.clone();
    let provenance = render_kernel_provenance(
        deep_revision,
        &rust_revision,
        evidence_nonce,
        progress_digest,
        pages,
        &kernel,
    )?;
    let ovmf_code = read_pinned_firmware(OVMF_CODE_PATH, OVMF_CODE_SHA256, "OVMF code")?;
    let ovmf_vars = read_pinned_firmware(OVMF_VARS_PATH, OVMF_VARS_SHA256, "OVMF vars")?;
    let product = output.join("product");
    fs::create_dir(&product).map_err(io)?;
    for (name, bytes) in [
        ("loader.efi", artifacts.loader.as_slice()),
        ("deepwyrm.elf", kernel.as_slice()),
        ("deepwyrm.symbols", symbols.as_slice()),
        ("bootstrap.elf", artifacts.bootstrap.as_slice()),
        ("kernel-provenance.toml", provenance.as_bytes()),
        ("bootfs.img", bootfs.as_slice()),
        ("OVMF_CODE.fd", ovmf_code.as_slice()),
        ("OVMF_VARS.fd", ovmf_vars.as_slice()),
        ("loader-debug.efi", artifacts.debug_loader.as_slice()),
        ("loader.pdb", artifacts.debug_symbols.as_slice()),
        ("wyr-source-build.toml", artifacts.source_receipt.as_bytes()),
        (
            "uefi-effective-config.txt",
            artifacts.effective_uefi_config.as_bytes(),
        ),
        (
            "uefi-inspection.json",
            artifacts.uefi_inspection_report.as_bytes(),
        ),
    ] {
        write_new(&product.join(name), bytes, 0o444)?;
    }
    for (index, actor) in artifacts.actors.iter().enumerate() {
        write_new(
            &product.join(format!("actor{}.elf", index + 1)),
            actor,
            0o444,
        )?;
    }
    let esp = product.join("esp.img");
    let image_args = crate::cli::G3ImageArguments {
        image: esp.display().to_string(),
        loader: product.join("loader.efi").display().to_string(),
        kernel: product.join("deepwyrm.elf").display().to_string(),
        bootstrap: product.join("bootstrap.elf").display().to_string(),
        bootfs: product.join("bootfs.img").display().to_string(),
    };
    crate::g3_image::build(&image_args)?;
    let values = product_values(&product)?;
    let receipt = render_build_receipt(
        deep_revision,
        &wyrmroot_revision,
        &rust_revision,
        evidence_nonce,
        progress_digest,
        pages,
        &values,
    )?;
    let receipt_snapshot = write_new(
        &product.join("build-receipt.toml"),
        receipt.as_bytes(),
        0o444,
    )?;
    let request = render_freeze_request(
        deep_revision,
        &wyrmroot_revision,
        &rust_revision,
        evidence_nonce,
        progress_digest,
        &values,
        &receipt_snapshot,
    )?;
    let request_snapshot = write_new(&output.join("request.toml"), request.as_bytes(), 0o444)?;
    let loaded = Request::load(&request_snapshot.path)?;
    verify_build_receipt(&loaded, &receipt_snapshot.path)?;
    verify_clean_repository(&repository, "Wyrmroot", &wyrmroot_revision)?;
    verify_clean_repository(deep_repository, "Deepwyrm", deep_revision)?;
    Ok(format!(
        "DW1_C_FREEZE_PASS selector={SELECTOR} test_id={TEST_ID} bootfs_max_pages={pages} request={} sha256={}",
        request_snapshot.path.display(),
        request_snapshot.sha256
    ))
}

fn build_bootfs(init0: &[u8], actors: &[Vec<u8>; 10]) -> Result<Vec<u8>, Failure> {
    let mut builder = Builder::new();
    builder
        .add(b"system/init0", init0, FileMode::Executable)
        .map_err(|error| Failure::task(format!("DW1-C bootfs init0 add failed: {error:?}")))?;
    let paths = (1..=10)
        .map(|index| format!("test/dw1-c/actor{index}"))
        .collect::<Vec<_>>();
    for (path, actor) in paths.iter().zip(actors) {
        builder
            .add(path.as_bytes(), actor, FileMode::Executable)
            .map_err(|error| Failure::task(format!("DW1-C bootfs actor add failed: {error:?}")))?;
    }
    let bootfs = builder
        .build()
        .map_err(|error| Failure::task(format!("DW1-C bootfs build failed: {error:?}")))?;
    let archive = Archive::new(&bootfs)
        .map_err(|error| Failure::task(format!("DW1-C bootfs invalid: {error:?}")))?;
    if archive.entries().count() != 11 {
        return Err(Failure::task("DW1-C bootfs entry count drifted"));
    }
    Ok(bootfs)
}

fn build_kernel(
    repository: &Path,
    target: &Path,
    evidence_nonce: &str,
    progress_digest: &str,
    pages: usize,
) -> Result<Vec<u8>, Failure> {
    fs::create_dir_all(target).map_err(io)?;
    let status = Command::new(repository.join("tools/pinned-cargo"))
        .arg("target")
        .args([
            "build",
            "--locked",
            "--offline",
            "--release",
            "--target",
            KERNEL_TARGET,
            "--package",
            "deepwyrm-kernel",
            "--bin",
            "deepwyrm-kernel",
            "--features",
            "test-support",
        ])
        .env("DEEPWYRM_PINNED_TARGET_DIR", target)
        .env("DEEPWYRM_GUEST_TEST_SELECTOR", SELECTOR)
        .env("DEEPWYRM_DW1C_EVIDENCE_NONCE", evidence_nonce)
        .env("DEEPWYRM_DW1C_PROGRESS_DIGEST", progress_digest)
        .env("DEEPWYRM_DW1C_BOOTFS_MAX_PAGES", pages.to_string())
        .env_remove("CARGO_HOME")
        .env_remove("LD_AUDIT")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD")
        .current_dir(repository)
        .stdin(Stdio::null())
        .status()
        .map_err(io)?;
    if !status.success() {
        return Err(Failure::task(
            "DW1-C canonical Deepwyrm kernel build failed",
        ));
    }
    read_cargo_build_output(
        &target.join(KERNEL_TARGET).join("release/deepwyrm-kernel"),
        "kernel",
        64 * 1024 * 1024,
    )
}

fn read_pinned_firmware(path: &str, expected: &str, label: &str) -> Result<Vec<u8>, Failure> {
    let bytes = read_regular(Path::new(path), label)?;
    if sha256::bytes_digest(&bytes) != expected {
        return Err(Failure::task(format!(
            "DW1-C pinned {label} identity mismatch"
        )));
    }
    Ok(bytes)
}

fn render_kernel_provenance(
    deep: &str,
    rust: &str,
    nonce: &str,
    digest: &str,
    pages: usize,
    kernel: &[u8],
) -> Result<String, Failure> {
    let mut fields = BTreeMap::new();
    for (key, value) in [
        ("schema_version", "1".to_owned()), ("kind", "wyrmroot-dw1-c-kernel-build".to_owned()),
        ("selector", SELECTOR.to_owned()), ("test_id", TEST_ID.to_owned()),
        ("deepwyrm_revision", deep.to_owned()), ("rust_revision", rust.to_owned()),
        ("kernel_command", "tools/pinned-cargo target build --locked --offline --release --target x86_64-unknown-none --package deepwyrm-kernel --bin deepwyrm-kernel --features test-support".to_owned()),
        ("kernel_sha256", sha256::bytes_digest(kernel)), ("symbols_sha256", sha256::bytes_digest(kernel)),
        ("evidence_nonce", nonce.to_owned()), ("progress_digest", digest.to_owned()), ("bootfs_max_pages", pages.to_string()),
    ] { fields.insert(key.to_owned(), value); }
    render(&fields)
}

fn product_values(product: &Path) -> Result<BTreeMap<String, String>, Failure> {
    let mut values = BTreeMap::new();
    for (label, file) in [
        ("loader", "loader.efi"),
        ("kernel", "deepwyrm.elf"),
        ("symbols", "deepwyrm.symbols"),
        ("bootstrap", "bootstrap.elf"),
        ("provenance", "kernel-provenance.toml"),
        ("bootfs", "bootfs.img"),
        ("esp", "esp.img"),
        ("ovmf_code", "OVMF_CODE.fd"),
        ("ovmf_vars_template", "OVMF_VARS.fd"),
    ] {
        values.insert(
            label.to_owned(),
            sha256::bytes_digest(&read_regular(&product.join(file), label)?),
        );
    }
    for index in 1..=10 {
        values.insert(
            format!("actor{index}"),
            sha256::bytes_digest(&read_regular(
                &product.join(format!("actor{index}.elf")),
                "actor",
            )?),
        );
    }
    Ok(values)
}

fn render_build_receipt(
    deep: &str,
    wyr: &str,
    rust: &str,
    nonce: &str,
    digest: &str,
    pages: usize,
    hashes: &BTreeMap<String, String>,
) -> Result<String, Failure> {
    let mut fields = BTreeMap::new();
    for (key, value) in [
        ("schema_version", "1"),
        ("kind", "wyrmroot-dw1-c-build-lineage"),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
        ("deepwyrm_revision", deep),
        ("wyrmroot_revision", wyr),
        ("rust_revision", rust),
        ("evidence_nonce", nonce),
        ("progress_digest", digest),
    ] {
        fields.insert(key.to_owned(), value.to_owned());
    }
    fields.insert("bootfs_max_pages".to_owned(), pages.to_string());
    for label in INPUTS {
        fields.insert(
            format!("{label}_sha256"),
            hashes
                .get(label)
                .cloned()
                .ok_or_else(|| Failure::task("DW1-C product hash missing"))?,
        );
    }
    render(&fields)
}

fn render_freeze_request(
    deep: &str,
    wyr: &str,
    rust: &str,
    nonce: &str,
    digest: &str,
    hashes: &BTreeMap<String, String>,
    receipt: &Snapshot,
) -> Result<String, Failure> {
    let mut fields = BTreeMap::new();
    for (key, value) in [
        ("schema_version", "1"),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
        ("timeout_seconds", "240"),
        ("vcpus", "4"),
        ("memory_mib", "2048"),
        ("deepwyrm_revision", deep),
        ("wyrmroot_revision", wyr),
        ("rust_revision", rust),
        ("evidence_nonce", nonce),
        ("progress_digest", digest),
        ("build_receipt", "product/build-receipt.toml"),
        ("campaign_directory", "campaign"),
    ] {
        fields.insert(key.to_owned(), value.to_owned());
    }
    fields.insert("build_receipt_sha256".to_owned(), receipt.sha256.clone());
    for label in INPUTS {
        if let Some(number) = label.strip_prefix("actor") {
            fields.insert(
                format!("{label}_path"),
                format!("product/actor{number}.elf"),
            );
            fields.insert(format!("{label}_sha256"), hashes[label].clone());
            continue;
        }
        let file = match label {
            "loader" => "loader.efi",
            "kernel" => "deepwyrm.elf",
            "symbols" => "deepwyrm.symbols",
            "bootstrap" => "bootstrap.elf",
            "provenance" => "kernel-provenance.toml",
            "bootfs" => "bootfs.img",
            "esp" => "esp.img",
            "ovmf_code" => "OVMF_CODE.fd",
            "ovmf_vars_template" => "OVMF_VARS.fd",
            _ => return Err(Failure::task("DW1-C input label drifted")),
        };
        fields.insert(format!("{label}_path"), format!("product/{file}"));
        fields.insert(format!("{label}_sha256"), hashes[label].clone());
    }
    render(&fields)
}

fn current_revision(repository: &Path) -> Result<String, Failure> {
    git_output(repository, &["rev-parse", "HEAD"])
}

fn git_output(repository: &Path, args: &[&str]) -> Result<String, Failure> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(args)
        .output()
        .map_err(io)?;
    if !output.status.success() {
        return Err(Failure::task(format!(
            "DW1-C git command failed for {}",
            repository.display()
        )));
    }
    String::from_utf8(output.stdout)
        .map(|bytes| bytes.trim().to_owned())
        .map_err(|_| Failure::task("DW1-C git output is not UTF-8"))
}

fn verify_clean_repository(repository: &Path, label: &str, expected: &str) -> Result<(), Failure> {
    if repository.is_symlink() || !repository.is_absolute() {
        return Err(Failure::task(format!(
            "DW1-C {label} repository is not canonical"
        )));
    }
    if current_revision(repository)? != expected {
        return Err(Failure::task(format!(
            "DW1-C {label} HEAD does not match the requested revision"
        )));
    }
    let status = git_output(
        repository,
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?;
    if !status.is_empty() {
        return Err(Failure::task(format!("DW1-C {label} repository is dirty")));
    }
    Ok(())
}

fn verify_build_receipt(request: &Request, path: &Path) -> Result<(), Failure> {
    let bytes = read_regular(path, "DW1-C build receipt")?;
    let values = scalars(
        core::str::from_utf8(&bytes)
            .map_err(|_| Failure::task("DW1-C build receipt is not UTF-8"))?,
    )?;
    let expected = BUILD_RECEIPT_KEYS.into_iter().collect::<BTreeSet<_>>();
    let actual = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(Failure::task("DW1-C build receipt key set is not exact"));
    }
    for (key, expected) in [
        ("schema_version", "1"),
        ("kind", "wyrmroot-dw1-c-build-lineage"),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
    ] {
        if values.get(key).map(String::as_str) != Some(expected) {
            return Err(Failure::task(format!(
                "DW1-C build receipt requires {key}={expected}"
            )));
        }
    }
    for key in [
        "deepwyrm_revision",
        "wyrmroot_revision",
        "rust_revision",
        "evidence_nonce",
        "progress_digest",
    ] {
        if values.get(key) != request.values.get(key) {
            return Err(Failure::task(format!(
                "DW1-C build receipt does not match request {key}"
            )));
        }
    }
    let pages = values
        .get("bootfs_max_pages")
        .ok_or_else(|| Failure::task("DW1-C build receipt omits bootfs_max_pages"))?
        .parse::<usize>()
        .map_err(|_| Failure::task("DW1-C build receipt bootfs_max_pages is not decimal"))?;
    if !(1..=8192).contains(&pages) {
        return Err(Failure::task(
            "DW1-C build receipt bootfs_max_pages is out of range",
        ));
    }
    let actual_bootfs = read_regular(&request.path("bootfs")?, "DW1-C bootfs")?;
    if pages != actual_bootfs.len().div_ceil(4096) {
        return Err(Failure::task(
            "DW1-C build receipt bootfs_max_pages does not match bootfs size",
        ));
    }
    for label in INPUTS {
        let key = format!("{label}_sha256");
        if values.get(&key) != request.values.get(&key) {
            return Err(Failure::task(format!(
                "DW1-C build receipt does not match request {key}"
            )));
        }
    }
    Ok(())
}

#[derive(Clone)]
struct Snapshot {
    path: PathBuf,
    sha256: String,
}

struct Request {
    root: PathBuf,
    values: BTreeMap<String, String>,
    build_receipt: PathBuf,
    campaign_directory: PathBuf,
}

impl Request {
    fn load(path: &Path) -> Result<Self, Failure> {
        let bytes = read_regular(path, "DW1-C request")?;
        let values = scalars(
            core::str::from_utf8(&bytes)
                .map_err(|_| Failure::task("DW1-C request is not UTF-8"))?,
        )?;
        let expected = REQUEST_KEYS.into_iter().collect::<BTreeSet<_>>();
        let actual = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
        if actual != expected {
            return Err(Failure::task("DW1-C request key set is not exact"));
        }
        for (key, expected) in [
            ("selector", SELECTOR),
            ("test_id", TEST_ID),
            ("timeout_seconds", "240"),
            ("vcpus", "4"),
            ("memory_mib", "2048"),
        ] {
            if values.get(key).map(String::as_str) != Some(expected) {
                return Err(Failure::task(format!(
                    "DW1-C request requires {key}={expected}"
                )));
            }
        }
        for key in [
            "deepwyrm_revision",
            "wyrmroot_revision",
            "rust_revision",
            "evidence_nonce",
            "progress_digest",
            "build_receipt",
            "build_receipt_sha256",
            "campaign_directory",
        ] {
            if values.get(key).is_none_or(String::is_empty) {
                return Err(Failure::task(format!("DW1-C request is missing {key}")));
            }
        }
        for key in ["deepwyrm_revision", "wyrmroot_revision", "rust_revision"] {
            let value = &values[key];
            if value.len() != 40
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(Failure::task(format!(
                    "DW1-C request {key} is not a lowercase Git revision"
                )));
            }
        }
        for key in ["evidence_nonce", "progress_digest"] {
            let value = &values[key];
            if value.len() != 16
                || value == "0000000000000000"
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase())
            {
                return Err(Failure::task(format!(
                    "DW1-C request {key} is not nonzero uppercase 16-hex"
                )));
            }
        }
        for label in INPUTS {
            for suffix in ["path", "sha256"] {
                if values
                    .get(&format!("{label}_{suffix}"))
                    .is_none_or(String::is_empty)
                {
                    return Err(Failure::task(format!(
                        "DW1-C request is missing {label}_{suffix}"
                    )));
                }
            }
        }
        let mut hash_keys = vec!["build_receipt_sha256".to_owned()];
        hash_keys.extend(INPUTS.map(|label| format!("{label}_sha256")));
        for key in hash_keys {
            let value = &values[&key];
            if value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(Failure::task(format!(
                    "DW1-C request {key} is not lowercase SHA-256"
                )));
            }
        }
        let root = fs::canonicalize(
            path.parent()
                .ok_or_else(|| Failure::task("DW1-C request has no parent"))?,
        )
        .map_err(io)?;
        let build_receipt = input_path(&root, values.get("build_receipt").unwrap())?;
        let campaign_directory = output_path(&root, values.get("campaign_directory").unwrap())?;
        Ok(Self {
            root,
            values,
            build_receipt,
            campaign_directory,
        })
    }
    fn path(&self, label: &str) -> Result<PathBuf, Failure> {
        input_path(
            &self.root,
            self.values
                .get(&format!("{label}_path"))
                .ok_or_else(|| Failure::task("missing input path"))?,
        )
    }
}

fn base_fields(
    request: &Request,
    request_snapshot: &Snapshot,
    receipt: &Snapshot,
    inputs: &BTreeMap<&str, Snapshot>,
) -> Result<BTreeMap<String, String>, Failure> {
    let mut fields = BTreeMap::new();
    for (key, value) in [
        ("schema_version", "1"),
        ("vcpus", "4"),
        ("memory_mib", "2048"),
        ("machine", MACHINE),
        ("firmware", "OVMF"),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
        ("timeout_seconds", "240"),
        ("evidence_protocol", "DW1C/01"),
        ("evidence_record_count", "46"),
        ("kernel_result_protocol", "DWTEST1"),
        ("kernel_result_test_id", TEST_ID),
        ("kernel_result_detail", "0"),
        ("com1", "kernel-diagnostics-host-capture"),
        ("com2", "absent"),
        ("network", "none"),
        ("host_shares", "none"),
        ("system_disk", "absent"),
    ] {
        fields.insert(key.into(), value.into());
    }
    for key in [
        "deepwyrm_revision",
        "wyrmroot_revision",
        "rust_revision",
        "evidence_nonce",
        "progress_digest",
    ] {
        fields.insert(key.into(), request.values[key].clone());
    }
    fields.insert("request_path".into(), text_path(&request_snapshot.path)?);
    fields.insert("request_sha256".into(), request_snapshot.sha256.clone());
    fields.insert("build_receipt_path".into(), text_path(&receipt.path)?);
    fields.insert("build_receipt_sha256".into(), receipt.sha256.clone());
    for (label, snapshot) in inputs {
        fields.insert(format!("{label}_path"), text_path(&snapshot.path)?);
        fields.insert(format!("{label}_sha256"), snapshot.sha256.clone());
    }
    Ok(fields)
}

fn domain_xml(inputs: &BTreeMap<&str, Snapshot>, vars: &Snapshot) -> Result<String, Failure> {
    Ok(format!(
        "<domain xmlns:qemu=\"http://libvirt.org/schemas/domain/qemu/1.0\" type=\"qemu\">\n  <name>OS-Project</name>\n  <uuid>{DOMAIN_UUID}</uuid>\n  <memory unit=\"KiB\">2097152</memory>\n  <currentMemory unit=\"KiB\">2097152</currentMemory>\n  <vcpu placement=\"static\">4</vcpu>\n  <sysinfo type=\"fwcfg\"><entry name=\"opt/org.deepwyrm.test.selector\">{SELECTOR}</entry><entry name=\"opt/org.deepwyrm.test.test_id\">{TEST_ID}</entry></sysinfo>\n  <os><type arch=\"x86_64\" machine=\"{MACHINE}\">hvm</type><loader readonly=\"yes\" secure=\"no\" type=\"pflash\" format=\"raw\">{}</loader><nvram type=\"file\" format=\"raw\"><source file=\"{}\"/></nvram><boot dev=\"hd\"/></os>\n  <features><acpi/><apic/></features>\n  <clock offset=\"utc\"><timer name=\"rtc\" tickpolicy=\"catchup\"/><timer name=\"pit\" tickpolicy=\"delay\"/><timer name=\"hpet\" present=\"no\"/></clock>\n  <on_poweroff>destroy</on_poweroff><on_reboot>restart</on_reboot><on_crash>destroy</on_crash>\n  <pm><suspend-to-mem enabled=\"no\"/><suspend-to-disk enabled=\"no\"/></pm>\n  <devices><emulator>/usr/bin/qemu-system-x86_64</emulator><disk type=\"file\" device=\"disk\"><driver name=\"qemu\" type=\"raw\"/><source file=\"{}\"/><target dev=\"vda\" bus=\"virtio\"/><readonly/></disk><controller type=\"pci\" index=\"0\" model=\"pcie-root\"/><serial type=\"pty\"><target type=\"isa-serial\" port=\"0\"/></serial><console type=\"pty\"><target type=\"serial\" port=\"0\"/></console></devices>\n  <qemu:commandline><qemu:arg value=\"-device\"/><qemu:arg value=\"isa-debug-exit,iobase=0xf4,iosize=0x04\"/></qemu:commandline>\n</domain>\n",
        xml(&inputs["ovmf_code"].path)?,
        xml(&vars.path)?,
        xml(&inputs["esp"].path)?
    ))
}

fn file_name(label: &str) -> String {
    format!("{label}.bin")
}
fn create_fresh_directory(path: &Path, label: &str) -> Result<PathBuf, Failure> {
    if path.exists() {
        return Err(Failure::task(format!("{label} already exists")));
    }
    fs::create_dir_all(path).map_err(io)?;
    Ok(path.to_path_buf())
}
fn ensure_absent_outputs(paths: &[&Path]) -> Result<(), Failure> {
    let mut seen = BTreeSet::new();
    for path in paths {
        if !seen.insert(*path) || path.exists() {
            return Err(Failure::task(
                "DW1-C pass output exists or aliases another output",
            ));
        }
    }
    Ok(())
}
fn snapshot(source: &Path, target: &Path) -> Result<Snapshot, Failure> {
    snapshot_with_mode(source, target, 0o444)
}
fn snapshot_with_mode(source: &Path, target: &Path, mode: u32) -> Result<Snapshot, Failure> {
    let bytes = read_regular(source, "DW1-C immutable input")?;
    write_new(target, &bytes, mode)
}
fn snapshot_expected(source: &Path, expected: &str, target: &Path) -> Result<Snapshot, Failure> {
    let bytes = read_regular(source, "DW1-C immutable input")?;
    if sha256::bytes_digest(&bytes) != expected {
        return Err(Failure::task(
            "DW1-C immutable input hash does not match request",
        ));
    }
    write_new(target, &bytes, 0o444)
}
fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<Snapshot, Failure> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(io)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(io)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(io)?;
    Ok(Snapshot {
        path: path.to_path_buf(),
        sha256: sha256::bytes_digest(bytes),
    })
}
fn read_regular(path: &Path, label: &str) -> Result<Vec<u8>, Failure> {
    let meta = fs::symlink_metadata(path).map_err(io)?;
    if meta.file_type().is_symlink()
        || !meta.is_file()
        || meta.nlink() != 1
        || meta.len() == 0
        || meta.len() > MAX_INPUT_BYTES
    {
        return Err(Failure::task(format!(
            "{label} is not a bounded single-link regular file"
        )));
    }
    fs::read(path).map_err(io)
}
fn input_path(root: &Path, value: &str) -> Result<PathBuf, Failure> {
    bounded_relative(root, value, false)
}
fn output_path(root: &Path, value: &str) -> Result<PathBuf, Failure> {
    bounded_relative(root, value, true)
}
fn bounded_relative(root: &Path, value: &str, allow_missing: bool) -> Result<PathBuf, Failure> {
    let relative = Path::new(value);
    if relative.is_absolute()
        || relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(Failure::task(
            "DW1-C path is not canonical request-relative",
        ));
    }
    let path = root.join(relative);
    if !allow_missing && !path.exists() {
        return Err(Failure::task("DW1-C input path is absent"));
    }
    Ok(path)
}
fn text_path(path: &Path) -> Result<String, Failure> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Failure::task("DW1-C path is not UTF-8"))
}
fn xml(path: &Path) -> Result<String, Failure> {
    let value = text_path(path)?;
    if value.contains(['&', '<', '>', '\"', '\'']) {
        return Err(Failure::task("DW1-C XML path requires escaping"));
    }
    Ok(value)
}
fn render(fields: &BTreeMap<String, String>) -> Result<String, Failure> {
    let mut out = String::new();
    for (key, value) in fields {
        if key.is_empty()
            || !key
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            || value.contains(['\n', '\r', '\"', '\\'])
        {
            return Err(Failure::task(
                "DW1-C handoff field is not safe all-string TOML",
            ));
        }
        out.push_str(&format!("{key} = \"{value}\"\n"));
    }
    Ok(out)
}
fn scalars(text: &str) -> Result<BTreeMap<String, String>, Failure> {
    let mut out = BTreeMap::new();
    for line in text
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
    {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| Failure::task("DW1-C request is not scalar TOML"))?;
        let key = key.trim();
        let value = value
            .trim()
            .strip_prefix('\"')
            .and_then(|x| x.strip_suffix('\"'))
            .ok_or_else(|| Failure::task("DW1-C request values must be quoted strings"))?;
        if out.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(Failure::task("DW1-C request duplicates a field"));
        }
    }
    Ok(out)
}
fn io(error: std::io::Error) -> Failure {
    Failure::task(format!("DW1-C I/O failure: {error}"))
}

fn validate_upper_hex(value: &str, expected_length: usize, label: &str) -> Result<(), Failure> {
    if value.len() != expected_length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase())
    {
        return Err(Failure::task(format!(
            "DW1-C {label} is not uppercase {expected_length}-hex"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn domain_is_exact_four_cpu_no_nic_or_share() {
        let p = PathBuf::from("/tmp/a");
        let s = Snapshot {
            path: p,
            sha256: "a".repeat(64),
        };
        let mut inputs = BTreeMap::new();
        for label in INPUTS {
            inputs.insert(label, s.clone());
        }
        let xml = domain_xml(&inputs, &s).unwrap();
        assert!(xml.contains("pc-q35-10.2"));
        assert!(xml.contains(DOMAIN_UUID));
        assert!(xml.contains("<vcpu placement=\"static\">4</vcpu>"));
        assert!(xml.contains("2097152"));
        for required in [
            "<clock offset=\"utc\">",
            "<on_poweroff>destroy</on_poweroff>",
            "<on_reboot>restart</on_reboot>",
            "<on_crash>destroy</on_crash>",
            "<suspend-to-mem enabled=\"no\"/>",
            "<suspend-to-disk enabled=\"no\"/>",
        ] {
            assert!(xml.contains(required));
        }
        assert!(!xml.contains("interface"));
        assert!(!xml.contains("filesystem"));
        assert!(!xml.contains("system_disk"));
    }
    #[test]
    fn render_is_all_string_toml() {
        let mut fields = BTreeMap::new();
        fields.insert("selector".into(), SELECTOR.into());
        assert_eq!(
            render(&fields).unwrap(),
            "selector = \"normal-preemption-smp\"\n"
        );
    }

    #[test]
    fn wyr_build_specs_are_ordered_and_bind_actor_digest_environment() {
        let specs = wyr_build_specs();
        assert_eq!(specs.len(), 12);
        assert_eq!(
            specs[..2],
            [
                WyrBuildSpec {
                    label: "bootstrap",
                    package: "wyrmroot-bootstrap",
                    binary: "wyrmroot-bootstrap",
                    features: "native-bootstrap,wyr0-init0-integration",
                    requires_progress_digest: false,
                },
                WyrBuildSpec {
                    label: "init0",
                    package: "wyrmroot-init0",
                    binary: "wyrmroot-init0",
                    features: "native-init0,dw1c-preemption-integration",
                    requires_progress_digest: false,
                },
            ]
        );
        for (index, spec) in specs[2..].iter().enumerate() {
            assert_eq!(spec.label, format!("actor{}", index + 1));
            assert_eq!(spec.package, "wyrmroot-dw1c-preemption");
            assert_eq!(spec.binary, format!("wyrmroot-dw1c-actor{}", index + 1));
            assert_eq!(spec.features, "native-payloads");
            assert_eq!(
                native_build_command(*spec),
                format!(
                    "cargo build --offline --locked --release --target {NATIVE_TARGET} --package wyrmroot-dw1c-preemption --bin wyrmroot-dw1c-actor{} --features native-payloads",
                    index + 1
                )
            );
            assert_eq!(
                progress_digest_environment(*spec, "A1B2C3D4E5F60708"),
                Some(("DEEPWYRM_DW1C_PROGRESS_DIGEST", "A1B2C3D4E5F60708"))
            );
        }
        assert_eq!(progress_digest_environment(specs[0], "A1"), None);
        assert_eq!(progress_digest_environment(specs[1], "A1"), None);
    }

    #[test]
    fn bootfs_has_only_the_fixed_init0_and_ten_actor_entries() {
        let init0 = b"init0".to_vec();
        let actors = core::array::from_fn(|index| format!("actor-{index}").into_bytes());
        let bootfs = build_bootfs(&init0, &actors).unwrap();
        let archive = Archive::new(&bootfs).unwrap();
        assert_eq!(archive.entries().count(), 11);
        assert_eq!(archive.lookup(b"system/init0").unwrap().data(), init0);
        for (index, actor) in actors.iter().enumerate() {
            let path = format!("test/dw1-c/actor{}", index + 1);
            let entry = archive.lookup(path.as_bytes()).unwrap();
            assert!(entry.is_executable());
            assert_eq!(entry.data(), actor);
        }
        assert!((1..=8192).contains(&bootfs.len().div_ceil(4096)));
    }

    #[test]
    fn freeze_receipt_and_request_have_the_exact_declared_key_sets() {
        let hashes = INPUTS
            .into_iter()
            .map(|label| (label.to_owned(), "a".repeat(64)))
            .collect::<BTreeMap<_, _>>();
        let receipt = render_build_receipt(
            &"d".repeat(40),
            &"w".repeat(40),
            &"r".repeat(40),
            "A1B2C3D4E5F60708",
            "1020304050607080",
            1,
            &hashes,
        )
        .unwrap();
        let receipt_values = scalars(&receipt).unwrap();
        assert_eq!(
            receipt_values
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BUILD_RECEIPT_KEYS.into_iter().collect()
        );
        let snapshot = Snapshot {
            path: PathBuf::from("/tmp/receipt"),
            sha256: "b".repeat(64),
        };
        let request = render_freeze_request(
            &"d".repeat(40),
            &"w".repeat(40),
            &"r".repeat(40),
            "A1B2C3D4E5F60708",
            "1020304050607080",
            &hashes,
            &snapshot,
        )
        .unwrap();
        let request_values = scalars(&request).unwrap();
        assert_eq!(
            request_values
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            REQUEST_KEYS.into_iter().collect()
        );
        assert_eq!(request_values["campaign_directory"], "campaign");
    }

    #[test]
    fn per_pass_vars_snapshot_is_owner_writable_only() {
        let root = std::env::temp_dir().join(format!("dw1c-vars-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let source = root.join("source.fd");
        fs::write(&source, b"vars").unwrap();
        let target = root.join("OVMF_VARS.fd");
        snapshot_with_mode(&source, &target, 0o600).unwrap();
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(root).unwrap();
    }
}
