//! WYR1-E7 selector-33 product freeze and paired live-VM handoff grammar.
//!
//! The freezer owns immutable inputs only.  The root verified runner owns the
//! COM1/COM2 interaction and derives all four challenges from trusted WRE1
//! generation records at run time.

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    cli::G3ImageArguments, error::Failure, g3_image, secure_fs::Directory, sha256, tasks, wyr1c,
    wyr1c6,
};

pub(crate) const SELECTOR: &str = "interactive-wyrmsh";
pub(crate) const TEST_ID: &str = "33";
pub(crate) const EVIDENCE_PROTOCOL: &str = "WRE1";
pub(crate) const RESULT_KIND: &str = "wyrmroot-wyr1-e7-selector33-result";
const REQUEST_KIND: &str = "wyrmroot-wyr1-e7-selector33-request";
const HANDOFF_KIND: &str = "wyrmroot-wyr1-e7-selector33-vm-handoff";
const PAIR_KIND: &str = "wyrmroot-wyr1-e7-selector33-vm-profile-pair";
const RECEIPT_KIND: &str = "wyrmroot-wyr1-e7-selector33-freeze-receipt";
const SOURCE_RECEIPT_KIND: &str = "wyrmroot-wyr1-e7-selector33-source-build";
const SOURCE_RECEIPT: &str = "e7-source-build.toml";
const MACHINE: &str = "pc-q35-10.2";
const TIMEOUT_SECONDS: &str = "300";
const KERNEL_TARGET: &str = "x86_64-unknown-none";
const COM1_FD_GROUP: &str = "wyr1-e7-com1-evidence-v1";
const COM2_FD_GROUP: &str = "wyr1-e7-com2-interactive-v1";
const ESP_FD_GROUP: &str = "dw-f13-esp-v1";
const VARS_FD_GROUP: &str = "dw-f13-ovmf-vars-v1";
const COM2_PRELUDE_KIND: &str = "ovmf-bds-session-banner";
const COM2_PRELUDE_LENGTH: &str = "354";
const COM2_PRELUDE_SHA256: &str =
    "8cf1a7eba89309b5ee101cbe77935604572151fb79f4e009a327125c5da8cb47";
const ACCEPTED_E6_REVISION: &str = "cca32f764e2b1b1532c0eabf00c66c2b1d19c94a";
const ACCEPTED_E6_SOURCE_RECEIPT_SHA256: &str =
    "7df2550df8b16a316ac9d30246f4a59f7e7f88db6977da8090a5b4c83717a819";
const ACCEPTED_E6_FREEZE_RECEIPT_SHA256: &str =
    "0507062b98e26ef62f1d65dcff73ffd3b0418935c1f08ad42b128579115c10bc";
const ACCEPTED_E6_REUSED_SHA256: &[(&str, &str)] = &[
    (
        "registryd",
        "3c75e3edaf27dd5457e433fdc1a5368c985a25469d6c70cdd954cb1646f3973b",
    ),
    (
        "devmgr",
        "0b4599c277038582879cab7d96ec2cd553155f815e750128148093788928b00b",
    ),
    (
        "uart16550d",
        "a6518f0293f7c88d816201d53661432345a8aa722409a25a9720c17972359a27",
    ),
    (
        "consoled",
        "16f9874dd2c09a484c9019bc3b4a3cab0a2deae533e113ca08920a78f627fd09",
    ),
    (
        "wyrmsh",
        "9d7f3ab7462488dd3f4db6226ef119516de7a2933c4441eeb331fc4f07f72101",
    ),
    (
        "hello",
        "5acb3922032f522de84d6378af837260d8fbcb63fff22bd26299a8642bcd5ba6",
    ),
    (
        "stack_report",
        "7eab648da90518331e95650becba6013158cb2edc3c5f5126beaabb6eb83ea7f",
    ),
];

pub(crate) const ARTIFACTS: &[(&str, &str)] = &[
    ("loader", "loader.efi"),
    ("kernel", "deepwyrm.elf"),
    ("symbols", "deepwyrm.symbols.elf"),
    ("bootstrap", "bootstrap.elf"),
    ("system_init", "system-init.elf"),
    ("registryd", "registryd.elf"),
    ("devmgr", "devmgr.elf"),
    ("uart16550d", "uart16550d.elf"),
    ("consoled", "consoled.elf"),
    ("wyrmsh", "wyrmsh.elf"),
    ("hello", "hello.elf"),
    ("cpu_hog", "cpu-hog.elf"),
    ("exit_nonzero", "exit-nonzero.elf"),
    ("fault", "fault.elf"),
    ("malformed_elf", "malformed-elf.bin"),
    ("rrc_manifest", "rrc-e7-v1.bin"),
    ("device_manifest", "wrdm-e7-v1.bin"),
    ("launch_policy", "launch-policy-e7-v1.bin"),
    ("boot_device_table", "boot-device-table.bin"),
    ("bootfs", "bootfs.img"),
    ("stack_report", "stack-report.json"),
    ("ovmf_code", "OVMF_CODE.fd"),
    ("ovmf_vars", "OVMF_VARS.fd"),
];

struct ProducedArtifacts {
    directory: PathBuf,
    deep_revision: String,
    abi_revision: String,
    abi_tree: String,
    wyrmroot_revision: String,
    rust_revision: String,
    e6_source_receipt_sha256: String,
    e6_freeze_receipt_sha256: String,
}

pub(crate) fn prepare(
    output: &Path,
    e6_product: &Path,
    deep_repository: &Path,
    deep_revision: &str,
    nonce: &str,
) -> Result<String, Failure> {
    reject_selector_environment()?;
    wyr1c6::validate_revision(deep_revision, "Deepwyrm revision")?;
    wyr1c6::validate_upper_hex_nonzero(nonce, 16, "WYR1-E7 evidence nonce")?;
    if output.exists() {
        return Err(Failure::task("WYR1-E7 output must be a fresh path"));
    }
    let repository = tasks::repository_root()?;
    let project = tasks::canonical_project_root(&repository)?;
    let e6 = crate::wyr1e::immutable_input_for_e7(
        e6_product,
        ACCEPTED_E6_REVISION,
        ACCEPTED_E6_SOURCE_RECEIPT_SHA256,
        ACCEPTED_E6_FREEZE_RECEIPT_SHA256,
    )?;
    let deep_repository = wyr1c6::canonical_deep_repository(deep_repository, &project)?;
    let wyrmroot_revision = wyr1c6::clean_revision(&repository, "Wyrmroot")?;
    wyr1c6::verify_clean_revision(&deep_repository, "Deepwyrm", deep_revision)?;
    let manifest = crate::metadata::BuildManifest::load(&repository)?;
    if manifest.rust_revision()? != wyr1c6::ACCEPTED_RUST_REVISION
        || manifest.rust_toolchain_name()? != wyr1c6::ACCEPTED_TOOLCHAIN_NAME
    {
        return Err(Failure::task(
            "WYR1-E7 source metadata does not name the accepted Rust toolchain",
        ));
    }
    let abi_revision = manifest.deepwyrm_revision()?.to_owned();
    let abi_tree = wyr1c6::matching_abi_tree(&deep_repository, deep_revision, &abi_revision)?;
    let output = wyr1c6::canonical_new_output(output, &project, &repository, &deep_repository)?;
    let temporary = repository.join(".tmp");
    fs::create_dir_all(&temporary).map_err(|error| {
        Failure::task(format!("could not create project temporary root: {error}"))
    })?;
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
        .as_nanos();
    let staging = temporary.join(format!("wyr1e7-producer-{}-{unique}", std::process::id()));
    fs::create_dir(&staging)
        .map_err(|error| Failure::task(format!("could not create WYR1-E7 staging: {error}")))?;
    let result = (|| {
        let produced = build_produced_artifacts(
            &staging,
            &repository,
            &deep_repository,
            &wyrmroot_revision,
            deep_revision,
            &abi_revision,
            &abi_tree,
            nonce,
            &e6,
        )?;
        freeze_produced(&output, &produced, nonce)
    })();
    if result.is_ok() {
        fs::remove_dir_all(&staging)
            .map_err(|error| Failure::task(format!("could not retire WYR1-E7 staging: {error}")))?;
    }
    result
}

/// Inspect the freshly prepared, unconsumed product graph. Once a verified
/// runner has captured a profile or changed its mutable vars, the root
/// post-run recheck owns validation of that runtime state.
pub(crate) fn inspect(output: &Path) -> Result<String, Failure> {
    reject_selector_environment()?;
    wyr1c::reject_e6_ambient_build_environment(env::vars_os())?;
    let repository = tasks::repository_root()?;
    let project = tasks::canonical_project_root(&repository)?;
    let output = canonical_existing_output(output, &project, &repository)?;
    let request_bytes =
        wyr1c6::read_regular_bounded(&output.join("request.toml"), 64 * 1024, "WYR1-E7 request")?;
    let request_text = std::str::from_utf8(&request_bytes)
        .map_err(|_| Failure::task("WYR1-E7 request is not UTF-8"))?;
    let request = parse_scalar_receipt(request_text, "WYR1-E7 request")?;
    if render_request(&request)? != request_text {
        return Err(Failure::task("WYR1-E7 request is not canonical"));
    }
    validate_request_contract(&request)?;
    let revision = wyr1c6::clean_revision(&repository, "Wyrmroot")?;
    if revision != value(&request, "wyrmroot_revision")? {
        return Err(Failure::task("WYR1-E7 source revision changed"));
    }
    let request_hash = sha256::bytes_digest(&request_bytes);
    validate_frozen_output(&output, &request, &request_hash)?;

    let artifacts_directory = output.join("artifacts");
    let mut artifacts = BTreeMap::new();
    for label in wyr1c::E7_ARTIFACT_LABELS {
        let key = label.replace('-', "_");
        artifacts.insert(
            label.to_owned(),
            wyr1c6::read_regular_bounded(
                &output.join(value(&request, &key)?),
                wyr1c6::MAX_ARTIFACT_BYTES,
                label,
            )?,
        );
    }
    let malformed = wyr1c6::read_regular_bounded(
        &output.join(value(&request, "malformed_elf")?),
        64 * 1024,
        "WYR1-E7 malformed ELF",
    )?;
    let assembled = wyr1c::reassemble_e7_snapshot(&revision, &artifacts, &malformed)?;
    for (key, actual) in [
        ("rrc_manifest", assembled.rrc_manifest.as_slice()),
        ("device_manifest", assembled.device_manifest.as_slice()),
        ("launch_policy", assembled.launch_policy.as_slice()),
        ("bootfs", assembled.bootfs.as_slice()),
    ] {
        let frozen = wyr1c6::read_regular_bounded(
            &output.join(value(&request, key)?),
            artifact_maximum(key),
            key,
        )?;
        if frozen != actual {
            return Err(Failure::task(format!(
                "WYR1-E7 {key} failed deterministic reconstruction"
            )));
        }
    }
    let mut inspections = BTreeMap::new();
    for (label, bytes) in &artifacts {
        let digest = sha256::bytes_digest(bytes);
        inspections.insert(
            label.clone(),
            wyr1c::inspect_native_bytes(&repository, bytes, &digest, label)?.into_bytes(),
        );
    }
    let stack_report = wyr1c6::read_regular_bounded(
        &output.join(value(&request, "stack_report")?),
        64 * 1024,
        "WYR1-E7 stack report",
    )?;
    wyr1c::validate_e7_artifact_reports(
        &repository,
        &artifacts,
        &inspections,
        &malformed,
        &stack_report,
    )?;

    validate_esp_contents(&output, &request)?;

    let source_bytes = wyr1c6::read_regular_bounded(
        &output.join(value(&request, "source_receipt")?),
        64 * 1024,
        "WYR1-E7 source receipt",
    )?;
    let source_text = std::str::from_utf8(&source_bytes)
        .map_err(|_| Failure::task("WYR1-E7 source receipt is not UTF-8"))?;
    parse_scalar_receipt(source_text, "WYR1-E7 source receipt")?;
    if sha256::bytes_digest(&source_bytes) != value(&request, "source_receipt_sha256")? {
        return Err(Failure::task(
            "WYR1-E7 source receipt does not match the request",
        ));
    }
    let manifest = crate::metadata::BuildManifest::load(&repository)?;
    if value(&request, "rust_revision")? != manifest.rust_revision()?
        || value(&request, "generated_abi_revision")? != manifest.deepwyrm_revision()?
    {
        return Err(Failure::task(
            "WYR1-E7 request does not match current source metadata",
        ));
    }
    let deep_repository = local_deep_repository(&project)?;
    let abi_tree = wyr1c6::matching_abi_tree(
        &deep_repository,
        value(&request, "deepwyrm_revision")?,
        value(&request, "generated_abi_revision")?,
    )?;
    if abi_tree != value(&request, "generated_abi_tree")? {
        return Err(Failure::task("WYR1-E7 generated ABI tree changed"));
    }
    let profile = manifest.validate_loader_build_readiness(&repository)?;
    let toolchain = tasks::prepare_loader_toolchain(&repository, &profile, &manifest)?;
    let expected_source = render_source_receipt(
        &manifest,
        toolchain.accepted(),
        value(&request, "deepwyrm_revision")?,
        value(&request, "generated_abi_revision")?,
        value(&request, "generated_abi_tree")?,
        &revision,
        value(&request, "evidence_nonce")?,
        &artifacts_directory,
        &assembled.generation,
    )?;
    if source_text != expected_source {
        return Err(Failure::task("WYR1-E7 source receipt is not canonical"));
    }
    let expected_receipt = render_freeze_receipt(&request_hash, &request)?;
    let receipt = wyr1c6::read_regular_bounded(
        &output.join("freeze-receipt.toml"),
        64 * 1024,
        "WYR1-E7 freeze receipt",
    )?;
    if receipt != expected_receipt.as_bytes() {
        return Err(Failure::task("WYR1-E7 freeze receipt is not canonical"));
    }
    Ok(format!(
        "WYR1_E7_INSPECT_PASS selector={SELECTOR} test_id={TEST_ID} evidence={EVIDENCE_PROTOCOL} wyrmroot_revision={revision} bootfs_sha256={}\n",
        sha256::bytes_digest(&assembled.bootfs),
    ))
}

fn validate_esp_contents(output: &Path, request: &BTreeMap<String, String>) -> Result<(), Failure> {
    let esp_arguments = G3ImageArguments {
        image: output.join(value(request, "esp")?).display().to_string(),
        loader: output.join(value(request, "loader")?).display().to_string(),
        kernel: output.join(value(request, "kernel")?).display().to_string(),
        bootstrap: output
            .join(value(request, "bootstrap")?)
            .display()
            .to_string(),
        bootfs: output.join(value(request, "bootfs")?).display().to_string(),
    };
    g3_image::inspect_d6(
        &esp_arguments,
        &output
            .join(value(request, "boot_device_table")?)
            .display()
            .to_string(),
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_produced_artifacts(
    staging: &Path,
    repository: &Path,
    deep_repository: &Path,
    wyrmroot_revision: &str,
    deep_revision: &str,
    abi_revision: &str,
    abi_tree: &str,
    nonce: &str,
    e6: &crate::wyr1e::ImmutableE6Input,
) -> Result<ProducedArtifacts, Failure> {
    let manifest = crate::metadata::BuildManifest::load(repository)?;
    let profile = manifest.validate_loader_build_readiness(repository)?;
    let layout = crate::deep_layout::prepare(
        repository,
        manifest.deepwyrm_repository()?,
        manifest.deepwyrm_revision()?,
    )?;
    let toolchain = tasks::prepare_loader_toolchain(repository, &profile, &manifest)?;
    let cargo_home = tasks::project_cargo_home(repository, &manifest)?;
    if env::var_os("CARGO_HOME").as_deref() != Some(cargo_home.as_os_str()) {
        return Err(Failure::task(
            "WYR1-E7 prepare requires the pinned launcher's exact CARGO_HOME",
        ));
    }
    toolchain.accepted().verify_unchanged()?;
    layout.verify_unchanged()?;
    let build = staging.join("build");
    fs::create_dir(&build)
        .map_err(|error| Failure::task(format!("could not create WYR1-E7 build root: {error}")))?;
    let uefi = tasks::build_deterministic_uefi_pair(
        repository,
        &toolchain,
        &profile,
        &layout,
        &tasks::IsolatedUefiBuild {
            cargo_home: &cargo_home,
            production_target: &build.join("uefi-production"),
            retained_debug_target: &build.join("uefi-retained-debug"),
            cargo_profile: tasks::UefiCargoProfile::Release,
        },
    )?;
    let build_directory = Directory::open_exact(&build, "WYR1-E7 build directory")?;
    let bootstrap =
        build_directory.with_inheritable_anchor("WYR1-E7 build directory", |anchor| {
            crate::dw1e3a::build_bootstrap(repository, &toolchain, &layout, &cargo_home, anchor)
        })?;
    let snapshot = crate::wyr1c::build_e7_snapshot(nonce, &e6.product)?;
    let kernel = build_kernel(deep_repository, nonce)?;
    let boot_device_table = wyr1c6::boot_device_table();
    let ovmf_code = wyr1c6::pinned_firmware(
        wyr1c6::OVMF_CODE_PATH,
        wyr1c6::OVMF_CODE_SHA256,
        "OVMF code",
    )?;
    let ovmf_vars = wyr1c6::pinned_firmware(
        wyr1c6::OVMF_VARS_PATH,
        wyr1c6::OVMF_VARS_SHA256,
        "OVMF vars",
    )?;
    let artifacts = staging.join("artifacts");
    fs::create_dir(&artifacts)
        .map_err(|error| Failure::task(format!("could not create WYR1-E7 artifacts: {error}")))?;
    let artifact = |name: &str| {
        snapshot
            .artifacts
            .get(name)
            .ok_or_else(|| Failure::task(format!("WYR1-E7 builder omitted {name}")))
    };
    for (name, bytes) in [
        ("loader.efi", &uefi.loader_bytes),
        ("deepwyrm.elf", &kernel),
        ("deepwyrm.symbols.elf", &kernel),
        ("bootstrap.elf", &bootstrap),
        ("system-init.elf", artifact("system-init")?),
        ("registryd.elf", artifact("registryd")?),
        ("devmgr.elf", artifact("devmgr")?),
        ("uart16550d.elf", artifact("uart16550d")?),
        ("consoled.elf", artifact("consoled")?),
        ("wyrmsh.elf", artifact("wyrmsh")?),
        ("hello.elf", artifact("hello")?),
        ("cpu-hog.elf", artifact("cpu-hog")?),
        ("exit-nonzero.elf", artifact("exit-nonzero")?),
        ("fault.elf", artifact("fault")?),
        ("malformed-elf.bin", &snapshot.malformed_elf),
        ("rrc-e7-v1.bin", &snapshot.rrc_manifest),
        ("wrdm-e7-v1.bin", &snapshot.device_manifest),
        ("launch-policy-e7-v1.bin", &snapshot.launch_policy),
        ("boot-device-table.bin", &boot_device_table),
        ("bootfs.img", &snapshot.bootfs),
        ("stack-report.json", &snapshot.stack_report),
        ("OVMF_CODE.fd", &ovmf_code),
        ("OVMF_VARS.fd", &ovmf_vars),
    ] {
        wyr1c6::write_new(&artifacts.join(name), bytes, name)?;
    }
    wyr1c6::write_new(
        &artifacts.join("e6-source-build.toml"),
        &e6.source_receipt,
        "WYR1-E7 inherited E6 source receipt",
    )?;
    wyr1c6::write_new(
        &artifacts.join("e6-freeze-receipt.toml"),
        &e6.freeze_receipt,
        "WYR1-E7 inherited E6 freeze receipt",
    )?;
    let source = render_source_receipt(
        &manifest,
        toolchain.accepted(),
        deep_revision,
        abi_revision,
        abi_tree,
        wyrmroot_revision,
        nonce,
        &artifacts,
        &snapshot.generation,
    )?;
    wyr1c6::write_new(
        &artifacts.join(SOURCE_RECEIPT),
        source.as_bytes(),
        "WYR1-E7 source receipt",
    )?;
    toolchain.accepted().verify_unchanged()?;
    layout.verify_unchanged()?;
    wyr1c6::verify_clean_revision(repository, "Wyrmroot", wyrmroot_revision)?;
    wyr1c6::verify_clean_revision(deep_repository, "Deepwyrm", deep_revision)?;
    Ok(ProducedArtifacts {
        directory: artifacts,
        deep_revision: deep_revision.to_owned(),
        abi_revision: abi_revision.to_owned(),
        abi_tree: abi_tree.to_owned(),
        wyrmroot_revision: wyrmroot_revision.to_owned(),
        rust_revision: manifest.rust_revision()?.to_owned(),
        e6_source_receipt_sha256: sha256::bytes_digest(&e6.source_receipt),
        e6_freeze_receipt_sha256: sha256::bytes_digest(&e6.freeze_receipt),
    })
}

fn build_kernel(repository: &Path, nonce: &str) -> Result<Vec<u8>, Failure> {
    let repository = Directory::open_exact(repository, "Deepwyrm source root")?;
    let build = fresh_kernel_target(&repository)?;
    // The pinned launcher initializes only an empty Cargo target directory.
    // Keep diagnostics alongside it so failures retain their original output.
    let target = build.create_child("target", 0o700, "WYR1-E7 Cargo target")?;
    let stdout = build.create_file("cargo.stdout.log", 0o600, "WYR1-E7 kernel stdout")?;
    let stderr = build.create_file("cargo.stderr.log", 0o600, "WYR1-E7 kernel stderr")?;
    let status = kernel_build_command(
        &repository.path().join("tools/pinned-cargo"),
        repository.path(),
        target.path(),
        nonce,
    )
    .stdout(Stdio::from(stdout))
    .stderr(Stdio::from(stderr))
    .status()
    .map_err(|error| Failure::task(format!("could not build WYR1-E7 kernel: {error}")))?;
    if !status.success() {
        return Err(Failure::task(format!(
            "WYR1-E7 selector-33 Deepwyrm kernel build failed; logs preserved in {}",
            build.path().display()
        )));
    }
    target.read_producer(
        &PathBuf::from(KERNEL_TARGET).join("release/deepwyrm-kernel"),
        wyr1c6::MAX_ARTIFACT_BYTES,
        "selector-33 kernel",
    )
}

fn fresh_kernel_target(repository: &Directory) -> Result<Directory, Failure> {
    let temporary = match repository.open_child(".tmp", "Deepwyrm temporary root") {
        Ok(directory) => directory,
        Err(_) => repository.create_child(".tmp", 0o700, "Deepwyrm temporary root")?,
    };
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
        .as_nanos();
    temporary.create_child(
        &format!("wyr1e7-kernel-{}-{unique}", std::process::id()),
        0o700,
        "WYR1-E7 kernel target",
    )
}

fn kernel_build_command(
    pinned_cargo: &Path,
    repository: &Path,
    target: &Path,
    nonce: &str,
) -> Command {
    let mut command = Command::new(pinned_cargo);
    command
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
        .env("DEEPWYRM_WYR1E7_EVIDENCE_NONCE", nonce)
        .env_remove("DEEPWYRM_WYR1D_EVIDENCE_NONCE")
        .env_remove("DEEPWYRM_DW1E_EVIDENCE_NONCE")
        .env_remove("DEEPWYRM_DW1E_E3B_FULL")
        .env_remove("WYRMROOT_DW1E3_CHALLENGE_1_NONCE")
        .env_remove("WYRMROOT_DW1E3_CHALLENGE_2_NONCE")
        .env_remove("CARGO_HOME")
        .env_remove("LD_AUDIT")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD")
        .current_dir(repository)
        .stdin(Stdio::null());
    command
}

#[allow(clippy::too_many_arguments)]
fn render_source_receipt(
    manifest: &crate::metadata::BuildManifest,
    toolchain: &crate::toolchain_artifact::AcceptedToolchain,
    deep_revision: &str,
    abi_revision: &str,
    abi_tree: &str,
    wyrmroot_revision: &str,
    nonce: &str,
    artifacts: &Path,
    generation: &[u8; 32],
) -> Result<String, Failure> {
    let mut values = BTreeMap::new();
    for (key, value) in [
        ("kind", SOURCE_RECEIPT_KIND.to_owned()),
        ("schema_version", "1".to_owned()),
        ("selector", SELECTOR.to_owned()),
        ("test_id", TEST_ID.to_owned()),
        ("evidence_protocol", EVIDENCE_PROTOCOL.to_owned()),
        ("deepwyrm_revision", deep_revision.to_owned()),
        ("generated_abi_revision", abi_revision.to_owned()),
        ("generated_abi_tree", abi_tree.to_owned()),
        ("wyrmroot_revision", wyrmroot_revision.to_owned()),
        ("e6_wyrmroot_revision", ACCEPTED_E6_REVISION.to_owned()),
        (
            "e6_source_receipt_sha256",
            ACCEPTED_E6_SOURCE_RECEIPT_SHA256.to_owned(),
        ),
        (
            "e6_freeze_receipt_sha256",
            ACCEPTED_E6_FREEZE_RECEIPT_SHA256.to_owned(),
        ),
        ("rust_revision", manifest.rust_revision()?.to_owned()),
        (
            "rustc_sha256",
            sha256::file_digest(&toolchain.rustc).map_err(|error| {
                Failure::task(format!("could not hash accepted rustc: {error}"))
            })?,
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
        (
            "rust_toolchain_name",
            manifest.rust_toolchain_name()?.to_owned(),
        ),
        ("evidence_nonce", nonce.to_owned()),
        ("boot_generation", hex_digest(generation)),
        (
            "loader_command",
            "canonical deterministic release UEFI loader pair".to_owned(),
        ),
        (
            "kernel_command",
            "tools/pinned-cargo target build --locked --offline --release --target x86_64-unknown-none --package deepwyrm-kernel --bin deepwyrm-kernel --features test-support [selector=interactive-wyrmsh nonce=validated]".to_owned(),
        ),
        (
            "bootstrap_command",
            "canonical DW1-E3A native bootstrap build".to_owned(),
        ),
        ("bootstrap_features", "wyr1c5-production".to_owned()),
        (
            "bootfs_command",
            "in-process wyrmroot-bootfs build_e7 exact 16-entry archive".to_owned(),
        ),
        (
            "esp_command",
            "canonical g3_image build_d6 selector33 ESP with explicit boot device table"
                .to_owned(),
        ),
        (
            "malformed_elf_literal",
            "WYR1-E7 malformed ELF\\n".to_owned(),
        ),
        (
            "malformed_elf_command",
            "literal ASCII WYR1-E7 malformed ELF followed by LF".to_owned(),
        ),
    ] {
        values.insert(key.to_owned(), value);
    }
    for label in crate::wyr1c::E7_ARTIFACT_LABELS {
        let command = crate::wyr1c::e7_native_command(label)?;
        values.insert(
            format!("{}_features", label.replace('-', "_")),
            crate::wyr1c::e7_native_features(label)?.to_owned(),
        );
        values.insert(
            format!("{}_command", label.replace('-', "_")),
            if matches!(label, "system-init" | "cpu-hog" | "exit-nonzero" | "fault") {
                command
            } else {
                format!("inherited E6 revision {ACCEPTED_E6_REVISION}: {command}")
            },
        );
    }
    for (key, name) in ARTIFACTS {
        values.insert(
            format!("{key}_sha256"),
            sha256::bytes_digest(&wyr1c6::read_regular_bounded(
                &artifacts.join(name),
                artifact_maximum(key),
                key,
            )?),
        );
    }
    render_source_fields(&values)
}

fn local_deep_repository(project: &Path) -> Result<PathBuf, Failure> {
    // Build metadata names the upstream Git URL, not a filesystem checkout.
    wyr1c6::canonical_deep_repository(&project.join("deepwyrm"), project)
}

fn render_source_fields(values: &BTreeMap<String, String>) -> Result<String, Failure> {
    render_dynamic(
        values,
        &source_receipt_keys(),
        &["schema_version", "test_id"],
        "WYR1-E7 source receipt",
    )
}

fn source_receipt_keys() -> Vec<String> {
    let mut keys = vec![
        "kind",
        "schema_version",
        "selector",
        "test_id",
        "evidence_protocol",
        "deepwyrm_revision",
        "generated_abi_revision",
        "generated_abi_tree",
        "wyrmroot_revision",
        "e6_wyrmroot_revision",
        "e6_source_receipt_sha256",
        "e6_freeze_receipt_sha256",
        "rust_revision",
        "evidence_nonce",
        "boot_generation",
        "rust_toolchain_name",
        "rustc_sha256",
        "cargo_sha256",
        "rust_lld_sha256",
        "toolchain_manifest_sha256",
        "toolchain_tree_sha256",
        "loader_command",
        "kernel_command",
        "bootstrap_command",
        "bootstrap_features",
        "system_init_command",
        "system_init_features",
        "registryd_command",
        "registryd_features",
        "devmgr_command",
        "devmgr_features",
        "uart16550d_command",
        "uart16550d_features",
        "consoled_command",
        "consoled_features",
        "wyrmsh_command",
        "wyrmsh_features",
        "hello_command",
        "hello_features",
        "cpu_hog_command",
        "cpu_hog_features",
        "exit_nonzero_command",
        "exit_nonzero_features",
        "fault_command",
        "fault_features",
        "bootfs_command",
        "esp_command",
        "malformed_elf_literal",
        "malformed_elf_command",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    for (key, _) in ARTIFACTS {
        keys.push(format!("{key}_sha256"));
    }
    keys
}

fn freeze_produced(
    output: &Path,
    produced: &ProducedArtifacts,
    nonce: &str,
) -> Result<String, Failure> {
    if output.exists() {
        return Err(Failure::task("WYR1-E7 output must be a fresh path"));
    }
    fs::create_dir(output)
        .map_err(|error| Failure::task(format!("could not create WYR1-E7 output: {error}")))?;
    let frozen = output.join("artifacts");
    fs::create_dir(&frozen)
        .map_err(|error| Failure::task(format!("could not create WYR1-E7 artifacts: {error}")))?;
    let mut fields = BTreeMap::new();
    for (key, name) in ARTIFACTS {
        let bytes = wyr1c6::read_regular_bounded(
            &produced.directory.join(name),
            artifact_maximum(key),
            key,
        )?;
        wyr1c6::write_new(&frozen.join(name), &bytes, key)?;
        fields.insert((*key).to_owned(), format!("artifacts/{name}"));
        fields.insert(format!("{key}_sha256"), sha256::bytes_digest(&bytes));
    }
    for name in ["e6-source-build.toml", "e6-freeze-receipt.toml"] {
        let bytes = wyr1c6::read_regular_bounded(
            &produced.directory.join(name),
            64 * 1024,
            "WYR1-E7 inherited E6 receipt",
        )?;
        wyr1c6::write_new(&frozen.join(name), &bytes, "WYR1-E7 inherited E6 receipt")?;
    }
    let source = wyr1c6::read_regular_bounded(
        &produced.directory.join(SOURCE_RECEIPT),
        64 * 1024,
        "WYR1-E7 source receipt",
    )?;
    wyr1c6::write_new(
        &frozen.join(SOURCE_RECEIPT),
        &source,
        "WYR1-E7 source receipt",
    )?;
    fields.insert(
        "source_receipt".into(),
        format!("artifacts/{SOURCE_RECEIPT}"),
    );
    fields.insert(
        "source_receipt_sha256".into(),
        sha256::bytes_digest(&source),
    );
    build_esp(output, &fields)?;
    let esp = frozen.join("selector33-esp.img");
    wyr1c6::seal_mode(&esp, 0o444, "WYR1-E7 ESP")?;
    fields.insert("esp".into(), "artifacts/selector33-esp.img".into());
    fields.insert(
        "esp_sha256".into(),
        sha256::bytes_digest(&wyr1c6::read_regular_bounded(
            &esp,
            g3_image::IMAGE_BYTES,
            "WYR1-E7 ESP",
        )?),
    );
    for (key, value) in [
        ("kind", REQUEST_KIND.to_owned()),
        ("schema_version", "1".to_owned()),
        ("selector", SELECTOR.to_owned()),
        ("test_id", TEST_ID.to_owned()),
        ("profile", "wyr1e7-selector33".to_owned()),
        ("scenario", "interactive-wyrmsh".to_owned()),
        ("evidence_protocol", EVIDENCE_PROTOCOL.to_owned()),
        ("full_evidence", "true".to_owned()),
        (
            "acceptance_claim",
            "full-selector33-interactive-wyrmsh".to_owned(),
        ),
        ("terminal_line", "DWTEST1 33 0".to_owned()),
        ("com2_prelude_kind", COM2_PRELUDE_KIND.to_owned()),
        ("com2_prelude_length", COM2_PRELUDE_LENGTH.to_owned()),
        ("com2_prelude_sha256", COM2_PRELUDE_SHA256.to_owned()),
        ("deepwyrm_revision", produced.deep_revision.clone()),
        ("generated_abi_revision", produced.abi_revision.clone()),
        ("generated_abi_tree", produced.abi_tree.clone()),
        ("wyrmroot_revision", produced.wyrmroot_revision.clone()),
        ("e6_wyrmroot_revision", ACCEPTED_E6_REVISION.to_owned()),
        (
            "e6_source_receipt_sha256",
            produced.e6_source_receipt_sha256.clone(),
        ),
        (
            "e6_freeze_receipt_sha256",
            produced.e6_freeze_receipt_sha256.clone(),
        ),
        ("rust_revision", produced.rust_revision.clone()),
        ("evidence_nonce", nonce.to_owned()),
        ("default_handoff", "default/handoff.toml".to_owned()),
        ("smp_handoff", "smp/handoff.toml".to_owned()),
        ("profile_pair", "profile-pair.toml".to_owned()),
        ("receipt", "freeze-receipt.toml".to_owned()),
        ("result_schema", "result-schema.toml".to_owned()),
    ] {
        fields.insert(key.to_owned(), value);
    }
    let request = render_request(&fields)?;
    wyr1c6::write_new(
        &output.join("request.toml"),
        request.as_bytes(),
        "WYR1-E7 request",
    )?;
    let request_hash = sha256::bytes_digest(request.as_bytes());
    let result_schema = render_result_schema()?;
    wyr1c6::write_new(
        &output.join("result-schema.toml"),
        result_schema.as_bytes(),
        "WYR1-E7 result schema",
    )?;
    for (profile, vcpus) in [("default", 1), ("smp", 4)] {
        stage_profile(output, profile, vcpus, &request_hash, &fields)?;
    }
    write_pair(output, &request_hash)?;
    wyr1c6::write_new(
        &output.join("freeze-receipt.toml"),
        render_freeze_receipt(&request_hash, &fields)?.as_bytes(),
        "WYR1-E7 freeze receipt",
    )?;
    validate_request_contract(&fields)?;
    validate_frozen_output(output, &fields, &request_hash)?;
    Ok(format!(
        "WYR1_E7_PREPARE_PASS selector={SELECTOR} test_id={TEST_ID} evidence={EVIDENCE_PROTOCOL} request={} default_handoff={} smp_handoff={} profile_pair={} terminal=DWTEST1-33-0\n",
        output.join("request.toml").display(),
        output.join("default/handoff.toml").display(),
        output.join("smp/handoff.toml").display(),
        output.join("profile-pair.toml").display(),
    ))
}

fn build_esp(output: &Path, values: &BTreeMap<String, String>) -> Result<(), Failure> {
    let arguments = G3ImageArguments {
        image: output
            .join("artifacts/selector33-esp.img")
            .display()
            .to_string(),
        loader: output.join(value(values, "loader")?).display().to_string(),
        kernel: output.join(value(values, "kernel")?).display().to_string(),
        bootstrap: output
            .join(value(values, "bootstrap")?)
            .display()
            .to_string(),
        bootfs: output.join(value(values, "bootfs")?).display().to_string(),
    };
    g3_image::build_d6(
        &arguments,
        &output
            .join(value(values, "boot_device_table")?)
            .display()
            .to_string(),
    )?;
    Ok(())
}

fn stage_profile(
    output: &Path,
    profile: &str,
    vcpus: u8,
    request_hash: &str,
    request: &BTreeMap<String, String>,
) -> Result<(), Failure> {
    let directory = output.join(profile);
    fs::create_dir(&directory)
        .map_err(|error| Failure::task(format!("could not create WYR1-E7 {profile}: {error}")))?;
    let vars = wyr1c6::read_regular_bounded(
        &output.join(value(request, "ovmf_vars")?),
        wyr1c6::MAX_FIRMWARE_BYTES,
        "WYR1-E7 OVMF vars",
    )?;
    let vars_path = directory.join("OVMF_VARS.mutable.fd");
    wyr1c6::write_new_mode(&vars_path, &vars, 0o600, "WYR1-E7 mutable OVMF vars")?;
    let xml = expected_profile_xml(output, profile, vcpus, request)?;
    wyr1c6::write_new(
        &directory.join("domain.xml"),
        xml.as_bytes(),
        "WYR1-E7 domain XML",
    )?;
    let fields = expected_handoff_fields(profile, vcpus, request_hash, request, &xml, &vars)?;
    let keys = handoff_keys();
    wyr1c6::write_new(
        &directory.join("handoff.toml"),
        render_handoff(&fields, &keys)?.as_bytes(),
        "WYR1-E7 handoff",
    )
}

fn expected_profile_xml(
    output: &Path,
    profile: &str,
    vcpus: u8,
    request: &BTreeMap<String, String>,
) -> Result<String, Failure> {
    let absolute = fs::canonicalize(output)
        .map_err(|error| Failure::task(format!("could not resolve WYR1-E7 output: {error}")))?;
    Ok(crate::dw1e3a::selected_domain_xml(
        vcpus,
        &absolute.join(value(request, "ovmf_code")?),
        &absolute.join(value(request, "esp")?),
        &absolute.join(profile).join("OVMF_VARS.mutable.fd"),
        &absolute.join(profile).join("com2.sock"),
        (SELECTOR, TEST_ID),
    ))
}

#[allow(clippy::too_many_arguments)]
fn expected_handoff_fields(
    profile: &str,
    vcpus: u8,
    request_hash: &str,
    request: &BTreeMap<String, String>,
    xml: &str,
    vars: &[u8],
) -> Result<BTreeMap<String, String>, Failure> {
    let mut fields = BTreeMap::new();
    for (key, field) in [
        ("kind", HANDOFF_KIND),
        ("schema_version", "1"),
        ("profile", profile),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("full_evidence", "true"),
        ("acceptance_claim", "full-selector33-interactive-wyrmsh"),
        ("terminal_line", "DWTEST1 33 0"),
        ("com2_prelude_kind", COM2_PRELUDE_KIND),
        ("com2_prelude_length", COM2_PRELUDE_LENGTH),
        ("com2_prelude_sha256", COM2_PRELUDE_SHA256),
        ("request", "request.toml"),
        ("request_sha256", request_hash),
        ("esp", value(request, "esp")?),
        ("esp_sha256", value(request, "esp_sha256")?),
        ("vcpus", if vcpus == 1 { "1" } else { "4" }),
        ("memory_mib", "2048"),
        ("machine", MACHINE),
        ("firmware", "OVMF"),
        ("timeout_seconds", TIMEOUT_SECONDS),
        ("scenario", "interactive-wyrmsh"),
        ("physical_io", "real-com2-irq3-required"),
        (
            "terminal_authority",
            "system-init-selector33-wre1-controller",
        ),
        ("com1_role", "trusted-wre1-evidence-and-terminal"),
        ("com2_role", "interactive-wyrmsh-byte-stream"),
        ("com2_transport", "unix-socket-byte-stream"),
        ("com2_socket_mode", "connect"),
        ("com2_socket_owner", "runner"),
        ("com1_fd_group", COM1_FD_GROUP),
        ("com2_fd_group", COM2_FD_GROUP),
        ("esp_fd_group", ESP_FD_GROUP),
        ("vars_fd_group", VARS_FD_GROUP),
        ("domain_xml", &format!("{profile}/domain.xml")),
        ("domain_xml_sha256", &sha256::bytes_digest(xml.as_bytes())),
        (
            "mutable_ovmf_vars",
            &format!("{profile}/OVMF_VARS.mutable.fd"),
        ),
        (
            "mutable_ovmf_vars_initial_sha256",
            &sha256::bytes_digest(vars),
        ),
        ("com2_socket", &format!("{profile}/com2.sock")),
        ("com1_serial_log", &format!("{profile}/com1.log")),
        ("com2_log", &format!("{profile}/com2.bin")),
        ("evidence_log", &format!("{profile}/evidence.bin")),
        ("result_path", &format!("{profile}/result.toml")),
        (
            "acceptance_receipt",
            &format!("{profile}/acceptance-receipt.toml"),
        ),
        ("result_schema", "result-schema.toml"),
        ("evidence_nonce", value(request, "evidence_nonce")?),
    ] {
        fields.insert(key.to_owned(), field.to_owned());
    }
    for (key, _) in ARTIFACTS {
        fields.insert(format!("{key}_path"), value(request, key)?.to_owned());
        fields.insert(
            format!("{key}_sha256"),
            value(request, &format!("{key}_sha256"))?.to_owned(),
        );
    }
    Ok(fields)
}

fn render_handoff(fields: &BTreeMap<String, String>, keys: &[String]) -> Result<String, Failure> {
    render_dynamic(
        fields,
        keys,
        &[
            "schema_version",
            "test_id",
            "vcpus",
            "memory_mib",
            "timeout_seconds",
            "com2_prelude_length",
        ],
        "WYR1-E7 handoff",
    )
}

fn write_pair(output: &Path, request_hash: &str) -> Result<(), Failure> {
    let fields = expected_pair_fields(output, request_hash)?;
    wyr1c6::write_new(
        &output.join("profile-pair.toml"),
        render_pair(&fields)?.as_bytes(),
        "WYR1-E7 profile pair",
    )
}

fn expected_pair_fields(
    output: &Path,
    request_hash: &str,
) -> Result<BTreeMap<String, String>, Failure> {
    let mut fields = BTreeMap::new();
    for (key, value) in [
        ("kind", PAIR_KIND),
        ("schema_version", "1"),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("full_evidence", "true"),
        ("acceptance_claim", "full-selector33-interactive-wyrmsh"),
        ("request", "request.toml"),
        ("request_sha256", request_hash),
        ("profiles", "default,smp"),
        ("default_handoff", "default/handoff.toml"),
        ("default_vcpus", "1"),
        ("smp_handoff", "smp/handoff.toml"),
        ("smp_vcpus", "4"),
        ("memory_mib", "2048"),
        ("machine", MACHINE),
        ("firmware", "OVMF"),
        ("timeout_seconds", TIMEOUT_SECONDS),
        ("result_schema", "result-schema.toml"),
    ] {
        fields.insert(key.to_owned(), value.to_owned());
    }
    for (key, path) in [
        (
            "default_handoff_sha256",
            output.join("default/handoff.toml"),
        ),
        ("smp_handoff_sha256", output.join("smp/handoff.toml")),
    ] {
        fields.insert(
            key.to_owned(),
            sha256::bytes_digest(&wyr1c6::read_regular_bounded(
                &path,
                64 * 1024,
                "WYR1-E7 handoff",
            )?),
        );
    }
    Ok(fields)
}

fn render_pair(fields: &BTreeMap<String, String>) -> Result<String, Failure> {
    render(
        fields,
        &pair_keys(),
        &[
            "schema_version",
            "test_id",
            "default_vcpus",
            "smp_vcpus",
            "memory_mib",
            "timeout_seconds",
        ],
        "WYR1-E7 profile pair",
    )
}

fn pair_keys() -> [&'static str; 21] {
    [
        "kind",
        "schema_version",
        "selector",
        "test_id",
        "evidence_protocol",
        "full_evidence",
        "acceptance_claim",
        "request",
        "request_sha256",
        "profiles",
        "default_handoff",
        "default_handoff_sha256",
        "default_vcpus",
        "smp_handoff",
        "smp_handoff_sha256",
        "smp_vcpus",
        "memory_mib",
        "machine",
        "firmware",
        "timeout_seconds",
        "result_schema",
    ]
}

fn render_request(values: &BTreeMap<String, String>) -> Result<String, Failure> {
    for (key, expected) in [
        ("kind", REQUEST_KIND),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("full_evidence", "true"),
        ("acceptance_claim", "full-selector33-interactive-wyrmsh"),
        ("terminal_line", "DWTEST1 33 0"),
        ("com2_prelude_kind", COM2_PRELUDE_KIND),
        ("com2_prelude_length", COM2_PRELUDE_LENGTH),
        ("com2_prelude_sha256", COM2_PRELUDE_SHA256),
    ] {
        if value(values, key)? != expected {
            return Err(Failure::task(format!("WYR1-E7 {key} drifted")));
        }
    }
    let keys = request_keys();
    render_dynamic(
        values,
        &keys,
        &["schema_version", "test_id", "com2_prelude_length"],
        "WYR1-E7 request",
    )
}

fn render_freeze_receipt(
    request_hash: &str,
    request: &BTreeMap<String, String>,
) -> Result<String, Failure> {
    let mut receipt = BTreeMap::new();
    for (key, value) in [
        ("kind", RECEIPT_KIND),
        ("schema_version", "1"),
        ("request_sha256", request_hash),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("scenario", "interactive-wyrmsh"),
        ("full_evidence", "true"),
        ("acceptance_claim", "full-selector33-interactive-wyrmsh"),
        ("terminal_line", "DWTEST1 33 0"),
        ("com2_prelude_kind", COM2_PRELUDE_KIND),
        ("com2_prelude_length", COM2_PRELUDE_LENGTH),
        ("com2_prelude_sha256", COM2_PRELUDE_SHA256),
        (
            "source_receipt_sha256",
            value(request, "source_receipt_sha256")?,
        ),
        ("esp_sha256", value(request, "esp_sha256")?),
    ] {
        receipt.insert(key.to_owned(), value.to_owned());
    }
    for (label, _) in ARTIFACTS {
        receipt.insert(
            format!("{label}_sha256"),
            value(request, &format!("{label}_sha256"))?.to_owned(),
        );
    }
    let mut keys = [
        "kind",
        "schema_version",
        "request_sha256",
        "selector",
        "test_id",
        "evidence_protocol",
        "scenario",
        "full_evidence",
        "acceptance_claim",
        "terminal_line",
        "com2_prelude_kind",
        "com2_prelude_length",
        "com2_prelude_sha256",
        "source_receipt_sha256",
        "esp_sha256",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    for (label, _) in ARTIFACTS {
        keys.push(format!("{label}_sha256"));
    }
    render_dynamic(
        &receipt,
        &keys,
        &["schema_version", "test_id", "com2_prelude_length"],
        "WYR1-E7 freeze receipt",
    )
}

fn render_result_schema() -> Result<String, Failure> {
    let keys = [
        "kind",
        "schema_version",
        "profile",
        "request_sha256",
        "handoff_sha256",
        "selector",
        "test_id",
        "evidence_protocol",
        "evidence_nonce",
        "evidence_records",
        "evidence_sha256",
        "terminal_line",
        "terminal_qemu_exit",
        "com1_sha256",
        "com2_accepted_length",
        "com2_accepted_sha256",
        "shutdown_byte_hex",
        "com2_full_length",
        "com2_full_sha256",
        "source_receipt_sha256",
        "esp_sha256",
        "bootfs_sha256",
        "effective_vcpus",
        "acceptance",
        "console_generation",
        "status_generation",
        "shell_generation",
        "outer_launch_transaction",
        "outer_job_id",
        "registry_generation",
        "registry_endpoint_id",
        "registry_endpoint_generation",
        "shell_jobs_connection_id",
        "shell_jobs_generation",
    ];
    let mut values = BTreeMap::new();
    for key in keys {
        values.insert(
            key.to_owned(),
            match key {
                "kind" => RESULT_KIND.to_owned(),
                "schema_version" => "1".to_owned(),
                "selector" => SELECTOR.to_owned(),
                "test_id" => TEST_ID.to_owned(),
                "evidence_protocol" => EVIDENCE_PROTOCOL.to_owned(),
                "terminal_line" => "DWTEST1 33 0".to_owned(),
                "shutdown_byte_hex" => "04".to_owned(),
                "acceptance" => "pass".to_owned(),
                _ => format!("<runner:{key}>"),
            },
        );
    }
    render(&values, &keys, &[], "WYR1-E7 result schema")
}

fn request_keys() -> Vec<String> {
    let mut keys = [
        "kind",
        "schema_version",
        "selector",
        "test_id",
        "profile",
        "scenario",
        "evidence_protocol",
        "full_evidence",
        "acceptance_claim",
        "terminal_line",
        "com2_prelude_kind",
        "com2_prelude_length",
        "com2_prelude_sha256",
        "deepwyrm_revision",
        "generated_abi_revision",
        "generated_abi_tree",
        "wyrmroot_revision",
        "e6_wyrmroot_revision",
        "e6_source_receipt_sha256",
        "e6_freeze_receipt_sha256",
        "rust_revision",
        "evidence_nonce",
        "esp",
        "esp_sha256",
        "default_handoff",
        "smp_handoff",
        "profile_pair",
        "receipt",
        "source_receipt",
        "source_receipt_sha256",
        "result_schema",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    for (key, _) in ARTIFACTS {
        keys.push((*key).to_owned());
        keys.push(format!("{key}_sha256"));
    }
    keys
}

fn handoff_keys() -> Vec<String> {
    let mut keys = [
        "kind",
        "schema_version",
        "profile",
        "selector",
        "test_id",
        "evidence_protocol",
        "full_evidence",
        "acceptance_claim",
        "terminal_line",
        "com2_prelude_kind",
        "com2_prelude_length",
        "com2_prelude_sha256",
        "request",
        "request_sha256",
        "esp",
        "esp_sha256",
        "vcpus",
        "memory_mib",
        "machine",
        "firmware",
        "timeout_seconds",
        "scenario",
        "physical_io",
        "terminal_authority",
        "com1_role",
        "com2_role",
        "com2_transport",
        "com2_socket_mode",
        "com2_socket_owner",
        "com1_fd_group",
        "com2_fd_group",
        "esp_fd_group",
        "vars_fd_group",
        "domain_xml",
        "domain_xml_sha256",
        "mutable_ovmf_vars",
        "mutable_ovmf_vars_initial_sha256",
        "com2_socket",
        "com1_serial_log",
        "com2_log",
        "evidence_log",
        "result_path",
        "acceptance_receipt",
        "result_schema",
        "evidence_nonce",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    for (key, _) in ARTIFACTS {
        keys.push(format!("{key}_path"));
        keys.push(format!("{key}_sha256"));
    }
    keys
}

fn validate_frozen_output(
    output: &Path,
    request: &BTreeMap<String, String>,
    request_hash: &str,
) -> Result<(), Failure> {
    validate_prepared_layout(output)?;
    require_mode(&output.join("request.toml"), 0o444, "WYR1-E7 request")?;
    for (key, name) in ARTIFACTS {
        let path = output.join(value(request, key)?);
        require_mode(&path, 0o444, key)?;
        let bytes = wyr1c6::read_regular_bounded(&path, artifact_maximum(key), key)?;
        if value(request, key)? != format!("artifacts/{name}")
            || sha256::bytes_digest(&bytes) != value(request, &format!("{key}_sha256"))?
        {
            return Err(Failure::task(format!(
                "WYR1-E7 frozen {key} identity drifted"
            )));
        }
    }
    for (name, key) in [
        ("e6-source-build.toml", "e6_source_receipt_sha256"),
        ("e6-freeze-receipt.toml", "e6_freeze_receipt_sha256"),
    ] {
        let path = output.join("artifacts").join(name);
        require_mode(&path, 0o444, "WYR1-E7 inherited E6 receipt")?;
        let bytes = wyr1c6::read_regular_bounded(&path, 64 * 1024, "WYR1-E7 inherited E6 receipt")?;
        if sha256::bytes_digest(&bytes) != value(request, key)? {
            return Err(Failure::task(
                "WYR1-E7 inherited E6 receipt identity drifted",
            ));
        }
    }

    let source_path = output.join(value(request, "source_receipt")?);
    require_mode(&source_path, 0o444, "WYR1-E7 source receipt")?;
    let source = wyr1c6::read_regular_bounded(&source_path, 64 * 1024, "WYR1-E7 source receipt")?;
    if sha256::bytes_digest(&source) != value(request, "source_receipt_sha256")? {
        return Err(Failure::task("WYR1-E7 source receipt identity drifted"));
    }
    let esp_path = output.join(value(request, "esp")?);
    require_mode(&esp_path, 0o444, "WYR1-E7 ESP")?;
    let esp = wyr1c6::read_regular_bounded(&esp_path, g3_image::IMAGE_BYTES, "WYR1-E7 ESP")?;
    if sha256::bytes_digest(&esp) != value(request, "esp_sha256")? {
        return Err(Failure::task("WYR1-E7 ESP identity drifted"));
    }

    let result_schema_path = output.join(value(request, "result_schema")?);
    require_mode(&result_schema_path, 0o444, "WYR1-E7 result schema")?;
    let result_schema =
        wyr1c6::read_regular_bounded(&result_schema_path, 64 * 1024, "WYR1-E7 result schema")?;
    if result_schema != render_result_schema()?.as_bytes() {
        return Err(Failure::task("WYR1-E7 result schema drifted"));
    }

    let vars = wyr1c6::read_regular_bounded(
        &output.join(value(request, "ovmf_vars")?),
        wyr1c6::MAX_FIRMWARE_BYTES,
        "WYR1-E7 OVMF vars",
    )?;
    for (profile, vcpus) in [("default", 1_u8), ("smp", 4_u8)] {
        let profile_directory = output.join(profile);
        let mutable_vars = profile_directory.join("OVMF_VARS.mutable.fd");
        require_mode(&mutable_vars, 0o600, "WYR1-E7 mutable OVMF vars")?;
        if wyr1c6::read_regular_bounded(
            &mutable_vars,
            wyr1c6::MAX_FIRMWARE_BYTES,
            "WYR1-E7 mutable OVMF vars",
        )? != vars
        {
            return Err(Failure::task(
                "WYR1-E7 output is consumed/runtime state because prepared OVMF variables changed; use the canonical post-run recheck",
            ));
        }
        let xml = expected_profile_xml(output, profile, vcpus, request)?;
        let xml_path = profile_directory.join("domain.xml");
        require_mode(&xml_path, 0o444, "WYR1-E7 domain XML")?;
        if wyr1c6::read_regular_bounded(&xml_path, 64 * 1024, "WYR1-E7 domain XML")?
            != xml.as_bytes()
        {
            return Err(Failure::task(format!(
                "WYR1-E7 {profile} domain XML drifted"
            )));
        }
        let fields = expected_handoff_fields(profile, vcpus, request_hash, request, &xml, &vars)?;
        let expected = render_handoff(&fields, &handoff_keys())?;
        let handoff_path = profile_directory.join("handoff.toml");
        require_mode(&handoff_path, 0o444, "WYR1-E7 handoff")?;
        if wyr1c6::read_regular_bounded(&handoff_path, 64 * 1024, "WYR1-E7 handoff")?
            != expected.as_bytes()
        {
            return Err(Failure::task(format!("WYR1-E7 {profile} handoff drifted")));
        }
    }

    let pair_path = output.join(value(request, "profile_pair")?);
    require_mode(&pair_path, 0o444, "WYR1-E7 profile pair")?;
    let expected_pair = render_pair(&expected_pair_fields(output, request_hash)?)?;
    if wyr1c6::read_regular_bounded(&pair_path, 64 * 1024, "WYR1-E7 profile pair")?
        != expected_pair.as_bytes()
    {
        return Err(Failure::task("WYR1-E7 profile pair drifted"));
    }

    let receipt_path = output.join(value(request, "receipt")?);
    require_mode(&receipt_path, 0o444, "WYR1-E7 freeze receipt")?;
    if wyr1c6::read_regular_bounded(&receipt_path, 64 * 1024, "WYR1-E7 freeze receipt")?
        != render_freeze_receipt(request_hash, request)?.as_bytes()
    {
        return Err(Failure::task("WYR1-E7 freeze receipt drifted"));
    }
    Ok(())
}

fn validate_request_contract(request: &BTreeMap<String, String>) -> Result<(), Failure> {
    for (key, expected) in [
        ("schema_version", "1"),
        ("profile", "wyr1e7-selector33"),
        ("scenario", "interactive-wyrmsh"),
        ("default_handoff", "default/handoff.toml"),
        ("smp_handoff", "smp/handoff.toml"),
        ("profile_pair", "profile-pair.toml"),
        ("receipt", "freeze-receipt.toml"),
        ("source_receipt", "artifacts/e7-source-build.toml"),
        ("esp", "artifacts/selector33-esp.img"),
        ("result_schema", "result-schema.toml"),
        ("e6_wyrmroot_revision", ACCEPTED_E6_REVISION),
        (
            "e6_source_receipt_sha256",
            ACCEPTED_E6_SOURCE_RECEIPT_SHA256,
        ),
        (
            "e6_freeze_receipt_sha256",
            ACCEPTED_E6_FREEZE_RECEIPT_SHA256,
        ),
    ] {
        if value(request, key)? != expected {
            return Err(Failure::task(format!("WYR1-E7 request changed {key}")));
        }
    }
    for (key, name) in ARTIFACTS {
        if value(request, key)? != format!("artifacts/{name}") {
            return Err(Failure::task(format!(
                "WYR1-E7 request {key} locality drifted"
            )));
        }
    }
    for (key, expected) in ACCEPTED_E6_REUSED_SHA256 {
        if value(request, &format!("{key}_sha256"))? != *expected {
            return Err(Failure::task(format!(
                "WYR1-E7 reused {key} is not from the accepted E6 product"
            )));
        }
    }
    for key in [
        "deepwyrm_revision",
        "generated_abi_revision",
        "generated_abi_tree",
        "wyrmroot_revision",
        "rust_revision",
        "e6_wyrmroot_revision",
    ] {
        wyr1c6::validate_revision(value(request, key)?, key)?;
    }
    wyr1c6::validate_upper_hex_nonzero(
        value(request, "evidence_nonce")?,
        16,
        "WYR1-E7 evidence nonce",
    )?;
    for key in [
        "esp_sha256",
        "source_receipt_sha256",
        "e6_source_receipt_sha256",
        "e6_freeze_receipt_sha256",
    ] {
        validate_lower_hex(value(request, key)?, 64, key)?;
    }
    for (key, _) in ARTIFACTS {
        let hash_key = format!("{key}_sha256");
        validate_lower_hex(value(request, &hash_key)?, 64, &hash_key)?;
    }
    Ok(())
}

fn validate_prepared_layout(output: &Path) -> Result<(), Failure> {
    for profile in ["default", "smp"] {
        for runtime in [
            "verification-manifest.json",
            "com2.sock",
            "com1.log",
            "com2.bin",
            "evidence.bin",
            "result.toml",
            "acceptance-receipt.toml",
        ] {
            if output.join(profile).join(runtime).exists() {
                return Err(Failure::task(
                    "WYR1-E7 output is consumed/runtime state; use the canonical post-run recheck",
                ));
            }
        }
    }
    require_exact_directory(
        output,
        &[
            "artifacts",
            "default",
            "smp",
            "request.toml",
            "result-schema.toml",
            "profile-pair.toml",
            "freeze-receipt.toml",
        ],
        "WYR1-E7 output",
    )?;
    let mut artifact_names = ARTIFACTS.iter().map(|(_, name)| *name).collect::<Vec<_>>();
    artifact_names.extend([
        "e6-source-build.toml",
        "e6-freeze-receipt.toml",
        SOURCE_RECEIPT,
        "selector33-esp.img",
    ]);
    require_exact_directory(
        &output.join("artifacts"),
        &artifact_names,
        "WYR1-E7 artifacts",
    )?;
    for profile in ["default", "smp"] {
        require_exact_directory(
            &output.join(profile),
            &["handoff.toml", "domain.xml", "OVMF_VARS.mutable.fd"],
            "WYR1-E7 prepared profile",
        )?;
    }
    Ok(())
}

fn require_exact_directory(path: &Path, expected: &[&str], label: &str) -> Result<(), Failure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Failure::task(format!("could not stat {label}: {error}")))?;
    if !metadata.file_type().is_dir() {
        return Err(Failure::task(format!("{label} is not a directory")));
    }
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(path)
        .map_err(|error| Failure::task(format!("could not read {label}: {error}")))?
    {
        let entry =
            entry.map_err(|error| Failure::task(format!("could not read {label}: {error}")))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Failure::task(format!("{label} contains a non-UTF-8 name")))?;
        actual.insert(name);
    }
    let expected = expected.iter().map(|name| (*name).to_owned()).collect();
    if actual != expected {
        return Err(Failure::task(format!("{label} entry set drifted")));
    }
    Ok(())
}

fn require_mode(path: &Path, expected: u32, label: &str) -> Result<(), Failure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Failure::task(format!("could not stat {label}: {error}")))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != expected
    {
        return Err(Failure::task(format!("{label} mode drifted")));
    }
    Ok(())
}

fn validate_lower_hex(value: &str, length: usize, label: &str) -> Result<(), Failure> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Failure::task(format!(
            "{label} is not lowercase hexadecimal"
        )));
    }
    Ok(())
}

fn reject_selector_environment() -> Result<(), Failure> {
    for key in [
        "DEEPWYRM_GUEST_TEST_SELECTOR",
        "DEEPWYRM_GUEST_TEST_ID",
        "DEEPWYRM_WYR1E7_EVIDENCE_NONCE",
        "DEEPWYRM_DW1E_EVIDENCE_NONCE",
        "DEEPWYRM_DW1E_E3B_FULL",
        "WYRMROOT_WYR1E7_EVIDENCE_NONCE",
        "CARGO_TARGET_DIR",
    ] {
        if env::var_os(key).is_some() {
            return Err(Failure::task(format!(
                "WYR1-E7 prepare refuses ambient {key}"
            )));
        }
    }
    Ok(())
}

fn artifact_maximum(key: &str) -> u64 {
    if matches!(key, "ovmf_code" | "ovmf_vars") {
        wyr1c6::MAX_FIRMWARE_BYTES
    } else if key == "bootfs" {
        g3_image::IMAGE_BYTES
    } else {
        wyr1c6::MAX_ARTIFACT_BYTES
    }
}

fn render_dynamic(
    values: &BTreeMap<String, String>,
    keys: &[String],
    integers: &[&str],
    label: &str,
) -> Result<String, Failure> {
    let keys = keys.iter().map(String::as_str).collect::<Vec<_>>();
    render(values, &keys, integers, label)
}

fn render(
    values: &BTreeMap<String, String>,
    keys: &[&str],
    integers: &[&str],
    label: &str,
) -> Result<String, Failure> {
    let expected: BTreeSet<_> = keys.iter().copied().collect();
    let actual: BTreeSet<_> = values.keys().map(String::as_str).collect();
    if expected != actual {
        return Err(Failure::task(format!(
            "{label} schema key set drifted: missing={:?} extra={:?}",
            expected.difference(&actual).collect::<Vec<_>>(),
            actual.difference(&expected).collect::<Vec<_>>()
        )));
    }
    let mut output = String::new();
    for key in keys {
        let entry = value(values, key)?;
        output.push_str(key);
        output.push_str(" = ");
        if integers.contains(key) {
            if entry.is_empty()
                || !entry.bytes().all(|byte| byte.is_ascii_digit())
                || (entry.len() > 1 && entry.starts_with('0'))
            {
                return Err(Failure::task(format!(
                    "{label} {key} is not a canonical integer"
                )));
            }
            output.push_str(entry);
        } else {
            output.push('"');
            output.push_str(&entry.replace('\\', "\\\\").replace('"', "\\\""));
            output.push('"');
        }
        output.push('\n');
    }
    Ok(output)
}

fn value<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, Failure> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| Failure::task(format!("WYR1-E7 omitted {key}")))
}

fn parse_scalar_receipt(text: &str, label: &str) -> Result<BTreeMap<String, String>, Failure> {
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let (key, encoded) = line
            .split_once(" = ")
            .ok_or_else(|| Failure::task(format!("{label} contains a malformed line")))?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            || values.contains_key(key)
        {
            return Err(Failure::task(format!(
                "{label} contains a noncanonical key"
            )));
        }
        let value = if let Some(inner) = encoded
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
        {
            decode_scalar_string(inner, label)?
        } else if !encoded.is_empty() && encoded.bytes().all(|byte| byte.is_ascii_digit()) {
            encoded.to_owned()
        } else {
            return Err(Failure::task(format!(
                "{label} contains a noncanonical scalar"
            )));
        };
        values.insert(key.to_owned(), value);
    }
    Ok(values)
}

fn decode_scalar_string(inner: &str, label: &str) -> Result<String, Failure> {
    let mut value = String::new();
    let mut characters = inner.chars();
    while let Some(character) = characters.next() {
        match character {
            '\\' => match characters.next() {
                Some('\\') => value.push('\\'),
                Some('"') => value.push('"'),
                _ => {
                    return Err(Failure::task(format!(
                        "{label} contains an unsupported escape"
                    )));
                }
            },
            '"' => {
                return Err(Failure::task(format!(
                    "{label} contains an unescaped quote"
                )));
            }
            other => value.push(other),
        }
    }
    Ok(value)
}

fn canonical_existing_output(
    output: &Path,
    project: &Path,
    repository: &Path,
) -> Result<PathBuf, Failure> {
    let output = fs::canonicalize(output)
        .map_err(|error| Failure::task(format!("could not resolve WYR1-E7 output: {error}")))?;
    let project = fs::canonicalize(project)
        .map_err(|error| Failure::task(format!("could not resolve OS-Project root: {error}")))?;
    let repository = fs::canonicalize(repository)
        .map_err(|error| Failure::task(format!("could not resolve Wyrmroot source: {error}")))?;
    let deep_repository = fs::canonicalize(project.join("deepwyrm")).map_err(|error| {
        Failure::task(format!(
            "could not resolve canonical Deepwyrm source: {error}"
        ))
    })?;
    if !output.starts_with(project)
        || output.starts_with(repository)
        || output.starts_with(deep_repository)
    {
        return Err(Failure::task(
            "WYR1-E7 output must remain inside OS-Project and outside source repositories",
        ));
    }
    Ok(output)
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
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;

    struct PreparedFixture {
        root: PathBuf,
        request: BTreeMap<String, String>,
        request_hash: String,
    }

    impl Drop for PreparedFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn prepared_fixture(label: &str) -> Result<PreparedFixture, Failure> {
        let repository = tasks::repository_root()?;
        let temporary = repository.join(".tmp");
        fs::create_dir_all(&temporary).map_err(|error| {
            Failure::task(format!("could not create WYR1-E7 test root: {error}"))
        })?;
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
            .as_nanos();
        let root = temporary.join(format!(
            "wyr1e7-inspector-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&root)
            .and_then(|()| fs::create_dir(root.join("artifacts")))
            .map_err(|error| Failure::task(format!("could not create E7 fixture: {error}")))?;

        let mut request = fixture_fields(
            &request_keys(),
            &["schema_version", "test_id", "com2_prelude_length"],
        );
        set_fields(
            &mut request,
            [
                ("kind", REQUEST_KIND),
                ("schema_version", "1"),
                ("selector", SELECTOR),
                ("test_id", TEST_ID),
                ("profile", "wyr1e7-selector33"),
                ("scenario", "interactive-wyrmsh"),
                ("evidence_protocol", EVIDENCE_PROTOCOL),
                ("full_evidence", "true"),
                ("acceptance_claim", "full-selector33-interactive-wyrmsh"),
                ("terminal_line", "DWTEST1 33 0"),
                ("com2_prelude_kind", COM2_PRELUDE_KIND),
                ("com2_prelude_length", COM2_PRELUDE_LENGTH),
                ("com2_prelude_sha256", COM2_PRELUDE_SHA256),
                ("deepwyrm_revision", "11"),
                ("generated_abi_revision", "22"),
                ("generated_abi_tree", "33"),
                ("wyrmroot_revision", "44"),
                ("rust_revision", "55"),
                ("e6_wyrmroot_revision", ACCEPTED_E6_REVISION),
                (
                    "e6_source_receipt_sha256",
                    ACCEPTED_E6_SOURCE_RECEIPT_SHA256,
                ),
                (
                    "e6_freeze_receipt_sha256",
                    ACCEPTED_E6_FREEZE_RECEIPT_SHA256,
                ),
                ("evidence_nonce", "0123456789ABCDEF"),
                ("default_handoff", "default/handoff.toml"),
                ("smp_handoff", "smp/handoff.toml"),
                ("profile_pair", "profile-pair.toml"),
                ("receipt", "freeze-receipt.toml"),
                ("source_receipt", "artifacts/e7-source-build.toml"),
                ("esp", "artifacts/selector33-esp.img"),
                ("result_schema", "result-schema.toml"),
            ],
        );
        for (key, name) in ARTIFACTS {
            let bytes = if *key == "malformed_elf" {
                b"WYR1-E7 malformed ELF\n".to_vec()
            } else {
                format!("fixture {name}\n").into_bytes()
            };
            wyr1c6::write_new(&root.join("artifacts").join(name), &bytes, key)?;
            request.insert((*key).to_owned(), format!("artifacts/{name}"));
            request.insert(format!("{key}_sha256"), sha256::bytes_digest(&bytes));
        }
        for (name, key, bytes) in [
            (
                "e6-source-build.toml",
                "e6_source_receipt_sha256",
                b"fixture E6 source\n".as_slice(),
            ),
            (
                "e6-freeze-receipt.toml",
                "e6_freeze_receipt_sha256",
                b"fixture E6 freeze\n".as_slice(),
            ),
            (
                SOURCE_RECEIPT,
                "source_receipt_sha256",
                b"fixture E7 source\n".as_slice(),
            ),
            (
                "selector33-esp.img",
                "esp_sha256",
                b"fixture ESP\n".as_slice(),
            ),
        ] {
            wyr1c6::write_new(
                &root.join("artifacts").join(name),
                bytes,
                "WYR1-E7 fixture input",
            )?;
            request.insert(key.to_owned(), sha256::bytes_digest(bytes));
        }
        let request_text = render_request(&request)?;
        wyr1c6::write_new(
            &root.join("request.toml"),
            request_text.as_bytes(),
            "WYR1-E7 fixture request",
        )?;
        let request_hash = sha256::bytes_digest(request_text.as_bytes());
        wyr1c6::write_new(
            &root.join("result-schema.toml"),
            render_result_schema()?.as_bytes(),
            "WYR1-E7 fixture result schema",
        )?;
        for (profile, vcpus) in [("default", 1_u8), ("smp", 4_u8)] {
            stage_profile(&root, profile, vcpus, &request_hash, &request)?;
        }
        write_pair(&root, &request_hash)?;
        wyr1c6::write_new(
            &root.join("freeze-receipt.toml"),
            render_freeze_receipt(&request_hash, &request)?.as_bytes(),
            "WYR1-E7 fixture freeze receipt",
        )?;
        Ok(PreparedFixture {
            root,
            request,
            request_hash,
        })
    }

    fn rewrite_frozen(path: &Path, bytes: &[u8], mode: u32) -> Result<(), Failure> {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .and_then(|()| fs::write(path, bytes))
            .and_then(|()| fs::set_permissions(path, fs::Permissions::from_mode(mode)))
            .map_err(|error| Failure::task(format!("could not mutate E7 fixture: {error}")))
    }

    fn rewrite_control_graph(
        root: &Path,
        request: &BTreeMap<String, String>,
    ) -> Result<String, Failure> {
        let request_text = render_request(request)?;
        rewrite_frozen(&root.join("request.toml"), request_text.as_bytes(), 0o444)?;
        let request_hash = sha256::bytes_digest(request_text.as_bytes());
        let vars = wyr1c6::read_regular_bounded(
            &root.join(value(request, "ovmf_vars")?),
            wyr1c6::MAX_FIRMWARE_BYTES,
            "WYR1-E7 fixture OVMF vars",
        )?;
        for (profile, vcpus) in [("default", 1_u8), ("smp", 4_u8)] {
            let xml = expected_profile_xml(root, profile, vcpus, request)?;
            let fields =
                expected_handoff_fields(profile, vcpus, &request_hash, request, &xml, &vars)?;
            rewrite_frozen(
                &root.join(profile).join("handoff.toml"),
                render_handoff(&fields, &handoff_keys())?.as_bytes(),
                0o444,
            )?;
        }
        rewrite_frozen(
            &root.join("profile-pair.toml"),
            render_pair(&expected_pair_fields(root, &request_hash)?)?.as_bytes(),
            0o444,
        )?;
        rewrite_frozen(
            &root.join("freeze-receipt.toml"),
            render_freeze_receipt(&request_hash, request)?.as_bytes(),
            0o444,
        )?;
        Ok(request_hash)
    }

    fn assert_metadata_rejected(fixture: &PreparedFixture, expected: &str) {
        let error = validate_frozen_output(&fixture.root, &fixture.request, &fixture.request_hash)
            .expect_err("mutated prepared output must be rejected");
        assert!(error.message.contains(expected), "{:?}", error);
    }

    fn fixture_fields(keys: &[String], integers: &[&str]) -> BTreeMap<String, String> {
        keys.iter()
            .map(|key| {
                let value = if integers.contains(&key.as_str()) {
                    "1".to_owned()
                } else if key.ends_with("_sha256") {
                    "ab".repeat(32)
                } else if key.ends_with("_revision") || key.ends_with("_tree") {
                    "cd".repeat(20)
                } else if key == "evidence_nonce" {
                    "0123456789ABCDEF".to_owned()
                } else if key == "boot_generation" {
                    "ef".repeat(32)
                } else {
                    "fixture".to_owned()
                };
                (key.clone(), value)
            })
            .collect()
    }

    fn set_fields<const N: usize>(
        fields: &mut BTreeMap<String, String>,
        values: [(&str, &str); N],
    ) {
        for (key, value) in values {
            fields.insert(key.to_owned(), value.to_owned());
        }
    }

    fn root_verifier_accepts_schema(schema: &str, text: &str) -> Result<(), Failure> {
        let repository = tasks::repository_root()?;
        let project = tasks::canonical_project_root(&repository)?;
        let verifier = project.join("tools/verify-vm-request.py");
        let program = r#"import importlib.util, sys
spec = importlib.util.spec_from_file_location("verify_vm_request", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
schemas = {
    "request": (module.E7_REQUEST_KEYS, frozenset({"schema_version", "test_id", "com2_prelude_length"})),
    "handoff": (module.E7_HANDOFF_KEYS, frozenset({"schema_version", "test_id", "vcpus", "memory_mib", "timeout_seconds", "com2_prelude_length"})),
    "pair": (module.E7_PAIR_KEYS, frozenset({"schema_version", "test_id", "default_vcpus", "smp_vcpus", "memory_mib", "timeout_seconds"})),
    "receipt": (module.E7_RECEIPT_KEYS, frozenset({"schema_version", "test_id", "com2_prelude_length"})),
}
if sys.argv[2] == "source":
    module.parse_e7_source_receipt(sys.stdin.buffer.read())
    sys.exit(0)
keys, integers = schemas[sys.argv[2]]
module._strict_c6_toml(sys.stdin.buffer.read(), keys, "Rust-rendered E7 fixture", integers)
"#;
        let mut child = Command::new("/usr/bin/python3")
            .args(["-c", program])
            .arg(&verifier)
            .arg(schema)
            .current_dir(project)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| Failure::task(format!("could not start root verifier: {error}")))?;
        child
            .stdin
            .take()
            .ok_or_else(|| Failure::task("root verifier stdin was unavailable"))?
            .write_all(text.as_bytes())
            .map_err(|error| Failure::task(format!("could not feed root verifier: {error}")))?;
        let output = child
            .wait_with_output()
            .map_err(|error| Failure::task(format!("could not wait for root verifier: {error}")))?;
        if !output.status.success() {
            return Err(Failure::task(format!(
                "root verifier rejected Rust-rendered {schema}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }

    #[test]
    fn e7_profile_selects_test33_without_changing_the_q35_transport() {
        let path = Path::new("/project/artifact");
        for vcpus in [1, 4] {
            let xml = crate::dw1e3a::selected_domain_xml(
                vcpus,
                path,
                path,
                path,
                path,
                (SELECTOR, TEST_ID),
            );
            assert!(
                xml.contains("name=\"opt/org.deepwyrm.test.selector\">interactive-wyrmsh</entry>")
            );
            assert!(xml.contains("name=\"opt/org.deepwyrm.test.test_id\">33</entry>"));
            let original = crate::dw1e3a::domain_xml(vcpus, path, path, path, path);
            assert_eq!(
                xml,
                original
                    .replace("q35-com2-interrupt", SELECTOR)
                    .replace("test.test_id\">31", "test.test_id\">33")
            );
        }
    }

    #[test]
    fn selector33_schema_is_distinct_and_binds_both_transports() {
        let schema = render_result_schema().unwrap();
        assert!(schema.contains("kind = \"wyrmroot-wyr1-e7-selector33-result\""));
        assert!(schema.contains("test_id = \"33\""));
        for key in [
            "com2_accepted_length",
            "com2_accepted_sha256",
            "shutdown_byte_hex = \"04\"",
            "com2_full_sha256",
            "shell_jobs_generation",
        ] {
            assert!(schema.contains(key));
        }
        assert!(!schema.contains("leg_1_"));
    }

    #[test]
    fn request_and_handoff_bind_all_selected_product_inputs() {
        let request = request_keys();
        let handoff = handoff_keys();
        assert_eq!(request.iter().collect::<BTreeSet<_>>().len(), request.len());
        assert_eq!(handoff.iter().collect::<BTreeSet<_>>().len(), handoff.len());
        for key in [
            "com2_prelude_kind",
            "com2_prelude_length",
            "com2_prelude_sha256",
        ] {
            assert!(request.contains(&key.to_owned()));
            assert!(handoff.contains(&key.to_owned()));
        }
        for key in [
            "wyrmsh",
            "cpu_hog",
            "exit_nonzero",
            "fault",
            "malformed_elf",
            "launch_policy",
            "stack_report",
            "bootfs",
        ] {
            assert!(request.contains(&key.to_owned()));
            assert!(request.contains(&format!("{key}_sha256")));
            assert!(handoff.contains(&format!("{key}_path")));
            assert!(handoff.contains(&format!("{key}_sha256")));
        }
    }

    #[test]
    fn selector_constants_freeze_e7_authority() {
        // The actual environment-mutating rejection cases are covered by the
        // existing serialized selector-environment tests.  Keep this table
        // assertion free of process-global mutation so tests remain parallel.
        assert_eq!(SELECTOR, "interactive-wyrmsh");
        assert_eq!(EVIDENCE_PROTOCOL, "WRE1");
        assert_eq!(TEST_ID, "33");
        assert_eq!(TIMEOUT_SECONDS, "300");
        assert_eq!(ARTIFACTS.len(), 23);
        assert_eq!(
            ARTIFACTS
                .iter()
                .find(|(label, _)| *label == "stack_report")
                .map(|(_, name)| *name),
            Some("stack-report.json")
        );
        assert_eq!(COM2_PRELUDE_LENGTH, "354");
    }

    #[test]
    fn canonical_root_parser_accepts_rust_rendered_e7_schemas() -> Result<(), Failure> {
        let request_keys = request_keys();
        let mut request = fixture_fields(
            &request_keys,
            &["schema_version", "test_id", "com2_prelude_length"],
        );
        set_fields(
            &mut request,
            [
                ("kind", REQUEST_KIND),
                ("schema_version", "1"),
                ("selector", SELECTOR),
                ("test_id", TEST_ID),
                ("profile", "wyr1e7-selector33"),
                ("scenario", "interactive-wyrmsh"),
                ("evidence_protocol", EVIDENCE_PROTOCOL),
                ("full_evidence", "true"),
                ("acceptance_claim", "full-selector33-interactive-wyrmsh"),
                ("terminal_line", "DWTEST1 33 0"),
                ("com2_prelude_kind", COM2_PRELUDE_KIND),
                ("com2_prelude_length", COM2_PRELUDE_LENGTH),
                ("com2_prelude_sha256", COM2_PRELUDE_SHA256),
            ],
        );
        let request_text = render_request(&request)?;

        let handoff_keys = handoff_keys();
        let mut handoff = fixture_fields(
            &handoff_keys,
            &[
                "schema_version",
                "test_id",
                "vcpus",
                "memory_mib",
                "timeout_seconds",
                "com2_prelude_length",
            ],
        );
        set_fields(
            &mut handoff,
            [
                ("kind", HANDOFF_KIND),
                ("schema_version", "1"),
                ("selector", SELECTOR),
                ("test_id", TEST_ID),
                ("evidence_protocol", EVIDENCE_PROTOCOL),
                (
                    "terminal_authority",
                    "system-init-selector33-wre1-controller",
                ),
                ("esp_fd_group", ESP_FD_GROUP),
                ("vars_fd_group", VARS_FD_GROUP),
                ("com2_prelude_kind", COM2_PRELUDE_KIND),
                ("com2_prelude_length", COM2_PRELUDE_LENGTH),
                ("com2_prelude_sha256", COM2_PRELUDE_SHA256),
            ],
        );
        let handoff_text = render_handoff(&handoff, &handoff_keys)?;

        let pair_keys = pair_keys();
        let pair_key_strings = pair_keys
            .iter()
            .map(|key| (*key).to_owned())
            .collect::<Vec<_>>();
        let mut pair = fixture_fields(
            &pair_key_strings,
            &[
                "schema_version",
                "test_id",
                "default_vcpus",
                "smp_vcpus",
                "memory_mib",
                "timeout_seconds",
            ],
        );
        set_fields(
            &mut pair,
            [
                ("kind", PAIR_KIND),
                ("schema_version", "1"),
                ("selector", SELECTOR),
                ("test_id", TEST_ID),
                ("evidence_protocol", EVIDENCE_PROTOCOL),
            ],
        );
        let pair_text = render_pair(&pair)?;

        let receipt_text = render_freeze_receipt(&"12".repeat(32), &request)?;
        let source_keys = source_receipt_keys();
        let mut source = fixture_fields(&source_keys, &[]);
        set_fields(
            &mut source,
            [
                ("kind", SOURCE_RECEIPT_KIND),
                ("schema_version", "1"),
                ("selector", SELECTOR),
                ("test_id", TEST_ID),
                ("evidence_protocol", EVIDENCE_PROTOCOL),
                ("malformed_elf_literal", "WYR1-E7 malformed ELF\\n"),
            ],
        );
        let source_text = render_source_fields(&source)?;
        assert_eq!(
            value(
                &parse_scalar_receipt(&source_text, "WYR1-E7 source fixture")?,
                "malformed_elf_literal",
            )?,
            "WYR1-E7 malformed ELF\\n"
        );

        for (schema, text) in [
            ("request", request_text),
            ("handoff", handoff_text),
            ("pair", pair_text),
            ("receipt", receipt_text),
            ("source", source_text),
        ] {
            root_verifier_accepts_schema(schema, &text)?;
        }
        Ok(())
    }

    #[test]
    fn prepared_inspector_rejoins_every_rendered_metadata_edge() -> Result<(), Failure> {
        let fixture = prepared_fixture("metadata")?;
        validate_frozen_output(&fixture.root, &fixture.request, &fixture.request_hash)?;
        for (relative, expected) in [
            ("artifacts/e7-source-build.toml", "source receipt identity"),
            ("default/handoff.toml", "default handoff drifted"),
            ("profile-pair.toml", "profile pair drifted"),
            ("result-schema.toml", "result schema drifted"),
            ("freeze-receipt.toml", "freeze receipt drifted"),
        ] {
            let path = fixture.root.join(relative);
            let original = fs::read(&path).map_err(|error| {
                Failure::task(format!("could not read E7 fixture metadata: {error}"))
            })?;
            let mut mutated = original.clone();
            mutated.push(b'x');
            rewrite_frozen(&path, &mutated, 0o444)?;
            assert_metadata_rejected(&fixture, expected);
            rewrite_frozen(&path, &original, 0o444)?;
            validate_frozen_output(&fixture.root, &fixture.request, &fixture.request_hash)?;
        }
        Ok(())
    }

    #[test]
    fn correlated_source_hash_rewrite_cannot_replace_actual_source_bytes() -> Result<(), Failure> {
        let fixture = prepared_fixture("source-join")?;
        let mut request = fixture.request.clone();
        request.insert("source_receipt_sha256".to_owned(), "ab".repeat(32));
        let request_hash = rewrite_control_graph(&fixture.root, &request)?;
        let error = validate_frozen_output(&fixture.root, &request, &request_hash)
            .expect_err("correlated source-hash rewrite must be rejected");
        assert!(
            error.message.contains("source receipt identity"),
            "{:?}",
            error
        );
        Ok(())
    }

    #[test]
    fn prepared_inspector_checks_esp_bytes_modes_and_exact_layout() -> Result<(), Failure> {
        let fixture = prepared_fixture("layout")?;
        let esp = fixture.root.join("artifacts/selector33-esp.img");
        rewrite_frozen(&esp, b"changed ESP\n", 0o444)?;
        assert_metadata_rejected(&fixture, "ESP identity drifted");

        rewrite_frozen(&esp, b"fixture ESP\n", 0o444)?;
        fs::set_permissions(
            fixture.root.join("request.toml"),
            fs::Permissions::from_mode(0o644),
        )
        .map_err(|error| Failure::task(format!("could not change fixture mode: {error}")))?;
        assert_metadata_rejected(&fixture, "request mode drifted");
        fs::set_permissions(
            fixture.root.join("request.toml"),
            fs::Permissions::from_mode(0o444),
        )
        .map_err(|error| Failure::task(format!("could not restore fixture mode: {error}")))?;

        fs::write(fixture.root.join("unexpected"), b"unexpected")
            .map_err(|error| Failure::task(format!("could not add fixture entry: {error}")))?;
        assert_metadata_rejected(&fixture, "entry set drifted");
        Ok(())
    }

    #[test]
    fn prepared_inspector_distinguishes_consumed_runtime_state() -> Result<(), Failure> {
        let fixture = prepared_fixture("consumed")?;
        let vars = fixture.root.join("default/OVMF_VARS.mutable.fd");
        let original = fs::read(&vars)
            .map_err(|error| Failure::task(format!("could not read fixture vars: {error}")))?;
        rewrite_frozen(&vars, b"consumed vars\n", 0o600)?;
        assert_metadata_rejected(&fixture, "consumed/runtime state");
        rewrite_frozen(&vars, &original, 0o600)?;
        validate_frozen_output(&fixture.root, &fixture.request, &fixture.request_hash)?;

        fs::write(
            fixture.root.join("default/verification-manifest.json"),
            b"{}\n",
        )
        .map_err(|error| Failure::task(format!("could not mark fixture consumed: {error}")))?;
        assert_metadata_rejected(&fixture, "consumed/runtime state");
        Ok(())
    }

    #[test]
    fn request_contract_freezes_localities_and_reused_e6_identities() -> Result<(), Failure> {
        let fixture = prepared_fixture("request")?;
        let mut request = fixture.request.clone();
        for key in [
            "deepwyrm_revision",
            "generated_abi_revision",
            "generated_abi_tree",
            "wyrmroot_revision",
            "rust_revision",
        ] {
            request.insert(key.to_owned(), "12".repeat(20));
        }
        for (key, digest) in ACCEPTED_E6_REUSED_SHA256 {
            request.insert(format!("{key}_sha256"), (*digest).to_owned());
        }
        request.insert(
            "e6_source_receipt_sha256".to_owned(),
            ACCEPTED_E6_SOURCE_RECEIPT_SHA256.to_owned(),
        );
        request.insert(
            "e6_freeze_receipt_sha256".to_owned(),
            ACCEPTED_E6_FREEZE_RECEIPT_SHA256.to_owned(),
        );
        validate_request_contract(&request)?;

        request.insert("esp".to_owned(), "default/selector33-esp.img".to_owned());
        assert!(
            validate_request_contract(&request)
                .expect_err("moved ESP must be rejected")
                .message
                .contains("changed esp")
        );
        request.insert("esp".to_owned(), "artifacts/selector33-esp.img".to_owned());
        request.insert("wyrmsh_sha256".to_owned(), "ab".repeat(32));
        assert!(
            validate_request_contract(&request)
                .expect_err("changed inherited shell must be rejected")
                .message
                .contains("accepted E6 product")
        );
        Ok(())
    }

    #[test]
    fn actual_esp_parser_rejects_a_hash_consistent_non_image() -> Result<(), Failure> {
        let fixture = prepared_fixture("esp-parser")?;
        let mut request = fixture.request.clone();
        let esp = fixture.root.join("artifacts/selector33-esp.img");
        rewrite_frozen(&esp, b"replacement ESP\n", 0o444)?;
        request.insert(
            "esp_sha256".to_owned(),
            sha256::bytes_digest(b"replacement ESP\n"),
        );
        let request_hash = rewrite_control_graph(&fixture.root, &request)?;
        validate_frozen_output(&fixture.root, &request, &request_hash)?;
        assert!(validate_esp_contents(&fixture.root, &request).is_err());
        Ok(())
    }

    #[test]
    fn inspector_uses_the_local_checkout_with_upstream_url_metadata() -> Result<(), Failure> {
        let repository = tasks::repository_root()?;
        let project = tasks::canonical_project_root(&repository)?;
        let manifest = crate::metadata::BuildManifest::load(&repository)?;
        assert!(manifest.deepwyrm_repository()?.starts_with("https://"));
        assert_eq!(
            local_deep_repository(&project)?,
            fs::canonicalize(project.join("deepwyrm")).unwrap()
        );
        Ok(())
    }

    #[test]
    fn kernel_build_keeps_logs_outside_the_fresh_cargo_target() -> Result<(), Failure> {
        let repository = tasks::repository_root()?;
        let temporary = Directory::open_exact(&repository.join(".tmp"), "test temporary root")?;
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
            .as_nanos();
        let scratch = temporary.create_scratch(
            &format!("wyr1e7-kernel-log-test-{}-{unique}", std::process::id()),
            "kernel log test scratch",
        )?;
        let result = (|| {
            let repository = scratch.path().join("deepwyrm");
            fs::create_dir_all(repository.join("tools"))
                .map_err(|error| Failure::task(format!("create fake repository: {error}")))?;
            let wrapper = repository.join("tools/pinned-cargo");
            fs::write(&wrapper, concat!(
                "#!/bin/sh\nset -eu\n",
                "test -z \"$(ls -A -- \"$DEEPWYRM_PINNED_TARGET_DIR\")\"\n",
                "test -f \"$DEEPWYRM_PINNED_TARGET_DIR/../cargo.stdout.log\"\n",
                "test -f \"$DEEPWYRM_PINNED_TARGET_DIR/../cargo.stderr.log\"\n",
                "mkdir -p -- \"$DEEPWYRM_PINNED_TARGET_DIR/x86_64-unknown-none/release\"\n",
                "printf 'kernel fixture' >\"$DEEPWYRM_PINNED_TARGET_DIR/x86_64-unknown-none/release/deepwyrm-kernel\"\n",
                "printf 'build stdout\\n'\nprintf 'build stderr\\n' >&2\n",
            ))
            .map_err(|error| Failure::task(format!("write fake launcher: {error}")))?;
            fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))
                .map_err(|error| Failure::task(format!("set fake launcher mode: {error}")))?;
            assert_eq!(
                build_kernel(&repository, "0123456789ABCDEF")?,
                b"kernel fixture"
            );
            let build = fs::read_dir(repository.join(".tmp"))
                .map_err(|error| Failure::task(format!("read build directory: {error}")))?
                .next()
                .expect("one build directory")
                .map_err(|error| Failure::task(format!("read build entry: {error}")))?
                .path();
            assert_eq!(
                fs::read(build.join("cargo.stdout.log")).unwrap(),
                b"build stdout\n"
            );
            assert_eq!(
                fs::read(build.join("cargo.stderr.log")).unwrap(),
                b"build stderr\n"
            );
            Ok(())
        })();
        scratch.finish(result)
    }

    #[test]
    fn kernel_command_uses_one_build_verb_and_an_admitted_deep_target() -> Result<(), Failure> {
        let repository = tasks::repository_root()?;
        let repository = Directory::open_exact(&repository, "Wyrmroot test source")?;
        let temporary = match repository.open_child(".tmp", "WYR1-E7 test temporary root") {
            Ok(directory) => directory,
            Err(_) => repository.create_child(".tmp", 0o700, "WYR1-E7 test temporary root")?,
        };
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
            .as_nanos();
        let scratch = temporary.create_scratch(
            &format!("wyr1e7-kernel-command-test-{}-{unique}", std::process::id()),
            "WYR1-E7 kernel command test scratch",
        )?;
        let result = (|| {
            let fake_deep = scratch.path().join("deepwyrm");
            let fake_tmp = fake_deep.join(".tmp");
            let target = fake_tmp.join("target");
            fs::create_dir(&fake_deep)
                .and_then(|()| fs::create_dir(&fake_tmp))
                .and_then(|()| fs::create_dir(&target))
                .map_err(|error| {
                    Failure::task(format!("could not create fake Deep tree: {error}"))
                })?;
            let wrapper = fake_deep.join("pinned-cargo");
            fs::write(
                &wrapper,
                b"#!/bin/sh\nset -eu\ncase \"$DEEPWYRM_PINNED_TARGET_DIR\" in \"$PWD\"/.tmp/*) ;; *) exit 4 ;; esac\nfor argument in \"$@\"; do printf 'ARG=%s\\n' \"$argument\"; done\nprintf 'TARGET=%s\\n' \"$DEEPWYRM_PINNED_TARGET_DIR\"\nprintf 'SELECTOR=%s\\n' \"$DEEPWYRM_GUEST_TEST_SELECTOR\"\nprintf 'NONCE=%s\\n' \"$DEEPWYRM_WYR1E7_EVIDENCE_NONCE\"\nprintf 'CARGO_HOME=%s\\n' \"${CARGO_HOME-unset}\"\n",
            )
            .map_err(|error| Failure::task(format!("could not write fake wrapper: {error}")))?;
            fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))
                .map_err(|error| Failure::task(format!("could not seal fake wrapper: {error}")))?;
            let output = kernel_build_command(&wrapper, &fake_deep, &target, "0123456789ABCDEF")
                .output()
                .map_err(|error| Failure::task(format!("could not run fake wrapper: {error}")))?;
            if !output.status.success() {
                return Err(Failure::task("fake Deep wrapper failed"));
            }
            let observed = String::from_utf8(output.stdout)
                .map_err(|_| Failure::task("fake wrapper output is not UTF-8"))?;
            let arguments = observed
                .lines()
                .filter_map(|line| line.strip_prefix("ARG="))
                .collect::<Vec<_>>();
            assert_eq!(
                arguments,
                [
                    "target",
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
                ]
            );
            assert_eq!(
                arguments
                    .iter()
                    .filter(|argument| **argument == "build")
                    .count(),
                1
            );
            assert!(observed.contains(&format!("TARGET={}\n", target.display())));
            assert!(observed.contains("SELECTOR=interactive-wyrmsh\n"));
            assert!(observed.contains("NONCE=0123456789ABCDEF\n"));
            assert!(observed.contains("CARGO_HOME=unset\n"));
            Ok(())
        })();
        scratch.finish(result)
    }
}
