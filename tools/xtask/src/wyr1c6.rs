//! WYR1-C6 selector-29 frozen-product and VM-handoff grammar.
//!
//! This module deliberately owns the *host* side of C6 only.  It freezes a
//! caller-built, feature-selected artifact set, makes the ESP deterministically,
//! and emits two immutable handoffs for the coordinator-owned VM.  It never
//! launches QEMU, talks to libvirt, or treats a serial line as evidence.  The
//! kernel collector is the sole authority for a `WRC6E1` terminal.

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    cli::G3ImageArguments,
    error::Failure,
    g3_image,
    secure_fs::{Directory, InheritableDirectory},
    sha256, tasks,
};
use deepwyrm_abi::{
    DW_BOOT_DEVICE_RESOURCE_FLAGS_SUPPORTED_MASK, DW_BOOT_DEVICE_RESOURCE_V1_SIZE,
    DW_BOOT_DEVICE_RESOURCE_V1_VERSION, DW_BOOT_DEVICE_TABLE_FLAGS_SUPPORTED_MASK,
    DW_BOOT_DEVICE_TABLE_RECORD_STRIDE, DW_BOOT_DEVICE_TABLE_V1_SIZE,
    DW_BOOT_DEVICE_TABLE_V1_VERSION, DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT,
    DwBootDeviceResourceV1, DwBootDeviceTableV1,
};
use wyrmroot_bootfs::archive::Archive;

pub(crate) const SELECTOR: &str = "device-coordinator-restart";
pub(crate) const TEST_ID: u32 = 29;
pub(crate) const EVIDENCE_PROTOCOL: &str = "WRC6E1";
const GATE_EVIDENCE_PROTOCOL: &str = "WRC6";
const GATE_PATH: &[u8] = b"system/bootstrap/wyr1-c6-gate-v1";
const SOURCE_RECEIPT: &str = "c6-source-build.toml";
const REQUEST_KIND: &str = "wyrmroot-wyr1-c6-selector29-request";
const RECEIPT_KIND: &str = "wyrmroot-wyr1-c6-selector29-receipt";
const HANDOFF_KIND: &str = "wyrmroot-wyr1-c6-selector29-vm-handoff";
const SCHEMA_VERSION: u32 = 1;
const SCENARIO: &str = "driver-and-devmgr-restart-no-io";
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FIRMWARE_BYTES: u64 = 128 * 1024 * 1024;
const MACHINE: &str = "pc-q35-10.2";
const DOMAIN_UUID: &str = "33005e22-d7c2-4b13-b1ac-b82eda95e584";
const ESP_FD_GROUP: &str = "dw-f13-esp-v1";
const VARS_FD_GROUP: &str = "dw-f13-ovmf-vars-v1";
const NATIVE_TARGET: &str = "x86_64-unknown-wyrmroot";
const KERNEL_TARGET: &str = "x86_64-unknown-none";
const OVMF_CODE_PATH: &str = "/usr/share/edk2/OvmfX64/OVMF_CODE.fd";
const OVMF_CODE_SHA256: &str = "f3ff7e73448ed2845ee15356f394882f5618eb5dab92c9a30ec6ee0e1468553a";
const OVMF_VARS_PATH: &str = "/usr/share/edk2/OvmfX64/OVMF_VARS.fd";
const OVMF_VARS_SHA256: &str = "6ed987af3a3c155be71665f510eae3e007eda9b8b94afd59d45e91c4a11565cc";
const ACCEPTED_RUST_REVISION: &str = "a92dc7f7464ad6ddfece4402bd7b86dbfa86166d";
const ACCEPTED_TOOLCHAIN_NAME: &str = "wyrmroot-1.97.1-a92dc7f7";

const ARTIFACTS: &[(&str, &str, u64)] = &[
    ("loader", "loader.efi", MAX_ARTIFACT_BYTES),
    ("kernel", "deepwyrm.elf", MAX_ARTIFACT_BYTES),
    ("symbols", "deepwyrm.symbols.elf", MAX_ARTIFACT_BYTES),
    ("bootstrap", "bootstrap.elf", MAX_ARTIFACT_BYTES),
    ("system_init", "system-init.elf", MAX_ARTIFACT_BYTES),
    ("registryd", "registryd.elf", MAX_ARTIFACT_BYTES),
    ("devmgr", "devmgr.elf", MAX_ARTIFACT_BYTES),
    ("uart16550d", "uart16550d.elf", MAX_ARTIFACT_BYTES),
    ("consoled", "consoled.elf", MAX_ARTIFACT_BYTES),
    ("wyrmsh", "wyrmsh.elf", MAX_ARTIFACT_BYTES),
    ("rrc_manifest", "rrc-c6-v1.bin", MAX_ARTIFACT_BYTES),
    ("device_manifest", "wrdm-c6-v1.bin", MAX_ARTIFACT_BYTES),
    (
        "boot_device_table",
        "boot-device-table.bin",
        MAX_ARTIFACT_BYTES,
    ),
    ("bootfs", "bootfs.img", g3_image::IMAGE_BYTES),
    ("ovmf_code", "OVMF_CODE.fd", MAX_FIRMWARE_BYTES),
    ("ovmf_vars", "OVMF_VARS.fd", MAX_FIRMWARE_BYTES),
];

const REQUEST_KEYS: &[&str] = &[
    "kind",
    "schema_version",
    "selector",
    "test_id",
    "profile",
    "scenario",
    "evidence_protocol",
    "deepwyrm_revision",
    "generated_abi_revision",
    "generated_abi_tree",
    "wyrmroot_revision",
    "rust_revision",
    "evidence_nonce",
    "evidence_challenge",
    "loader",
    "loader_sha256",
    "kernel",
    "kernel_sha256",
    "symbols",
    "symbols_sha256",
    "bootstrap",
    "bootstrap_sha256",
    "system_init",
    "system_init_sha256",
    "registryd",
    "registryd_sha256",
    "devmgr",
    "devmgr_sha256",
    "uart16550d",
    "uart16550d_sha256",
    "consoled",
    "consoled_sha256",
    "wyrmsh",
    "wyrmsh_sha256",
    "rrc_manifest",
    "rrc_manifest_sha256",
    "device_manifest",
    "device_manifest_sha256",
    "boot_device_table",
    "boot_device_table_sha256",
    "bootfs",
    "bootfs_sha256",
    "ovmf_code",
    "ovmf_code_sha256",
    "ovmf_vars",
    "ovmf_vars_sha256",
    "esp",
    "esp_sha256",
    "default_handoff",
    "smp_handoff",
    "receipt",
    "gate_config_sha256",
    "source_receipt",
    "source_receipt_sha256",
    "profile_pair",
];

#[cfg(test)]
const HANDOFF_KEYS: &[&str] = &[
    "kind",
    "schema_version",
    "profile",
    "selector",
    "test_id",
    "evidence_protocol",
    "request",
    "request_sha256",
    "esp",
    "esp_sha256",
    "vcpus",
    "scenario",
    "physical_io",
    "terminal_authority",
];

#[derive(Clone, Debug, Eq, PartialEq)]
struct Request {
    root: PathBuf,
    values: BTreeMap<String, String>,
}

struct ProducedArtifacts {
    directory: PathBuf,
    deep_revision: String,
    abi_revision: String,
    abi_tree: String,
}

/// Build, inspect, measure, and freeze the selector-29 product in one
/// producer-owned transaction.  There is deliberately no command that accepts
/// an arbitrary artifacts directory: the receipt below is created only from
/// the exact commands and bytes this function stages.
pub(crate) fn prepare(
    output: &Path,
    deep_repository: &Path,
    deep_revision: &str,
    nonce: &str,
    challenge: &str,
) -> Result<String, Failure> {
    reject_selector_environment()?;
    validate_revision(deep_revision, "Deepwyrm revision")?;
    validate_upper_hex_nonzero(nonce, 16, "evidence nonce")?;
    validate_upper_hex_nonzero(challenge, 16, "evidence challenge")?;
    if output.exists() {
        return Err(Failure::task("WYR1-C6 output must be a fresh path"));
    }

    let repository = tasks::repository_root()?;
    let project = tasks::canonical_project_root(&repository)?;
    let deep_repository = canonical_deep_repository(deep_repository, &project)?;
    let wyrmroot_revision = clean_revision(&repository, "Wyrmroot")?;
    verify_clean_revision(&deep_repository, "Deepwyrm", deep_revision)?;
    let manifest = crate::metadata::BuildManifest::load(&repository)?;
    if manifest.rust_revision()? != ACCEPTED_RUST_REVISION
        || manifest.rust_toolchain_name()? != ACCEPTED_TOOLCHAIN_NAME
    {
        return Err(Failure::task(
            "WYR1-C6 source metadata does not name the accepted Rust toolchain",
        ));
    }
    // Selector-29 code may live at a newer clean Deepwyrm commit than the
    // generated ABI consumer pin.  The semantic join is the immutable `abi`
    // tree, checked below; do not advance the generated ABI pin merely for
    // private evidence code.
    let abi_revision = manifest.deepwyrm_revision()?.to_owned();
    let abi_tree = matching_abi_tree(&deep_repository, deep_revision, &abi_revision)?;
    let output = canonical_new_output(output, &project, &repository, &deep_repository)?;
    let tmp = project.join(".tmp");
    fs::create_dir_all(&tmp).map_err(|error| {
        Failure::task(format!("could not create project temporary root: {error}"))
    })?;
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
        .as_nanos();
    let staging = tmp.join(format!("wyr1c6-producer-{}-{unique}", std::process::id()));
    fs::create_dir(&staging)
        .map_err(|error| Failure::task(format!("could not create C6 producer staging: {error}")))?;

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
        )?;
        freeze_produced(&output, &produced, nonce, challenge)
    })();
    if result.is_ok() {
        fs::remove_dir_all(&staging).map_err(|error| {
            Failure::task(format!("could not retire C6 producer staging: {error}"))
        })?;
    }
    result
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
            "WYR1-C6 prepare requires the pinned launcher exact CARGO_HOME",
        ));
    }
    toolchain.accepted().verify_unchanged()?;
    layout.verify_unchanged()?;
    let build = staging.join("build");
    fs::create_dir(&build)
        .map_err(|error| Failure::task(format!("could not create C6 build directory: {error}")))?;
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
    let loader = uefi.loader_bytes;
    let build_directory = Directory::open_exact(&build, "WYR1-C6 build directory")?;
    let bootstrap =
        build_directory.with_inheritable_anchor("WYR1-C6 build directory", |build_directory| {
            build_c6_bootstrap(
                repository,
                &toolchain,
                &layout,
                &cargo_home,
                build_directory,
            )
        })?;
    let snapshot = crate::wyr1c::build_c6_snapshot(nonce)?;
    let kernel = build_selector29_kernel(deep_repository, nonce)?;
    let table = boot_device_table();
    let code = pinned_firmware(OVMF_CODE_PATH, OVMF_CODE_SHA256, "OVMF code")?;
    let vars = pinned_firmware(OVMF_VARS_PATH, OVMF_VARS_SHA256, "OVMF vars")?;
    let artifacts = staging.join("artifacts");
    fs::create_dir(&artifacts).map_err(|error| {
        Failure::task(format!("could not create C6 producer artifacts: {error}"))
    })?;
    let artifact = |name: &str| {
        snapshot
            .artifacts
            .get(name)
            .ok_or_else(|| Failure::task(format!("WYR1-C6 builder omitted {name}")))
    };
    for (name, bytes) in [
        ("loader.efi", &loader),
        ("deepwyrm.elf", &kernel),
        ("deepwyrm.symbols.elf", &kernel),
        ("bootstrap.elf", &bootstrap),
        ("system-init.elf", artifact("system-init")?),
        ("registryd.elf", artifact("registryd")?),
        ("devmgr.elf", artifact("devmgr")?),
        ("uart16550d.elf", artifact("uart16550d")?),
        ("consoled.elf", artifact("consoled")?),
        ("wyrmsh.elf", artifact("wyrmsh")?),
        ("rrc-c6-v1.bin", &snapshot.rrc_manifest),
        ("wrdm-c6-v1.bin", &snapshot.device_manifest),
        ("boot-device-table.bin", &table),
        ("bootfs.img", &snapshot.bootfs),
        ("OVMF_CODE.fd", &code),
        ("OVMF_VARS.fd", &vars),
    ] {
        write_new(&artifacts.join(name), bytes, name)?;
    }
    let receipt = render_source_receipt(
        &manifest,
        toolchain.accepted(),
        deep_revision,
        abi_revision,
        abi_tree,
        wyrmroot_revision,
        nonce,
        &artifacts,
    )?;
    write_new(
        &artifacts.join(SOURCE_RECEIPT),
        receipt.as_bytes(),
        "C6 source receipt",
    )?;
    verify_source_receipt(
        receipt.as_bytes(),
        &artifacts,
        deep_revision,
        abi_revision,
        abi_tree,
        wyrmroot_revision,
        manifest.rust_revision()?,
        nonce,
    )?;
    toolchain.accepted().verify_unchanged()?;
    layout.verify_unchanged()?;
    verify_clean_revision(repository, "Wyrmroot", wyrmroot_revision)?;
    verify_clean_revision(deep_repository, "Deepwyrm", deep_revision)?;
    Ok(ProducedArtifacts {
        directory: artifacts,
        deep_revision: deep_revision.to_owned(),
        abi_revision: abi_revision.to_owned(),
        abi_tree: abi_tree.to_owned(),
    })
}

/// Freeze only the private artifact directory produced by [`prepare`].
fn freeze_produced(
    output: &Path,
    produced: &ProducedArtifacts,
    nonce: &str,
    challenge: &str,
) -> Result<String, Failure> {
    reject_selector_environment()?;
    let artifacts = &produced.directory;
    let deep_revision = &produced.deep_revision;
    let abi_revision = &produced.abi_revision;
    let abi_tree = &produced.abi_tree;
    validate_upper_hex_nonzero(nonce, 16, "evidence nonce")?;
    validate_upper_hex_nonzero(challenge, 16, "evidence challenge")?;
    if output.exists() {
        return Err(Failure::task("WYR1-C6 output must be a fresh path"));
    }
    if !artifacts.is_dir() {
        return Err(Failure::task("WYR1-C6 artifacts input is not a directory"));
    }
    let repository = tasks::repository_root()?;
    let wyrmroot_revision = clean_revision(&repository, "Wyrmroot")?;
    let manifest = crate::metadata::BuildManifest::load(&repository)?;
    let rust_revision = manifest.rust_revision()?.to_owned();

    let parent = output
        .parent()
        .ok_or_else(|| Failure::task("WYR1-C6 output has no parent"))?;
    if !parent.is_dir() {
        return Err(Failure::task("WYR1-C6 output parent is not a directory"));
    }
    fs::create_dir(output)
        .map_err(|error| Failure::task(format!("could not create C6 output: {error}")))?;
    let frozen = output.join("artifacts");
    fs::create_dir(&frozen)
        .map_err(|error| Failure::task(format!("could not create C6 artifacts: {error}")))?;

    let mut values = BTreeMap::new();
    let source_receipt = read_regular_bounded(
        &artifacts.join(SOURCE_RECEIPT),
        64 * 1024,
        "C6 source receipt",
    )?;
    verify_source_receipt(
        &source_receipt,
        artifacts,
        deep_revision,
        abi_revision,
        abi_tree,
        &wyrmroot_revision,
        &rust_revision,
        nonce,
    )?;
    write_new(
        &frozen.join(SOURCE_RECEIPT),
        &source_receipt,
        "C6 source receipt",
    )?;
    values.insert(
        "source_receipt".into(),
        format!("artifacts/{SOURCE_RECEIPT}"),
    );
    values.insert(
        "source_receipt_sha256".into(),
        sha256::bytes_digest(&source_receipt),
    );
    for (key, name, maximum) in ARTIFACTS {
        let source = artifacts.join(name);
        let bytes = read_regular_bounded(&source, *maximum, key)?;
        let destination = frozen.join(name);
        write_new(&destination, &bytes, key)?;
        values.insert((*key).to_owned(), format!("artifacts/{name}"));
        values.insert(format!("{key}_sha256"), sha256::bytes_digest(&bytes));
    }
    let gate = validate_gate(
        &read_regular_bounded(&frozen.join("bootfs.img"), g3_image::IMAGE_BYTES, "bootfs")?,
        nonce,
    )?;
    values.insert("gate_config_sha256".into(), sha256::bytes_digest(&gate));

    let esp = frozen.join("selector29-esp.img");
    let image_args = G3ImageArguments {
        image: esp.display().to_string(),
        loader: frozen.join("loader.efi").display().to_string(),
        kernel: frozen.join("deepwyrm.elf").display().to_string(),
        bootstrap: frozen.join("bootstrap.elf").display().to_string(),
        bootfs: frozen.join("bootfs.img").display().to_string(),
    };
    g3_image::build_d6(
        &image_args,
        &frozen.join("boot-device-table.bin").display().to_string(),
    )?;
    seal_mode(&esp, 0o444, "ESP")?;
    values.insert("esp".into(), "artifacts/selector29-esp.img".into());
    values.insert(
        "esp_sha256".into(),
        sha256::bytes_digest(&read_regular_bounded(&esp, g3_image::IMAGE_BYTES, "ESP")?),
    );
    values.insert("kind".into(), REQUEST_KIND.into());
    values.insert("schema_version".into(), SCHEMA_VERSION.to_string());
    values.insert("selector".into(), SELECTOR.into());
    values.insert("test_id".into(), TEST_ID.to_string());
    values.insert("profile".into(), "wyr1c6-selector29".into());
    values.insert("scenario".into(), SCENARIO.into());
    values.insert("evidence_protocol".into(), EVIDENCE_PROTOCOL.into());
    values.insert("deepwyrm_revision".into(), deep_revision.into());
    values.insert("generated_abi_revision".into(), abi_revision.into());
    values.insert("generated_abi_tree".into(), abi_tree.into());
    values.insert("wyrmroot_revision".into(), wyrmroot_revision);
    values.insert("rust_revision".into(), rust_revision);
    values.insert("evidence_nonce".into(), nonce.to_ascii_uppercase());
    values.insert("evidence_challenge".into(), challenge.to_ascii_uppercase());
    values.insert("default_handoff".into(), "default/handoff.toml".into());
    values.insert("smp_handoff".into(), "smp/handoff.toml".into());
    values.insert("receipt".into(), "build-receipt.toml".into());
    values.insert("profile_pair".into(), "profile-pair.toml".into());

    let request_text = render(&values, REQUEST_KEYS)?;
    let request_path = output.join("request.toml");
    write_new(&request_path, request_text.as_bytes(), "request")?;
    let request_sha256 = sha256::bytes_digest(request_text.as_bytes());
    let esp_sha256 = values
        .get("esp_sha256")
        .ok_or_else(|| Failure::task("C6 ESP digest was not recorded"))?;
    for (profile, vcpus) in [("default", 1_u8), ("smp", 4)] {
        stage_profile(output, profile, vcpus, &request_sha256, esp_sha256, &values)?;
    }
    write_profile_pair(output, &request_sha256)?;
    let mut receipt = BTreeMap::new();
    receipt.insert("kind".into(), RECEIPT_KIND.into());
    receipt.insert("schema_version".into(), SCHEMA_VERSION.to_string());
    receipt.insert("request_sha256".into(), request_sha256.clone());
    receipt.insert("selector".into(), SELECTOR.into());
    receipt.insert("test_id".into(), TEST_ID.to_string());
    receipt.insert("evidence_protocol".into(), EVIDENCE_PROTOCOL.into());
    receipt.insert("scenario".into(), SCENARIO.into());
    receipt.insert("physical_io".into(), "not-performed".into());
    let receipt_text = render(
        &receipt,
        &[
            "kind",
            "schema_version",
            "request_sha256",
            "selector",
            "test_id",
            "evidence_protocol",
            "scenario",
            "physical_io",
        ],
    )?;
    write_new(
        &output.join("build-receipt.toml"),
        receipt_text.as_bytes(),
        "receipt",
    )?;
    inspect(&request_path)?;
    Ok(format!(
        "WYR1_C6_FREEZE_PASS selector={SELECTOR} test_id={TEST_ID} evidence={EVIDENCE_PROTOCOL} request={} default_handoff={} smp_handoff={} physical_io=not-performed\n",
        request_path.display(),
        output.join("default/handoff.toml").display(),
        output.join("smp/handoff.toml").display(),
    ))
}

pub(crate) fn inspect(path: &Path) -> Result<String, Failure> {
    let request = load(path)?;
    require_mode(path, 0o444, "request")?;
    for (key, _, maximum) in ARTIFACTS {
        let relative = request.value(key)?;
        let artifact = request.root.join(relative);
        require_mode(&artifact, 0o444, key)?;
        let bytes = read_regular_bounded(&artifact, *maximum, key)?;
        if sha256::bytes_digest(&bytes) != request.value(&format!("{key}_sha256"))? {
            return Err(Failure::task(format!("WYR1-C6 {key} digest drifted")));
        }
    }
    let source_path = request.root.join(request.value("source_receipt")?);
    require_mode(&source_path, 0o444, "source receipt")?;
    let source_receipt = read_regular_bounded(&source_path, 64 * 1024, "C6 source receipt")?;
    if sha256::bytes_digest(&source_receipt) != request.value("source_receipt_sha256")? {
        return Err(Failure::task("WYR1-C6 source receipt digest drifted"));
    }
    verify_source_receipt(
        &source_receipt,
        &request.root.join("artifacts"),
        request.value("deepwyrm_revision")?,
        request.value("generated_abi_revision")?,
        request.value("generated_abi_tree")?,
        request.value("wyrmroot_revision")?,
        request.value("rust_revision")?,
        request.value("evidence_nonce")?,
    )?;
    let esp_path = request.root.join(request.value("esp")?);
    require_mode(&esp_path, 0o444, "ESP")?;
    let esp = read_regular_bounded(&esp_path, g3_image::IMAGE_BYTES, "ESP")?;
    if sha256::bytes_digest(&esp) != request.value("esp_sha256")? {
        return Err(Failure::task("WYR1-C6 ESP digest drifted"));
    }
    let gate = validate_gate(
        &read_regular_bounded(
            &request.root.join(request.value("bootfs")?),
            g3_image::IMAGE_BYTES,
            "bootfs",
        )?,
        request.value("evidence_nonce")?,
    )?;
    if sha256::bytes_digest(&gate) != request.value("gate_config_sha256")? {
        return Err(Failure::task("WYR1-C6 bootfs gate digest drifted"));
    }
    let args = G3ImageArguments {
        image: request
            .root
            .join(request.value("esp")?)
            .display()
            .to_string(),
        loader: request
            .root
            .join(request.value("loader")?)
            .display()
            .to_string(),
        kernel: request
            .root
            .join(request.value("kernel")?)
            .display()
            .to_string(),
        bootstrap: request
            .root
            .join(request.value("bootstrap")?)
            .display()
            .to_string(),
        bootfs: request
            .root
            .join(request.value("bootfs")?)
            .display()
            .to_string(),
    };
    g3_image::inspect_d6(
        &args,
        &request
            .root
            .join(request.value("boot_device_table")?)
            .display()
            .to_string(),
    )?;
    let request_sha256 = sha256::bytes_digest(&read_regular_bounded(path, 64 * 1024, "request")?);
    for (profile, vcpus, key) in [
        ("default", 1_u8, "default_handoff"),
        ("smp", 4, "smp_handoff"),
    ] {
        validate_handoff(
            &request.root.join(request.value(key)?),
            profile,
            vcpus,
            &request_sha256,
            request.value("esp_sha256")?,
        )?;
    }
    validate_profile_pair(&request.root, &request_sha256)?;
    require_mode(
        &request.root.join(request.value("receipt")?),
        0o444,
        "receipt",
    )?;
    Ok(format!(
        "WYR1_C6_INSPECTION_PASS selector={SELECTOR} test_id={TEST_ID} evidence={EVIDENCE_PROTOCOL} physical_io=not-performed\n"
    ))
}

/// The persistent VM is coordinator-owned.  This command refuses to create a
/// side channel; the immutable default/smp handoffs are the only run inputs.
pub(crate) fn run(path: &Path) -> Result<String, Failure> {
    let _ = inspect(path)?;
    Err(Failure::unavailable(
        "wyr1c6 run is coordinator-owned; use the frozen default/smp handoff with the designated OS-Project VM",
    ))
}

/// Evidence parsing is intentionally unavailable until the selector-29
/// collector lands.  A textual driver line is never substituted for WRC6E1.
pub(crate) fn evidence(
    path: &Path,
    default_log: &Path,
    smp_log: &Path,
    output: &Path,
) -> Result<String, Failure> {
    let _ = inspect(path)?;
    if output.exists() {
        return Err(Failure::task(
            "WYR1-C6 evidence receipt must be a fresh path",
        ));
    }
    let request = load(path)?;
    let nonce = request.value("evidence_nonce")?;
    let default = parse_evidence(
        &read_regular_bounded(default_log, 16 * 1024 * 1024, "default evidence")?,
        nonce,
    )?;
    let smp = parse_evidence(
        &read_regular_bounded(smp_log, 16 * 1024 * 1024, "SMP evidence")?,
        nonce,
    )?;
    let request_sha256 = sha256::bytes_digest(&read_regular_bounded(path, 64 * 1024, "request")?);
    let mut receipt = BTreeMap::new();
    for (key, value) in [
        ("kind", "wyrmroot-wyr1-c6-selector29-evidence-receipt"),
        ("schema_version", "1"),
        ("selector", SELECTOR),
        ("test_id", "29"),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("request_sha256", request_sha256.as_str()),
        ("default_sha256", default.sha256.as_str()),
        ("smp_sha256", smp.sha256.as_str()),
        ("default_records", "27"),
        ("smp_records", "27"),
        ("terminal", "kernel-verified"),
        ("physical_io", "not-performed"),
    ] {
        receipt.insert(key.to_owned(), value.to_owned());
    }
    let keys = [
        "kind",
        "schema_version",
        "selector",
        "test_id",
        "evidence_protocol",
        "request_sha256",
        "default_sha256",
        "smp_sha256",
        "default_records",
        "smp_records",
        "terminal",
        "physical_io",
    ];
    write_new(
        output,
        render(&receipt, &keys)?.as_bytes(),
        "evidence receipt",
    )?;
    Ok(format!(
        "WYR1_C6_EVIDENCE_PASS selector={SELECTOR} test_id={TEST_ID} evidence={EVIDENCE_PROTOCOL} default_records={} smp_records={} receipt={} physical_io=not-performed\n",
        default.records,
        smp.records,
        output.display(),
    ))
}

struct ParsedEvidence {
    records: usize,
    sha256: String,
}

fn parse_evidence(bytes: &[u8], nonce: &str) -> Result<ParsedEvidence, Failure> {
    // Fixed ASCII record: `WRC6|01|` + seven upper-hex fields separated by
    // bars, with no line terminator.  It is exactly 113 bytes, so prose on the serial line
    // cannot be mistaken for selector-29 evidence.
    const RECORD_BYTES: usize = 113;
    let mut records = Vec::new();
    let mut cursor = 0;
    while cursor + RECORD_BYTES <= bytes.len() {
        if &bytes[cursor..cursor + 5] == b"WRC6|" {
            records.push(&bytes[cursor..cursor + RECORD_BYTES]);
            cursor += RECORD_BYTES;
        } else {
            cursor += 1;
        }
    }
    if records.len() != 27 {
        return Err(Failure::task(
            "WRC6E1 requires exactly twenty-seven records",
        ));
    }
    let mut leases = Vec::with_capacity(27);
    let mut bindings = Vec::with_capacity(27);
    let mut values = Vec::with_capacity(27);
    let mut auxiliaries = Vec::with_capacity(27);
    for (sequence, line) in records.iter().enumerate() {
        if line.len() != RECORD_BYTES {
            return Err(Failure::task("WRC6E1 record size drifted"));
        }
        let text =
            std::str::from_utf8(line).map_err(|_| Failure::task("WRC6E1 record is not ASCII"))?;
        let fields = text.split('|').collect::<Vec<_>>();
        if fields.len() != 10 || fields[0] != "WRC6" || fields[1] != "01" || fields[2] != nonce {
            return Err(Failure::task("WRC6E1 header or nonce mismatch"));
        }
        for (field, length) in [
            (fields[3], 8),
            (fields[4], 2),
            (fields[5], 16),
            (fields[6], 16),
            (fields[7], 16),
            (fields[8], 16),
            (fields[9], 8),
        ] {
            if field.len() != length
                || !field
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F'))
            {
                return Err(Failure::task("WRC6E1 hexadecimal field is invalid"));
            }
        }
        let observed_sequence = u32::from_str_radix(fields[3], 16)
            .map_err(|_| Failure::task("WRC6E1 sequence is invalid"))?;
        if observed_sequence != sequence as u32 {
            return Err(Failure::task("WRC6E1 sequence is not contiguous"));
        }
        let expected_event = if sequence == 26 {
            0xff
        } else {
            (sequence + 1) as u8
        };
        if u8::from_str_radix(fields[4], 16)
            .map_err(|_| Failure::task("WRC6E1 event is invalid"))?
            != expected_event
        {
            return Err(Failure::task("WRC6E1 event order drifted"));
        }
        let observed_checksum = u32::from_str_radix(fields[9], 16)
            .map_err(|_| Failure::task("WRC6E1 checksum is invalid"))?;
        let checksum_input = &line[..105];
        if fnv1a(checksum_input) != observed_checksum {
            return Err(Failure::task("WRC6E1 checksum mismatch"));
        }
        leases.push(fields[5]);
        bindings.push(fields[6]);
        values.push(fields[7]);
        auxiliaries.push(fields[8]);
    }
    let zero = "0000000000000000";
    if [leases[26], bindings[26], values[26], auxiliaries[26]] != [zero; 4] {
        return Err(Failure::task("WRC6E1 terminal tuple must be zero"));
    }
    if leases[..26].contains(&zero) {
        return Err(Failure::task("WRC6E1 nonterminal lease is zero"));
    }
    let number = |field: &str| {
        u64::from_str_radix(field, 16)
            .map_err(|_| Failure::task("WRC6E1 numeric tuple field is invalid"))
    };
    let d1 = leases[0];
    if leases[..18].iter().any(|lease| *lease != d1)
        || bindings[0] != bindings[1]
        || values[0] != values[1]
        || auxiliaries[0] != auxiliaries[1]
    {
        return Err(Failure::task("WRC6E1 D1 begin/lease tuple drifted"));
    }
    let u1 = (bindings[2], values[2], auxiliaries[2]);
    if (bindings[3], values[3], auxiliaries[3]) != u1
        || (bindings[5], values[5], auxiliaries[5]) != u1
        || (bindings[7], values[7], auxiliaries[7]) != u1
    {
        return Err(Failure::task("WRC6E1 U1 tuple drifted"));
    }
    let p1 = (bindings[4], values[4], auxiliaries[4]);
    if (bindings[6], values[6], auxiliaries[6]) != p1
        || bindings[12] != p1.0
        || values[12] != p1.1
        || auxiliaries[12] != "0000000000000003"
    {
        return Err(Failure::task("WRC6E1 P1 retirement/stale tuple drifted"));
    }
    if bindings[8] != u1.0 || values[8] != "0000000000000001" || auxiliaries[8] != zero {
        return Err(Failure::task("WRC6E1 old interrupt release tuple drifted"));
    }
    let u2 = (bindings[9], values[9], auxiliaries[9]);
    // A fresh boot-monotonic endpoint ID begins at endpoint generation one,
    // so that field can equal U1's. The new Interrupt binding and strictly
    // newer attempt are the WRC6 freshness proof.
    if (bindings[10], values[10], auxiliaries[10]) != u2
        || (bindings[15], values[15], auxiliaries[15]) != u2
        || u2.0 == u1.0
        || number(u2.1)? <= number(u1.1)?
    {
        return Err(Failure::task("WRC6E1 U2 tuple is not fresh"));
    }
    let p2 = (bindings[11], values[11], auxiliaries[11]);
    if (bindings[14], values[14], auxiliaries[14]) != p2
        || p2.1 != u2.1
        || number(p2.0)? <= number(p1.0)?
    {
        return Err(Failure::task("WRC6E1 P2 tuple is not newer"));
    }
    if bindings[13] != p2.0
        || values[13] != values[0]
        || auxiliaries[13] != zero
        || bindings[16] != zero
        || values[16] != values[0]
        || auxiliaries[16] != "0000000000000001"
        || bindings[17] != zero
        || values[17] != "0000000000000001"
        || auxiliaries[17] != zero
    {
        return Err(Failure::task("WRC6E1 D1 recovery tuple drifted"));
    }
    let d2 = leases[18];
    if d2 == d1
        || d2 == zero
        || leases[18..26].iter().any(|lease| *lease != d2)
        || bindings[18] != "0000000000000001"
        || values[18] <= values[0]
        || (bindings[19], values[19], auxiliaries[19])
            != (bindings[18], values[18], auxiliaries[18])
        || (bindings[20], values[20], auxiliaries[20])
            != (bindings[18], values[18], auxiliaries[18])
        || (bindings[21], values[21], auxiliaries[21])
            != (bindings[18], values[18], auxiliaries[18])
    {
        return Err(Failure::task("WRC6E1 D2 custody tuple drifted"));
    }
    if bindings[22] != zero
        || values[22] != "0000000000000003"
        || auxiliaries[22] != zero
        || bindings[23] != zero
        || values[23] != zero
        || auxiliaries[23] != zero
        || bindings[24] != zero
        || bindings[25] != zero
        || values[25] != "0000000000000004"
    {
        return Err(Failure::task(
            "WRC6E1 no-authority/no-io/accounting tuple drifted",
        ));
    }
    let driver_failures = number(values[24])?;
    let devmgr_failures = number(auxiliaries[24])?;
    let backoff_ns = number(auxiliaries[25])?;
    if driver_failures > 4 || devmgr_failures > 4 || backoff_ns != 25_000_000 {
        return Err(Failure::task(
            "WRC6E1 bounded restart accounting exceeded policy",
        ));
    }
    Ok(ParsedEvidence {
        records: records.len(),
        sha256: sha256::bytes_digest(bytes),
    })
}

fn build_c6_bootstrap(
    repository: &Path,
    toolchain: &tasks::LoaderToolchain,
    layout: &crate::deep_layout::DeepLayoutBuild,
    cargo_home: &Path,
    build: &InheritableDirectory,
) -> Result<Vec<u8>, Failure> {
    toolchain.accepted().verify_unchanged()?;
    layout.verify_unchanged()?;
    let target = build.path().join("bootstrap-native");
    fs::create_dir(&target)
        .map_err(|error| Failure::task(format!("could not create C6 bootstrap target: {error}")))?;
    let source = fs::canonicalize(repository)
        .map_err(|error| Failure::task(format!("could not resolve C6 source root: {error}")))?;
    let cargo_home = fs::canonicalize(cargo_home)
        .map_err(|error| Failure::task(format!("could not resolve C6 Cargo home: {error}")))?;
    let target_identity = fs::canonicalize(&target).map_err(|error| {
        Failure::task(format!("could not resolve C6 bootstrap target: {error}"))
    })?;
    let flags = [
        format!("--remap-path-prefix={}=/source/wyrmroot", source.display()),
        format!("--remap-path-prefix={}=/cargo-home", cargo_home.display()),
        format!(
            "--remap-path-prefix={}=/cargo-target",
            target_identity.display()
        ),
    ]
    .join("\u{1f}");
    let status = Command::new(&toolchain.accepted().cargo)
        .args([
            "build",
            "--offline",
            "--locked",
            "--release",
            "--target",
            NATIVE_TARGET,
            "--package",
            "wyrmroot-bootstrap",
            "--bin",
            "wyrmroot-bootstrap",
            "--features",
            "wyr1c6-production",
        ])
        .arg("--target-dir")
        .arg(&target)
        .env("RUSTC", &toolchain.accepted().rustc)
        .env("CARGO_HOME", &cargo_home)
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
        .map_err(|error| Failure::task(format!("could not build C6 bootstrap: {error}")))?;
    if !status.success() {
        return Err(Failure::task("WYR1-C6 native bootstrap build failed"));
    }
    let bootstrap = PathBuf::from("bootstrap-native")
        .join(NATIVE_TARGET)
        .join("release")
        .join("wyrmroot-bootstrap");
    let bytes = build.read_producer(&bootstrap, MAX_ARTIFACT_BYTES, "bootstrap")?;
    build.with_inheritance_disabled("WYR1-C6 build directory", || {
        crate::wyr1c::inspect_native_bytes(
            repository,
            &bytes,
            &sha256::bytes_digest(&bytes),
            "bootstrap",
        )
    })?;
    toolchain.accepted().verify_unchanged()?;
    layout.verify_unchanged()?;
    Ok(bytes)
}

fn build_selector29_kernel(repository: &Path, nonce: &str) -> Result<Vec<u8>, Failure> {
    let repository = Directory::open_exact(repository, "Deepwyrm source root")?;
    let temporary = match repository.open_child(".tmp", "Deepwyrm temporary root") {
        Ok(directory) => directory,
        Err(_) => repository.create_child(".tmp", 0o700, "Deepwyrm temporary root")?,
    };
    temporary.verify_owned_container_path("Deepwyrm temporary root")?;
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
        .as_nanos();
    let scratch = temporary.create_scratch(
        &format!("wyr1c6-kernel-{}-{unique}", std::process::id()),
        "WYR1-C6 Deepwyrm target",
    )?;
    let result = (|| {
        let mut command = Command::new(repository.path().join("tools/pinned-cargo"));
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
            .env("DEEPWYRM_PINNED_TARGET_DIR", scratch.path())
            .env_remove("CARGO_HOME")
            .env_remove("LD_AUDIT")
            .env_remove("LD_LIBRARY_PATH")
            .env_remove("LD_PRELOAD")
            .current_dir(repository.path())
            .stdin(Stdio::null());
        for (key, value) in selector29_kernel_environment(nonce) {
            command.env(key, value);
        }
        let status = command
            .status()
            .map_err(|error| Failure::task(format!("could not build C6 kernel: {error}")))?;
        if !status.success() {
            return Err(Failure::task(
                "WYR1-C6 selector-29 Deepwyrm kernel build failed",
            ));
        }
        scratch.read_producer(
            &PathBuf::from(KERNEL_TARGET).join("release/deepwyrm-kernel"),
            MAX_ARTIFACT_BYTES,
            "selector-29 kernel",
        )
    })();
    scratch.finish(result)
}

fn selector29_kernel_environment(nonce: &str) -> [(&'static str, String); 2] {
    [
        ("DEEPWYRM_GUEST_TEST_SELECTOR", SELECTOR.to_owned()),
        ("DEEPWYRM_WYR1C_EVIDENCE_NONCE", nonce.to_owned()),
    ]
}

fn boot_device_table() -> Vec<u8> {
    const RESOURCE_ID: u64 = 1;
    const DEVICE_CORRELATION_ID: u64 = 1;
    const PIO_BASE: u16 = 0x02f8;
    const PIO_LENGTH: u16 = 8;
    const INTERRUPT_SOURCE: u32 = 3;
    let header = usize::try_from(DW_BOOT_DEVICE_TABLE_V1_SIZE).expect("table header fits");
    let stride = usize::try_from(DW_BOOT_DEVICE_TABLE_RECORD_STRIDE).expect("table stride fits");
    let total = header.checked_add(stride).expect("table length fits");
    let mut table = vec![0; total];
    write_u32(
        &mut table,
        core::mem::offset_of!(DwBootDeviceTableV1, size),
        DW_BOOT_DEVICE_TABLE_V1_SIZE,
    );
    write_u32(
        &mut table,
        core::mem::offset_of!(DwBootDeviceTableV1, version),
        DW_BOOT_DEVICE_TABLE_V1_VERSION,
    );
    write_u32(
        &mut table,
        core::mem::offset_of!(DwBootDeviceTableV1, resource_count),
        1,
    );
    write_u32(
        &mut table,
        core::mem::offset_of!(DwBootDeviceTableV1, flags),
        DW_BOOT_DEVICE_TABLE_FLAGS_SUPPORTED_MASK,
    );
    write_u32(
        &mut table,
        core::mem::offset_of!(DwBootDeviceTableV1, record_stride),
        DW_BOOT_DEVICE_TABLE_RECORD_STRIDE,
    );
    write_u64(
        &mut table,
        core::mem::offset_of!(DwBootDeviceTableV1, total_byte_len),
        u64::try_from(total).expect("table total fits"),
    );
    let record = header;
    write_u32(
        &mut table,
        record + core::mem::offset_of!(DwBootDeviceResourceV1, size),
        DW_BOOT_DEVICE_RESOURCE_V1_SIZE,
    );
    write_u32(
        &mut table,
        record + core::mem::offset_of!(DwBootDeviceResourceV1, version),
        DW_BOOT_DEVICE_RESOURCE_V1_VERSION,
    );
    write_u32(
        &mut table,
        record + core::mem::offset_of!(DwBootDeviceResourceV1, kind),
        DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT.0,
    );
    write_u32(
        &mut table,
        record + core::mem::offset_of!(DwBootDeviceResourceV1, flags),
        DW_BOOT_DEVICE_RESOURCE_FLAGS_SUPPORTED_MASK,
    );
    write_u64(
        &mut table,
        record + core::mem::offset_of!(DwBootDeviceResourceV1, resource_id),
        RESOURCE_ID,
    );
    write_u64(
        &mut table,
        record + core::mem::offset_of!(DwBootDeviceResourceV1, device_correlation_id),
        DEVICE_CORRELATION_ID,
    );
    write_u16(
        &mut table,
        record + core::mem::offset_of!(DwBootDeviceResourceV1, pio_base),
        PIO_BASE,
    );
    write_u16(
        &mut table,
        record + core::mem::offset_of!(DwBootDeviceResourceV1, pio_length),
        PIO_LENGTH,
    );
    write_u32(
        &mut table,
        record + core::mem::offset_of!(DwBootDeviceResourceV1, interrupt_source),
        INTERRUPT_SOURCE,
    );
    table
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn pinned_firmware(path: &str, expected: &str, label: &str) -> Result<Vec<u8>, Failure> {
    let bytes = read_regular_bounded(Path::new(path), MAX_FIRMWARE_BYTES, label)?;
    if sha256::bytes_digest(&bytes) != expected {
        return Err(Failure::task(format!(
            "WYR1-C6 pinned {label} identity changed"
        )));
    }
    Ok(bytes)
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
) -> Result<String, Failure> {
    let mut values = BTreeMap::new();
    for (key, value) in [
        (
            "kind",
            "wyrmroot-wyr1-c6-selector29-source-build".to_owned(),
        ),
        ("schema_version", "1".to_owned()),
        ("selector", SELECTOR.to_owned()),
        ("test_id", TEST_ID.to_string()),
        ("evidence_protocol", EVIDENCE_PROTOCOL.to_owned()),
        ("deepwyrm_revision", deep_revision.to_owned()),
        ("generated_abi_revision", abi_revision.to_owned()),
        ("generated_abi_tree", abi_tree.to_owned()),
        ("wyrmroot_revision", wyrmroot_revision.to_owned()),
        ("evidence_nonce", nonce.to_owned()),
        ("rust_revision", manifest.rust_revision()?.to_owned()),
        (
            "rust_toolchain_name",
            manifest.rust_toolchain_name()?.to_owned(),
        ),
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
            "loader_command",
            "accepted-cargo UEFI loader pair".to_owned(),
        ),
        (
            "kernel_command",
            "pinned-cargo selector29 ff1e WRC6".to_owned(),
        ),
        ("bootstrap_features", "wyr1c6-production".to_owned()),
        (
            "system_init_features",
            "wyr1c6-production,wyr1c6-selector29".to_owned(),
        ),
        (
            "devmgr_features",
            "wyr1c6-production,wyr1c6-selector29".to_owned(),
        ),
        (
            "uart16550d_features",
            "wyr1c6-production,wyr1c6-selector29".to_owned(),
        ),
        ("registryd_features", "native-registryd".to_owned()),
        ("consoled_features", "native-retained".to_owned()),
        ("wyrmsh_features", "native-retained".to_owned()),
        (
            "bootstrap_command",
            "accepted-cargo native bootstrap".to_owned(),
        ),
        (
            "system_init_command",
            "accepted-cargo native system-init".to_owned(),
        ),
        (
            "registryd_command",
            "accepted-cargo native registryd".to_owned(),
        ),
        ("devmgr_command", "accepted-cargo native devmgr".to_owned()),
        (
            "uart16550d_command",
            "accepted-cargo native uart16550d".to_owned(),
        ),
        (
            "consoled_command",
            "accepted-cargo native consoled".to_owned(),
        ),
        ("wyrmsh_command", "accepted-cargo native wyrmsh".to_owned()),
    ] {
        values.insert(key.to_owned(), value);
    }
    for (key, name, maximum) in ARTIFACTS {
        values.insert(
            format!("{key}_sha256"),
            sha256::bytes_digest(&read_regular_bounded(&artifacts.join(name), *maximum, key)?),
        );
    }
    render_sorted(&values)
}

fn canonical_deep_repository(input: &Path, project: &Path) -> Result<PathBuf, Failure> {
    if !input.is_absolute()
        || input.components().any(|component| {
            !matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(Failure::task(
            "WYR1-C6 Deepwyrm repository path is not canonical",
        ));
    }
    let canonical = fs::canonicalize(input).map_err(|error| {
        Failure::task(format!("could not resolve Deepwyrm repository: {error}"))
    })?;
    let expected = fs::canonicalize(project.join("deepwyrm")).map_err(|error| {
        Failure::task(format!(
            "could not resolve canonical Deepwyrm repository: {error}"
        ))
    })?;
    if canonical != input || canonical != expected {
        return Err(Failure::task(
            "WYR1-C6 Deepwyrm repository must be the canonical OS-Project sibling",
        ));
    }
    Ok(canonical)
}

fn canonical_new_output(
    output: &Path,
    project: &Path,
    repository: &Path,
    deep_repository: &Path,
) -> Result<PathBuf, Failure> {
    let parent = output
        .parent()
        .ok_or_else(|| Failure::task("WYR1-C6 output has no parent"))?;
    let parent = fs::canonicalize(parent)
        .map_err(|error| Failure::task(format!("could not resolve C6 output parent: {error}")))?;
    let name = output
        .file_name()
        .ok_or_else(|| Failure::task("WYR1-C6 output has no final component"))?;
    let result = parent.join(name);
    if !result.starts_with(project)
        || result.starts_with(repository)
        || result.starts_with(deep_repository)
    {
        return Err(Failure::task(
            "WYR1-C6 output must be beneath OS-Project and outside source repositories",
        ));
    }
    Ok(result)
}

fn matching_abi_tree(
    deep_repository: &Path,
    kernel_revision: &str,
    generated_abi_revision: &str,
) -> Result<String, Failure> {
    let kernel_tree = git_revision(deep_repository, &format!("{kernel_revision}:abi"))?;
    let generated_tree = git_revision(deep_repository, &format!("{generated_abi_revision}:abi"))?;
    validate_revision(&kernel_tree, "Deepwyrm ABI tree")?;
    validate_revision(&generated_tree, "generated ABI tree")?;
    if kernel_tree != generated_tree {
        return Err(Failure::task(
            "WYR1-C6 selected kernel does not match the generated ABI tree",
        ));
    }
    Ok(kernel_tree)
}

fn git_revision(repository: &Path, spec: &str) -> Result<String, Failure> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["rev-parse", spec])
        .output()
        .map_err(|error| Failure::task(format!("could not query Git revision: {error}")))?;
    if !output.status.success() {
        return Err(Failure::task("WYR1-C6 Git revision query failed"));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| Failure::task("WYR1-C6 Git revision is not UTF-8"))
}

fn verify_clean_revision(repository: &Path, label: &str, expected: &str) -> Result<(), Failure> {
    if git_revision(repository, "HEAD")? != expected {
        return Err(Failure::task(format!(
            "WYR1-C6 {label} revision changed during production"
        )));
    }
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["status", "--porcelain=v1", "--untracked-files=all"])
        .output()
        .map_err(|error| Failure::task(format!("could not inspect {label} status: {error}")))?;
    if !output.status.success() || !output.stdout.is_empty() {
        return Err(Failure::task(format!(
            "WYR1-C6 {label} source tree is no longer clean"
        )));
    }
    Ok(())
}

fn fnv1a(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c9dc5_u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x01000193)
    })
}

fn validate_gate(bootfs: &[u8], nonce: &str) -> Result<Vec<u8>, Failure> {
    let archive = Archive::new(bootfs)
        .map_err(|error| Failure::task(format!("WYR1-C6 bootfs is invalid: {error:?}")))?;
    let gate = archive
        .lookup(GATE_PATH)
        .map_err(|error| Failure::task(format!("WYR1-C6 bootfs gate is missing: {error:?}")))?;
    if gate.is_executable() {
        return Err(Failure::task("WYR1-C6 bootfs gate must be read-only"));
    }
    let text = std::str::from_utf8(gate.data())
        .map_err(|_| Failure::task("WYR1-C6 bootfs gate is not UTF-8"))?;
    let values = parse(text)?;
    let keys = [
        "schema",
        "selector",
        "test_id",
        "evidence_protocol",
        "nonce",
        "physical_io",
    ];
    if values.keys().map(String::as_str).collect::<BTreeSet<_>>() != keys.iter().copied().collect()
    {
        return Err(Failure::task("WYR1-C6 bootfs gate key set drifted"));
    }
    for (key, expected) in [
        ("schema", "1"),
        ("selector", SELECTOR),
        ("test_id", "29"),
        ("evidence_protocol", GATE_EVIDENCE_PROTOCOL),
        ("nonce", nonce),
        ("physical_io", "not-performed"),
    ] {
        if values.get(key).map(String::as_str) != Some(expected) {
            return Err(Failure::task(format!("WYR1-C6 bootfs gate {key} drifted")));
        }
    }
    Ok(gate.data().to_vec())
}

#[allow(clippy::too_many_arguments)]
fn verify_source_receipt(
    bytes: &[u8],
    artifacts: &Path,
    deep_revision: &str,
    abi_revision: &str,
    abi_tree: &str,
    wyrmroot_revision: &str,
    rust_revision: &str,
    nonce: &str,
) -> Result<(), Failure> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Failure::task("WYR1-C6 source receipt is not UTF-8"))?;
    let values = parse(text)?;
    let mut keys = BTreeSet::from([
        "kind".to_owned(),
        "schema_version".to_owned(),
        "selector".to_owned(),
        "test_id".to_owned(),
        "evidence_protocol".to_owned(),
        "deepwyrm_revision".to_owned(),
        "generated_abi_revision".to_owned(),
        "generated_abi_tree".to_owned(),
        "wyrmroot_revision".to_owned(),
        "evidence_nonce".to_owned(),
        "rust_revision".to_owned(),
        "rust_toolchain_name".to_owned(),
        "rustc_sha256".to_owned(),
        "cargo_sha256".to_owned(),
        "rust_lld_sha256".to_owned(),
        "toolchain_manifest_sha256".to_owned(),
        "toolchain_tree_sha256".to_owned(),
        "bootstrap_features".to_owned(),
        "system_init_features".to_owned(),
        "devmgr_features".to_owned(),
        "uart16550d_features".to_owned(),
        "registryd_features".to_owned(),
        "consoled_features".to_owned(),
        "wyrmsh_features".to_owned(),
        "bootstrap_command".to_owned(),
        "system_init_command".to_owned(),
        "registryd_command".to_owned(),
        "devmgr_command".to_owned(),
        "uart16550d_command".to_owned(),
        "consoled_command".to_owned(),
        "wyrmsh_command".to_owned(),
        "loader_command".to_owned(),
        "kernel_command".to_owned(),
    ]);
    for (key, _, _) in ARTIFACTS {
        keys.insert(format!("{key}_sha256"));
    }
    if values.keys().cloned().collect::<BTreeSet<_>>() != keys {
        return Err(Failure::task("WYR1-C6 source receipt key set drifted"));
    }
    for (key, expected) in [
        ("kind", "wyrmroot-wyr1-c6-selector29-source-build"),
        ("schema_version", "1"),
        ("selector", SELECTOR),
        ("test_id", "29"),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("deepwyrm_revision", deep_revision),
        ("generated_abi_revision", abi_revision),
        ("generated_abi_tree", abi_tree),
        ("wyrmroot_revision", wyrmroot_revision),
        ("evidence_nonce", nonce),
        ("rust_revision", rust_revision),
        ("rust_toolchain_name", ACCEPTED_TOOLCHAIN_NAME),
        ("bootstrap_features", "wyr1c6-production"),
        (
            "system_init_features",
            "wyr1c6-production,wyr1c6-selector29",
        ),
        ("devmgr_features", "wyr1c6-production,wyr1c6-selector29"),
        ("uart16550d_features", "wyr1c6-production,wyr1c6-selector29"),
        ("registryd_features", "native-registryd"),
        ("consoled_features", "native-retained"),
        ("wyrmsh_features", "native-retained"),
        ("bootstrap_command", "accepted-cargo native bootstrap"),
        ("system_init_command", "accepted-cargo native system-init"),
        ("registryd_command", "accepted-cargo native registryd"),
        ("devmgr_command", "accepted-cargo native devmgr"),
        ("uart16550d_command", "accepted-cargo native uart16550d"),
        ("consoled_command", "accepted-cargo native consoled"),
        ("wyrmsh_command", "accepted-cargo native wyrmsh"),
        ("loader_command", "accepted-cargo UEFI loader pair"),
        ("kernel_command", "pinned-cargo selector29 ff1e WRC6"),
    ] {
        if values.get(key).map(String::as_str) != Some(expected) {
            return Err(Failure::task(format!(
                "WYR1-C6 source receipt {key} drifted"
            )));
        }
    }
    if !values.contains_key("rust_toolchain_name") {
        return Err(Failure::task(
            "WYR1-C6 source receipt lacks a toolchain name",
        ));
    }
    for key in [
        "rustc_sha256",
        "cargo_sha256",
        "rust_lld_sha256",
        "toolchain_manifest_sha256",
        "toolchain_tree_sha256",
    ] {
        validate_lower_hex(value(&values, key)?, 64, key)?;
    }
    for (key, name, maximum) in ARTIFACTS {
        let actual =
            sha256::bytes_digest(&read_regular_bounded(&artifacts.join(name), *maximum, key)?);
        if values.get(&format!("{key}_sha256")).map(String::as_str) != Some(actual.as_str()) {
            return Err(Failure::task(format!(
                "WYR1-C6 source receipt {key} binding drifted"
            )));
        }
    }
    Ok(())
}

fn load(path: &Path) -> Result<Request, Failure> {
    let root = path
        .parent()
        .ok_or_else(|| Failure::task("WYR1-C6 request has no parent"))?
        .to_path_buf();
    let text = String::from_utf8(read_regular_bounded(path, 64 * 1024, "request")?)
        .map_err(|_| Failure::task("WYR1-C6 request is not UTF-8"))?;
    let values = parse(&text)?;
    if values.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != REQUEST_KEYS.iter().copied().collect()
    {
        return Err(Failure::task("WYR1-C6 request key set drifted"));
    }
    for (key, expected) in [
        ("kind", REQUEST_KIND),
        ("schema_version", "1"),
        ("selector", SELECTOR),
        ("test_id", "29"),
        ("profile", "wyr1c6-selector29"),
        ("scenario", SCENARIO),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
    ] {
        if values.get(key).map(String::as_str) != Some(expected) {
            return Err(Failure::task(format!("WYR1-C6 request {key} drifted")));
        }
    }
    for key in [
        "deepwyrm_revision",
        "generated_abi_revision",
        "generated_abi_tree",
        "wyrmroot_revision",
        "rust_revision",
    ] {
        validate_revision(value(&values, key)?, key)?;
    }
    validate_upper_hex_nonzero(value(&values, "evidence_nonce")?, 16, "evidence nonce")?;
    validate_upper_hex_nonzero(
        value(&values, "evidence_challenge")?,
        16,
        "evidence challenge",
    )?;
    for (key, name, _) in ARTIFACTS {
        let expected = format!("artifacts/{name}");
        if value(&values, key)? != expected {
            return Err(Failure::task(format!("WYR1-C6 request {key} path drifted")));
        }
        validate_lower_hex(value(&values, &format!("{key}_sha256"))?, 64, key)?;
    }
    for (key, expected) in [
        ("esp", "artifacts/selector29-esp.img"),
        ("default_handoff", "default/handoff.toml"),
        ("smp_handoff", "smp/handoff.toml"),
        ("receipt", "build-receipt.toml"),
        ("source_receipt", "artifacts/c6-source-build.toml"),
        ("profile_pair", "profile-pair.toml"),
    ] {
        if value(&values, key)? != expected {
            return Err(Failure::task(format!("WYR1-C6 request {key} path drifted")));
        }
    }
    validate_lower_hex(value(&values, "esp_sha256")?, 64, "ESP")?;
    validate_lower_hex(value(&values, "gate_config_sha256")?, 64, "bootfs gate")?;
    validate_lower_hex(
        value(&values, "source_receipt_sha256")?,
        64,
        "source receipt",
    )?;
    Ok(Request { root, values })
}

impl Request {
    fn value(&self, key: &str) -> Result<&str, Failure> {
        value(&self.values, key)
    }
}

fn stage_profile(
    output: &Path,
    profile: &str,
    vcpus: u8,
    request_sha256: &str,
    esp_sha256: &str,
    request: &BTreeMap<String, String>,
) -> Result<(), Failure> {
    let directory = output.join(profile);
    fs::create_dir(&directory).map_err(|error| {
        Failure::task(format!("could not create C6 {profile} handoff: {error}"))
    })?;
    let vars = read_regular_bounded(
        &output.join(value(request, "ovmf_vars")?),
        MAX_FIRMWARE_BYTES,
        "OVMF variables template",
    )?;
    let vars_path = directory.join("OVMF_VARS.fd");
    write_new_mode(&vars_path, &vars, 0o600, "profile OVMF variables")?;
    let vars_sha256 = sha256::bytes_digest(&vars);
    let absolute_output = fs::canonicalize(output)
        .map_err(|error| Failure::task(format!("could not resolve C6 output: {error}")))?;
    let xml = domain_xml(
        vcpus,
        &absolute_output.join(value(request, "ovmf_code")?),
        &absolute_output.join(value(request, "esp")?),
        &absolute_output.join(profile).join("OVMF_VARS.fd"),
    );
    let xml_path = directory.join("domain.xml");
    write_new(&xml_path, xml.as_bytes(), "profile domain XML")?;
    let xml_sha256 = sha256::bytes_digest(xml.as_bytes());
    let mut fields = BTreeMap::new();
    for (key, field) in [
        ("kind", HANDOFF_KIND),
        ("schema_version", "1"),
        ("profile", profile),
        ("selector", SELECTOR),
        ("test_id", "29"),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("request", "request.toml"),
        ("request_sha256", request_sha256),
        ("esp", value(request, "esp")?),
        ("esp_sha256", esp_sha256),
        ("vcpus", if vcpus == 1 { "1" } else { "4" }),
        ("scenario", SCENARIO),
        ("physical_io", "not-performed"),
        ("terminal_authority", "selector29-kernel-collector"),
        ("memory_mib", "2048"),
        ("machine", MACHINE),
        ("timeout_seconds", "300"),
        ("esp_fd_group", ESP_FD_GROUP),
        ("vars_fd_group", VARS_FD_GROUP),
        ("domain_xml", &format!("{profile}/domain.xml")),
        ("domain_xml_sha256", &xml_sha256),
        ("ovmf_vars", &format!("{profile}/OVMF_VARS.fd")),
        ("ovmf_vars_sha256", &vars_sha256),
        ("serial_log", &format!("{profile}/serial.log")),
        ("stderr_log", &format!("{profile}/qemu.stderr.log")),
        ("run_receipt", &format!("{profile}/run-receipt.toml")),
    ] {
        fields.insert(key.to_owned(), field.to_owned());
    }
    for (key, _, _) in ARTIFACTS {
        fields.insert(format!("{key}_path"), value(request, key)?.to_owned());
        fields.insert(
            format!("{key}_sha256"),
            value(request, &format!("{key}_sha256"))?.to_owned(),
        );
    }
    let handoff = render_sorted(&fields)?;
    write_new(
        &directory.join("handoff.toml"),
        handoff.as_bytes(),
        "VM handoff",
    )?;
    Ok(())
}

fn write_profile_pair(output: &Path, request_sha256: &str) -> Result<(), Failure> {
    let default = output.join("default/handoff.toml");
    let smp = output.join("smp/handoff.toml");
    let mut fields = BTreeMap::new();
    for (key, value) in [
        ("kind", "wyrmroot-wyr1-c6-selector29-vm-profile-pair"),
        ("schema_version", "1"),
        ("selector", SELECTOR),
        ("test_id", "29"),
        ("machine", MACHINE),
        ("memory_mib", "2048"),
        ("timeout_seconds", "300"),
        ("request", "request.toml"),
        ("request_sha256", request_sha256),
        ("default_handoff", "default/handoff.toml"),
        ("smp_handoff", "smp/handoff.toml"),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("scenario", SCENARIO),
        ("physical_io", "not-performed"),
    ] {
        fields.insert(key.to_owned(), value.to_owned());
    }
    for (key, path) in [
        ("default_handoff_sha256", &default),
        ("smp_handoff_sha256", &smp),
    ] {
        fields.insert(
            key.to_owned(),
            sha256::bytes_digest(&read_regular_bounded(path, 64 * 1024, "profile handoff")?),
        );
    }
    write_new(
        &output.join("profile-pair.toml"),
        render_sorted(&fields)?.as_bytes(),
        "profile pair",
    )
}

fn domain_xml(vcpus: u8, code: &Path, esp: &Path, vars: &Path) -> String {
    format!(
        "<domain xmlns:qemu=\"http://libvirt.org/schemas/domain/qemu/1.0\" type=\"qemu\">\n  <name>OS-Project</name>\n  <uuid>{DOMAIN_UUID}</uuid>\n  <memory unit=\"KiB\">2097152</memory><currentMemory unit=\"KiB\">2097152</currentMemory><vcpu placement=\"static\">{vcpus}</vcpu>\n  <sysinfo type=\"fwcfg\"><entry name=\"opt/org.deepwyrm.test.selector\">{SELECTOR}</entry><entry name=\"opt/org.deepwyrm.test.test_id\">{TEST_ID}</entry></sysinfo>\n  <os><type arch=\"x86_64\" machine=\"{MACHINE}\">hvm</type><loader readonly=\"yes\" secure=\"no\" type=\"pflash\" format=\"raw\">{}</loader><nvram type=\"file\" format=\"raw\"><source file=\"{}\" fdgroup=\"{VARS_FD_GROUP}\"/></nvram><boot dev=\"hd\"/></os>\n  <features><acpi/><apic/></features><clock offset=\"utc\"><timer name=\"rtc\" tickpolicy=\"catchup\"/><timer name=\"pit\" tickpolicy=\"delay\"/><timer name=\"hpet\" present=\"no\"/></clock><on_poweroff>destroy</on_poweroff><on_reboot>restart</on_reboot><on_crash>destroy</on_crash><pm><suspend-to-mem enabled=\"no\"/><suspend-to-disk enabled=\"no\"/></pm><devices><emulator>/usr/bin/qemu-system-x86_64</emulator><disk type=\"file\" device=\"disk\"><driver name=\"qemu\" type=\"raw\"/><source file=\"{}\" fdgroup=\"{ESP_FD_GROUP}\"/><target dev=\"vda\" bus=\"virtio\"/><readonly/></disk><controller type=\"pci\" index=\"0\" model=\"pcie-root\"/><serial type=\"pty\"><target type=\"isa-serial\" port=\"0\"/></serial><serial type=\"null\"><target type=\"isa-serial\" port=\"1\"/></serial><console type=\"pty\"><target type=\"serial\" port=\"0\"/></console></devices>\n  <qemu:commandline><qemu:arg value=\"-device\"/><qemu:arg value=\"isa-debug-exit,iobase=0xf4,iosize=0x04\"/></qemu:commandline>\n</domain>\n",
        code.display(),
        vars.display(),
        esp.display(),
    )
}

fn render_sorted(values: &BTreeMap<String, String>) -> Result<String, Failure> {
    let keys = values.keys().map(String::as_str).collect::<Vec<_>>();
    render(values, &keys)
}

#[cfg(test)]
fn render_handoff(
    profile: &str,
    vcpus: u8,
    request_sha256: &str,
    esp_sha256: &str,
) -> Result<String, Failure> {
    let mut values = BTreeMap::new();
    for (key, value) in [
        ("kind", HANDOFF_KIND),
        ("schema_version", "1"),
        ("profile", profile),
        ("selector", SELECTOR),
        ("test_id", "29"),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("request", "request.toml"),
        ("request_sha256", request_sha256),
        ("esp", "artifacts/selector29-esp.img"),
        ("esp_sha256", esp_sha256),
        ("vcpus", if vcpus == 1 { "1" } else { "4" }),
        ("scenario", SCENARIO),
        ("physical_io", "not-performed"),
        ("terminal_authority", "selector29-kernel-collector"),
    ] {
        values.insert(key.to_owned(), value.to_owned());
    }
    render(&values, HANDOFF_KEYS)
}

fn validate_handoff(
    path: &Path,
    profile: &str,
    vcpus: u8,
    request_sha256: &str,
    esp_sha256: &str,
) -> Result<(), Failure> {
    require_mode(path, 0o444, "VM handoff")?;
    let text = String::from_utf8(read_regular_bounded(path, 64 * 1024, "VM handoff")?)
        .map_err(|_| Failure::task("WYR1-C6 VM handoff is not UTF-8"))?;
    let values = parse(&text)?;
    let mut expected = BTreeSet::from(
        [
            "kind",
            "schema_version",
            "profile",
            "selector",
            "test_id",
            "evidence_protocol",
            "request",
            "request_sha256",
            "esp",
            "esp_sha256",
            "vcpus",
            "scenario",
            "physical_io",
            "terminal_authority",
            "memory_mib",
            "machine",
            "timeout_seconds",
            "esp_fd_group",
            "vars_fd_group",
            "domain_xml",
            "domain_xml_sha256",
            "ovmf_vars",
            "ovmf_vars_sha256",
            "serial_log",
            "stderr_log",
            "run_receipt",
        ]
        .map(str::to_owned),
    );
    for (name, _, _) in ARTIFACTS {
        expected.insert(format!("{name}_path"));
        expected.insert(format!("{name}_sha256"));
    }
    if values.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return Err(Failure::task("WYR1-C6 VM handoff key set drifted"));
    }
    for (key, expected) in [
        ("kind", HANDOFF_KIND),
        ("schema_version", "1"),
        ("profile", profile),
        ("selector", SELECTOR),
        ("test_id", "29"),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("request", "request.toml"),
        ("request_sha256", request_sha256),
        ("esp", "artifacts/selector29-esp.img"),
        ("esp_sha256", esp_sha256),
        ("vcpus", if vcpus == 1 { "1" } else { "4" }),
        ("scenario", SCENARIO),
        ("physical_io", "not-performed"),
        ("terminal_authority", "selector29-kernel-collector"),
    ] {
        if values.get(key).map(String::as_str) != Some(expected) {
            return Err(Failure::task(format!("WYR1-C6 VM handoff {key} drifted")));
        }
    }
    for (key, expected) in [
        ("memory_mib", "2048"),
        ("machine", MACHINE),
        ("timeout_seconds", "300"),
        ("esp_fd_group", ESP_FD_GROUP),
        ("vars_fd_group", VARS_FD_GROUP),
        ("domain_xml", &format!("{profile}/domain.xml")),
        ("ovmf_vars", &format!("{profile}/OVMF_VARS.fd")),
        ("serial_log", &format!("{profile}/serial.log")),
        ("stderr_log", &format!("{profile}/qemu.stderr.log")),
        ("run_receipt", &format!("{profile}/run-receipt.toml")),
    ] {
        if values.get(key).map(String::as_str) != Some(expected) {
            return Err(Failure::task(format!("WYR1-C6 VM handoff {key} drifted")));
        }
    }
    for key in ["domain_xml_sha256", "ovmf_vars_sha256"] {
        validate_lower_hex(value(&values, key)?, 64, key)?;
    }
    let root = path
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| Failure::task("WYR1-C6 VM handoff has no frozen root"))?;
    let domain = root.join(value(&values, "domain_xml")?);
    let vars = root.join(value(&values, "ovmf_vars")?);
    require_mode(&domain, 0o444, "domain XML")?;
    require_mode(&vars, 0o600, "profile OVMF vars")?;
    if sha256::bytes_digest(&read_regular_bounded(&domain, 64 * 1024, "domain XML")?)
        != value(&values, "domain_xml_sha256")?
        || sha256::bytes_digest(&read_regular_bounded(
            &vars,
            MAX_FIRMWARE_BYTES,
            "profile OVMF vars",
        )?) != value(&values, "ovmf_vars_sha256")?
    {
        return Err(Failure::task(
            "WYR1-C6 VM handoff local profile binding drifted",
        ));
    }
    Ok(())
}

fn validate_profile_pair(root: &Path, request_sha256: &str) -> Result<(), Failure> {
    let path = root.join("profile-pair.toml");
    require_mode(&path, 0o444, "profile pair")?;
    let text = String::from_utf8(read_regular_bounded(&path, 64 * 1024, "profile pair")?)
        .map_err(|_| Failure::task("WYR1-C6 profile pair is not UTF-8"))?;
    let values = parse(&text)?;
    let expected = [
        "kind",
        "schema_version",
        "selector",
        "test_id",
        "machine",
        "memory_mib",
        "timeout_seconds",
        "request",
        "request_sha256",
        "default_handoff",
        "smp_handoff",
        "evidence_protocol",
        "scenario",
        "physical_io",
        "default_handoff_sha256",
        "smp_handoff_sha256",
    ];
    if values.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != expected.iter().copied().collect()
    {
        return Err(Failure::task("WYR1-C6 profile pair key set drifted"));
    }
    for (key, expected) in [
        ("kind", "wyrmroot-wyr1-c6-selector29-vm-profile-pair"),
        ("schema_version", "1"),
        ("selector", SELECTOR),
        ("test_id", "29"),
        ("machine", MACHINE),
        ("memory_mib", "2048"),
        ("timeout_seconds", "300"),
        ("request", "request.toml"),
        ("request_sha256", request_sha256),
        ("default_handoff", "default/handoff.toml"),
        ("smp_handoff", "smp/handoff.toml"),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("scenario", SCENARIO),
        ("physical_io", "not-performed"),
    ] {
        if values.get(key).map(String::as_str) != Some(expected) {
            return Err(Failure::task(format!("WYR1-C6 profile pair {key} drifted")));
        }
    }
    for (key, relative) in [
        ("default_handoff_sha256", "default/handoff.toml"),
        ("smp_handoff_sha256", "smp/handoff.toml"),
    ] {
        validate_lower_hex(value(&values, key)?, 64, key)?;
        if sha256::bytes_digest(&read_regular_bounded(
            &root.join(relative),
            64 * 1024,
            "profile handoff",
        )?) != value(&values, key)?
        {
            return Err(Failure::task("WYR1-C6 profile pair handoff digest drifted"));
        }
    }
    Ok(())
}

fn parse(text: &str) -> Result<BTreeMap<String, String>, Failure> {
    if !text.ends_with('\n') || text.contains('\r') {
        return Err(Failure::task("WYR1-C6 TOML line endings are invalid"));
    }
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let (key, raw) = line
            .split_once(" = ")
            .ok_or_else(|| Failure::task("WYR1-C6 TOML line is malformed"))?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            || values.contains_key(key)
        {
            return Err(Failure::task("WYR1-C6 TOML key is invalid or duplicate"));
        }
        let value = if raw.bytes().all(|b| b.is_ascii_digit()) && !raw.is_empty() {
            raw
        } else if raw.starts_with('"') && raw.ends_with('"') && raw.len() >= 2 {
            let string = &raw[1..raw.len() - 1];
            if string.is_empty() || string.contains(['"', '\\']) {
                return Err(Failure::task("WYR1-C6 TOML string is invalid"));
            }
            string
        } else {
            return Err(Failure::task("WYR1-C6 TOML scalar is invalid"));
        };
        values.insert(key.into(), value.into());
    }
    Ok(values)
}

fn render(values: &BTreeMap<String, String>, keys: &[&str]) -> Result<String, Failure> {
    if values.keys().map(String::as_str).collect::<BTreeSet<_>>() != keys.iter().copied().collect()
    {
        return Err(Failure::task("WYR1-C6 render key set drifted"));
    }
    let mut text = String::new();
    for key in keys {
        let value = value(values, key)?;
        if matches!(*key, "schema_version" | "test_id" | "vcpus") {
            text.push_str(&format!("{key} = {value}\n"));
        } else {
            text.push_str(&format!("{key} = \"{value}\"\n"));
        }
    }
    Ok(text)
}

fn value<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, Failure> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| Failure::task(format!("WYR1-C6 value {key} is missing")))
}

fn read_regular_bounded(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>, Failure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Failure::task(format!("could not stat {label}: {error}")))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(Failure::task(format!(
            "WYR1-C6 {label} is not a bounded regular file"
        )));
    }
    fs::read(path).map_err(|error| Failure::task(format!("could not read {label}: {error}")))
}

fn require_mode(path: &Path, expected: u32, label: &str) -> Result<(), Failure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Failure::task(format!("could not stat {label}: {error}")))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != expected
    {
        return Err(Failure::task(format!("WYR1-C6 {label} mode drifted")));
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8], label: &str) -> Result<(), Failure> {
    write_new_mode(path, bytes, 0o444, label)
}

fn write_new_mode(path: &Path, bytes: &[u8], mode: u32, label: &str) -> Result<(), Failure> {
    if path.exists() {
        return Err(Failure::task(format!(
            "WYR1-C6 {label} output already exists"
        )));
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(0x2_0000)
        .open(path)
        .map_err(|error| Failure::task(format!("could not create {label}: {error}")))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| Failure::task(format!("could not write {label}: {error}")))?;
    seal_mode(path, mode, label)
}

fn seal_mode(path: &Path, mode: u32, label: &str) -> Result<(), Failure> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| Failure::task(format!("could not seal {label}: {error}")))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Failure::task(format!("could not recheck {label}: {error}")))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != mode
    {
        return Err(Failure::task(format!("WYR1-C6 {label} mode drifted")));
    }
    Ok(())
}

fn validate_revision(value: &str, label: &str) -> Result<(), Failure> {
    validate_lower_hex(value, 40, label)
}
fn validate_lower_hex(value: &str, length: usize, label: &str) -> Result<(), Failure> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(Failure::task(format!(
            "WYR1-C6 {label} is not lowercase hexadecimal"
        )));
    }
    Ok(())
}
fn validate_upper_hex_nonzero(value: &str, length: usize, label: &str) -> Result<(), Failure> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F'))
        || value.bytes().all(|byte| byte == b'0')
    {
        return Err(Failure::task(format!(
            "WYR1-C6 {label} is not nonzero uppercase hexadecimal"
        )));
    }
    Ok(())
}
fn clean_revision(repository: &Path, label: &str) -> Result<String, Failure> {
    let output = std::process::Command::new("git")
        .args(["status", "--porcelain=v1", "--untracked-files=all"])
        .current_dir(repository)
        .output()
        .map_err(|error| Failure::task(format!("could not inspect {label} status: {error}")))?;
    if !output.status.success() || !output.stdout.is_empty() {
        return Err(Failure::task(format!(
            "WYR1-C6 requires a clean {label} source tree"
        )));
    }
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repository)
        .output()
        .map_err(|error| Failure::task(format!("could not inspect {label} revision: {error}")))?;
    let revision = String::from_utf8(output.stdout)
        .map_err(|_| Failure::task("Git revision is not UTF-8"))?
        .trim()
        .to_owned();
    validate_revision(&revision, label)?;
    Ok(revision)
}
fn reject_selector_environment() -> Result<(), Failure> {
    for key in [
        "DEEPWYRM_GUEST_TEST_SELECTOR",
        "DEEPWYRM_GUEST_TEST_ID",
        "DEEPWYRM_WYR1C_EVIDENCE_NONCE",
        "CARGO_TARGET_DIR",
    ] {
        if std::env::var_os(key).is_some() {
            return Err(Failure::task(format!(
                "WYR1-C6 freeze refuses ambient {key}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_parser_rejects_selector_or_io_drift() {
        let mut values = BTreeMap::new();
        for key in REQUEST_KEYS {
            values.insert((*key).to_owned(), "x".to_owned());
        }
        values.insert("kind".into(), REQUEST_KIND.into());
        values.insert("schema_version".into(), "1".into());
        values.insert("selector".into(), SELECTOR.into());
        values.insert("test_id".into(), "29".into());
        values.insert("profile".into(), "wyr1c6-selector29".into());
        values.insert("scenario".into(), SCENARIO.into());
        values.insert("evidence_protocol".into(), EVIDENCE_PROTOCOL.into());
        for key in [
            "deepwyrm_revision",
            "generated_abi_revision",
            "generated_abi_tree",
            "wyrmroot_revision",
            "rust_revision",
        ] {
            values.insert(key.into(), "a".repeat(40));
        }
        for key in ["evidence_nonce", "evidence_challenge"] {
            values.insert(key.into(), "A".repeat(16));
        }
        for (key, _, _) in ARTIFACTS {
            values.insert((*key).into(), format!("artifacts/{key}"));
            values.insert(format!("{key}_sha256"), "b".repeat(64));
        }
        values.insert("esp".into(), "artifacts/selector29-esp.img".into());
        values.insert("esp_sha256".into(), "c".repeat(64));
        values.insert("default_handoff".into(), "default-handoff.toml".into());
        values.insert("smp_handoff".into(), "smp-handoff.toml".into());
        values.insert("receipt".into(), "build-receipt.toml".into());
        values.insert("gate_config_sha256".into(), "d".repeat(64));
        values.insert(
            "source_receipt".into(),
            format!("artifacts/{SOURCE_RECEIPT}"),
        );
        values.insert("source_receipt_sha256".into(), "e".repeat(64));
        let text = render(&values, REQUEST_KEYS).unwrap();
        let parsed = parse(&text).unwrap();
        assert_eq!(parsed.get("selector").unwrap(), SELECTOR);
        assert_eq!(parsed.get("scenario").unwrap(), SCENARIO);
        let hostile = text.replace("evidence_protocol", "evidence-protocol");
        assert!(parse(&hostile).is_err());
    }
    #[test]
    fn handoff_binds_one_cpu_and_four_cpu_profiles() {
        let request = "d".repeat(64);
        let esp = "e".repeat(64);
        let default = parse(&render_handoff("default", 1, &request, &esp).unwrap()).unwrap();
        let smp = parse(&render_handoff("smp", 4, &request, &esp).unwrap()).unwrap();
        assert_eq!(default.get("vcpus").unwrap(), "1");
        assert_eq!(smp.get("vcpus").unwrap(), "4");
        assert_eq!(default.get("physical_io").unwrap(), "not-performed");
        assert_eq!(default.get("evidence_protocol").unwrap(), EVIDENCE_PROTOCOL);
    }

    #[test]
    fn immutable_and_profile_vars_modes_are_sealed_exactly() {
        let root = std::env::temp_dir().join(format!(
            "wyr1c6-modes-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let immutable = root.join("immutable");
        let vars = root.join("OVMF_VARS.fd");
        write_new(&immutable, b"immutable", "immutable test").unwrap();
        write_new_mode(&vars, b"vars", 0o600, "vars test").unwrap();
        require_mode(&immutable, 0o444, "immutable test").unwrap();
        require_mode(&vars, 0o600, "vars test").unwrap();
        assert!(write_new(&immutable, b"replace", "immutable test").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn selector29_hex_fields_reject_nonhex_letters_and_zero_challenges() {
        assert!(validate_lower_hex(&"a".repeat(40), 40, "revision").is_ok());
        assert!(validate_lower_hex(&format!("{}g", "a".repeat(39)), 40, "revision").is_err());
        assert!(validate_upper_hex_nonzero("0123456789ABCDEF", 16, "nonce").is_ok());
        assert!(validate_upper_hex_nonzero("0000000000000000", 16, "nonce").is_err());
        assert!(validate_upper_hex_nonzero("0123456789ABCDEG", 16, "nonce").is_err());
    }

    #[test]
    fn source_receipt_rejects_missing_or_forged_producer_binding() {
        let root = source_fixture_directory();
        let nonce = "0123456789ABCDEF";
        let receipt = source_receipt_fixture(&root, nonce);
        verify_source_receipt(
            receipt.as_bytes(),
            &root,
            &"a".repeat(40),
            &"a".repeat(40),
            &"b".repeat(40),
            &"c".repeat(40),
            ACCEPTED_RUST_REVISION,
            nonce,
        )
        .unwrap();
        let missing = receipt
            .lines()
            .filter(|line| !line.starts_with("evidence_nonce = "))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        assert!(
            verify_source_receipt(
                missing.as_bytes(),
                &root,
                &"a".repeat(40),
                &"a".repeat(40),
                &"b".repeat(40),
                &"c".repeat(40),
                ACCEPTED_RUST_REVISION,
                nonce,
            )
            .is_err()
        );
        let loader = sha256::bytes_digest(
            &read_regular_bounded(&root.join("loader.efi"), MAX_ARTIFACT_BYTES, "loader").unwrap(),
        );
        let forged = receipt.replace(&loader, &"0".repeat(64));
        assert!(
            verify_source_receipt(
                forged.as_bytes(),
                &root,
                &"a".repeat(40),
                &"a".repeat(40),
                &"b".repeat(40),
                &"c".repeat(40),
                ACCEPTED_RUST_REVISION,
                nonce,
            )
            .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn selector29_kernel_environment_is_exact() {
        assert_eq!(
            selector29_kernel_environment("0123456789ABCDEF"),
            [
                ("DEEPWYRM_GUEST_TEST_SELECTOR", SELECTOR.to_owned()),
                (
                    "DEEPWYRM_WYR1C_EVIDENCE_NONCE",
                    "0123456789ABCDEF".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn selected_kernel_may_differ_when_the_generated_abi_tree_matches() {
        let root = std::env::temp_dir().join(format!(
            "wyr1c6-abi-tree-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let git = |arguments: &[&str]| {
            let output = Command::new("git")
                .args(["-c", "commit.gpgsign=false"])
                .arg("-C")
                .arg(&root)
                .args(arguments)
                .output()
                .unwrap();
            assert!(output.status.success(), "git {arguments:?} failed");
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        };
        git(&["init", "-q"]);
        git(&["config", "user.name", "C6 Test"]);
        git(&["config", "user.email", "c6@example.invalid"]);
        fs::create_dir(root.join("abi")).unwrap();
        fs::write(root.join("abi/schema"), b"stable").unwrap();
        git(&["add", "abi/schema"]);
        git(&["commit", "-q", "-m", "generated abi"]);
        let generated = git(&["rev-parse", "HEAD"]);
        fs::write(root.join("selector29-only"), b"private evidence").unwrap();
        git(&["add", "selector29-only"]);
        git(&["commit", "-q", "-m", "selector29 private evidence"]);
        let selected = git(&["rev-parse", "HEAD"]);
        assert_ne!(selected, generated);
        assert!(matching_abi_tree(&root, &selected, &generated).is_ok());
        fs::write(root.join("abi/schema"), b"drift").unwrap();
        git(&["add", "abi/schema"]);
        git(&["commit", "-q", "-m", "abi drift"]);
        let mismatched = git(&["rev-parse", "HEAD"]);
        assert!(matching_abi_tree(&root, &mismatched, &generated).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    fn source_fixture_directory() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "wyr1c6-source-receipt-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        for (key, name, _) in ARTIFACTS {
            write_new(&root.join(name), key.as_bytes(), key).unwrap();
        }
        root
    }

    fn source_receipt_fixture(root: &Path, nonce: &str) -> String {
        let mut values = BTreeMap::new();
        for (key, value) in [
            ("kind", "wyrmroot-wyr1-c6-selector29-source-build"),
            ("schema_version", "1"),
            ("selector", SELECTOR),
            ("test_id", "29"),
            ("evidence_protocol", EVIDENCE_PROTOCOL),
            ("deepwyrm_revision", &"a".repeat(40)),
            ("generated_abi_revision", &"a".repeat(40)),
            ("generated_abi_tree", &"b".repeat(40)),
            ("wyrmroot_revision", &"c".repeat(40)),
            ("evidence_nonce", nonce),
            ("rust_revision", ACCEPTED_RUST_REVISION),
            ("rust_toolchain_name", ACCEPTED_TOOLCHAIN_NAME),
            ("rustc_sha256", &"d".repeat(64)),
            ("cargo_sha256", &"e".repeat(64)),
            ("rust_lld_sha256", &"f".repeat(64)),
            ("toolchain_manifest_sha256", &"a".repeat(64)),
            ("toolchain_tree_sha256", &"b".repeat(64)),
            ("bootstrap_features", "wyr1c6-production"),
            (
                "system_init_features",
                "wyr1c6-production,wyr1c6-selector29",
            ),
            ("devmgr_features", "wyr1c6-production,wyr1c6-selector29"),
            ("uart16550d_features", "wyr1c6-production,wyr1c6-selector29"),
            ("registryd_features", "native-registryd"),
            ("consoled_features", "native-retained"),
            ("wyrmsh_features", "native-retained"),
            ("bootstrap_command", "accepted-cargo native bootstrap"),
            ("system_init_command", "accepted-cargo native system-init"),
            ("registryd_command", "accepted-cargo native registryd"),
            ("devmgr_command", "accepted-cargo native devmgr"),
            ("uart16550d_command", "accepted-cargo native uart16550d"),
            ("consoled_command", "accepted-cargo native consoled"),
            ("wyrmsh_command", "accepted-cargo native wyrmsh"),
            ("loader_command", "accepted-cargo UEFI loader pair"),
            ("kernel_command", "pinned-cargo selector29 ff1e WRC6"),
        ] {
            values.insert(key.to_owned(), value.to_owned());
        }
        for (key, name, maximum) in ARTIFACTS {
            values.insert(
                format!("{key}_sha256"),
                sha256::bytes_digest(
                    &read_regular_bounded(&root.join(name), *maximum, key).unwrap(),
                ),
            );
        }
        render_sorted(&values).unwrap()
    }
    #[test]
    fn evidence_requires_the_exact_kernel_collector_sequence() {
        let nonce = "0123456789ABCDEF";
        let mut stream = Vec::new();
        for sequence in 0..27_u32 {
            let event = if sequence == 26 {
                0xff
            } else {
                sequence as u8 + 1
            };
            let terminal = sequence == 26;
            let lease = if terminal {
                0
            } else if sequence < 18 {
                1
            } else {
                2
            };
            let (binding, value, auxiliary) = if terminal {
                (0, 0, 0)
            } else {
                match sequence {
                    0 | 1 => (1, 100, 9),
                    2 | 3 | 5 | 7 => (11, 101, 111),
                    4 | 6 => (21, 101, 121),
                    8 => (11, 1, 0),
                    // Each fresh boot-monotonic endpoint ID begins at endpoint
                    // generation one. U2 freshness is instead proved by its
                    // newer attempt and distinct Interrupt binding.
                    9 | 10 | 15 => (12, 102, 111),
                    11 | 14 => (22, 102, 122),
                    12 => (21, 101, 3),
                    13 => (22, 100, 0),
                    16 => (0, 100, 1),
                    17 => (0, 1, 0),
                    18..=21 => (1, 200, 9),
                    22 => (0, 3, 0),
                    23 => (0, 0, 0),
                    24 => (0, 1, 1),
                    25 => (0, 4, 25_000_000),
                    _ => unreachable!(),
                }
            };
            let body = format!(
                "WRC6|01|{nonce}|{sequence:08X}|{event:02X}|{lease:016X}|{binding:016X}|{value:016X}|{auxiliary:016X}|"
            );
            assert_eq!(body.len(), 105);
            stream.extend_from_slice(format!("{body}{:08X}", fnv1a(body.as_bytes())).as_bytes());
        }
        assert_eq!(stream.len(), 27 * 113);
        assert_eq!(parse_evidence(&stream, nonce).unwrap().records, 27);
        for (field, replacement) in [
            (54..70, b"000000000000000B".as_slice()),
            (71..87, b"0000000000000065".as_slice()),
        ] {
            let mut stale_u2 = stream.clone();
            let record = &mut stale_u2[9 * 113..10 * 113];
            record[field].copy_from_slice(replacement);
            let checksum = format!("{:08X}", fnv1a(&record[..105]));
            record[105..113].copy_from_slice(checksum.as_bytes());
            assert!(parse_evidence(&stale_u2, nonce).is_err());
        }
        let mut invalid_hex = stream.clone();
        invalid_hex[37] = b'G';
        let checksum = format!("{:08X}", fnv1a(&invalid_hex[..105]));
        invalid_hex[105..113].copy_from_slice(checksum.as_bytes());
        assert!(parse_evidence(&invalid_hex, nonce).is_err());
        stream[4 * 113 + 32] = b'F';
        assert!(parse_evidence(&stream, nonce).is_err());
    }
}
