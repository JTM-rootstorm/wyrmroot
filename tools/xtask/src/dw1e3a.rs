//! DW1-E3A selector-31 request, VM-handoff, and partial-evidence grammar.
//!
//! E3A deliberately stops after sequence 8: one production raw COM2
//! challenge/response round trip. It cannot emit or accept the 26-record
//! terminal, a `DWTEST1` line, or an acceptance receipt.

#![allow(dead_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    cli::G3ImageArguments,
    error::Failure,
    g3_image,
    secure_fs::{Directory, InheritableDirectory},
    sha256, tasks, wyr1c6,
};

pub(crate) const SELECTOR: &str = "q35-com2-interrupt";
pub(crate) const TEST_ID: &str = "31";
pub(crate) const EVIDENCE_PROTOCOL: &str = "DWE3E1";
pub(crate) const REQUEST_KIND: &str = "wyrmroot-dw1-e3a-selector31-request";
pub(crate) const HANDOFF_KIND: &str = "wyrmroot-dw1-e3a-selector31-vm-handoff";
pub(crate) const PROFILE_PAIR_KIND: &str = "wyrmroot-dw1-e3a-selector31-vm-profile-pair";
pub(crate) const RECEIPT_KIND: &str = "wyrmroot-dw1-e3a-selector31-receipt";
pub(crate) const SOURCE_RECEIPT_KIND: &str = "wyrmroot-dw1-e3a-selector31-source-build";
pub(crate) const PARTIAL_RESULT_KIND: &str = "wyrmroot-dw1-e3a-selector31-partial-result";
pub(crate) const READINESS_MARKER: &str =
    "DWE3READY|01|<NONCE16>|<STREAM16>|<CHALLENGE16>|<FNV16>|<FNV32>";
pub(crate) const ACCEPTANCE_CLAIM: &str = "partial-non-acceptance";
pub(crate) const TIMEOUT_SECONDS: &str = "120";
const SOURCE_RECEIPT: &str = "e3a-source-build.toml";
pub(crate) const E3B_CHALLENGE_1_NONCE_ENV: &str = "WYRMROOT_DW1E3_CHALLENGE_1_NONCE";
pub(crate) const E3B_CHALLENGE_2_NONCE_ENV: &str = "WYRMROOT_DW1E3_CHALLENGE_2_NONCE";
pub(crate) const E3B_FULL_KERNEL_ENV: &str = "DEEPWYRM_DW1E_E3B_FULL";
const NATIVE_TARGET: &str = "x86_64-unknown-wyrmroot";
const KERNEL_TARGET: &str = "x86_64-unknown-none";
const MACHINE: &str = "pc-q35-10.2";
const DOMAIN_UUID: &str = "33005e22-d7c2-4b13-b1ac-b82eda95e584";
const ESP_FD_GROUP: &str = "dw-f13-esp-v1";
const VARS_FD_GROUP: &str = "dw-f13-ovmf-vars-v1";
const COM1_FD_GROUP: &str = "dw-e3a-com1-evidence-v1";
const COM2_FD_GROUP: &str = "dw-e3a-com2-raw-v1";
const COM2_PRELUDE_KIND: &str = "ovmf-bds-session-banner";
const COM2_PRELUDE_LENGTH: &str = "354";
const COM2_PRELUDE_SHA256: &str =
    "8cf1a7eba89309b5ee101cbe77935604572151fb79f4e009a327125c5da8cb47";
const COM2_PRELUDE: &[u8] = concat!(
    "\x1b[2J\x1b[01;01H\x1b[=3h\x1b[2J\x1b[01;01H",
    "\x1b[2J\x1b[01;01H\x1b[=3h\x1b[2J\x1b[01;01H",
    "BdsDxe: loading Boot0001 \"UEFI Non-Block Boot Device\" from ",
    "PciRoot(0x0)/Pci(0x1,0x1)/Pci(0x0,0x0)\r\n",
    "BdsDxe: starting Boot0001 \"UEFI Non-Block Boot Device\" from ",
    "PciRoot(0x0)/Pci(0x1,0x1)/Pci(0x0,0x0)\r\n",
    "wyrmroot-loader: UEFI adapter online\r\n",
    "wyrmroot-loader: final UEFI memory map / ExitBootServices\r\n",
)
.as_bytes();

static E3B_PAYLOAD_ENVIRONMENT_LOCK: Mutex<()> = Mutex::new(());

/// Producer-owned entry into the accepted native product builder. The
/// request freezer consumes this snapshot together with its kernel/firmware
/// inputs; callers cannot substitute a sixth normal role for the probe.
pub(crate) fn build_product_snapshot(nonce: &str) -> Result<crate::wyr1c::E3ASnapshot, Failure> {
    reject_e3b_payload_environment()?;
    crate::wyr1c::build_e3a_snapshot(nonce)
}

/// Builds the E3B product snapshot with the two frozen raw-payload identities
/// scoped to the native Cargo invocations. This leaves the E3A build path and
/// its public interface unchanged.
fn build_e3b_product_snapshot(
    evidence_nonce: &str,
    challenge_1_nonce: &str,
    challenge_2_nonce: &str,
) -> Result<crate::wyr1c::E3ASnapshot, Failure> {
    with_e3b_payload_environment(challenge_1_nonce, challenge_2_nonce, || {
        crate::wyr1c::build_e3a_snapshot(evidence_nonce)
    })
}

fn with_e3b_payload_environment<T>(
    challenge_1_nonce: &str,
    challenge_2_nonce: &str,
    build: impl FnOnce() -> Result<T, Failure>,
) -> Result<T, Failure> {
    wyr1c6::validate_upper_hex_nonzero(challenge_1_nonce, 16, "DW1-E3B challenge 1 nonce")?;
    wyr1c6::validate_upper_hex_nonzero(challenge_2_nonce, 16, "DW1-E3B challenge 2 nonce")?;
    if challenge_1_nonce == challenge_2_nonce {
        return Err(Failure::task("DW1-E3B challenge nonces must be distinct"));
    }
    let _lock = E3B_PAYLOAD_ENVIRONMENT_LOCK
        .lock()
        .map_err(|_| Failure::task("DW1-E3B payload environment lock is poisoned"))?;
    reject_e3b_payload_environment()?;
    // SAFETY: the process-wide mutex serializes this narrow build-only scope.
    // The guard clears both values before the mutex is released.
    unsafe {
        env::set_var(E3B_CHALLENGE_1_NONCE_ENV, challenge_1_nonce);
        env::set_var(E3B_CHALLENGE_2_NONCE_ENV, challenge_2_nonce);
    }
    let _environment = ScopedE3BPayloadEnvironment;
    build()
}

struct ScopedE3BPayloadEnvironment;

impl Drop for ScopedE3BPayloadEnvironment {
    fn drop(&mut self) {
        // SAFETY: this guard only clears values installed by
        // `with_e3b_payload_environment` while its mutex remains held.
        unsafe {
            env::remove_var(E3B_CHALLENGE_1_NONCE_ENV);
            env::remove_var(E3B_CHALLENGE_2_NONCE_ENV);
        }
    }
}

pub(crate) struct ProducedArtifacts {
    pub(crate) directory: PathBuf,
    pub(crate) deep_revision: String,
    pub(crate) abi_revision: String,
    pub(crate) abi_tree: String,
    pub(crate) wyrmroot_revision: String,
    pub(crate) rust_revision: String,
}

#[derive(Clone, Copy)]
enum KernelMode {
    E3A,
    E3BFull,
}

/// Builds and freezes the complete selector-31 E3A handoff without starting
/// a VM. The output is a fresh, project-local directory containing immutable
/// shared inputs and two non-aliasing profile-local mutable-vars templates.
pub(crate) fn prepare(
    output: &Path,
    deep_repository: &Path,
    deep_revision: &str,
    nonce: &str,
) -> Result<String, Failure> {
    reject_selector_environment()?;
    wyr1c6::validate_revision(deep_revision, "Deepwyrm revision")?;
    wyr1c6::validate_upper_hex_nonzero(nonce, 16, "DW1-E3A evidence nonce")?;
    if output.exists() {
        return Err(Failure::task("DW1-E3A output must be a fresh path"));
    }

    let repository = tasks::repository_root()?;
    let project = tasks::canonical_project_root(&repository)?;
    let deep_repository = wyr1c6::canonical_deep_repository(deep_repository, &project)?;
    let wyrmroot_revision = wyr1c6::clean_revision(&repository, "Wyrmroot")?;
    wyr1c6::verify_clean_revision(&deep_repository, "Deepwyrm", deep_revision)?;
    let manifest = crate::metadata::BuildManifest::load(&repository)?;
    if manifest.rust_revision()? != wyr1c6::ACCEPTED_RUST_REVISION
        || manifest.rust_toolchain_name()? != wyr1c6::ACCEPTED_TOOLCHAIN_NAME
    {
        return Err(Failure::task(
            "DW1-E3A source metadata does not name the accepted Rust toolchain",
        ));
    }
    let abi_revision = manifest.deepwyrm_revision()?.to_owned();
    let abi_tree = wyr1c6::matching_abi_tree(&deep_repository, deep_revision, &abi_revision)?;
    let output = wyr1c6::canonical_new_output(output, &project, &repository, &deep_repository)?;
    let temporary = project.join(".tmp");
    fs::create_dir_all(&temporary).map_err(|error| {
        Failure::task(format!("could not create project temporary root: {error}"))
    })?;
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
        .as_nanos();
    let staging = temporary.join(format!("dw1e3a-producer-{}-{unique}", std::process::id()));
    fs::create_dir(&staging).map_err(|error| {
        Failure::task(format!(
            "could not create DW1-E3A producer staging: {error}"
        ))
    })?;

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
        freeze_produced(&output, &produced, nonce, build_esp)
    })();
    if result.is_ok() {
        fs::remove_dir_all(&staging)
            .map_err(|error| Failure::task(format!("could not retire DW1-E3A staging: {error}")))?;
    }
    result
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_produced_artifacts(
    staging: &Path,
    repository: &Path,
    deep_repository: &Path,
    wyrmroot_revision: &str,
    deep_revision: &str,
    abi_revision: &str,
    abi_tree: &str,
    nonce: &str,
) -> Result<ProducedArtifacts, Failure> {
    build_produced_artifacts_with_snapshot(
        staging,
        repository,
        deep_repository,
        wyrmroot_revision,
        deep_revision,
        abi_revision,
        abi_tree,
        nonce,
        KernelMode::E3A,
        || build_product_snapshot(nonce),
    )
}

/// E3B-only producer path. It binds the frozen leg nonces to every Cargo
/// process used by the Wyrmroot product snapshot, but never to Deepwyrm.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_e3b_produced_artifacts(
    staging: &Path,
    repository: &Path,
    deep_repository: &Path,
    wyrmroot_revision: &str,
    deep_revision: &str,
    abi_revision: &str,
    abi_tree: &str,
    evidence_nonce: &str,
    challenge_1_nonce: &str,
    challenge_2_nonce: &str,
) -> Result<ProducedArtifacts, Failure> {
    build_produced_artifacts_with_snapshot(
        staging,
        repository,
        deep_repository,
        wyrmroot_revision,
        deep_revision,
        abi_revision,
        abi_tree,
        evidence_nonce,
        KernelMode::E3BFull,
        || build_e3b_product_snapshot(evidence_nonce, challenge_1_nonce, challenge_2_nonce),
    )
}

#[allow(clippy::too_many_arguments)]
fn build_produced_artifacts_with_snapshot(
    staging: &Path,
    repository: &Path,
    deep_repository: &Path,
    wyrmroot_revision: &str,
    deep_revision: &str,
    abi_revision: &str,
    abi_tree: &str,
    nonce: &str,
    kernel_mode: KernelMode,
    build_snapshot: impl FnOnce() -> Result<crate::wyr1c::E3ASnapshot, Failure>,
) -> Result<ProducedArtifacts, Failure> {
    // No Wyrmroot-side build accepts the Deepwyrm-only E3B selector (or the
    // payload bindings) from its caller. E3B scopes its bindings later, only
    // around the native product snapshot.
    reject_e3b_payload_environment()?;
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
            "DW1-E3A prepare requires the pinned launcher's exact CARGO_HOME",
        ));
    }
    toolchain.accepted().verify_unchanged()?;
    layout.verify_unchanged()?;
    let build = staging.join("build");
    fs::create_dir(&build).map_err(|error| {
        Failure::task(format!("could not create DW1-E3A build directory: {error}"))
    })?;
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
    let build_directory = Directory::open_exact(&build, "DW1-E3A build directory")?;
    let bootstrap = build_directory
        .with_inheritable_anchor("DW1-E3A build directory", |anchor| {
            build_bootstrap(repository, &toolchain, &layout, &cargo_home, anchor)
        })?;
    let snapshot = build_snapshot()?;
    let kernel = build_kernel(deep_repository, nonce, kernel_mode)?;
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
        .map_err(|error| Failure::task(format!("could not create DW1-E3A artifacts: {error}")))?;
    let artifact = |name: &str| {
        snapshot
            .artifacts
            .get(name)
            .ok_or_else(|| Failure::task(format!("DW1-E3A builder omitted {name}")))
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
        ("dw1e3-com2-test.elf", artifact("dw1e3-com2-test")?),
        ("rrc-e3a-v1.bin", &snapshot.rrc_manifest),
        ("wrdm-e3a-v1.bin", &snapshot.device_manifest),
        ("boot-device-table.bin", &boot_device_table),
        ("bootfs.img", &snapshot.bootfs),
        ("OVMF_CODE.fd", &ovmf_code),
        ("OVMF_VARS.fd", &ovmf_vars),
    ] {
        wyr1c6::write_new(&artifacts.join(name), bytes, name)?;
    }
    let (challenge, response) = challenge_pair(nonce)?;
    let receipt = render_source_receipt(
        &manifest,
        toolchain.accepted(),
        deep_revision,
        abi_revision,
        abi_tree,
        wyrmroot_revision,
        nonce,
        &challenge,
        &response,
        &artifacts,
    )?;
    wyr1c6::write_new(
        &artifacts.join(SOURCE_RECEIPT),
        receipt.as_bytes(),
        "DW1-E3A source receipt",
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
    })
}

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
    ("dw1e3_com2_test", "dw1e3-com2-test.elf"),
    ("rrc_manifest", "rrc-e3a-v1.bin"),
    ("device_manifest", "wrdm-e3a-v1.bin"),
    ("boot_device_table", "boot-device-table.bin"),
    ("bootfs", "bootfs.img"),
    ("ovmf_code", "OVMF_CODE.fd"),
    ("ovmf_vars", "OVMF_VARS.fd"),
];

pub(crate) const REQUEST_KEYS: &[&str] = &[
    "kind",
    "schema_version",
    "selector",
    "test_id",
    "profile",
    "scenario",
    "evidence_protocol",
    "partial_evidence",
    "acceptance_claim",
    "readiness_marker",
    "com2_prelude_kind",
    "com2_prelude_hex",
    "com2_prelude_length",
    "com2_prelude_sha256",
    "deepwyrm_revision",
    "generated_abi_revision",
    "generated_abi_tree",
    "wyrmroot_revision",
    "rust_revision",
    "evidence_nonce",
    "challenge_hex",
    "challenge_length",
    "challenge_fnv1a64",
    "challenge_sha256",
    "response_hex",
    "response_length",
    "response_fnv1a64",
    "response_sha256",
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
    "dw1e3_com2_test",
    "dw1e3_com2_test_sha256",
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
    "profile_pair",
    "receipt",
    "source_receipt",
    "source_receipt_sha256",
];

pub(crate) const HANDOFF_KEYS: &[&str] = &[
    "kind",
    "schema_version",
    "profile",
    "selector",
    "test_id",
    "evidence_protocol",
    "partial_evidence",
    "acceptance_claim",
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
    "com2_prelude_kind",
    "com2_prelude_length",
    "com2_prelude_sha256",
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
    "partial_evidence_log",
    "result_path",
    "absent_receipt",
    "readiness_marker",
    "challenge_hex",
    "expected_response_hex",
    "loader_path",
    "loader_sha256",
    "kernel_path",
    "kernel_sha256",
    "symbols_path",
    "symbols_sha256",
    "bootstrap_path",
    "bootstrap_sha256",
    "system_init_path",
    "system_init_sha256",
    "registryd_path",
    "registryd_sha256",
    "devmgr_path",
    "devmgr_sha256",
    "uart16550d_path",
    "uart16550d_sha256",
    "consoled_path",
    "consoled_sha256",
    "wyrmsh_path",
    "wyrmsh_sha256",
    "dw1e3_com2_test_path",
    "dw1e3_com2_test_sha256",
    "rrc_manifest_path",
    "rrc_manifest_sha256",
    "device_manifest_path",
    "device_manifest_sha256",
    "boot_device_table_path",
    "boot_device_table_sha256",
    "bootfs_path",
    "bootfs_sha256",
    "ovmf_code_path",
    "ovmf_code_sha256",
    "ovmf_vars_path",
    "ovmf_vars_sha256",
];

pub(crate) const PROFILE_PAIR_KEYS: &[&str] = &[
    "kind",
    "schema_version",
    "selector",
    "test_id",
    "evidence_protocol",
    "partial_evidence",
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
];

const BUILD_RECEIPT_KEYS: &[&str] = &[
    "kind",
    "schema_version",
    "request_sha256",
    "selector",
    "test_id",
    "evidence_protocol",
    "scenario",
    "partial_evidence",
    "acceptance_claim",
    "physical_io",
];

const SOURCE_RECEIPT_KEYS: &[&str] = &[
    "kind",
    "schema_version",
    "selector",
    "test_id",
    "evidence_protocol",
    "deepwyrm_revision",
    "generated_abi_revision",
    "generated_abi_tree",
    "wyrmroot_revision",
    "evidence_nonce",
    "challenge_sha256",
    "response_sha256",
    "rust_revision",
    "rust_toolchain_name",
    "rustc_sha256",
    "cargo_sha256",
    "rust_lld_sha256",
    "toolchain_manifest_sha256",
    "toolchain_tree_sha256",
    "loader_command",
    "kernel_command",
    "bootstrap_features",
    "system_init_features",
    "registryd_features",
    "devmgr_features",
    "uart16550d_features",
    "consoled_features",
    "wyrmsh_features",
    "dw1e3_com2_test_features",
    "bootstrap_command",
    "system_init_command",
    "registryd_command",
    "devmgr_command",
    "uart16550d_command",
    "consoled_command",
    "wyrmsh_command",
    "dw1e3_com2_test_command",
    "loader_sha256",
    "kernel_sha256",
    "symbols_sha256",
    "bootstrap_sha256",
    "system_init_sha256",
    "registryd_sha256",
    "devmgr_sha256",
    "uart16550d_sha256",
    "consoled_sha256",
    "wyrmsh_sha256",
    "dw1e3_com2_test_sha256",
    "rrc_manifest_sha256",
    "device_manifest_sha256",
    "boot_device_table_sha256",
    "bootfs_sha256",
    "ovmf_code_sha256",
    "ovmf_vars_sha256",
];

pub(crate) fn build_bootstrap(
    repository: &Path,
    toolchain: &tasks::LoaderToolchain,
    layout: &crate::deep_layout::DeepLayoutBuild,
    cargo_home: &Path,
    build: &InheritableDirectory,
) -> Result<Vec<u8>, Failure> {
    toolchain.accepted().verify_unchanged()?;
    layout.verify_unchanged()?;
    let target = build.path().join("bootstrap-native");
    fs::create_dir(&target).map_err(|error| {
        Failure::task(format!(
            "could not create DW1-E3A bootstrap target: {error}"
        ))
    })?;
    let source = fs::canonicalize(repository).map_err(|error| {
        Failure::task(format!("could not resolve DW1-E3A source root: {error}"))
    })?;
    let cargo_home = fs::canonicalize(cargo_home)
        .map_err(|error| Failure::task(format!("could not resolve DW1-E3A Cargo home: {error}")))?;
    let target_identity = fs::canonicalize(&target).map_err(|error| {
        Failure::task(format!(
            "could not resolve DW1-E3A bootstrap target: {error}"
        ))
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
            "wyr1c5-production",
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
        .map_err(|error| Failure::task(format!("could not build DW1-E3A bootstrap: {error}")))?;
    if !status.success() {
        return Err(Failure::task("DW1-E3A native bootstrap build failed"));
    }
    let relative = PathBuf::from("bootstrap-native")
        .join(NATIVE_TARGET)
        .join("release")
        .join("wyrmroot-bootstrap");
    let bytes = build.read_producer(&relative, wyr1c6::MAX_ARTIFACT_BYTES, "bootstrap")?;
    build.with_inheritance_disabled("DW1-E3A build directory", || {
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

fn build_kernel(repository: &Path, nonce: &str, mode: KernelMode) -> Result<Vec<u8>, Failure> {
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
        &format!("dw1e3a-kernel-{}-{unique}", std::process::id()),
        "DW1-E3A Deepwyrm target",
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
            .current_dir(repository.path())
            .stdin(Stdio::null());
        configure_kernel_environment(&mut command, scratch.path(), nonce, mode);
        let status = command
            .status()
            .map_err(|error| Failure::task(format!("could not build DW1-E3A kernel: {error}")))?;
        if !status.success() {
            return Err(Failure::task(
                "DW1-E3A selector-31 Deepwyrm kernel build failed",
            ));
        }
        scratch.read_producer(
            &PathBuf::from(KERNEL_TARGET).join("release/deepwyrm-kernel"),
            wyr1c6::MAX_ARTIFACT_BYTES,
            "selector-31 kernel",
        )
    })();
    scratch.finish(result)
}

fn configure_kernel_environment(
    command: &mut Command,
    scratch: &Path,
    nonce: &str,
    mode: KernelMode,
) {
    command
        .env("DEEPWYRM_PINNED_TARGET_DIR", scratch)
        .env("DEEPWYRM_GUEST_TEST_SELECTOR", SELECTOR)
        .env("DEEPWYRM_DW1E_EVIDENCE_NONCE", nonce)
        .env_remove(E3B_FULL_KERNEL_ENV)
        .env_remove(E3B_CHALLENGE_1_NONCE_ENV)
        .env_remove(E3B_CHALLENGE_2_NONCE_ENV)
        .env_remove("CARGO_HOME")
        .env_remove("LD_AUDIT")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD");
    if matches!(mode, KernelMode::E3BFull) {
        command.env(E3B_FULL_KERNEL_ENV, "1");
    }
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
    challenge: &[u8],
    response: &[u8],
    artifacts: &Path,
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
        ("evidence_nonce", nonce.to_owned()),
        ("challenge_sha256", sha256::bytes_digest(challenge)),
        ("response_sha256", sha256::bytes_digest(response)),
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
            "pinned-cargo selector31 ff1f DWE3E1".to_owned(),
        ),
        ("bootstrap_features", "wyr1c5-production".to_owned()),
        ("system_init_features", "dw1e3-selector31".to_owned()),
        ("registryd_features", "native-registryd".to_owned()),
        ("devmgr_features", "dw1e3-selector31".to_owned()),
        ("uart16550d_features", "dw1e3-selector31".to_owned()),
        ("consoled_features", "native-retained".to_owned()),
        ("wyrmsh_features", "native-retained".to_owned()),
        ("dw1e3_com2_test_features", "native-probe".to_owned()),
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
        (
            "dw1e3_com2_test_command",
            "accepted-cargo native dw1e3-com2-test".to_owned(),
        ),
    ] {
        values.insert(key.to_owned(), value);
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
    render_with_integers(&values, SOURCE_RECEIPT_KEYS, &["schema_version", "test_id"])
}

fn freeze_produced(
    output: &Path,
    produced: &ProducedArtifacts,
    nonce: &str,
    esp_builder: impl FnOnce(&Path, &BTreeMap<String, String>) -> Result<(), Failure>,
) -> Result<String, Failure> {
    if output.exists() {
        return Err(Failure::task("DW1-E3A output must be a fresh path"));
    }
    fs::create_dir(output)
        .map_err(|error| Failure::task(format!("could not create DW1-E3A output: {error}")))?;
    let frozen = output.join("artifacts");
    fs::create_dir(&frozen).map_err(|error| {
        Failure::task(format!(
            "could not create DW1-E3A frozen artifacts: {error}"
        ))
    })?;
    let mut values = BTreeMap::new();
    let source = wyr1c6::read_regular_bounded(
        &produced.directory.join(SOURCE_RECEIPT),
        64 * 1024,
        "DW1-E3A source receipt",
    )?;
    wyr1c6::write_new(
        &frozen.join(SOURCE_RECEIPT),
        &source,
        "DW1-E3A source receipt",
    )?;
    values.insert(
        "source_receipt".into(),
        format!("artifacts/{SOURCE_RECEIPT}"),
    );
    values.insert(
        "source_receipt_sha256".into(),
        sha256::bytes_digest(&source),
    );
    for (key, name) in ARTIFACTS {
        let bytes = wyr1c6::read_regular_bounded(
            &produced.directory.join(name),
            artifact_maximum(key),
            key,
        )?;
        wyr1c6::write_new(&frozen.join(name), &bytes, key)?;
        values.insert((*key).to_owned(), format!("artifacts/{name}"));
        values.insert(format!("{key}_sha256"), sha256::bytes_digest(&bytes));
    }
    esp_builder(output, &values)?;
    let esp = frozen.join("selector31-esp.img");
    wyr1c6::seal_mode(&esp, 0o444, "DW1-E3A ESP")?;
    values.insert("esp".into(), "artifacts/selector31-esp.img".into());
    values.insert(
        "esp_sha256".into(),
        sha256::bytes_digest(&wyr1c6::read_regular_bounded(
            &esp,
            g3_image::IMAGE_BYTES,
            "DW1-E3A ESP",
        )?),
    );
    let (challenge, response) = challenge_pair(nonce)?;
    for (key, value) in [
        ("kind", REQUEST_KIND.to_owned()),
        ("schema_version", "1".to_owned()),
        ("selector", SELECTOR.to_owned()),
        ("test_id", TEST_ID.to_owned()),
        ("profile", "dw1e3a-selector31".to_owned()),
        ("scenario", "one-production-raw-com2-round-trip".to_owned()),
        ("evidence_protocol", EVIDENCE_PROTOCOL.to_owned()),
        ("partial_evidence", "true".to_owned()),
        ("acceptance_claim", ACCEPTANCE_CLAIM.to_owned()),
        ("readiness_marker", READINESS_MARKER.to_owned()),
        ("com2_prelude_kind", COM2_PRELUDE_KIND.to_owned()),
        ("com2_prelude_hex", upper_hex(COM2_PRELUDE)),
        ("com2_prelude_length", COM2_PRELUDE_LENGTH.to_owned()),
        ("com2_prelude_sha256", COM2_PRELUDE_SHA256.to_owned()),
        ("deepwyrm_revision", produced.deep_revision.clone()),
        ("generated_abi_revision", produced.abi_revision.clone()),
        ("generated_abi_tree", produced.abi_tree.clone()),
        ("wyrmroot_revision", produced.wyrmroot_revision.clone()),
        ("rust_revision", produced.rust_revision.clone()),
        ("evidence_nonce", nonce.to_owned()),
        ("challenge_hex", upper_hex(&challenge)),
        ("challenge_length", challenge.len().to_string()),
        ("challenge_fnv1a64", format!("{:016X}", fnv1a64(&challenge))),
        ("challenge_sha256", sha256::bytes_digest(&challenge)),
        ("response_hex", upper_hex(&response)),
        ("response_length", response.len().to_string()),
        ("response_fnv1a64", format!("{:016X}", fnv1a64(&response))),
        ("response_sha256", sha256::bytes_digest(&response)),
        ("default_handoff", "default/handoff.toml".to_owned()),
        ("smp_handoff", "smp/handoff.toml".to_owned()),
        ("profile_pair", "profile-pair.toml".to_owned()),
        ("receipt", "build-receipt.toml".to_owned()),
    ] {
        values.insert(key.to_owned(), value);
    }
    let request_text = render_request(&values)?;
    let request_path = output.join("request.toml");
    wyr1c6::write_new(&request_path, request_text.as_bytes(), "DW1-E3A request")?;
    let request_sha256 = sha256::bytes_digest(request_text.as_bytes());
    for (profile, vcpus) in [("default", 1_u8), ("smp", 4)] {
        stage_profile(output, profile, vcpus, &request_sha256, &values)?;
    }
    write_profile_pair(output, &request_sha256)?;
    let mut receipt = BTreeMap::new();
    for (key, value) in [
        ("kind", RECEIPT_KIND),
        ("schema_version", "1"),
        ("request_sha256", request_sha256.as_str()),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("scenario", "one-production-raw-com2-round-trip"),
        ("partial_evidence", "true"),
        ("acceptance_claim", ACCEPTANCE_CLAIM),
        ("physical_io", "real-com2-irq3-intended"),
    ] {
        receipt.insert(key.to_owned(), value.to_owned());
    }
    wyr1c6::write_new(
        &output.join("build-receipt.toml"),
        render_with_integers(&receipt, BUILD_RECEIPT_KEYS, &["schema_version", "test_id"])?
            .as_bytes(),
        "DW1-E3A build receipt",
    )?;
    validate_frozen_output(output, &values, &request_sha256)?;
    Ok(format!(
        "DW1_E3A_PREPARE_PASS selector={SELECTOR} test_id={TEST_ID} evidence={EVIDENCE_PROTOCOL} request={} default_handoff={} smp_handoff={} profile_pair={} partial_evidence=true acceptance_claim={ACCEPTANCE_CLAIM}\n",
        request_path.display(),
        output.join("default/handoff.toml").display(),
        output.join("smp/handoff.toml").display(),
        output.join("profile-pair.toml").display(),
    ))
}

pub(crate) fn build_esp(output: &Path, values: &BTreeMap<String, String>) -> Result<(), Failure> {
    let frozen = output.join("artifacts");
    let arguments = G3ImageArguments {
        image: frozen.join("selector31-esp.img").display().to_string(),
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
    request_sha256: &str,
    request: &BTreeMap<String, String>,
) -> Result<(), Failure> {
    let directory = output.join(profile);
    fs::create_dir(&directory).map_err(|error| {
        Failure::task(format!(
            "could not create DW1-E3A {profile} profile: {error}"
        ))
    })?;
    let vars = wyr1c6::read_regular_bounded(
        &output.join(value(request, "ovmf_vars")?),
        wyr1c6::MAX_FIRMWARE_BYTES,
        "DW1-E3A OVMF vars template",
    )?;
    let vars_path = directory.join("OVMF_VARS.mutable.fd");
    wyr1c6::write_new_mode(&vars_path, &vars, 0o600, "DW1-E3A mutable OVMF vars")?;
    let absolute = fs::canonicalize(output)
        .map_err(|error| Failure::task(format!("could not resolve DW1-E3A output: {error}")))?;
    let xml = domain_xml(
        vcpus,
        &absolute.join(value(request, "ovmf_code")?),
        &absolute.join(value(request, "esp")?),
        &absolute.join(profile).join("OVMF_VARS.mutable.fd"),
        &absolute.join(profile).join("com2.sock"),
    );
    let xml_path = directory.join("domain.xml");
    wyr1c6::write_new(&xml_path, xml.as_bytes(), "DW1-E3A domain XML")?;
    let xml_sha256 = sha256::bytes_digest(xml.as_bytes());
    let vars_sha256 = sha256::bytes_digest(&vars);
    let mut fields = BTreeMap::new();
    for (key, field) in [
        ("kind", HANDOFF_KIND),
        ("schema_version", "1"),
        ("profile", profile),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("partial_evidence", "true"),
        ("acceptance_claim", ACCEPTANCE_CLAIM),
        ("request", "request.toml"),
        ("request_sha256", request_sha256),
        ("esp", value(request, "esp")?),
        ("esp_sha256", value(request, "esp_sha256")?),
        ("vcpus", if vcpus == 1 { "1" } else { "4" }),
        ("memory_mib", "2048"),
        ("machine", MACHINE),
        ("firmware", "OVMF"),
        ("timeout_seconds", TIMEOUT_SECONDS),
        ("scenario", "one-production-raw-com2-round-trip"),
        ("physical_io", "real-com2-irq3-intended"),
        ("terminal_authority", "deepwyrm-selector31-partial-only"),
        ("com1_role", "trusted-evidence-and-readiness"),
        ("com2_role", "raw-challenge-response"),
        ("com2_transport", "unix-socket-byte-stream"),
        ("com2_socket_mode", "connect"),
        ("com2_socket_owner", "runner"),
        ("com2_prelude_kind", value(request, "com2_prelude_kind")?),
        (
            "com2_prelude_length",
            value(request, "com2_prelude_length")?,
        ),
        (
            "com2_prelude_sha256",
            value(request, "com2_prelude_sha256")?,
        ),
        ("com1_fd_group", COM1_FD_GROUP),
        ("com2_fd_group", COM2_FD_GROUP),
        ("esp_fd_group", ESP_FD_GROUP),
        ("vars_fd_group", VARS_FD_GROUP),
        ("domain_xml", &format!("{profile}/domain.xml")),
        ("domain_xml_sha256", &xml_sha256),
        (
            "mutable_ovmf_vars",
            &format!("{profile}/OVMF_VARS.mutable.fd"),
        ),
        ("mutable_ovmf_vars_initial_sha256", &vars_sha256),
        ("com2_socket", &format!("{profile}/com2.sock")),
        ("com1_serial_log", &format!("{profile}/com1.log")),
        ("com2_log", &format!("{profile}/com2.bin")),
        (
            "partial_evidence_log",
            &format!("{profile}/partial-evidence.log"),
        ),
        ("result_path", &format!("{profile}/result.toml")),
        (
            "absent_receipt",
            &format!("{profile}/acceptance-receipt.toml"),
        ),
        ("readiness_marker", READINESS_MARKER),
        ("challenge_hex", value(request, "challenge_hex")?),
        ("expected_response_hex", value(request, "response_hex")?),
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
    let handoff = render_handoff(&fields)?;
    wyr1c6::write_new(
        &directory.join("handoff.toml"),
        handoff.as_bytes(),
        "DW1-E3A handoff",
    )
}

fn write_profile_pair(output: &Path, request_sha256: &str) -> Result<(), Failure> {
    let mut fields = BTreeMap::new();
    for (key, field) in [
        ("kind", PROFILE_PAIR_KIND),
        ("schema_version", "1"),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("partial_evidence", "true"),
        ("acceptance_claim", ACCEPTANCE_CLAIM),
        ("request", "request.toml"),
        ("request_sha256", request_sha256),
        ("profiles", "default,smp"),
        ("default_handoff", "default/handoff.toml"),
        ("default_vcpus", "1"),
        ("smp_handoff", "smp/handoff.toml"),
        ("smp_vcpus", "4"),
        ("memory_mib", "2048"),
        ("machine", MACHINE),
        ("firmware", "OVMF"),
        ("timeout_seconds", TIMEOUT_SECONDS),
    ] {
        fields.insert(key.to_owned(), field.to_owned());
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
                "DW1-E3A handoff",
            )?),
        );
    }
    wyr1c6::write_new(
        &output.join("profile-pair.toml"),
        render_profile_pair(&fields)?.as_bytes(),
        "DW1-E3A profile pair",
    )
}

pub(crate) fn domain_xml(vcpus: u8, code: &Path, esp: &Path, vars: &Path, com2: &Path) -> String {
    selected_domain_xml(vcpus, code, esp, vars, com2, (SELECTOR, TEST_ID))
}

pub(crate) fn selected_domain_xml(
    vcpus: u8,
    code: &Path,
    esp: &Path,
    vars: &Path,
    com2: &Path,
    selection: (&str, &str),
) -> String {
    let (selector, test_id) = selection;
    format!(
        "<domain xmlns:qemu=\"http://libvirt.org/schemas/domain/qemu/1.0\" type=\"qemu\">\n  <name>OS-Project</name>\n  <uuid>{DOMAIN_UUID}</uuid>\n  <memory unit=\"KiB\">2097152</memory><currentMemory unit=\"KiB\">2097152</currentMemory><vcpu placement=\"static\">{vcpus}</vcpu>\n  <sysinfo type=\"fwcfg\"><entry name=\"opt/org.deepwyrm.test.selector\">{selector}</entry><entry name=\"opt/org.deepwyrm.test.test_id\">{test_id}</entry></sysinfo>\n  <os><type arch=\"x86_64\" machine=\"{MACHINE}\">hvm</type><loader readonly=\"yes\" secure=\"no\" type=\"pflash\" format=\"raw\">{}</loader><nvram type=\"file\" format=\"raw\"><source file=\"{}\" fdgroup=\"{VARS_FD_GROUP}\"/></nvram><boot dev=\"hd\"/></os>\n  <features><acpi/><apic/></features><clock offset=\"utc\"><timer name=\"rtc\" tickpolicy=\"catchup\"/><timer name=\"pit\" tickpolicy=\"delay\"/><timer name=\"hpet\" present=\"no\"/></clock><on_poweroff>destroy</on_poweroff><on_reboot>restart</on_reboot><on_crash>destroy</on_crash><pm><suspend-to-mem enabled=\"no\"/><suspend-to-disk enabled=\"no\"/></pm><devices><emulator>/usr/bin/qemu-system-x86_64</emulator><disk type=\"file\" device=\"disk\"><driver name=\"qemu\" type=\"raw\"/><source file=\"{}\" fdgroup=\"{ESP_FD_GROUP}\"/><target dev=\"vda\" bus=\"virtio\"/><readonly/></disk><controller type=\"pci\" index=\"0\" model=\"pcie-root\"/><serial type=\"pty\"><target type=\"isa-serial\" port=\"0\"/></serial><serial type=\"unix\"><source mode=\"connect\" path=\"{}\"/><target type=\"isa-serial\" port=\"1\"/></serial><console type=\"pty\"><target type=\"serial\" port=\"0\"/></console></devices>\n  <qemu:commandline><qemu:arg value=\"-device\"/><qemu:arg value=\"isa-debug-exit,iobase=0xf4,iosize=0x04\"/></qemu:commandline>\n</domain>\n",
        xml_escape(code),
        xml_escape(vars),
        xml_escape(esp),
        xml_escape(com2),
    )
}

fn xml_escape(path: &Path) -> String {
    path.display()
        .to_string()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub(crate) fn challenge_pair(nonce: &str) -> Result<([u8; 24], [u8; 24]), Failure> {
    wyr1c6::validate_upper_hex_nonzero(nonce, 16, "DW1-E3A evidence nonce")?;
    let number = u64::from_str_radix(nonce, 16)
        .map_err(|_| Failure::task("DW1-E3A evidence nonce is invalid"))?;
    let mut challenge = [0u8; 24];
    challenge[..8].copy_from_slice(b"\r\n\0\x7fDW1E");
    challenge[8..16].copy_from_slice(&number.to_le_bytes());
    challenge[16..24].copy_from_slice(&number.rotate_left(17).to_le_bytes());
    let mut response = [0u8; 24];
    for (index, byte) in response.iter_mut().enumerate() {
        *byte = challenge[23 - index] ^ 0xa5u8.wrapping_add(index as u8);
    }
    Ok((challenge, response))
}

pub(crate) fn upper_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

pub(crate) const fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325;
    let mut index = 0;
    while index < bytes.len() {
        hash ^= bytes[index] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        index += 1;
    }
    hash
}

pub(crate) fn artifact_maximum(key: &str) -> u64 {
    if matches!(key, "ovmf_code" | "ovmf_vars") {
        wyr1c6::MAX_FIRMWARE_BYTES
    } else if key == "bootfs" {
        g3_image::IMAGE_BYTES
    } else {
        wyr1c6::MAX_ARTIFACT_BYTES
    }
}

pub(crate) fn reject_selector_environment() -> Result<(), Failure> {
    for key in [
        "DEEPWYRM_GUEST_TEST_SELECTOR",
        "DEEPWYRM_GUEST_TEST_ID",
        "DEEPWYRM_DW1E_EVIDENCE_NONCE",
        E3B_FULL_KERNEL_ENV,
        E3B_CHALLENGE_1_NONCE_ENV,
        E3B_CHALLENGE_2_NONCE_ENV,
        "CARGO_TARGET_DIR",
    ] {
        if env::var_os(key).is_some() {
            return Err(Failure::task(format!(
                "DW1-E3A prepare refuses ambient {key}"
            )));
        }
    }
    Ok(())
}

fn reject_e3b_payload_environment() -> Result<(), Failure> {
    for key in [
        E3B_CHALLENGE_1_NONCE_ENV,
        E3B_CHALLENGE_2_NONCE_ENV,
        E3B_FULL_KERNEL_ENV,
    ] {
        if env::var_os(key).is_some() {
            return Err(Failure::task(format!(
                "DW1-E3A product build refuses ambient {key}"
            )));
        }
    }
    Ok(())
}

fn validate_frozen_output(
    output: &Path,
    request: &BTreeMap<String, String>,
    request_sha256: &str,
) -> Result<(), Failure> {
    for (key, name) in ARTIFACTS {
        let path = output.join(value(request, key)?);
        let bytes = wyr1c6::read_regular_bounded(&path, artifact_maximum(key), key)?;
        if sha256::bytes_digest(&bytes) != value(request, &format!("{key}_sha256"))?
            || path.file_name().and_then(|name| name.to_str()) != Some(name)
        {
            return Err(Failure::task(format!(
                "DW1-E3A frozen {key} identity drifted"
            )));
        }
    }
    for profile in ["default", "smp"] {
        let bytes = wyr1c6::read_regular_bounded(
            &output.join(profile).join("handoff.toml"),
            64 * 1024,
            "DW1-E3A handoff",
        )?;
        let text =
            String::from_utf8(bytes).map_err(|_| Failure::task("DW1-E3A handoff is not UTF-8"))?;
        if !text.contains(&format!("request_sha256 = \"{request_sha256}\""))
            || text.contains("DWTEST1")
        {
            return Err(Failure::task("DW1-E3A handoff join drifted"));
        }
        for absent in [
            "com2.sock",
            "com1.log",
            "com2.bin",
            "partial-evidence.log",
            "result.toml",
            "acceptance-receipt.toml",
        ] {
            if output.join(profile).join(absent).exists() {
                return Err(Failure::task("DW1-E3A runtime output exists before VM run"));
            }
        }
    }
    Ok(())
}

pub(crate) fn render_request(values: &BTreeMap<String, String>) -> Result<String, Failure> {
    require(values, "kind", REQUEST_KIND)?;
    require(values, "schema_version", "1")?;
    require(values, "selector", SELECTOR)?;
    require(values, "test_id", TEST_ID)?;
    require(values, "profile", "dw1e3a-selector31")?;
    require(values, "scenario", "one-production-raw-com2-round-trip")?;
    require(values, "evidence_protocol", EVIDENCE_PROTOCOL)?;
    require(values, "partial_evidence", "true")?;
    require(values, "acceptance_claim", ACCEPTANCE_CLAIM)?;
    require(values, "readiness_marker", READINESS_MARKER)?;
    require(values, "com2_prelude_kind", COM2_PRELUDE_KIND)?;
    require(values, "com2_prelude_hex", &upper_hex(COM2_PRELUDE))?;
    require(values, "com2_prelude_length", COM2_PRELUDE_LENGTH)?;
    require(values, "com2_prelude_sha256", COM2_PRELUDE_SHA256)?;
    require(values, "challenge_length", "24")?;
    require(values, "response_length", "24")?;
    require(values, "default_handoff", "default/handoff.toml")?;
    require(values, "smp_handoff", "smp/handoff.toml")?;
    require(values, "profile_pair", "profile-pair.toml")?;
    require(values, "receipt", "build-receipt.toml")?;
    require(values, "source_receipt", "artifacts/e3a-source-build.toml")?;
    reject_terminal(values)?;
    render_with_integers(values, REQUEST_KEYS, &["schema_version", "test_id"])
}

pub(crate) fn render_handoff(values: &BTreeMap<String, String>) -> Result<String, Failure> {
    require(values, "kind", HANDOFF_KIND)?;
    let profile = value(values, "profile")?;
    let expected_vcpus = match profile {
        "default" => "1",
        "smp" => "4",
        _ => {
            return Err(Failure::task(
                "DW1-E3A handoff profile must be default or smp",
            ));
        }
    };
    for (key, expected) in [
        ("schema_version", "1"),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("partial_evidence", "true"),
        ("acceptance_claim", ACCEPTANCE_CLAIM),
        ("vcpus", expected_vcpus),
        ("memory_mib", "2048"),
        ("machine", "pc-q35-10.2"),
        ("firmware", "OVMF"),
        ("timeout_seconds", TIMEOUT_SECONDS),
        ("scenario", "one-production-raw-com2-round-trip"),
        ("physical_io", "real-com2-irq3-intended"),
        ("terminal_authority", "deepwyrm-selector31-partial-only"),
        ("com1_role", "trusted-evidence-and-readiness"),
        ("com2_role", "raw-challenge-response"),
        ("com2_transport", "unix-socket-byte-stream"),
        ("com2_socket_mode", "connect"),
        ("com2_socket_owner", "runner"),
        ("com2_prelude_kind", COM2_PRELUDE_KIND),
        ("com2_prelude_length", COM2_PRELUDE_LENGTH),
        ("com2_prelude_sha256", COM2_PRELUDE_SHA256),
        ("com1_fd_group", "dw-e3a-com1-evidence-v1"),
        ("com2_fd_group", "dw-e3a-com2-raw-v1"),
        ("esp_fd_group", "dw-f13-esp-v1"),
        ("vars_fd_group", "dw-f13-ovmf-vars-v1"),
        ("readiness_marker", READINESS_MARKER),
    ] {
        require(values, key, expected)?;
    }
    for (key, name) in [
        ("domain_xml", "domain.xml"),
        ("mutable_ovmf_vars", "OVMF_VARS.mutable.fd"),
        ("com2_socket", "com2.sock"),
        ("com1_serial_log", "com1.log"),
        ("com2_log", "com2.bin"),
        ("partial_evidence_log", "partial-evidence.log"),
        ("result_path", "result.toml"),
        ("absent_receipt", "acceptance-receipt.toml"),
    ] {
        require(values, key, &format!("{profile}/{name}"))?;
    }
    reject_terminal(values)?;
    render_with_integers(
        values,
        HANDOFF_KEYS,
        &[
            "schema_version",
            "test_id",
            "vcpus",
            "memory_mib",
            "timeout_seconds",
        ],
    )
}

pub(crate) fn render_profile_pair(values: &BTreeMap<String, String>) -> Result<String, Failure> {
    for (key, expected) in [
        ("kind", PROFILE_PAIR_KIND),
        ("schema_version", "1"),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("partial_evidence", "true"),
        ("acceptance_claim", ACCEPTANCE_CLAIM),
        ("profiles", "default,smp"),
        ("default_handoff", "default/handoff.toml"),
        ("default_vcpus", "1"),
        ("smp_handoff", "smp/handoff.toml"),
        ("smp_vcpus", "4"),
        ("memory_mib", "2048"),
        ("machine", "pc-q35-10.2"),
        ("firmware", "OVMF"),
        ("timeout_seconds", TIMEOUT_SECONDS),
    ] {
        require(values, key, expected)?;
    }
    reject_terminal(values)?;
    render_with_integers(
        values,
        PROFILE_PAIR_KEYS,
        &[
            "schema_version",
            "test_id",
            "default_vcpus",
            "smp_vcpus",
            "memory_mib",
            "timeout_seconds",
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PartialEvidence {
    pub(crate) records: usize,
    pub(crate) sha256: String,
    pub(crate) stream_generation: u64,
    pub(crate) challenge_generation: u64,
}

pub(crate) fn parse_partial_evidence(
    bytes: &[u8],
    nonce: &str,
    challenge_length: u64,
    challenge_fnv1a64: u64,
    response_length: u64,
    response_fnv1a64: u64,
) -> Result<PartialEvidence, Failure> {
    if nonce.len() != 16 || bytes.len() != 9 * 204 || bytes.windows(7).any(|w| w == b"DWTEST1") {
        return Err(Failure::task(
            "DW1-E3A evidence is not the exact nine-record partial prefix",
        ));
    }
    let events = [1u8, 2, 3, 4, 5, 6, 7, 8, 9];
    let actors = [0u8, 0, 0, 0, 0, 0, 1, 0, 2];
    let mut joined = None;
    for sequence in 0..9 {
        let record = &bytes[sequence * 204..(sequence + 1) * 204];
        if &record[..6] != b"DWE3E1"
            || &record[7..9] != b"01"
            || record[203] != b'\n'
            || &record[10..26] != nonce.as_bytes()
            || parse_hex(&record[27..35])? != sequence as u64
            || parse_hex(&record[36..38])? != u64::from(events[sequence])
            || parse_hex(&record[39..41])? != u64::from(actors[sequence])
            || parse_hex(&record[195..203])? != u64::from(fnv1a32(&record[..195]))
        {
            return Err(Failure::task("DW1-E3A partial evidence record drifted"));
        }
        let stream = parse_hex(&record[127..143])?;
        let challenge = parse_hex(&record[144..160])?;
        if sequence >= 3 {
            if stream == 0
                || challenge == 0
                || joined.is_some_and(|pair| pair != (stream, challenge))
            {
                return Err(Failure::task("DW1-E3A stream/challenge join drifted"));
            }
            joined = Some((stream, challenge));
        }
        let value = parse_hex(&record[161..177])?;
        let auxiliary = parse_hex(&record[178..194])?;
        if (sequence == 6 && (value != challenge_length || auxiliary != challenge_fnv1a64))
            || (sequence == 8 && (value != response_length || auxiliary != response_fnv1a64))
        {
            return Err(Failure::task("DW1-E3A raw payload evidence drifted"));
        }
    }
    let (stream_generation, challenge_generation) =
        joined.ok_or_else(|| Failure::task("DW1-E3A partial evidence lacks an attached stream"))?;
    Ok(PartialEvidence {
        records: 9,
        sha256: sha256::bytes_digest(bytes),
        stream_generation,
        challenge_generation,
    })
}

fn reject_terminal(values: &BTreeMap<String, String>) -> Result<(), Failure> {
    if values.iter().any(|(key, value)| {
        key.contains("terminal") && key != "terminal_authority"
            || value.contains("DWTEST1")
            || value.contains("26-record")
    }) {
        return Err(Failure::task(
            "DW1-E3A cannot claim selector terminal acceptance",
        ));
    }
    Ok(())
}

fn render(values: &BTreeMap<String, String>, keys: &[&str]) -> Result<String, Failure> {
    render_with_integers(values, keys, &[])
}

fn render_with_integers(
    values: &BTreeMap<String, String>,
    keys: &[&str],
    integer_keys: &[&str],
) -> Result<String, Failure> {
    let expected: BTreeSet<_> = keys.iter().copied().collect();
    let actual: BTreeSet<_> = values.keys().map(String::as_str).collect();
    if actual != expected {
        let missing = expected.difference(&actual).copied().collect::<Vec<_>>();
        let extra = actual.difference(&expected).copied().collect::<Vec<_>>();
        return Err(Failure::task(format!(
            "DW1-E3A schema key set drifted: missing={missing:?} extra={extra:?}"
        )));
    }
    let mut output = String::new();
    for key in keys {
        let value = value(values, key)?;
        output.push_str(key);
        output.push_str(" = ");
        if integer_keys.contains(key) {
            if value.is_empty()
                || !value.bytes().all(|byte| byte.is_ascii_digit())
                || (value.len() != 1 && value.starts_with('0'))
            {
                return Err(Failure::task(format!(
                    "DW1-E3A {key} is not a canonical integer"
                )));
            }
            output.push_str(value);
            output.push('\n');
        } else {
            let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
            output.push('"');
            output.push_str(&escaped);
            output.push_str("\"\n");
        }
    }
    Ok(output)
}

fn require(values: &BTreeMap<String, String>, key: &str, expected: &str) -> Result<(), Failure> {
    if value(values, key)? != expected {
        return Err(Failure::task(format!("DW1-E3A {key} drifted")));
    }
    Ok(())
}

fn value<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, Failure> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| Failure::task(format!("DW1-E3A omitted {key}")))
}

fn parse_hex(bytes: &[u8]) -> Result<u64, Failure> {
    let mut value = 0u64;
    for byte in bytes {
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'A'..=b'F' => u64::from(byte - b'A' + 10),
            _ => return Err(Failure::task("DW1-E3A evidence hex is malformed")),
        };
        value = value
            .checked_mul(16)
            .and_then(|value| value.checked_add(digit))
            .ok_or_else(|| Failure::task("DW1-E3A evidence hex overflow"))?;
    }
    Ok(value)
}

const fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    let mut index = 0;
    while index < bytes.len() {
        hash ^= bytes[index] as u32;
        hash = hash.wrapping_mul(0x0100_0193);
        index += 1;
    }
    hash
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Mutex, MutexGuard};

    use super::*;

    static E3B_PAYLOAD_ENVIRONMENT_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn payload_environment_test_lock() -> MutexGuard<'static, ()> {
        E3B_PAYLOAD_ENVIRONMENT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn with_ambient_e3b_kernel_mode<T>(test: impl FnOnce() -> T) -> T {
        // SAFETY: callers hold `E3B_PAYLOAD_ENVIRONMENT_TEST_LOCK` for this
        // scoped test-only process-environment mutation.
        unsafe { env::set_var(E3B_FULL_KERNEL_ENV, "unexpected") };
        let _environment = ScopedTestE3BKernelMode;
        test()
    }

    struct ScopedTestE3BKernelMode;

    impl Drop for ScopedTestE3BKernelMode {
        fn drop(&mut self) {
            // SAFETY: this guard clears only the test value installed above.
            unsafe { env::remove_var(E3B_FULL_KERNEL_ENV) };
        }
    }

    fn values(keys: &[&str]) -> BTreeMap<String, String> {
        keys.iter()
            .map(|key| ((*key).to_owned(), "x".to_owned()))
            .collect()
    }

    fn fixed_request() -> BTreeMap<String, String> {
        let mut map = values(REQUEST_KEYS);
        for (key, value) in [
            ("kind", REQUEST_KIND),
            ("schema_version", "1"),
            ("selector", SELECTOR),
            ("test_id", TEST_ID),
            ("profile", "dw1e3a-selector31"),
            ("scenario", "one-production-raw-com2-round-trip"),
            ("evidence_protocol", EVIDENCE_PROTOCOL),
            ("partial_evidence", "true"),
            ("acceptance_claim", ACCEPTANCE_CLAIM),
            ("readiness_marker", READINESS_MARKER),
            ("com2_prelude_kind", COM2_PRELUDE_KIND),
            ("com2_prelude_hex", &upper_hex(COM2_PRELUDE)),
            ("com2_prelude_length", COM2_PRELUDE_LENGTH),
            ("com2_prelude_sha256", COM2_PRELUDE_SHA256),
            ("challenge_length", "24"),
            ("response_length", "24"),
            ("default_handoff", "default/handoff.toml"),
            ("smp_handoff", "smp/handoff.toml"),
            ("profile_pair", "profile-pair.toml"),
            ("receipt", "build-receipt.toml"),
            ("source_receipt", "artifacts/e3a-source-build.toml"),
        ] {
            map.insert(key.into(), value.into());
        }
        map
    }

    fn put_hex(output: &mut [u8], value: u64) {
        let width = output.len();
        for (index, byte) in output.iter_mut().enumerate() {
            let shift = (width - 1 - index) * 4;
            *byte = b"0123456789ABCDEF"[((value >> shift) & 0xf) as usize];
        }
    }

    fn record(sequence: usize, challenge_fnv: u64, response_fnv: u64) -> [u8; 204] {
        let mut bytes = [b'0'; 204];
        bytes[..6].copy_from_slice(b"DWE3E1");
        for delimiter in [
            6, 9, 26, 35, 38, 41, 58, 75, 92, 109, 126, 143, 160, 177, 194,
        ] {
            bytes[delimiter] = b'|';
        }
        bytes[7..9].copy_from_slice(b"01");
        bytes[10..26].copy_from_slice(b"0123456789ABCDEF");
        put_hex(&mut bytes[27..35], sequence as u64);
        put_hex(&mut bytes[36..38], (sequence + 1) as u64);
        put_hex(&mut bytes[39..41], [0u64, 0, 0, 0, 0, 0, 1, 0, 2][sequence]);
        if sequence != 0 {
            for range in [42..58, 59..75, 76..92, 93..109, 110..126] {
                put_hex(&mut bytes[range], 1);
            }
        }
        if sequence >= 3 {
            put_hex(&mut bytes[127..143], 7);
            put_hex(&mut bytes[144..160], 1);
        }
        if sequence == 6 {
            put_hex(&mut bytes[161..177], 24);
            put_hex(&mut bytes[178..194], challenge_fnv);
        } else if sequence == 8 {
            put_hex(&mut bytes[161..177], 24);
            put_hex(&mut bytes[178..194], response_fnv);
        }
        let checksum = fnv1a32(&bytes[..195]);
        put_hex(&mut bytes[195..203], u64::from(checksum));
        bytes[203] = b'\n';
        bytes
    }

    #[test]
    fn request_schema_is_exact_partial_and_has_full_payload_hashes() {
        let rendered = render_request(&fixed_request()).unwrap();
        assert!(rendered.contains("challenge_sha256"));
        assert!(rendered.contains("response_sha256"));
        assert!(rendered.contains("schema_version = 1\n"));
        assert!(rendered.contains("test_id = 31\n"));
        assert!(!rendered.contains("schema_version = \"1\""));
        assert!(!rendered.contains("test_id = \"31\""));
        assert!(!rendered.contains("default_handoff_sha256"));
        assert!(!rendered.contains("smp_handoff_sha256"));
        assert!(!rendered.contains("DWTEST1"));
        let mut extra = fixed_request();
        extra.insert("terminal".into(), "pass".into());
        assert!(render_request(&extra).is_err());
    }

    #[test]
    fn com2_prelude_is_the_exact_ovmf_bds_session_banner() {
        assert_eq!(COM2_PRELUDE.len(), 354);
        assert_eq!(sha256::bytes_digest(COM2_PRELUDE), COM2_PRELUDE_SHA256);
        assert_eq!(upper_hex(COM2_PRELUDE).len(), 708);
        assert!(COM2_PRELUDE.starts_with(b"\x1b[2J\x1b[01;01H\x1b[=3h"));
        assert!(
            COM2_PRELUDE
                .ends_with(b"wyrmroot-loader: final UEFI memory map / ExitBootServices\r\n")
        );
    }

    #[test]
    fn e3a_product_path_rejects_e3b_payload_environment() {
        let _lock = payload_environment_test_lock();
        with_e3b_payload_environment("E300000000000002", "E300000000000003", || {
            assert!(build_product_snapshot("E300000000000001").is_err());
            Ok(())
        })
        .unwrap();
        with_ambient_e3b_kernel_mode(|| {
            assert!(reject_selector_environment().is_err());
            assert!(build_product_snapshot("E300000000000001").is_err());
        });
    }

    #[test]
    fn e3b_product_environment_binds_two_distinct_payload_nonces() {
        let _lock = payload_environment_test_lock();
        let output = with_e3b_payload_environment("E300000000000002", "E300000000000003", || {
            Command::new("/usr/bin/env").output().map_err(|error| {
                Failure::task(format!("could not inspect test environment: {error}"))
            })
        })
        .unwrap();
        let environment = String::from_utf8(output.stdout).unwrap();
        assert!(environment.contains("WYRMROOT_DW1E3_CHALLENGE_1_NONCE=E300000000000002\n"));
        assert!(environment.contains("WYRMROOT_DW1E3_CHALLENGE_2_NONCE=E300000000000003\n"));
        assert!(!environment.contains(E3B_FULL_KERNEL_ENV));
        assert!(env::var_os(E3B_CHALLENGE_1_NONCE_ENV).is_none());
        assert!(env::var_os(E3B_CHALLENGE_2_NONCE_ENV).is_none());
    }

    #[test]
    fn kernel_environment_selects_only_the_e3b_full_build() {
        let _lock = payload_environment_test_lock();
        let output = with_e3b_payload_environment("E300000000000002", "E300000000000003", || {
            let mut command = Command::new("/usr/bin/env");
            command.env(E3B_FULL_KERNEL_ENV, "ambient");
            configure_kernel_environment(
                &mut command,
                Path::new("/tmp/dw1e3a-kernel-test"),
                "E300000000000001",
                KernelMode::E3A,
            );
            command.output().map_err(|error| {
                Failure::task(format!("could not inspect kernel environment: {error}"))
            })
        })
        .unwrap();
        let environment = String::from_utf8(output.stdout).unwrap();
        assert!(environment.contains("DEEPWYRM_DW1E_EVIDENCE_NONCE=E300000000000001\n"));
        assert!(!environment.contains(E3B_FULL_KERNEL_ENV));
        assert!(!environment.contains(E3B_CHALLENGE_1_NONCE_ENV));
        assert!(!environment.contains(E3B_CHALLENGE_2_NONCE_ENV));

        let mut command = Command::new("/usr/bin/env");
        command.env(E3B_FULL_KERNEL_ENV, "ambient");
        configure_kernel_environment(
            &mut command,
            Path::new("/tmp/dw1e3b-kernel-test"),
            "E300000000000001",
            KernelMode::E3BFull,
        );
        let output = command.output().unwrap();
        let environment = String::from_utf8(output.stdout).unwrap();
        assert!(environment.contains("DEEPWYRM_DW1E_E3B_FULL=1\n"));
        assert!(!environment.contains(E3B_CHALLENGE_1_NONCE_ENV));
        assert!(!environment.contains(E3B_CHALLENGE_2_NONCE_ENV));
    }

    #[test]
    fn handoff_and_pair_freeze_profiles_transport_and_absent_receipt() {
        for (profile, vcpus) in [("default", "1"), ("smp", "4")] {
            let mut map = values(HANDOFF_KEYS);
            for (key, value) in [
                ("kind", HANDOFF_KIND),
                ("schema_version", "1"),
                ("profile", profile),
                ("selector", SELECTOR),
                ("test_id", TEST_ID),
                ("evidence_protocol", EVIDENCE_PROTOCOL),
                ("partial_evidence", "true"),
                ("acceptance_claim", ACCEPTANCE_CLAIM),
                ("vcpus", vcpus),
                ("memory_mib", "2048"),
                ("machine", "pc-q35-10.2"),
                ("firmware", "OVMF"),
                ("timeout_seconds", "120"),
                ("scenario", "one-production-raw-com2-round-trip"),
                ("physical_io", "real-com2-irq3-intended"),
                ("terminal_authority", "deepwyrm-selector31-partial-only"),
                ("com1_role", "trusted-evidence-and-readiness"),
                ("com2_role", "raw-challenge-response"),
                ("com2_transport", "unix-socket-byte-stream"),
                ("com2_socket_mode", "connect"),
                ("com2_socket_owner", "runner"),
                ("com2_prelude_kind", COM2_PRELUDE_KIND),
                ("com2_prelude_length", COM2_PRELUDE_LENGTH),
                ("com2_prelude_sha256", COM2_PRELUDE_SHA256),
                ("com1_fd_group", "dw-e3a-com1-evidence-v1"),
                ("com2_fd_group", "dw-e3a-com2-raw-v1"),
                ("esp_fd_group", "dw-f13-esp-v1"),
                ("vars_fd_group", "dw-f13-ovmf-vars-v1"),
                ("domain_xml", &format!("{profile}/domain.xml")),
                (
                    "mutable_ovmf_vars",
                    &format!("{profile}/OVMF_VARS.mutable.fd"),
                ),
                ("com2_socket", &format!("{profile}/com2.sock")),
                ("com1_serial_log", &format!("{profile}/com1.log")),
                ("com2_log", &format!("{profile}/com2.bin")),
                (
                    "partial_evidence_log",
                    &format!("{profile}/partial-evidence.log"),
                ),
                ("result_path", &format!("{profile}/result.toml")),
                (
                    "absent_receipt",
                    &format!("{profile}/acceptance-receipt.toml"),
                ),
                ("readiness_marker", READINESS_MARKER),
            ] {
                map.insert(key.into(), value.into());
            }
            assert!(render_handoff(&map).is_ok());
        }
        let mut pair = values(PROFILE_PAIR_KEYS);
        for (key, value) in [
            ("kind", PROFILE_PAIR_KIND),
            ("schema_version", "1"),
            ("selector", SELECTOR),
            ("test_id", TEST_ID),
            ("evidence_protocol", EVIDENCE_PROTOCOL),
            ("partial_evidence", "true"),
            ("acceptance_claim", ACCEPTANCE_CLAIM),
            ("profiles", "default,smp"),
            ("default_handoff", "default/handoff.toml"),
            ("default_vcpus", "1"),
            ("smp_handoff", "smp/handoff.toml"),
            ("smp_vcpus", "4"),
            ("memory_mib", "2048"),
            ("machine", "pc-q35-10.2"),
            ("firmware", "OVMF"),
            ("timeout_seconds", "120"),
        ] {
            pair.insert(key.into(), value.into());
        }
        assert!(render_profile_pair(&pair).is_ok());
    }

    #[test]
    fn partial_parser_accepts_only_sequences_zero_through_eight_without_terminal() {
        let challenge_fnv = 0x1122_3344_5566_7788;
        let response_fnv = 0x8877_6655_4433_2211;
        let mut bytes = Vec::new();
        for sequence in 0..9 {
            bytes.extend_from_slice(&record(sequence, challenge_fnv, response_fnv));
        }
        let parsed = parse_partial_evidence(
            &bytes,
            "0123456789ABCDEF",
            24,
            challenge_fnv,
            24,
            response_fnv,
        )
        .unwrap();
        assert_eq!(parsed.records, 9);
        assert_eq!(parsed.stream_generation, 7);
        let mut terminal = bytes.clone();
        terminal.extend_from_slice(b"DWTEST1 31 0\n");
        assert!(
            parse_partial_evidence(
                &terminal,
                "0123456789ABCDEF",
                24,
                challenge_fnv,
                24,
                response_fnv,
            )
            .is_err()
        );
    }

    #[test]
    fn dispatched_prepare_freezes_exact_acyclic_partial_output() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "wyrmroot-dw1e3a-freezer-test-{}-{unique}",
            std::process::id()
        ));
        let produced_root = root.join("produced");
        let output = root.join("output");
        fs::create_dir_all(&produced_root).unwrap();
        for (_, name) in ARTIFACTS {
            wyr1c6::write_new(&produced_root.join(name), name.as_bytes(), name).unwrap();
        }
        wyr1c6::write_new(
            &produced_root.join(SOURCE_RECEIPT),
            b"source-receipt\n",
            "source receipt",
        )
        .unwrap();
        let produced = ProducedArtifacts {
            directory: produced_root,
            deep_revision: "1".repeat(40),
            abi_revision: "2".repeat(40),
            abi_tree: "3".repeat(40),
            wyrmroot_revision: "4".repeat(40),
            rust_revision: "5".repeat(40),
        };
        let action = crate::cli::dispatch(&[
            "dw1-e3a-prepare".into(),
            output.display().to_string(),
            "/deepwyrm".into(),
            "1".repeat(40),
            "E300000000000001".into(),
        ])
        .unwrap();
        assert!(matches!(action, crate::cli::Action::Dw1E3APrepare { .. }));
        let result = freeze_produced(&output, &produced, "E300000000000001", |output, _| {
            wyr1c6::write_new(
                &output.join("artifacts/selector31-esp.img"),
                b"synthetic-esp",
                "synthetic ESP",
            )
        })
        .unwrap();
        assert!(result.starts_with(
            "DW1_E3A_PREPARE_PASS selector=q35-com2-interrupt test_id=31 evidence=DWE3E1"
        ));
        let request = fs::read_to_string(output.join("request.toml")).unwrap();
        assert!(request.contains("selector = \"q35-com2-interrupt\""));
        assert!(request.contains("com2_prelude_kind = \"ovmf-bds-session-banner\""));
        assert!(request.contains("com2_prelude_length = \"354\""));
        assert!(request.contains(&format!(
            "com2_prelude_hex = \"{}\"",
            upper_hex(COM2_PRELUDE)
        )));
        assert!(request.contains(&format!("com2_prelude_sha256 = \"{COM2_PRELUDE_SHA256}\"")));
        assert!(!request.contains("default_handoff_sha256"));
        assert!(!request.contains("smp_handoff_sha256"));
        assert!(!request.contains("profile_pair_sha256"));
        assert!(!request.contains("DWTEST1"));
        let request_hash = sha256::bytes_digest(request.as_bytes());
        for profile in ["default", "smp"] {
            let handoff = fs::read_to_string(output.join(profile).join("handoff.toml")).unwrap();
            assert!(handoff.contains(&format!("request_sha256 = \"{request_hash}\"")));
            assert!(handoff.contains(&format!("com2_socket = \"{profile}/com2.sock\"")));
            assert!(handoff.contains("com2_socket_mode = \"connect\""));
            assert!(handoff.contains("com2_socket_owner = \"runner\""));
            assert!(handoff.contains("com2_prelude_kind = \"ovmf-bds-session-banner\""));
            assert!(handoff.contains("com2_prelude_length = \"354\""));
            assert!(handoff.contains(&format!("com2_prelude_sha256 = \"{COM2_PRELUDE_SHA256}\"")));
            assert!(!handoff.contains("DWTEST1"));
            let domain = fs::read_to_string(output.join(profile).join("domain.xml")).unwrap();
            assert!(domain.contains(&format!(
                "<source mode=\"connect\" path=\"{}/com2.sock\"/>",
                output.join(profile).display()
            )));
            assert!(!domain.contains("<source mode=\"bind\""));
            assert_eq!(
                fs::metadata(output.join(profile).join("OVMF_VARS.mutable.fd"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let pair = fs::read_to_string(output.join("profile-pair.toml")).unwrap();
        assert!(pair.contains(&format!("request_sha256 = \"{request_hash}\"")));
        assert!(pair.contains("default_handoff_sha256"));
        assert!(pair.contains("smp_handoff_sha256"));
        let receipt = fs::read_to_string(output.join("build-receipt.toml")).unwrap();
        assert!(!receipt.contains("profile_pair_sha256"));
        assert!(receipt.contains("partial_evidence = \"true\""));
        assert!(receipt.contains("schema_version = 1\n"));
        assert!(receipt.contains("test_id = 31\n"));
        fs::remove_dir_all(&root).unwrap();
    }
}
