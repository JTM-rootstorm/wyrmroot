//! WYR1-D5 selector-32 product freeze and paired live-VM handoff grammar.
//!
//! The freezer owns immutable inputs only.  The root verified runner owns the
//! COM1/COM2 interaction and derives all four challenges from trusted WRD1
//! generation records at run time.

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    cli::G3ImageArguments, error::Failure, g3_image, secure_fs::Directory, sha256, tasks, wyr1c6,
};

pub(crate) const SELECTOR: &str = "native-console-streams";
pub(crate) const TEST_ID: &str = "32";
pub(crate) const EVIDENCE_PROTOCOL: &str = "WRD1";
pub(crate) const RESULT_KIND: &str = "wyrmroot-wyr1-d5-selector32-result";
const REQUEST_KIND: &str = "wyrmroot-wyr1-d5-selector32-request";
const HANDOFF_KIND: &str = "wyrmroot-wyr1-d5-selector32-vm-handoff";
const PAIR_KIND: &str = "wyrmroot-wyr1-d5-selector32-vm-profile-pair";
const RECEIPT_KIND: &str = "wyrmroot-wyr1-d5-selector32-freeze-receipt";
const SOURCE_RECEIPT_KIND: &str = "wyrmroot-wyr1-d5-selector32-source-build";
const SOURCE_RECEIPT: &str = "d5-source-build.toml";
const MACHINE: &str = "pc-q35-10.2";
const TIMEOUT_SECONDS: &str = "120";
const KERNEL_TARGET: &str = "x86_64-unknown-none";
const COM1_FD_GROUP: &str = "wyr1-d5-com1-evidence-v1";
const COM2_FD_GROUP: &str = "wyr1-d5-com2-raw-v1";

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
    ("console_echo", "console-echo.elf"),
    ("rrc_manifest", "rrc-d5-v1.bin"),
    ("device_manifest", "wrdm-d5-v1.bin"),
    ("launch_policy", "launch-policy-d5-v1.bin"),
    ("boot_device_table", "boot-device-table.bin"),
    ("bootfs", "bootfs.img"),
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
}

pub(crate) fn prepare(
    output: &Path,
    deep_repository: &Path,
    deep_revision: &str,
    nonce: &str,
) -> Result<String, Failure> {
    reject_selector_environment()?;
    wyr1c6::validate_revision(deep_revision, "Deepwyrm revision")?;
    wyr1c6::validate_upper_hex_nonzero(nonce, 16, "WYR1-D5 evidence nonce")?;
    if output.exists() {
        return Err(Failure::task("WYR1-D5 output must be a fresh path"));
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
            "WYR1-D5 source metadata does not name the accepted Rust toolchain",
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
    let staging = temporary.join(format!("wyr1d5-producer-{}-{unique}", std::process::id()));
    fs::create_dir(&staging)
        .map_err(|error| Failure::task(format!("could not create WYR1-D5 staging: {error}")))?;
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
        freeze_produced(&output, &produced, nonce)
    })();
    if result.is_ok() {
        fs::remove_dir_all(&staging)
            .map_err(|error| Failure::task(format!("could not retire WYR1-D5 staging: {error}")))?;
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
            "WYR1-D5 prepare requires the pinned launcher's exact CARGO_HOME",
        ));
    }
    toolchain.accepted().verify_unchanged()?;
    layout.verify_unchanged()?;
    let build = staging.join("build");
    fs::create_dir(&build)
        .map_err(|error| Failure::task(format!("could not create WYR1-D5 build root: {error}")))?;
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
    let build_directory = Directory::open_exact(&build, "WYR1-D5 build directory")?;
    let bootstrap =
        build_directory.with_inheritable_anchor("WYR1-D5 build directory", |anchor| {
            crate::dw1e3a::build_bootstrap(repository, &toolchain, &layout, &cargo_home, anchor)
        })?;
    let snapshot = crate::wyr1c::build_d5_snapshot(nonce)?;
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
        .map_err(|error| Failure::task(format!("could not create WYR1-D5 artifacts: {error}")))?;
    let artifact = |name: &str| {
        snapshot
            .artifacts
            .get(name)
            .ok_or_else(|| Failure::task(format!("WYR1-D5 builder omitted {name}")))
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
        ("console-echo.elf", artifact("console-echo")?),
        ("rrc-d5-v1.bin", &snapshot.rrc_manifest),
        ("wrdm-d5-v1.bin", &snapshot.device_manifest),
        ("launch-policy-d5-v1.bin", &snapshot.launch_policy),
        ("boot-device-table.bin", &boot_device_table),
        ("bootfs.img", &snapshot.bootfs),
        ("OVMF_CODE.fd", &ovmf_code),
        ("OVMF_VARS.fd", &ovmf_vars),
    ] {
        wyr1c6::write_new(&artifacts.join(name), bytes, name)?;
    }
    let source = render_source_receipt(
        &manifest,
        toolchain.accepted(),
        deep_revision,
        abi_revision,
        abi_tree,
        wyrmroot_revision,
        nonce,
        &artifacts,
    )?;
    wyr1c6::write_new(
        &artifacts.join(SOURCE_RECEIPT),
        source.as_bytes(),
        "WYR1-D5 source receipt",
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

fn build_kernel(repository: &Path, nonce: &str) -> Result<Vec<u8>, Failure> {
    let repository = Directory::open_exact(repository, "Deepwyrm source root")?;
    let temporary = match repository.open_child(".tmp", "Deepwyrm temporary root") {
        Ok(directory) => directory,
        Err(_) => repository.create_child(".tmp", 0o700, "Deepwyrm temporary root")?,
    };
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
        .as_nanos();
    let scratch = temporary.create_scratch(
        &format!("wyr1d5-kernel-{}-{unique}", std::process::id()),
        "WYR1-D5 Deepwyrm target",
    )?;
    let result = (|| {
        let status = Command::new(repository.path().join("tools/pinned-cargo"))
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
            .env("DEEPWYRM_GUEST_TEST_SELECTOR", SELECTOR)
            .env("DEEPWYRM_WYR1D_EVIDENCE_NONCE", nonce)
            .env_remove("DEEPWYRM_DW1E_EVIDENCE_NONCE")
            .env_remove("DEEPWYRM_DW1E_E3B_FULL")
            .env_remove("WYRMROOT_DW1E3_CHALLENGE_1_NONCE")
            .env_remove("WYRMROOT_DW1E3_CHALLENGE_2_NONCE")
            .env_remove("CARGO_HOME")
            .env_remove("LD_AUDIT")
            .env_remove("LD_LIBRARY_PATH")
            .env_remove("LD_PRELOAD")
            .current_dir(repository.path())
            .stdin(Stdio::null())
            .status()
            .map_err(|error| Failure::task(format!("could not build WYR1-D5 kernel: {error}")))?;
        if !status.success() {
            return Err(Failure::task(
                "WYR1-D5 selector-32 Deepwyrm kernel build failed",
            ));
        }
        scratch.read_producer(
            &PathBuf::from(KERNEL_TARGET).join("release/deepwyrm-kernel"),
            wyr1c6::MAX_ARTIFACT_BYTES,
            "selector-32 kernel",
        )
    })();
    scratch.finish(result)
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
        ("kind", SOURCE_RECEIPT_KIND.to_owned()),
        ("schema_version", "1".to_owned()),
        ("selector", SELECTOR.to_owned()),
        ("test_id", TEST_ID.to_owned()),
        ("evidence_protocol", EVIDENCE_PROTOCOL.to_owned()),
        ("deepwyrm_revision", deep_revision.to_owned()),
        ("generated_abi_revision", abi_revision.to_owned()),
        ("generated_abi_tree", abi_tree.to_owned()),
        ("wyrmroot_revision", wyrmroot_revision.to_owned()),
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
        ("evidence_nonce", nonce.to_owned()),
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
        "rust_revision",
        "evidence_nonce",
        "rustc_sha256",
        "cargo_sha256",
        "rust_lld_sha256",
        "toolchain_manifest_sha256",
        "toolchain_tree_sha256",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    for (key, _) in ARTIFACTS {
        keys.push(format!("{key}_sha256"));
    }
    render_dynamic(
        &values,
        &keys,
        &["schema_version", "test_id"],
        "WYR1-D5 source receipt",
    )
}

fn freeze_produced(
    output: &Path,
    produced: &ProducedArtifacts,
    nonce: &str,
) -> Result<String, Failure> {
    if output.exists() {
        return Err(Failure::task("WYR1-D5 output must be a fresh path"));
    }
    fs::create_dir(output)
        .map_err(|error| Failure::task(format!("could not create WYR1-D5 output: {error}")))?;
    let frozen = output.join("artifacts");
    fs::create_dir(&frozen)
        .map_err(|error| Failure::task(format!("could not create WYR1-D5 artifacts: {error}")))?;
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
    let source = wyr1c6::read_regular_bounded(
        &produced.directory.join(SOURCE_RECEIPT),
        64 * 1024,
        "WYR1-D5 source receipt",
    )?;
    wyr1c6::write_new(
        &frozen.join(SOURCE_RECEIPT),
        &source,
        "WYR1-D5 source receipt",
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
    let esp = frozen.join("selector32-esp.img");
    wyr1c6::seal_mode(&esp, 0o444, "WYR1-D5 ESP")?;
    fields.insert("esp".into(), "artifacts/selector32-esp.img".into());
    fields.insert(
        "esp_sha256".into(),
        sha256::bytes_digest(&wyr1c6::read_regular_bounded(
            &esp,
            g3_image::IMAGE_BYTES,
            "WYR1-D5 ESP",
        )?),
    );
    for (key, value) in [
        ("kind", REQUEST_KIND.to_owned()),
        ("schema_version", "1".to_owned()),
        ("selector", SELECTOR.to_owned()),
        ("test_id", TEST_ID.to_owned()),
        ("profile", "wyr1d5-selector32".to_owned()),
        ("scenario", "native-console-streams".to_owned()),
        ("evidence_protocol", EVIDENCE_PROTOCOL.to_owned()),
        ("full_evidence", "true".to_owned()),
        ("acceptance_claim", "full-selector32-acceptance".to_owned()),
        ("terminal_line", "DWTEST1 32 0".to_owned()),
        ("deepwyrm_revision", produced.deep_revision.clone()),
        ("generated_abi_revision", produced.abi_revision.clone()),
        ("generated_abi_tree", produced.abi_tree.clone()),
        ("wyrmroot_revision", produced.wyrmroot_revision.clone()),
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
        "WYR1-D5 request",
    )?;
    let request_hash = sha256::bytes_digest(request.as_bytes());
    let result_schema = render_result_schema()?;
    wyr1c6::write_new(
        &output.join("result-schema.toml"),
        result_schema.as_bytes(),
        "WYR1-D5 result schema",
    )?;
    for (profile, vcpus) in [("default", 1), ("smp", 4)] {
        stage_profile(output, profile, vcpus, &request_hash, &fields)?;
    }
    write_pair(output, &request_hash)?;
    let mut receipt = BTreeMap::new();
    for (key, value) in [
        ("kind", RECEIPT_KIND),
        ("schema_version", "1"),
        ("request_sha256", request_hash.as_str()),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("scenario", "native-console-streams"),
        ("full_evidence", "true"),
        ("acceptance_claim", "full-selector32-acceptance"),
        ("terminal_line", "DWTEST1 32 0"),
    ] {
        receipt.insert(key.to_owned(), value.to_owned());
    }
    wyr1c6::write_new(
        &output.join("freeze-receipt.toml"),
        render(
            &receipt,
            &[
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
            ],
            &["schema_version", "test_id"],
            "WYR1-D5 freeze receipt",
        )?
        .as_bytes(),
        "WYR1-D5 freeze receipt",
    )?;
    validate_frozen_output(output, &fields, &request_hash)?;
    Ok(format!(
        "WYR1_D5_PREPARE_PASS selector={SELECTOR} test_id={TEST_ID} evidence={EVIDENCE_PROTOCOL} request={} default_handoff={} smp_handoff={} profile_pair={} terminal=DWTEST1-32-0\n",
        output.join("request.toml").display(),
        output.join("default/handoff.toml").display(),
        output.join("smp/handoff.toml").display(),
        output.join("profile-pair.toml").display(),
    ))
}

fn build_esp(output: &Path, values: &BTreeMap<String, String>) -> Result<(), Failure> {
    let arguments = G3ImageArguments {
        image: output
            .join("artifacts/selector32-esp.img")
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
        .map_err(|error| Failure::task(format!("could not create WYR1-D5 {profile}: {error}")))?;
    let vars = wyr1c6::read_regular_bounded(
        &output.join(value(request, "ovmf_vars")?),
        wyr1c6::MAX_FIRMWARE_BYTES,
        "WYR1-D5 OVMF vars",
    )?;
    let vars_path = directory.join("OVMF_VARS.mutable.fd");
    wyr1c6::write_new_mode(&vars_path, &vars, 0o600, "WYR1-D5 mutable OVMF vars")?;
    let absolute = fs::canonicalize(output)
        .map_err(|error| Failure::task(format!("could not resolve WYR1-D5 output: {error}")))?;
    let xml = crate::dw1e3a::selected_domain_xml(
        vcpus,
        &absolute.join(value(request, "ovmf_code")?),
        &absolute.join(value(request, "esp")?),
        &absolute.join(profile).join("OVMF_VARS.mutable.fd"),
        &absolute.join(profile).join("com2.sock"),
        (SELECTOR, TEST_ID),
    );
    wyr1c6::write_new(
        &directory.join("domain.xml"),
        xml.as_bytes(),
        "WYR1-D5 domain XML",
    )?;
    let mut fields = BTreeMap::new();
    for (key, field) in [
        ("kind", HANDOFF_KIND),
        ("schema_version", "1"),
        ("profile", profile),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("full_evidence", "true"),
        ("acceptance_claim", "full-selector32-acceptance"),
        ("terminal_line", "DWTEST1 32 0"),
        ("request", "request.toml"),
        ("request_sha256", request_hash),
        ("esp", value(request, "esp")?),
        ("esp_sha256", value(request, "esp_sha256")?),
        ("vcpus", if vcpus == 1 { "1" } else { "4" }),
        ("memory_mib", "2048"),
        ("machine", MACHINE),
        ("firmware", "OVMF"),
        ("timeout_seconds", TIMEOUT_SECONDS),
        ("scenario", "native-console-streams"),
        ("physical_io", "real-com2-irq3-required"),
        ("terminal_authority", "system-init-selector32-controller"),
        ("com1_role", "trusted-evidence-and-terminal"),
        ("com2_role", "four-native-stream-legs"),
        ("com2_transport", "unix-socket-byte-stream"),
        ("com2_socket_mode", "connect"),
        ("com2_socket_owner", "runner"),
        ("com1_fd_group", COM1_FD_GROUP),
        ("com2_fd_group", COM2_FD_GROUP),
        ("domain_xml", &format!("{profile}/domain.xml")),
        ("domain_xml_sha256", &sha256::bytes_digest(xml.as_bytes())),
        (
            "mutable_ovmf_vars",
            &format!("{profile}/OVMF_VARS.mutable.fd"),
        ),
        (
            "mutable_ovmf_vars_initial_sha256",
            &sha256::bytes_digest(&vars),
        ),
        ("com2_socket", &format!("{profile}/com2.sock")),
        ("com1_serial_log", &format!("{profile}/com1.log")),
        ("com2_log", &format!("{profile}/com2.bin")),
        ("evidence_log", &format!("{profile}/evidence.log")),
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
    let keys = handoff_keys();
    wyr1c6::write_new(
        &directory.join("handoff.toml"),
        render_dynamic(
            &fields,
            &keys,
            &[
                "schema_version",
                "test_id",
                "vcpus",
                "memory_mib",
                "timeout_seconds",
            ],
            "WYR1-D5 handoff",
        )?
        .as_bytes(),
        "WYR1-D5 handoff",
    )
}

fn write_pair(output: &Path, request_hash: &str) -> Result<(), Failure> {
    let mut fields = BTreeMap::new();
    for (key, value) in [
        ("kind", PAIR_KIND),
        ("schema_version", "1"),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("full_evidence", "true"),
        ("acceptance_claim", "full-selector32-acceptance"),
        ("terminal_line", "DWTEST1 32 0"),
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
                "WYR1-D5 handoff",
            )?),
        );
    }
    render_and_write(
        output,
        "profile-pair.toml",
        &fields,
        &[
            "kind",
            "schema_version",
            "selector",
            "test_id",
            "evidence_protocol",
            "full_evidence",
            "acceptance_claim",
            "terminal_line",
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
        ],
        &[
            "schema_version",
            "test_id",
            "default_vcpus",
            "smp_vcpus",
            "memory_mib",
            "timeout_seconds",
        ],
        "WYR1-D5 profile pair",
    )
}

fn render_request(values: &BTreeMap<String, String>) -> Result<String, Failure> {
    for (key, expected) in [
        ("kind", REQUEST_KIND),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("full_evidence", "true"),
        ("acceptance_claim", "full-selector32-acceptance"),
        ("terminal_line", "DWTEST1 32 0"),
    ] {
        if value(values, key)? != expected {
            return Err(Failure::task(format!("WYR1-D5 {key} drifted")));
        }
    }
    let keys = request_keys();
    render_dynamic(
        values,
        &keys,
        &["schema_version", "test_id"],
        "WYR1-D5 request",
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
        "com2_raw_sha256",
        "acceptance",
        "leg_1_challenge",
        "leg_1_command_sha256",
        "leg_1_response_sha256",
        "leg_1_transcript_sha256",
        "leg_2_challenge",
        "leg_2_command_sha256",
        "leg_2_response_sha256",
        "leg_2_transcript_sha256",
        "leg_3_challenge",
        "leg_3_command_sha256",
        "leg_3_response_sha256",
        "leg_3_transcript_sha256",
        "leg_4_challenge",
        "leg_4_command_sha256",
        "leg_4_response_sha256",
        "leg_4_transcript_sha256",
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
                "evidence_records" => "12".to_owned(),
                "terminal_line" => "DWTEST1 32 0".to_owned(),
                "acceptance" => "pass".to_owned(),
                _ => format!("<runner:{key}>"),
            },
        );
    }
    render(&values, &keys, &[], "WYR1-D5 result schema")
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
        "deepwyrm_revision",
        "generated_abi_revision",
        "generated_abi_tree",
        "wyrmroot_revision",
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
    for (key, name) in ARTIFACTS {
        let path = output.join(value(request, key)?);
        let bytes = wyr1c6::read_regular_bounded(&path, artifact_maximum(key), key)?;
        if path.file_name().and_then(|name| name.to_str()) != Some(name)
            || sha256::bytes_digest(&bytes) != value(request, &format!("{key}_sha256"))?
        {
            return Err(Failure::task(format!(
                "WYR1-D5 frozen {key} identity drifted"
            )));
        }
    }
    for profile in ["default", "smp"] {
        let handoff = String::from_utf8(wyr1c6::read_regular_bounded(
            &output.join(profile).join("handoff.toml"),
            64 * 1024,
            "WYR1-D5 handoff",
        )?)
        .map_err(|_| Failure::task("WYR1-D5 handoff is not UTF-8"))?;
        if !handoff.contains(&format!("request_sha256 = \"{request_hash}\"")) {
            return Err(Failure::task("WYR1-D5 handoff request join drifted"));
        }
        for absent in [
            "com2.sock",
            "com1.log",
            "com2.bin",
            "evidence.log",
            "result.toml",
            "acceptance-receipt.toml",
        ] {
            if output.join(profile).join(absent).exists() {
                return Err(Failure::task(
                    "WYR1-D5 runtime output exists before runner execution",
                ));
            }
        }
    }
    Ok(())
}

fn reject_selector_environment() -> Result<(), Failure> {
    for key in [
        "DEEPWYRM_GUEST_TEST_SELECTOR",
        "DEEPWYRM_GUEST_TEST_ID",
        "DEEPWYRM_WYR1D_EVIDENCE_NONCE",
        "DEEPWYRM_DW1E_EVIDENCE_NONCE",
        "DEEPWYRM_DW1E_E3B_FULL",
        "CARGO_TARGET_DIR",
    ] {
        if env::var_os(key).is_some() {
            return Err(Failure::task(format!(
                "WYR1-D5 prepare refuses ambient {key}"
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

fn render_and_write(
    output: &Path,
    name: &str,
    values: &BTreeMap<String, String>,
    keys: &[&str],
    integers: &[&str],
    label: &str,
) -> Result<(), Failure> {
    let text = render(values, keys, integers, label)?;
    wyr1c6::write_new(&output.join(name), text.as_bytes(), label)
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
        .ok_or_else(|| Failure::task(format!("WYR1-D5 omitted {key}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn d5_profile_selects_test32_without_changing_the_q35_transport() {
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
            assert!(xml.contains(
                "name=\"opt/org.deepwyrm.test.selector\">native-console-streams</entry>"
            ));
            assert!(xml.contains("name=\"opt/org.deepwyrm.test.test_id\">32</entry>"));
            let original = crate::dw1e3a::domain_xml(vcpus, path, path, path, path);
            assert_eq!(
                xml,
                original
                    .replace("q35-com2-interrupt", SELECTOR)
                    .replace("test.test_id\">31", "test.test_id\">32")
            );
        }
    }

    #[test]
    fn selector32_schema_is_distinct_and_has_four_dynamic_legs() {
        let schema = render_result_schema().unwrap();
        assert!(schema.contains("kind = \"wyrmroot-wyr1-d5-selector32-result\""));
        assert!(schema.contains("test_id = \"32\""));
        assert!(schema.contains("evidence_records = \"12\""));
        for leg in 1..=4 {
            assert!(schema.contains(&format!("leg_{leg}_transcript_sha256")));
        }
        assert!(!schema.contains("selector31"));
        assert!(!schema.contains("DWE3"));
    }

    #[test]
    fn request_and_handoff_artifact_tables_include_console_policy() {
        let request = request_keys();
        let handoff = handoff_keys();
        for key in ["console_echo", "launch_policy", "consoled", "bootfs"] {
            assert!(request.contains(&key.to_owned()));
            assert!(request.contains(&format!("{key}_sha256")));
            assert!(handoff.contains(&format!("{key}_path")));
            assert!(handoff.contains(&format!("{key}_sha256")));
        }
    }

    #[test]
    fn selector_environment_rejects_d5_nonce() {
        // The actual environment-mutating rejection cases are covered by the
        // existing serialized selector-environment tests.  Keep this table
        // assertion free of process-global mutation so tests remain parallel.
        assert_eq!(SELECTOR, "native-console-streams");
        assert_eq!(EVIDENCE_PROTOCOL, "WRD1");
        assert_eq!(TEST_ID, "32");
    }
}
