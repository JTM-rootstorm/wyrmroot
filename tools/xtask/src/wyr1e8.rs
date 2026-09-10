//! Additive WYR1-E8 selector-33 product freeze and inspection.
//!
//! E8 consumes the accepted immutable E6 product directly. The accepted E7
//! product remains compatibility evidence and is not a mutable build input.

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    cli::G3ImageArguments, error::Failure, g3_image, secure_fs::Directory, sha256, tasks, wyr1c,
    wyr1c6, wyr1e7,
};

pub(crate) const SELECTOR: &str = "interactive-wyrmsh";
pub(crate) const TEST_ID: &str = "33";
pub(crate) const EVIDENCE_PROTOCOL: &str = "WRE1";
pub(crate) const RESULT_KIND: &str = "wyrmroot-wyr1-e8-selector33-result";
const REQUEST_KIND: &str = "wyrmroot-wyr1-e8-selector33-request";
const HANDOFF_KIND: &str = "wyrmroot-wyr1-e8-selector33-vm-handoff";
const PAIR_KIND: &str = "wyrmroot-wyr1-e8-selector33-vm-profile-pair";
const RECEIPT_KIND: &str = "wyrmroot-wyr1-e8-selector33-freeze-receipt";
const SOURCE_KIND: &str = "wyrmroot-wyr1-e8-selector33-source-build";
const SOURCE_RECEIPT: &str = "e8-source-build.toml";
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
        "wyrmsh",
        "9d7f3ab7462488dd3f4db6226ef119516de7a2933c4441eeb331fc4f07f72101",
    ),
    (
        "stack_report",
        "7eab648da90518331e95650becba6013158cb2edc3c5f5126beaabb6eb83ea7f",
    ),
];
const COM2_PRELUDE_KIND: &str = "ovmf-bds-session-banner";
const COM2_PRELUDE_LENGTH: &str = "354";
const COM2_PRELUDE_SHA256: &str =
    "8cf1a7eba89309b5ee101cbe77935604572151fb79f4e009a327125c5da8cb47";
const TOKEN_INDEX_SCHEDULE: &str = "s1=0001..0006,s2_echo=0101,driver=0102,s3_echo=0201,registry=0202,s4_echo=0301,smp_echo=0310..0312,smp_hello=0320..0322";
const CAPACITY_KEYS: [&str; 4] = [
    "per_process_handle_capacity",
    "memory_object_capacity",
    "mapping_lease_capacity",
    "registry_object_capacity",
];
const LOCKED_CAPACITIES: [u64; 4] = [64, 64, 64, 160];

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
    ("recovery_trigger", "recovery-trigger.elf"),
    ("stdout_pressure", "stdout-pressure.elf"),
    ("malformed_elf", "malformed-elf.bin"),
    ("rrc_manifest", "rrc-e8-v1.bin"),
    ("device_manifest", "wrdm-e8-v1.bin"),
    ("launch_policy", "launch-policy-e8-v1.bin"),
    ("boot_device_table", "boot-device-table.bin"),
    ("bootfs", "bootfs.img"),
    ("stack_report", "stack-report.json"),
    ("ovmf_code", "OVMF_CODE.fd"),
    ("ovmf_vars", "OVMF_VARS.fd"),
];

struct Produced {
    directory: PathBuf,
    deep_revision: String,
    abi_revision: String,
    abi_tree: String,
    wyrmroot_revision: String,
    rust_revision: String,
    e6_source_receipt_sha256: String,
    e6_freeze_receipt_sha256: String,
    capacities: [u64; 4],
}

pub(crate) fn prepare(
    output: &Path,
    e6_product: &Path,
    deep_repository: &Path,
    deep_revision: &str,
    nonce: &str,
) -> Result<String, Failure> {
    wyr1c::reject_e6_ambient_build_environment(env::vars_os())?;
    wyr1c6::validate_revision(deep_revision, "Deepwyrm revision")?;
    wyr1c::validate_e8_nonce(nonce)?;
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
    let abi_revision = manifest.deepwyrm_revision()?.to_owned();
    let abi_tree = wyr1c6::matching_abi_tree(&deep_repository, deep_revision, &abi_revision)?;
    let layout = crate::deep_layout::prepare_current_kernel_source(
        &repository,
        &deep_repository,
        deep_revision,
    )?;
    let capacity_contract =
        crate::deep_layout::read_wyr1e8_capacity_contract(&deep_repository, deep_revision)?;
    validate_locked_capacities(capacity_contract.receipt_values())?;
    let output = wyr1c::validate_fresh_output(&repository, &project, output)?;
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
        .as_nanos();
    let staging = repository
        .join(".tmp")
        .join(format!("wyr1e8-producer-{}-{unique}", std::process::id()));
    fs::create_dir(&staging)
        .map_err(|error| Failure::task(format!("could not create WYR1-E8 staging: {error}")))?;
    let result = (|| {
        let produced = build_produced(
            &staging,
            &repository,
            &deep_repository,
            &wyrmroot_revision,
            deep_revision,
            &abi_revision,
            &abi_tree,
            nonce,
            &e6,
            &layout,
            &capacity_contract,
        )?;
        capacity_contract.verify_unchanged()?;
        freeze(&output, &produced, nonce)
    })();
    if result.is_ok() {
        fs::remove_dir_all(&staging)
            .map_err(|error| Failure::task(format!("could not retire WYR1-E8 staging: {error}")))?;
    }
    result
}

pub(crate) fn inspect(product: &Path) -> Result<String, Failure> {
    let repository = tasks::repository_root()?;
    let project = tasks::canonical_project_root(&repository)?;
    let product = fs::canonicalize(product)
        .map_err(|error| Failure::task(format!("could not resolve WYR1-E8 product: {error}")))?;
    if !product.starts_with(&project) || product.starts_with(&repository) {
        return Err(Failure::task("WYR1-E8 product locality is invalid"));
    }
    let request_bytes =
        wyr1c6::read_regular_bounded(&product.join("request.toml"), 64 * 1024, "WYR1-E8 request")?;
    let request_text = std::str::from_utf8(&request_bytes)
        .map_err(|_| Failure::task("WYR1-E8 request is not UTF-8"))?;
    let request = parse(request_text)?;
    wyr1c6::validate_revision(field(&request, "deepwyrm_revision")?, "deepwyrm_revision")?;
    let deep_repository = wyr1c6::canonical_deep_repository(&project.join("deepwyrm"), &project)?;
    let capacity_contract = crate::deep_layout::read_wyr1e8_capacity_contract(
        &deep_repository,
        field(&request, "deepwyrm_revision")?,
    )?;
    let capacities = capacity_contract.receipt_values();
    validate_locked_capacities(capacities)?;
    validate_request(&request, capacities)?;
    if render(&request, &request_keys(), ScalarSchema::Request)? != request_text {
        return Err(Failure::task("WYR1-E8 request is not canonical"));
    }
    let revision = wyr1c6::clean_revision(&repository, "Wyrmroot")?;
    if field(&request, "wyrmroot_revision")? != revision {
        return Err(Failure::task("WYR1-E8 source revision changed"));
    }
    let request_hash = sha256::bytes_digest(&request_bytes);
    validate_frozen_metadata(&product, &request, &request_hash)?;
    let mut artifacts = BTreeMap::new();
    for label in wyr1c::E8_ARTIFACT_LABELS {
        let key = label.replace('-', "_");
        artifacts.insert(
            label.to_owned(),
            wyr1c6::read_regular_bounded(
                &product.join(field(&request, &key)?),
                wyr1c6::MAX_ARTIFACT_BYTES,
                label,
            )?,
        );
    }
    let malformed = wyr1c6::read_regular_bounded(
        &product.join(field(&request, "malformed_elf")?),
        64 * 1024,
        "malformed ELF",
    )?;
    let assembled = wyr1c::reassemble_e8_snapshot(&revision, &artifacts, &malformed)?;
    for (key, actual) in [
        ("rrc_manifest", assembled.rrc_manifest.as_slice()),
        ("device_manifest", assembled.device_manifest.as_slice()),
        ("launch_policy", assembled.launch_policy.as_slice()),
        ("bootfs", assembled.bootfs.as_slice()),
    ] {
        let frozen = wyr1c6::read_regular_bounded(
            &product.join(field(&request, key)?),
            wyr1c6::MAX_ARTIFACT_BYTES,
            key,
        )?;
        if frozen != actual {
            return Err(Failure::task(format!(
                "WYR1-E8 {key} reconstruction failed"
            )));
        }
    }
    for (key, _) in ARTIFACTS {
        let bytes = wyr1c6::read_regular_bounded(
            &product.join(field(&request, key)?),
            artifact_maximum(key),
            key,
        )?;
        if sha256::bytes_digest(&bytes) != field(&request, &format!("{key}_sha256"))? {
            return Err(Failure::task(format!("WYR1-E8 {key} hash drifted")));
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
        &product.join(field(&request, "stack_report")?),
        64 * 1024,
        "WYR1-E8 stack report",
    )?;
    wyr1c::validate_e8_artifact_reports(
        &repository,
        &artifacts,
        &inspections,
        &malformed,
        &stack_report,
    )?;
    validate_esp(&product, &request)?;
    let source = wyr1c6::read_regular_bounded(
        &product.join(field(&request, "source_receipt")?),
        64 * 1024,
        "WYR1-E8 source receipt",
    )?;
    let source_text = std::str::from_utf8(&source)
        .map_err(|_| Failure::task("WYR1-E8 source receipt is not UTF-8"))?;
    if sha256::bytes_digest(&source) != field(&request, "source_receipt_sha256")?
        || parse(source_text).is_err()
    {
        return Err(Failure::task("WYR1-E8 source receipt drifted"));
    }
    let manifest = crate::metadata::BuildManifest::load(&repository)?;
    if field(&request, "rust_revision")? != manifest.rust_revision()?
        || field(&request, "generated_abi_revision")? != manifest.deepwyrm_revision()?
    {
        return Err(Failure::task(
            "WYR1-E8 request does not match current source metadata",
        ));
    }
    let abi_tree = wyr1c6::matching_abi_tree(
        &deep_repository,
        field(&request, "deepwyrm_revision")?,
        field(&request, "generated_abi_revision")?,
    )?;
    if abi_tree != field(&request, "generated_abi_tree")? {
        return Err(Failure::task("WYR1-E8 generated ABI tree changed"));
    }
    let profile = manifest.validate_loader_build_readiness(&repository)?;
    let toolchain = tasks::prepare_loader_toolchain(&repository, &profile, &manifest)?;
    let expected_source = source_receipt(
        &manifest,
        toolchain.accepted(),
        field(&request, "deepwyrm_revision")?,
        field(&request, "generated_abi_revision")?,
        field(&request, "generated_abi_tree")?,
        &revision,
        field(&request, "evidence_nonce")?,
        &product.join("artifacts"),
        &assembled.generation,
        &inspections,
        capacities,
    )?;
    if source_text != expected_source {
        return Err(Failure::task("WYR1-E8 source receipt is not canonical"));
    }
    Ok(format!(
        "WYR1_E8_INSPECT_PASS selector={SELECTOR} test_id={TEST_ID} evidence={EVIDENCE_PROTOCOL} wyrmroot_revision={revision} bootfs_sha256={}\n",
        sha256::bytes_digest(&assembled.bootfs)
    ))
}

#[allow(clippy::too_many_arguments)]
fn build_produced(
    staging: &Path,
    repository: &Path,
    deep_repository: &Path,
    wyrmroot_revision: &str,
    deep_revision: &str,
    abi_revision: &str,
    abi_tree: &str,
    nonce: &str,
    e6: &crate::wyr1e::ImmutableE6Input,
    layout: &crate::deep_layout::DeepLayoutBuild,
    capacity_contract: &crate::deep_layout::Wyr1E8CapacityContract,
) -> Result<Produced, Failure> {
    let manifest = crate::metadata::BuildManifest::load(repository)?;
    let profile = manifest.validate_loader_build_readiness(repository)?;
    let toolchain = tasks::prepare_loader_toolchain(repository, &profile, &manifest)?;
    let cargo_home = tasks::project_cargo_home(repository, &manifest)?;
    if env::var_os("CARGO_HOME").as_deref() != Some(cargo_home.as_os_str()) {
        return Err(Failure::task(
            "WYR1-E8 prepare requires the pinned launcher's exact CARGO_HOME",
        ));
    }
    let build = staging.join("build");
    fs::create_dir(&build)
        .map_err(|e| Failure::task(format!("could not create WYR1-E8 build root: {e}")))?;
    let uefi = tasks::build_deterministic_uefi_pair(
        repository,
        &toolchain,
        &profile,
        layout,
        &tasks::IsolatedUefiBuild {
            cargo_home: &cargo_home,
            production_target: &build.join("uefi-production"),
            retained_debug_target: &build.join("uefi-retained-debug"),
            cargo_profile: tasks::UefiCargoProfile::Release,
        },
    )?;
    let build_directory = Directory::open_exact(&build, "WYR1-E8 build directory")?;
    let bootstrap =
        build_directory.with_inheritable_anchor("WYR1-E8 build directory", |anchor| {
            crate::dw1e3a::build_bootstrap(repository, &toolchain, layout, &cargo_home, anchor)
        })?;
    let snapshot = wyr1c::build_e8_snapshot(nonce, &e6.product)?;
    let kernel = wyr1e7::build_e8_kernel(deep_repository, nonce)?;
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
        .map_err(|e| Failure::task(format!("could not create WYR1-E8 artifacts: {e}")))?;
    let artifact = |name: &str| {
        snapshot
            .artifacts
            .get(name)
            .ok_or_else(|| Failure::task(format!("WYR1-E8 builder omitted {name}")))
    };
    for (name, bytes) in [
        ("loader.efi", uefi.loader_bytes.as_slice()),
        ("deepwyrm.elf", kernel.as_slice()),
        ("deepwyrm.symbols.elf", kernel.as_slice()),
        ("bootstrap.elf", bootstrap.as_slice()),
        ("system-init.elf", artifact("system-init")?.as_slice()),
        ("registryd.elf", artifact("registryd")?.as_slice()),
        ("devmgr.elf", artifact("devmgr")?.as_slice()),
        ("uart16550d.elf", artifact("uart16550d")?.as_slice()),
        ("consoled.elf", artifact("consoled")?.as_slice()),
        ("wyrmsh.elf", artifact("wyrmsh")?.as_slice()),
        ("hello.elf", artifact("hello")?.as_slice()),
        ("cpu-hog.elf", artifact("cpu-hog")?.as_slice()),
        ("exit-nonzero.elf", artifact("exit-nonzero")?.as_slice()),
        ("fault.elf", artifact("fault")?.as_slice()),
        (
            "recovery-trigger.elf",
            artifact("recovery-trigger")?.as_slice(),
        ),
        (
            "stdout-pressure.elf",
            artifact("stdout-pressure")?.as_slice(),
        ),
        ("malformed-elf.bin", snapshot.malformed_elf.as_slice()),
        ("rrc-e8-v1.bin", snapshot.rrc_manifest.as_slice()),
        ("wrdm-e8-v1.bin", snapshot.device_manifest.as_slice()),
        ("launch-policy-e8-v1.bin", snapshot.launch_policy.as_slice()),
        ("boot-device-table.bin", boot_device_table.as_slice()),
        ("bootfs.img", snapshot.bootfs.as_slice()),
        ("stack-report.json", snapshot.stack_report.as_slice()),
        ("OVMF_CODE.fd", ovmf_code.as_slice()),
        ("OVMF_VARS.fd", ovmf_vars.as_slice()),
    ] {
        wyr1c6::write_new(&artifacts.join(name), bytes, name)?;
    }
    wyr1c6::write_new(
        &artifacts.join("e6-source-build.toml"),
        &e6.source_receipt,
        "E6 source receipt",
    )?;
    wyr1c6::write_new(
        &artifacts.join("e6-freeze-receipt.toml"),
        &e6.freeze_receipt,
        "E6 freeze receipt",
    )?;
    let source = source_receipt(
        &manifest,
        toolchain.accepted(),
        deep_revision,
        abi_revision,
        abi_tree,
        wyrmroot_revision,
        nonce,
        &artifacts,
        &snapshot.generation,
        &snapshot.inspections,
        capacity_contract.receipt_values(),
    )?;
    wyr1c6::write_new(
        &artifacts.join(SOURCE_RECEIPT),
        source.as_bytes(),
        "WYR1-E8 source receipt",
    )?;
    toolchain.accepted().verify_unchanged()?;
    layout.verify_unchanged()?;
    capacity_contract.verify_unchanged()?;
    wyr1c6::verify_clean_revision(repository, "Wyrmroot", wyrmroot_revision)?;
    wyr1c6::verify_clean_revision(deep_repository, "Deepwyrm", deep_revision)?;
    Ok(Produced {
        directory: artifacts,
        deep_revision: deep_revision.into(),
        abi_revision: abi_revision.into(),
        abi_tree: abi_tree.into(),
        wyrmroot_revision: wyrmroot_revision.into(),
        rust_revision: manifest.rust_revision()?.into(),
        e6_source_receipt_sha256: sha256::bytes_digest(&e6.source_receipt),
        e6_freeze_receipt_sha256: sha256::bytes_digest(&e6.freeze_receipt),
        capacities: capacity_contract.receipt_values(),
    })
}

fn fixed_fields() -> [(&'static str, &'static str); 31] {
    [
        ("kind", REQUEST_KIND),
        ("schema_version", "1"),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
        ("profile", "wyr1e8-selector33"),
        ("scenario", "interactive-wyrmsh-e8"),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("evidence_version_major", "1"),
        ("evidence_version_minor", "1"),
        ("evidence_record_bytes", "192"),
        ("evidence_record_capacity", "128"),
        ("default_evidence_records", "33"),
        ("smp_evidence_records", "69"),
        ("full_evidence", "true"),
        ("acceptance_claim", "full-selector33-recovery-adversarial"),
        ("terminal_line", "DWTEST1 33 0"),
        ("com2_prelude_kind", COM2_PRELUDE_KIND),
        ("com2_prelude_length", COM2_PRELUDE_LENGTH),
        ("com2_prelude_sha256", COM2_PRELUDE_SHA256),
        ("process_capacity", "64"),
        ("thread_capacity", "64"),
        ("root_address_space_capacity", "64"),
        ("task_group_capacity", "64"),
        ("channel_pair_capacity", "32"),
        ("wait_capacity", "64"),
        ("overall_timeout_seconds", "600"),
        ("ordinary_timeout_seconds", "30"),
        ("transition_timeout_seconds", "60"),
        ("com2_capture_bytes", "2097152"),
        ("send_limit", "1024"),
        ("input_limit_bytes", "131072"),
    ]
}

fn insert_capacity_fields(fields: &mut BTreeMap<String, String>, capacities: [u64; 4]) {
    for (key, value) in CAPACITY_KEYS.into_iter().zip(capacities) {
        fields.insert(key.into(), value.to_string());
    }
}

fn validate_locked_capacities(capacities: [u64; 4]) -> Result<(), Failure> {
    if capacities != LOCKED_CAPACITIES {
        return Err(Failure::task(format!(
            "Deepwyrm WYR1-E8 selected capacities drifted: observed {capacities:?}, expected {LOCKED_CAPACITIES:?}"
        )));
    }
    Ok(())
}

fn extra_fields() -> [(&'static str, &'static str); 8] {
    [
        ("audit_limit_bytes", "524288"),
        ("pressure_pause_milliseconds", "500"),
        ("pressure_bytes", "262144"),
        (
            "pressure_sha256",
            "df1878cecca437f240a27321523bf204e607a7a5b85d6569e81ce1290a4dcf79",
        ),
        ("pressure_min_would_blocks", "1"),
        ("pressure_max_would_blocks", "4095"),
        ("token_index_schedule", TOKEN_INDEX_SCHEDULE),
        ("physical_io", "real-com2-irq3-required"),
    ]
}

fn freeze(output: &Path, produced: &Produced, nonce: &str) -> Result<String, Failure> {
    fs::create_dir(output)
        .map_err(|e| Failure::task(format!("could not create WYR1-E8 output: {e}")))?;
    let frozen = output.join("artifacts");
    fs::create_dir(&frozen)
        .map_err(|e| Failure::task(format!("could not create artifacts: {e}")))?;
    let mut fields = BTreeMap::new();
    for (key, name) in ARTIFACTS {
        let bytes = wyr1c6::read_regular_bounded(
            &produced.directory.join(name),
            artifact_maximum(key),
            key,
        )?;
        wyr1c6::write_new(&frozen.join(name), &bytes, key)?;
        fields.insert((*key).into(), format!("artifacts/{name}"));
        fields.insert(format!("{key}_sha256"), sha256::bytes_digest(&bytes));
    }
    for name in [
        "e6-source-build.toml",
        "e6-freeze-receipt.toml",
        SOURCE_RECEIPT,
    ] {
        let bytes = wyr1c6::read_regular_bounded(&produced.directory.join(name), 64 * 1024, name)?;
        wyr1c6::write_new(&frozen.join(name), &bytes, name)?;
        if name == SOURCE_RECEIPT {
            fields.insert("source_receipt".into(), format!("artifacts/{name}"));
            fields.insert("source_receipt_sha256".into(), sha256::bytes_digest(&bytes));
        }
    }
    build_esp(output, &fields)?;
    let esp = frozen.join("selector33-e8-esp.img");
    wyr1c6::seal_mode(&esp, 0o444, "WYR1-E8 ESP")?;
    fields.insert("esp".into(), "artifacts/selector33-e8-esp.img".into());
    fields.insert(
        "esp_sha256".into(),
        sha256::bytes_digest(&wyr1c6::read_regular_bounded(
            &esp,
            g3_image::IMAGE_BYTES,
            "ESP",
        )?),
    );
    for (k, v) in fixed_fields().into_iter().chain(extra_fields()) {
        fields.insert(k.into(), v.into());
    }
    insert_capacity_fields(&mut fields, produced.capacities);
    for (k, v) in [
        ("deepwyrm_revision", produced.deep_revision.as_str()),
        ("generated_abi_revision", produced.abi_revision.as_str()),
        ("generated_abi_tree", produced.abi_tree.as_str()),
        ("wyrmroot_revision", produced.wyrmroot_revision.as_str()),
        ("rust_revision", produced.rust_revision.as_str()),
        ("evidence_nonce", nonce),
        ("e6_wyrmroot_revision", ACCEPTED_E6_REVISION),
        (
            "e6_source_receipt_sha256",
            produced.e6_source_receipt_sha256.as_str(),
        ),
        (
            "e6_freeze_receipt_sha256",
            produced.e6_freeze_receipt_sha256.as_str(),
        ),
        ("default_handoff", "default/handoff.toml"),
        ("smp_handoff", "smp/handoff.toml"),
        ("profile_pair", "profile-pair.toml"),
        ("receipt", "freeze-receipt.toml"),
        ("result_schema", "result-schema.toml"),
    ] {
        fields.insert(k.into(), v.into());
    }
    let request = render(&fields, &request_keys(), ScalarSchema::Request)?;
    wyr1c6::write_new(
        &output.join("request.toml"),
        request.as_bytes(),
        "WYR1-E8 request",
    )?;
    let request_hash = sha256::bytes_digest(request.as_bytes());
    wyr1c6::write_new(
        &output.join("result-schema.toml"),
        result_schema()?.as_bytes(),
        "result schema",
    )?;
    for (profile, vcpus, count) in [("default", 1, "33"), ("smp", 4, "69")] {
        stage_profile(output, profile, vcpus, count, &request_hash, &fields)?;
    }
    let pair = pair_fields(output, &request_hash)?;
    wyr1c6::write_new(
        &output.join("profile-pair.toml"),
        render_sorted(&pair, ScalarSchema::Pair)?.as_bytes(),
        "profile pair",
    )?;
    let receipt = receipt_fields(&request_hash, &fields);
    wyr1c6::write_new(
        &output.join("freeze-receipt.toml"),
        render_sorted(&receipt, ScalarSchema::FreezeReceipt)?.as_bytes(),
        "freeze receipt",
    )?;
    validate_request(&fields, produced.capacities)?;
    Ok(format!(
        "WYR1_E8_PREPARE_PASS selector={SELECTOR} test_id={TEST_ID} request={} default_handoff={} smp_handoff={}\n",
        output.join("request.toml").display(),
        output.join("default/handoff.toml").display(),
        output.join("smp/handoff.toml").display()
    ))
}

#[allow(clippy::too_many_arguments)]
fn source_receipt(
    manifest: &crate::metadata::BuildManifest,
    toolchain: &crate::toolchain_artifact::AcceptedToolchain,
    deep: &str,
    abi: &str,
    tree: &str,
    wyrmroot: &str,
    nonce: &str,
    artifacts: &Path,
    generation: &[u8; 32],
    inspections: &BTreeMap<String, Vec<u8>>,
    capacities: [u64; 4],
) -> Result<String, Failure> {
    let mut f = BTreeMap::new();
    for (k, v) in fixed_fields().into_iter().chain(extra_fields()) {
        if k != "kind" {
            f.insert(k.into(), v.into());
        }
    }
    insert_capacity_fields(&mut f, capacities);
    for (k, v) in [
        ("kind", SOURCE_KIND),
        ("deepwyrm_revision", deep),
        ("generated_abi_revision", abi),
        ("generated_abi_tree", tree),
        ("wyrmroot_revision", wyrmroot),
        ("e6_wyrmroot_revision", ACCEPTED_E6_REVISION),
        (
            "e6_source_receipt_sha256",
            ACCEPTED_E6_SOURCE_RECEIPT_SHA256,
        ),
        (
            "e6_freeze_receipt_sha256",
            ACCEPTED_E6_FREEZE_RECEIPT_SHA256,
        ),
        ("rust_revision", manifest.rust_revision()?),
        ("evidence_nonce", nonce),
        ("rust_toolchain_name", manifest.rust_toolchain_name()?),
    ] {
        f.insert(k.into(), v.into());
    }
    f.insert(
        "boot_generation".into(),
        generation.iter().map(|b| format!("{b:02x}")).collect(),
    );
    f.insert(
        "rustc_sha256".into(),
        sha256::file_digest(&toolchain.rustc)
            .map_err(|e| Failure::task(format!("rustc hash: {e}")))?,
    );
    for (k, v) in [
        ("cargo_sha256", toolchain.cargo_sha256.as_str()),
        ("rust_lld_sha256", toolchain.rust_lld_sha256.as_str()),
        (
            "toolchain_manifest_sha256",
            toolchain.manifest_sha256.as_str(),
        ),
        (
            "toolchain_tree_sha256",
            toolchain.toolchain_tree_sha256.as_str(),
        ),
        (
            "loader_command",
            "canonical deterministic release UEFI loader pair",
        ),
        (
            "kernel_command",
            "tools/pinned-cargo target build --locked --offline --release --target x86_64-unknown-none --package deepwyrm-kernel --bin deepwyrm-kernel --features test-support [selector=interactive-wyrmsh DEEPWYRM_WYR1E8_EVIDENCE=1 nonce=validated]",
        ),
        (
            "bootstrap_command",
            "canonical DW1-E3A native bootstrap build",
        ),
        ("bootstrap_features", "wyr1c5-production"),
        (
            "bootfs_command",
            "in-process wyrmroot-bootfs build_e8 exact 18-entry archive",
        ),
        (
            "esp_command",
            "canonical g3_image build_d6 selector33 E8 ESP with explicit boot device table",
        ),
        ("malformed_elf_literal", "WYR1-E7 malformed ELF\\n"),
        (
            "malformed_elf_command",
            "inherited exact E7 literal ASCII followed by LF",
        ),
    ] {
        f.insert(k.into(), v.into());
    }
    for label in wyr1c::E8_ARTIFACT_LABELS {
        let key = label.replace('-', "_");
        f.insert(
            format!("{key}_features"),
            wyr1c::e8_native_features(label)?.into(),
        );
        let command = wyr1c::e8_native_command(label)?;
        f.insert(
            format!("{key}_command"),
            if matches!(label, "registryd" | "wyrmsh") {
                format!("inherited E6 revision {ACCEPTED_E6_REVISION}: {command}")
            } else {
                command
            },
        );
        f.insert(
            format!("{key}_inspection_sha256"),
            sha256::bytes_digest(
                inspections
                    .get(label)
                    .ok_or_else(|| Failure::task(format!("WYR1-E8 lacks {label} inspection")))?,
            ),
        );
    }
    for (k, n) in ARTIFACTS {
        f.insert(
            format!("{k}_sha256"),
            sha256::bytes_digest(&wyr1c6::read_regular_bounded(
                &artifacts.join(n),
                artifact_maximum(k),
                k,
            )?),
        );
    }
    render(&f, &source_receipt_keys(), ScalarSchema::SourceReceipt)
}

fn source_receipt_keys() -> Vec<String> {
    let mut keys = fixed_fields()
        .iter()
        .chain(extra_fields().iter())
        .map(|(key, _)| (*key).to_owned())
        .collect::<BTreeSet<_>>();
    keys.extend(CAPACITY_KEYS.into_iter().map(str::to_owned));
    keys.extend(
        [
            "deepwyrm_revision",
            "generated_abi_revision",
            "generated_abi_tree",
            "wyrmroot_revision",
            "e6_wyrmroot_revision",
            "e6_source_receipt_sha256",
            "e6_freeze_receipt_sha256",
            "rust_revision",
            "evidence_nonce",
            "rust_toolchain_name",
            "boot_generation",
            "rustc_sha256",
            "cargo_sha256",
            "rust_lld_sha256",
            "toolchain_manifest_sha256",
            "toolchain_tree_sha256",
            "loader_command",
            "kernel_command",
            "bootstrap_command",
            "bootstrap_features",
            "bootfs_command",
            "esp_command",
            "malformed_elf_literal",
            "malformed_elf_command",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    for label in wyr1c::E8_ARTIFACT_LABELS {
        let key = label.replace('-', "_");
        keys.insert(format!("{key}_command"));
        keys.insert(format!("{key}_features"));
        keys.insert(format!("{key}_inspection_sha256"));
    }
    for (key, _) in ARTIFACTS {
        keys.insert(format!("{key}_sha256"));
    }
    keys.into_iter().collect()
}

fn build_esp(output: &Path, f: &BTreeMap<String, String>) -> Result<(), Failure> {
    let a = G3ImageArguments {
        image: output
            .join("artifacts/selector33-e8-esp.img")
            .display()
            .to_string(),
        loader: output.join(field(f, "loader")?).display().to_string(),
        kernel: output.join(field(f, "kernel")?).display().to_string(),
        bootstrap: output.join(field(f, "bootstrap")?).display().to_string(),
        bootfs: output.join(field(f, "bootfs")?).display().to_string(),
    };
    g3_image::build_d6(
        &a,
        &output
            .join(field(f, "boot_device_table")?)
            .display()
            .to_string(),
    )
    .map(|_| ())
}
fn validate_esp(output: &Path, f: &BTreeMap<String, String>) -> Result<(), Failure> {
    let a = G3ImageArguments {
        image: output.join(field(f, "esp")?).display().to_string(),
        loader: output.join(field(f, "loader")?).display().to_string(),
        kernel: output.join(field(f, "kernel")?).display().to_string(),
        bootstrap: output.join(field(f, "bootstrap")?).display().to_string(),
        bootfs: output.join(field(f, "bootfs")?).display().to_string(),
    };
    g3_image::inspect_d6(
        &a,
        &output
            .join(field(f, "boot_device_table")?)
            .display()
            .to_string(),
    )
    .map(|_| ())
}
fn stage_profile(
    output: &Path,
    profile: &str,
    vcpus: u8,
    count: &str,
    request_hash: &str,
    r: &BTreeMap<String, String>,
) -> Result<(), Failure> {
    let d = output.join(profile);
    fs::create_dir(&d).map_err(|e| Failure::task(format!("profile directory: {e}")))?;
    let vars = wyr1c6::read_regular_bounded(
        &output.join(field(r, "ovmf_vars")?),
        wyr1c6::MAX_FIRMWARE_BYTES,
        "OVMF vars",
    )?;
    wyr1c6::write_new_mode(
        &d.join("OVMF_VARS.mutable.fd"),
        &vars,
        0o600,
        "mutable OVMF vars",
    )?;
    let abs =
        fs::canonicalize(output).map_err(|e| Failure::task(format!("output resolve: {e}")))?;
    let xml = crate::dw1e3a::selected_domain_xml(
        vcpus,
        &abs.join(field(r, "ovmf_code")?),
        &abs.join(field(r, "esp")?),
        &abs.join(profile).join("OVMF_VARS.mutable.fd"),
        &abs.join(profile).join("com2.sock"),
        (SELECTOR, TEST_ID),
    );
    wyr1c6::write_new(&d.join("domain.xml"), xml.as_bytes(), "domain XML")?;
    let h = profile_fields(profile, vcpus, count, request_hash, r, &xml, &vars)?;
    wyr1c6::write_new(
        &d.join("handoff.toml"),
        render_sorted(&h, ScalarSchema::Handoff)?.as_bytes(),
        "handoff",
    )
}

fn profile_fields(
    profile: &str,
    vcpus: u8,
    count: &str,
    request_hash: &str,
    r: &BTreeMap<String, String>,
    xml: &str,
    vars: &[u8],
) -> Result<BTreeMap<String, String>, Failure> {
    let mut h = BTreeMap::new();
    for (k, v) in fixed_fields().into_iter().chain(extra_fields()) {
        h.insert(k.into(), v.into());
    }
    for key in CAPACITY_KEYS {
        h.insert(key.into(), field(r, key)?.into());
    }
    h.insert("kind".into(), HANDOFF_KIND.into());
    h.insert("profile".into(), profile.into());
    h.insert("vcpus".into(), vcpus.to_string());
    h.insert("expected_evidence_records".into(), count.into());
    h.insert("request".into(), "request.toml".into());
    h.insert("request_sha256".into(), request_hash.into());
    h.insert("esp".into(), field(r, "esp")?.into());
    h.insert("esp_sha256".into(), field(r, "esp_sha256")?.into());
    h.insert("memory_mib".into(), "2048".into());
    h.insert("machine".into(), "pc-q35-10.2".into());
    h.insert("firmware".into(), "OVMF".into());
    h.insert("timeout_seconds".into(), "600".into());
    h.insert("scenario".into(), "interactive-wyrmsh-e8".into());
    h.insert(
        "terminal_authority".into(),
        "system-init-selector33-wre1.1-controller".into(),
    );
    h.insert(
        "com1_role".into(),
        "trusted-wre1.1-evidence-and-terminal".into(),
    );
    h.insert("com2_role".into(), "interactive-wyrmsh-byte-stream".into());
    h.insert("com2_transport".into(), "unix-socket-byte-stream".into());
    h.insert("com2_socket_mode".into(), "connect".into());
    h.insert("com2_socket_owner".into(), "runner".into());
    h.insert("com1_fd_group".into(), "com1".into());
    h.insert("com2_fd_group".into(), "com2".into());
    h.insert("esp_fd_group".into(), "esp".into());
    h.insert("vars_fd_group".into(), "vars".into());
    h.insert("domain_xml".into(), format!("{profile}/domain.xml"));
    h.insert(
        "domain_xml_sha256".into(),
        sha256::bytes_digest(xml.as_bytes()),
    );
    h.insert(
        "mutable_ovmf_vars".into(),
        format!("{profile}/OVMF_VARS.mutable.fd"),
    );
    h.insert(
        "mutable_ovmf_vars_initial_sha256".into(),
        sha256::bytes_digest(vars),
    );
    h.insert("com2_socket".into(), format!("{profile}/com2.sock"));
    h.insert("com1_serial_log".into(), format!("{profile}/com1.log"));
    h.insert("com2_log".into(), format!("{profile}/com2.bin"));
    h.insert("evidence_log".into(), format!("{profile}/evidence.bin"));
    h.insert(
        "backpressure_audit".into(),
        format!("{profile}/backpressure-audit.json"),
    );
    h.insert("result_path".into(), format!("{profile}/result.toml"));
    h.insert(
        "acceptance_receipt".into(),
        format!("{profile}/acceptance-receipt.toml"),
    );
    h.insert("result_schema".into(), "result-schema.toml".into());
    h.insert("evidence_nonce".into(), field(r, "evidence_nonce")?.into());
    for (k, _) in ARTIFACTS {
        h.insert(format!("{k}_path"), field(r, k)?.into());
        h.insert(
            format!("{k}_sha256"),
            field(r, &format!("{k}_sha256"))?.into(),
        );
    }
    Ok(h)
}
fn pair_fields(output: &Path, request_hash: &str) -> Result<BTreeMap<String, String>, Failure> {
    let mut f = BTreeMap::new();
    for (k, v) in [
        ("kind", PAIR_KIND),
        ("schema_version", "1"),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("evidence_version_major", "1"),
        ("evidence_version_minor", "1"),
        ("default_evidence_records", "33"),
        ("smp_evidence_records", "69"),
        ("request", "request.toml"),
        ("request_sha256", request_hash),
        ("profiles", "default,smp"),
        ("default_handoff", "default/handoff.toml"),
        ("default_vcpus", "1"),
        ("smp_handoff", "smp/handoff.toml"),
        ("smp_vcpus", "4"),
        ("memory_mib", "2048"),
        ("machine", "pc-q35-10.2"),
        ("firmware", "OVMF"),
        ("timeout_seconds", "600"),
        ("result_schema", "result-schema.toml"),
    ] {
        f.insert(k.into(), v.into());
    }
    for (p, k) in [
        ("default", "default_handoff_sha256"),
        ("smp", "smp_handoff_sha256"),
    ] {
        f.insert(
            k.into(),
            sha256::bytes_digest(&wyr1c6::read_regular_bounded(
                &output.join(p).join("handoff.toml"),
                64 * 1024,
                "handoff",
            )?),
        );
    }
    Ok(f)
}
fn receipt_fields(hash: &str, r: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut f = BTreeMap::new();
    f.insert("kind".into(), RECEIPT_KIND.into());
    f.insert("request_sha256".into(), hash.into());
    for k in [
        "schema_version",
        "selector",
        "test_id",
        "evidence_protocol",
        "evidence_version_major",
        "evidence_version_minor",
        "evidence_nonce",
        "default_evidence_records",
        "smp_evidence_records",
        "source_receipt_sha256",
        "esp_sha256",
    ] {
        f.insert(k.into(), r[k].clone());
    }
    for (k, _) in ARTIFACTS {
        f.insert(format!("{k}_sha256"), r[&format!("{k}_sha256")].clone());
    }
    f
}

fn request_keys() -> Vec<String> {
    let mut k = Vec::new();
    for (key, _) in fixed_fields() {
        k.push(key.into());
        if key == "task_group_capacity" {
            k.extend(CAPACITY_KEYS.into_iter().map(str::to_owned));
        }
    }
    k.extend(extra_fields().iter().map(|(k, _)| (*k).into()));
    for x in [
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
    ] {
        k.push(x.into());
    }
    for (a, _) in ARTIFACTS {
        k.push((*a).into());
        k.push(format!("{a}_sha256"));
    }
    k
}
fn result_schema() -> Result<String, Failure> {
    let keys = result_keys();
    let mut f = BTreeMap::new();
    for k in &keys {
        let k = k.as_str();
        f.insert(
            k.into(),
            match k {
                "kind" => RESULT_KIND.into(),
                "schema_version" => "1".into(),
                "selector" => SELECTOR.into(),
                "test_id" => TEST_ID.into(),
                "evidence_protocol" => EVIDENCE_PROTOCOL.into(),
                "evidence_version_major" | "evidence_version_minor" => "1".into(),
                "terminal_line" => "DWTEST1 33 0".into(),
                "shutdown_byte_hex" => "04".into(),
                "acceptance" => "pass".into(),
                _ => format!("<runner:{k}>"),
            },
        );
    }
    render(&f, &keys, ScalarSchema::ResultTemplate)
}

fn result_keys() -> Vec<String> {
    [
        "kind",
        "schema_version",
        "profile",
        "request_sha256",
        "handoff_sha256",
        "selector",
        "test_id",
        "evidence_protocol",
        "evidence_version_major",
        "evidence_version_minor",
        "evidence_nonce",
        "expected_evidence_records",
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
        "s1_console_generation",
        "s1_status_generation",
        "s1_shell_generation",
        "s1_outer_launch_transaction",
        "s1_outer_job_id",
        "s1_registry_generation",
        "s1_registry_endpoint_id",
        "s1_registry_endpoint_generation",
        "s1_shell_jobs_connection_id",
        "s1_shell_jobs_generation",
        "s2_console_generation",
        "s2_status_generation",
        "s2_shell_generation",
        "s2_outer_launch_transaction",
        "s2_outer_job_id",
        "s2_registry_generation",
        "s2_registry_endpoint_id",
        "s2_registry_endpoint_generation",
        "s2_shell_jobs_connection_id",
        "s2_shell_jobs_generation",
        "s3_console_generation",
        "s3_status_generation",
        "s3_shell_generation",
        "s3_outer_launch_transaction",
        "s3_outer_job_id",
        "s3_registry_generation",
        "s3_registry_endpoint_id",
        "s3_registry_endpoint_generation",
        "s3_shell_jobs_connection_id",
        "s3_shell_jobs_generation",
        "s4_console_generation",
        "s4_status_generation",
        "s4_shell_generation",
        "s4_outer_launch_transaction",
        "s4_outer_job_id",
        "s4_registry_generation",
        "s4_registry_endpoint_id",
        "s4_registry_endpoint_generation",
        "s4_shell_jobs_connection_id",
        "s4_shell_jobs_generation",
        "s1_retired_cause",
        "s2_retired_cause",
        "s3_retired_cause",
        "s4_retired_cause",
        "pressure_bytes",
        "pressure_sha256",
        "pressure_would_blocks",
        "pressure_pause_offset",
        "pressure_resume_offset",
        "pressure_pause_monotonic_ns",
        "pressure_resume_monotonic_ns",
        "send_count",
        "input_bytes",
        "audit_bytes",
        "backpressure_audit_sha256",
        "acceptance",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
fn validate_request(f: &BTreeMap<String, String>, capacities: [u64; 4]) -> Result<(), Failure> {
    for (k, v) in fixed_fields().into_iter().chain(extra_fields()) {
        if field(f, k)? != v {
            return Err(Failure::task(format!("WYR1-E8 {k} drifted")));
        }
    }
    validate_locked_capacities(capacities)?;
    for (key, value) in CAPACITY_KEYS.into_iter().zip(capacities) {
        if field(f, key)? != value.to_string() {
            return Err(Failure::task(format!(
                "WYR1-E8 {key} does not match the selected Deepwyrm source"
            )));
        }
    }
    for (k, v) in [
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
        if field(f, k)? != v {
            return Err(Failure::task(format!("WYR1-E8 {k} drifted")));
        }
    }
    for (k, v) in ACCEPTED_E6_REUSED_SHA256 {
        if field(f, &format!("{k}_sha256"))? != *v {
            return Err(Failure::task(format!("WYR1-E8 inherited {k} drifted")));
        }
    }
    for (k, n) in ARTIFACTS {
        if field(f, k)? != format!("artifacts/{n}") {
            return Err(Failure::task(format!("WYR1-E8 {k} path drifted")));
        }
    }
    for (k, v) in [
        ("default_handoff", "default/handoff.toml"),
        ("smp_handoff", "smp/handoff.toml"),
        ("profile_pair", "profile-pair.toml"),
        ("receipt", "freeze-receipt.toml"),
        ("source_receipt", "artifacts/e8-source-build.toml"),
        ("esp", "artifacts/selector33-e8-esp.img"),
        ("result_schema", "result-schema.toml"),
    ] {
        if field(f, k)? != v {
            return Err(Failure::task(format!("WYR1-E8 {k} path drifted")));
        }
    }
    for k in [
        "deepwyrm_revision",
        "generated_abi_revision",
        "generated_abi_tree",
        "wyrmroot_revision",
        "rust_revision",
    ] {
        wyr1c6::validate_revision(field(f, k)?, k)?;
    }
    wyr1c::validate_e8_nonce(field(f, "evidence_nonce")?)?;
    for k in [
        "esp_sha256",
        "source_receipt_sha256",
        "e6_source_receipt_sha256",
        "e6_freeze_receipt_sha256",
    ] {
        validate_lower_hex(field(f, k)?, 64, k)?;
    }
    for (k, _) in ARTIFACTS {
        let hash = format!("{k}_sha256");
        validate_lower_hex(field(f, &hash)?, 64, &hash)?;
    }
    Ok(())
}

fn validate_frozen_metadata(
    output: &Path,
    request: &BTreeMap<String, String>,
    request_hash: &str,
) -> Result<(), Failure> {
    for profile in ["default", "smp"] {
        for runtime in [
            "verification-manifest.json",
            "com2.sock",
            "com1.log",
            "com2.bin",
            "evidence.bin",
            "backpressure-audit.json",
            "result.toml",
            "acceptance-receipt.toml",
        ] {
            if output.join(profile).join(runtime).exists() {
                return Err(Failure::task(
                    "WYR1-E8 output is consumed/runtime state; use the canonical post-run recheck",
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
        "WYR1-E8 output",
    )?;
    let mut artifact_names = ARTIFACTS.iter().map(|(_, name)| *name).collect::<Vec<_>>();
    artifact_names.extend([
        "e6-source-build.toml",
        "e6-freeze-receipt.toml",
        SOURCE_RECEIPT,
        "selector33-e8-esp.img",
    ]);
    require_exact_directory(
        &output.join("artifacts"),
        &artifact_names,
        "WYR1-E8 artifacts",
    )?;
    require_mode(&output.join("request.toml"), 0o444, "WYR1-E8 request")?;
    for (key, _) in ARTIFACTS {
        require_mode(&output.join(field(request, key)?), 0o444, key)?;
    }
    for (name, key) in [
        ("e6-source-build.toml", "e6_source_receipt_sha256"),
        ("e6-freeze-receipt.toml", "e6_freeze_receipt_sha256"),
    ] {
        let path = output.join("artifacts").join(name);
        require_mode(&path, 0o444, "WYR1-E8 inherited E6 receipt")?;
        let bytes = wyr1c6::read_regular_bounded(&path, 64 * 1024, name)?;
        if sha256::bytes_digest(&bytes) != field(request, key)? {
            return Err(Failure::task(
                "WYR1-E8 inherited E6 receipt identity drifted",
            ));
        }
    }
    for key in ["source_receipt", "esp", "result_schema"] {
        require_mode(&output.join(field(request, key)?), 0o444, key)?;
    }
    let result_schema_bytes = wyr1c6::read_regular_bounded(
        &output.join(field(request, "result_schema")?),
        64 * 1024,
        "WYR1-E8 result schema",
    )?;
    if result_schema_bytes != result_schema()?.as_bytes() {
        return Err(Failure::task("WYR1-E8 result schema drifted"));
    }
    let vars = wyr1c6::read_regular_bounded(
        &output.join(field(request, "ovmf_vars")?),
        wyr1c6::MAX_FIRMWARE_BYTES,
        "WYR1-E8 OVMF vars",
    )?;
    let absolute = fs::canonicalize(output)
        .map_err(|e| Failure::task(format!("could not resolve WYR1-E8 output: {e}")))?;
    for (profile, vcpus, count) in [("default", 1_u8, "33"), ("smp", 4_u8, "69")] {
        require_exact_directory(
            &output.join(profile),
            &["handoff.toml", "domain.xml", "OVMF_VARS.mutable.fd"],
            "WYR1-E8 prepared profile",
        )?;
        let mutable_vars = output.join(profile).join("OVMF_VARS.mutable.fd");
        require_mode(&mutable_vars, 0o600, "WYR1-E8 mutable OVMF vars")?;
        if wyr1c6::read_regular_bounded(
            &mutable_vars,
            wyr1c6::MAX_FIRMWARE_BYTES,
            "WYR1-E8 mutable OVMF vars",
        )? != vars
        {
            return Err(Failure::task(
                "WYR1-E8 output is consumed/runtime state because OVMF variables changed",
            ));
        }
        let xml = crate::dw1e3a::selected_domain_xml(
            vcpus,
            &absolute.join(field(request, "ovmf_code")?),
            &absolute.join(field(request, "esp")?),
            &absolute.join(profile).join("OVMF_VARS.mutable.fd"),
            &absolute.join(profile).join("com2.sock"),
            (SELECTOR, TEST_ID),
        );
        let xml_path = output.join(profile).join("domain.xml");
        require_mode(&xml_path, 0o444, "WYR1-E8 domain XML")?;
        if wyr1c6::read_regular_bounded(&xml_path, 64 * 1024, "WYR1-E8 domain XML")?
            != xml.as_bytes()
        {
            return Err(Failure::task(format!(
                "WYR1-E8 {profile} domain XML drifted"
            )));
        }
        let handoff = profile_fields(profile, vcpus, count, request_hash, request, &xml, &vars)?;
        let handoff_path = output.join(profile).join("handoff.toml");
        require_mode(&handoff_path, 0o444, "WYR1-E8 handoff")?;
        if wyr1c6::read_regular_bounded(&handoff_path, 64 * 1024, "WYR1-E8 handoff")?
            != render_sorted(&handoff, ScalarSchema::Handoff)?.as_bytes()
        {
            return Err(Failure::task(format!("WYR1-E8 {profile} handoff drifted")));
        }
    }
    let pair = pair_fields(output, request_hash)?;
    if wyr1c6::read_regular_bounded(
        &output.join(field(request, "profile_pair")?),
        64 * 1024,
        "WYR1-E8 profile pair",
    )? != render_sorted(&pair, ScalarSchema::Pair)?.as_bytes()
    {
        return Err(Failure::task("WYR1-E8 profile pair drifted"));
    }
    let receipt = receipt_fields(request_hash, request);
    if wyr1c6::read_regular_bounded(
        &output.join(field(request, "receipt")?),
        64 * 1024,
        "WYR1-E8 freeze receipt",
    )? != render_sorted(&receipt, ScalarSchema::FreezeReceipt)?.as_bytes()
    {
        return Err(Failure::task("WYR1-E8 freeze receipt drifted"));
    }
    Ok(())
}

fn require_exact_directory(path: &Path, expected: &[&str], label: &str) -> Result<(), Failure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| Failure::task(format!("could not stat {label}: {e}")))?;
    if !metadata.file_type().is_dir() {
        return Err(Failure::task(format!("{label} is not a directory")));
    }
    let actual = fs::read_dir(path)
        .map_err(|e| Failure::task(format!("could not read {label}: {e}")))?
        .map(|entry| {
            entry
                .map_err(|e| Failure::task(format!("could not read {label}: {e}")))?
                .file_name()
                .into_string()
                .map_err(|_| Failure::task(format!("{label} contains a non-UTF-8 name")))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = expected.iter().map(|name| (*name).to_owned()).collect();
    if actual != expected {
        return Err(Failure::task(format!("{label} entry set drifted")));
    }
    Ok(())
}

fn require_mode(path: &Path, expected: u32, label: &str) -> Result<(), Failure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| Failure::task(format!("could not stat {label}: {e}")))?;
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
fn field<'a>(f: &'a BTreeMap<String, String>, k: &str) -> Result<&'a str, Failure> {
    f.get(k)
        .map(String::as_str)
        .ok_or_else(|| Failure::task(format!("missing WYR1-E8 field {k}")))
}
fn artifact_maximum(k: &str) -> u64 {
    match k {
        "ovmf_code" | "ovmf_vars" => wyr1c6::MAX_FIRMWARE_BYTES,
        "esp" => g3_image::IMAGE_BYTES,
        _ => wyr1c6::MAX_ARTIFACT_BYTES,
    }
}
const SEMANTIC_INTEGER_KEYS: &[&str] = &[
    "evidence_version_major",
    "evidence_version_minor",
    "evidence_record_bytes",
    "evidence_record_capacity",
    "default_evidence_records",
    "smp_evidence_records",
    "com2_prelude_length",
    "process_capacity",
    "thread_capacity",
    "root_address_space_capacity",
    "task_group_capacity",
    "per_process_handle_capacity",
    "memory_object_capacity",
    "mapping_lease_capacity",
    "registry_object_capacity",
    "channel_pair_capacity",
    "wait_capacity",
    "overall_timeout_seconds",
    "ordinary_timeout_seconds",
    "transition_timeout_seconds",
    "com2_capture_bytes",
    "send_limit",
    "input_limit_bytes",
    "audit_limit_bytes",
    "pressure_pause_milliseconds",
    "pressure_bytes",
    "pressure_min_would_blocks",
    "pressure_max_would_blocks",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScalarSchema {
    Request,
    SourceReceipt,
    Handoff,
    FreezeReceipt,
    Pair,
    ResultTemplate,
}

impl ScalarSchema {
    fn label(self) -> &'static str {
        match self {
            Self::Request => "WYR1-E8 request",
            Self::SourceReceipt => "WYR1-E8 source receipt",
            Self::Handoff => "WYR1-E8 handoff",
            Self::FreezeReceipt => "WYR1-E8 freeze receipt",
            Self::Pair => "WYR1-E8 profile pair",
            Self::ResultTemplate => "WYR1-E8 result schema",
        }
    }

    fn is_integer(self, key: &str) -> bool {
        match self {
            Self::Request | Self::SourceReceipt => {
                matches!(key, "schema_version" | "test_id") || SEMANTIC_INTEGER_KEYS.contains(&key)
            }
            Self::Handoff => {
                matches!(
                    key,
                    "schema_version"
                        | "test_id"
                        | "expected_evidence_records"
                        | "vcpus"
                        | "memory_mib"
                        | "timeout_seconds"
                ) || SEMANTIC_INTEGER_KEYS.contains(&key)
            }
            Self::FreezeReceipt => matches!(
                key,
                "schema_version"
                    | "test_id"
                    | "evidence_version_major"
                    | "evidence_version_minor"
                    | "default_evidence_records"
                    | "smp_evidence_records"
            ),
            Self::Pair => matches!(
                key,
                "schema_version"
                    | "test_id"
                    | "evidence_version_major"
                    | "evidence_version_minor"
                    | "default_evidence_records"
                    | "smp_evidence_records"
                    | "default_vcpus"
                    | "smp_vcpus"
                    | "memory_mib"
                    | "timeout_seconds"
            ),
            Self::ResultTemplate => false,
        }
    }
}

fn render(
    f: &BTreeMap<String, String>,
    keys: &[String],
    schema: ScalarSchema,
) -> Result<String, Failure> {
    let label = schema.label();
    let expected = keys.iter().cloned().collect::<BTreeSet<_>>();
    if f.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return Err(Failure::task(format!("{label} fields drifted")));
    }
    let mut out = String::new();
    for k in keys {
        let v = field(f, k)?;
        if v.contains(['\n', '\r']) {
            return Err(Failure::task(format!("{label} unsafe value")));
        }
        if schema.is_integer(k) {
            if v.is_empty()
                || !v.bytes().all(|byte| byte.is_ascii_digit())
                || (v.len() > 1 && v.starts_with('0'))
            {
                return Err(Failure::task(format!(
                    "{label} {k} is not a canonical integer"
                )));
            }
            out.push_str(&format!("{k} = {v}\n"));
        } else {
            let escaped = v.replace('\\', "\\\\").replace('"', "\\\"");
            out.push_str(&format!("{k} = \"{escaped}\"\n"));
        }
    }
    Ok(out)
}
fn render_sorted(f: &BTreeMap<String, String>, schema: ScalarSchema) -> Result<String, Failure> {
    let keys = f.keys().cloned().collect::<Vec<_>>();
    render(f, &keys, schema)
}
fn parse(text: &str) -> Result<BTreeMap<String, String>, Failure> {
    if !text.ends_with('\n') || text.contains('\r') {
        return Err(Failure::task("noncanonical WYR1-E8 scalar file"));
    }
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let (k, v) = line
            .split_once(" = ")
            .ok_or_else(|| Failure::task("malformed WYR1-E8 scalar line"))?;
        if k.is_empty()
            || !k
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(Failure::task("invalid WYR1-E8 key"));
        }
        let value = if let Some(q) = v.strip_prefix('"').and_then(|x| x.strip_suffix('"')) {
            decode_scalar_string(q)?
        } else if v.bytes().all(|b| b.is_ascii_digit()) {
            v.to_owned()
        } else {
            return Err(Failure::task("invalid WYR1-E8 value"));
        };
        if out.insert(k.into(), value).is_some() {
            return Err(Failure::task("duplicate WYR1-E8 key"));
        }
    }
    Ok(out)
}

fn decode_scalar_string(inner: &str) -> Result<String, Failure> {
    let mut value = String::new();
    let mut characters = inner.chars();
    while let Some(character) = characters.next() {
        match character {
            '\\' => match characters.next() {
                Some('\\') => value.push('\\'),
                Some('"') => value.push('"'),
                _ => return Err(Failure::task("unsupported WYR1-E8 scalar escape")),
            },
            '"' => return Err(Failure::task("unescaped WYR1-E8 scalar quote")),
            other => value.push(other),
        }
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::Write as _,
        process::{Command, Stdio},
        time::{SystemTime, UNIX_EPOCH},
    };

    fn root_verifier_accepts_request(text: &str) -> Result<(), Failure> {
        let repository = tasks::repository_root()?;
        let project = tasks::canonical_project_root(&repository)?;
        let verifier = project.join("tools/verify-vm-request.py");
        let program = r#"import importlib.util, sys
spec = importlib.util.spec_from_file_location("verify_vm_request", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
integers = frozenset({"schema_version", "test_id"}) | module.E8_SEMANTIC_INTEGER_KEYS
module._strict_c6_toml(
    sys.stdin.buffer.read(),
    module.E8_REQUEST_KEYS,
    "Rust-rendered E8 request fixture",
    integers,
)
"#;
        let mut child = Command::new("/usr/bin/python3")
            .args(["-c", program])
            .arg(verifier)
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
                "root verifier rejected Rust-rendered E8 request: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }

    fn normalized_a1_request() -> BTreeMap<String, String> {
        let mut request = fixed_fields()
            .into_iter()
            .chain(extra_fields())
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect::<BTreeMap<_, _>>();
        insert_capacity_fields(&mut request, LOCKED_CAPACITIES);
        for (key, value) in [
            (
                "deepwyrm_revision",
                "89cac01882d83a8cd76b4dd30639573839b2b8cd",
            ),
            (
                "generated_abi_revision",
                "085b184c32ae1fa3d5ec322c86957dd5d036595c",
            ),
            (
                "generated_abi_tree",
                "a9b067107ec38e2be44630f4dce428dab0f48de8",
            ),
            (
                "wyrmroot_revision",
                "f262c60226cf038a575c6bf0da150083ea9bd07d",
            ),
            ("e6_wyrmroot_revision", ACCEPTED_E6_REVISION),
            (
                "e6_source_receipt_sha256",
                ACCEPTED_E6_SOURCE_RECEIPT_SHA256,
            ),
            (
                "e6_freeze_receipt_sha256",
                ACCEPTED_E6_FREEZE_RECEIPT_SHA256,
            ),
            ("rust_revision", "a92dc7f7464ad6ddfece4402bd7b86dbfa86166d"),
            ("evidence_nonce", "E800000000000101"),
            ("esp", "artifacts/selector33-e8-esp.img"),
            ("default_handoff", "default/handoff.toml"),
            ("smp_handoff", "smp/handoff.toml"),
            ("profile_pair", "profile-pair.toml"),
            ("receipt", "freeze-receipt.toml"),
            ("source_receipt", "artifacts/e8-source-build.toml"),
            ("result_schema", "result-schema.toml"),
        ] {
            request.insert(key.to_owned(), value.to_owned());
        }
        request.insert("esp_sha256".into(), "ab".repeat(32));
        request.insert("source_receipt_sha256".into(), "cd".repeat(32));
        for (key, name) in ARTIFACTS {
            request.insert((*key).to_owned(), format!("artifacts/{name}"));
            request.insert(format!("{key}_sha256"), "ef".repeat(32));
        }
        for (key, digest) in ACCEPTED_E6_REUSED_SHA256 {
            request.insert(format!("{key}_sha256"), (*digest).to_owned());
        }
        request
    }

    fn normalized_source_receipt() -> BTreeMap<String, String> {
        let mut source = fixed_fields()
            .into_iter()
            .chain(extra_fields())
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect::<BTreeMap<_, _>>();
        insert_capacity_fields(&mut source, LOCKED_CAPACITIES);
        source.insert("kind".into(), SOURCE_KIND.into());
        for (key, value) in [
            (
                "deepwyrm_revision",
                "89cac01882d83a8cd76b4dd30639573839b2b8cd",
            ),
            (
                "generated_abi_revision",
                "085b184c32ae1fa3d5ec322c86957dd5d036595c",
            ),
            (
                "generated_abi_tree",
                "a9b067107ec38e2be44630f4dce428dab0f48de8",
            ),
            (
                "wyrmroot_revision",
                "f262c60226cf038a575c6bf0da150083ea9bd07d",
            ),
            ("rust_revision", "a92dc7f7464ad6ddfece4402bd7b86dbfa86166d"),
            ("e6_wyrmroot_revision", ACCEPTED_E6_REVISION),
            (
                "e6_source_receipt_sha256",
                ACCEPTED_E6_SOURCE_RECEIPT_SHA256,
            ),
            (
                "e6_freeze_receipt_sha256",
                ACCEPTED_E6_FREEZE_RECEIPT_SHA256,
            ),
            ("evidence_nonce", "E800000000000101"),
            ("boot_generation", "01"),
            ("rust_toolchain_name", "wyrmroot-test-toolchain"),
            ("rustc_sha256", "01"),
            ("cargo_sha256", "02"),
            ("rust_lld_sha256", "03"),
            ("toolchain_manifest_sha256", "04"),
            ("toolchain_tree_sha256", "05"),
            (
                "loader_command",
                "canonical deterministic release UEFI loader pair",
            ),
            (
                "kernel_command",
                "tools/pinned-cargo target build --locked --offline --release --target x86_64-unknown-none --package deepwyrm-kernel --bin deepwyrm-kernel --features test-support [selector=interactive-wyrmsh DEEPWYRM_WYR1E8_EVIDENCE=1 nonce=validated]",
            ),
            (
                "bootstrap_command",
                "canonical DW1-E3A native bootstrap build",
            ),
            ("bootstrap_features", "wyr1c5-production"),
            (
                "bootfs_command",
                "in-process wyrmroot-bootfs build_e8 exact 18-entry archive",
            ),
            (
                "esp_command",
                "canonical g3_image build_d6 selector33 E8 ESP with explicit boot device table",
            ),
            ("malformed_elf_literal", "WYR1-E7 malformed ELF\\n"),
            (
                "malformed_elf_command",
                "inherited exact E7 literal ASCII followed by LF",
            ),
        ] {
            source.insert(key.into(), value.into());
        }
        for label in wyr1c::E8_ARTIFACT_LABELS {
            let key = label.replace('-', "_");
            source.insert(
                format!("{key}_features"),
                wyr1c::e8_native_features(label).unwrap().into(),
            );
            let command = wyr1c::e8_native_command(label).unwrap();
            source.insert(
                format!("{key}_command"),
                if matches!(label, "registryd" | "wyrmsh") {
                    format!("inherited E6 revision {ACCEPTED_E6_REVISION}: {command}")
                } else {
                    command
                },
            );
            source.insert(format!("{key}_inspection_sha256"), "06".repeat(32));
        }
        for (key, _) in ARTIFACTS {
            source.insert(format!("{key}_sha256"), "07".repeat(32));
        }
        for (key, digest) in ACCEPTED_E6_REUSED_SHA256 {
            source.insert(format!("{key}_sha256"), (*digest).into());
        }
        assert_eq!(source.len(), 128);
        source
    }

    fn root_accepts_all_scalar_records(records: &[String; 7]) -> Result<(), Failure> {
        let repository = tasks::repository_root()?;
        let project = tasks::canonical_project_root(&repository)?;
        let verifier = project.join("tools/verify-vm-request.py");
        let runner = project.join("tools/run-verified-vm-request.py");
        let program = r#"import importlib.util, sys
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
verify = load("verify_vm_request", sys.argv[1])
runner = load("run_verified_vm_request", sys.argv[2])
records = sys.stdin.buffer.read().split(b"\0")
if len(records) != 7:
    raise RuntimeError("expected seven Rust-rendered E8 scalar records")
request, source, freeze, pair, default_handoff, smp_handoff, result = records
semantic = verify.E8_SEMANTIC_INTEGER_KEYS
profiles = (
    (request, verify.E8_REQUEST_KEYS, frozenset({"schema_version", "test_id"}) | semantic, "request"),
    (source, verify.E8_SOURCE_RECEIPT_KEYS, frozenset({"schema_version", "test_id"}) | semantic, "source"),
    (freeze, verify.E8_RECEIPT_KEYS, frozenset({"schema_version", "test_id", "evidence_version_major", "evidence_version_minor", "default_evidence_records", "smp_evidence_records"}), "freeze"),
    (pair, verify.E8_PAIR_KEYS, frozenset({"schema_version", "test_id", "evidence_version_major", "evidence_version_minor", "default_evidence_records", "smp_evidence_records", "default_vcpus", "smp_vcpus", "memory_mib", "timeout_seconds"}), "pair"),
    (default_handoff, verify.E8_HANDOFF_KEYS, frozenset({"schema_version", "test_id", "vcpus", "memory_mib", "timeout_seconds", "expected_evidence_records"}) | semantic, "default handoff"),
    (smp_handoff, verify.E8_HANDOFF_KEYS, frozenset({"schema_version", "test_id", "vcpus", "memory_mib", "timeout_seconds", "expected_evidence_records"}) | semantic, "SMP handoff"),
)
def replace_value(contents, key, replacement):
    prefix = key + " = "
    lines = contents.decode("utf-8").splitlines()
    matches = [index for index, line in enumerate(lines) if line.startswith(prefix)]
    if len(matches) != 1:
        raise RuntimeError(f"missing unique {key}")
    lines[matches[0]] = prefix + replacement
    return ("\n".join(lines) + "\n").encode()
for contents, keys, integers, label in profiles:
    parsed = verify._strict_c6_toml(contents, keys, f"Rust-rendered E8 {label}", integers)
    for key in keys:
        replacement = f'"{parsed[key]}"' if key in integers else "1"
        try:
            verify._strict_c6_toml(replace_value(contents, key, replacement), keys, f"mistyped E8 {label}", integers)
        except verify.VerificationError:
            pass
        else:
            raise RuntimeError(f"root accepted mistyped E8 {label} field {key}")
source_fields = verify.parse_e8_source_receipt(source)
verify.validate_e8_source_receipt_lineage(source_fields)
if source_fields["malformed_elf_literal"] != r"WYR1-E7 malformed ELF\n":
    raise RuntimeError("source literal did not preserve backslash+n")
values = {key: f"value-{key}" for key in verify.E8_RESULT_KEYS}
runner._render_e8_result_toml(values, result)
for key in verify.E8_RESULT_KEYS:
    try:
        runner._render_e8_result_toml(values, replace_value(result, key, "1"))
    except runner.RunnerError:
        pass
    else:
        raise RuntimeError(f"runner accepted mistyped E8 result field {key}")
"#;
        let mut child = Command::new("/usr/bin/python3")
            .args(["-c", program])
            .arg(verifier)
            .arg(runner)
            .current_dir(project)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| Failure::task(format!("could not start root E8 parsers: {error}")))?;
        let input = records.join("\0");
        child
            .stdin
            .take()
            .ok_or_else(|| Failure::task("root E8 parser stdin was unavailable"))?
            .write_all(input.as_bytes())
            .map_err(|error| Failure::task(format!("could not feed root E8 parsers: {error}")))?;
        let output = child.wait_with_output().map_err(|error| {
            Failure::task(format!("could not wait for root E8 parsers: {error}"))
        })?;
        if !output.status.success() {
            return Err(Failure::task(format!(
                "root rejected Rust-rendered E8 scalar records: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }

    #[test]
    fn request_contract_has_one_exact_additive_key_set() {
        let keys = request_keys();
        assert_eq!(keys.len(), 111);
        assert_eq!(
            keys.iter().cloned().collect::<BTreeSet<_>>().len(),
            keys.len()
        );
        assert_eq!(
            &keys[..7],
            [
                "kind",
                "schema_version",
                "selector",
                "test_id",
                "profile",
                "scenario",
                "evidence_protocol",
            ]
        );
        assert_eq!(keys.last().map(String::as_str), Some("ovmf_vars_sha256"));
        assert_eq!(ARTIFACTS.len(), 25);
        assert_eq!(ARTIFACTS[0], ("loader", "loader.efi"));
        assert_eq!(ARTIFACTS[24], ("ovmf_vars", "OVMF_VARS.fd"));
        let source_keys = source_receipt_keys();
        assert_eq!(source_keys.len(), 128);
        assert!(source_keys.contains(&"profile".to_owned()));
        assert!(source_keys.contains(&"scenario".to_owned()));
        for label in wyr1c::E8_ARTIFACT_LABELS {
            let key = label.replace('-', "_");
            assert!(source_keys.contains(&format!("{key}_inspection_sha256")));
        }
        assert_eq!(
            fixed_fields()[19..25],
            [
                ("process_capacity", "64"),
                ("thread_capacity", "64"),
                ("root_address_space_capacity", "64"),
                ("task_group_capacity", "64"),
                ("channel_pair_capacity", "32"),
                ("wait_capacity", "64"),
            ]
        );
        assert_eq!(
            CAPACITY_KEYS,
            [
                "per_process_handle_capacity",
                "memory_object_capacity",
                "mapping_lease_capacity",
                "registry_object_capacity",
            ]
        );
        assert_eq!(LOCKED_CAPACITIES, [64, 64, 64, 160]);
    }

    #[test]
    fn request_rejects_each_capacity_mismatch_from_selected_source() {
        for (key, capacity) in CAPACITY_KEYS.into_iter().zip(LOCKED_CAPACITIES) {
            let mut request = normalized_a1_request();
            request.insert(key.into(), (capacity - 1).to_string());
            assert!(validate_request(&request, LOCKED_CAPACITIES).is_err());
        }
        for index in 0..LOCKED_CAPACITIES.len() {
            let mut source_capacities = LOCKED_CAPACITIES;
            source_capacities[index] -= 1;
            assert!(validate_request(&normalized_a1_request(), source_capacities).is_err());
        }
    }

    #[test]
    fn result_schema_is_ordered_and_binds_the_backpressure_audit_last() {
        let keys = result_keys();
        assert_eq!(
            keys.iter().cloned().collect::<BTreeSet<_>>().len(),
            keys.len()
        );
        assert_eq!(keys[keys.len() - 2], "backpressure_audit_sha256");
        assert_eq!(keys[keys.len() - 1], "acceptance");
        assert!(!keys.iter().any(|key| key.ends_with("cleanup_mask")));
        let rendered = result_schema().unwrap();
        assert!(rendered.ends_with(
            "backpressure_audit_sha256 = \"<runner:backpressure_audit_sha256>\"\nacceptance = \"pass\"\n"
        ));
        assert!(rendered.contains("evidence_nonce = \"<runner:evidence_nonce>\"\n"));
        assert!(rendered.contains("schema_version = \"1\"\n"));
        assert!(
            rendered
                .contains("expected_evidence_records = \"<runner:expected_evidence_records>\"\n")
        );
    }

    #[test]
    fn all_e8_scalar_records_match_root_type_and_escape_contracts() {
        let request = normalized_a1_request();
        let request_text = render(&request, &request_keys(), ScalarSchema::Request).unwrap();
        let request_hash = sha256::bytes_digest(request_text.as_bytes());
        let source_text = render(
            &normalized_source_receipt(),
            &source_receipt_keys(),
            ScalarSchema::SourceReceipt,
        )
        .unwrap();
        assert!(source_text.contains("malformed_elf_literal = \"WYR1-E7 malformed ELF\\\\n\"\n"));
        assert_eq!(
            parse(&source_text).unwrap()["malformed_elf_literal"],
            "WYR1-E7 malformed ELF\\n"
        );

        let default = profile_fields(
            "default",
            1,
            "33",
            &request_hash,
            &request,
            "<domain profile=\"default\"/>",
            b"default vars",
        )
        .unwrap();
        let smp = profile_fields(
            "smp",
            4,
            "69",
            &request_hash,
            &request,
            "<domain profile=\"smp\"/>",
            b"smp vars",
        )
        .unwrap();
        assert_eq!(default.len(), 126);
        assert_eq!(smp.len(), 126);
        let default_text = render_sorted(&default, ScalarSchema::Handoff).unwrap();
        let smp_text = render_sorted(&smp, ScalarSchema::Handoff).unwrap();

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let repository = tasks::repository_root().unwrap();
        let scratch = repository
            .join(".tmp/wyr1e8-schema-tests")
            .join(format!("{}-{unique}", std::process::id()));
        fs::create_dir_all(scratch.join("default")).unwrap();
        fs::create_dir_all(scratch.join("smp")).unwrap();
        fs::write(scratch.join("default/handoff.toml"), &default_text).unwrap();
        fs::write(scratch.join("smp/handoff.toml"), &smp_text).unwrap();
        let pair = pair_fields(&scratch, &request_hash).unwrap();
        assert_eq!(pair.len(), 23);
        let pair_text = render_sorted(&pair, ScalarSchema::Pair).unwrap();
        fs::remove_dir_all(&scratch).unwrap();
        assert!(pair_text.contains("default_vcpus = 1\n"));
        assert!(pair_text.contains("smp_vcpus = 4\n"));

        let freeze = receipt_fields(&request_hash, &request);
        assert_eq!(freeze.len(), 38);
        let freeze_text = render_sorted(&freeze, ScalarSchema::FreezeReceipt).unwrap();
        assert_eq!(result_keys().len(), 82);
        let result_text = result_schema().unwrap();
        for (key, value) in CAPACITY_KEYS.into_iter().zip(LOCKED_CAPACITIES) {
            let field = format!("{key} = {value}\n");
            assert!(request_text.contains(&field));
            assert!(source_text.contains(&field));
            assert!(default_text.contains(&field));
            assert!(smp_text.contains(&field));
            assert!(!freeze_text.contains(&format!("{key} = ")));
            assert!(!pair_text.contains(&format!("{key} = ")));
            assert!(!result_text.contains(&format!("{key} = ")));
        }
        let records = [
            request_text,
            source_text,
            freeze_text,
            pair_text,
            default_text,
            smp_text,
            result_text,
        ];
        root_accepts_all_scalar_records(&records).unwrap();

        let mut noncanonical_pair = pair;
        noncanonical_pair.insert("default_vcpus".into(), "01".into());
        assert!(render_sorted(&noncanonical_pair, ScalarSchema::Pair).is_err());
    }

    #[test]
    fn current_and_inherited_native_lineage_is_exact() {
        assert_eq!(
            wyr1c::e8_native_features("system-init").unwrap(),
            "wyr1e8-selector33"
        );
        assert_eq!(
            wyr1c::e8_native_features("devmgr").unwrap(),
            "wyr1e8-production"
        );
        assert_eq!(
            wyr1c::e8_native_features("consoled").unwrap(),
            "native-consoled,wyr1e-wyrmsh,wyr1e8-recovery"
        );
        assert_eq!(
            wyr1c::e8_native_features("uart16550d").unwrap(),
            "native-uart16550d"
        );
        assert_eq!(
            wyr1c::e8_native_command("uart16550d").unwrap(),
            "cargo build --offline --locked --release --target x86_64-unknown-wyrmroot --package wyrmroot-uart16550d --bin uart16550d --no-default-features --features native-uart16550d"
        );
        assert_eq!(
            wyr1c::e8_native_features("recovery-trigger").unwrap(),
            "native-recovery-trigger"
        );
        assert_eq!(
            wyr1c::e8_native_features("stdout-pressure").unwrap(),
            "native-stdout-pressure"
        );
        assert!(
            wyr1c::e8_native_command("system-init")
                .unwrap()
                .ends_with("[env: WYRMROOT_WYR1E8_EVIDENCE_NONCE=<validated-16-hex>]")
        );
        assert_eq!(
            ACCEPTED_E6_REUSED_SHA256
                .iter()
                .map(|(label, _)| *label)
                .collect::<Vec<_>>(),
            ["registryd", "wyrmsh", "stack_report"]
        );
    }

    #[test]
    fn current_kernel_layout_is_preflighted_before_e8_output_and_build_effects() {
        let source = include_str!("wyr1e8.rs");
        let prepare = &source[source.find("pub(crate) fn prepare(").unwrap()
            ..source.find("pub(crate) fn inspect(").unwrap()];
        let abi_join = prepare.find("matching_abi_tree(").unwrap();
        let current_layout = prepare
            .find("deep_layout::prepare_current_kernel_source(")
            .unwrap();
        let current_capacities = prepare
            .find("deep_layout::read_wyr1e8_capacity_contract(")
            .unwrap();
        let output = prepare.find("validate_fresh_output(").unwrap();
        let staging = prepare.find("fs::create_dir(&staging)").unwrap();
        let native_build = prepare.find("build_produced(").unwrap();
        assert!(abi_join < current_layout);
        assert!(current_layout < current_capacities);
        assert!(current_capacities < output);
        assert!(output < staging);
        assert!(staging < native_build);

        let build = &source
            [source.find("fn build_produced(").unwrap()..source.find("fn fixed_fields(").unwrap()];
        assert!(!build.contains("deep_layout::prepare("));
        assert!(build.contains("layout: &crate::deep_layout::DeepLayoutBuild"));
        assert!(build.contains("capacity_contract: &crate::deep_layout::Wyr1E8CapacityContract"));
        assert!(build.contains("capacity_contract.verify_unchanged()?"));

        let inspect = &source[source.find("pub(crate) fn inspect(").unwrap()
            ..source.find("fn build_produced(").unwrap()];
        let read_capacities = inspect
            .find("deep_layout::read_wyr1e8_capacity_contract(")
            .unwrap();
        let validate_request = inspect
            .find("validate_request(&request, capacities)?")
            .unwrap();
        let frozen_metadata = inspect.find("validate_frozen_metadata(").unwrap();
        let source_receipt = inspect
            .find("let expected_source = source_receipt(")
            .unwrap();
        assert!(read_capacities < validate_request);
        assert!(validate_request < frozen_metadata);
        assert!(frozen_metadata < source_receipt);
    }

    #[test]
    fn scalar_parser_rejects_ambiguity_and_noncanonical_values() {
        assert!(parse("kind = \"one\"\nkind = \"two\"\n").is_err());
        assert!(parse("kind=\"one\"\n").is_err());
        assert!(parse("kind = bare\n").is_err());
        assert!(parse("kind = \"one\"\r\n").is_err());
        assert!(parse("kind = \"one\"").is_err());
    }

    #[test]
    fn actual_a1_request_reaches_git_tree_and_root_scalar_domains() {
        // Byte-exact source evidence SHA-256:
        // bb30ae7a6edb4d883c18e6da3af78391d0f23921d4b6e654051b7e8f0e138163.
        // Artifact digests are normalized here; lineage and failing field values are retained.
        let request = normalized_a1_request();
        assert_eq!(request.len(), 111);
        assert_eq!(
            field(&request, "generated_abi_tree").unwrap(),
            "a9b067107ec38e2be44630f4dce428dab0f48de8"
        );
        validate_request(&request, LOCKED_CAPACITIES).unwrap();

        let corrected = render(&request, &request_keys(), ScalarSchema::Request).unwrap();
        assert!(corrected.contains("com2_prelude_length = 354\n"));
        assert!(!corrected.contains("com2_prelude_length = \"354\"\n"));
        root_verifier_accepts_request(&corrected).unwrap();

        let failed_a1_scalar = corrected.replacen(
            "com2_prelude_length = 354\n",
            "com2_prelude_length = \"354\"\n",
            1,
        );
        assert_ne!(failed_a1_scalar, corrected);
        assert!(root_verifier_accepts_request(&failed_a1_scalar).is_err());

        let mut sha_sized_tree = request.clone();
        sha_sized_tree.insert("generated_abi_tree".into(), "ab".repeat(32));
        assert!(validate_request(&sha_sized_tree, LOCKED_CAPACITIES).is_err());

        let mut tree_sized_sha = request;
        tree_sized_sha.insert("esp_sha256".into(), "ab".repeat(20));
        assert!(validate_request(&tree_sized_sha, LOCKED_CAPACITIES).is_err());
    }
}
