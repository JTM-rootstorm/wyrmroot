//! WYR1-C6 selector-29 frozen-product and VM-handoff grammar.
//!
//! This module deliberately owns the *host* side of C6 only.  It freezes a
//! caller-built, feature-selected artifact set, makes the ESP deterministically,
//! and emits two immutable handoffs for the coordinator-owned VM.  It never
//! launches QEMU, talks to libvirt, or treats a serial line as evidence.  The
//! kernel collector is the sole authority for a `WRC6E1` terminal.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use crate::{cli::G3ImageArguments, error::Failure, g3_image, sha256, tasks};
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

/// Freeze an already built C6 artifact directory.
///
/// The build itself is intentionally an explicit preceding step: this makes
/// the selected compiler/features visible in the source receipt supplied with
/// the frozen artifacts, and avoids an xtask fallback to C3/C5 binaries.
pub(crate) fn freeze(
    output: &Path,
    artifacts: &Path,
    deep_revision: &str,
    abi_revision: &str,
    abi_tree: &str,
    nonce: &str,
    challenge: &str,
) -> Result<String, Failure> {
    reject_selector_environment()?;
    validate_revision(deep_revision, "Deepwyrm revision")?;
    validate_revision(abi_revision, "generated ABI revision")?;
    validate_revision(abi_tree, "generated ABI tree")?;
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
        output.join("default-handoff.toml").display(),
        output.join("smp-handoff.toml").display(),
    ))
}

pub(crate) fn inspect(path: &Path) -> Result<String, Failure> {
    let request = load(path)?;
    for (key, _, maximum) in ARTIFACTS {
        let relative = request.value(key)?;
        let bytes = read_regular_bounded(&request.root.join(relative), *maximum, key)?;
        if sha256::bytes_digest(&bytes) != request.value(&format!("{key}_sha256"))? {
            return Err(Failure::task(format!("WYR1-C6 {key} digest drifted")));
        }
    }
    let source_receipt = read_regular_bounded(
        &request.root.join(request.value("source_receipt")?),
        64 * 1024,
        "C6 source receipt",
    )?;
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
    )?;
    let esp = read_regular_bounded(
        &request.root.join(request.value("esp")?),
        g3_image::IMAGE_BYTES,
        "ESP",
    )?;
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
    g3_image::inspect(&args)?;
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
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
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
    if (bindings[10], values[10], auxiliaries[10]) != u2
        || (bindings[15], values[15], auxiliaries[15]) != u2
        || u2.0 == u1.0
        || u2.2 == u1.2
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

fn verify_source_receipt(
    bytes: &[u8],
    artifacts: &Path,
    deep_revision: &str,
    abi_revision: &str,
    abi_tree: &str,
    wyrmroot_revision: &str,
    rust_revision: &str,
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
        "devmgr_command".to_owned(),
        "uart16550d_command".to_owned(),
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
        ("rust_revision", rust_revision),
        ("bootstrap_features", "wyr1c6-production"),
        ("system_init_features", "wyr1c6-production"),
        ("devmgr_features", "wyr1c6-production,wyr1c6-selector29"),
        ("uart16550d_features", "wyr1c6-production,wyr1c6-selector29"),
        ("registryd_features", "native-registryd"),
        ("consoled_features", "native-retained"),
        ("wyrmsh_features", "native-retained"),
        ("bootstrap_command", "accepted-cargo native bootstrap"),
        ("system_init_command", "accepted-cargo native system-init"),
        ("devmgr_command", "accepted-cargo native devmgr"),
        ("uart16550d_command", "accepted-cargo native uart16550d"),
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
    for (key, _, _) in ARTIFACTS {
        validate_relative(value(&values, key)?, key)?;
        validate_lower_hex(value(&values, &format!("{key}_sha256"))?, 64, key)?;
    }
    validate_relative(value(&values, "esp")?, "ESP")?;
    validate_lower_hex(value(&values, "esp_sha256")?, 64, "ESP")?;
    validate_lower_hex(value(&values, "gate_config_sha256")?, 64, "bootfs gate")?;
    validate_relative(value(&values, "source_receipt")?, "source receipt")?;
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
    write_new(&vars_path, &vars, "profile OVMF variables")?;
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
    let text = String::from_utf8(read_regular_bounded(path, 64 * 1024, "VM handoff")?)
        .map_err(|_| Failure::task("WYR1-C6 VM handoff is not UTF-8"))?;
    let values = parse(&text)?;
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
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(Failure::task(format!(
            "WYR1-C6 {label} is not a bounded regular file"
        )));
    }
    fs::read(path).map_err(|error| Failure::task(format!("could not read {label}: {error}")))
}

fn write_new(path: &Path, bytes: &[u8], label: &str) -> Result<(), Failure> {
    if path.exists() {
        return Err(Failure::task(format!(
            "WYR1-C6 {label} output already exists"
        )));
    }
    fs::write(path, bytes)
        .map_err(|error| Failure::task(format!("could not write {label}: {error}")))
}

fn validate_relative(value: &str, label: &str) -> Result<(), Failure> {
    let path = Path::new(value);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(Failure::task(format!(
            "WYR1-C6 {label} path escapes the frozen root"
        )));
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
            .all(|byte| byte.is_ascii_digit() || byte.is_ascii_lowercase())
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
            .all(|byte| byte.is_ascii_digit() || byte.is_ascii_uppercase())
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
                    9 | 10 | 15 => (12, 102, 112),
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
        stream[4 * 113 + 32] = b'F';
        assert!(parse_evidence(&stream, nonce).is_err());
    }
}
