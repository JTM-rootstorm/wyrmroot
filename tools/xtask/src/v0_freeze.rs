//! Create-new V0 evidence binding for an already validated release candidate.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::error::Failure;
use crate::{h_integration, h_request, secure_fs, sha256};

const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_EVIDENCE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MATRIX_ENTRIES: u32 = 64;
const REQUEST_KEYS: &[&str] = &[
    "schema_version",
    "manifest_kind",
    "deepwyrm_revision",
    "wyrmroot_revision",
    "rust_revision",
    "candidate_request",
    "default_result",
    "i1_result",
    "i2_summary",
    "geometry_report",
    "geometry_report_sha256",
    "qemu_argument_report",
    "qemu_argument_report_sha256",
    "version_report",
    "version_report_sha256",
    "host_matrix",
    "manifest",
];

#[derive(Debug)]
struct FreezeRequest {
    root: PathBuf,
    secure_root: secure_fs::Root,
    deepwyrm_revision: String,
    wyrmroot_revision: String,
    rust_revision: String,
    candidate_request: PathBuf,
    default_result: PathBuf,
    i1_result: PathBuf,
    i2_summary: PathBuf,
    geometry_report: PathBuf,
    geometry_report_sha256: String,
    qemu_argument_report: PathBuf,
    qemu_argument_report_sha256: String,
    version_report: PathBuf,
    version_report_sha256: String,
    host_matrix: PathBuf,
    manifest: PathBuf,
}

#[derive(Debug)]
struct MatrixEntry {
    name: String,
    sha256: String,
}

pub(crate) fn freeze(request_path: &str) -> Result<String, Failure> {
    let request = load_request(Path::new(request_path))?;
    let candidate = h_request::load(&request.candidate_request)?;
    if candidate.schema_version != 4 {
        return Err(Failure::task(
            "V0 candidate_request must use the I2 schema_version = 4 contract",
        ));
    }
    if request.deepwyrm_revision != candidate.deepwyrm_revision
        || request.wyrmroot_revision != candidate.wyrmroot_revision
        || request.rust_revision != candidate.rust_revision
    {
        return Err(Failure::task(
            "V0 revisions do not exactly match the candidate request",
        ));
    }
    let stress = candidate
        .stress
        .as_ref()
        .ok_or_else(|| Failure::task("V0 candidate request lacks the I2 stress contract"))?;
    if request.manifest != stress.v0_manifest {
        return Err(Failure::task(
            "V0 manifest output does not match the schema-v4 candidate request",
        ));
    }
    let expected_summary = candidate.run_directory.join("i2/summary.json");
    if request.i2_summary != expected_summary {
        return Err(Failure::task(
            "V0 i2_summary is not the candidate's fixed runs/i2/summary.json",
        ));
    }

    let default_bytes = read_regular(&request, &request.default_result, "default evidence")?;
    validate_result(&default_bytes, 2, "WYR0-H", &request, "default evidence")?;
    let i1_bytes = read_regular(&request, &request.i1_result, "I1 evidence")?;
    validate_result(&i1_bytes, 3, "WYR0-H", &request, "I1 evidence")?;
    require_json_scalar(&i1_bytes, "observed_evidence_mask", "255", "I1 evidence")?;
    require_json_scalar(&i1_bytes, "evidence_protocol", "dwevid1", "I1 evidence")?;
    let i2_bytes = read_regular(&request, &request.i2_summary, "I2 summary")?;
    validate_result(&i2_bytes, 4, "WYR0-H-I2", &request, "I2 summary")?;
    require_json_scalar(&i2_bytes, "kind", "stress-summary", "I2 summary")?;
    require_json_scalar(
        &i2_bytes,
        "requested_runs",
        &stress.run_count.to_string(),
        "I2 summary",
    )?;
    require_json_scalar(
        &i2_bytes,
        "completed_runs",
        &stress.run_count.to_string(),
        "I2 summary",
    )?;
    require_json_scalar(&i2_bytes, "failing_run_index", "null", "I2 summary")?;
    require_json_scalar(&i2_bytes, "candidate_revalidated", "true", "I2 summary")?;
    cross_bind_candidate_artifacts(&default_bytes, &i1_bytes, &i2_bytes)?;

    let geometry = checked_expected_digest(
        &request,
        &request.geometry_report,
        &request.geometry_report_sha256,
        "geometry report",
    )?;
    let qemu_arguments = checked_expected_digest(
        &request,
        &request.qemu_argument_report,
        &request.qemu_argument_report_sha256,
        "QEMU argument-shape report",
    )?;
    let version = checked_expected_digest(
        &request,
        &request.version_report,
        &request.version_report_sha256,
        "version report",
    )?;
    let matrix = load_matrix(&request)?;
    if matrix.is_empty() {
        return Err(Failure::task(
            "V0 host matrix must contain at least one coordinator-supplied entry",
        ));
    }
    let candidate_fields = h_integration::freeze_candidate_fields(&request.candidate_request)?;
    let run_fields = validate_i2_results(&request, &candidate, &i2_bytes)?;
    let matrix_manifest = file_digest(&request, &request.host_matrix, "V0 host matrix")?;

    let mut matrix_fields = String::new();
    for (index, entry) in matrix.iter().enumerate() {
        matrix_fields.push_str(&format!(
            "host_matrix_{index:03}_name = \"{}\"\nhost_matrix_{index:03}_sha256 = \"{}\"\n",
            entry.name, entry.sha256
        ));
    }
    let manifest = format!(
        concat!(
            "schema_version = 1\n",
            "manifest_kind = \"wyr0-v0-evidence-freeze\"\n",
            "validation_status = \"BOUND_EVIDENCE_COMPLETE\"\n",
            "v0_pass = true\n",
            "independent_guest_execution = false\n",
            "deepwyrm_revision = \"{}\"\n",
            "wyrmroot_revision = \"{}\"\n",
            "rust_revision = \"{}\"\n",
            "default_result_schema = 2\n",
            "i1_result_schema = 3\n",
            "i2_result_schema = 4\n",
            "freeze_manifest_schema = 1\n",
            "default_result_sha256 = \"{}\"\n",
            "i1_result_sha256 = \"{}\"\n",
            "i2_summary_sha256 = \"{}\"\n",
            "geometry_report_sha256 = \"{}\"\n",
            "qemu_argument_report_sha256 = \"{}\"\n",
            "version_report_sha256 = \"{}\"\n",
            "host_matrix_manifest_sha256 = \"{}\"\n",
            "stress_schedule_version = \"{}\"\n",
            "stress_base_seed = \"{:016X}\"\n",
            "stress_run_count = {}\n",
            "stress_operations_per_run = {}\n",
            "host_matrix_entry_count = {}\n",
            "{}{}{}"
        ),
        request.deepwyrm_revision,
        request.wyrmroot_revision,
        request.rust_revision,
        sha256::bytes_digest(&default_bytes),
        sha256::bytes_digest(&i1_bytes),
        sha256::bytes_digest(&i2_bytes),
        geometry,
        qemu_arguments,
        version,
        matrix_manifest,
        stress.schedule_version,
        stress.base_seed,
        stress.run_count,
        stress.operations_per_run,
        matrix.len(),
        candidate_fields,
        run_fields,
        matrix_fields,
    );
    write_new(
        &request,
        &request.manifest,
        manifest.as_bytes(),
        "V0 manifest",
    )?;
    Ok(format!(
        "{{\"schema_version\":1,\"phase\":\"V0\",\"status\":\"BOUND_EVIDENCE_COMPLETE\",\"v0_pass\":true,\"manifest_sha256\":\"{}\"}}\n",
        sha256::bytes_digest(manifest.as_bytes())
    ))
}

fn cross_bind_candidate_artifacts(default: &[u8], i1: &[u8], i2: &[u8]) -> Result<(), Failure> {
    let default = parse_json_object(default, "default evidence")?;
    let i1 = parse_json_object(i1, "I1 evidence")?;
    let i2 = parse_json_object(i2, "I2 summary")?;
    for key in [
        "loader_sha256",
        "kernel_sha256",
        "symbols_sha256",
        "bootstrap_sha256",
        "init0_sha256",
        "hello_sha256",
        "bootfs_sha256",
        "esp_sha256",
        "ovmf_code_sha256",
        "ovmf_vars_template_sha256",
    ] {
        let expected = i2
            .get(key)
            .ok_or_else(|| Failure::task(format!("I2 summary lacks '{key}'")))?;
        if default.get(key) != Some(expected) || i1.get(key) != Some(expected) {
            return Err(Failure::task(format!(
                "default/I1/I2 evidence disagree on admitted candidate binding '{key}'"
            )));
        }
    }
    Ok(())
}

fn load_request(path: &Path) -> Result<FreezeRequest, Failure> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let root = fs::canonicalize(parent)
        .map_err(|error| Failure::task(format!("could not resolve V0 request root: {error}")))?;
    let secure_root = secure_fs::Root::open(&root, "V0 request root")?;
    let name = path
        .file_name()
        .ok_or_else(|| Failure::task("V0 request has no file name"))?;
    let path = root.join(name);
    let request_bytes = secure_root.read(&path, "V0 request", MAX_REQUEST_BYTES, false)?;
    let text = std::str::from_utf8(&request_bytes)
        .map_err(|_| Failure::task("V0 request is not UTF-8"))?;
    let values = parse_flat(text, "V0 request")?;
    exact_keys(&values, REQUEST_KEYS, "V0 request")?;
    if required(&values, "schema_version", "V0 request")? != "1"
        || required(&values, "manifest_kind", "V0 request")? != "wyr0-v0-freeze-request"
    {
        return Err(Failure::task("V0 request schema identity is invalid"));
    }
    let manifest = output_path(&root, required(&values, "manifest", "V0 request")?)?;
    let request = FreezeRequest {
        root: root.clone(),
        secure_root,
        deepwyrm_revision: revision(&values, "deepwyrm_revision", "V0 request")?,
        wyrmroot_revision: revision(&values, "wyrmroot_revision", "V0 request")?,
        rust_revision: revision(&values, "rust_revision", "V0 request")?,
        candidate_request: input_path(&root, &values, "candidate_request", "V0 request")?,
        default_result: input_path(&root, &values, "default_result", "V0 request")?,
        i1_result: input_path(&root, &values, "i1_result", "V0 request")?,
        i2_summary: input_path(&root, &values, "i2_summary", "V0 request")?,
        geometry_report: input_path(&root, &values, "geometry_report", "V0 request")?,
        geometry_report_sha256: sha256_value(&values, "geometry_report_sha256", "V0 request")?,
        qemu_argument_report: input_path(&root, &values, "qemu_argument_report", "V0 request")?,
        qemu_argument_report_sha256: sha256_value(
            &values,
            "qemu_argument_report_sha256",
            "V0 request",
        )?,
        version_report: input_path(&root, &values, "version_report", "V0 request")?,
        version_report_sha256: sha256_value(&values, "version_report_sha256", "V0 request")?,
        host_matrix: input_path(&root, &values, "host_matrix", "V0 request")?,
        manifest,
    };
    for path in [
        &request.candidate_request,
        &request.default_result,
        &request.i1_result,
        &request.i2_summary,
        &request.geometry_report,
        &request.qemu_argument_report,
        &request.version_report,
        &request.host_matrix,
    ] {
        validate_relative_contained(&request, path, true)?;
    }
    validate_relative_contained(&request, &request.manifest, false)?;
    if request
        .secure_root
        .exists(&request.manifest, "V0 manifest")?
    {
        return Err(Failure::task("V0 manifest output already exists"));
    }
    for input in [
        &request.candidate_request,
        &request.default_result,
        &request.i1_result,
        &request.i2_summary,
        &request.geometry_report,
        &request.qemu_argument_report,
        &request.version_report,
        &request.host_matrix,
    ] {
        if request.manifest == *input
            || request.manifest.starts_with(input)
            || input.starts_with(&request.manifest)
        {
            return Err(Failure::task(
                "V0 manifest aliases or overlaps a freeze input",
            ));
        }
    }
    Ok(request)
}

fn load_matrix(request: &FreezeRequest) -> Result<Vec<MatrixEntry>, Failure> {
    let bytes = read_regular(request, &request.host_matrix, "V0 host matrix")?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| Failure::task("V0 host matrix is not UTF-8"))?;
    let values = parse_flat(text, "V0 host matrix")?;
    let count = required(&values, "entry_count", "V0 host matrix")?
        .parse::<u32>()
        .map_err(|_| Failure::task("V0 host matrix entry_count is not an integer"))?;
    if count == 0 || count > MAX_MATRIX_ENTRIES {
        return Err(Failure::task(
            "V0 host matrix entry_count must be between 1 and 64",
        ));
    }
    let mut expected = BTreeSet::from([
        "schema_version".to_owned(),
        "manifest_kind".to_owned(),
        "entry_count".to_owned(),
    ]);
    for index in 0..count {
        for suffix in ["name", "status", "evidence", "sha256"] {
            expected.insert(format!("entry_{index:03}_{suffix}"));
        }
    }
    if values.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return Err(Failure::task("V0 host matrix key set drifted"));
    }
    if required(&values, "schema_version", "V0 host matrix")? != "1"
        || required(&values, "manifest_kind", "V0 host matrix")? != "wyr0-v0-host-matrix"
    {
        return Err(Failure::task("V0 host matrix schema identity is invalid"));
    }
    let mut names = BTreeSet::new();
    let mut entries = Vec::new();
    for index in 0..count {
        let name = required(&values, &format!("entry_{index:03}_name"), "V0 host matrix")?;
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || !names.insert(name.to_owned())
        {
            return Err(Failure::task(
                "V0 host matrix entry names must be unique bounded lowercase identifiers",
            ));
        }
        if required(
            &values,
            &format!("entry_{index:03}_status"),
            "V0 host matrix",
        )? != "pass"
        {
            return Err(Failure::task("V0 host matrix contains a non-passing entry"));
        }
        let evidence = relative_path(
            &request.root,
            required(
                &values,
                &format!("entry_{index:03}_evidence"),
                "V0 host matrix",
            )?,
        )?;
        validate_relative_contained(request, &evidence, true)?;
        let expected_digest = sha256_value(
            &values,
            &format!("entry_{index:03}_sha256"),
            "V0 host matrix",
        )?;
        let actual_digest = file_digest(request, &evidence, "V0 host-matrix evidence")?;
        if actual_digest != expected_digest {
            return Err(Failure::task("V0 host-matrix evidence digest mismatch"));
        }
        entries.push(MatrixEntry {
            name: name.to_owned(),
            sha256: actual_digest,
        });
    }
    Ok(entries)
}

fn validate_i2_results(
    request: &FreezeRequest,
    candidate: &h_request::HRequest,
    summary: &[u8],
) -> Result<String, Failure> {
    let stress = candidate.stress.as_ref().expect("checked by caller");
    let mut fields = String::new();
    let mut ordered = Vec::new();
    for index in 0..stress.run_count {
        let seed = splitmix64_seed(stress.base_seed, index);
        let result = candidate
            .run_directory
            .join(format!("i2/run-{index:06}/result.json"));
        validate_relative_contained(request, &result, true)?;
        let bytes = read_regular(request, &result, "I2 run result")?;
        validate_result(&bytes, 4, "WYR0-H-I2", request, "I2 run result")?;
        cross_bind_i2_run(summary, &bytes)?;
        require_json_scalar(&bytes, "run_index", &index.to_string(), "I2 run result")?;
        require_json_scalar(
            &bytes,
            "stress_seed",
            &format!("{seed:016X}"),
            "I2 run result",
        )?;
        require_json_scalar(
            &bytes,
            "configured_operations",
            &stress.operations_per_run.to_string(),
            "I2 run result",
        )?;
        require_json_scalar(
            &bytes,
            "completed_operations",
            &stress.operations_per_run.to_string(),
            "I2 run result",
        )?;
        require_json_scalar(&bytes, "cpu_mask", "15", "I2 run result")?;
        require_json_scalar(&bytes, "family_mask", "511", "I2 run result")?;
        require_json_scalar(&bytes, "candidate_revalidated", "true", "I2 run result")?;
        let digest = sha256::bytes_digest(&bytes);
        ordered.push((index, format!("{seed:016X}"), digest.clone()));
        fields.push_str(&format!(
            "i2_run_{index:03}_seed = \"{seed:016X}\"\ni2_run_{index:03}_result_sha256 = \"{digest}\"\n"
        ));
    }
    validate_ordered_results(summary, &ordered)?;
    Ok(fields)
}

fn cross_bind_i2_run(summary: &[u8], run: &[u8]) -> Result<(), Failure> {
    let summary = parse_json_object(summary, "I2 summary")?;
    let run = parse_json_object(run, "I2 run result")?;
    for key in [
        "selector",
        "test_id",
        "stress_schedule_version",
        "stress_base_seed",
        "candidate_sha256",
        "provenance_sha256",
        "request_sha256",
        "loader_sha256",
        "kernel_sha256",
        "symbols_sha256",
        "bootstrap_sha256",
        "init0_sha256",
        "hello_sha256",
        "bootfs_sha256",
        "esp_sha256",
        "ovmf_code_sha256",
        "ovmf_vars_template_sha256",
        "deepwyrm_revision",
        "wyrmroot_revision",
        "rust_revision",
    ] {
        if run.get(key) != summary.get(key) {
            return Err(Failure::task(format!(
                "I2 run result disagrees with its summary on '{key}'"
            )));
        }
    }
    Ok(())
}

fn validate_ordered_results(
    summary: &[u8],
    expected: &[(u32, String, String)],
) -> Result<(), Failure> {
    let object = parse_json_document_object(summary, "I2 summary")?;
    let JsonValue::Array(results) = object
        .get("ordered_results")
        .ok_or_else(|| Failure::task("I2 summary lacks ordered_results"))?
    else {
        return Err(Failure::task("I2 summary ordered_results is not an array"));
    };
    if results.len() != expected.len() {
        return Err(Failure::task("I2 summary ordered_results length drifted"));
    }
    for (position, (value, (index, seed, digest))) in
        results.iter().zip(expected.iter()).enumerate()
    {
        let JsonValue::Object(entry) = value else {
            return Err(Failure::task(format!(
                "I2 summary ordered_results[{position}] is not an object"
            )));
        };
        if entry.keys().cloned().collect::<BTreeSet<_>>()
            != key_set(&["run_index", "seed", "result_sha256", "status"])
        {
            return Err(Failure::task(format!(
                "I2 summary ordered_results[{position}] key set drifted"
            )));
        }
        for (key, expected) in [
            ("run_index", index.to_string()),
            ("seed", seed.clone()),
            ("result_sha256", digest.clone()),
            ("status", "PASS".to_owned()),
        ] {
            if entry.get(key).and_then(JsonValue::scalar).as_deref() != Some(expected.as_str()) {
                return Err(Failure::task(format!(
                    "I2 summary ordered_results[{position}] has invalid '{key}'"
                )));
            }
        }
    }
    Ok(())
}

fn validate_result(
    bytes: &[u8],
    schema: u32,
    phase: &str,
    request: &FreezeRequest,
    label: &str,
) -> Result<(), Failure> {
    let values = parse_json_object(bytes, label)?;
    let expected_keys = match (schema, phase, values.get("kind").map(String::as_str)) {
        (2, "WYR0-H", None) => default_result_keys(false),
        (3, "WYR0-H", None) => default_result_keys(true),
        (4, "WYR0-H-I2", Some("stress-summary")) => i2_summary_keys(),
        (4, "WYR0-H-I2", None) => i2_run_keys(),
        _ => {
            return Err(Failure::task(format!(
                "{label} has an unsupported JSON schema kind"
            )));
        }
    };
    let actual = values.keys().cloned().collect::<BTreeSet<_>>();
    if actual != expected_keys {
        return Err(Failure::task(format!(
            "{label} JSON key set drifted (unknown or missing fields)"
        )));
    }
    for (key, expected) in [
        ("schema_version", schema.to_string()),
        ("phase", phase.to_owned()),
        ("status", "PASS".to_owned()),
        ("deepwyrm_revision", request.deepwyrm_revision.clone()),
        ("wyrmroot_revision", request.wyrmroot_revision.clone()),
        ("rust_revision", request.rust_revision.clone()),
    ] {
        if values.get(key) != Some(&expected) {
            return Err(Failure::task(format!(
                "{label} has an invalid or missing '{key}' binding"
            )));
        }
    }
    for (key, value) in &values {
        if key.ends_with("_sha256") && !is_sha256(value) {
            return Err(Failure::task(format!(
                "{label} has an invalid '{key}' digest"
            )));
        }
    }
    match schema {
        2 => {
            require_map_scalar(&values, "profile", "default", label)?;
            require_map_scalar(&values, "selector", "primordial-bootstrap", label)?;
            require_map_scalar(&values, "test_id", "18", label)?;
            require_map_scalar(&values, "actual_outcome", "pass", label)?;
            require_map_scalar(&values, "detail", "0", label)?;
        }
        3 => {
            require_map_scalar(&values, "profile", "smp", label)?;
            require_map_scalar(&values, "selector", h_request::I1_SELECTOR, label)?;
            require_map_scalar(
                &values,
                "test_id",
                &h_request::I1_TEST_ID.to_string(),
                label,
            )?;
            require_map_scalar(&values, "actual_outcome", "pass", label)?;
            require_map_scalar(&values, "detail", "0", label)?;
        }
        4 if !values.contains_key("kind") => {
            require_map_scalar(&values, "profile", "smp", label)?;
            require_map_scalar(&values, "selector", h_request::I2_SELECTOR, label)?;
            require_map_scalar(
                &values,
                "test_id",
                &h_request::I2_TEST_ID.to_string(),
                label,
            )?;
            require_map_scalar(&values, "actual_outcome", "pass", label)?;
            require_map_scalar(&values, "detail", "0", label)?;
            require_map_scalar(&values, "failing_operation", &u32::MAX.to_string(), label)?;
            require_map_scalar(&values, "stage", "0", label)?;
        }
        4 => {
            require_map_scalar(&values, "selector", h_request::I2_SELECTOR, label)?;
            require_map_scalar(
                &values,
                "test_id",
                &h_request::I2_TEST_ID.to_string(),
                label,
            )?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn require_map_scalar(
    values: &BTreeMap<String, String>,
    key: &str,
    expected: &str,
    label: &str,
) -> Result<(), Failure> {
    if values.get(key).map(String::as_str) != Some(expected) {
        return Err(Failure::task(format!(
            "{label} has an invalid or missing '{key}' binding"
        )));
    }
    Ok(())
}

fn key_set(keys: &[&str]) -> BTreeSet<String> {
    keys.iter().map(|key| (*key).to_owned()).collect()
}

fn default_result_keys(i1: bool) -> BTreeSet<String> {
    let mut keys = key_set(&[
        "schema_version",
        "phase",
        "mode",
        "profile",
        "selector",
        "status",
        "vcpu",
        "memory_mib",
        "test_id",
        "expected_outcome",
        "expected_detail",
        "actual_outcome",
        "detail",
        "serial_line",
        "qemu_exit_status",
        "candidate_sha256",
        "provenance_sha256",
        "request_sha256",
        "loader_sha256",
        "kernel_sha256",
        "symbols_sha256",
        "bootstrap_sha256",
        "init0_sha256",
        "hello_sha256",
        "bootfs_sha256",
        "esp_sha256",
        "ovmf_code_sha256",
        "ovmf_vars_template_sha256",
        "serial_sha256",
        "qemu_stderr_sha256",
        "ovmf_vars_sha256",
        "deepwyrm_revision",
        "wyrmroot_revision",
        "rust_revision",
        "no_host_share",
    ]);
    if i1 {
        keys.extend(key_set(&[
            "evidence_protocol",
            "evidence_nonce",
            "required_evidence_mask",
            "observed_evidence_mask",
            "evidence_event_count",
            "first_evidence_sequence",
            "last_evidence_sequence",
        ]));
    }
    keys
}

fn i2_run_keys() -> BTreeSet<String> {
    key_set(&[
        "schema_version",
        "phase",
        "status",
        "profile",
        "selector",
        "test_id",
        "run_index",
        "stress_schedule_version",
        "stress_base_seed",
        "stress_seed",
        "configured_operations",
        "completed_operations",
        "cpu_mask",
        "family_mask",
        "actual_outcome",
        "detail",
        "failing_operation",
        "stage",
        "stress_serial_line",
        "terminal_serial_line",
        "qemu_exit_status",
        "serial_sha256",
        "qemu_stderr_sha256",
        "ovmf_vars_sha256",
        "candidate_sha256",
        "provenance_sha256",
        "request_sha256",
        "loader_sha256",
        "kernel_sha256",
        "symbols_sha256",
        "bootstrap_sha256",
        "init0_sha256",
        "hello_sha256",
        "bootfs_sha256",
        "esp_sha256",
        "ovmf_code_sha256",
        "ovmf_vars_template_sha256",
        "deepwyrm_revision",
        "wyrmroot_revision",
        "rust_revision",
        "candidate_revalidated",
        "no_host_share",
    ])
}

fn i2_summary_keys() -> BTreeSet<String> {
    key_set(&[
        "schema_version",
        "phase",
        "kind",
        "status",
        "selector",
        "test_id",
        "stress_schedule_version",
        "stress_base_seed",
        "requested_runs",
        "completed_runs",
        "failing_run_index",
        "operations_per_run",
        "reason",
        "ordered_results",
        "candidate_sha256",
        "provenance_sha256",
        "request_sha256",
        "loader_sha256",
        "kernel_sha256",
        "symbols_sha256",
        "bootstrap_sha256",
        "init0_sha256",
        "hello_sha256",
        "bootfs_sha256",
        "esp_sha256",
        "ovmf_code_sha256",
        "ovmf_vars_template_sha256",
        "deepwyrm_revision",
        "wyrmroot_revision",
        "rust_revision",
        "candidate_revalidated",
    ])
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn require_json_scalar(
    bytes: &[u8],
    key: &str,
    expected: &str,
    label: &str,
) -> Result<(), Failure> {
    let values = parse_json_object(bytes, label)?;
    if values.get(key).map(String::as_str) != Some(expected) {
        return Err(Failure::task(format!(
            "{label} has an invalid or missing '{key}' binding"
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum JsonValue {
    String(String),
    Number(String),
    Bool(bool),
    Null,
    Object(BTreeMap<String, JsonValue>),
    Array(Vec<JsonValue>),
}

fn parse_json_document_object(
    bytes: &[u8],
    label: &str,
) -> Result<BTreeMap<String, JsonValue>, Failure> {
    std::str::from_utf8(bytes)
        .map_err(|_| Failure::task(format!("{label} is not UTF-8 JSON evidence")))?;
    let (value, index) = parse_json_value(bytes, skip_json_whitespace(bytes, 0), label)?;
    if skip_json_whitespace(bytes, index) != bytes.len() {
        return Err(Failure::task(format!("{label} has trailing JSON data")));
    }
    let JsonValue::Object(object) = value else {
        return Err(Failure::task(format!("{label} is not a JSON object")));
    };
    Ok(object)
}

impl JsonValue {
    fn scalar(&self) -> Option<String> {
        match self {
            Self::String(value) | Self::Number(value) => Some(value.clone()),
            Self::Bool(value) => Some(value.to_string()),
            Self::Null => Some("null".to_owned()),
            Self::Object(_) | Self::Array(_) => None,
        }
    }
}

fn parse_json_object(bytes: &[u8], label: &str) -> Result<BTreeMap<String, String>, Failure> {
    std::str::from_utf8(bytes)
        .map_err(|_| Failure::task(format!("{label} is not UTF-8 JSON evidence")))?;
    let (value, index) = parse_json_value(bytes, skip_json_whitespace(bytes, 0), label)?;
    if skip_json_whitespace(bytes, index) != bytes.len() {
        return Err(Failure::task(format!(
            "{label} has trailing data after its JSON object"
        )));
    }
    let JsonValue::Object(object) = value else {
        return Err(Failure::task(format!("{label} is not a JSON object")));
    };
    Ok(object
        .into_iter()
        .map(|(key, value)| {
            let scalar = value.scalar().unwrap_or_else(|| "<compound>".to_owned());
            (key, scalar)
        })
        .collect())
}

fn parse_json_string(bytes: &[u8], start: usize, label: &str) -> Result<(String, usize), Failure> {
    if bytes.get(start) != Some(&b'"') {
        return Err(Failure::task(format!("{label} JSON expected a string")));
    }
    let mut index = start + 1;
    while let Some(byte) = bytes.get(index).copied() {
        match byte {
            b'"' => {
                let value = std::str::from_utf8(&bytes[start + 1..index])
                    .map_err(|_| Failure::task(format!("{label} JSON string is not UTF-8")))?;
                return Ok((value.to_owned(), index + 1));
            }
            b'\\' | 0..=0x1F => {
                return Err(Failure::task(format!(
                    "{label} JSON strings must be unescaped and free of controls"
                )));
            }
            _ => index += 1,
        }
    }
    Err(Failure::task(format!(
        "{label} JSON contains an unterminated string"
    )))
}

fn parse_json_value(
    bytes: &[u8],
    start: usize,
    label: &str,
) -> Result<(JsonValue, usize), Failure> {
    match bytes.get(start).copied() {
        Some(b'"') => {
            let (value, next) = parse_json_string(bytes, start, label)?;
            Ok((JsonValue::String(value), next))
        }
        Some(b'0'..=b'9') => {
            let mut end = start;
            while bytes.get(end).is_some_and(u8::is_ascii_digit) {
                end += 1;
            }
            let value = std::str::from_utf8(&bytes[start..end])
                .expect("ASCII decimal JSON value")
                .to_owned();
            if value.len() > 1 && value.starts_with('0') {
                return Err(Failure::task(format!(
                    "{label} JSON number has a leading zero"
                )));
            }
            Ok((JsonValue::Number(value), end))
        }
        Some(b't') if bytes.get(start..start + 4) == Some(b"true") => {
            Ok((JsonValue::Bool(true), start + 4))
        }
        Some(b'f') if bytes.get(start..start + 5) == Some(b"false") => {
            Ok((JsonValue::Bool(false), start + 5))
        }
        Some(b'n') if bytes.get(start..start + 4) == Some(b"null") => {
            Ok((JsonValue::Null, start + 4))
        }
        Some(b'{') => parse_json_map(bytes, start, label),
        Some(b'[') => parse_json_array(bytes, start, label),
        _ => Err(Failure::task(format!(
            "{label} JSON contains an unsupported value"
        ))),
    }
}

fn parse_json_map(bytes: &[u8], start: usize, label: &str) -> Result<(JsonValue, usize), Failure> {
    let mut index = start + 1;
    let mut values = BTreeMap::new();
    loop {
        index = skip_json_whitespace(bytes, index);
        if bytes.get(index) == Some(&b'}') {
            return Ok((JsonValue::Object(values), index + 1));
        }
        let (key, next) = parse_json_string(bytes, index, label)?;
        index = skip_json_whitespace(bytes, next);
        if bytes.get(index) != Some(&b':') {
            return Err(Failure::task(format!("{label} JSON key lacks ':'")));
        }
        let (value, next) = parse_json_value(bytes, skip_json_whitespace(bytes, index + 1), label)?;
        if values.insert(key.clone(), value).is_some() {
            return Err(Failure::task(format!(
                "{label} JSON repeats object key '{key}'"
            )));
        }
        index = skip_json_whitespace(bytes, next);
        match bytes.get(index) {
            Some(b',') => index += 1,
            Some(b'}') => return Ok((JsonValue::Object(values), index + 1)),
            _ => {
                return Err(Failure::task(format!(
                    "{label} JSON object has invalid framing"
                )));
            }
        }
    }
}

fn parse_json_array(
    bytes: &[u8],
    start: usize,
    label: &str,
) -> Result<(JsonValue, usize), Failure> {
    let mut index = start + 1;
    let mut values = Vec::new();
    loop {
        index = skip_json_whitespace(bytes, index);
        if bytes.get(index) == Some(&b']') {
            return Ok((JsonValue::Array(values), index + 1));
        }
        let (value, next) = parse_json_value(bytes, index, label)?;
        values.push(value);
        index = skip_json_whitespace(bytes, next);
        match bytes.get(index) {
            Some(b',') => index += 1,
            Some(b']') => return Ok((JsonValue::Array(values), index + 1)),
            _ => {
                return Err(Failure::task(format!(
                    "{label} JSON array has invalid framing"
                )));
            }
        }
    }
}

fn skip_json_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while bytes
        .get(index)
        .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
    {
        index += 1;
    }
    index
}

fn checked_expected_digest(
    request: &FreezeRequest,
    path: &Path,
    expected: &str,
    label: &str,
) -> Result<String, Failure> {
    let actual = sha256::bytes_digest(&read_regular(request, path, label)?);
    if actual != expected {
        return Err(Failure::task(format!(
            "{label} digest does not match the request"
        )));
    }
    Ok(actual)
}

fn parse_flat(text: &str, label: &str) -> Result<BTreeMap<String, String>, Failure> {
    let mut values = BTreeMap::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            return Err(Failure::task(format!(
                "{label} line {} uses an unsupported section",
                index + 1
            )));
        }
        let (key, raw_value) = line.split_once('=').ok_or_else(|| {
            Failure::task(format!(
                "{label} line {} is not a scalar assignment",
                index + 1
            ))
        })?;
        let key = key.trim();
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(Failure::task(format!(
                "{label} line {} has an invalid key",
                index + 1
            )));
        }
        let raw_value = raw_value.trim();
        let value = if let Some(quoted) = raw_value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
        {
            if quoted.contains(['"', '\\']) || quoted.chars().any(char::is_control) {
                return Err(Failure::task(format!(
                    "{label} line {} has an unsupported quoted value",
                    index + 1
                )));
            }
            quoted.to_owned()
        } else if !raw_value.is_empty() && raw_value.bytes().all(|byte| byte.is_ascii_digit()) {
            raw_value.to_owned()
        } else {
            return Err(Failure::task(format!(
                "{label} line {} has an invalid value",
                index + 1
            )));
        };
        if values.insert(key.to_owned(), value).is_some() {
            return Err(Failure::task(format!("{label} repeats key '{key}'")));
        }
    }
    Ok(values)
}

fn exact_keys(
    values: &BTreeMap<String, String>,
    expected: &[&str],
    label: &str,
) -> Result<(), Failure> {
    let expected = expected
        .iter()
        .map(|key| (*key).to_owned())
        .collect::<BTreeSet<_>>();
    let actual = values.keys().cloned().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(Failure::task(format!("{label} key set drifted")));
    }
    Ok(())
}

fn required<'a>(
    values: &'a BTreeMap<String, String>,
    key: &str,
    label: &str,
) -> Result<&'a str, Failure> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| Failure::task(format!("{label} is missing '{key}'")))
}

fn revision(values: &BTreeMap<String, String>, key: &str, label: &str) -> Result<String, Failure> {
    let value = required(values, key, label)?;
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Failure::task(format!(
            "{label} '{key}' must be a full lowercase Git revision"
        )));
    }
    Ok(value.to_owned())
}

fn sha256_value(
    values: &BTreeMap<String, String>,
    key: &str,
    label: &str,
) -> Result<String, Failure> {
    let value = required(values, key, label)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Failure::task(format!(
            "{label} '{key}' must be a lowercase SHA-256"
        )));
    }
    Ok(value.to_owned())
}

fn input_path(
    root: &Path,
    values: &BTreeMap<String, String>,
    key: &str,
    label: &str,
) -> Result<PathBuf, Failure> {
    relative_path(root, required(values, key, label)?)
}

fn relative_path(root: &Path, value: &str) -> Result<PathBuf, Failure> {
    let relative = Path::new(value);
    if relative.is_absolute()
        || relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Failure::task(
            "V0 paths must be nonempty request-relative normal paths",
        ));
    }
    Ok(root.join(relative))
}

fn output_path(root: &Path, value: &str) -> Result<PathBuf, Failure> {
    relative_path(root, value)
}

fn validate_relative_contained(
    request: &FreezeRequest,
    path: &Path,
    must_exist: bool,
) -> Result<(), Failure> {
    request.secure_root.relative(path, "V0 path")?;
    if must_exist {
        let _ = request
            .secure_root
            .read(path, "V0 input", MAX_EVIDENCE_BYTES, false)?;
    } else {
        request.secure_root.validate_parent(path, "V0 output")?;
    }
    Ok(())
}

fn read_regular(request: &FreezeRequest, path: &Path, label: &str) -> Result<Vec<u8>, Failure> {
    request
        .secure_root
        .read(path, label, MAX_EVIDENCE_BYTES, false)
}

fn file_digest(request: &FreezeRequest, path: &Path, label: &str) -> Result<String, Failure> {
    Ok(sha256::bytes_digest(&read_regular(request, path, label)?))
}

fn write_new(
    request: &FreezeRequest,
    path: &Path,
    bytes: &[u8],
    label: &str,
) -> Result<(), Failure> {
    request.secure_root.write_new(path, bytes, label)
}

fn splitmix64_seed(base_seed: u64, run_index: u32) -> u64 {
    const GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut value = base_seed.wrapping_add(GAMMA.wrapping_mul(u64::from(run_index) + 1));
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    let mixed = value ^ (value >> 31);
    if mixed == 0 { GAMMA } else { mixed }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root(label: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!(
                "xtask-v0-{label}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system clock before epoch")
                    .as_nanos()
            ))
    }

    fn valid_request_text() -> String {
        format!(
            concat!(
                "schema_version = 1\n",
                "manifest_kind = \"wyr0-v0-freeze-request\"\n",
                "deepwyrm_revision = \"{}\"\n",
                "wyrmroot_revision = \"{}\"\n",
                "rust_revision = \"{}\"\n",
                "candidate_request = \"candidate.toml\"\n",
                "default_result = \"default.json\"\n",
                "i1_result = \"i1.json\"\n",
                "i2_summary = \"runs/i2/summary.json\"\n",
                "geometry_report = \"geometry.json\"\n",
                "geometry_report_sha256 = \"{}\"\n",
                "qemu_argument_report = \"qemu-args.json\"\n",
                "qemu_argument_report_sha256 = \"{}\"\n",
                "version_report = \"versions.json\"\n",
                "version_report_sha256 = \"{}\"\n",
                "host_matrix = \"matrix.toml\"\n",
                "manifest = \"evidence/v0.toml\"\n"
            ),
            "1".repeat(40),
            "2".repeat(40),
            "3".repeat(40),
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
        )
    }

    fn write_request_fixture(label: &str, text: &str) -> (PathBuf, PathBuf) {
        let root = fixture_root(label);
        fs::create_dir_all(root.join("runs/i2")).expect("create run fixture");
        fs::create_dir(root.join("evidence")).expect("create evidence fixture");
        for name in [
            "candidate.toml",
            "default.json",
            "i1.json",
            "runs/i2/summary.json",
            "geometry.json",
            "qemu-args.json",
            "versions.json",
            "matrix.toml",
        ] {
            fs::write(root.join(name), b"evidence").expect("write evidence fixture");
        }
        let path = root.join("freeze.toml");
        fs::write(&path, text).expect("write freeze request");
        (root, path)
    }

    #[test]
    fn flat_freeze_inputs_reject_sections_duplicates_and_unknown_keys() {
        assert!(parse_flat("a = 1\nb = \"x\"\n", "fixture").is_ok());
        assert!(parse_flat("[x]\na = 1\n", "fixture").is_err());
        assert!(parse_flat("a = 1\na = 2\n", "fixture").is_err());
        let values = parse_flat("a = 1\n", "fixture").unwrap();
        assert!(exact_keys(&values, &["a"], "fixture").is_ok());
        assert!(exact_keys(&values, &["a", "b"], "fixture").is_err());
    }

    #[test]
    fn relative_paths_and_hashes_are_strict() {
        for invalid in ["", "/tmp/x", "../x", "a/../x", "./x"] {
            assert!(relative_path(Path::new("/request"), invalid).is_err());
        }
        assert_eq!(
            relative_path(Path::new("/request"), "a/x").unwrap(),
            Path::new("/request/a/x")
        );
        let mut values = BTreeMap::new();
        values.insert("digest".into(), "a".repeat(64));
        assert!(sha256_value(&values, "digest", "fixture").is_ok());
        values.insert("digest".into(), "A".repeat(64));
        assert!(sha256_value(&values, "digest", "fixture").is_err());
    }

    #[test]
    fn minimal_result_binding_is_rejected_by_the_complete_schema() {
        let request = FreezeRequest {
            root: PathBuf::from("/request"),
            secure_root: secure_fs::Root::placeholder(Path::new("/request")),
            deepwyrm_revision: "1".repeat(40),
            wyrmroot_revision: "2".repeat(40),
            rust_revision: "3".repeat(40),
            candidate_request: PathBuf::new(),
            default_result: PathBuf::new(),
            i1_result: PathBuf::new(),
            i2_summary: PathBuf::new(),
            geometry_report: PathBuf::new(),
            geometry_report_sha256: "a".repeat(64),
            qemu_argument_report: PathBuf::new(),
            qemu_argument_report_sha256: "b".repeat(64),
            version_report: PathBuf::new(),
            version_report_sha256: "c".repeat(64),
            host_matrix: PathBuf::new(),
            manifest: PathBuf::new(),
        };
        let valid = format!(
            "{{\"schema_version\":4,\"phase\":\"WYR0-H-I2\",\"status\":\"PASS\",\"deepwyrm_revision\":\"{}\",\"wyrmroot_revision\":\"{}\",\"rust_revision\":\"{}\"}}",
            request.deepwyrm_revision, request.wyrmroot_revision, request.rust_revision
        );
        assert!(validate_result(valid.as_bytes(), 4, "WYR0-H-I2", &request, "fixture").is_err());
        assert!(parse_json_object(br#"{"a":[{"b":1}],"c":null}"#, "fixture").is_ok());
        assert!(parse_json_object(br#"{"a":1,"a":1}"#, "fixture").is_err());
        assert!(parse_json_object(br#"{"a":{"b":1,"b":2}}"#, "fixture").is_err());
        assert!(parse_json_object(br#"{"a":"escaped\\n"}"#, "fixture").is_err());
    }

    #[test]
    fn freeze_request_rejects_unknown_keys_escapes_symlinks_and_existing_output() {
        for (label, mutation) in [
            ("unknown", format!("{}unknown = 1\n", valid_request_text())),
            (
                "escape",
                valid_request_text().replace("default.json", "../default.json"),
            ),
            (
                "absolute",
                valid_request_text().replace("default.json", "/tmp/default.json"),
            ),
            (
                "bad-hash",
                valid_request_text().replace(&"a".repeat(64), &"A".repeat(64)),
            ),
            (
                "wrong-kind",
                valid_request_text().replace("wyr0-v0-freeze-request", "other"),
            ),
        ] {
            let (root, path) = write_request_fixture(label, &mutation);
            assert!(
                load_request(&path).is_err(),
                "admitted hostile V0 request {label}"
            );
            fs::remove_dir_all(root).expect("remove V0 fixture");
        }

        let (root, path) = write_request_fixture("existing", &valid_request_text());
        fs::write(root.join("evidence/v0.toml"), b"old").expect("write existing output");
        assert!(load_request(&path).is_err());
        fs::remove_dir_all(root).expect("remove V0 fixture");

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let (root, path) = write_request_fixture("symlink", &valid_request_text());
            fs::remove_file(root.join("default.json")).expect("remove input fixture");
            symlink(root.join("i1.json"), root.join("default.json")).expect("create input symlink");
            assert!(load_request(&path).is_err());
            fs::remove_dir_all(root).expect("remove V0 fixture");
        }
    }

    #[test]
    fn host_matrix_requires_contiguous_unique_passing_digest_bound_entries() {
        let (root, path) = write_request_fixture("matrix", &valid_request_text());
        fs::write(root.join("host-check.txt"), b"host evidence").expect("write host evidence");
        let digest = sha256::bytes_digest(b"host evidence");
        let valid_matrix = format!(
            concat!(
                "schema_version = 1\n",
                "manifest_kind = \"wyr0-v0-host-matrix\"\n",
                "entry_count = 1\n",
                "entry_000_name = \"workspace-tests\"\n",
                "entry_000_status = \"pass\"\n",
                "entry_000_evidence = \"host-check.txt\"\n",
                "entry_000_sha256 = \"{}\"\n"
            ),
            digest
        );
        fs::write(root.join("matrix.toml"), &valid_matrix).expect("write matrix");
        let request = load_request(&path).expect("valid freeze request rejected");
        assert_eq!(
            load_matrix(&request).expect("valid matrix rejected").len(),
            1
        );
        for mutation in [
            valid_matrix.replace("entry_000_status = \"pass\"", "entry_000_status = \"fail\""),
            valid_matrix.replace(&digest, &"0".repeat(64)),
            format!("{valid_matrix}unknown = 1\n"),
            valid_matrix.replace("entry_count = 1", "entry_count = 0"),
            valid_matrix.replace(
                "entry_000_evidence = \"host-check.txt\"",
                "entry_000_evidence = \"../host-check.txt\"",
            ),
        ] {
            fs::write(root.join("matrix.toml"), mutation).expect("mutate matrix");
            assert!(load_matrix(&request).is_err());
        }
        fs::remove_dir_all(root).expect("remove V0 fixture");
    }
}
