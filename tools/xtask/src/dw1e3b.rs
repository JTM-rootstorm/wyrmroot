//! DW1-E3B selector-31 full-acceptance freeze and runner grammar.
//!
//! E3B is deliberately separate from E3A: it freezes two distinct raw COM2
//! payload legs and the complete restart/stale-binding transcript contract.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{error::Failure, g3_image, sha256, tasks, wyr1c6};

use crate::dw1e3a::{self, ARTIFACTS, ProducedArtifacts};

pub(crate) const SELECTOR: &str = dw1e3a::SELECTOR;
pub(crate) const TEST_ID: &str = dw1e3a::TEST_ID;
pub(crate) const EVIDENCE_PROTOCOL: &str = dw1e3a::EVIDENCE_PROTOCOL;
const REQUEST_KIND: &str = "wyrmroot-dw1-e3b-selector31-request";
const HANDOFF_KIND: &str = "wyrmroot-dw1-e3b-selector31-vm-handoff";
const PAIR_KIND: &str = "wyrmroot-dw1-e3b-selector31-vm-profile-pair";
const RECEIPT_KIND: &str = "wyrmroot-dw1-e3b-selector31-freeze-receipt";
pub(crate) const RESULT_KIND: &str = "wyrmroot-dw1-e3b-selector31-full-result";
const SOURCE_RECEIPT: &str = "e3b-source-freeze.toml";
const INHERITED_SOURCE_RECEIPT: &str = "e3a-source-build.toml";
const MACHINE: &str = "pc-q35-10.2";
const TIMEOUT_SECONDS: &str = "120";
const COM1_FD_GROUP: &str = "dw-e3b-com1-evidence-v1";
const COM2_FD_GROUP: &str = "dw-e3b-com2-raw-v1";

const BASE_REQUEST_KEYS: &[&str] = &[
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
    "challenge_1_nonce",
    "challenge_1_hex",
    "challenge_1_length",
    "challenge_1_fnv64",
    "challenge_1_sha256",
    "response_1_hex",
    "response_1_length",
    "response_1_fnv64",
    "response_1_sha256",
    "challenge_2_nonce",
    "challenge_2_hex",
    "challenge_2_length",
    "challenge_2_fnv64",
    "challenge_2_sha256",
    "response_2_hex",
    "response_2_length",
    "response_2_fnv64",
    "response_2_sha256",
    "esp",
    "esp_sha256",
    "default_handoff",
    "smp_handoff",
    "profile_pair",
    "receipt",
    "source_receipt",
    "source_receipt_sha256",
    "result_schema",
];

const BASE_HANDOFF_KEYS: &[&str] = &[
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
    "challenge_1_nonce",
    "challenge_1_hex",
    "challenge_1_length",
    "challenge_1_fnv64",
    "challenge_1_sha256",
    "response_1_hex",
    "response_1_length",
    "response_1_fnv64",
    "response_1_sha256",
    "challenge_2_nonce",
    "challenge_2_hex",
    "challenge_2_length",
    "challenge_2_fnv64",
    "challenge_2_sha256",
    "response_2_hex",
    "response_2_length",
    "response_2_fnv64",
    "response_2_sha256",
];

const PAIR_KEYS: &[&str] = &[
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
];

const RESULT_KEYS: &[&str] = &[
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
    "challenge_1_nonce",
    "challenge_1_sha256",
    "response_1_sha256",
    "challenge_1_transcript_sha256",
    "challenge_2_nonce",
    "challenge_2_sha256",
    "response_2_sha256",
    "challenge_2_transcript_sha256",
    "u1_route_generation",
    "u1_object_generation",
    "u1_binding_generation",
    "u1_lease_generation",
    "u1_attempt_generation",
    "u1_stream_generation",
    "u1_challenge_generation",
    "u2_route_generation",
    "u2_object_generation",
    "u2_binding_generation",
    "u2_lease_generation",
    "u2_attempt_generation",
    "u2_stream_generation",
    "u2_challenge_generation",
    "acceptance",
];

pub(crate) fn prepare(
    output: &Path,
    deep_repository: &Path,
    deep_revision: &str,
    evidence_nonce: &str,
    challenge_1_nonce: &str,
    challenge_2_nonce: &str,
) -> Result<String, Failure> {
    dw1e3a::reject_selector_environment()?;
    for (name, value) in [
        ("Deepwyrm revision", deep_revision),
        ("DW1-E3B evidence nonce", evidence_nonce),
        ("DW1-E3B challenge 1 nonce", challenge_1_nonce),
        ("DW1-E3B challenge 2 nonce", challenge_2_nonce),
    ] {
        if name == "Deepwyrm revision" {
            wyr1c6::validate_revision(value, name)?;
        } else {
            wyr1c6::validate_upper_hex_nonzero(value, 16, name)?;
        }
    }
    if challenge_1_nonce == challenge_2_nonce {
        return Err(Failure::task("DW1-E3B challenge nonces must be distinct"));
    }
    if output.exists() {
        return Err(Failure::task("DW1-E3B output must be a fresh path"));
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
            "DW1-E3B source metadata does not name the accepted Rust toolchain",
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
    let staging = temporary.join(format!("dw1e3b-producer-{}-{unique}", std::process::id()));
    fs::create_dir(&staging).map_err(|error| {
        Failure::task(format!(
            "could not create DW1-E3B producer staging: {error}"
        ))
    })?;
    let result = (|| {
        // The two leg identities are build-owned for this E3B snapshot: guest
        // products receive them only while their Cargo processes run so
        // system-init can arm the frozen payload hashes. Deepwyrm receives
        // only the selector evidence nonce.
        let produced = dw1e3a::build_e3b_produced_artifacts(
            &staging,
            &repository,
            &deep_repository,
            &wyrmroot_revision,
            deep_revision,
            &abi_revision,
            &abi_tree,
            evidence_nonce,
            challenge_1_nonce,
            challenge_2_nonce,
        )?;
        freeze_produced(
            &output,
            &produced,
            evidence_nonce,
            challenge_1_nonce,
            challenge_2_nonce,
            dw1e3a::build_esp,
        )
    })();
    if result.is_ok() {
        fs::remove_dir_all(&staging)
            .map_err(|error| Failure::task(format!("could not retire DW1-E3B staging: {error}")))?;
    }
    result
}

fn request_keys() -> Vec<String> {
    let mut keys = BASE_REQUEST_KEYS
        .iter()
        .map(|key| (*key).to_owned())
        .collect::<Vec<_>>();
    for (key, _) in ARTIFACTS {
        keys.push((*key).to_owned());
        keys.push(format!("{key}_sha256"));
    }
    keys
}

fn handoff_keys() -> Vec<String> {
    let mut keys = BASE_HANDOFF_KEYS
        .iter()
        .map(|key| (*key).to_owned())
        .collect::<Vec<_>>();
    for (key, _) in ARTIFACTS {
        keys.push(format!("{key}_path"));
        keys.push(format!("{key}_sha256"));
    }
    keys
}

fn freeze_produced(
    output: &Path,
    produced: &ProducedArtifacts,
    evidence_nonce: &str,
    challenge_1_nonce: &str,
    challenge_2_nonce: &str,
    esp_builder: impl FnOnce(&Path, &BTreeMap<String, String>) -> Result<(), Failure>,
) -> Result<String, Failure> {
    if output.exists() {
        return Err(Failure::task("DW1-E3B output must be a fresh path"));
    }
    fs::create_dir(output)
        .map_err(|error| Failure::task(format!("could not create DW1-E3B output: {error}")))?;
    let frozen = output.join("artifacts");
    fs::create_dir(&frozen)
        .map_err(|error| Failure::task(format!("could not create DW1-E3B artifacts: {error}")))?;
    let mut fields = BTreeMap::new();
    let inherited = wyr1c6::read_regular_bounded(
        &produced.directory.join(INHERITED_SOURCE_RECEIPT),
        64 * 1024,
        "DW1-E3B inherited source receipt",
    )?;
    wyr1c6::write_new(
        &frozen.join(INHERITED_SOURCE_RECEIPT),
        &inherited,
        "DW1-E3B inherited source receipt",
    )?;
    for (key, name) in ARTIFACTS {
        let bytes = wyr1c6::read_regular_bounded(
            &produced.directory.join(name),
            dw1e3a::artifact_maximum(key),
            key,
        )?;
        wyr1c6::write_new(&frozen.join(name), &bytes, key)?;
        fields.insert((*key).to_owned(), format!("artifacts/{name}"));
        fields.insert(format!("{key}_sha256"), sha256::bytes_digest(&bytes));
    }
    let (challenge_1, response_1) = dw1e3a::challenge_pair(challenge_1_nonce)?;
    let (challenge_2, response_2) = dw1e3a::challenge_pair(challenge_2_nonce)?;
    let source = render_source_receipt(
        produced,
        evidence_nonce,
        challenge_1_nonce,
        &challenge_1,
        &response_1,
        challenge_2_nonce,
        &challenge_2,
        &response_2,
        &inherited,
    )?;
    wyr1c6::write_new(
        &frozen.join(SOURCE_RECEIPT),
        source.as_bytes(),
        "DW1-E3B source receipt",
    )?;
    fields.insert(
        "source_receipt".into(),
        format!("artifacts/{SOURCE_RECEIPT}"),
    );
    fields.insert(
        "source_receipt_sha256".into(),
        sha256::bytes_digest(source.as_bytes()),
    );
    esp_builder(output, &fields)?;
    let esp = frozen.join("selector31-esp.img");
    wyr1c6::seal_mode(&esp, 0o444, "DW1-E3B ESP")?;
    fields.insert("esp".into(), "artifacts/selector31-esp.img".into());
    fields.insert(
        "esp_sha256".into(),
        sha256::bytes_digest(&wyr1c6::read_regular_bounded(
            &esp,
            g3_image::IMAGE_BYTES,
            "DW1-E3B ESP",
        )?),
    );
    for (key, value) in [
        ("kind", REQUEST_KIND.to_owned()),
        ("schema_version", "1".to_owned()),
        ("selector", SELECTOR.to_owned()),
        ("test_id", TEST_ID.to_owned()),
        ("profile", "dw1e3b-selector31".to_owned()),
        (
            "scenario",
            "two-raw-com2-round-trips-with-replacement-and-stale-u1-rejection".to_owned(),
        ),
        ("evidence_protocol", EVIDENCE_PROTOCOL.to_owned()),
        ("full_evidence", "true".to_owned()),
        ("acceptance_claim", "full-selector31-acceptance".to_owned()),
        ("terminal_line", "DWTEST1 31 0".to_owned()),
        ("deepwyrm_revision", produced.deep_revision.clone()),
        ("generated_abi_revision", produced.abi_revision.clone()),
        ("generated_abi_tree", produced.abi_tree.clone()),
        ("wyrmroot_revision", produced.wyrmroot_revision.clone()),
        ("rust_revision", produced.rust_revision.clone()),
        ("evidence_nonce", evidence_nonce.to_owned()),
        ("profile_pair", "profile-pair.toml".to_owned()),
        ("default_handoff", "default/handoff.toml".to_owned()),
        ("smp_handoff", "smp/handoff.toml".to_owned()),
        ("receipt", "freeze-receipt.toml".to_owned()),
        ("result_schema", "result-schema.toml".to_owned()),
    ] {
        fields.insert(key.to_owned(), value);
    }
    insert_leg(&mut fields, 1, challenge_1_nonce, &challenge_1, &response_1);
    insert_leg(&mut fields, 2, challenge_2_nonce, &challenge_2, &response_2);
    let request = render_request(&fields)?;
    wyr1c6::write_new(
        &output.join("request.toml"),
        request.as_bytes(),
        "DW1-E3B request",
    )?;
    let request_hash = sha256::bytes_digest(request.as_bytes());
    let result_schema = render_result_schema()?;
    wyr1c6::write_new(
        &output.join("result-schema.toml"),
        result_schema.as_bytes(),
        "DW1-E3B result schema",
    )?;
    for (profile, vcpus) in [("default", 1), ("smp", 4)] {
        stage_profile(output, profile, vcpus, &request_hash, &fields)?;
    }
    write_pair(output, &request_hash)?;
    let mut receipt = BTreeMap::new();
    for (key, value) in [
        ("kind", RECEIPT_KIND),
        ("schema_version", "1"),
        ("request_sha256", &request_hash),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        (
            "scenario",
            "two-raw-com2-round-trips-with-replacement-and-stale-u1-rejection",
        ),
        ("full_evidence", "true"),
        ("acceptance_claim", "full-selector31-acceptance"),
        ("terminal_line", "DWTEST1 31 0"),
        ("challenge_1_nonce", challenge_1_nonce),
        ("challenge_2_nonce", challenge_2_nonce),
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
                "challenge_1_nonce",
                "challenge_2_nonce",
            ],
            &["schema_version", "test_id"],
            "DW1-E3B receipt",
        )?
        .as_bytes(),
        "DW1-E3B receipt",
    )?;
    validate_frozen_output(output, &fields, &request_hash)?;
    Ok(format!(
        "DW1_E3B_PREPARE_PASS selector={SELECTOR} test_id={TEST_ID} evidence={EVIDENCE_PROTOCOL} request={} default_handoff={} smp_handoff={} profile_pair={} full_evidence=true terminal=DWTEST1-31-0\n",
        output.join("request.toml").display(),
        output.join("default/handoff.toml").display(),
        output.join("smp/handoff.toml").display(),
        output.join("profile-pair.toml").display()
    ))
}

fn insert_leg(
    fields: &mut BTreeMap<String, String>,
    leg: u8,
    nonce: &str,
    challenge: &[u8],
    response: &[u8],
) {
    for (suffix, value) in [
        ("nonce", nonce.to_owned()),
        ("hex", dw1e3a::upper_hex(challenge)),
        ("length", challenge.len().to_string()),
        ("fnv64", format!("{:016X}", dw1e3a::fnv1a64(challenge))),
        ("sha256", sha256::bytes_digest(challenge)),
    ] {
        fields.insert(format!("challenge_{leg}_{suffix}"), value);
    }
    for (suffix, value) in [
        ("hex", dw1e3a::upper_hex(response)),
        ("length", response.len().to_string()),
        ("fnv64", format!("{:016X}", dw1e3a::fnv1a64(response))),
        ("sha256", sha256::bytes_digest(response)),
    ] {
        fields.insert(format!("response_{leg}_{suffix}"), value);
    }
}

#[allow(clippy::too_many_arguments)]
fn render_source_receipt(
    produced: &ProducedArtifacts,
    evidence_nonce: &str,
    n1: &str,
    c1: &[u8],
    r1: &[u8],
    n2: &str,
    c2: &[u8],
    r2: &[u8],
    inherited: &[u8],
) -> Result<String, Failure> {
    let mut values = BTreeMap::new();
    for (key, value) in [
        (
            "kind",
            "wyrmroot-dw1-e3b-selector31-source-freeze".to_owned(),
        ),
        ("schema_version", "1".to_owned()),
        ("selector", SELECTOR.to_owned()),
        ("test_id", TEST_ID.to_owned()),
        ("evidence_protocol", EVIDENCE_PROTOCOL.to_owned()),
        ("deepwyrm_revision", produced.deep_revision.clone()),
        ("generated_abi_revision", produced.abi_revision.clone()),
        ("generated_abi_tree", produced.abi_tree.clone()),
        ("wyrmroot_revision", produced.wyrmroot_revision.clone()),
        ("rust_revision", produced.rust_revision.clone()),
        ("evidence_nonce", evidence_nonce.to_owned()),
        (
            "inherited_e3a_source_receipt",
            format!("artifacts/{INHERITED_SOURCE_RECEIPT}"),
        ),
        (
            "inherited_e3a_source_receipt_sha256",
            sha256::bytes_digest(inherited),
        ),
    ] {
        values.insert(key.to_owned(), value);
    }
    insert_leg(&mut values, 1, n1, c1, r1);
    insert_leg(&mut values, 2, n2, c2, r2);
    render(
        &values,
        &[
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
            "inherited_e3a_source_receipt",
            "inherited_e3a_source_receipt_sha256",
            "challenge_1_nonce",
            "challenge_1_hex",
            "challenge_1_length",
            "challenge_1_fnv64",
            "challenge_1_sha256",
            "response_1_hex",
            "response_1_length",
            "response_1_fnv64",
            "response_1_sha256",
            "challenge_2_nonce",
            "challenge_2_hex",
            "challenge_2_length",
            "challenge_2_fnv64",
            "challenge_2_sha256",
            "response_2_hex",
            "response_2_length",
            "response_2_fnv64",
            "response_2_sha256",
        ],
        &[
            "schema_version",
            "test_id",
            "challenge_1_length",
            "response_1_length",
            "challenge_2_length",
            "response_2_length",
        ],
        "DW1-E3B source receipt",
    )
}

fn stage_profile(
    output: &Path,
    profile: &str,
    vcpus: u8,
    request_hash: &str,
    request: &BTreeMap<String, String>,
) -> Result<(), Failure> {
    let directory = output.join(profile);
    fs::create_dir(&directory).map_err(|error| {
        Failure::task(format!(
            "could not create DW1-E3B {profile} profile: {error}"
        ))
    })?;
    let vars = wyr1c6::read_regular_bounded(
        &output.join(value(request, "ovmf_vars")?),
        wyr1c6::MAX_FIRMWARE_BYTES,
        "DW1-E3B OVMF vars",
    )?;
    let vars_path = directory.join("OVMF_VARS.mutable.fd");
    wyr1c6::write_new_mode(&vars_path, &vars, 0o600, "DW1-E3B mutable OVMF vars")?;
    let absolute = fs::canonicalize(output)
        .map_err(|error| Failure::task(format!("could not resolve DW1-E3B output: {error}")))?;
    let xml = dw1e3a::domain_xml(
        vcpus,
        &absolute.join(value(request, "ovmf_code")?),
        &absolute.join(value(request, "esp")?),
        &absolute.join(profile).join("OVMF_VARS.mutable.fd"),
        &absolute.join(profile).join("com2.sock"),
    );
    wyr1c6::write_new(
        &directory.join("domain.xml"),
        xml.as_bytes(),
        "DW1-E3B domain XML",
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
        ("acceptance_claim", "full-selector31-acceptance"),
        ("terminal_line", "DWTEST1 31 0"),
        ("request", "request.toml"),
        ("request_sha256", request_hash),
        ("esp", value(request, "esp")?),
        ("esp_sha256", value(request, "esp_sha256")?),
        ("vcpus", if vcpus == 1 { "1" } else { "4" }),
        ("memory_mib", "2048"),
        ("machine", MACHINE),
        ("firmware", "OVMF"),
        ("timeout_seconds", TIMEOUT_SECONDS),
        (
            "scenario",
            "two-raw-com2-round-trips-with-replacement-and-stale-u1-rejection",
        ),
        ("physical_io", "real-com2-irq3-required"),
        ("terminal_authority", "deepwyrm-selector31-controller"),
        ("com1_role", "trusted-evidence-and-terminal"),
        ("com2_role", "two-raw-challenge-response-legs"),
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
    for leg in [1, 2] {
        for suffix in ["nonce", "hex", "length", "fnv64", "sha256"] {
            fields.insert(
                format!("challenge_{leg}_{suffix}"),
                value(request, &format!("challenge_{leg}_{suffix}"))?.to_owned(),
            );
        }
        for suffix in ["hex", "length", "fnv64", "sha256"] {
            fields.insert(
                format!("response_{leg}_{suffix}"),
                value(request, &format!("response_{leg}_{suffix}"))?.to_owned(),
            );
        }
    }
    for (key, _) in ARTIFACTS {
        fields.insert(format!("{key}_path"), value(request, key)?.to_owned());
        fields.insert(
            format!("{key}_sha256"),
            value(request, &format!("{key}_sha256"))?.to_owned(),
        );
    }
    wyr1c6::write_new(
        &directory.join("handoff.toml"),
        render_handoff(&fields)?.as_bytes(),
        "DW1-E3B handoff",
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
        ("acceptance_claim", "full-selector31-acceptance"),
        ("terminal_line", "DWTEST1 31 0"),
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
                "DW1-E3B handoff",
            )?),
        );
    }
    wyr1c6::write_new(
        &output.join("profile-pair.toml"),
        render(
            &fields,
            PAIR_KEYS,
            &[
                "schema_version",
                "test_id",
                "default_vcpus",
                "smp_vcpus",
                "memory_mib",
                "timeout_seconds",
            ],
            "DW1-E3B profile pair",
        )?
        .as_bytes(),
        "DW1-E3B profile pair",
    )
}

fn render_request(values: &BTreeMap<String, String>) -> Result<String, Failure> {
    for (key, expected) in [
        ("kind", REQUEST_KIND),
        ("schema_version", "1"),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
        ("profile", "dw1e3b-selector31"),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("full_evidence", "true"),
        ("acceptance_claim", "full-selector31-acceptance"),
        ("terminal_line", "DWTEST1 31 0"),
        ("result_schema", "result-schema.toml"),
    ] {
        require(values, key, expected)?;
    }
    for leg in [1, 2] {
        require(values, &format!("challenge_{leg}_length"), "24")?;
        require(values, &format!("response_{leg}_length"), "24")?;
    }
    if value(values, "challenge_1_nonce")? == value(values, "challenge_2_nonce")? {
        return Err(Failure::task("DW1-E3B request repeats challenge nonce"));
    }
    render_dynamic(
        values,
        &request_keys(),
        &[
            "schema_version",
            "test_id",
            "challenge_1_length",
            "response_1_length",
            "challenge_2_length",
            "response_2_length",
        ],
        "DW1-E3B request",
    )
}

fn render_handoff(values: &BTreeMap<String, String>) -> Result<String, Failure> {
    let profile = value(values, "profile")?;
    let vcpus = match profile {
        "default" => "1",
        "smp" => "4",
        _ => {
            return Err(Failure::task(
                "DW1-E3B handoff profile must be default or smp",
            ));
        }
    };
    for (key, expected) in [
        ("kind", HANDOFF_KIND),
        ("schema_version", "1"),
        ("selector", SELECTOR),
        ("test_id", TEST_ID),
        ("evidence_protocol", EVIDENCE_PROTOCOL),
        ("full_evidence", "true"),
        ("acceptance_claim", "full-selector31-acceptance"),
        ("terminal_line", "DWTEST1 31 0"),
        ("vcpus", vcpus),
        ("memory_mib", "2048"),
        ("machine", MACHINE),
        ("firmware", "OVMF"),
        ("timeout_seconds", TIMEOUT_SECONDS),
        ("physical_io", "real-com2-irq3-required"),
        ("terminal_authority", "deepwyrm-selector31-controller"),
        ("com2_transport", "unix-socket-byte-stream"),
        ("com2_socket_mode", "connect"),
        ("com2_socket_owner", "runner"),
        ("result_schema", "result-schema.toml"),
    ] {
        require(values, key, expected)?;
    }
    render_dynamic(
        values,
        &handoff_keys(),
        &[
            "schema_version",
            "test_id",
            "vcpus",
            "memory_mib",
            "timeout_seconds",
            "challenge_1_length",
            "response_1_length",
            "challenge_2_length",
            "response_2_length",
        ],
        "DW1-E3B handoff",
    )
}

fn render_result_schema() -> Result<String, Failure> {
    let mut values = BTreeMap::new();
    for key in RESULT_KEYS {
        values.insert(
            (*key).to_owned(),
            if *key == "kind" {
                RESULT_KIND.to_owned()
            } else if *key == "schema_version" {
                "1".to_owned()
            } else if *key == "selector" {
                SELECTOR.to_owned()
            } else if *key == "test_id" {
                TEST_ID.to_owned()
            } else if *key == "evidence_protocol" {
                EVIDENCE_PROTOCOL.to_owned()
            } else if *key == "evidence_records" {
                "26".to_owned()
            } else if *key == "terminal_line" {
                "DWTEST1 31 0".to_owned()
            } else if *key == "acceptance" {
                "pass".to_owned()
            } else {
                format!("<runner:{}>", key)
            },
        );
    }
    // This is a schema/template, not a completed runner result. Keep the
    // runner-owned fields visibly unresolved instead of forging integers.
    render(&values, RESULT_KEYS, &[], "DW1-E3B result schema")
}

fn validate_frozen_output(
    output: &Path,
    request: &BTreeMap<String, String>,
    request_hash: &str,
) -> Result<(), Failure> {
    for (key, name) in ARTIFACTS {
        let path = output.join(value(request, key)?);
        let bytes = wyr1c6::read_regular_bounded(&path, dw1e3a::artifact_maximum(key), key)?;
        if path.file_name().and_then(|n| n.to_str()) != Some(name)
            || sha256::bytes_digest(&bytes) != value(request, &format!("{key}_sha256"))?
        {
            return Err(Failure::task(format!(
                "DW1-E3B frozen {key} identity drifted"
            )));
        }
    }
    for profile in ["default", "smp"] {
        let text = String::from_utf8(wyr1c6::read_regular_bounded(
            &output.join(profile).join("handoff.toml"),
            64 * 1024,
            "DW1-E3B handoff",
        )?)
        .map_err(|_| Failure::task("DW1-E3B handoff is not UTF-8"))?;
        if !text.contains(&format!("request_sha256 = \"{request_hash}\"")) {
            return Err(Failure::task("DW1-E3B handoff request join drifted"));
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
                    "DW1-E3B runtime output exists before runner execution",
                ));
            }
        }
    }
    Ok(())
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

fn render_dynamic(
    values: &BTreeMap<String, String>,
    keys: &[String],
    integers: &[&str],
    label: &str,
) -> Result<String, Failure> {
    let names = keys.iter().map(String::as_str).collect::<Vec<_>>();
    render(values, &names, integers, label)
}

fn require(values: &BTreeMap<String, String>, key: &str, expected: &str) -> Result<(), Failure> {
    if value(values, key)? != expected {
        return Err(Failure::task(format!("DW1-E3B {key} drifted")));
    }
    Ok(())
}
fn value<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, Failure> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| Failure::task(format!("DW1-E3B omitted {key}")))
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FullEvidence {
    pub(crate) sha256: String,
    pub(crate) u1: [u64; 7],
    pub(crate) u2: [u64; 7],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LegPayloadIdentity {
    pub(crate) challenge_length: u64,
    pub(crate) challenge_fnv: u64,
    pub(crate) response_length: u64,
    pub(crate) response_fnv: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FullEvidenceInputs<'a> {
    pub(crate) nonce: &'a str,
    pub(crate) challenge_1: LegPayloadIdentity,
    pub(crate) challenge_2: LegPayloadIdentity,
}

/// Parses the byte-defined E0 section-11 transaction and its trusted terminal.
#[allow(dead_code)]
pub(crate) fn parse_full_evidence(
    bytes: &[u8],
    inputs: FullEvidenceInputs<'_>,
) -> Result<FullEvidence, Failure> {
    const EVENTS: [u8; 26] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        255,
    ];
    const ACTORS: [u8; 26] = [
        0, 0, 0, 0, 0, 0, 1, 0, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 0, 0,
    ];
    if inputs.nonce.len() != 16
        || bytes.len() != 26 * 204 + 13
        || &bytes[26 * 204..] != b"DWTEST1 31 0\n"
    {
        return Err(Failure::task(
            "DW1-E3B evidence lacks exact 26-record DWTEST1 31/0 terminal",
        ));
    }
    let mut rows = [[0u64; 9]; 26];
    for sequence in 0..26 {
        let record = &bytes[sequence * 204..(sequence + 1) * 204];
        if &record[..6] != b"DWE3E1"
            || &record[7..9] != b"01"
            || record[203] != b'\n'
            || &record[10..26] != inputs.nonce.as_bytes()
            || parse_hex(&record[27..35])? != sequence as u64
            || parse_hex(&record[36..38])? != EVENTS[sequence] as u64
            || parse_hex(&record[39..41])? != ACTORS[sequence] as u64
            || parse_hex(&record[195..203])? != fnv1a32(&record[..195]) as u64
        {
            return Err(Failure::task("DW1-E3B evidence record framing drifted"));
        }
        for (index, range) in [
            42..58,
            59..75,
            76..92,
            93..109,
            110..126,
            127..143,
            144..160,
            161..177,
            178..194,
        ]
        .into_iter()
        .enumerate()
        {
            rows[sequence][index] = parse_hex(&record[range])?;
        }
    }
    let u1: [u64; 7] = rows[3][..7].try_into().unwrap();
    let u2: [u64; 7] = rows[17][..7].try_into().unwrap();
    if rows[0].iter().any(|value| *value != 0)
        || rows[25].iter().any(|value| *value != 0)
        || u1.contains(&0)
        || u2.contains(&0)
    {
        return Err(Failure::task(
            "DW1-E3B evidence zero-generation rule drifted",
        ));
    }
    for sequence in [1, 2] {
        if rows[sequence][..5].contains(&0) || rows[sequence][5] != 0 || rows[sequence][6] != 0 {
            return Err(Failure::task("DW1-E3B U1 reserve/commit tuple drifted"));
        }
    }
    for row in rows.iter().take(15).skip(3) {
        if row[..7] != u1 {
            return Err(Failure::task("DW1-E3B U1 tuple join drifted"));
        }
    }
    for sequence in [15, 16] {
        if rows[sequence][..5].contains(&0)
            || rows[sequence][5] != 0
            || rows[sequence][6] != 0
            || rows[sequence][3] != u1[3]
        {
            return Err(Failure::task("DW1-E3B U2 reserve/commit tuple drifted"));
        }
    }
    for row in rows.iter().take(23).skip(17) {
        if row[..7] != u2 {
            return Err(Failure::task("DW1-E3B U2 tuple join drifted"));
        }
    }
    if rows[23][..7] != u1
        || rows[23][7] != u2[2]
        || rows[23][8] != u2[1]
        || rows[24][..7] != u2
        || u1[0] != u1[2]
        || u2[0] != u2[2]
        || u2[0] <= u1[0]
        || u2[1] == u1[1]
        || u2[2] <= u1[2]
        || u2[4] <= u1[4]
        || u2[5] <= u1[5]
        || u2[6] <= u1[6]
    {
        return Err(Failure::task("DW1-E3B replacement/stale relation drifted"));
    }
    for (sequence, length, hash) in [
        (
            6,
            inputs.challenge_1.challenge_length,
            inputs.challenge_1.challenge_fnv,
        ),
        (
            8,
            inputs.challenge_1.response_length,
            inputs.challenge_1.response_fnv,
        ),
        (
            20,
            inputs.challenge_2.challenge_length,
            inputs.challenge_2.challenge_fnv,
        ),
        (
            22,
            inputs.challenge_2.response_length,
            inputs.challenge_2.response_fnv,
        ),
    ] {
        if rows[sequence][7] != length || rows[sequence][8] != hash {
            return Err(Failure::task("DW1-E3B raw leg identity drifted"));
        }
    }
    Ok(FullEvidence {
        sha256: sha256::bytes_digest(bytes),
        u1,
        u2,
    })
}

#[allow(dead_code)]
fn parse_hex(bytes: &[u8]) -> Result<u64, Failure> {
    let mut value = 0u64;
    for byte in bytes {
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'A'..=b'F' => u64::from(byte - b'A' + 10),
            _ => return Err(Failure::task("DW1-E3B evidence hex is malformed")),
        };
        value = value
            .checked_mul(16)
            .and_then(|v| v.checked_add(digit))
            .ok_or_else(|| Failure::task("DW1-E3B evidence hex overflow"))?;
    }
    Ok(value)
}
#[allow(dead_code)]
const fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u32;
        hash = hash.wrapping_mul(0x0100_0193);
        i += 1;
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    fn put_hex(out: &mut [u8], value: u64) {
        let width = out.len();
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = b"0123456789ABCDEF"[((value >> ((width - index - 1) * 4)) & 15) as usize];
        }
    }
    fn record(sequence: usize, tuple: [u64; 7], value: u64, auxiliary: u64) -> [u8; 204] {
        const EVENTS: [u8; 26] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 255,
        ];
        const ACTORS: [u8; 26] = [
            0, 0, 0, 0, 0, 0, 1, 0, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 0, 0,
        ];
        let mut r = [b'0'; 204];
        r[..6].copy_from_slice(b"DWE3E1");
        for n in [
            6, 9, 26, 35, 38, 41, 58, 75, 92, 109, 126, 143, 160, 177, 194,
        ] {
            r[n] = b'|';
        }
        r[7..9].copy_from_slice(b"01");
        r[10..26].copy_from_slice(b"0123456789ABCDEF");
        put_hex(&mut r[27..35], sequence as u64);
        put_hex(&mut r[36..38], EVENTS[sequence] as u64);
        put_hex(&mut r[39..41], ACTORS[sequence] as u64);
        for (range, v) in [
            42..58,
            59..75,
            76..92,
            93..109,
            110..126,
            127..143,
            144..160,
        ]
        .into_iter()
        .zip(tuple)
        {
            put_hex(&mut r[range], v);
        }
        put_hex(&mut r[161..177], value);
        put_hex(&mut r[178..194], auxiliary);
        let checksum = fnv1a32(&r[..195]) as u64;
        put_hex(&mut r[195..203], checksum);
        r[203] = b'\n';
        r
    }
    #[test]
    fn full_parser_accepts_exact_restart_tuple_and_terminal() {
        let c1 = dw1e3a::challenge_pair("E300000000000001").unwrap();
        let c2 = dw1e3a::challenge_pair("E300000000000002").unwrap();
        let u1 = [1, 11, 1, 7, 3, 5, 9];
        let u2 = [2, 12, 2, 7, 4, 6, 10];
        let mut bytes = Vec::new();
        for s in 0..26 {
            let tuple = match s {
                0 | 25 => [0; 7],
                1 | 2 => [1, 11, 1, 7, 3, 0, 0],
                3..=14 | 23 => u1,
                15 | 16 => [2, 12, 2, 7, 4, 0, 0],
                _ => u2,
            };
            let (v, x) = match s {
                6 => (c1.0.len() as u64, dw1e3a::fnv1a64(&c1.0)),
                8 => (c1.1.len() as u64, dw1e3a::fnv1a64(&c1.1)),
                20 => (c2.0.len() as u64, dw1e3a::fnv1a64(&c2.0)),
                22 => (c2.1.len() as u64, dw1e3a::fnv1a64(&c2.1)),
                23 => (u2[2], u2[1]),
                _ => (0, 0),
            };
            bytes.extend_from_slice(&record(s, tuple, v, x));
        }
        bytes.extend_from_slice(b"DWTEST1 31 0\n");
        let parsed = parse_full_evidence(
            &bytes,
            FullEvidenceInputs {
                nonce: "0123456789ABCDEF",
                challenge_1: LegPayloadIdentity {
                    challenge_length: 24,
                    challenge_fnv: dw1e3a::fnv1a64(&c1.0),
                    response_length: 24,
                    response_fnv: dw1e3a::fnv1a64(&c1.1),
                },
                challenge_2: LegPayloadIdentity {
                    challenge_length: 24,
                    challenge_fnv: dw1e3a::fnv1a64(&c2.0),
                    response_length: 24,
                    response_fnv: dw1e3a::fnv1a64(&c2.1),
                },
            },
        )
        .unwrap();
        assert_eq!(parsed.u2, u2);
    }
    #[test]
    fn schema_rejects_same_payload_nonce() {
        let mut values = BTreeMap::new();
        for key in request_keys() {
            values.insert(key.to_owned(), "x".to_owned());
        }
        for (k, v) in [
            ("kind", REQUEST_KIND),
            ("schema_version", "1"),
            ("selector", SELECTOR),
            ("test_id", TEST_ID),
            ("profile", "dw1e3b-selector31"),
            ("evidence_protocol", EVIDENCE_PROTOCOL),
            ("full_evidence", "true"),
            ("acceptance_claim", "full-selector31-acceptance"),
            ("terminal_line", "DWTEST1 31 0"),
            ("result_schema", "result-schema.toml"),
            ("challenge_1_length", "24"),
            ("response_1_length", "24"),
            ("challenge_2_length", "24"),
            ("response_2_length", "24"),
            ("challenge_1_nonce", "E300000000000001"),
            ("challenge_2_nonce", "E300000000000001"),
        ] {
            values.insert(k.into(), v.into());
        }
        assert!(render_request(&values).is_err());
    }
    #[test]
    fn freezer_seals_two_nonce_distinct_legs_and_runner_schema() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "wyrmroot-dw1e3b-freezer-test-{}-{unique}",
            std::process::id()
        ));
        let produced_root = root.join("produced");
        let output = root.join("output");
        fs::create_dir_all(&produced_root).unwrap();
        for (_, name) in ARTIFACTS {
            wyr1c6::write_new(&produced_root.join(name), name.as_bytes(), name).unwrap();
        }
        wyr1c6::write_new(
            &produced_root.join(INHERITED_SOURCE_RECEIPT),
            b"e3a-source\n",
            "inherited source",
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
        let result = freeze_produced(
            &output,
            &produced,
            "E300000000000001",
            "E300000000000002",
            "E300000000000003",
            |output, _| {
                wyr1c6::write_new(
                    &output.join("artifacts/selector31-esp.img"),
                    b"synthetic-esp",
                    "synthetic ESP",
                )
            },
        )
        .unwrap();
        assert!(result.contains("terminal=DWTEST1-31-0"));
        let request = fs::read_to_string(output.join("request.toml")).unwrap();
        assert!(request.contains("challenge_1_nonce = \"E300000000000002\""));
        assert!(request.contains("challenge_2_nonce = \"E300000000000003\""));
        assert!(request.contains("terminal_line = \"DWTEST1 31 0\""));
        let swapped_output = root.join("output-swapped");
        freeze_produced(
            &swapped_output,
            &produced,
            "E300000000000001",
            "E300000000000003",
            "E300000000000002",
            |output, _| {
                wyr1c6::write_new(
                    &output.join("artifacts/selector31-esp.img"),
                    b"synthetic-esp",
                    "synthetic ESP",
                )
            },
        )
        .unwrap();
        let swapped_request = fs::read_to_string(swapped_output.join("request.toml")).unwrap();
        let source_receipt_hash = request
            .lines()
            .find(|line| line.starts_with("source_receipt_sha256 = "))
            .unwrap();
        let swapped_source_receipt_hash = swapped_request
            .lines()
            .find(|line| line.starts_with("source_receipt_sha256 = "))
            .unwrap();
        assert_ne!(source_receipt_hash, swapped_source_receipt_hash);
        assert!(swapped_request.contains("challenge_1_nonce = \"E300000000000003\""));
        assert!(swapped_request.contains("challenge_2_nonce = \"E300000000000002\""));
        let schema = fs::read_to_string(output.join("result-schema.toml")).unwrap();
        assert!(schema.contains("evidence_records = \"26\""));
        assert!(schema.contains("acceptance = \"pass\""));
        for profile in ["default", "smp"] {
            let handoff = fs::read_to_string(output.join(profile).join("handoff.toml")).unwrap();
            assert!(handoff.contains("full_evidence = \"true\""));
            assert!(handoff.contains("result_schema = \"result-schema.toml\""));
        }
        fs::remove_dir_all(root).unwrap();
    }
}
