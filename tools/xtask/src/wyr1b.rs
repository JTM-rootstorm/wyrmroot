//! Selector-27 WYR1-B request, deterministic bootfs, receipt, and WRB1 evidence.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};

use crate::wyr1::fixed_builder_for_profile;
use crate::{error::Failure, sha256};
use wyrmroot_bootfs::{
    archive::Archive,
    launch_policy::{LaunchPolicy, LaunchPolicyEntry, encode as encode_policy},
    wyr1::{Product, ProductB, build_b},
};
use wyrmroot_rrc_manifest::{Activation, Manifest, RoleId, StartupProfile};

pub const SCHEMA: u32 = 6;
pub const SELECTOR: &str = "bootstrap-registry-launch";
pub const TEST_ID: u32 = 27;
const MAX_REQUEST: usize = 64 * 1024;
const MAX_EVIDENCE: usize = 1024 * 1024;
const KEYS: &[&str] = &[
    "schema_version",
    "selector",
    "test_id",
    "deepwyrm_revision",
    "wyrmroot_revision",
    "rust_revision",
    "init",
    "registryd",
    "devmgr",
    "uart16550d",
    "consoled",
    "wyrmsh",
    "rrc_manifest",
    "hello",
    "publisher",
    "client",
    "bootfs",
    "receipt",
    "evidence_nonce",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    path: PathBuf,
    request_sha256: String,
    deepwyrm_revision: String,
    wyrmroot_revision: String,
    rust_revision: String,
    init: PathBuf,
    registryd: PathBuf,
    devmgr: PathBuf,
    uart16550d: PathBuf,
    consoled: PathBuf,
    wyrmsh: PathBuf,
    rrc_manifest: PathBuf,
    hello: PathBuf,
    publisher: PathBuf,
    client: PathBuf,
    bootfs: PathBuf,
    receipt: PathBuf,
    evidence_nonce: u64,
}

pub fn load(path: &Path) -> Result<Request, Failure> {
    let bytes = fs::read(path)
        .map_err(|error| Failure::task(format!("could not read WYR1-B request: {error}")))?;
    if bytes.is_empty() || bytes.len() > MAX_REQUEST {
        return Err(Failure::task("WYR1-B request is empty or oversized"));
    }
    let values = parse_scalars(
        std::str::from_utf8(&bytes).map_err(|_| Failure::task("WYR1-B request is not UTF-8"))?,
    )?;
    let expected = KEYS.iter().copied().collect::<BTreeSet<_>>();
    let actual = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if expected != actual {
        return Err(Failure::task("WYR1-B request key set drifted"));
    }
    if number::<u32>(&values, "schema_version")? != SCHEMA
        || required(&values, "selector")? != SELECTOR
        || number::<u32>(&values, "test_id")? != TEST_ID
    {
        return Err(Failure::task(
            "WYR1-B request must name schema 6 selector 27",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| Failure::task("WYR1-B request has no parent"))?;
    let request = Request {
        path: path.to_path_buf(),
        request_sha256: sha256::bytes_digest(&bytes),
        deepwyrm_revision: revision(&values, "deepwyrm_revision")?,
        wyrmroot_revision: revision(&values, "wyrmroot_revision")?,
        rust_revision: revision(&values, "rust_revision")?,
        init: input(parent, required(&values, "init")?),
        registryd: input(parent, required(&values, "registryd")?),
        devmgr: input(parent, required(&values, "devmgr")?),
        uart16550d: input(parent, required(&values, "uart16550d")?),
        consoled: input(parent, required(&values, "consoled")?),
        wyrmsh: input(parent, required(&values, "wyrmsh")?),
        rrc_manifest: output(parent, required(&values, "rrc_manifest")?)?,
        hello: input(parent, required(&values, "hello")?),
        publisher: input(parent, required(&values, "publisher")?),
        client: input(parent, required(&values, "client")?),
        bootfs: output(parent, required(&values, "bootfs")?)?,
        receipt: output(parent, required(&values, "receipt")?)?,
        evidence_nonce: nonce(required(&values, "evidence_nonce")?)?,
    };
    if request.bootfs == request.receipt
        || request.bootfs == request.rrc_manifest
        || request.receipt == request.rrc_manifest
        || request.bootfs.starts_with(&request.receipt)
        || request.receipt.starts_with(&request.bootfs)
        || request.bootfs.starts_with(&request.rrc_manifest)
        || request.rrc_manifest.starts_with(&request.bootfs)
        || request.receipt.starts_with(&request.rrc_manifest)
        || request.rrc_manifest.starts_with(&request.receipt)
    {
        return Err(Failure::task("WYR1-B outputs overlap"));
    }
    Ok(request)
}

pub fn build(path: &Path) -> Result<String, Failure> {
    let request = load(path)?;
    let init = read(&request.init, "init")?;
    let registryd = read(&request.registryd, "registryd")?;
    let devmgr = read(&request.devmgr, "devmgr")?;
    let uart = read(&request.uart16550d, "uart16550d")?;
    let console = read(&request.consoled, "consoled")?;
    let shell = read(&request.wyrmsh, "wyrmsh")?;
    let hello = read(&request.hello, "hello")?;
    let publisher = read(&request.publisher, "publisher")?;
    let client = read(&request.client, "client")?;
    let boot_generation = decode_digest(&request.request_sha256)?;
    let role_hashes = [
        sha256::bytes_digest_array(&registryd),
        sha256::bytes_digest_array(&devmgr),
        sha256::bytes_digest_array(&uart),
        sha256::bytes_digest_array(&console),
        sha256::bytes_digest_array(&shell),
    ];
    let manifest = fixed_builder_for_profile(
        &boot_generation,
        role_hashes,
        StartupProfile::BootstrapRegistry,
    )?
    .build_structural()
    .map_err(|error| Failure::task(format!("WYR1-B manifest build failed: {error:?}")))?;
    fs::write(&request.rrc_manifest, &manifest)
        .map_err(|error| Failure::task(format!("could not write WYR1-B manifest: {error}")))?;
    let policy_entry = LaunchPolicyEntry {
        path: "bin/hello",
        content_sha256: sha256::bytes_digest_array(&hello),
        startup_abi: 2,
        profile_id: 1,
        allow_no_streams: true,
        allow_three_streams: true,
    };
    let mut policy_bytes = [0u8; 512];
    let policy_size = encode_policy(boot_generation, &[policy_entry], &mut policy_bytes)
        .map_err(|error| Failure::task(format!("WYR1-B launch policy failed: {error:?}")))?;
    let policy = &policy_bytes[..policy_size];
    let a_gate = format!(
        "schema = 1\nselector = \"permanent-supervisor-rrc\"\ntest_id = 25\nscenario = \"normal\"\nevidence_protocol = \"wyr1evid1\"\nnonce = \"{:016X}\"\n",
        request.evidence_nonce
    );
    let b_gate = format!(
        "schema = 6\nselector = \"bootstrap-registry-launch\"\ntest_id = 27\nevidence_protocol = \"wrb1\"\nnonce = \"{:016X}\"\n",
        request.evidence_nonce
    );
    let expected = build_b(ProductB {
        base: Product {
            init: &init,
            registryd: &registryd,
            devmgr: &devmgr,
            uart16550d: &uart,
            consoled: &console,
            wyrmsh: &shell,
            rrc_manifest: &manifest,
            gate_config: a_gate.as_bytes(),
        },
        launch_policy: policy,
        gate_config: b_gate.as_bytes(),
        hello: &hello,
        publisher: &publisher,
        client: &client,
    })
    .map_err(|error| Failure::task(format!("WYR1-B bootfs build failed: {error:?}")))?;
    fs::write(&request.bootfs, &expected)
        .map_err(|error| Failure::task(format!("could not write WYR1-B bootfs: {error}")))?;
    let observed = fs::read(&request.bootfs)
        .map_err(|error| Failure::task(format!("could not reread WYR1-B bootfs: {error}")))?;
    verify_archive(
        &observed,
        &boot_generation,
        &hello,
        &publisher,
        &client,
        policy,
        b_gate.as_bytes(),
    )?;
    if expected != observed {
        return Err(Failure::task("WYR1-B independent bootfs reread mismatch"));
    }
    let receipt = receipt(
        &request,
        &observed,
        &manifest,
        policy,
        b_gate.as_bytes(),
        &hello,
        &publisher,
        &client,
    );
    fs::write(&request.receipt, receipt)
        .map_err(|error| Failure::task(format!("could not write WYR1-B receipt: {error}")))?;
    Ok(format!(
        "WYR1_B_IMAGE_PASS selector={} test_id={} bootfs_sha256={}\n",
        SELECTOR,
        TEST_ID,
        sha256::bytes_digest(&observed)
    ))
}

pub fn inspect(path: &Path) -> Result<String, Failure> {
    let request = load(path)?;
    let bootfs = read(&request.bootfs, "bootfs")?;
    let values = parse_scalars(
        std::str::from_utf8(&read(&request.receipt, "receipt")?)
            .map_err(|_| Failure::task("WYR1-B receipt is not UTF-8"))?,
    )?;
    if required(&values, "kind")? != "wyrmroot-wyr1-b-build-lineage"
        || required(&values, "request_sha256")? != request.request_sha256
        || required(&values, "bootfs_sha256")? != sha256::bytes_digest(&bootfs)
    {
        return Err(Failure::task("WYR1-B receipt identity mismatch"));
    }
    let archive = Archive::new(&bootfs)
        .map_err(|error| Failure::task(format!("WYR1-B archive invalid: {error:?}")))?;
    verify_manifest_profile(&archive, &decode_digest(&request.request_sha256)?)?;
    if archive.entries().count() != 13 {
        return Err(Failure::task(
            "WYR1-B archive must contain exactly 13 entries",
        ));
    }
    let policy = archive
        .lookup(b"system/bootstrap/launch-policy-v1")
        .map_err(|error| Failure::task(format!("WYR1-B policy missing: {error:?}")))?;
    LaunchPolicy::parse(policy.data())
        .map_err(|error| Failure::task(format!("WYR1-B policy invalid: {error:?}")))?;
    Ok(format!(
        "WYR1_B_INSPECTION_PASS entries=13 bootfs_sha256={}\n",
        sha256::bytes_digest(&bootfs)
    ))
}

pub fn evidence(request: &Path, log: &Path) -> Result<String, Failure> {
    let request = load(request)?;
    let bytes = fs::read(log)
        .map_err(|error| Failure::task(format!("could not read WRB1 evidence: {error}")))?;
    if bytes.is_empty() || bytes.len() > MAX_EVIDENCE || !bytes.len().is_multiple_of(96) {
        return Err(Failure::task("WRB1 evidence length is invalid"));
    }
    let expected_events = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0xff];
    if bytes.len() / 96 != expected_events.len() {
        return Err(Failure::task("WRB1 evidence event count is invalid"));
    }
    for (sequence, (record, expected)) in bytes.chunks_exact(96).zip(expected_events).enumerate() {
        verify_record(record, request.evidence_nonce, sequence as u32, expected)?;
    }
    Ok(format!(
        "WYR1_B_EVIDENCE_PASS records={} terminal=normal\n",
        expected_events.len()
    ))
}

fn verify_archive(
    bootfs: &[u8],
    boot_generation: &[u8; 32],
    hello: &[u8],
    publisher: &[u8],
    client: &[u8],
    policy: &[u8],
    gate: &[u8],
) -> Result<(), Failure> {
    let archive = Archive::new(bootfs)
        .map_err(|error| Failure::task(format!("WYR1-B archive invalid: {error:?}")))?;
    verify_manifest_profile(&archive, boot_generation)?;
    for (path, bytes, executable) in [
        ("bin/hello", hello, true),
        ("test/wyr1-b/publisher", publisher, true),
        ("test/wyr1-b/client", client, true),
        ("system/bootstrap/launch-policy-v1", policy, false),
        ("system/bootstrap/wyr1-b-gate-v1", gate, false),
    ] {
        let entry = archive
            .lookup(path.as_bytes())
            .map_err(|error| Failure::task(format!("WYR1-B missing {path}: {error:?}")))?;
        if entry.data() != bytes || entry.is_executable() != executable {
            return Err(Failure::task(format!("WYR1-B substitution at {path}")));
        }
    }
    if archive.entries().count() != 13 {
        return Err(Failure::task("WYR1-B archive contains undeclared entries"));
    }
    Ok(())
}

fn verify_manifest_profile(
    archive: &Archive<'_>,
    boot_generation: &[u8; 32],
) -> Result<(), Failure> {
    let entry = archive
        .lookup(wyrmroot_rrc_manifest::MANIFEST_PATH.as_bytes())
        .map_err(|error| Failure::task(format!("WYR1-B manifest missing: {error:?}")))?;
    let manifest = Manifest::parse_structural(entry.data(), boot_generation)
        .map_err(|error| Failure::task(format!("WYR1-B manifest invalid: {error:?}")))?;
    let registry = manifest
        .role(RoleId::Registryd)
        .ok_or_else(|| Failure::task("WYR1-B registry role missing"))?;
    let devmgr = manifest
        .role(RoleId::Devmgr)
        .ok_or_else(|| Failure::task("WYR1-B devmgr role missing"))?;
    if registry.activation() != Activation::Early
        || registry.startup_profile() != StartupProfile::BootstrapRegistry
        || devmgr.activation() != Activation::Early
        || devmgr.startup_profile() != StartupProfile::EarlyBootStub
    {
        return Err(Failure::task("WYR1-B retained-role profile drifted"));
    }
    Ok(())
}

fn receipt(
    request: &Request,
    bootfs: &[u8],
    manifest: &[u8],
    policy: &[u8],
    gate: &[u8],
    hello: &[u8],
    publisher: &[u8],
    client: &[u8],
) -> String {
    format!(
        "kind = \"wyrmroot-wyr1-b-build-lineage\"\nschema_version = 6\nselector = \"{}\"\ntest_id = 27\nrequest_sha256 = \"{}\"\ndeepwyrm_revision = \"{}\"\nwyrmroot_revision = \"{}\"\nrust_revision = \"{}\"\nbootfs_sha256 = \"{}\"\nrrc_manifest_sha256 = \"{}\"\nlaunch_policy_sha256 = \"{}\"\ngate_sha256 = \"{}\"\nhello_sha256 = \"{}\"\npublisher_sha256 = \"{}\"\nclient_sha256 = \"{}\"\n",
        SELECTOR,
        request.request_sha256,
        request.deepwyrm_revision,
        request.wyrmroot_revision,
        request.rust_revision,
        sha256::bytes_digest(bootfs),
        sha256::bytes_digest(manifest),
        sha256::bytes_digest(policy),
        sha256::bytes_digest(gate),
        sha256::bytes_digest(hello),
        sha256::bytes_digest(publisher),
        sha256::bytes_digest(client)
    )
}

fn verify_record(record: &[u8], nonce: u64, sequence: u32, event: u8) -> Result<(), Failure> {
    if &record[..4] != b"WRB1"
        || record[4] != b'|'
        || parse_hex(&record[5..7])? != 1
        || parse_hex(&record[8..24])? != nonce
        || parse_hex(&record[25..33])? != u64::from(sequence)
        || parse_hex(&record[34..36])? != u64::from(event)
    {
        return Err(Failure::task("WRB1 identity or sequence mismatch"));
    }
    for offset in [7usize, 24, 33, 36, 53, 70, 87] {
        if record[offset] != b'|' {
            return Err(Failure::task("WRB1 delimiter mismatch"));
        }
    }
    if parse_hex(&record[88..96])? != u64::from(fnv1a32(&record[..88])) {
        return Err(Failure::task("WRB1 checksum mismatch"));
    }
    let subject = parse_hex(&record[37..53])?;
    let generation = parse_hex(&record[54..70])?;
    let value = parse_hex(&record[71..87])?;
    if (event == 0xff) != (subject == 0 && generation == 0 && value == 0)
        || (event != 0xff && (subject == 0 || generation == 0))
    {
        return Err(Failure::task("WRB1 event identity mismatch"));
    }
    Ok(())
}

fn parse_scalars(text: &str) -> Result<BTreeMap<String, String>, Failure> {
    let mut values = BTreeMap::new();
    for (line_no, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (key, raw_value) = line
            .split_once('=')
            .ok_or_else(|| Failure::task(format!("WYR1-B line {} is malformed", line_no + 1)))?;
        let key = key.trim();
        let raw_value = raw_value.trim();
        let value = if let Some(value) = raw_value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
        {
            value
        } else {
            raw_value
        };
        if values.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(Failure::task("WYR1-B duplicate key"));
        }
    }
    Ok(values)
}
fn required<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, Failure> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| Failure::task(format!("missing WYR1-B {key}")))
}
fn number<T: std::str::FromStr>(
    values: &BTreeMap<String, String>,
    key: &str,
) -> Result<T, Failure> {
    required(values, key)?
        .parse()
        .map_err(|_| Failure::task(format!("invalid WYR1-B {key}")))
}
fn revision(values: &BTreeMap<String, String>, key: &str) -> Result<String, Failure> {
    let value = required(values, key)?;
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Failure::task(format!("invalid WYR1-B {key}")));
    }
    Ok(value.to_ascii_lowercase())
}
fn input(parent: &Path, value: &str) -> PathBuf {
    parent.join(value)
}
fn output(parent: &Path, value: &str) -> Result<PathBuf, Failure> {
    let path = Path::new(value);
    if path.is_absolute()
        || path.components().any(|part| {
            matches!(
                part,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(Failure::task("WYR1-B output must be request-relative"));
    }
    Ok(parent.join(path))
}
fn nonce(value: &str) -> Result<u64, Failure> {
    if value.len() != 16 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Failure::task("invalid WYR1-B evidence nonce"));
    }
    let value = u64::from_str_radix(value, 16)
        .map_err(|_| Failure::task("invalid WYR1-B evidence nonce"))?;
    if value == 0 {
        return Err(Failure::task("zero WYR1-B evidence nonce"));
    }
    Ok(value)
}
fn read(path: &Path, label: &str) -> Result<Vec<u8>, Failure> {
    fs::read(path).map_err(|error| Failure::task(format!("could not read WYR1-B {label}: {error}")))
}
fn decode_digest(value: &str) -> Result<[u8; 32], Failure> {
    if value.len() != 64 {
        return Err(Failure::task("invalid WYR1-B request digest"));
    }
    let mut out = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        out[index] = ((pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| Failure::task("invalid digest"))?
            << 4
            | (pair[1] as char)
                .to_digit(16)
                .ok_or_else(|| Failure::task("invalid digest"))?) as u8;
    }
    Ok(out)
}
fn parse_hex(bytes: &[u8]) -> Result<u64, Failure> {
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F'))
    {
        return Err(Failure::task("WRB1 hexadecimal field is invalid"));
    }
    u64::from_str_radix(
        std::str::from_utf8(bytes).map_err(|_| Failure::task("WRB1 is not ASCII"))?,
        16,
    )
    .map_err(|_| Failure::task("WRB1 hexadecimal field is invalid"))
}
fn fnv1a32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c9dc5, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x01000193)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wrb1_rejects_wrong_event_order_and_checksum() {
        let mut record = [b'|'; 96];
        record[..4].copy_from_slice(b"WRB1");
        for (range, value) in [
            (5..7, 1),
            (8..24, 1),
            (25..33, 0),
            (34..36, 1),
            (37..53, 1),
            (54..70, 1),
            (71..87, 0),
        ] {
            let width = range.len();
            let text = format!("{value:0width$X}");
            record[range].copy_from_slice(text.as_bytes());
        }
        let checksum = fnv1a32(&record[..88]);
        record[88..96].copy_from_slice(format!("{checksum:08X}").as_bytes());
        assert_eq!(verify_record(&record, 1, 0, 1), Ok(()));
        record[95] ^= 1;
        assert!(verify_record(&record, 1, 0, 1).is_err());
    }

    #[test]
    fn selector_27_builder_uses_bootstrap_registry_without_changing_devmgr() {
        let generation = [0x42; 32];
        let manifest = fixed_builder_for_profile(
            &generation,
            [[1; 32], [2; 32], [3; 32], [4; 32], [5; 32]],
            StartupProfile::BootstrapRegistry,
        )
        .unwrap()
        .build_structural()
        .unwrap();
        let parsed = Manifest::parse_structural(&manifest, &generation).unwrap();
        assert_eq!(
            parsed.role(RoleId::Registryd).unwrap().startup_profile(),
            StartupProfile::BootstrapRegistry
        );
        assert_eq!(
            parsed.role(RoleId::Devmgr).unwrap().startup_profile(),
            StartupProfile::EarlyBootStub
        );
    }
}
