//! WYR1-A request, image, receipt, and structured host-evidence plumbing.
//!
//! This is deliberately separate from `h_request`/`h_integration`: schema 5
//! and the WYR1 selector/scenario are not an extension of the WYR0-H wire or
//! selector surface.  WYR0 callers therefore retain their exact parser and
//! output behavior.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::error::Failure;
use crate::sha256;

pub const SCHEMA_VERSION: u32 = 5;
pub const SELECTOR: &str = "permanent-supervisor-rrc";
pub const TEST_ID: u32 = 25;
pub const EVIDENCE_PROTOCOL: &str = "wyr1evid1";
pub const RECEIPT_KIND: &str = "wyrmroot-wyr1-a-build-lineage";
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_EVIDENCE_BYTES: usize = 16 * 1024 * 1024;

const REQUIRED_KEYS: &[&str] = &[
    "schema_version",
    "deepwyrm_revision",
    "wyrmroot_revision",
    "rust_revision",
    "selector",
    "test_id",
    "scenario",
    "timeout_seconds",
    "loader",
    "kernel",
    "symbols",
    "bootstrap",
    "init",
    "registryd",
    "devmgr",
    "uart16550d",
    "consoled",
    "wyrmsh",
    "rrc_manifest",
    "bootfs",
    "esp",
    "provenance",
    "ovmf_code",
    "ovmf_vars_template",
    "run_directory",
    "evidence_nonce",
    "receipt",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scenario {
    Normal,
    DegradedRecovery,
}

impl Scenario {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::DegradedRecovery => "degraded_recovery",
        }
    }
    fn parse(value: &str) -> Result<Self, Failure> {
        match value {
            "normal" => Ok(Self::Normal),
            "degraded_recovery" => Ok(Self::DegradedRecovery),
            _ => Err(Failure::task(
                "WYR1 scenario must be normal or degraded_recovery",
            )),
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    Default,
    Smp,
}

impl Profile {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Smp => "smp",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub path: PathBuf,
    pub request_sha256: String,
    pub deepwyrm_revision: String,
    pub wyrmroot_revision: String,
    pub rust_revision: String,
    pub selector: String,
    pub test_id: u32,
    pub scenario: Scenario,
    pub timeout_seconds: u64,
    pub loader: PathBuf,
    pub kernel: PathBuf,
    pub symbols: PathBuf,
    pub bootstrap: PathBuf,
    pub init: PathBuf,
    pub registryd: PathBuf,
    pub devmgr: PathBuf,
    pub uart16550d: PathBuf,
    pub consoled: PathBuf,
    pub wyrmsh: PathBuf,
    pub rrc_manifest: PathBuf,
    pub bootfs: PathBuf,
    pub esp: PathBuf,
    pub provenance: PathBuf,
    pub ovmf_code: PathBuf,
    pub ovmf_vars_template: PathBuf,
    pub run_directory: PathBuf,
    pub evidence_nonce: u64,
    pub receipt: PathBuf,
}

impl Request {
    pub fn artifact_paths(&self) -> [(&'static str, &Path); 7] {
        [
            ("system/init", &self.init),
            ("system/registryd", &self.registryd),
            ("system/devmgr", &self.devmgr),
            ("system/uart16550d", &self.uart16550d),
            ("system/consoled", &self.consoled),
            ("system/wyrmsh", &self.wyrmsh),
            ("system/bootstrap/rrc-a-v1", &self.rrc_manifest),
        ]
    }
}

pub fn load(path: &Path) -> Result<Request, Failure> {
    let bytes = fs::read(path)
        .map_err(|error| Failure::task(format!("could not read WYR1 request: {error}")))?;
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
        return Err(Failure::task(
            "WYR1 request is empty or exceeds its size limit",
        ));
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| Failure::task("WYR1 request is not UTF-8"))?;
    let values = parse_scalars(text)?;
    let expected = REQUIRED_KEYS.iter().copied().collect::<BTreeSet<_>>();
    let actual = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if expected != actual {
        return Err(Failure::task(format!(
            "WYR1 request key set drifted (missing: {}; unknown: {})",
            expected
                .difference(&actual)
                .copied()
                .collect::<Vec<_>>()
                .join(", "),
            actual
                .difference(&expected)
                .copied()
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    let schema = number::<u32>(&values, "schema_version")?;
    if schema != SCHEMA_VERSION {
        return Err(Failure::task("WYR1 request schema_version must be 5"));
    }
    if required(&values, "selector")? != SELECTOR || number::<u32>(&values, "test_id")? != TEST_ID {
        return Err(Failure::task(
            "WYR1 request selector/test_id do not name WYR1-A",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| Failure::task("WYR1 request has no parent"))?;
    let request = Request {
        path: path.to_path_buf(),
        request_sha256: sha256::bytes_digest(&bytes),
        deepwyrm_revision: revision(&values, "deepwyrm_revision")?,
        wyrmroot_revision: revision(&values, "wyrmroot_revision")?,
        rust_revision: revision(&values, "rust_revision")?,
        selector: SELECTOR.to_owned(),
        test_id: TEST_ID,
        scenario: Scenario::parse(required(&values, "scenario")?)?,
        timeout_seconds: bounded_number(&values, "timeout_seconds", 1, 600)?,
        loader: input(parent, required(&values, "loader")?),
        kernel: input(parent, required(&values, "kernel")?),
        symbols: input(parent, required(&values, "symbols")?),
        bootstrap: input(parent, required(&values, "bootstrap")?),
        init: input(parent, required(&values, "init")?),
        registryd: input(parent, required(&values, "registryd")?),
        devmgr: input(parent, required(&values, "devmgr")?),
        uart16550d: input(parent, required(&values, "uart16550d")?),
        consoled: input(parent, required(&values, "consoled")?),
        wyrmsh: input(parent, required(&values, "wyrmsh")?),
        rrc_manifest: input(parent, required(&values, "rrc_manifest")?),
        bootfs: output(parent, required(&values, "bootfs")?, "bootfs")?,
        esp: output(parent, required(&values, "esp")?, "esp")?,
        provenance: output(parent, required(&values, "provenance")?, "provenance")?,
        ovmf_code: input(parent, required(&values, "ovmf_code")?),
        ovmf_vars_template: input(parent, required(&values, "ovmf_vars_template")?),
        run_directory: output(parent, required(&values, "run_directory")?, "run_directory")?,
        evidence_nonce: parse_nonce(required(&values, "evidence_nonce")?)?,
        receipt: output(parent, required(&values, "receipt")?, "receipt")?,
    };
    reject_output_aliases(&request)?;
    Ok(request)
}

fn parse_scalars(text: &str) -> Result<BTreeMap<String, String>, Failure> {
    let mut values = BTreeMap::new();
    for (line_no, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            return Err(Failure::task(format!(
                "WYR1 request line {} uses a section",
                line_no + 1
            )));
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            Failure::task(format!(
                "WYR1 request line {} is not an assignment",
                line_no + 1
            ))
        })?;
        let key = key.trim();
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(Failure::task(format!(
                "WYR1 request line {} has an invalid key",
                line_no + 1
            )));
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .ok_or_else(|| {
                Failure::task(format!(
                    "WYR1 request line {} requires a quoted scalar",
                    line_no + 1
                ))
            })?;
        if value.contains(['"', '\\'])
            || value.chars().any(char::is_control)
            || values.insert(key.to_owned(), value.to_owned()).is_some()
        {
            return Err(Failure::task(format!(
                "WYR1 request line {} has an invalid or duplicate scalar",
                line_no + 1
            )));
        }
    }
    Ok(values)
}

fn required<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, Failure> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| Failure::task(format!("WYR1 request is missing '{key}'")))
}
fn number<T: std::str::FromStr>(
    values: &BTreeMap<String, String>,
    key: &str,
) -> Result<T, Failure> {
    required(values, key)?
        .parse()
        .map_err(|_| Failure::task(format!("WYR1 request '{key}' is not a valid integer")))
}
fn bounded_number(
    values: &BTreeMap<String, String>,
    key: &str,
    min: u64,
    max: u64,
) -> Result<u64, Failure> {
    let value = number::<u64>(values, key)?;
    if !(min..=max).contains(&value) {
        return Err(Failure::task(format!(
            "WYR1 request '{key}' is outside its bounded range"
        )));
    }
    Ok(value)
}
fn revision(values: &BTreeMap<String, String>, key: &str) -> Result<String, Failure> {
    let value = required(values, key)?;
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Failure::task(format!(
            "WYR1 request '{key}' must be lowercase Git revision"
        )));
    }
    Ok(value.to_owned())
}
fn parse_nonce(value: &str) -> Result<u64, Failure> {
    if value.len() != 16
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase())
    {
        return Err(Failure::task(
            "WYR1 evidence_nonce must be 16 uppercase hexadecimal digits",
        ));
    }
    u64::from_str_radix(value, 16)
        .map_err(|_| Failure::task("WYR1 evidence_nonce is invalid"))
        .and_then(|nonce| {
            if nonce == 0 {
                Err(Failure::task("WYR1 evidence_nonce must be nonzero"))
            } else {
                Ok(nonce)
            }
        })
}
fn input(parent: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        parent.join(path)
    }
}
fn output(parent: &Path, value: &str, label: &str) -> Result<PathBuf, Failure> {
    let path = Path::new(value);
    if path.is_absolute()
        || path.as_os_str().is_empty()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(Failure::task(format!(
            "WYR1 {label} must be request-relative and non-escaping"
        )));
    }
    Ok(parent.join(path))
}
fn reject_output_aliases(request: &Request) -> Result<(), Failure> {
    let outputs = [
        &request.bootfs,
        &request.esp,
        &request.provenance,
        &request.run_directory,
        &request.receipt,
    ];
    for (index, left) in outputs.iter().enumerate() {
        for right in outputs.iter().skip(index + 1) {
            if left == right || left.starts_with(right) || right.starts_with(left) {
                return Err(Failure::task("WYR1 output paths overlap"));
            }
        }
    }
    Ok(())
}

/// Build the exact WYR1 archive from explicit request artifact paths.
pub fn build_bootfs(request: &Request) -> Result<String, Failure> {
    let read = |path: &Path, label: &str| {
        fs::read(path)
            .map_err(|error| Failure::task(format!("could not read WYR1 {label}: {error}")))
    };
    let init = read(&request.init, "init")?;
    let registryd = read(&request.registryd, "registryd")?;
    let devmgr = read(&request.devmgr, "devmgr")?;
    let uart = read(&request.uart16550d, "uart16550d")?;
    let console = read(&request.consoled, "consoled")?;
    let shell = read(&request.wyrmsh, "wyrmsh")?;
    let manifest = read(&request.rrc_manifest, "rrc_manifest")?;
    let expected = decode_digest(&request.request_sha256)?;
    if manifest.len() < 80 || &manifest[..4] != b"WRRM" || manifest[48..80] != expected {
        return Err(Failure::task(
            "WYR1 WRRM header or boot-generation identity is invalid",
        ));
    }
    let archive = wyrmroot_bootfs::wyr1::build(wyrmroot_bootfs::wyr1::Product {
        init: &init,
        registryd: &registryd,
        devmgr: &devmgr,
        uart16550d: &uart,
        consoled: &console,
        wyrmsh: &shell,
        rrc_manifest: &manifest,
    })
    .map_err(|error| Failure::task(format!("WYR1 bootfs build failed: {error:?}")))?;
    fs::write(&request.bootfs, &archive)
        .map_err(|error| Failure::task(format!("could not write WYR1 bootfs: {error}")))?;
    Ok(sha256::bytes_digest(&archive))
}

fn decode_digest(value: &str) -> Result<[u8; 32], Failure> {
    if value.len() != 64 {
        return Err(Failure::task("request identity is not a SHA-256 digest"));
    }
    let mut output = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex(pair[0])? << 4) | hex(pair[1])?;
    }
    Ok(output)
}
fn hex(byte: u8) -> Result<u8, Failure> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(Failure::task(
            "request identity is not lowercase hexadecimal",
        )),
    }
}

/// One strict lineage receipt. Values are canonical scalar strings and are
/// intentionally external to the WRRM bytes, avoiding self-referential hashes.
pub fn receipt_text(
    request: &Request,
    bootfs_sha256: &str,
    esp_sha256: &str,
    profile: Profile,
) -> Result<String, Failure> {
    let mut lines = vec![
        format!("schema_version = \"1\""),
        format!("kind = \"{RECEIPT_KIND}\""),
        format!("request_sha256 = \"{}\"", request.request_sha256),
        format!("deepwyrm_revision = \"{}\"", request.deepwyrm_revision),
        format!("wyrmroot_revision = \"{}\"", request.wyrmroot_revision),
        format!("rust_revision = \"{}\"", request.rust_revision),
        format!("scenario = \"{}\"", request.scenario.name()),
        format!("profile = \"{}\"", profile.name()),
        format!("bootfs_sha256 = \"{bootfs_sha256}\""),
        format!("esp_sha256 = \"{esp_sha256}\""),
        format!(
            "manifest_sha256 = \"{}\"",
            sha256::file_digest(&request.rrc_manifest)
                .map_err(|error| Failure::task(format!("could not hash manifest: {error}")))?
        ),
        format!("evidence_protocol = \"{EVIDENCE_PROTOCOL}\""),
        format!("evidence_nonce = \"{:016X}\"", request.evidence_nonce),
    ];
    for (label, artifact) in [
        ("loader", &request.loader),
        ("kernel", &request.kernel),
        ("symbols", &request.symbols),
        ("bootstrap", &request.bootstrap),
        ("provenance", &request.provenance),
        ("ovmf_code", &request.ovmf_code),
        ("ovmf_vars_template", &request.ovmf_vars_template),
    ] {
        lines.push(format!(
            "{label}_sha256 = \"{}\"",
            sha256::file_digest(artifact)
                .map_err(|error| Failure::task(format!("could not hash {label}: {error}")))?
        ));
    }
    for (path, artifact) in request.artifact_paths() {
        lines.push(format!(
            "artifact_{}_sha256 = \"{}\"",
            artifact_key(path),
            sha256::file_digest(artifact)
                .map_err(|error| Failure::task(format!("could not hash {path}: {error}")))?
        ));
    }
    lines.push(format!(
        "ovmf_code_sha256 = \"{}\"",
        sha256::file_digest(&request.ovmf_code)
            .map_err(|error| Failure::task(format!("could not hash OVMF code: {error}")))?
    ));
    lines.push(format!(
        "ovmf_vars_template_sha256 = \"{}\"",
        sha256::file_digest(&request.ovmf_vars_template)
            .map_err(|error| Failure::task(format!("could not hash OVMF vars: {error}")))?
    ));
    Ok(format!("{}\n", lines.join("\n")))
}

pub fn write_receipt(request: &Request, text: &str) -> Result<(), Failure> {
    fs::write(&request.receipt, text)
        .map_err(|error| Failure::task(format!("could not write WYR1 receipt: {error}")))
}

/// Re-read a receipt and compare every identity against the request and its
/// current immutable inputs. Unknown/missing/duplicate keys are rejected.
pub fn verify_receipt(request: &Request, profile: Profile) -> Result<(), Failure> {
    let bytes = fs::read(&request.receipt)
        .map_err(|error| Failure::task(format!("could not read WYR1 receipt: {error}")))?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| Failure::task("WYR1 receipt is not UTF-8"))?;
    let values = parse_scalars(text)?;
    let mut expected = vec![
        "schema_version",
        "kind",
        "request_sha256",
        "deepwyrm_revision",
        "wyrmroot_revision",
        "rust_revision",
        "scenario",
        "profile",
        "bootfs_sha256",
        "esp_sha256",
        "manifest_sha256",
        "evidence_protocol",
        "evidence_nonce",
        "loader_sha256",
        "kernel_sha256",
        "symbols_sha256",
        "bootstrap_sha256",
        "provenance_sha256",
        "ovmf_code_sha256",
        "ovmf_vars_template_sha256",
    ];
    for (path, _) in request.artifact_paths() {
        expected.push(Box::leak(
            format!("artifact_{}_sha256", artifact_key(path)).into_boxed_str(),
        ));
    }
    let expected = expected.into_iter().collect::<BTreeSet<_>>();
    let actual = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(Failure::task("WYR1 receipt key set drifted"));
    }
    let check = |key: &str, expected: &str| -> Result<(), Failure> {
        if required(&values, key)? != expected {
            Err(Failure::task(format!(
                "WYR1 receipt field '{key}' mismatch"
            )))
        } else {
            Ok(())
        }
    };
    check("schema_version", "1")?;
    check("kind", RECEIPT_KIND)?;
    check("request_sha256", &request.request_sha256)?;
    check("deepwyrm_revision", &request.deepwyrm_revision)?;
    check("wyrmroot_revision", &request.wyrmroot_revision)?;
    check("rust_revision", &request.rust_revision)?;
    check("scenario", request.scenario.name())?;
    check("profile", profile.name())?;
    check(
        "bootfs_sha256",
        &sha256::file_digest(&request.bootfs)
            .map_err(|error| Failure::task(format!("could not hash bootfs: {error}")))?,
    )?;
    check(
        "esp_sha256",
        &sha256::file_digest(&request.esp)
            .map_err(|error| Failure::task(format!("could not hash ESP: {error}")))?,
    )?;
    check("evidence_protocol", EVIDENCE_PROTOCOL)?;
    check(
        "evidence_nonce",
        &format!("{:016X}", request.evidence_nonce),
    )?;
    for (label, artifact) in [
        ("loader", &request.loader),
        ("kernel", &request.kernel),
        ("symbols", &request.symbols),
        ("bootstrap", &request.bootstrap),
        ("provenance", &request.provenance),
        ("ovmf_code", &request.ovmf_code),
        ("ovmf_vars_template", &request.ovmf_vars_template),
    ] {
        let digest = sha256::file_digest(artifact)
            .map_err(|error| Failure::task(format!("could not hash {label}: {error}")))?;
        check(&format!("{label}_sha256"), &digest)?;
    }
    for (path, artifact) in request.artifact_paths() {
        let digest = sha256::file_digest(artifact)
            .map_err(|error| Failure::task(format!("could not hash {path}: {error}")))?;
        check(&format!("artifact_{}_sha256", artifact_key(path)), &digest)?;
        if path == "system/bootstrap/rrc-a-v1" {
            check("manifest_sha256", &digest)?;
        }
    }
    Ok(())
}

fn artifact_key(path: &str) -> String {
    path.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceRecord {
    pub sequence: u64,
    pub event: Event,
    pub role: u32,
    pub generation: u64,
    pub transaction: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    Ready,
    Reap,
    Restart,
    PermanentFailure,
    Normal,
    Degraded,
}
impl Event {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "READY" => Self::Ready,
            "REAP" => Self::Reap,
            "RESTART" => Self::Restart,
            "PermanentFailure" => Self::PermanentFailure,
            "NORMAL" => Self::Normal,
            "DEGRADED" => Self::Degraded,
            _ => return None,
        })
    }
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ready => "READY",
            Self::Reap => "REAP",
            Self::Restart => "RESTART",
            Self::PermanentFailure => "PermanentFailure",
            Self::Normal => "NORMAL",
            Self::Degraded => "DEGRADED",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceResult {
    pub records: Vec<EvidenceRecord>,
    pub terminal: Event,
}

/// Parse canonical newline-delimited WYR1 evidence. Each non-terminal event
/// carries role/generation/transaction identity; terminal events carry zeros.
/// The checksum is FNV-1a over the line through the final `|` before checksum.
pub fn parse_evidence(
    bytes: &[u8],
    nonce: u64,
    scenario: Scenario,
) -> Result<EvidenceResult, Failure> {
    if bytes.is_empty() || bytes.len() > MAX_EVIDENCE_BYTES {
        return Err(Failure::task(
            "WYR1 evidence is empty or exceeds its size limit",
        ));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| Failure::task("WYR1 evidence is not UTF-8"))?;
    let mut records = Vec::new();
    let mut terminal = None;
    for (expected_sequence, line) in text.lines().enumerate() {
        if terminal.is_some() {
            return Err(Failure::task("WYR1 evidence has records after terminal"));
        }
        let fields: Vec<_> = line.split('|').collect();
        if fields.len() != 8 || fields[0] != EVIDENCE_PROTOCOL {
            return Err(Failure::task("WYR1 evidence framing is invalid"));
        }
        let read = |prefix: &str| {
            fields
                .iter()
                .find_map(|field| field.strip_prefix(prefix))
                .ok_or_else(|| Failure::task("WYR1 evidence field is missing"))
        };
        let got_nonce = u64::from_str_radix(read("nonce=")?, 16)
            .map_err(|_| Failure::task("WYR1 evidence nonce is invalid"))?;
        if got_nonce != nonce || nonce == 0 {
            return Err(Failure::task("WYR1 evidence nonce mismatch"));
        }
        let sequence = read("seq=")?
            .parse::<u64>()
            .map_err(|_| Failure::task("WYR1 evidence sequence is invalid"))?;
        if sequence != expected_sequence as u64 {
            return Err(Failure::task("WYR1 evidence sequence is not contiguous"));
        }
        let event = Event::parse(read("event=")?)
            .ok_or_else(|| Failure::task("WYR1 evidence event is unknown"))?;
        let role = u32::from_str_radix(read("role=")?, 16)
            .map_err(|_| Failure::task("WYR1 evidence role is invalid"))?;
        let generation = u64::from_str_radix(read("generation=")?, 16)
            .map_err(|_| Failure::task("WYR1 evidence generation is invalid"))?;
        let transaction = u64::from_str_radix(read("transaction=")?, 16)
            .map_err(|_| Failure::task("WYR1 evidence transaction is invalid"))?;
        let checksum_text = read("checksum=")?;
        let checksum = u32::from_str_radix(checksum_text, 16)
            .map_err(|_| Failure::task("WYR1 evidence checksum is invalid"))?;
        let prefix = line
            .rsplit_once("|checksum=")
            .ok_or_else(|| Failure::task("WYR1 evidence checksum framing is invalid"))?
            .0;
        if fnv1a32(prefix.as_bytes()) != checksum {
            return Err(Failure::task("WYR1 evidence checksum mismatch"));
        }
        let is_terminal = matches!(event, Event::Normal | Event::Degraded);
        if is_terminal {
            if role != 0 || generation != 0 || transaction != 0 || terminal.replace(event).is_some()
            {
                return Err(Failure::task(
                    "WYR1 terminal evidence identity/order is invalid",
                ));
            }
        } else if role == 0 || generation == 0 || transaction == 0 {
            return Err(Failure::task("WYR1 role evidence identity is invalid"));
        }
        records.push(EvidenceRecord {
            sequence,
            event,
            role,
            generation,
            transaction,
        });
    }
    let terminal = terminal.ok_or_else(|| Failure::task("WYR1 evidence has no terminal result"))?;
    if terminal
        != match scenario {
            Scenario::Normal => Event::Normal,
            Scenario::DegradedRecovery => Event::Degraded,
        }
    {
        return Err(Failure::task(
            "WYR1 terminal scenario does not match request",
        ));
    }
    if !records.iter().any(|record| record.event == Event::Ready) {
        return Err(Failure::task("WYR1 evidence has no READY record"));
    }
    if scenario == Scenario::DegradedRecovery
        && !records
            .iter()
            .any(|record| record.event == Event::PermanentFailure)
    {
        return Err(Failure::task(
            "WYR1 degraded evidence has no PermanentFailure",
        ));
    }
    Ok(EvidenceResult { records, terminal })
}

#[allow(dead_code)]
pub fn encode_evidence_line(
    nonce: u64,
    sequence: u64,
    event: Event,
    role: u32,
    generation: u64,
    transaction: u64,
) -> String {
    let prefix = format!(
        "{EVIDENCE_PROTOCOL}|nonce={nonce:016X}|seq={sequence}|event={}|role={role:08X}|generation={generation:016X}|transaction={transaction:016X}",
        match event {
            Event::Ready => "READY",
            Event::Reap => "REAP",
            Event::Restart => "RESTART",
            Event::PermanentFailure => "PermanentFailure",
            Event::Normal => "NORMAL",
            Event::Degraded => "DEGRADED",
        }
    );
    format!("{prefix}|checksum={:08X}\n", fnv1a32(prefix.as_bytes()))
}
fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5;
    for byte in bytes {
        hash = (hash ^ u32::from(*byte)).wrapping_mul(0x01000193);
    }
    hash
}

/// Keep both profile outcomes: a default failure must not suppress an SMP
/// run (and vice versa).
pub fn join_profiles(
    default: Result<EvidenceResult, Failure>,
    smp: Result<EvidenceResult, Failure>,
) -> Result<(EvidenceResult, EvidenceResult), Failure> {
    match (default, smp) {
        (Ok(default), Ok(smp)) => Ok((default, smp)),
        (left, right) => {
            let mut errors = Vec::new();
            if let Err(error) = left {
                errors.push(format!("default: {}", error.message));
            }
            if let Err(error) = right {
                errors.push(format!("smp: {}", error.message));
            }
            Err(Failure::task(errors.join("; ")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evidence_rejects_gap_checksum_stale_nonce_and_after_terminal() {
        let nonce = 0x0123_4567_89ab_cdef;
        let valid = format!(
            "{}{}",
            encode_evidence_line(nonce, 0, Event::Ready, 1, 1, 2),
            encode_evidence_line(nonce, 1, Event::Normal, 0, 0, 0)
        );
        assert!(parse_evidence(valid.as_bytes(), nonce, Scenario::Normal).is_ok());
        let gap = valid.replace("seq=1", "seq=2");
        assert!(parse_evidence(gap.as_bytes(), nonce, Scenario::Normal).is_err());
        let mut checksum = valid.clone();
        let index = checksum.find("checksum=").unwrap() + "checksum=".len();
        checksum.replace_range(index..index + 1, "0");
        assert!(parse_evidence(checksum.as_bytes(), nonce, Scenario::Normal).is_err());
        assert!(parse_evidence(valid.as_bytes(), nonce + 1, Scenario::Normal).is_err());
        let after = format!(
            "{}{}",
            valid,
            encode_evidence_line(nonce, 2, Event::Reap, 1, 1, 2)
        );
        assert!(parse_evidence(after.as_bytes(), nonce, Scenario::Normal).is_err());
    }
    #[test]
    fn degraded_requires_permanent_failure() {
        let line = encode_evidence_line(1, 0, Event::Ready, 1, 1, 1);
        let terminal = encode_evidence_line(1, 1, Event::Degraded, 0, 0, 0);
        assert!(
            parse_evidence(
                format!("{line}{terminal}").as_bytes(),
                1,
                Scenario::DegradedRecovery
            )
            .is_err()
        );
        let failure = encode_evidence_line(1, 1, Event::PermanentFailure, 1, 1, 1);
        let terminal = encode_evidence_line(1, 2, Event::Degraded, 0, 0, 0);
        assert!(
            parse_evidence(
                format!("{line}{failure}{terminal}").as_bytes(),
                1,
                Scenario::DegradedRecovery
            )
            .is_ok()
        );
    }

    #[test]
    fn checked_fixtures_are_valid_for_both_terminal_scenarios() {
        let nonce = 0x0123_4567_89ab_cdef;
        assert!(
            parse_evidence(
                include_bytes!("../../../tools/xtask/tests/fixtures/wyr1-a-normal.evidence"),
                nonce,
                Scenario::Normal,
            )
            .is_ok()
        );
        assert!(
            parse_evidence(
                include_bytes!("../../../tools/xtask/tests/fixtures/wyr1-a-degraded.evidence"),
                nonce,
                Scenario::DegradedRecovery,
            )
            .is_ok()
        );
    }
}
