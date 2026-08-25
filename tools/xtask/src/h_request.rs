//! Strict, dependency-free parsing for one WYR0-H integration candidate.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use crate::error::Failure;
use crate::sha256;

const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const O_DIRECTORY: i32 = 0o200000;
const O_NOFOLLOW: i32 = 0o400000;
const REQUIRED_KEYS_V2: &[&str] = &[
    "schema_version",
    "deepwyrm_revision",
    "wyrmroot_revision",
    "rust_revision",
    "selector",
    "test_id",
    "expected_outcome",
    "expected_detail",
    "timeout_seconds",
    "loader",
    "kernel",
    "symbols",
    "bootstrap",
    "init0",
    "hello",
    "bootfs",
    "esp",
    "provenance",
    "ovmf_code",
    "ovmf_vars_template",
    "run_directory",
];
const REQUIRED_KEYS_V3: &[&str] = &[
    "schema_version",
    "deepwyrm_revision",
    "wyrmroot_revision",
    "rust_revision",
    "selector",
    "test_id",
    "expected_outcome",
    "expected_detail",
    "timeout_seconds",
    "loader",
    "kernel",
    "symbols",
    "bootstrap",
    "init0",
    "hello",
    "bootfs",
    "esp",
    "provenance",
    "ovmf_code",
    "ovmf_vars_template",
    "run_directory",
    "evidence_protocol",
    "evidence_nonce",
    "required_evidence_mask",
];
const REQUIRED_KEYS_V4: &[&str] = &[
    "schema_version",
    "deepwyrm_revision",
    "wyrmroot_revision",
    "rust_revision",
    "selector",
    "test_id",
    "expected_outcome",
    "expected_detail",
    "timeout_seconds",
    "loader",
    "kernel",
    "symbols",
    "bootstrap",
    "init0",
    "hello",
    "selector_config",
    "selector_asset",
    "bootfs",
    "esp",
    "provenance",
    "ovmf_code",
    "ovmf_vars_template",
    "run_directory",
    "evidence_protocol",
    "evidence_nonce",
    "required_evidence_mask",
    "certificate",
    "capability_summary",
];

pub(crate) const I1_SELECTOR: &str = "smp-runtime-acceptance";
pub(crate) const I1_TEST_ID: u32 = 23;
pub(crate) const I1_EVIDENCE_PROTOCOL: &str = "dwevid1";
pub(crate) const I1_EVIDENCE_NONCE: u64 = 0x0123_4567_89AB_CDEF;
pub(crate) const I1_REQUIRED_EVIDENCE_MASK: u32 = 255;
pub(crate) const I_CAPABILITY_SELECTOR: &str = "native-userspace-capability";
pub(crate) const I_CAPABILITY_TEST_ID: u32 = 24;
pub(crate) const I_CAPABILITY_EVIDENCE_PROTOCOL: &str = "wrcap1";
pub(crate) const I_CAPABILITY_REQUIRED_EVIDENCE_MASK: u32 = 0x03FF;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EvidenceProtocol {
    Dwevid1,
    Wrcap1,
}

impl EvidenceProtocol {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Dwevid1 => I1_EVIDENCE_PROTOCOL,
            Self::Wrcap1 => I_CAPABILITY_EVIDENCE_PROTOCOL,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExpectedOutcome {
    Pass,
    Fail,
    Panic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EvidenceRequest {
    pub(crate) protocol: EvidenceProtocol,
    pub(crate) nonce: u64,
    pub(crate) required_mask: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CapabilityRequest {
    pub(crate) selector_config: PathBuf,
    pub(crate) selector_asset: PathBuf,
    pub(crate) certificate: PathBuf,
    pub(crate) capability_summary: PathBuf,
}

impl ExpectedOutcome {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Panic => "panic",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HRequest {
    pub(crate) path: PathBuf,
    pub(crate) request_sha256: String,
    pub(crate) schema_version: u32,
    pub(crate) deepwyrm_revision: String,
    pub(crate) wyrmroot_revision: String,
    pub(crate) rust_revision: String,
    pub(crate) selector: String,
    pub(crate) test_id: u32,
    pub(crate) expected_outcome: ExpectedOutcome,
    pub(crate) expected_detail: u32,
    pub(crate) timeout_seconds: u64,
    pub(crate) loader: PathBuf,
    pub(crate) kernel: PathBuf,
    pub(crate) symbols: PathBuf,
    pub(crate) bootstrap: PathBuf,
    pub(crate) init0: PathBuf,
    pub(crate) hello: PathBuf,
    pub(crate) bootfs: PathBuf,
    pub(crate) esp: PathBuf,
    pub(crate) provenance: PathBuf,
    pub(crate) ovmf_code: PathBuf,
    pub(crate) ovmf_vars_template: PathBuf,
    pub(crate) run_directory: PathBuf,
    pub(crate) evidence: Option<EvidenceRequest>,
    pub(crate) capability: Option<CapabilityRequest>,
}

/// Stable request-root capability used for every WYR0-H output operation.
///
/// The request keeps lexical, request-relative output names for evidence. Actual traversal is
/// rooted at this already-open directory and rejects symlink components. Renaming or replacing a
/// checked pathname therefore cannot redirect a later create outside the admitted request root.
#[derive(Debug)]
pub(crate) struct CheckedOutputRoot {
    path: PathBuf,
    directory: fs::File,
}

#[derive(Debug)]
pub(crate) struct CheckedOutputTarget {
    parent: fs::File,
    name: OsString,
}

#[derive(Clone, Copy)]
enum MissingParent {
    Reject,
    Absent,
    Create,
}

impl CheckedOutputTarget {
    /// Returns a procfs path rooted at the already-open parent directory.
    ///
    /// The target must remain alive while the path is used so its parent descriptor remains
    /// valid. The final component is still opened with create-new or no-follow semantics.
    pub(crate) fn path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.parent.as_raw_fd())).join(&self.name)
    }
}

impl CheckedOutputRoot {
    pub(crate) fn open(request: &HRequest) -> Result<Self, Failure> {
        let root = request
            .path
            .parent()
            .ok_or_else(|| Failure::task("WYR0-H request has no parent directory"))?;
        let lexical_root = root.to_path_buf();
        let root = fs::canonicalize(root).map_err(|error| {
            Failure::task(format!("could not resolve WYR0-H request root: {error}"))
        })?;
        let expected = fs::metadata(&root).map_err(|error| {
            Failure::task(format!("could not stat WYR0-H request root: {error}"))
        })?;
        let directory = open_directory(&root, "WYR0-H request root")?;
        let opened = directory.metadata().map_err(|error| {
            Failure::task(format!(
                "could not stat opened WYR0-H request root: {error}"
            ))
        })?;
        if !same_file(&expected, &opened) {
            return Err(Failure::task(
                "WYR0-H request root changed while it was being opened",
            ));
        }
        Ok(Self {
            path: lexical_root,
            directory,
        })
    }

    pub(crate) fn target(&self, path: &Path, label: &str) -> Result<CheckedOutputTarget, Failure> {
        self.target_with_missing_parent(path, label, MissingParent::Reject)?
            .ok_or_else(|| Failure::task(format!("WYR0-H {label} parent does not exist")))
    }

    fn target_with_missing_parent(
        &self,
        path: &Path,
        label: &str,
        missing_parent: MissingParent,
    ) -> Result<Option<CheckedOutputTarget>, Failure> {
        let relative = path.strip_prefix(&self.path).map_err(|_| {
            Failure::task(format!(
                "WYR0-H {label} is not inside the admitted request root"
            ))
        })?;
        let mut components = relative
            .components()
            .filter_map(|component| match component {
                Component::CurDir => None,
                Component::Normal(component) => Some(Ok(component)),
                _ => Some(Err(Failure::task(format!(
                    "WYR0-H {label} is not a normalized request-relative output"
                )))),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let name = components
            .pop()
            .ok_or_else(|| Failure::task(format!("WYR0-H {label} has no file name")))?;
        let mut parent = self.directory.try_clone().map_err(|error| {
            Failure::task(format!(
                "could not clone WYR0-H request-root descriptor: {error}"
            ))
        })?;
        for component in components {
            parent = match open_directory_child_io(&parent, component) {
                Ok(directory) => directory,
                Err(error) if error.kind() == io::ErrorKind::NotFound => match missing_parent {
                    MissingParent::Reject => return Err(open_directory_failure(label, error)),
                    MissingParent::Absent => return Ok(None),
                    MissingParent::Create => {
                        let child = directory_child_path(&parent, component);
                        match fs::create_dir(&child) {
                            Ok(()) => {}
                            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                            Err(error) => {
                                return Err(Failure::task(format!(
                                    "could not create {label} parent directory: {error}"
                                )));
                            }
                        }
                        open_directory_child(&parent, component, label)?
                    }
                },
                Err(error) => return Err(open_directory_failure(label, error)),
            };
        }
        Ok(Some(CheckedOutputTarget {
            parent,
            name: name.to_os_string(),
        }))
    }

    pub(crate) fn directory_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
    }

    pub(crate) fn create_new_file(
        &self,
        path: &Path,
        label: &str,
        read: bool,
        write: bool,
    ) -> Result<fs::File, Failure> {
        let target = self
            .target_with_missing_parent(path, label, MissingParent::Create)?
            .ok_or_else(|| Failure::task(format!("WYR0-H {label} parent does not exist")))?;
        OpenOptions::new()
            .read(read)
            .write(write)
            .create_new(true)
            .custom_flags(O_NOFOLLOW)
            .open(target.path())
            .map_err(|error| Failure::task(format!("could not create {label}: {error}")))
    }

    pub(crate) fn open_regular_file(
        &self,
        path: &Path,
        label: &str,
        read: bool,
        write: bool,
    ) -> Result<fs::File, Failure> {
        let target = self.target(path, label)?;
        let file = OpenOptions::new()
            .read(read)
            .write(write)
            .custom_flags(O_NOFOLLOW)
            .open(target.path())
            .map_err(|error| Failure::task(format!("could not open {label}: {error}")))?;
        let metadata = file
            .metadata()
            .map_err(|error| Failure::task(format!("could not stat {label}: {error}")))?;
        if !metadata.file_type().is_file() {
            return Err(Failure::task(format!(
                "WYR0-H {label} must be a real regular file"
            )));
        }
        Ok(file)
    }

    pub(crate) fn create_dir(&self, path: &Path, label: &str) -> Result<(), Failure> {
        let target = self
            .target_with_missing_parent(path, label, MissingParent::Create)?
            .ok_or_else(|| Failure::task(format!("WYR0-H {label} parent does not exist")))?;
        fs::create_dir(target.path())
            .map_err(|error| Failure::task(format!("could not create {label}: {error}")))
    }

    pub(crate) fn is_dir(&self, path: &Path, label: &str) -> Result<bool, Failure> {
        if !self.exists(path, label)? {
            return Ok(false);
        }
        let target = self.target(path, label)?;
        open_directory(&target.path(), label).map(|_| true)
    }

    pub(crate) fn exists(&self, path: &Path, label: &str) -> Result<bool, Failure> {
        let Some(target) = self.target_with_missing_parent(path, label, MissingParent::Absent)?
        else {
            return Ok(false);
        };
        match fs::symlink_metadata(target.path()) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(Failure::task(format!(
                "could not inspect WYR0-H {label}: {error}"
            ))),
        }
    }

    pub(crate) fn remove_file(&self, path: &Path, label: &str) {
        if let Ok(target) = self.target(path, label) {
            let _ = fs::remove_file(target.path());
        }
    }
}

fn open_directory(path: &Path, label: &str) -> Result<fs::File, Failure> {
    open_directory_io(path).map_err(|error| open_directory_failure(label, error))
}

fn open_directory_io(path: &Path) -> io::Result<fs::File> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW)
        .open(path)?;
    let metadata = directory.metadata()?;
    if !metadata.file_type().is_dir() {
        return Err(io::Error::other("opened object is not a real directory"));
    }
    Ok(directory)
}

fn open_directory_failure(label: &str, error: io::Error) -> Failure {
    Failure::task(format!("could not open {label}: {error}"))
}

fn directory_child_path(parent: &fs::File, component: &OsStr) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd())).join(component)
}

fn open_directory_child(
    parent: &fs::File,
    component: &OsStr,
    label: &str,
) -> Result<fs::File, Failure> {
    open_directory_io(&directory_child_path(parent, component))
        .map_err(|error| open_directory_failure(label, error))
}

fn open_directory_child_io(parent: &fs::File, component: &OsStr) -> io::Result<fs::File> {
    open_directory_io(&directory_child_path(parent, component))
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

pub(crate) fn load(path: &Path) -> Result<HRequest, Failure> {
    let path = canonical_regular(path, "WYR0-H request", MAX_REQUEST_BYTES)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(&path)
        .map_err(|error| Failure::task(format!("could not open WYR0-H request: {error}")))?;
    let metadata = file
        .metadata()
        .map_err(|error| Failure::task(format!("could not stat WYR0-H request: {error}")))?;
    if metadata.len() == 0 || metadata.len() > MAX_REQUEST_BYTES {
        return Err(Failure::task(
            "WYR0-H request must be nonempty and within its size limit",
        ));
    }
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|error| Failure::task(format!("could not read WYR0-H request: {error}")))?;
    if u64::try_from(text.len()).ok() != Some(metadata.len()) {
        return Err(Failure::task(
            "WYR0-H request changed length while its opened bytes were read",
        ));
    }
    let request_sha256 = sha256::bytes_digest(text.as_bytes());
    let values = parse(&text)?;
    let schema_version = number::<u32>(&values, "schema_version")?;
    let required_keys = match schema_version {
        2 => REQUIRED_KEYS_V2,
        3 => REQUIRED_KEYS_V3,
        4 => REQUIRED_KEYS_V4,
        _ => {
            return Err(Failure::task(
                "WYR0-H acceptance commands require schema_version = 2, 3, or 4",
            ));
        }
    };
    let expected = required_keys.iter().copied().collect::<BTreeSet<_>>();
    let actual = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual != expected {
        let unknown = actual.difference(&expected).copied().collect::<Vec<_>>();
        let missing = expected.difference(&actual).copied().collect::<Vec<_>>();
        return Err(Failure::task(format!(
            "WYR0-H request key set drifted (missing: {}; unknown: {})",
            missing.join(", "),
            unknown.join(", ")
        )));
    }
    let parent = path
        .parent()
        .ok_or_else(|| Failure::task("WYR0-H request has no parent directory"))?
        .to_path_buf();
    let selector = selector(&values)?;
    let test_id = number::<u32>(&values, "test_id")?;
    let expected_outcome = expected_outcome(&values)?;
    let expected_detail = number::<u32>(&values, "expected_detail")?;
    let evidence = match schema_version {
        2 => {
            if selector == I1_SELECTOR {
                return Err(Failure::task(
                    "WYR0-H I1 selector requires schema_version = 3",
                ));
            }
            if selector == I_CAPABILITY_SELECTOR {
                return Err(Failure::task(
                    "WYR0-H WYR0-I capability selector requires schema_version = 4",
                ));
            }
            None
        }
        3 => {
            if selector != I1_SELECTOR || test_id != I1_TEST_ID {
                return Err(Failure::task(format!(
                    "WYR0-H schema_version = 3 is reserved for selector '{I1_SELECTOR}' with test_id {I1_TEST_ID}"
                )));
            }
            if expected_outcome != ExpectedOutcome::Pass || expected_detail != 0 {
                return Err(Failure::task(
                    "WYR0-H schema_version = 3 requires expected_outcome = \"pass\" and expected_detail = 0",
                ));
            }
            if required(&values, "evidence_protocol")? != I1_EVIDENCE_PROTOCOL {
                return Err(Failure::task(format!(
                    "WYR0-H I1 evidence_protocol must be '{I1_EVIDENCE_PROTOCOL}'"
                )));
            }
            let nonce = evidence_nonce(&values)?;
            let required_mask = number::<u32>(&values, "required_evidence_mask")?;
            if required_mask != I1_REQUIRED_EVIDENCE_MASK {
                return Err(Failure::task(format!(
                    "WYR0-H I1 required_evidence_mask must be {I1_REQUIRED_EVIDENCE_MASK}"
                )));
            }
            Some(EvidenceRequest {
                protocol: EvidenceProtocol::Dwevid1,
                nonce,
                required_mask,
            })
        }
        4 => {
            if selector != I_CAPABILITY_SELECTOR || test_id != I_CAPABILITY_TEST_ID {
                return Err(Failure::task(format!(
                    "WYR0-H schema_version = 4 is reserved for selector '{I_CAPABILITY_SELECTOR}' with test_id {I_CAPABILITY_TEST_ID}"
                )));
            }
            if expected_outcome != ExpectedOutcome::Pass || expected_detail != 0 {
                return Err(Failure::task(
                    "WYR0-H schema_version = 4 requires expected_outcome = \"pass\" and expected_detail = 0",
                ));
            }
            if required(&values, "evidence_protocol")? != I_CAPABILITY_EVIDENCE_PROTOCOL {
                return Err(Failure::task(format!(
                    "WYR0-H WYR0-I evidence_protocol must be '{I_CAPABILITY_EVIDENCE_PROTOCOL}'"
                )));
            }
            let nonce = capability_evidence_nonce(&values)?;
            let required_mask = number::<u32>(&values, "required_evidence_mask")?;
            if required_mask != I_CAPABILITY_REQUIRED_EVIDENCE_MASK {
                return Err(Failure::task(format!(
                    "WYR0-H WYR0-I required_evidence_mask must be {I_CAPABILITY_REQUIRED_EVIDENCE_MASK}"
                )));
            }
            Some(EvidenceRequest {
                protocol: EvidenceProtocol::Wrcap1,
                nonce,
                required_mask,
            })
        }
        _ => unreachable!("schema version admitted above"),
    };
    let capability = if schema_version == 4 {
        Some(CapabilityRequest {
            selector_config: input_path(&parent, required(&values, "selector_config")?),
            selector_asset: input_path(&parent, required(&values, "selector_asset")?),
            certificate: output_path(&parent, required(&values, "certificate")?, "certificate")?,
            capability_summary: output_path(
                &parent,
                required(&values, "capability_summary")?,
                "capability_summary",
            )?,
        })
    } else {
        None
    };
    let request = HRequest {
        path,
        request_sha256,
        schema_version,
        deepwyrm_revision: revision(&values, "deepwyrm_revision")?,
        wyrmroot_revision: revision(&values, "wyrmroot_revision")?,
        rust_revision: revision(&values, "rust_revision")?,
        selector,
        test_id,
        expected_outcome,
        expected_detail,
        timeout_seconds: number::<u64>(&values, "timeout_seconds")?,
        loader: input_path(&parent, required(&values, "loader")?),
        kernel: input_path(&parent, required(&values, "kernel")?),
        symbols: input_path(&parent, required(&values, "symbols")?),
        bootstrap: input_path(&parent, required(&values, "bootstrap")?),
        init0: input_path(&parent, required(&values, "init0")?),
        hello: input_path(&parent, required(&values, "hello")?),
        bootfs: output_path(&parent, required(&values, "bootfs")?, "bootfs")?,
        esp: output_path(&parent, required(&values, "esp")?, "esp")?,
        provenance: output_path(&parent, required(&values, "provenance")?, "provenance")?,
        ovmf_code: input_path(&parent, required(&values, "ovmf_code")?),
        ovmf_vars_template: input_path(&parent, required(&values, "ovmf_vars_template")?),
        run_directory: output_path(
            &parent,
            required(&values, "run_directory")?,
            "run_directory",
        )?,
        evidence,
        capability,
    };
    if request.test_id == 0 {
        return Err(Failure::task("WYR0-H test_id must be nonzero"));
    }
    if !(1..=600).contains(&request.timeout_seconds) {
        return Err(Failure::task(
            "WYR0-H timeout_seconds must be between 1 and 600",
        ));
    }
    validate_outputs(&request)?;
    Ok(request)
}

fn expected_outcome(values: &BTreeMap<String, String>) -> Result<ExpectedOutcome, Failure> {
    match required(values, "expected_outcome")? {
        "pass" => Ok(ExpectedOutcome::Pass),
        "fail" => Ok(ExpectedOutcome::Fail),
        "panic" => Ok(ExpectedOutcome::Panic),
        _ => Err(Failure::task(
            "WYR0-H expected_outcome must be pass, fail, or panic",
        )),
    }
}

fn parse(text: &str) -> Result<BTreeMap<String, String>, Failure> {
    let mut values = BTreeMap::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            return Err(Failure::task(format!(
                "WYR0-H request line {} uses an unsupported section",
                index + 1
            )));
        }
        let (key, raw_value) = line.split_once('=').ok_or_else(|| {
            Failure::task(format!(
                "WYR0-H request line {} is not a scalar assignment",
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
                "WYR0-H request line {} has an invalid key",
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
                    "WYR0-H request line {} has an unsupported quoted value",
                    index + 1
                )));
            }
            quoted.to_owned()
        } else if !raw_value.is_empty() && raw_value.bytes().all(|byte| byte.is_ascii_digit()) {
            raw_value.to_owned()
        } else {
            return Err(Failure::task(format!(
                "WYR0-H request line {} must use a quoted string or unsigned integer",
                index + 1
            )));
        };
        if values.insert(key.to_owned(), value).is_some() {
            return Err(Failure::task(format!(
                "WYR0-H request line {} repeats key '{key}'",
                index + 1
            )));
        }
    }
    Ok(values)
}

fn required<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, Failure> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| Failure::task(format!("WYR0-H request is missing '{key}'")))
}

fn number<T>(values: &BTreeMap<String, String>, key: &str) -> Result<T, Failure>
where
    T: std::str::FromStr,
{
    required(values, key)?
        .parse()
        .map_err(|_| Failure::task(format!("WYR0-H request '{key}' is not a valid integer")))
}

fn revision(values: &BTreeMap<String, String>, key: &str) -> Result<String, Failure> {
    let value = required(values, key)?;
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Failure::task(format!(
            "WYR0-H request '{key}' must be a full lowercase Git revision"
        )));
    }
    Ok(value.to_owned())
}

fn selector(values: &BTreeMap<String, String>) -> Result<String, Failure> {
    let value = required(values, "selector")?;
    if value.is_empty()
        || value.len() > 64
        || value.starts_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(Failure::task(
            "WYR0-H selector must be a bounded lowercase selector name",
        ));
    }
    Ok(value.to_owned())
}

fn evidence_nonce(values: &BTreeMap<String, String>) -> Result<u64, Failure> {
    let value = required(values, "evidence_nonce")?;
    if value.len() != 16
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
    {
        return Err(Failure::task(
            "WYR0-H I1 evidence_nonce must be 16 uppercase hexadecimal digits",
        ));
    }
    let nonce = u64::from_str_radix(value, 16)
        .map_err(|_| Failure::task("WYR0-H I1 evidence_nonce is not a valid u64"))?;
    if nonce == 0 {
        return Err(Failure::task("WYR0-H I1 evidence_nonce must be nonzero"));
    }
    if nonce != I1_EVIDENCE_NONCE {
        return Err(Failure::task(format!(
            "WYR0-H I1 evidence_nonce must be {I1_EVIDENCE_NONCE:016X}"
        )));
    }
    Ok(nonce)
}

fn capability_evidence_nonce(values: &BTreeMap<String, String>) -> Result<u64, Failure> {
    let value = required(values, "evidence_nonce")?;
    if value.len() != 16
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
    {
        return Err(Failure::task(
            "WYR0-H WYR0-I evidence_nonce must be 16 uppercase hexadecimal digits",
        ));
    }
    let nonce = u64::from_str_radix(value, 16)
        .map_err(|_| Failure::task("WYR0-H WYR0-I evidence_nonce is not a valid u64"))?;
    if nonce == 0 {
        return Err(Failure::task(
            "WYR0-H WYR0-I evidence_nonce must be nonzero",
        ));
    }
    Ok(nonce)
}

fn input_path(parent: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        parent.join(path)
    }
}

fn output_path(parent: &Path, value: &str, label: &str) -> Result<PathBuf, Failure> {
    let relative = Path::new(value);
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
        || relative.as_os_str().is_empty()
    {
        return Err(Failure::task(format!(
            "WYR0-H {label} must be a non-escaping request-relative path"
        )));
    }
    Ok(parent.join(relative))
}

fn reject_output_aliases(request: &HRequest) -> Result<(), Failure> {
    let mut outputs = vec![
        (&request.bootfs, "bootfs"),
        (&request.esp, "esp"),
        (&request.provenance, "provenance"),
        (&request.run_directory, "run_directory"),
    ];
    if let Some(capability) = &request.capability {
        outputs.push((&capability.certificate, "certificate"));
        outputs.push((&capability.capability_summary, "capability_summary"));
        if capability.certificate.starts_with(&request.run_directory)
            || capability
                .capability_summary
                .starts_with(&request.run_directory)
        {
            return Err(Failure::task(
                "WYR0-H capability outputs must not be nested under run_directory",
            ));
        }
    }
    for (index, (left, left_label)) in outputs.iter().enumerate() {
        for (right, right_label) in outputs.iter().skip(index + 1) {
            if left == right {
                return Err(Failure::task(format!(
                    "WYR0-H {left_label} and {right_label} paths alias"
                )));
            }
        }
    }
    Ok(())
}

/// Output names are lexically request-relative, but a pre-existing directory
/// component may still redirect creation through a symlink. Re-run this before
/// each output open/create boundary as well as during request admission.
pub(crate) fn validate_outputs(request: &HRequest) -> Result<(), Failure> {
    reject_output_aliases(request)?;
    let mut outputs = vec![
        (&request.bootfs, "bootfs"),
        (&request.esp, "esp"),
        (&request.provenance, "provenance"),
        (&request.run_directory, "run_directory"),
    ];
    if let Some(capability) = &request.capability {
        outputs.push((&capability.certificate, "certificate"));
        outputs.push((&capability.capability_summary, "capability_summary"));
    }
    for (path, label) in outputs {
        validate_output_parent(request, path, label)?;
    }
    validate_run_directory(request)
}

pub(crate) fn validate_output_parent(
    request: &HRequest,
    path: &Path,
    label: &str,
) -> Result<(), Failure> {
    let request_root = request
        .path
        .parent()
        .ok_or_else(|| Failure::task("WYR0-H request has no parent directory"))?;
    let request_root = fs::canonicalize(request_root).map_err(|error| {
        Failure::task(format!("could not resolve WYR0-H request root: {error}"))
    })?;
    let existing_parent = nearest_existing_parent(path)?;
    let resolved_parent = fs::canonicalize(existing_parent).map_err(|error| {
        Failure::task(format!(
            "could not resolve WYR0-H {label} output parent: {error}"
        ))
    })?;
    if !resolved_parent.starts_with(&request_root) {
        return Err(Failure::task(format!(
            "WYR0-H {label} output parent escapes the request root through a symlink"
        )));
    }
    Ok(())
}

fn validate_run_directory(request: &HRequest) -> Result<(), Failure> {
    let metadata = match fs::symlink_metadata(&request.run_directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(Failure::task(format!(
                "could not inspect WYR0-H run_directory: {error}"
            )));
        }
    };
    let root = request
        .path
        .parent()
        .ok_or_else(|| Failure::task("WYR0-H request has no parent directory"))?;
    let root = fs::canonicalize(root).map_err(|error| {
        Failure::task(format!("could not resolve WYR0-H request root: {error}"))
    })?;
    let resolved = fs::canonicalize(&request.run_directory).map_err(|error| {
        Failure::task(format!("could not resolve WYR0-H run_directory: {error}"))
    })?;
    if !resolved.starts_with(root) {
        return Err(Failure::task(
            "WYR0-H run_directory escapes the request root through a symlink",
        ));
    }
    if !metadata.file_type().is_dir() {
        return Err(Failure::task(
            "WYR0-H run_directory must be a real directory when it already exists",
        ));
    }
    Ok(())
}

fn nearest_existing_parent(path: &Path) -> Result<&Path, Failure> {
    let mut candidate = path
        .parent()
        .ok_or_else(|| Failure::task("WYR0-H output path has no parent directory"))?;
    loop {
        if fs::symlink_metadata(candidate).is_ok() {
            return Ok(candidate);
        }
        candidate = candidate
            .parent()
            .ok_or_else(|| Failure::task("WYR0-H output path has no existing parent directory"))?;
    }
}

pub(crate) fn canonical_regular(
    path: &Path,
    label: &str,
    max_bytes: u64,
) -> Result<PathBuf, Failure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Failure::task(format!("could not inspect {label}: {error}")))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(Failure::task(format!(
            "{label} must be a nonempty regular file no larger than {max_bytes} bytes"
        )));
    }
    fs::canonicalize(path)
        .map_err(|error| Failure::task(format!("could not resolve {label}: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> String {
        let revision = "1".repeat(40);
        format!(
            concat!(
                "schema_version = 1\n",
                "deepwyrm_revision = \"{}\"\n",
                "wyrmroot_revision = \"{}\"\n",
                "rust_revision = \"{}\"\n",
                "selector = \"primordial-bootstrap\"\n",
                "test_id = 18\n",
                "timeout_seconds = 180\n",
                "loader = \"loader.efi\"\n",
                "kernel = \"deepwyrm.elf\"\n",
                "symbols = \"deepwyrm.elf\"\n",
                "bootstrap = \"bootstrap.elf\"\n",
                "init0 = \"init0.elf\"\n",
                "hello = \"hello.elf\"\n",
                "bootfs = \"media/bootfs.img\"\n",
                "esp = \"media/wyrmroot-esp.img\"\n",
                "provenance = \"media/provenance.toml\"\n",
                "ovmf_code = \"OVMF_CODE.fd\"\n",
                "ovmf_vars_template = \"OVMF_VARS.fd\"\n",
                "run_directory = \"runs\"\n"
            ),
            revision, revision, revision,
        )
    }

    fn valid_v2() -> String {
        valid()
            .replace("schema_version = 1", "schema_version = 2")
            .replace(
                "test_id = 18\n",
                "test_id = 18\nexpected_outcome = \"pass\"\nexpected_detail = 0\n",
            )
    }

    fn valid_v3() -> String {
        valid_v2()
            .replace("schema_version = 2", "schema_version = 3")
            .replace(
                "selector = \"primordial-bootstrap\"",
                "selector = \"smp-runtime-acceptance\"",
            )
            .replace("test_id = 18", "test_id = 23")
            + concat!(
                "evidence_protocol = \"dwevid1\"\n",
                "evidence_nonce = \"0123456789ABCDEF\"\n",
                "required_evidence_mask = 255\n"
            )
    }

    fn valid_v4() -> String {
        valid_v2()
            .replace("schema_version = 2", "schema_version = 4")
            .replace(
                "selector = \"primordial-bootstrap\"",
                "selector = \"native-userspace-capability\"",
            )
            .replace("test_id = 18", "test_id = 24")
            .replace(
                "hello = \"hello.elf\"\n",
                concat!(
                    "hello = \"hello.elf\"\n",
                    "selector_config = \"selector-config.toml\"\n",
                    "selector_asset = \"selector-asset.bin\"\n"
                ),
            )
            + concat!(
                "evidence_protocol = \"wrcap1\"\n",
                "evidence_nonce = \"89ABCDEF01234567\"\n",
                "required_evidence_mask = 1023\n",
                "certificate = \"wyr0-i/certificate.json\"\n",
                "capability_summary = \"wyr0-i/capability.md\"\n"
            )
    }

    fn request_root(label: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!(
                "xtask-h-request-{label}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system clock before epoch")
                    .as_nanos()
            ))
    }

    fn write_request_fixture(root: &Path, request: &str) -> PathBuf {
        fs::create_dir(root).expect("create request fixture");
        for name in [
            "loader.efi",
            "deepwyrm.elf",
            "bootstrap.elf",
            "init0.elf",
            "hello.elf",
            "OVMF_CODE.fd",
            "OVMF_VARS.fd",
        ] {
            fs::write(root.join(name), b"artifact").expect("write request artifact");
        }
        let path = root.join("request.toml");
        fs::write(&path, request).expect("write request fixture");
        path
    }

    #[test]
    fn flat_request_parser_rejects_ambiguity() {
        let parsed = parse(&valid()).unwrap();
        assert_eq!(parsed.get("test_id").map(String::as_str), Some("18"));
        for invalid in [
            valid().replace("schema_version = 1", "schema_version = true"),
            format!("{}schema_version = 1\n", valid()),
            valid().replace("loader =", "[paths]\nloader ="),
            valid().replace("loader.efi", "loader\\.efi"),
        ] {
            assert!(parse(&invalid).is_err());
        }
    }

    #[test]
    fn output_paths_cannot_escape_the_request() {
        let parent = Path::new("/request");
        assert_eq!(
            output_path(parent, "media/esp.img", "esp").unwrap(),
            Path::new("/request/media/esp.img")
        );
        for invalid in ["/tmp/esp.img", "../esp.img", "media/../../esp.img", ""] {
            assert!(output_path(parent, invalid, "esp").is_err());
        }
    }

    #[test]
    fn revisions_and_selectors_are_strict() {
        let values = parse(&valid()).unwrap();
        assert_eq!(revision(&values, "deepwyrm_revision").unwrap().len(), 40);
        assert_eq!(selector(&values).unwrap(), "primordial-bootstrap");
        let mut bad = values.clone();
        bad.insert("deepwyrm_revision".into(), "A".repeat(40));
        assert!(revision(&bad, "deepwyrm_revision").is_err());
        bad.insert("selector".into(), "--help".into());
        assert!(selector(&bad).is_err());
    }

    #[test]
    fn schema_two_requires_a_named_terminal_outcome() {
        let request = valid()
            .replace("schema_version = 1", "schema_version = 2")
            .replace(
                "test_id = 18\n",
                "test_id = 18\nexpected_outcome = \"fail\"\nexpected_detail = 2952791041\n",
            );
        let values = parse(&request).unwrap();
        assert_eq!(expected_outcome(&values).unwrap(), ExpectedOutcome::Fail);
        assert_eq!(
            number::<u32>(&values, "expected_detail").unwrap(),
            0xB000_0401
        );
        let mut invalid = values;
        invalid.insert("expected_outcome".into(), "anything".into());
        assert!(expected_outcome(&invalid).is_err());
    }

    #[test]
    fn schema_two_loads_only_with_the_complete_explicit_expectation_contract() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("xtask-h-request-v2-test-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        for name in [
            "loader.efi",
            "deepwyrm.elf",
            "bootstrap.elf",
            "init0.elf",
            "hello.elf",
            "OVMF_CODE.fd",
            "OVMF_VARS.fd",
        ] {
            fs::write(root.join(name), b"artifact").unwrap();
        }
        let request = valid()
            .replace("schema_version = 1", "schema_version = 2")
            .replace(
                "test_id = 18\n",
                "test_id = 18\nexpected_outcome = \"fail\"\nexpected_detail = 2952791041\n",
            );
        let path = root.join("request.toml");
        fs::write(&path, request).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.expected_outcome, ExpectedOutcome::Fail);
        assert_eq!(loaded.expected_detail, 0xB000_0401);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn schema_three_is_reserved_for_the_exact_i1_contract() {
        let root = request_root("v3");
        let path = write_request_fixture(&root, &valid_v3());
        let loaded = load(&path).expect("valid I1 request rejected");
        assert_eq!(loaded.schema_version, 3);
        assert_eq!(loaded.selector, I1_SELECTOR);
        assert_eq!(loaded.test_id, I1_TEST_ID);
        assert_eq!(
            loaded.evidence,
            Some(EvidenceRequest {
                protocol: EvidenceProtocol::Dwevid1,
                nonce: 0x0123_4567_89AB_CDEF,
                required_mask: I1_REQUIRED_EVIDENCE_MASK,
            })
        );

        for (label, request) in [
            (
                "v2-i1",
                valid_v3()
                    .replace("schema_version = 3", "schema_version = 2")
                    .replace("evidence_protocol = \"dwevid1\"\n", "")
                    .replace("evidence_nonce = \"0123456789ABCDEF\"\n", "")
                    .replace("required_evidence_mask = 255\n", ""),
            ),
            (
                "v3-non-i1",
                valid_v3().replace(
                    "selector = \"smp-runtime-acceptance\"",
                    "selector = \"primordial-bootstrap\"",
                ),
            ),
            (
                "v3-id22",
                valid_v3().replace("test_id = 23", "test_id = 22"),
            ),
            (
                "v3-expected-fail",
                valid_v3().replace("expected_outcome = \"pass\"", "expected_outcome = \"fail\""),
            ),
            (
                "v3-expected-panic",
                valid_v3().replace(
                    "expected_outcome = \"pass\"",
                    "expected_outcome = \"panic\"",
                ),
            ),
            (
                "v3-expected-detail",
                valid_v3().replace("expected_detail = 0", "expected_detail = 1"),
            ),
            (
                "v3-extra",
                format!("{}unexpected = \"field\"\n", valid_v3()),
            ),
            (
                "v3-missing",
                valid_v3().replace("required_evidence_mask = 255\n", ""),
            ),
        ] {
            let invalid_root = request_root(label);
            let invalid_path = write_request_fixture(&invalid_root, &request);
            assert!(load(&invalid_path).is_err(), "admitted invalid {label}");
            fs::remove_dir_all(invalid_root).expect("remove invalid fixture");
        }
        fs::remove_dir_all(root).expect("remove request fixture");
    }

    #[test]
    fn schema_three_evidence_scalars_are_exact_and_fail_closed() {
        for (label, request) in [
            (
                "protocol-case",
                valid_v3().replace("\"dwevid1\"", "\"DWEVID1\""),
            ),
            (
                "nonce-lower",
                valid_v3().replace("0123456789ABCDEF", "0123456789abcDEF"),
            ),
            (
                "nonce-short",
                valid_v3().replace("0123456789ABCDEF", "123456789ABCDEF"),
            ),
            (
                "nonce-zero",
                valid_v3().replace("0123456789ABCDEF", "0000000000000000"),
            ),
            (
                "nonce-other",
                valid_v3().replace("0123456789ABCDEF", "FEDCBA9876543210"),
            ),
            (
                "mask-low",
                valid_v3().replace(
                    "required_evidence_mask = 255",
                    "required_evidence_mask = 254",
                ),
            ),
            (
                "mask-hex",
                valid_v3().replace(
                    "required_evidence_mask = 255",
                    "required_evidence_mask = \"FF\"",
                ),
            ),
        ] {
            let root = request_root(label);
            let path = write_request_fixture(&root, &request);
            assert!(load(&path).is_err(), "admitted invalid {label}");
            fs::remove_dir_all(root).expect("remove evidence fixture");
        }
    }

    #[test]
    fn schema_four_is_reserved_for_the_exact_wyr0_i_capability_contract() {
        let root = request_root("v4");
        let path = write_request_fixture(&root, &valid_v4());
        let loaded = load(&path).expect("valid WYR0-I capability request rejected");
        assert_eq!(loaded.schema_version, 4);
        assert_eq!(loaded.selector, I_CAPABILITY_SELECTOR);
        assert_eq!(loaded.test_id, I_CAPABILITY_TEST_ID);
        assert_eq!(
            loaded.evidence,
            Some(EvidenceRequest {
                protocol: EvidenceProtocol::Wrcap1,
                nonce: 0x89AB_CDEF_0123_4567,
                required_mask: I_CAPABILITY_REQUIRED_EVIDENCE_MASK,
            })
        );
        let capability = loaded
            .capability
            .expect("schema 4 omitted capability paths");
        let canonical_root = fs::canonicalize(&root).expect("canonical request root");
        assert_eq!(
            capability.selector_config,
            canonical_root.join("selector-config.toml")
        );
        assert_eq!(
            capability.selector_asset,
            canonical_root.join("selector-asset.bin")
        );
        assert_eq!(
            capability.certificate,
            canonical_root.join("wyr0-i/certificate.json")
        );
        assert_eq!(
            capability.capability_summary,
            canonical_root.join("wyr0-i/capability.md")
        );

        for (label, request) in [
            (
                "v2-capability",
                valid_v4()
                    .replace("schema_version = 4", "schema_version = 2")
                    .replace("selector_config = \"selector-config.toml\"\n", "")
                    .replace("selector_asset = \"selector-asset.bin\"\n", "")
                    .replace("evidence_protocol = \"wrcap1\"\n", "")
                    .replace("evidence_nonce = \"89ABCDEF01234567\"\n", "")
                    .replace("required_evidence_mask = 1023\n", "")
                    .replace("certificate = \"wyr0-i/certificate.json\"\n", "")
                    .replace("capability_summary = \"wyr0-i/capability.md\"\n", ""),
            ),
            (
                "v4-selector",
                valid_v4().replace(
                    "selector = \"native-userspace-capability\"",
                    "selector = \"primordial-bootstrap\"",
                ),
            ),
            (
                "v4-test-id",
                valid_v4().replace("test_id = 24", "test_id = 23"),
            ),
            (
                "v4-outcome",
                valid_v4().replace("expected_outcome = \"pass\"", "expected_outcome = \"fail\""),
            ),
            (
                "v4-detail",
                valid_v4().replace("expected_detail = 0", "expected_detail = 1"),
            ),
            (
                "v4-protocol",
                valid_v4().replace("\"wrcap1\"", "\"WRCAP1\""),
            ),
            (
                "v4-nonce-lower",
                valid_v4().replace("89ABCDEF01234567", "89abcdef01234567"),
            ),
            (
                "v4-nonce-zero",
                valid_v4().replace("89ABCDEF01234567", "0000000000000000"),
            ),
            (
                "v4-mask",
                valid_v4().replace(
                    "required_evidence_mask = 1023",
                    "required_evidence_mask = 1022",
                ),
            ),
            ("v4-extra", format!("{}unexpected = 1\n", valid_v4())),
            (
                "v4-missing-output",
                valid_v4().replace("certificate = \"wyr0-i/certificate.json\"\n", ""),
            ),
            (
                "v4-output-alias",
                valid_v4().replace(
                    "capability_summary = \"wyr0-i/capability.md\"",
                    "capability_summary = \"wyr0-i/certificate.json\"",
                ),
            ),
            (
                "v4-output-under-runs",
                valid_v4().replace(
                    "certificate = \"wyr0-i/certificate.json\"",
                    "certificate = \"runs/default/result.json\"",
                ),
            ),
        ] {
            let invalid_root = request_root(label);
            let invalid_path = write_request_fixture(&invalid_root, &request);
            assert!(load(&invalid_path).is_err(), "admitted invalid {label}");
            fs::remove_dir_all(invalid_root).expect("remove invalid fixture");
        }
        fs::remove_dir_all(root).expect("remove request fixture");
    }

    #[test]
    fn schema_one_is_historical_and_rejected_for_acceptance_commands() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("xtask-h-request-v1-test-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let path = root.join("request.toml");
        fs::write(&path, valid()).unwrap();
        let error = load(&path).expect_err("schema v1 request admitted");
        assert!(error.message.contains("require schema_version = 2"));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn output_parent_symlink_cannot_escape_request_root() {
        use std::os::unix::fs::symlink;

        let nonce = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = std::env::temp_dir().join(format!("xtask-h-request-root-{nonce}"));
        let outside = std::env::temp_dir().join(format!("xtask-h-request-outside-{nonce}"));
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        for name in [
            "loader.efi",
            "deepwyrm.elf",
            "bootstrap.elf",
            "init0.elf",
            "hello.elf",
            "OVMF_CODE.fd",
            "OVMF_VARS.fd",
        ] {
            fs::write(root.join(name), b"artifact").unwrap();
        }
        symlink(&outside, root.join("media")).unwrap();
        let path = root.join("request.toml");
        let request = valid()
            .replace("schema_version = 1", "schema_version = 2")
            .replace(
                "test_id = 18\n",
                "test_id = 18\nexpected_outcome = \"pass\"\nexpected_detail = 0\n",
            );
        fs::write(&path, request).unwrap();
        let error = load(&path).expect_err("escaping media symlink accepted");
        assert!(error.message.contains("escapes the request root"));
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn existing_run_directory_symlink_cannot_escape_request_root() {
        use std::os::unix::fs::symlink;

        let nonce = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = std::env::temp_dir().join(format!("xtask-h-run-root-{nonce}"));
        let outside = std::env::temp_dir().join(format!("xtask-h-run-outside-{nonce}"));
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        for name in [
            "loader.efi",
            "deepwyrm.elf",
            "bootstrap.elf",
            "init0.elf",
            "hello.elf",
            "OVMF_CODE.fd",
            "OVMF_VARS.fd",
        ] {
            fs::write(root.join(name), b"artifact").unwrap();
        }
        symlink(&outside, root.join("runs")).unwrap();
        let request = valid()
            .replace("schema_version = 1", "schema_version = 2")
            .replace(
                "test_id = 18\n",
                "test_id = 18\nexpected_outcome = \"pass\"\nexpected_detail = 0\n",
            );
        let path = root.join("request.toml");
        fs::write(&path, request).unwrap();
        let error = load(&path).expect_err("escaping run_directory symlink accepted");
        assert!(
            error
                .message
                .contains("run_directory escapes the request root")
        );
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn checked_output_target_survives_an_ancestor_rename_and_symlink_swap() {
        use std::io::Write;
        use std::os::unix::fs::symlink;

        let root = request_root("checked-parent-race");
        let outside = request_root("checked-parent-race-outside");
        let path = write_request_fixture(&root, &valid_v2());
        fs::create_dir(root.join("media")).expect("create media directory");
        fs::create_dir(&outside).expect("create outside directory");
        let request = load(&path).expect("load checked-parent fixture");
        let checked = CheckedOutputRoot::open(&request).expect("open checked root");
        let target = checked
            .target(&request.bootfs, "bootfs")
            .expect("resolve stable output parent");

        fs::rename(root.join("media"), root.join("retained-media"))
            .expect("rename admitted parent");
        symlink(&outside, root.join("media")).expect("replace parent with escaping symlink");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(O_NOFOLLOW)
            .open(target.path())
            .expect("create through stable parent descriptor");
        file.write_all(b"trusted").expect("write stable output");

        assert_eq!(
            fs::read(root.join("retained-media/bootfs.img")).expect("read stable output"),
            b"trusted"
        );
        assert!(!outside.join("bootfs.img").exists());
        fs::remove_dir_all(root).expect("remove checked-parent fixture");
        fs::remove_dir_all(outside).expect("remove outside fixture");
    }

    #[cfg(unix)]
    #[test]
    fn checked_output_creation_builds_missing_media_and_run_parents() {
        use std::io::Write;

        let root = request_root("checked-fresh-parents");
        let path = write_request_fixture(&root, &valid_v2());
        let request = load(&path).expect("load fresh-parent fixture");
        let checked = CheckedOutputRoot::open(&request).expect("open checked root");

        assert!(!root.join("media").exists());
        assert!(!root.join("runs").exists());
        assert!(
            !checked
                .exists(&request.bootfs, "bootfs")
                .expect("inspect absent bootfs through absent parent")
        );

        let mut bootfs = checked
            .create_new_file(&request.bootfs, "bootfs", false, true)
            .expect("create bootfs and its missing parent");
        bootfs
            .write_all(b"trusted")
            .expect("write fresh bootfs output");
        drop(bootfs);
        checked
            .create_dir(
                &request.run_directory.join("default"),
                "fresh default run directory",
            )
            .expect("create nested run directory and its missing parent");

        assert_eq!(
            fs::read(root.join("media/bootfs.img")).expect("read fresh bootfs"),
            b"trusted"
        );
        assert!(root.join("runs/default").is_dir());
        assert!(
            checked
                .create_new_file(&request.bootfs, "bootfs", false, true)
                .is_err()
        );
        assert!(
            checked
                .create_dir(
                    &request.run_directory.join("default"),
                    "fresh default run directory",
                )
                .is_err()
        );
        fs::remove_dir_all(root).expect("remove fresh-parent fixture");
    }

    #[cfg(unix)]
    #[test]
    fn checked_output_creation_rejects_a_new_symlink_parent() {
        use std::os::unix::fs::symlink;

        let root = request_root("checked-new-parent-symlink");
        let outside = request_root("checked-new-parent-symlink-outside");
        let path = write_request_fixture(&root, &valid_v2());
        fs::create_dir(&outside).expect("create outside directory");
        let request = load(&path).expect("load missing-parent fixture");
        let checked = CheckedOutputRoot::open(&request).expect("open checked root");

        symlink(&outside, root.join("media")).expect("install post-admission symlink");
        let error = checked
            .create_new_file(&request.bootfs, "bootfs", false, true)
            .expect_err("created through a post-admission parent symlink");

        assert!(error.message.contains("could not open bootfs"));
        assert!(!outside.join("bootfs.img").exists());
        fs::remove_dir_all(root).expect("remove symlink-parent fixture");
        fs::remove_dir_all(outside).expect("remove outside fixture");
    }

    #[cfg(unix)]
    #[test]
    fn checked_output_root_survives_request_root_replacement() {
        use std::os::unix::fs::symlink;

        let root = request_root("checked-root-race");
        let retained = request_root("checked-root-race-retained");
        let outside = request_root("checked-root-race-outside");
        let path = write_request_fixture(&root, &valid_v2());
        fs::create_dir(&outside).expect("create outside directory");
        let request = load(&path).expect("load checked-root fixture");
        let checked = CheckedOutputRoot::open(&request).expect("open checked root");

        fs::rename(&root, &retained).expect("rename admitted request root");
        fs::create_dir(&root).expect("create replacement request root");
        symlink(&outside, root.join("media")).expect("install escaping replacement");
        let mut output = checked
            .create_new_file(&request.bootfs, "bootfs", false, true)
            .expect("create missing parent under retained request-root descriptor");
        use std::io::Write as _;
        output.write_all(b"trusted").expect("write retained output");

        assert_eq!(
            fs::read(retained.join("media/bootfs.img")).expect("read retained output"),
            b"trusted"
        );
        assert!(!outside.join("bootfs.img").exists());
        fs::remove_dir_all(root).expect("remove replacement root");
        fs::remove_dir_all(retained).expect("remove retained root");
        fs::remove_dir_all(outside).expect("remove outside fixture");
    }
}
