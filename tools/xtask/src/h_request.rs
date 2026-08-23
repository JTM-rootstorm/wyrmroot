//! Strict, dependency-free parsing for one WYR0-H integration candidate.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::error::Failure;

const MAX_REQUEST_BYTES: u64 = 64 * 1024;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExpectedOutcome {
    Pass,
    Fail,
    Panic,
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
}

pub(crate) fn load(path: &Path) -> Result<HRequest, Failure> {
    let path = canonical_regular(path, "WYR0-H request", MAX_REQUEST_BYTES)?;
    let metadata = fs::metadata(&path)
        .map_err(|error| Failure::task(format!("could not stat WYR0-H request: {error}")))?;
    if metadata.len() > MAX_REQUEST_BYTES {
        return Err(Failure::task("WYR0-H request exceeds its size limit"));
    }
    let text = fs::read_to_string(&path)
        .map_err(|error| Failure::task(format!("could not read WYR0-H request: {error}")))?;
    let values = parse(&text)?;
    let schema_version = required(&values, "schema_version")?;
    if schema_version != "2" {
        return Err(Failure::task(
            "WYR0-H acceptance commands require schema_version = 2",
        ));
    }
    let required_keys = REQUIRED_KEYS_V2;
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
    let request = HRequest {
        path,
        deepwyrm_revision: revision(&values, "deepwyrm_revision")?,
        wyrmroot_revision: revision(&values, "wyrmroot_revision")?,
        rust_revision: revision(&values, "rust_revision")?,
        selector: selector(&values)?,
        test_id: number::<u32>(&values, "test_id")?,
        expected_outcome: expected_outcome(&values)?,
        expected_detail: number::<u32>(&values, "expected_detail")?,
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
    let outputs = [
        (&request.bootfs, "bootfs"),
        (&request.esp, "esp"),
        (&request.provenance, "provenance"),
        (&request.run_directory, "run_directory"),
    ];
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
    for (path, label) in [
        (&request.bootfs, "bootfs"),
        (&request.esp, "esp"),
        (&request.provenance, "provenance"),
        (&request.run_directory, "run_directory"),
    ] {
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
}
