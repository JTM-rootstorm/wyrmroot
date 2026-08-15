use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Take};
use std::path::{Component as PathComponent, Path, PathBuf};

use crate::error::Failure;
use crate::sha256::{bytes_digest, file_digest};

const REQUEST_PATH: &str = "toolchain/requests/RUST-WYR0B-UEFI-001.toml";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const COORDINATOR_REQUEST: &str = "RUST-PHASE0B-TOOLCHAIN-001";
const CONSUMER_REQUEST: &str = "RUST-WYR0B-UEFI-001";
const CONFIGURATION_SHA256: &str =
    "63e532b52e6d4c2ef4ed4a003e2aafd7ec11b55e3de5a635c1aea8bfa849f332";

const RUSTC_SHA256: &str = "284606eec4c85a3780627a889f7e2694759446b68c4f65e7ce21168432f8915d";
const CARGO_SHA256: &str = "1dbc247d0d8568da0b472a8ceaba18d29cea19e20d2d48cf21597b8574633438";
const RUST_LLD_SHA256: &str = "38a9f28404309892f9c9afe02fa4979a0d9e8bc866979cde09f5bb7ec17e5721";
const UEFI_CORE_SHA256: &str = "6777111445c5cf0c4abd7063fa0f7165c3df3809d7de4a9cbedaa84a6d7d9d68";
const UEFI_BUILTINS_SHA256: &str =
    "eea1964f8b5e2ed67defcde06d7ca9874e13ba972f08526d8b1bb52127ccb136";

#[derive(Clone)]
struct ArtifactComponent {
    label: &'static str,
    path: PathBuf,
    sha256: String,
}

pub(crate) struct AcceptedToolchain {
    pub(crate) rustc: PathBuf,
    pub(crate) cargo: PathBuf,
    pub(crate) rust_lld: PathBuf,
    pub(crate) sysroot: PathBuf,
    pub(crate) manifest_sha256: String,
    pub(crate) cargo_sha256: String,
    pub(crate) rust_lld_sha256: String,
    pub(crate) uefi_core_sha256: String,
    pub(crate) uefi_builtins_sha256: String,
    root: PathBuf,
    manifest: ArtifactComponent,
    components: Vec<ArtifactComponent>,
}

impl AcceptedToolchain {
    pub(crate) fn verify_unchanged(&self) -> Result<(), Failure> {
        validate_component(&self.root, &self.manifest)?;
        for component in &self.components {
            validate_component(&self.root, component)?;
        }
        Ok(())
    }
}

pub(crate) fn prepare(
    repository: &Path,
    configured_rustc: &Path,
    expected_name: &str,
    expected_commit: &str,
) -> Result<AcceptedToolchain, Failure> {
    let request_path = repository.join(REQUEST_PATH);
    let request_contents =
        read_utf8_bounded(&request_path, MAX_MANIFEST_BYTES, "toolchain request")?;
    let request = parse_manifest(&request_contents)?;
    expect_integer(&request, "schema_version", 1, "toolchain request")?;
    expect_string(
        &request,
        "request_id",
        CONSUMER_REQUEST,
        "toolchain request",
    )?;
    expect_string(
        &request,
        "coordinator_request_id",
        COORDINATOR_REQUEST,
        "toolchain request",
    )?;
    expect_string(
        &request,
        "artifact_request_id",
        COORDINATOR_REQUEST,
        "toolchain request",
    )?;
    expect_string(
        &request,
        "status",
        "accepted-immutable-artifact",
        "toolchain request",
    )?;
    expect_string(
        &request,
        "request_kind",
        "build-immutable-existing-wyrmroot-rust-toolchain",
        "toolchain request",
    )?;
    expect_string(
        &request,
        "artifact_configuration_id",
        &CONFIGURATION_SHA256[..16],
        "toolchain request",
    )?;
    let expected_manifest_sha =
        required_sha256(&request, "artifact_manifest_sha256", "toolchain request")?;

    let (root, canonical_rustc) = artifact_root_from_rustc(configured_rustc, expected_name)?;
    let manifest_path = root.join("manifest.toml");
    validate_contained_regular_file(&root, &manifest_path, "artifact manifest")?;
    let manifest_bytes = read_bounded(&manifest_path, MAX_MANIFEST_BYTES, "artifact manifest")?;
    let actual_manifest_sha = bytes_digest(&manifest_bytes);
    if actual_manifest_sha != expected_manifest_sha {
        return Err(Failure::task(format!(
            "accepted toolchain manifest hash is {actual_manifest_sha}, expected {expected_manifest_sha}"
        )));
    }
    let manifest_contents = std::str::from_utf8(&manifest_bytes)
        .map_err(|_| Failure::task("accepted toolchain manifest is not UTF-8"))?;
    let manifest = parse_manifest(manifest_contents)?;
    validate_manifest_identity(&manifest, expected_name, expected_commit)?;

    let rustc = component(&root, &manifest, "artifacts.rustc", "rustc", RUSTC_SHA256)?;
    if rustc.path != canonical_rustc {
        return Err(Failure::task(
            "configured WYRMROOT_RUSTC does not match manifest-declared rustc artifact",
        ));
    }
    let cargo = component(&root, &manifest, "artifacts.cargo", "cargo", CARGO_SHA256)?;
    let rust_lld = component(
        &root,
        &manifest,
        "artifacts.rust_lld",
        "rust-lld",
        RUST_LLD_SHA256,
    )?;
    let uefi_core = component(
        &root,
        &manifest,
        "artifacts.uefi_core",
        "UEFI core",
        UEFI_CORE_SHA256,
    )?;
    let uefi_builtins = component(
        &root,
        &manifest,
        "artifacts.uefi_compiler_builtins",
        "UEFI compiler-builtins",
        UEFI_BUILTINS_SHA256,
    )?;

    let toolchain_directory =
        required_string(&manifest, "toolchain_directory", "artifact manifest")?;
    let expected_directory = format!("toolchains/{expected_name}");
    if toolchain_directory != expected_directory {
        return Err(Failure::task(format!(
            "artifact manifest toolchain_directory is '{toolchain_directory}', expected '{expected_directory}'"
        )));
    }
    let sysroot = contained_path(&root, &toolchain_directory, "accepted sysroot")?;
    let sysroot_metadata = fs::symlink_metadata(&sysroot)
        .map_err(|error| Failure::task(format!("could not inspect accepted sysroot: {error}")))?;
    if !sysroot_metadata.is_dir() || sysroot_metadata.file_type().is_symlink() {
        return Err(Failure::task(
            "accepted sysroot is not a non-symlink directory",
        ));
    }

    let manifest_component = ArtifactComponent {
        label: "artifact manifest",
        path: manifest_path,
        sha256: actual_manifest_sha.clone(),
    };
    let components = vec![
        rustc.clone(),
        cargo.clone(),
        rust_lld.clone(),
        uefi_core.clone(),
        uefi_builtins.clone(),
    ];
    let accepted = AcceptedToolchain {
        rustc: rustc.path.clone(),
        cargo: cargo.path.clone(),
        rust_lld: rust_lld.path.clone(),
        sysroot,
        manifest_sha256: actual_manifest_sha,
        cargo_sha256: cargo.sha256.clone(),
        rust_lld_sha256: rust_lld.sha256.clone(),
        uefi_core_sha256: uefi_core.sha256.clone(),
        uefi_builtins_sha256: uefi_builtins.sha256.clone(),
        root,
        manifest: manifest_component,
        components,
    };
    accepted.verify_unchanged()?;
    Ok(accepted)
}

fn validate_manifest_identity(
    manifest: &BTreeMap<String, Value>,
    expected_name: &str,
    expected_commit: &str,
) -> Result<(), Failure> {
    expect_integer(manifest, "schema_version", 1, "artifact manifest")?;
    expect_string(
        manifest,
        "request_id",
        COORDINATOR_REQUEST,
        "artifact manifest",
    )?;
    expect_string(
        manifest,
        "registered_name",
        expected_name,
        "artifact manifest",
    )?;
    expect_string(
        manifest,
        "source_commit",
        expected_commit,
        "artifact manifest",
    )?;
    expect_bool(manifest, "source_dirty", false, "artifact manifest")?;
    expect_bool(manifest, "source_modified", false, "artifact manifest")?;
    expect_integer(manifest, "bootstrap_stage", 2, "artifact manifest")?;
    expect_string(
        manifest,
        "host",
        "x86_64-unknown-linux-gnu",
        "artifact manifest",
    )?;
    expect_string(
        manifest,
        "configuration_sha256",
        CONFIGURATION_SHA256,
        "artifact manifest",
    )?;
    require_array_member(
        manifest,
        "consumer_requests",
        CONSUMER_REQUEST,
        "artifact manifest",
    )?;
    for target in [
        "x86_64-unknown-linux-gnu",
        "x86_64-unknown-uefi",
        "x86_64-unknown-none",
    ] {
        require_array_member(manifest, "targets", target, "artifact manifest")?;
    }
    expect_string(manifest, "build.status", "passed", "artifact manifest")?;
    expect_bool(
        manifest,
        "build.rust_source_changes",
        false,
        "artifact manifest",
    )?;
    for key in [
        "acceptance.rustc_identity",
        "acceptance.uefi_sysroot_presence",
        "acceptance.consumer_gates",
    ] {
        expect_string(manifest, key, "passed", "artifact manifest")?;
    }
    Ok(())
}

fn artifact_root_from_rustc(
    configured: &Path,
    expected_name: &str,
) -> Result<(PathBuf, PathBuf), Failure> {
    if !configured.is_absolute()
        || configured
            .components()
            .any(|component| matches!(component, PathComponent::ParentDir | PathComponent::CurDir))
        || configured.file_name().and_then(|name| name.to_str()) != Some("rustc")
    {
        return Err(Failure::task(
            "WYRMROOT_RUSTC must be an absolute non-traversing canonical rustc artifact path",
        ));
    }
    let bin = configured
        .parent()
        .filter(|path| path.file_name().and_then(|name| name.to_str()) == Some("bin"))
        .ok_or_else(|| Failure::task("WYRMROOT_RUSTC is not beneath a canonical bin directory"))?;
    let toolchain = bin
        .parent()
        .ok_or_else(|| Failure::task("missing toolchain directory"))?;
    if toolchain.file_name().and_then(|name| name.to_str()) != Some(expected_name) {
        return Err(Failure::task(
            "WYRMROOT_RUSTC toolchain directory does not match the pinned registered name",
        ));
    }
    let toolchains = toolchain
        .parent()
        .filter(|path| path.file_name().and_then(|name| name.to_str()) == Some("toolchains"))
        .ok_or_else(|| Failure::task("WYRMROOT_RUSTC is not beneath toolchains/<registered>"))?;
    let root = toolchains
        .parent()
        .ok_or_else(|| Failure::task("accepted artifact root is missing"))?
        .to_path_buf();
    reject_symlink_components(&root, configured, "configured rustc")?;
    let canonical_root = fs::canonicalize(&root)
        .map_err(|error| Failure::task(format!("could not canonicalize artifact root: {error}")))?;
    if canonical_root != root {
        return Err(Failure::task(
            "accepted artifact root path is not canonical or contains a symlink",
        ));
    }
    let canonical_rustc = fs::canonicalize(configured).map_err(|error| {
        Failure::task(format!("could not canonicalize configured rustc: {error}"))
    })?;
    if !canonical_rustc.starts_with(&canonical_root) || canonical_rustc != configured {
        return Err(Failure::task(
            "configured rustc escapes the artifact root or resolves through a symlink",
        ));
    }
    Ok((root, canonical_rustc))
}

fn component(
    root: &Path,
    manifest: &BTreeMap<String, Value>,
    section: &str,
    label: &'static str,
    expected_sha256: &str,
) -> Result<ArtifactComponent, Failure> {
    let path_key = format!("{section}.path");
    let hash_key = format!("{section}.sha256");
    let relative = required_string(manifest, &path_key, "artifact manifest")?;
    let declared_sha = required_sha256(manifest, &hash_key, "artifact manifest")?;
    if declared_sha != expected_sha256 {
        return Err(Failure::task(format!(
            "artifact manifest {label} hash is {declared_sha}, expected {expected_sha256}"
        )));
    }
    let path = contained_path(root, &relative, label)?;
    let component = ArtifactComponent {
        label,
        path,
        sha256: declared_sha,
    };
    validate_component(root, &component)?;
    Ok(component)
}

fn contained_path(root: &Path, relative: &str, label: &str) -> Result<PathBuf, Failure> {
    let relative = Path::new(relative);
    if relative.is_absolute()
        || relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, PathComponent::Normal(_)))
    {
        return Err(Failure::task(format!(
            "{label} path must be a normal relative path beneath the artifact root"
        )));
    }
    let path = root.join(relative);
    reject_symlink_components(root, &path, label)?;
    let canonical = fs::canonicalize(&path)
        .map_err(|error| Failure::task(format!("could not canonicalize {label}: {error}")))?;
    if !canonical.starts_with(root) || canonical != path {
        return Err(Failure::task(format!(
            "{label} path escapes the artifact root or is not canonical"
        )));
    }
    Ok(path)
}

fn validate_component(root: &Path, component: &ArtifactComponent) -> Result<(), Failure> {
    validate_contained_regular_file(root, &component.path, component.label)?;
    let actual = file_digest(&component.path).map_err(|error| {
        Failure::task(format!(
            "could not hash accepted {}: {error}",
            component.label
        ))
    })?;
    if actual != component.sha256 {
        return Err(Failure::task(format!(
            "accepted {} hash changed: {actual}, expected {}",
            component.label, component.sha256
        )));
    }
    Ok(())
}

fn validate_contained_regular_file(root: &Path, path: &Path, label: &str) -> Result<(), Failure> {
    reject_symlink_components(root, path, label)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Failure::task(format!("could not inspect {label}: {error}")))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Failure::task(format!(
            "{label} is not a regular non-symlink file"
        )));
    }
    Ok(())
}

fn reject_symlink_components(root: &Path, path: &Path, label: &str) -> Result<(), Failure> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| Failure::task(format!("{label} is outside the artifact root")))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let PathComponent::Normal(component) = component else {
            return Err(Failure::task(format!("{label} path contains traversal")));
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|error| Failure::task(format!("could not inspect {label}: {error}")))?;
        if metadata.file_type().is_symlink() {
            return Err(Failure::task(format!(
                "{label} path contains symlink {}",
                current.display()
            )));
        }
    }
    Ok(())
}

fn read_utf8_bounded(path: &Path, maximum: u64, label: &str) -> Result<String, Failure> {
    let bytes = read_bounded(path, maximum, label)?;
    String::from_utf8(bytes).map_err(|_| Failure::task(format!("{label} is not UTF-8")))
}

fn read_bounded(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>, Failure> {
    let file = File::open(path)
        .map_err(|error| Failure::task(format!("could not open {label}: {error}")))?;
    let mut bytes = Vec::new();
    let mut bounded: Take<File> = file.take(maximum + 1);
    bounded
        .read_to_end(&mut bytes)
        .map_err(|error| Failure::task(format!("could not read {label}: {error}")))?;
    if bytes.len() as u64 > maximum {
        return Err(Failure::task(format!(
            "{label} exceeds the {maximum}-byte limit"
        )));
    }
    Ok(bytes)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Value {
    String(String),
    Integer(u64),
    Bool(bool),
    Strings(Vec<String>),
}

fn parse_manifest(contents: &str) -> Result<BTreeMap<String, Value>, Failure> {
    let mut section = String::new();
    let mut values = BTreeMap::new();
    let lines: Vec<&str> = contents.lines().collect();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index].trim();
        if line.is_empty() || line.starts_with('#') {
            index += 1;
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            if line.starts_with("[[") {
                return Err(manifest_error(index, "array tables are unsupported"));
            }
            section = line[1..line.len() - 1].trim().to_owned();
            index += 1;
            continue;
        }
        let (key, raw_value) = line
            .split_once('=')
            .ok_or_else(|| manifest_error(index, "expected key = value"))?;
        let key = key.trim();
        if key.is_empty() || key.contains('.') {
            return Err(manifest_error(index, "invalid key"));
        }
        let qualified = if section.is_empty() {
            key.to_owned()
        } else {
            format!("{section}.{key}")
        };
        let mut raw_value = raw_value.trim().to_owned();
        if raw_value.starts_with('[') && !raw_value.ends_with(']') {
            loop {
                index += 1;
                let continuation = lines
                    .get(index)
                    .ok_or_else(|| manifest_error(index, "unterminated array"))?
                    .trim();
                raw_value.push_str(continuation);
                if continuation.ends_with(']') {
                    break;
                }
            }
        }
        let value = parse_value(&raw_value, index)?;
        if values.insert(qualified.clone(), value).is_some() {
            return Err(manifest_error(index, &format!("duplicate key {qualified}")));
        }
        index += 1;
    }
    Ok(values)
}

fn parse_value(value: &str, index: usize) -> Result<Value, Failure> {
    if let Some(value) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    {
        if value.contains(['"', '\\']) || value.chars().any(char::is_control) {
            return Err(manifest_error(
                index,
                "unsupported string escape or control",
            ));
        }
        return Ok(Value::String(value.to_owned()));
    }
    if let Some(inner) = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        let mut strings = Vec::new();
        if inner.trim().is_empty() {
            return Ok(Value::Strings(strings));
        }
        let items: Vec<&str> = inner.split(',').collect();
        for (position, item) in items.iter().enumerate() {
            let item = item.trim();
            if item.is_empty() && position + 1 == items.len() {
                continue;
            }
            let item = item
                .strip_prefix('"')
                .and_then(|item| item.strip_suffix('"'))
                .ok_or_else(|| manifest_error(index, "arrays must contain quoted strings"))?;
            if item.is_empty() || item.contains(['"', '\\']) {
                return Err(manifest_error(index, "invalid array string"));
            }
            strings.push(item.to_owned());
        }
        return Ok(Value::Strings(strings));
    }
    match value {
        "true" => Ok(Value::Bool(true)),
        "false" => Ok(Value::Bool(false)),
        _ => value
            .parse::<u64>()
            .map(Value::Integer)
            .map_err(|_| manifest_error(index, "unsupported value")),
    }
}

fn manifest_error(index: usize, message: &str) -> Failure {
    Failure::task(format!("toolchain manifest line {}: {message}", index + 1))
}

fn required_string(
    values: &BTreeMap<String, Value>,
    key: &str,
    label: &str,
) -> Result<String, Failure> {
    match values.get(key) {
        Some(Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(Failure::task(format!(
            "{label} field '{key}' has wrong type"
        ))),
        None => Err(Failure::task(format!("{label} is missing field '{key}'"))),
    }
}

fn required_sha256(
    values: &BTreeMap<String, Value>,
    key: &str,
    label: &str,
) -> Result<String, Failure> {
    let value = required_string(values, key, label)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Failure::task(format!(
            "{label} field '{key}' is not a lowercase SHA-256"
        )));
    }
    Ok(value)
}

fn expect_string(
    values: &BTreeMap<String, Value>,
    key: &str,
    expected: &str,
    label: &str,
) -> Result<(), Failure> {
    let actual = required_string(values, key, label)?;
    if actual == expected {
        Ok(())
    } else {
        Err(Failure::task(format!(
            "{label} field '{key}' is '{actual}', expected '{expected}'"
        )))
    }
}

fn expect_integer(
    values: &BTreeMap<String, Value>,
    key: &str,
    expected: u64,
    label: &str,
) -> Result<(), Failure> {
    match values.get(key) {
        Some(Value::Integer(actual)) if *actual == expected => Ok(()),
        Some(Value::Integer(actual)) => Err(Failure::task(format!(
            "{label} field '{key}' is {actual}, expected {expected}"
        ))),
        Some(_) => Err(Failure::task(format!(
            "{label} field '{key}' has wrong type"
        ))),
        None => Err(Failure::task(format!("{label} is missing field '{key}'"))),
    }
}

fn expect_bool(
    values: &BTreeMap<String, Value>,
    key: &str,
    expected: bool,
    label: &str,
) -> Result<(), Failure> {
    match values.get(key) {
        Some(Value::Bool(actual)) if *actual == expected => Ok(()),
        Some(Value::Bool(actual)) => Err(Failure::task(format!(
            "{label} field '{key}' is {actual}, expected {expected}"
        ))),
        Some(_) => Err(Failure::task(format!(
            "{label} field '{key}' has wrong type"
        ))),
        None => Err(Failure::task(format!("{label} is missing field '{key}'"))),
    }
}

fn require_array_member(
    values: &BTreeMap<String, Value>,
    key: &str,
    expected: &str,
    label: &str,
) -> Result<(), Failure> {
    match values.get(key) {
        Some(Value::Strings(actual)) if actual.iter().any(|value| value == expected) => Ok(()),
        Some(Value::Strings(_)) => Err(Failure::task(format!(
            "{label} field '{key}' does not contain '{expected}'"
        ))),
        Some(_) => Err(Failure::task(format!(
            "{label} field '{key}' has wrong type"
        ))),
        None => Err(Failure::task(format!("{label} is missing field '{key}'"))),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactComponent, CONFIGURATION_SHA256, CONSUMER_REQUEST, COORDINATOR_REQUEST,
        parse_manifest, prepare, validate_component, validate_manifest_identity,
    };
    use crate::sha256::file_digest;
    use std::fs;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    const NAME: &str = "wyrmroot-1.97.1-8bab26f4";
    const COMMIT: &str = "8bab26f4f68e0e26f0bb7960be334d5b520ea452";

    #[test]
    fn manifest_identity_requires_commit_configuration_targets_and_acceptance() {
        let manifest = parse_manifest(&identity_manifest()).expect("parse identity fixture");
        validate_manifest_identity(&manifest, NAME, COMMIT)
            .expect("canonical identity fixture rejected");
        assert!(validate_manifest_identity(&manifest, NAME, "stale").is_err());
        let missing_target =
            parse_manifest(&identity_manifest().replace("    \"x86_64-unknown-none\",\n", ""))
                .expect("parse missing-target fixture");
        assert!(validate_manifest_identity(&missing_target, NAME, COMMIT).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn manifest_hash_failure_never_executes_configured_rustc() {
        use std::os::unix::fs::PermissionsExt;

        let root = temporary_root("no-invocation");
        let bin = root.join(format!("toolchains/{NAME}/bin"));
        fs::create_dir_all(&bin).expect("create synthetic toolchain");
        let marker = root.join("executed");
        let rustc = bin.join("rustc");
        fs::write(&rustc, format!("#!/bin/sh\n: > \"{}\"\n", marker.display()))
            .expect("write sentinel rustc");
        let mut permissions = fs::metadata(&rustc).expect("stat sentinel").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&rustc, permissions).expect("make sentinel executable");
        fs::write(root.join("manifest.toml"), "not the pinned manifest")
            .expect("write mismatched manifest");

        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("repository root");
        assert!(prepare(repository, &rustc, NAME, COMMIT).is_err());
        assert!(
            !marker.exists(),
            "untrusted rustc was executed before trust validation"
        );
        fs::remove_dir_all(root).expect("remove synthetic toolchain");
    }

    #[cfg(unix)]
    #[test]
    fn component_identity_rejects_content_and_symlink_swaps() {
        use std::os::unix::fs::symlink;

        let root = temporary_root("component-swap");
        fs::create_dir(&root).expect("create synthetic artifact root");
        let path = root.join("component");
        fs::write(&path, b"trusted").expect("write trusted component");
        let component = ArtifactComponent {
            label: "test component",
            path: path.clone(),
            sha256: file_digest(&path).expect("hash trusted component"),
        };
        validate_component(&root, &component).expect("trusted component rejected");
        fs::write(&path, b"changed").expect("replace component content");
        assert!(validate_component(&root, &component).is_err());
        fs::remove_file(&path).expect("remove changed component");
        let target = root.join("target");
        fs::write(&target, b"trusted").expect("write symlink target");
        symlink(&target, &path).expect("swap component for symlink");
        assert!(validate_component(&root, &component).is_err());
        fs::remove_dir_all(root).expect("remove synthetic artifact root");
    }

    fn temporary_root(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "wyrmroot-toolchain-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn identity_manifest() -> String {
        format!(
            r#"schema_version = 1
request_id = "{COORDINATOR_REQUEST}"
consumer_requests = [
    "{CONSUMER_REQUEST}",
]
registered_name = "{NAME}"
source_commit = "{COMMIT}"
source_dirty = false
source_modified = false
bootstrap_stage = 2
host = "x86_64-unknown-linux-gnu"
targets = [
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-uefi",
    "x86_64-unknown-none",
]
configuration_sha256 = "{CONFIGURATION_SHA256}"

[build]
status = "passed"
rust_source_changes = false

[acceptance]
rustc_identity = "passed"
uefi_sysroot_presence = "passed"
consumer_gates = "passed"
"#
        )
    }
}
