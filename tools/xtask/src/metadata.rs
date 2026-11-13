use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::error::Failure;

#[derive(Debug)]
pub(crate) struct BuildManifest {
    values: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LoaderProfile {
    pub(crate) cargo_package: String,
    pub(crate) cargo_binary: String,
    pub(crate) cargo_features: String,
    pub(crate) uefi_crate_version: String,
    pub(crate) artifact_name: String,
    pub(crate) rust_target: String,
    pub(crate) toolchain_inspection: String,
    pub(crate) artifact_inspection: String,
}

impl BuildManifest {
    pub(crate) fn load(repository: &Path) -> Result<Self, Failure> {
        let path = repository.join("toolchain/versions.toml");
        let contents = read_file(&path)?;
        let values = parse_scalar_toml(&contents, &path)?;
        let manifest = Self { values };
        manifest.validate_host_test_metadata()?;
        Ok(manifest)
    }

    fn validate_host_test_metadata(&self) -> Result<(), Failure> {
        self.expect("schema_version", "1")?;
        self.expect("milestone", "WYR0")?;
        self.require_revision("deepwyrm.revision")?;
        self.require_abi_fingerprint("deepwyrm.abi_fingerprint")?;
        self.require_revision("rust.upstream_stable_revision")?;
        self.require_revision("rust.wyrmroot_revision")?;
        self.require_nonempty("deepwyrm.repository")?;
        self.require_nonempty("rust.upstream_stable_release")?;
        self.require_nonempty("rust.local_toolchain_name")?;
        self.require_nonempty("rust.accepted_artifact_root")?;
        self.require_nonempty("rust.project_cargo_home")?;
        self.require_nonempty("rust.native_target")?;
        self.require_nonempty("deepwyrm.abi_dependency_state")?;
        self.require_nonempty("rust.native_target_state")?;
        self.require_nonempty("llvm.host_version_state")?;
        self.expect("bootstrap_constraints.allow_moving_rust_channel", "false")?;
        self.expect(
            "bootstrap_constraints.allow_host_target_defaults_for_guest",
            "false",
        )?;
        self.expect("bootstrap_constraints.allow_host_libc_for_guest", "false")?;
        self.expect(
            "bootstrap_constraints.allow_unimplemented_deepwyrm_abi_dependency",
            "false",
        )?;
        self.expect(
            "bootstrap_constraints.allow_unimplemented_native_target",
            "false",
        )?;
        Ok(())
    }

    pub(crate) fn validate_host_build_readiness(&self, repository: &Path) -> Result<(), Failure> {
        self.validate_phase_a_states()?;

        let revision = self.required("deepwyrm.revision")?;
        let repository_url = self.required("deepwyrm.repository")?;
        let root_manifest = read_file(&repository.join("Cargo.toml"))?;
        if !root_has_deepwyrm_dependency(&root_manifest, repository_url, revision)
            || !root_has_deepwyrm_package(
                &root_manifest,
                "deepwyrm-syscall",
                repository_url,
                revision,
            )
        {
            return Err(Failure::task(format!(
                "Cargo.toml does not pin both Deepwyrm guest packages at manifest repository {repository_url} and revision {revision}"
            )));
        }

        let lockfile = read_file(&repository.join("Cargo.lock"))?;
        if !lock_has_git_package(&lockfile, "deepwyrm-abi", repository_url, revision) {
            return Err(Failure::task(format!(
                "Cargo.lock does not resolve deepwyrm-abi from manifest repository {repository_url} at revision {revision}"
            )));
        }
        if !lock_has_git_package(&lockfile, "deepwyrm-syscall", repository_url, revision) {
            return Err(Failure::task(format!(
                "Cargo.lock does not resolve deepwyrm-syscall from manifest repository {repository_url} at revision {revision}"
            )));
        }

        if !has_abi_consumer(repository)? {
            return Err(Failure::task(
                "no Wyrmroot workspace crate consumes the pinned deepwyrm-abi dependency",
            ));
        }
        if !workspace_member_consumes_dependency(
            repository,
            "crates/wyrmroot-runtime",
            "deepwyrm-syscall",
        )? {
            return Err(Failure::task(
                "crates/wyrmroot-runtime does not consume the pinned deepwyrm-syscall dependency",
            ));
        }

        self.validate_native_profile(repository)?;
        self.validate_provenance_template(repository)?;
        validate_reserved_target_policy(repository, self.required("rust.native_target")?)?;
        Ok(())
    }

    pub(crate) fn validate_loader_build_readiness(
        &self,
        repository: &Path,
    ) -> Result<LoaderProfile, Failure> {
        self.validate_host_build_readiness(repository)?;
        let profile = self.load_loader_profile(repository)?;
        validate_loader_dependency(repository, &profile)?;
        Ok(profile)
    }

    pub(crate) fn rust_revision(&self) -> Result<&str, Failure> {
        self.required("rust.wyrmroot_revision")
    }

    pub(crate) fn rust_toolchain_name(&self) -> Result<&str, Failure> {
        self.required("rust.local_toolchain_name")
    }

    pub(crate) fn project_cargo_home(&self) -> Result<&str, Failure> {
        self.required("rust.project_cargo_home")
    }

    pub(crate) fn accepted_artifact_root(&self) -> Result<&str, Failure> {
        self.required("rust.accepted_artifact_root")
    }

    fn validate_phase_a_states(&self) -> Result<(), Failure> {
        self.expect("deepwyrm.abi_dependency_state", "available")?;
        self.expect("rust.native_target_state", "available")?;
        Ok(())
    }

    fn validate_native_profile(&self, repository: &Path) -> Result<(), Failure> {
        let path = repository.join("toolchain/profiles.toml");
        let values = parse_scalar_toml(&read_file(&path)?, &path)?;
        expect_map_value(&values, "schema_version", "1", &path)?;
        expect_map_value(
            &values,
            "native_guest.rust_target",
            self.required("rust.native_target")?,
            &path,
        )?;
        expect_map_value(&values, "native_guest.target_state", "available", &path)?;
        expect_map_value(&values, "native_guest.host_libc", "prohibited", &path)?;
        expect_map_value(
            &values,
            "native_guest.dynamic_interpreter",
            "prohibited",
            &path,
        )?;
        expect_map_value(
            &values,
            "native_guest.unix_target_family",
            "prohibited",
            &path,
        )?;
        Ok(())
    }

    fn load_loader_profile(&self, repository: &Path) -> Result<LoaderProfile, Failure> {
        let path = repository.join("toolchain/profiles.toml");
        let values = parse_scalar_toml(&read_file(&path)?, &path)?;

        for (key, expected) in [
            ("schema_version", "1"),
            ("uefi_loader.execution_environment", "64-bit UEFI firmware"),
            ("uefi_loader.binary_format", "PE32+ COFF"),
            ("uefi_loader.machine", "x86_64"),
            ("uefi_loader.rustc_linker", "rust-lld"),
            ("uefi_loader.rustc_linker_flavor", "msvc-lld"),
            ("uefi_loader.lld_flavor", "link"),
            ("uefi_loader.host_linker_fallback", "prohibited"),
            ("uefi_loader.host_libc_fallback", "prohibited"),
        ] {
            expect_map_value(&values, key, expected, &path)?;
        }

        let profile = LoaderProfile {
            cargo_package: required_map_value(&values, "uefi_loader.cargo_package", &path)?,
            cargo_binary: required_map_value(&values, "uefi_loader.cargo_binary", &path)?,
            cargo_features: required_map_value(&values, "uefi_loader.cargo_features", &path)?,
            uefi_crate_version: required_map_value(
                &values,
                "uefi_loader.uefi_crate_version",
                &path,
            )?,
            artifact_name: required_map_value(&values, "uefi_loader.artifact_name", &path)?,
            rust_target: required_map_value(&values, "uefi_loader.rust_target", &path)?,
            toolchain_inspection: required_map_value(
                &values,
                "uefi_loader.toolchain_inspection",
                &path,
            )?,
            artifact_inspection: required_map_value(
                &values,
                "uefi_loader.artifact_inspection",
                &path,
            )?,
        };
        validate_loader_profile_components(&profile)?;
        Ok(profile)
    }

    fn validate_provenance_template(&self, repository: &Path) -> Result<(), Failure> {
        let path = repository.join("toolchain/templates/build-provenance.toml");
        let values = parse_scalar_toml(&read_file(&path)?, &path)?;
        expect_map_value(&values, "schema_version", "1", &path)?;
        // Filled from toolchain/versions.toml when a record is generated; the
        // template does not restate the Deepwyrm pin.
        expect_map_value(&values, "source.deepwyrm_revision", "", &path)?;
        expect_map_value(
            &values,
            "source.deepwyrm_abi_dependency_state",
            "available",
            &path,
        )?;
        expect_map_value(
            &values,
            "source.rust_revision",
            self.required("rust.wyrmroot_revision")?,
            &path,
        )?;
        expect_map_value(
            &values,
            "toolchain.rust_toolchain_name",
            self.required("rust.local_toolchain_name")?,
            &path,
        )?;
        Ok(())
    }

    fn require_revision(&self, key: &str) -> Result<(), Failure> {
        let value = self.required(key)?;
        if value.len() != 40
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Failure::task(format!(
                "toolchain/versions.toml key '{key}' must be a full lowercase Git revision"
            )));
        }
        Ok(())
    }

    fn require_abi_fingerprint(&self, key: &str) -> Result<(), Failure> {
        if !crate::abi_pairing::is_lower_hex(self.required(key)?, 64) {
            return Err(Failure::task(format!(
                "toolchain/versions.toml key '{key}' must be a 64-digit lowercase SHA-256 ABI fingerprint"
            )));
        }
        Ok(())
    }

    fn require_nonempty(&self, key: &str) -> Result<(), Failure> {
        if self.required(key)?.is_empty() {
            return Err(Failure::task(format!(
                "toolchain/versions.toml key '{key}' must not be empty"
            )));
        }
        Ok(())
    }

    fn expect(&self, key: &str, expected: &str) -> Result<(), Failure> {
        let actual = self.required(key)?;
        if actual == expected {
            Ok(())
        } else {
            Err(Failure::task(format!(
                "toolchain/versions.toml key '{key}' is '{actual}', expected '{expected}'"
            )))
        }
    }

    /// The pinned semantic ABI fingerprint, validated at load.
    pub(crate) fn deepwyrm_abi_fingerprint(&self) -> Result<&str, Failure> {
        self.required("deepwyrm.abi_fingerprint")
    }

    /// The pinned Deepwyrm revision, `[deepwyrm] revision`.
    pub(crate) fn deepwyrm_revision(&self) -> Result<&str, Failure> {
        self.required("deepwyrm.revision")
    }

    fn required(&self, key: &str) -> Result<&str, Failure> {
        self.values.get(key).map(String::as_str).ok_or_else(|| {
            Failure::task(format!(
                "toolchain/versions.toml is missing required key '{key}'"
            ))
        })
    }
}

fn read_file(path: &Path) -> Result<String, Failure> {
    fs::read_to_string(path)
        .map_err(|error| Failure::task(format!("could not read {}: {error}", path.display())))
}

pub(crate) fn parse_scalar_toml(
    contents: &str,
    path: &Path,
) -> Result<BTreeMap<String, String>, Failure> {
    if contains_toml_multiline_string(contents) {
        return Err(Failure::task(format!(
            "{} contains an unsupported TOML multiline string",
            path.display()
        )));
    }
    let mut section = String::new();
    let mut values = BTreeMap::new();

    for (index, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "]" {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') && !line.starts_with("[[") {
            section = line[1..line.len() - 1].trim().to_owned();
            continue;
        }
        if line.starts_with('[') || line.ends_with(']') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || value.is_empty() {
            return Err(Failure::task(format!(
                "{}:{} contains an empty key or value",
                path.display(),
                index + 1
            )));
        }
        if value.starts_with('[') {
            continue;
        }
        let value = if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
            value[1..value.len() - 1].to_owned()
        } else {
            value.to_owned()
        };
        let qualified = if section.is_empty() {
            key.to_owned()
        } else {
            format!("{section}.{key}")
        };
        if values.insert(qualified.clone(), value).is_some() {
            return Err(Failure::task(format!(
                "{} contains duplicate key '{qualified}'",
                path.display()
            )));
        }
    }
    Ok(values)
}

fn expect_map_value(
    values: &BTreeMap<String, String>,
    key: &str,
    expected: &str,
    path: &Path,
) -> Result<(), Failure> {
    let Some(actual) = values.get(key) else {
        return Err(Failure::task(format!(
            "{} is missing required key '{key}'",
            path.display()
        )));
    };
    if actual == expected {
        Ok(())
    } else {
        Err(Failure::task(format!(
            "{} key '{key}' is '{actual}', expected '{expected}'",
            path.display()
        )))
    }
}

fn required_map_value(
    values: &BTreeMap<String, String>,
    key: &str,
    path: &Path,
) -> Result<String, Failure> {
    let value = values.get(key).ok_or_else(|| {
        Failure::task(format!(
            "{} is missing required key '{key}'",
            path.display()
        ))
    })?;
    if value.is_empty() {
        return Err(Failure::task(format!(
            "{} key '{key}' must not be empty",
            path.display()
        )));
    }
    Ok(value.clone())
}

fn validate_loader_profile_components(profile: &LoaderProfile) -> Result<(), Failure> {
    for (label, value) in [
        ("cargo package", profile.cargo_package.as_str()),
        ("cargo binary", profile.cargo_binary.as_str()),
        ("cargo features", profile.cargo_features.as_str()),
        ("artifact name", profile.artifact_name.as_str()),
    ] {
        if value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            || value == "."
            || value == ".."
        {
            return Err(Failure::task(format!(
                "UEFI loader {label} '{value}' is not a safe deterministic component"
            )));
        }
    }
    if profile.rust_target != "x86_64-unknown-uefi" {
        return Err(Failure::task(format!(
            "UEFI loader target is '{}', expected 'x86_64-unknown-uefi'",
            profile.rust_target
        )));
    }
    if profile.cargo_features != "firmware" {
        return Err(Failure::task(format!(
            "UEFI loader Cargo feature is '{}', expected 'firmware'",
            profile.cargo_features
        )));
    }
    if profile.uefi_crate_version != "0.39.0" {
        return Err(Failure::task(format!(
            "UEFI loader crate version is '{}', expected '0.39.0'",
            profile.uefi_crate_version
        )));
    }
    if profile.artifact_name != format!("{}.efi", profile.cargo_binary) {
        return Err(Failure::task(format!(
            "UEFI loader artifact '{}' does not match Cargo binary '{}.efi'",
            profile.artifact_name, profile.cargo_binary
        )));
    }
    for (label, actual, expected) in [
        (
            "toolchain inspection",
            profile.toolchain_inspection.as_str(),
            "toolchain/verify-uefi-toolchain.sh",
        ),
        (
            "artifact inspection",
            profile.artifact_inspection.as_str(),
            "toolchain/inspect-uefi-artifact.sh",
        ),
    ] {
        if actual != expected {
            return Err(Failure::task(format!(
                "UEFI loader {label} path is '{actual}', expected '{expected}'"
            )));
        }
    }
    Ok(())
}

fn validate_loader_dependency(repository: &Path, profile: &LoaderProfile) -> Result<(), Failure> {
    let root_path = repository.join("Cargo.toml");
    let root_manifest = read_file(&root_path)?;
    let root_ready = root_has_uefi_dependency(&root_manifest, &profile.uefi_crate_version);
    if !root_ready {
        return Err(Failure::task(format!(
            "{} must pin workspace dependency uefi exactly at ={} with default features disabled",
            root_path.display(),
            profile.uefi_crate_version
        )));
    }

    let loader_path = repository.join("loader/Cargo.toml");
    let loader_manifest = read_file(&loader_path)?;
    let loader_ready = loader_has_optional_uefi_dependency(&loader_manifest);
    if !loader_ready {
        return Err(Failure::task(format!(
            "{} must consume uefi as an optional workspace dependency",
            loader_path.display()
        )));
    }

    let lock_path = repository.join("Cargo.lock");
    let lockfile = read_file(&lock_path)?;
    if !lock_has_package(&lockfile, "uefi", &profile.uefi_crate_version) {
        return Err(Failure::task(format!(
            "{} does not resolve uefi {}",
            lock_path.display(),
            profile.uefi_crate_version
        )));
    }
    Ok(())
}

fn root_has_uefi_dependency(manifest: &str, version: &str) -> bool {
    manifest_inline_dependency(manifest, "workspace.dependencies", "uefi").is_some_and(|fields| {
        let required_features = BTreeSet::from([
            "alloc".to_owned(),
            "global_allocator".to_owned(),
            "panic_handler".to_owned(),
        ]);
        fields.get("version").map(String::as_str) == Some(format!("\"={version}\"").as_str())
            && fields.get("default-features").map(String::as_str) == Some("false")
            && fields
                .get("features")
                .and_then(|value| inline_string_array(value))
                == Some(required_features)
    })
}

fn root_has_deepwyrm_dependency(manifest: &str, repository: &str, revision: &str) -> bool {
    root_has_deepwyrm_package(manifest, "deepwyrm-abi", repository, revision)
}

fn root_has_deepwyrm_package(
    manifest: &str,
    package: &str,
    repository: &str,
    revision: &str,
) -> bool {
    manifest_inline_dependency(manifest, "workspace.dependencies", package).is_some_and(|fields| {
        fields.len() == 2
            && fields
                .get("git")
                .and_then(|value| basic_toml_string(value))
                .is_some_and(|actual| git_repositories_match(actual, repository))
            && fields.get("rev").and_then(|value| basic_toml_string(value)) == Some(revision)
    })
}

fn loader_has_optional_uefi_dependency(manifest: &str) -> bool {
    manifest_inline_dependency(manifest, "dependencies", "uefi").is_some_and(|fields| {
        fields.get("workspace").map(String::as_str) == Some("true")
            && fields.get("optional").map(String::as_str) == Some("true")
    })
}

fn manifest_inline_dependency(
    manifest: &str,
    required_section: &str,
    dependency: &str,
) -> Option<BTreeMap<String, String>> {
    if contains_toml_multiline_string(manifest) {
        return None;
    }
    let mut section = "";
    for raw_line in manifest.lines() {
        let line = toml_code(raw_line);
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line.strip_prefix('[')?.strip_suffix(']')?.trim();
            continue;
        }
        if section != required_section {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if name.trim() != dependency {
            continue;
        }
        let table = value.trim().strip_prefix('{')?.strip_suffix('}')?;
        let mut fields = BTreeMap::new();
        for assignment in split_inline_table(table)? {
            let (key, value) = assignment.split_once('=')?;
            let key = key.trim();
            let value = value.trim();
            if key.is_empty()
                || value.is_empty()
                || fields.insert(key.to_owned(), value.to_owned()).is_some()
            {
                return None;
            }
        }
        return Some(fields);
    }
    None
}

fn split_inline_table(table: &str) -> Option<Vec<&str>> {
    let mut assignments = Vec::new();
    let mut start = 0;
    let mut nested = 0_u32;
    let mut quoted = false;
    let mut escaped = false;

    for (index, character) in table.char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                quoted = false;
            }
            continue;
        }
        match character {
            '"' => quoted = true,
            '[' | '{' | '(' => nested = nested.checked_add(1)?,
            ']' | '}' | ')' => nested = nested.checked_sub(1)?,
            ',' if nested == 0 => {
                assignments.push(&table[start..index]);
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    if quoted || escaped || nested != 0 {
        return None;
    }
    assignments.push(&table[start..]);
    Some(assignments)
}

fn inline_string_array(value: &str) -> Option<BTreeSet<String>> {
    let contents = value.trim().strip_prefix('[')?.strip_suffix(']')?;
    let mut values = BTreeSet::new();
    for item in split_inline_table(contents)? {
        let item = item.trim().strip_prefix('"')?.strip_suffix('"')?;
        if item.is_empty()
            || !item
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || !values.insert(item.to_owned())
        {
            return None;
        }
    }
    Some(values)
}

fn lock_has_package(lockfile: &str, name: &str, version: &str) -> bool {
    parse_lock_packages(lockfile).is_some_and(|packages| {
        packages
            .iter()
            .any(|package| package.name == name && package.version == version)
    })
}

fn lock_has_git_package(lockfile: &str, name: &str, repository: &str, revision: &str) -> bool {
    let Some(packages) = parse_lock_packages(lockfile) else {
        return false;
    };
    let mut matching = packages.iter().filter(|package| package.name == name);
    let Some(package) = matching.next() else {
        return false;
    };
    matching.next().is_none()
        && package
            .source
            .is_some_and(|source| git_lock_source_matches(source, repository, revision))
}

struct LockPackage<'a> {
    name: &'a str,
    version: &'a str,
    source: Option<&'a str>,
}

fn parse_lock_packages(lockfile: &str) -> Option<Vec<LockPackage<'_>>> {
    if contains_toml_multiline_string(lockfile) {
        return None;
    }
    let mut packages = Vec::new();
    let mut in_package = false;
    let mut name = None;
    let mut version = None;
    let mut source = None;

    for raw_line in lockfile.lines() {
        let line = toml_code(raw_line);
        if line.is_empty() {
            continue;
        }
        if line == "[[package]]" {
            finish_lock_package(
                &mut packages,
                in_package,
                &mut name,
                &mut version,
                &mut source,
            )?;
            in_package = true;
            continue;
        }
        if line.starts_with('[') {
            finish_lock_package(
                &mut packages,
                in_package,
                &mut name,
                &mut version,
                &mut source,
            )?;
            in_package = false;
            continue;
        }
        if !in_package {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.contains(['"', '\'']) || key.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return None;
        }
        let value = value.trim();
        match key {
            "name" if name.is_none() => name = Some(basic_toml_string(value)?),
            "version" if version.is_none() => version = Some(basic_toml_string(value)?),
            "source" if source.is_none() => source = Some(basic_toml_string(value)?),
            "name" | "version" | "source" => return None,
            _ => {}
        }
    }
    finish_lock_package(
        &mut packages,
        in_package,
        &mut name,
        &mut version,
        &mut source,
    )?;
    Some(packages)
}

fn finish_lock_package<'a>(
    packages: &mut Vec<LockPackage<'a>>,
    in_package: bool,
    name: &mut Option<&'a str>,
    version: &mut Option<&'a str>,
    source: &mut Option<&'a str>,
) -> Option<()> {
    if in_package {
        packages.push(LockPackage {
            name: name.take()?,
            version: version.take()?,
            source: source.take(),
        });
    }
    *name = None;
    *version = None;
    *source = None;
    Some(())
}

fn git_lock_source_matches(source: &str, repository: &str, revision: &str) -> bool {
    let Some(source) = source.strip_prefix("git+") else {
        return false;
    };
    let Some((requested, locked_revision)) = source.rsplit_once('#') else {
        return false;
    };
    if locked_revision != revision {
        return false;
    }
    let Some((actual_repository, requested_revision)) = requested.rsplit_once("?rev=") else {
        return false;
    };
    requested_revision == revision && git_repositories_match(actual_repository, repository)
}

fn git_repositories_match(left: &str, right: &str) -> bool {
    fn normalized(repository: &str) -> &str {
        let repository = repository.trim_end_matches('/');
        repository.strip_suffix(".git").unwrap_or(repository)
    }

    normalized(left) == normalized(right)
}

fn basic_toml_string(value: &str) -> Option<&str> {
    let value = value.trim();
    let contents = value.strip_prefix('"')?.strip_suffix('"')?;
    if contents
        .bytes()
        .any(|byte| byte == b'"' || byte == b'\\' || byte.is_ascii_control())
    {
        return None;
    }
    Some(contents)
}

fn toml_code(line: &str) -> &str {
    let mut quoted = None;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if let Some(quote) = quoted {
            if quote == '"' && escaped {
                escaped = false;
            } else if quote == '"' && character == '\\' {
                escaped = true;
            } else if character == quote {
                quoted = None;
            }
            continue;
        }
        match character {
            '"' | '\'' => quoted = Some(character),
            '#' => return line[..index].trim(),
            _ => {}
        }
    }
    line.trim()
}

fn contains_toml_multiline_string(contents: &str) -> bool {
    contents.contains("\"\"\"") || contents.contains("'''")
}

fn has_abi_consumer(repository: &Path) -> Result<bool, Failure> {
    has_workspace_dependency_consumer(repository, "deepwyrm-abi")
}

fn has_workspace_dependency_consumer(repository: &Path, dependency: &str) -> Result<bool, Failure> {
    let root_manifest_path = repository.join("Cargo.toml");
    let root_manifest = read_file(&root_manifest_path)?;
    for member in parse_workspace_members(&root_manifest, &root_manifest_path)? {
        let manifest = workspace_member_manifest(repository, &member)?;
        if manifest_consumes_workspace_dependency(&read_file(&manifest)?, dependency) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn workspace_member_consumes_dependency(
    repository: &Path,
    member: &str,
    dependency: &str,
) -> Result<bool, Failure> {
    let root_manifest_path = repository.join("Cargo.toml");
    let root_manifest = read_file(&root_manifest_path)?;
    let members = parse_workspace_members(&root_manifest, &root_manifest_path)?;
    if !members.contains(member) {
        return Ok(false);
    }
    let manifest = workspace_member_manifest(repository, member)?;
    Ok(manifest_consumes_workspace_dependency(
        &read_file(&manifest)?,
        dependency,
    ))
}

fn parse_workspace_members(manifest: &str, path: &Path) -> Result<BTreeSet<String>, Failure> {
    if contains_toml_multiline_string(manifest) {
        return Err(Failure::task(format!(
            "{} contains an unsupported TOML multiline string",
            path.display()
        )));
    }
    let mut section = String::new();
    let mut members_body = None;
    let mut collecting_members = false;

    for (index, raw_line) in manifest.lines().enumerate() {
        let line = toml_code(raw_line);
        if line.is_empty() {
            continue;
        }
        if collecting_members {
            collecting_members = collect_workspace_members_line(
                line,
                members_body
                    .as_mut()
                    .expect("member collection has initialized storage"),
                path,
                index + 1,
            )?;
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_owned();
            continue;
        }
        if section != "workspace" {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.contains(['"', '\'']) || key.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(Failure::task(format!(
                "{} uses an unsupported workspace key form",
                path.display()
            )));
        }
        if key == "exclude" {
            return Err(Failure::task(format!(
                "{} uses unsupported workspace exclude semantics",
                path.display()
            )));
        }
        if key != "members" {
            continue;
        }
        if members_body.is_some() {
            return Err(Failure::task(format!(
                "{} contains duplicate workspace members",
                path.display()
            )));
        }
        let value = value.trim();
        let Some(value) = value.strip_prefix('[') else {
            return Err(Failure::task(format!(
                "{}:{} workspace members must be an explicit string array",
                path.display(),
                index + 1
            )));
        };
        members_body = Some(String::new());
        collecting_members = collect_workspace_members_line(
            value,
            members_body
                .as_mut()
                .expect("member collection has initialized storage"),
            path,
            index + 1,
        )?;
    }

    if collecting_members {
        return Err(Failure::task(format!(
            "{} contains an unterminated workspace members array",
            path.display()
        )));
    }
    let body = members_body.ok_or_else(|| {
        Failure::task(format!(
            "{} is missing the explicit workspace members array",
            path.display()
        ))
    })?;
    let items = split_inline_table(&body).ok_or_else(|| {
        Failure::task(format!(
            "{} contains malformed workspace members",
            path.display()
        ))
    })?;
    let item_count = items.len();
    let mut members = BTreeSet::new();
    for (index, item) in items.into_iter().enumerate() {
        let item = item.trim();
        if item.is_empty() && index + 1 == item_count {
            continue;
        }
        let member = basic_toml_string(item).ok_or_else(|| {
            Failure::task(format!(
                "{} workspace member must be a basic string path",
                path.display()
            ))
        })?;
        validate_workspace_member(member, path)?;
        if !members.insert(member.to_owned()) {
            return Err(Failure::task(format!(
                "{} contains duplicate workspace member '{member}'",
                path.display()
            )));
        }
    }
    if members.is_empty() {
        return Err(Failure::task(format!(
            "{} workspace members must not be empty",
            path.display()
        )));
    }
    Ok(members)
}

fn collect_workspace_members_line(
    line: &str,
    body: &mut String,
    path: &Path,
    line_number: usize,
) -> Result<bool, Failure> {
    let Some(closing) = line.find(']') else {
        body.push_str(line);
        body.push('\n');
        return Ok(true);
    };
    if !line[closing + 1..].trim().is_empty() || line[..closing].contains('[') {
        return Err(Failure::task(format!(
            "{}:{line_number} contains malformed workspace members",
            path.display()
        )));
    }
    body.push_str(&line[..closing]);
    Ok(false)
}

fn validate_workspace_member(member: &str, path: &Path) -> Result<(), Failure> {
    let relative = Path::new(member);
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || member
            .bytes()
            .any(|byte| matches!(byte, b'*' | b'?' | b'[' | b']'))
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(Failure::task(format!(
            "{} workspace member '{member}' is not a non-traversing relative path",
            path.display()
        )));
    }
    Ok(())
}

fn workspace_member_manifest(
    repository: &Path,
    member: &str,
) -> Result<std::path::PathBuf, Failure> {
    let mut current = repository.to_path_buf();
    for component in Path::new(member).components() {
        let std::path::Component::Normal(component) = component else {
            return Err(Failure::task(
                "validated workspace member path changed form",
            ));
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            Failure::task(format!(
                "could not inspect workspace member path {}: {error}",
                current.display()
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(Failure::task(format!(
                "workspace member path must contain only non-symlink directories: {}",
                current.display()
            )));
        }
    }
    let manifest = current.join("Cargo.toml");
    let metadata = fs::symlink_metadata(&manifest).map_err(|error| {
        Failure::task(format!(
            "could not inspect workspace member manifest {}: {error}",
            manifest.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Failure::task(format!(
            "workspace member manifest must be a regular non-symlink file: {}",
            manifest.display()
        )));
    }
    Ok(manifest)
}

fn manifest_consumes_workspace_dependency(manifest: &str, dependency: &str) -> bool {
    if contains_toml_multiline_string(manifest) {
        return false;
    }
    let mut section = String::new();
    let workspace_key = format!("{dependency}.workspace");
    let field_prefix = format!("{dependency}.");
    let dependency_table = format!("dependencies.{dependency}");
    let mut consumes = false;
    for raw_line in manifest.lines() {
        let line = toml_code(raw_line);
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_owned();
            if section == dependency_table || section.starts_with("dependencies.") {
                return false;
            }
            continue;
        }
        if section != "dependencies" {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key.contains(['"', '\'']) || key.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return false;
        }
        if key == workspace_key {
            if consumes || value != "true" {
                return false;
            }
            consumes = true;
            continue;
        }
        if key == dependency || key.starts_with(&field_prefix) {
            return false;
        }
    }
    consumes
}

fn validate_reserved_target_policy(repository: &Path, native_target: &str) -> Result<(), Failure> {
    for relative in [
        ".cargo",
        "bootstrap",
        "crates",
        "loader",
        "toolchain",
        "userspace",
    ] {
        scan_policy_tree(&repository.join(relative), native_target)?;
    }
    Ok(())
}

fn scan_policy_tree(root: &Path, native_target: &str) -> Result<(), Failure> {
    for entry in fs::read_dir(root)
        .map_err(|error| Failure::task(format!("could not inspect {}: {error}", root.display())))?
    {
        let entry = entry.map_err(|error| {
            Failure::task(format!(
                "could not inspect an entry in {}: {error}",
                root.display()
            ))
        })?;
        let path = entry.path();
        let file_type = checked_file_type(&entry, root)?;
        if file_type.is_symlink() {
            return Err(Failure::task(format!(
                "refusing to follow symlink while validating reserved-target policy: {}",
                path.display()
            )));
        }
        if file_type.is_dir() {
            // Request records are immutable evidence, not guest build inputs. They may name
            // forbidden configurations to document that validation rejected them.
            if root.file_name().and_then(|name| name.to_str()) == Some("toolchain")
                && path.file_name().and_then(|name| name.to_str()) == Some("requests")
            {
                continue;
            }
            scan_policy_tree(&path, native_target)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }

        let extension = path.extension().and_then(|value| value.to_str());
        if extension == Some("json") {
            let contents = read_file(&path)?;
            if path.file_stem().and_then(|value| value.to_str()) == Some(native_target)
                || contents.contains(native_target)
                || contents.contains("\"llvm-target\"")
            {
                return Err(Failure::task(format!(
                    "unimplemented native target must not be supplied by target JSON {}",
                    path.display()
                )));
            }
        }

        if !matches!(extension, Some("rs" | "toml")) {
            continue;
        }
        let contents = read_file(&path)?;
        if contents.contains("cfg(unix)")
            || contents.contains("target_family = \"unix\"")
            || (contents.contains("target-family") && contents.contains("unix"))
        {
            return Err(Failure::task(format!(
                "reserved Wyrmroot native target must not inherit Unix behavior in {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn checked_file_type(entry: &fs::DirEntry, root: &Path) -> Result<fs::FileType, Failure> {
    entry.file_type().map_err(|error| {
        Failure::task(format!(
            "could not inspect an entry type in {}: {error}",
            root.display()
        ))
    })
}

#[cfg(test)]
mod tests;
