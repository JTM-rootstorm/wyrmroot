use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::error::Failure;

#[derive(Debug)]
pub(crate) struct BuildManifest {
    values: BTreeMap<String, String>,
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
        self.require_revision("rust.upstream_stable_revision")?;
        self.require_revision("rust.wyrmroot_revision")?;
        self.require_nonempty("deepwyrm.repository")?;
        self.require_nonempty("rust.upstream_stable_release")?;
        self.require_nonempty("rust.local_toolchain_name")?;
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

    pub(crate) fn validate_build_readiness(&self, repository: &Path) -> Result<(), Failure> {
        self.validate_phase_a_states()?;

        let revision = self.required("deepwyrm.revision")?;
        let root_manifest = read_file(&repository.join("Cargo.toml"))?;
        if !root_manifest.contains("deepwyrm-abi") || !root_manifest.contains(revision) {
            return Err(Failure::task(format!(
                "Cargo.toml does not pin deepwyrm-abi at manifest revision {revision}"
            )));
        }

        let lockfile = read_file(&repository.join("Cargo.lock"))?;
        if !lockfile.contains("name = \"deepwyrm-abi\"") || !lockfile.contains(revision) {
            return Err(Failure::task(format!(
                "Cargo.lock does not resolve deepwyrm-abi at manifest revision {revision}"
            )));
        }

        if !has_abi_consumer(repository)? {
            return Err(Failure::task(
                "no Wyrmroot workspace crate consumes the pinned deepwyrm-abi dependency",
            ));
        }

        self.validate_profiles(repository)?;
        self.validate_provenance_template(repository)?;
        validate_reserved_target_policy(repository, self.required("rust.native_target")?)?;
        Ok(())
    }

    fn validate_phase_a_states(&self) -> Result<(), Failure> {
        self.expect("deepwyrm.abi_dependency_state", "available")?;
        self.expect("rust.native_target_state", "reserved-not-yet-implemented")?;
        Ok(())
    }

    fn validate_profiles(&self, repository: &Path) -> Result<(), Failure> {
        let path = repository.join("toolchain/profiles.toml");
        let values = parse_scalar_toml(&read_file(&path)?, &path)?;
        expect_map_value(&values, "schema_version", "1", &path)?;
        expect_map_value(
            &values,
            "native_guest.rust_target",
            self.required("rust.native_target")?,
            &path,
        )?;
        expect_map_value(
            &values,
            "native_guest.target_state",
            "reserved-not-yet-implemented",
            &path,
        )?;
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

    fn validate_provenance_template(&self, repository: &Path) -> Result<(), Failure> {
        let path = repository.join("toolchain/templates/build-provenance.toml");
        let values = parse_scalar_toml(&read_file(&path)?, &path)?;
        expect_map_value(&values, "schema_version", "1", &path)?;
        expect_map_value(
            &values,
            "source.deepwyrm_revision",
            self.required("deepwyrm.revision")?,
            &path,
        )?;
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

fn parse_scalar_toml(contents: &str, path: &Path) -> Result<BTreeMap<String, String>, Failure> {
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

fn has_abi_consumer(repository: &Path) -> Result<bool, Failure> {
    for relative in ["bootstrap", "crates", "loader", "userspace"] {
        let root = repository.join(relative);
        if manifest_tree_contains(&root, "deepwyrm-abi")? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn manifest_tree_contains(root: &Path, needle: &str) -> Result<bool, Failure> {
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
                "refusing to follow symlink while validating ABI consumers: {}",
                path.display()
            )));
        }
        if file_type.is_dir() {
            if manifest_tree_contains(&path, needle)? {
                return Ok(true);
            }
        } else if file_type.is_file()
            && path.file_name().and_then(|name| name.to_str()) == Some("Cargo.toml")
            && read_file(&path)?.contains(needle)
        {
            return Ok(true);
        }
    }
    Ok(false)
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
mod tests {
    use super::{BuildManifest, parse_scalar_toml};
    use std::collections::BTreeMap;
    use std::path::Path;

    #[cfg(unix)]
    use super::scan_policy_tree;
    #[cfg(unix)]
    use std::fs;

    #[test]
    fn scalar_manifest_parser_qualifies_sections_and_skips_arrays() {
        let values = parse_scalar_toml(
            "schema_version = 1\n[deepwyrm]\nrevision = \"0123\"\nitems = [\n  \"x\",\n]\n[constraints]\nstrict = false\n",
            Path::new("versions.toml"),
        )
        .unwrap();
        assert_eq!(values.get("schema_version").unwrap(), "1");
        assert_eq!(values.get("deepwyrm.revision").unwrap(), "0123");
        assert_eq!(values.get("constraints.strict").unwrap(), "false");
        assert!(!values.contains_key("deepwyrm.items"));
    }

    #[test]
    fn host_tests_allow_pending_abi_but_build_states_fail_closed() {
        let pending = phase_a_manifest("not-yet-available", "reserved-not-yet-implemented");
        pending
            .validate_host_test_metadata()
            .expect("host metadata validation must remain independently runnable");
        assert!(pending.validate_phase_a_states().is_err());

        let ready = phase_a_manifest("available", "reserved-not-yet-implemented");
        ready
            .validate_phase_a_states()
            .expect("available ABI with a reserved target is the WYR0-A build state");

        let premature_target = phase_a_manifest("available", "implemented");
        assert!(premature_target.validate_phase_a_states().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn policy_scan_rejects_symlinks_without_following_them() {
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "wyrmroot-xtask-symlink-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create isolated test directory");
        symlink("/", root.join("escape")).expect("create test symlink");

        let failure = scan_policy_tree(&root, "x86_64-unknown-wyrmroot")
            .expect_err("policy scan followed or accepted a symlink");
        assert!(failure.message.contains("refusing to follow symlink"));

        fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    fn phase_a_manifest(abi_state: &str, target_state: &str) -> BuildManifest {
        BuildManifest {
            values: BTreeMap::from([
                ("schema_version".to_owned(), "1".to_owned()),
                ("milestone".to_owned(), "WYR0".to_owned()),
                (
                    "deepwyrm.revision".to_owned(),
                    "0123456789abcdef0123456789abcdef01234567".to_owned(),
                ),
                (
                    "rust.upstream_stable_revision".to_owned(),
                    "89abcdef0123456789abcdef0123456789abcdef".to_owned(),
                ),
                (
                    "rust.wyrmroot_revision".to_owned(),
                    "fedcba9876543210fedcba9876543210fedcba98".to_owned(),
                ),
                (
                    "deepwyrm.repository".to_owned(),
                    "https://example.invalid/deepwyrm".to_owned(),
                ),
                (
                    "rust.upstream_stable_release".to_owned(),
                    "1.97.1".to_owned(),
                ),
                (
                    "rust.local_toolchain_name".to_owned(),
                    "wyrmroot-test".to_owned(),
                ),
                (
                    "rust.native_target".to_owned(),
                    "x86_64-unknown-wyrmroot".to_owned(),
                ),
                (
                    "deepwyrm.abi_dependency_state".to_owned(),
                    abi_state.to_owned(),
                ),
                (
                    "rust.native_target_state".to_owned(),
                    target_state.to_owned(),
                ),
                (
                    "llvm.host_version_state".to_owned(),
                    "not-yet-adopted".to_owned(),
                ),
                (
                    "bootstrap_constraints.allow_moving_rust_channel".to_owned(),
                    "false".to_owned(),
                ),
                (
                    "bootstrap_constraints.allow_host_target_defaults_for_guest".to_owned(),
                    "false".to_owned(),
                ),
                (
                    "bootstrap_constraints.allow_host_libc_for_guest".to_owned(),
                    "false".to_owned(),
                ),
                (
                    "bootstrap_constraints.allow_unimplemented_deepwyrm_abi_dependency".to_owned(),
                    "false".to_owned(),
                ),
                (
                    "bootstrap_constraints.allow_unimplemented_native_target".to_owned(),
                    "false".to_owned(),
                ),
            ]),
        }
    }
}
