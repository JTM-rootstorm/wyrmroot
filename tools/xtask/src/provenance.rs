use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::deep_layout::{
    GENERATED_ABI_ASSERTION_SCOPE, GENERATED_POLICY_CONTRACT, GENERATED_POLICY_VALIDATION_SCOPE,
    LAYOUT_SCHEMA, LAYOUT_VERSION, TRANSITION_TABLE_CONTRACT,
};
use crate::error::Failure;

const MAX_PROVENANCE_BYTES: u64 = 1024 * 1024;
const MAX_PROVENANCE_PATH_BYTES: usize = 4096;
const MAX_PROVENANCE_IDENTIFIER_BYTES: usize = 128;
const LOADER_PROVENANCE_SCHEMA_VERSION: u64 = 3;
const LOADER_PROVENANCE_MANIFEST_KIND: &str = "wyrmroot-wyr0-b-loader-provenance";
const LOADER_PROVENANCE_RECORD_ROLE: &str = "generated-loader-artifact-provenance";
const BUILD_PROVENANCE_TEMPLATE_SCHEMA_VERSION: u64 = 1;
const BUILD_PROVENANCE_TEMPLATE_MANIFEST_KIND: &str = "wyrmroot-build-provenance-template";
const BUILD_PROVENANCE_TEMPLATE: &str =
    include_str!("../../../toolchain/templates/build-provenance.toml");

pub(crate) struct LoaderProvenance<'a> {
    pub(crate) repository_revision: &'a str,
    pub(crate) repository_dirty: bool,
    pub(crate) deepwyrm_revision: &'a str,
    pub(crate) rust_revision: &'a str,
    pub(crate) rust_toolchain_name: &'a str,
    pub(crate) rustc_sha256: &'a str,
    pub(crate) cargo_sha256: &'a str,
    pub(crate) rust_lld_sha256: &'a str,
    pub(crate) uefi_core_sha256: &'a str,
    pub(crate) uefi_alloc_sha256: &'a str,
    pub(crate) uefi_builtins_sha256: &'a str,
    pub(crate) rustc_driver_sha256: &'a str,
    pub(crate) llvm_sha256: &'a str,
    pub(crate) toolchain_tree_sha256: &'a str,
    pub(crate) toolchain_manifest_sha256: &'a str,
    pub(crate) target: &'a str,
    pub(crate) package: &'a str,
    pub(crate) binary: &'a str,
    pub(crate) artifact_path: &'a str,
    pub(crate) artifact_sha256: &'a str,
    pub(crate) debug_path: &'a str,
    pub(crate) debug_sha256: &'a str,
    pub(crate) versions_sha256: &'a str,
    pub(crate) profiles_sha256: &'a str,
    pub(crate) deep_layout_sha256: &'a str,
    pub(crate) generated_layout_policy_sha256: &'a str,
    pub(crate) toolchain_report_sha256: &'a str,
    pub(crate) artifact_report_sha256: &'a str,
}

pub(crate) fn write_loader_provenance(
    target_directory: &Path,
    record: &LoaderProvenance<'_>,
) -> Result<PathBuf, Failure> {
    let contents = render(record)?;
    let directory = target_directory.join("provenance");
    let directory_identity = ensure_provenance_directory(target_directory, &directory)?;
    let destination = directory.join("wyr0-b-loader.toml");
    validate_optional_regular_file(&destination, "loader provenance")?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| Failure::task(format!("system clock precedes Unix epoch: {error}")))?
        .as_nanos();
    let mut temporary = None;
    for attempt in 0_u8..16 {
        let candidate = directory.join(format!(
            ".wyr0-b-loader.toml.tmp-{}-{nonce}-{attempt}",
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(Failure::task(format!(
                    "could not create exclusive provenance temporary file: {error}"
                )));
            }
        }
    }
    let (temporary, mut file) = temporary
        .ok_or_else(|| Failure::task("could not reserve a unique provenance temporary file"))?;
    let result = (|| {
        file.write_all(contents.as_bytes()).map_err(|error| {
            Failure::task(format!(
                "could not write temporary provenance {}: {error}",
                temporary.display()
            ))
        })?;
        file.flush().map_err(|error| {
            Failure::task(format!(
                "could not flush temporary provenance {}: {error}",
                temporary.display()
            ))
        })?;
        verify_open_file_identity(&file, &temporary, "loader provenance temporary file")?;
        verify_directory_identity(&directory, &directory_identity, "provenance directory")?;
        validate_optional_regular_file(&destination, "loader provenance")?;
        fs::rename(&temporary, &destination).map_err(|error| {
            Failure::task(format!(
                "could not install provenance record {}: {error}",
                destination.display()
            ))
        })?;
        verify_directory_identity(&directory, &directory_identity, "provenance directory")?;
        let installed = read_bounded(&destination, MAX_PROVENANCE_BYTES, "loader provenance")?;
        if installed != contents.as_bytes() {
            return Err(Failure::task("installed loader provenance content changed"));
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map(|()| destination)
}

fn ensure_provenance_directory(
    target_directory: &Path,
    directory: &Path,
) -> Result<fs::Metadata, Failure> {
    if !target_directory.is_absolute() {
        return Err(Failure::task(
            "provenance target directory must be absolute",
        ));
    }
    validate_directory(target_directory, "provenance target directory")?;
    let canonical = fs::canonicalize(target_directory).map_err(|error| {
        Failure::task(format!(
            "could not canonicalize provenance target directory: {error}"
        ))
    })?;
    if canonical != target_directory {
        return Err(Failure::task(
            "provenance target directory is not canonical or contains a symlink",
        ));
    }
    match fs::create_dir(directory) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(Failure::task(format!(
                "could not create provenance directory {}: {error}",
                directory.display()
            )));
        }
    }
    validate_directory(directory, "provenance directory")?;
    fs::symlink_metadata(directory)
        .map_err(|error| Failure::task(format!("could not inspect provenance directory: {error}")))
}

fn validate_directory(path: &Path, label: &str) -> Result<(), Failure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Failure::task(format!("could not inspect {label}: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Failure::task(format!(
            "{label} must be a non-symlink directory"
        )));
    }
    Ok(())
}

fn validate_optional_regular_file(path: &Path, label: &str) -> Result<(), Failure> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(Failure::task(format!(
                "{label} destination must be a regular non-symlink file"
            )))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Failure::task(format!(
            "could not inspect {label} destination: {error}"
        ))),
    }
}

fn verify_directory_identity(
    path: &Path,
    expected: &fs::Metadata,
    label: &str,
) -> Result<(), Failure> {
    let current = fs::symlink_metadata(path)
        .map_err(|error| Failure::task(format!("could not re-inspect {label}: {error}")))?;
    if current.file_type().is_symlink()
        || !current.is_dir()
        || !same_file_identity(expected, &current)
    {
        return Err(Failure::task(format!(
            "{label} identity changed during provenance installation"
        )));
    }
    Ok(())
}

fn verify_open_file_identity(file: &File, path: &Path, label: &str) -> Result<(), Failure> {
    let opened = file
        .metadata()
        .map_err(|error| Failure::task(format!("could not inspect open {label}: {error}")))?;
    let current = fs::symlink_metadata(path)
        .map_err(|error| Failure::task(format!("could not re-inspect {label}: {error}")))?;
    if current.file_type().is_symlink()
        || !current.is_file()
        || !same_file_identity(&opened, &current)
    {
        return Err(Failure::task(format!(
            "{label} identity changed during validation"
        )));
    }
    Ok(())
}

fn read_bounded(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>, Failure> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| Failure::task(format!("could not inspect {label}: {error}")))?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(Failure::task(format!(
            "{label} must be a regular non-symlink file"
        )));
    }
    let file = File::open(path)
        .map_err(|error| Failure::task(format!("could not open {label}: {error}")))?;
    let opened = file
        .metadata()
        .map_err(|error| Failure::task(format!("could not inspect open {label}: {error}")))?;
    if !same_file_identity(&before, &opened) {
        return Err(Failure::task(format!(
            "{label} identity changed while it was opened"
        )));
    }
    let mut bytes = Vec::new();
    (&file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| Failure::task(format!("could not read {label}: {error}")))?;
    if bytes.len() as u64 > maximum {
        return Err(Failure::task(format!(
            "{label} exceeds the {maximum}-byte limit"
        )));
    }
    verify_open_file_identity(&file, path, label)?;
    Ok(bytes)
}

#[cfg(unix)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
        && left.created().ok() == right.created().ok()
}

fn render(record: &LoaderProvenance<'_>) -> Result<String, Failure> {
    validate_template_schema_distinction(BUILD_PROVENANCE_TEMPLATE)?;
    for (value, label) in [
        (record.repository_revision, "Wyrmroot revision"),
        (record.deepwyrm_revision, "Deepwyrm revision"),
        (record.rust_revision, "Rust revision"),
    ] {
        validate_lower_hex(value, 40, label)?;
    }
    for (value, label) in [
        (record.rustc_sha256, "rustc SHA-256"),
        (record.cargo_sha256, "Cargo SHA-256"),
        (record.rust_lld_sha256, "rust-lld SHA-256"),
        (record.uefi_core_sha256, "UEFI core library SHA-256"),
        (record.uefi_alloc_sha256, "UEFI alloc library SHA-256"),
        (record.uefi_builtins_sha256, "UEFI builtins library SHA-256"),
        (record.rustc_driver_sha256, "rustc driver SHA-256"),
        (record.llvm_sha256, "LLVM SHA-256"),
        (record.toolchain_tree_sha256, "toolchain tree SHA-256"),
        (
            record.toolchain_manifest_sha256,
            "toolchain manifest SHA-256",
        ),
        (record.artifact_sha256, "UEFI loader artifact SHA-256"),
        (record.debug_sha256, "UEFI loader debug symbol SHA-256"),
        (record.versions_sha256, "versions manifest SHA-256"),
        (record.profiles_sha256, "profiles manifest SHA-256"),
        (record.deep_layout_sha256, "Deepwyrm layout SHA-256"),
        (
            record.generated_layout_policy_sha256,
            "generated layout policy SHA-256",
        ),
        (
            record.toolchain_report_sha256,
            "toolchain validation report SHA-256",
        ),
        (
            record.artifact_report_sha256,
            "artifact inspection report SHA-256",
        ),
    ] {
        validate_lower_hex(value, 64, label)?;
    }
    for (value, label) in [
        (record.rust_toolchain_name, "Rust toolchain name"),
        (record.target, "Rust target"),
        (record.package, "Cargo package"),
        (record.binary, "Cargo binary"),
    ] {
        validate_identifier(value, label)?;
    }
    validate_relative_path(record.artifact_path, "UEFI loader artifact")?;
    validate_relative_path(record.debug_path, "UEFI loader debug symbols")?;
    Ok(format!(
        "schema_version = {}\n\
manifest_kind = \"{}\"\n\
record_role = \"{}\"\n\
distinct_from_schema_version = {}\n\
distinct_from_manifest_kind = \"{}\"\n\
\n\
[source]\n\
wyrmroot_revision = \"{}\"\n\
wyrmroot_dirty = {}\n\
deepwyrm_revision = \"{}\"\n\
rust_revision = \"{}\"\n\
\n\
[configuration]\n\
deepwyrm_layout_schema = \"{}\"\n\
deepwyrm_layout_version = {}\n\
deepwyrm_transition_table_contract = \"{}\"\n\
generated_layout_policy_contract = \"{}\"\n\
generated_layout_policy_validation_scope = \"{}\"\n\
generated_layout_abi_assertion_scope = \"{}\"\n\
behavioral_handoff_conformance = \"not-claimed-by-build-provenance\"\n\
versions_sha256 = \"{}\"\n\
profiles_sha256 = \"{}\"\n\
deepwyrm_layout_sha256 = \"{}\"\n\
generated_layout_policy_sha256 = \"{}\"\n\
\n\
[toolchain]\n\
rust_toolchain_name = \"{}\"\n\
rustc_sha256 = \"{}\"\n\
cargo_sha256 = \"{}\"\n\
rust_lld_sha256 = \"{}\"\n\
uefi_core_sha256 = \"{}\"\n\
uefi_alloc_sha256 = \"{}\"\n\
uefi_builtins_sha256 = \"{}\"\n\
rustc_driver_sha256 = \"{}\"\n\
llvm_sha256 = \"{}\"\n\
toolchain_tree_sha256 = \"{}\"\n\
artifact_manifest_sha256 = \"{}\"\n\
target = \"{}\"\n\
validation_report_sha256 = \"{}\"\n\
\n\
[build]\n\
package = \"{}\"\n\
binary = \"{}\"\n\
profile = \"dev\"\n\
\n\
[uefi_loader]\n\
artifact_path = \"{}\"\n\
artifact_sha256 = \"{}\"\n\
debug_symbol_path = \"{}\"\n\
debug_symbol_sha256 = \"{}\"\n\
inspection_report_sha256 = \"{}\"\n",
        LOADER_PROVENANCE_SCHEMA_VERSION,
        escape(LOADER_PROVENANCE_MANIFEST_KIND),
        escape(LOADER_PROVENANCE_RECORD_ROLE),
        BUILD_PROVENANCE_TEMPLATE_SCHEMA_VERSION,
        escape(BUILD_PROVENANCE_TEMPLATE_MANIFEST_KIND),
        escape(record.repository_revision),
        record.repository_dirty,
        escape(record.deepwyrm_revision),
        escape(record.rust_revision),
        escape(LAYOUT_SCHEMA),
        LAYOUT_VERSION,
        escape(TRANSITION_TABLE_CONTRACT),
        escape(GENERATED_POLICY_CONTRACT),
        escape(GENERATED_POLICY_VALIDATION_SCOPE),
        escape(GENERATED_ABI_ASSERTION_SCOPE),
        escape(record.versions_sha256),
        escape(record.profiles_sha256),
        escape(record.deep_layout_sha256),
        escape(record.generated_layout_policy_sha256),
        escape(record.rust_toolchain_name),
        escape(record.rustc_sha256),
        escape(record.cargo_sha256),
        escape(record.rust_lld_sha256),
        escape(record.uefi_core_sha256),
        escape(record.uefi_alloc_sha256),
        escape(record.uefi_builtins_sha256),
        escape(record.rustc_driver_sha256),
        escape(record.llvm_sha256),
        escape(record.toolchain_tree_sha256),
        escape(record.toolchain_manifest_sha256),
        escape(record.target),
        escape(record.toolchain_report_sha256),
        escape(record.package),
        escape(record.binary),
        escape(record.artifact_path),
        escape(record.artifact_sha256),
        escape(record.debug_path),
        escape(record.debug_sha256),
        escape(record.artifact_report_sha256),
    ))
}

fn validate_template_schema_distinction(contents: &str) -> Result<(), Failure> {
    let (schema_version, manifest_kind) = template_schema_identity(contents)?;
    if schema_version != BUILD_PROVENANCE_TEMPLATE_SCHEMA_VERSION
        || manifest_kind != BUILD_PROVENANCE_TEMPLATE_MANIFEST_KIND
    {
        return Err(Failure::task(format!(
            "build provenance template identity is schema {schema_version} kind '{manifest_kind}', expected schema {} kind '{}'",
            BUILD_PROVENANCE_TEMPLATE_SCHEMA_VERSION, BUILD_PROVENANCE_TEMPLATE_MANIFEST_KIND
        )));
    }
    if schema_version == LOADER_PROVENANCE_SCHEMA_VERSION
        || manifest_kind == LOADER_PROVENANCE_MANIFEST_KIND
    {
        return Err(Failure::task(
            "loader artifact provenance and build provenance template must remain distinct schema kinds",
        ));
    }
    Ok(())
}

fn template_schema_identity(contents: &str) -> Result<(u64, &str), Failure> {
    let mut schema_version = None;
    let mut manifest_kind = None;
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            break;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(Failure::task(
                "build provenance template contains a malformed top-level identity field",
            ));
        };
        match key.trim() {
            "schema_version" => {
                if schema_version.is_some() {
                    return Err(Failure::task(
                        "build provenance template repeats schema_version",
                    ));
                }
                schema_version = Some(value.trim().parse::<u64>().map_err(|_| {
                    Failure::task("build provenance template schema_version is not an integer")
                })?);
            }
            "manifest_kind" => {
                if manifest_kind.is_some() {
                    return Err(Failure::task(
                        "build provenance template repeats manifest_kind",
                    ));
                }
                let value = value.trim();
                manifest_kind = Some(
                    value
                        .strip_prefix('"')
                        .and_then(|value| value.strip_suffix('"'))
                        .filter(|value| {
                            !value.is_empty()
                                && value.bytes().all(|byte| {
                                    byte.is_ascii_alphanumeric()
                                        || matches!(byte, b'-' | b'_' | b'.')
                                })
                        })
                        .ok_or_else(|| {
                            Failure::task(
                                "build provenance template manifest_kind is not a simple quoted identifier",
                            )
                        })?,
                );
            }
            _ => {}
        }
    }
    Ok((
        schema_version
            .ok_or_else(|| Failure::task("build provenance template lacks schema_version"))?,
        manifest_kind
            .ok_or_else(|| Failure::task("build provenance template lacks manifest_kind"))?,
    ))
}

fn validate_relative_path(value: &str, label: &str) -> Result<(), Failure> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > MAX_PROVENANCE_PATH_BYTES
        || value.chars().any(char::is_control)
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Failure::task(format!(
            "{label} provenance path must be repository-relative without traversal"
        )));
    }
    Ok(())
}

fn validate_lower_hex(value: &str, length: usize, label: &str) -> Result<(), Failure> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Failure::task(format!(
            "{label} must contain exactly {length} lowercase hexadecimal digits"
        )));
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &str) -> Result<(), Failure> {
    if value.is_empty()
        || value.len() > MAX_PROVENANCE_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(Failure::task(format!(
            "{label} must be a bounded ASCII identifier"
        )));
    }
    Ok(())
}

fn escape(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                unreachable!("provenance strings are validated before escaping")
            }
            character => output.push(character),
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{
        BUILD_PROVENANCE_TEMPLATE, LoaderProvenance, render, validate_template_schema_distinction,
        write_loader_provenance,
    };

    const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
    const SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn record() -> LoaderProvenance<'static> {
        LoaderProvenance {
            repository_revision: REVISION,
            repository_dirty: true,
            deepwyrm_revision: REVISION,
            rust_revision: REVISION,
            rust_toolchain_name: "toolchain",
            rustc_sha256: SHA256,
            cargo_sha256: SHA256,
            rust_lld_sha256: SHA256,
            uefi_core_sha256: SHA256,
            uefi_alloc_sha256: SHA256,
            uefi_builtins_sha256: SHA256,
            rustc_driver_sha256: SHA256,
            llvm_sha256: SHA256,
            toolchain_tree_sha256: SHA256,
            toolchain_manifest_sha256: SHA256,
            target: "x86_64-unknown-uefi",
            package: "wyrmroot-efi-loader",
            binary: "loader",
            artifact_path: "target/wyr0-b/x86_64-unknown-uefi/debug/loader.efi",
            artifact_sha256: SHA256,
            debug_path: "target/wyr0-b/x86_64-unknown-uefi/debug/loader.pdb",
            debug_sha256: SHA256,
            versions_sha256: SHA256,
            profiles_sha256: SHA256,
            deep_layout_sha256: SHA256,
            generated_layout_policy_sha256: SHA256,
            toolchain_report_sha256: SHA256,
            artifact_report_sha256: SHA256,
        }
    }

    #[test]
    fn generated_record_uses_relative_paths_and_stable_hash_identities() {
        const SYNTHETIC_WORKSPACE: &str = "/synthetic/private/workspace";
        let record = record();
        let rendered = render(&record).expect("valid relative provenance record rejected");
        assert!(rendered.starts_with("schema_version = 3\n"));
        assert!(rendered.contains("manifest_kind = \"wyrmroot-wyr0-b-loader-provenance\""));
        assert!(rendered.contains("record_role = \"generated-loader-artifact-provenance\""));
        assert!(rendered.contains("distinct_from_schema_version = 1"));
        assert!(
            rendered
                .contains("distinct_from_manifest_kind = \"wyrmroot-build-provenance-template\"")
        );
        assert!(rendered.contains("wyrmroot_dirty = true"));
        assert!(rendered.contains(&format!("artifact_sha256 = \"{SHA256}\"")));
        assert!(rendered.contains(&format!("rustc_sha256 = \"{SHA256}\"")));
        assert!(rendered.contains(&format!("toolchain_tree_sha256 = \"{SHA256}\"")));
        assert!(rendered.contains(&format!("validation_report_sha256 = \"{SHA256}\"")));
        assert!(rendered.contains(&format!("inspection_report_sha256 = \"{SHA256}\"")));
        assert!(rendered.contains(&format!("deepwyrm_layout_sha256 = \"{SHA256}\"")));
        assert!(rendered.contains("deepwyrm_layout_version = 2"));
        assert!(rendered.contains(
            "generated_layout_abi_assertion_scope = \"base-page-and-paging-handoff-numeric-constants\""
        ));
        assert!(
            rendered
                .contains("behavioral_handoff_conformance = \"not-claimed-by-build-provenance\"")
        );
        assert!(!rendered.contains(SYNTHETIC_WORKSPACE));
        assert!(!rendered.contains("rustc_path"));
        assert!(!rendered.contains("{\\\"verified\\\""));

        let absolute = LoaderProvenance {
            artifact_path: "/synthetic/private/workspace/target/loader.efi",
            ..record
        };
        assert!(render(&absolute).is_err());
    }

    #[test]
    fn generated_and_template_provenance_are_distinct_validated_schema_kinds() {
        validate_template_schema_distinction(BUILD_PROVENANCE_TEMPLATE)
            .expect("current build provenance template identity rejected");
        assert!(
            validate_template_schema_distinction(
                "schema_version = 2\nmanifest_kind = \"wyrmroot-build-provenance-template\"\n"
            )
            .is_err()
        );
        assert!(
            validate_template_schema_distinction(
                "schema_version = 1\nmanifest_kind = \"wyrmroot-wyr0-b-loader-provenance\"\n"
            )
            .is_err()
        );
        assert!(
            validate_template_schema_distinction(
                "schema_version = 1\nschema_version = 1\nmanifest_kind = \"wyrmroot-build-provenance-template\"\n"
            )
            .is_err()
        );
    }

    #[test]
    fn generated_record_rejects_malformed_identities_and_controls() {
        let short_revision = LoaderProvenance {
            repository_revision: "abcd",
            ..record()
        };
        assert!(render(&short_revision).is_err());

        let uppercase_hash = LoaderProvenance {
            artifact_sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeF",
            ..record()
        };
        assert!(render(&uppercase_hash).is_err());

        let control_identifier = LoaderProvenance {
            binary: "loader\nforged",
            ..record()
        };
        assert!(render(&control_identifier).is_err());

        let control_path = LoaderProvenance {
            artifact_path: "target/loader\nforged.efi",
            ..record()
        };
        assert!(render(&control_path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn provenance_writer_rejects_symlink_directory_and_destination() {
        use std::fs;
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "wyrmroot-provenance-write-test-{}-{nonce}",
            std::process::id()
        ));
        let outside = std::env::temp_dir().join(format!(
            "wyrmroot-provenance-outside-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create provenance target");
        fs::create_dir(&outside).expect("create outside directory");
        symlink(&outside, root.join("provenance")).expect("create provenance directory symlink");
        assert!(write_loader_provenance(&root, &record()).is_err());

        fs::remove_file(root.join("provenance")).expect("remove directory symlink");
        fs::create_dir(root.join("provenance")).expect("create real provenance directory");
        let outside_file = outside.join("outside.toml");
        fs::write(&outside_file, b"outside").expect("write outside file");
        symlink(&outside_file, root.join("provenance/wyr0-b-loader.toml"))
            .expect("create provenance destination symlink");
        assert!(write_loader_provenance(&root, &record()).is_err());
        assert_eq!(
            fs::read(&outside_file).expect("read outside file"),
            b"outside"
        );
        fs::remove_file(root.join("provenance/wyr0-b-loader.toml"))
            .expect("remove destination symlink");
        let installed = write_loader_provenance(&root, &record()).expect("write loader provenance");
        let installed_text = fs::read_to_string(&installed).expect("read loader provenance");
        assert!(installed_text.contains("behavioral_handoff_conformance"));
        assert!(
            fs::read_dir(root.join("provenance"))
                .expect("read provenance directory")
                .all(|entry| {
                    !entry
                        .expect("read provenance entry")
                        .file_name()
                        .to_string_lossy()
                        .contains(".tmp-")
                })
        );

        fs::remove_dir_all(&root).expect("remove provenance target");
        fs::remove_dir_all(&outside).expect("remove outside directory");
    }
}
