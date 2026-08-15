use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::Failure;

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
    let directory = target_directory.join("provenance");
    fs::create_dir_all(&directory).map_err(|error| {
        Failure::task(format!(
            "could not create provenance directory {}: {error}",
            directory.display()
        ))
    })?;
    let destination = directory.join("wyr0-b-loader.toml");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| Failure::task(format!("system clock precedes Unix epoch: {error}")))?
        .as_nanos();
    let temporary = directory.join(format!(
        ".wyr0-b-loader.toml.tmp-{}-{nonce}",
        std::process::id()
    ));
    let contents = render(record)?;
    fs::write(&temporary, contents).map_err(|error| {
        Failure::task(format!(
            "could not write temporary provenance {}: {error}",
            temporary.display()
        ))
    })?;
    fs::rename(&temporary, &destination).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        Failure::task(format!(
            "could not install provenance record {}: {error}",
            destination.display()
        ))
    })?;
    Ok(destination)
}

fn render(record: &LoaderProvenance<'_>) -> Result<String, Failure> {
    validate_relative_path(record.artifact_path, "UEFI loader artifact")?;
    validate_relative_path(record.debug_path, "UEFI loader debug symbols")?;
    Ok(format!(
        "schema_version = 1\n\
manifest_kind = \"wyrmroot-wyr0-b-loader-provenance\"\n\
\n\
[source]\n\
wyrmroot_revision = \"{}\"\n\
wyrmroot_dirty = {}\n\
deepwyrm_revision = \"{}\"\n\
rust_revision = \"{}\"\n\
\n\
[configuration]\n\
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
        escape(record.repository_revision),
        record.repository_dirty,
        escape(record.deepwyrm_revision),
        escape(record.rust_revision),
        escape(record.versions_sha256),
        escape(record.profiles_sha256),
        escape(record.deep_layout_sha256),
        escape(record.generated_layout_policy_sha256),
        escape(record.rust_toolchain_name),
        escape(record.rustc_sha256),
        escape(record.cargo_sha256),
        escape(record.rust_lld_sha256),
        escape(record.uefi_core_sha256),
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

fn validate_relative_path(value: &str, label: &str) -> Result<(), Failure> {
    let path = Path::new(value);
    if value.is_empty()
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

fn escape(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => output.push('?'),
            character => output.push(character),
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{LoaderProvenance, render};

    #[test]
    fn generated_record_uses_relative_paths_and_stable_hash_identities() {
        const SYNTHETIC_WORKSPACE: &str = "/synthetic/private/workspace";
        let record = LoaderProvenance {
            repository_revision: "a",
            repository_dirty: true,
            deepwyrm_revision: "b",
            rust_revision: "c",
            rust_toolchain_name: "toolchain",
            rustc_sha256: "1",
            cargo_sha256: "6",
            rust_lld_sha256: "7",
            uefi_core_sha256: "8",
            uefi_builtins_sha256: "9",
            rustc_driver_sha256: "a1",
            llvm_sha256: "a2",
            toolchain_tree_sha256: "a3",
            toolchain_manifest_sha256: "a",
            target: "x86_64-unknown-uefi",
            package: "wyrmroot-efi-loader",
            binary: "loader",
            artifact_path: "target/wyr0-b/x86_64-unknown-uefi/debug/loader.efi",
            artifact_sha256: "d",
            debug_path: "target/wyr0-b/x86_64-unknown-uefi/debug/loader.pdb",
            debug_sha256: "e",
            versions_sha256: "f",
            profiles_sha256: "0",
            deep_layout_sha256: "4",
            generated_layout_policy_sha256: "5",
            toolchain_report_sha256: "2",
            artifact_report_sha256: "3",
        };
        let rendered = render(&record).expect("valid relative provenance record rejected");
        assert!(rendered.contains("wyrmroot_dirty = true"));
        assert!(rendered.contains("artifact_sha256 = \"d\""));
        assert!(rendered.contains("rustc_sha256 = \"1\""));
        assert!(rendered.contains("toolchain_tree_sha256 = \"a3\""));
        assert!(rendered.contains("validation_report_sha256 = \"2\""));
        assert!(rendered.contains("inspection_report_sha256 = \"3\""));
        assert!(rendered.contains("deepwyrm_layout_sha256 = \"4\""));
        assert!(!rendered.contains(SYNTHETIC_WORKSPACE));
        assert!(!rendered.contains("rustc_path"));
        assert!(!rendered.contains("{\\\"verified\\\""));

        let absolute = LoaderProvenance {
            artifact_path: "/synthetic/private/workspace/target/loader.efi",
            ..record
        };
        assert!(render(&absolute).is_err());
    }
}
