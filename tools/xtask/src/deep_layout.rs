use std::collections::BTreeMap;
use std::env;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{Read, Take, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};

use crate::error::Failure;
use crate::sha256::bytes_digest;

const PACKAGE_NAME: &str = "deepwyrm-abi";
const PACKAGE_MANIFEST: &str = "crates/deepwyrm-abi/Cargo.toml";
const LAYOUT_PATH: &str = "kernel/arch/x86_64/layout.toml";
const GENERATED_POLICY_PATH: &str = "target/wyr0-b/generated/deepwyrm_layout_policy.rs";
const MAX_LAYOUT_BYTES: u64 = 1024 * 1024;

pub(crate) struct DeepLayoutBuild {
    pub(crate) policy_path: PathBuf,
    pub(crate) layout_sha256: String,
    pub(crate) policy_sha256: String,
}

impl DeepLayoutBuild {
    pub(crate) fn verify_unchanged(&self) -> Result<(), Failure> {
        validate_regular_file(&self.policy_path, "generated Deepwyrm layout policy")?;
        let bytes = read_bounded(
            &self.policy_path,
            MAX_LAYOUT_BYTES,
            "generated Deepwyrm layout policy",
        )?;
        let actual = bytes_digest(&bytes);
        if actual != self.policy_sha256 {
            return Err(Failure::task(format!(
                "generated Deepwyrm layout policy hash changed: {actual}, expected {}",
                self.policy_sha256
            )));
        }
        Ok(())
    }
}

pub(crate) fn prepare(
    repository: &Path,
    expected_repository: &str,
    expected_revision: &str,
) -> Result<DeepLayoutBuild, Failure> {
    let metadata = cargo_metadata(repository)?;
    let package = locate_package(&metadata, expected_repository, expected_revision)?;
    let source_root = validate_git_source(&package.manifest_path, expected_revision)?;
    let layout_path = source_root.join(LAYOUT_PATH);
    validate_regular_path(&source_root, &layout_path, "Deepwyrm x86_64 layout")?;
    let layout_bytes = read_bounded(&layout_path, MAX_LAYOUT_BYTES, "Deepwyrm x86_64 layout")?;
    verify_tracked_bytes(&source_root, LAYOUT_PATH, &layout_bytes)?;
    let contents = std::str::from_utf8(&layout_bytes)
        .map_err(|_| Failure::task("Deepwyrm x86_64 layout is not UTF-8"))?;
    let policy = LayoutPolicy::parse(contents)?;
    let generated = policy.render_rust();
    let layout_sha256 = bytes_digest(&layout_bytes);
    let policy_sha256 = bytes_digest(generated.as_bytes());
    let policy_path = repository.join(GENERATED_POLICY_PATH);
    write_generated_policy(&policy_path, &generated)?;
    verify_git_source_identity(&source_root, expected_revision)?;

    let build = DeepLayoutBuild {
        policy_path,
        layout_sha256,
        policy_sha256,
    };
    build.verify_unchanged()?;
    Ok(build)
}

fn cargo_metadata(repository: &Path) -> Result<String, Failure> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsStr::new("cargo").to_owned());
    let output = Command::new(cargo)
        .args(["metadata", "--locked", "--format-version", "1"])
        .current_dir(repository)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| Failure::task(format!("could not run locked Cargo metadata: {error}")))?;
    output_stdout(output, "locked Cargo metadata")
}

struct PackageSource {
    manifest_path: PathBuf,
}

fn locate_package(
    metadata: &str,
    expected_repository: &str,
    expected_revision: &str,
) -> Result<PackageSource, Failure> {
    let root = JsonParser::new(metadata).parse()?;
    let packages = root
        .object_field("packages")?
        .as_array("Cargo metadata packages")?;
    let repository = expected_repository.trim_end_matches('/');
    let normalized_repository = if repository.ends_with(".git") {
        repository.to_owned()
    } else {
        format!("{repository}.git")
    };
    let expected_source =
        format!("git+{normalized_repository}?rev={expected_revision}#{expected_revision}");
    let mut selected = None;
    for package in packages {
        if package.object_field("name")?.as_string("package name")? != PACKAGE_NAME {
            continue;
        }
        if selected.is_some() {
            return Err(Failure::task(
                "locked Cargo metadata contains multiple deepwyrm-abi packages",
            ));
        }
        let source = package.object_field("source")?;
        let actual_source = source.as_string("deepwyrm-abi source").map_err(|_| {
            Failure::task(
                "deepwyrm-abi must resolve from the exact pinned Git source, not a path or registry",
            )
        })?;
        if actual_source != expected_source {
            return Err(Failure::task(format!(
                "deepwyrm-abi source is '{actual_source}', expected exact locked source '{expected_source}'"
            )));
        }
        let manifest = package
            .object_field("manifest_path")?
            .as_string("deepwyrm-abi manifest path")?;
        let manifest_path = PathBuf::from(manifest);
        validate_metadata_manifest_path(&manifest_path)?;
        selected = Some(PackageSource { manifest_path });
    }
    selected.ok_or_else(|| {
        Failure::task("locked Cargo metadata does not contain the pinned deepwyrm-abi package")
    })
}

fn validate_metadata_manifest_path(path: &Path) -> Result<(), Failure> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        || path.file_name().and_then(OsStr::to_str) != Some("Cargo.toml")
        || path
            .parent()
            .and_then(Path::file_name)
            .and_then(OsStr::to_str)
            != Some("deepwyrm-abi")
        || path
            .parent()
            .and_then(Path::parent)
            .and_then(Path::file_name)
            .and_then(OsStr::to_str)
            != Some("crates")
    {
        return Err(Failure::task(format!(
            "deepwyrm-abi metadata manifest path is not an absolute non-traversing crates/deepwyrm-abi/Cargo.toml path: {}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_git_source(manifest: &Path, expected_revision: &str) -> Result<PathBuf, Failure> {
    validate_regular_file(manifest, "deepwyrm-abi manifest")?;
    let manifest_directory = manifest
        .parent()
        .ok_or_else(|| Failure::task("deepwyrm-abi manifest has no parent directory"))?;
    let root_output = git_output(manifest_directory, ["rev-parse", "--show-toplevel"])?;
    let root = PathBuf::from(root_output.trim());
    if !root.is_absolute() {
        return Err(Failure::task(
            "deepwyrm-abi Git source root is not an absolute path",
        ));
    }
    validate_directory(&root, "deepwyrm-abi Git source root")?;
    let canonical_root = fs::canonicalize(&root).map_err(|error| {
        Failure::task(format!(
            "could not canonicalize deepwyrm-abi Git source root: {error}"
        ))
    })?;
    if canonical_root != root {
        return Err(Failure::task(
            "deepwyrm-abi Git source root is not canonical or contains a symlink",
        ));
    }
    validate_regular_path(&root, manifest, "deepwyrm-abi manifest")?;
    if root.join(PACKAGE_MANIFEST) != manifest {
        return Err(Failure::task(format!(
            "deepwyrm-abi manifest is not at canonical repository path {PACKAGE_MANIFEST}"
        )));
    }

    verify_git_source_identity(&root, expected_revision)?;
    Ok(root)
}

fn verify_git_source_identity(root: &Path, expected_revision: &str) -> Result<(), Failure> {
    let revision = git_output(root, ["rev-parse", "HEAD"])?;
    if revision.trim() != expected_revision {
        return Err(Failure::task(format!(
            "deepwyrm-abi source checkout revision is '{}', expected '{}'",
            revision.trim(),
            expected_revision
        )));
    }
    let status = git_output(root, ["status", "--porcelain=v1", "--untracked-files=all"])?;
    validate_git_status(root, &status)
}

fn validate_git_status(root: &Path, status: &str) -> Result<(), Failure> {
    for line in status.lines() {
        if line != "?? .cargo-ok" {
            return Err(Failure::task(format!(
                "deepwyrm-abi Git source checkout contains a disallowed change: {line}"
            )));
        }
        let marker = root.join(".cargo-ok");
        let metadata = fs::symlink_metadata(&marker).map_err(|error| {
            Failure::task(format!("could not inspect Cargo checkout marker: {error}"))
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != 0 {
            return Err(Failure::task(
                "Cargo checkout .cargo-ok marker must be a regular non-symlink zero-byte file",
            ));
        }
    }
    Ok(())
}

fn git_output<I, S>(repository: &Path, arguments: I) -> Result<String, Failure>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            Failure::task(format!("could not inspect Deepwyrm Git source: {error}"))
        })?;
    output_stdout(output, "Deepwyrm Git source inspection")
}

fn output_stdout(output: Output, label: &str) -> Result<String, Failure> {
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| Failure::task(format!("{label} produced non-UTF-8 output")))?;
    if output.status.success() {
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(Failure::task(format!(
            "{label} failed with exit code {}{}",
            output.status.code().unwrap_or(-1),
            if stderr.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", stderr.trim())
            }
        )))
    }
}

fn validate_regular_path(root: &Path, path: &Path, label: &str) -> Result<(), Failure> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| Failure::task(format!("{label} is outside the Deepwyrm Git source root")))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(Failure::task(format!(
                "{label} path contains traversal or a non-normal component"
            )));
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            Failure::task(format!(
                "could not inspect {label} {}: {error}",
                current.display()
            ))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(Failure::task(format!(
                "{label} path contains a symlink: {}",
                current.display()
            )));
        }
    }
    validate_regular_file(path, label)
}

fn validate_regular_file(path: &Path, label: &str) -> Result<(), Failure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Failure::task(format!("could not inspect {label}: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Failure::task(format!(
            "{label} must be a regular non-symlink file"
        )));
    }
    Ok(())
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

fn verify_tracked_bytes(root: &Path, relative: &str, bytes: &[u8]) -> Result<(), Failure> {
    git_output(root, ["ls-files", "--error-unmatch", relative])?;
    let expected = git_output(root, ["rev-parse", &format!("HEAD:{relative}")])?;
    let actual = git_hash_bytes(root, bytes)?;
    if expected.trim() != actual.trim() {
        return Err(Failure::task(
            "Deepwyrm x86_64 layout content does not match the pinned Git revision",
        ));
    }
    Ok(())
}

fn git_hash_bytes(root: &Path, bytes: &[u8]) -> Result<String, Failure> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["hash-object", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| Failure::task(format!("could not hash Deepwyrm layout bytes: {error}")))?;
    child
        .stdin
        .take()
        .ok_or_else(|| Failure::task("could not open Git hash-object stdin"))?
        .write_all(bytes)
        .map_err(|error| Failure::task(format!("could not send layout bytes to Git: {error}")))?;
    let output = child.wait_with_output().map_err(|error| {
        Failure::task(format!("could not wait for Deepwyrm layout hash: {error}"))
    })?;
    output_stdout(output, "Deepwyrm layout byte hashing")
}

fn write_generated_policy(path: &Path, contents: &str) -> Result<(), Failure> {
    let directory = path
        .parent()
        .ok_or_else(|| Failure::task("generated layout policy has no parent directory"))?;
    fs::create_dir_all(directory).map_err(|error| {
        Failure::task(format!(
            "could not create generated policy directory {}: {error}",
            directory.display()
        ))
    })?;
    let temporary = directory.join(format!(
        ".deepwyrm_layout_policy.rs.tmp-{}",
        std::process::id()
    ));
    fs::write(&temporary, contents).map_err(|error| {
        Failure::task(format!(
            "could not write generated layout policy {}: {error}",
            temporary.display()
        ))
    })?;
    fs::rename(&temporary, path).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        Failure::task(format!(
            "could not install generated layout policy {}: {error}",
            path.display()
        ))
    })
}

fn read_bounded(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>, Failure> {
    let file = open_stable_regular_file(path, label)?;
    let mut bytes = Vec::new();
    let mut bounded: Take<&File> = (&file).take(maximum + 1);
    bounded
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

fn open_stable_regular_file(path: &Path, label: &str) -> Result<File, Failure> {
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
    verify_open_file_identity(&file, path, label)?;
    Ok(file)
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

#[derive(Clone, Debug, Eq, PartialEq)]
enum TomlValue {
    String(String),
    Integer(u64),
    Bool(bool),
    Strings(Vec<String>),
}

struct LayoutPolicy {
    values: BTreeMap<String, TomlValue>,
}

impl LayoutPolicy {
    fn parse(contents: &str) -> Result<Self, Failure> {
        let mut values = parse_layout_toml(contents)?;
        expect_string(&mut values, "schema", "deepwyrm-x86_64-layout")?;
        expect_integer(&mut values, "version", 1)?;
        expect_string(&mut values, "entry_contract", "DW_BOOT_X86_64_ENTRY_V1")?;
        expect_string(&mut values, "elf_type", "ET_EXEC")?;
        expect_string(&mut values, "entry_symbol", "_dw_kernel_entry")?;
        let link_base_text = take_string(&mut values, "link_base")?;
        let link_base = parse_hex_u64(&link_base_text, "link_base")?;
        expect_integer(&mut values, "base_page_size", 4096)?;
        expect_bool(&mut values, "red_zone", false)?;
        expect_integer(&mut values, "kernel_boot_stack_size", 65536)?;
        expect_integer(&mut values, "kernel_boot_stack_alignment", 4096)?;
        expect_integer(&mut values, "loader_transition_stack_size", 16384)?;
        expect_integer(&mut values, "loader_transition_stack_alignment", 4096)?;
        expect_string(&mut values, "p_paddr_policy", "ignored")?;
        expect_strings(&mut values, "allowed_program_header_types", &["PT_LOAD"])?;

        for (key, expected) in [
            ("load_policy.upper_canonical", true),
            ("load_policy.non_overlapping", true),
            ("load_policy.writable_xor_executable", true),
            ("load_policy.entry_in_executable_segment", true),
            ("entry_state.returns", false),
            ("entry_state.immediate_kernel_stack_switch", true),
            ("entry_state.interrupts_enabled", false),
            ("entry_state.direction_flag_set", false),
            ("entry_state.cr0_write_protect", true),
            ("entry_state.execute_disable", true),
            ("entry_state.uefi_services_available", false),
            ("handoff_mappings.mutable", false),
            ("handoff_mappings.page_zero_mapped", false),
            ("handoff_mappings.framebuffer_pixels_identity_mapped", false),
        ] {
            expect_bool(&mut values, key, expected)?;
        }
        for (key, expected) in [
            ("entry_state.boot_info_alignment", 8),
            ("entry_state.loader_stack_rsp_mod_16", 0),
            ("entry_state.kernel_stack_rsp_mod_16_before_call", 0),
            ("entry_state.rust_entry_rsp_mod_16", 8),
        ] {
            expect_integer(&mut values, key, expected)?;
        }
        for (key, expected) in [
            ("entry_state.transfer", "jmp"),
            ("entry_state.boot_info_register", "RDI"),
            ("entry_state.boot_info_address", "identity-mapped-physical"),
            ("entry_state.loader_stack_owner", "loader"),
            ("entry_state.loader_stack_rsp", "one-past-end"),
            (
                "entry_state.loader_stack_lifetime",
                "until-kernel-page-table-replacement",
            ),
            ("entry_state.kernel_stack_owner", "kernel"),
            ("entry_state.rust_entry_abi", "sysv64"),
            ("entry_state.paging_mode", "x86_64-4-level"),
            ("entry_state.initial_processor", "BSP"),
            (
                "entry_state.descriptor_state",
                "valid-CS-SS-others-unspecified",
            ),
            ("entry_state.tls_state", "FS-GS-unspecified"),
            (
                "entry_state.fp_simd_state",
                "unavailable-until-kernel-initialization",
            ),
            ("entry_state.firmware_exit", "ExitBootServices-complete"),
            ("handoff_mappings.kernel_load_segments", "mapped-at-p_vaddr"),
            (
                "handoff_mappings.physical_allocation",
                "arbitrary-suitable-firmware-pages",
            ),
            ("handoff_mappings.boot_info", "identity-mapped"),
            ("handoff_mappings.referenced_ranges", "identity-mapped"),
            (
                "handoff_mappings.lifetime",
                "until-kernel-page-table-replacement",
            ),
        ] {
            expect_string(&mut values, key, expected)?;
        }
        expect_strings(&mut values, "entry_state.defined_incoming_gprs", &["RDI"])?;
        expect_integer(
            &mut values,
            "early_intake.max_normalized_memory_map_entries",
            128,
        )?;
        expect_integer(&mut values, "early_intake.max_module_entries", 16)?;
        expect_integer(
            &mut values,
            "early_intake.acpi_rsdp_max_intersecting_pages",
            2,
        )?;
        expect_bool(
            &mut values,
            "early_intake.acpi_memory_types_identity_mapped",
            false,
        )?;
        for (key, expected) in [
            ("early_intake.acpi_scope", "rsdp-only"),
            (
                "early_intake.acpi_guid_preference",
                "ACPI_20_TABLE_GUID-then-ACPI_TABLE_GUID",
            ),
            ("early_intake.acpi_duplicate_selected_guid", "reject"),
            ("early_intake.acpi_preferred_invalid", "reject-no-downgrade"),
            ("early_intake.acpi_rsdp_signature", "RSD PTR "),
            (
                "early_intake.acpi_rsdp_length_rule",
                "revision-lt-2:20;revision-ge-2:declared-36..4096",
            ),
            (
                "early_intake.acpi_rsdp_checksum",
                "v1-first-20-and-v2-full-record",
            ),
            (
                "early_intake.acpi_rsdp_mapping",
                "validated-record-intersecting-base-pages-only",
            ),
            ("early_intake.acpi_mapping_overlap", "coalesce"),
            ("early_intake.acpi_table_traversal", "deferred-dw0-c"),
        ] {
            expect_string(&mut values, key, expected)?;
        }
        if !values.is_empty() {
            return Err(Failure::task(format!(
                "Deepwyrm layout contains unsupported or stale field '{}'",
                values.keys().next().expect("nonempty map")
            )));
        }
        if link_base < 0xffff_8000_0000_0000 || link_base % 4096 != 0 {
            return Err(Failure::task(
                "Deepwyrm link_base must be upper-canonical and base-page aligned",
            ));
        }

        let mut rendered_values = parse_layout_toml(contents)?;
        rendered_values.insert("link_base".to_owned(), TomlValue::Integer(link_base));
        Ok(Self {
            values: rendered_values,
        })
    }

    fn render_rust(&self) -> String {
        let mut output = String::from(
            "// @generated by Wyrmroot xtask from the pinned Deepwyrm layout.\n\
             // Do not edit; this file contains no host paths.\n\n",
        );
        for (key, value) in &self.values {
            let identifier = format!("DEEPWYRM_{}", key.replace('.', "_").to_ascii_uppercase());
            match value {
                TomlValue::String(value) => {
                    output.push_str(&format!("pub const {identifier}: &str = {value:?};\n"));
                }
                TomlValue::Integer(value) if key == "link_base" => {
                    output.push_str(&format!("pub const {identifier}: u64 = {value:#018x};\n"));
                }
                TomlValue::Integer(value) => {
                    output.push_str(&format!("pub const {identifier}: u64 = {value};\n"));
                }
                TomlValue::Bool(value) => {
                    output.push_str(&format!("pub const {identifier}: bool = {value};\n"));
                }
                TomlValue::Strings(values) => {
                    let values = values
                        .iter()
                        .map(|value| format!("{value:?}"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    output.push_str(&format!("pub const {identifier}: &[&str] = &[{values}];\n"));
                }
            }
        }
        output.push_str(
            "\n// Conservative half-open kernel ELF window. u64::MAX is excluded.\n\
pub const DEEPWYRM_ELF_WINDOW_START: u64 = DEEPWYRM_LINK_BASE;\n\
pub const DEEPWYRM_ELF_WINDOW_END_EXCLUSIVE: u64 = u64::MAX;\n\
pub const fn deepwyrm_lowest_pt_load_matches_layout(\n\
    lowest_page_rounded_pt_load: u64,\n\
) -> bool {\n\
    lowest_page_rounded_pt_load == DEEPWYRM_ELF_WINDOW_START\n\
}\n",
        );
        output
    }
}

fn parse_layout_toml(contents: &str) -> Result<BTreeMap<String, TomlValue>, Failure> {
    let mut section = String::new();
    let mut values = BTreeMap::new();
    for (index, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            if line.starts_with("[[") {
                return Err(layout_line_error(index, "array tables are unsupported"));
            }
            section = line[1..line.len() - 1].trim().to_owned();
            if !matches!(
                section.as_str(),
                "load_policy" | "entry_state" | "handoff_mappings" | "early_intake"
            ) {
                return Err(layout_line_error(index, "unknown layout section"));
            }
            continue;
        }
        let (key, raw_value) = line
            .split_once('=')
            .ok_or_else(|| layout_line_error(index, "expected key = value"))?;
        let key = key.trim();
        if key.is_empty() || key.contains('.') {
            return Err(layout_line_error(index, "invalid layout key"));
        }
        let qualified = if section.is_empty() {
            key.to_owned()
        } else {
            format!("{section}.{key}")
        };
        let value = parse_layout_value(raw_value.trim(), index)?;
        if values.insert(qualified.clone(), value).is_some() {
            return Err(layout_line_error(
                index,
                &format!("duplicate key {qualified}"),
            ));
        }
    }
    Ok(values)
}

fn parse_layout_value(value: &str, index: usize) -> Result<TomlValue, Failure> {
    if let Some(value) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        if value.contains(['"', '\\']) || value.chars().any(char::is_control) {
            return Err(layout_line_error(
                index,
                "unsupported string escape or control",
            ));
        }
        return Ok(TomlValue::String(value.to_owned()));
    }
    if let Some(inner) = value.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
        let mut strings = Vec::new();
        for item in inner.split(',') {
            let item = item.trim();
            let string = item
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .ok_or_else(|| layout_line_error(index, "arrays must contain strings"))?;
            if string.is_empty() || string.contains(['"', '\\']) {
                return Err(layout_line_error(index, "invalid array string"));
            }
            strings.push(string.to_owned());
        }
        return Ok(TomlValue::Strings(strings));
    }
    match value {
        "true" => Ok(TomlValue::Bool(true)),
        "false" => Ok(TomlValue::Bool(false)),
        _ => value
            .parse::<u64>()
            .map(TomlValue::Integer)
            .map_err(|_| layout_line_error(index, "unsupported layout value")),
    }
}

fn layout_line_error(index: usize, message: &str) -> Failure {
    Failure::task(format!("Deepwyrm layout line {}: {message}", index + 1))
}

fn take_value(values: &mut BTreeMap<String, TomlValue>, key: &str) -> Result<TomlValue, Failure> {
    values
        .remove(key)
        .ok_or_else(|| Failure::task(format!("Deepwyrm layout is missing locked field '{key}'")))
}

fn take_string(values: &mut BTreeMap<String, TomlValue>, key: &str) -> Result<String, Failure> {
    match take_value(values, key)? {
        TomlValue::String(value) => Ok(value),
        _ => Err(Failure::task(format!(
            "Deepwyrm layout field '{key}' has the wrong type"
        ))),
    }
}

fn expect_string(
    values: &mut BTreeMap<String, TomlValue>,
    key: &str,
    expected: &str,
) -> Result<(), Failure> {
    let actual = take_string(values, key)?;
    if actual == expected {
        Ok(())
    } else {
        Err(Failure::task(format!(
            "Deepwyrm layout field '{key}' is '{actual}', expected '{expected}'"
        )))
    }
}

fn expect_integer(
    values: &mut BTreeMap<String, TomlValue>,
    key: &str,
    expected: u64,
) -> Result<(), Failure> {
    match take_value(values, key)? {
        TomlValue::Integer(actual) if actual == expected => Ok(()),
        TomlValue::Integer(actual) => Err(Failure::task(format!(
            "Deepwyrm layout field '{key}' is {actual}, expected {expected}"
        ))),
        _ => Err(Failure::task(format!(
            "Deepwyrm layout field '{key}' has the wrong type"
        ))),
    }
}

fn expect_bool(
    values: &mut BTreeMap<String, TomlValue>,
    key: &str,
    expected: bool,
) -> Result<(), Failure> {
    match take_value(values, key)? {
        TomlValue::Bool(actual) if actual == expected => Ok(()),
        TomlValue::Bool(actual) => Err(Failure::task(format!(
            "Deepwyrm layout field '{key}' is {actual}, expected {expected}"
        ))),
        _ => Err(Failure::task(format!(
            "Deepwyrm layout field '{key}' has the wrong type"
        ))),
    }
}

fn expect_strings(
    values: &mut BTreeMap<String, TomlValue>,
    key: &str,
    expected: &[&str],
) -> Result<(), Failure> {
    match take_value(values, key)? {
        TomlValue::Strings(actual)
            if actual
                .iter()
                .map(String::as_str)
                .eq(expected.iter().copied()) =>
        {
            Ok(())
        }
        TomlValue::Strings(actual) => Err(Failure::task(format!(
            "Deepwyrm layout field '{key}' is {actual:?}, expected {expected:?}"
        ))),
        _ => Err(Failure::task(format!(
            "Deepwyrm layout field '{key}' has the wrong type"
        ))),
    }
}

fn parse_hex_u64(value: &str, key: &str) -> Result<u64, Failure> {
    let digits = value.strip_prefix("0x").ok_or_else(|| {
        Failure::task(format!(
            "Deepwyrm layout field '{key}' must use 0x hexadecimal"
        ))
    })?;
    if digits.len() != 16 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Failure::task(format!(
            "Deepwyrm layout field '{key}' must contain exactly 16 hexadecimal digits"
        )));
    }
    u64::from_str_radix(digits, 16)
        .map_err(|_| Failure::task(format!("Deepwyrm layout field '{key}' overflows u64")))
}

#[derive(Debug)]
enum JsonValue {
    Null,
    Bool,
    Number,
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    fn object_field(&self, key: &str) -> Result<&Self, Failure> {
        let Self::Object(values) = self else {
            return Err(Failure::task("Cargo metadata JSON value is not an object"));
        };
        values
            .get(key)
            .ok_or_else(|| Failure::task(format!("Cargo metadata is missing field '{key}'")))
    }

    fn as_array(&self, label: &str) -> Result<&[Self], Failure> {
        match self {
            Self::Array(values) => Ok(values),
            _ => Err(Failure::task(format!("{label} is not an array"))),
        }
    }

    fn as_string(&self, label: &str) -> Result<&str, Failure> {
        match self {
            Self::String(value) => Ok(value),
            _ => Err(Failure::task(format!("{label} is not a string"))),
        }
    }
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            bytes: input.as_bytes(),
            offset: 0,
        }
    }

    fn parse(mut self) -> Result<JsonValue, Failure> {
        let value = self.value()?;
        self.whitespace();
        if self.offset != self.bytes.len() {
            return Err(self.error("trailing data"));
        }
        Ok(value)
    }

    fn value(&mut self) -> Result<JsonValue, Failure> {
        self.whitespace();
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => self.string().map(JsonValue::String),
            Some(b't') => {
                self.literal(b"true")?;
                Ok(JsonValue::Bool)
            }
            Some(b'f') => {
                self.literal(b"false")?;
                Ok(JsonValue::Bool)
            }
            Some(b'n') => {
                self.literal(b"null")?;
                Ok(JsonValue::Null)
            }
            Some(b'-' | b'0'..=b'9') => {
                self.number()?;
                Ok(JsonValue::Number)
            }
            _ => Err(self.error("expected JSON value")),
        }
    }

    fn object(&mut self) -> Result<JsonValue, Failure> {
        self.expect(b'{')?;
        let mut values = BTreeMap::new();
        self.whitespace();
        if self.consume(b'}') {
            return Ok(JsonValue::Object(values));
        }
        loop {
            self.whitespace();
            let key = self.string()?;
            self.whitespace();
            self.expect(b':')?;
            let value = self.value()?;
            if values.insert(key, value).is_some() {
                return Err(self.error("duplicate JSON object key"));
            }
            self.whitespace();
            if self.consume(b'}') {
                break;
            }
            self.expect(b',')?;
        }
        Ok(JsonValue::Object(values))
    }

    fn array(&mut self) -> Result<JsonValue, Failure> {
        self.expect(b'[')?;
        let mut values = Vec::new();
        self.whitespace();
        if self.consume(b']') {
            return Ok(JsonValue::Array(values));
        }
        loop {
            values.push(self.value()?);
            self.whitespace();
            if self.consume(b']') {
                break;
            }
            self.expect(b',')?;
        }
        Ok(JsonValue::Array(values))
    }

    fn string(&mut self) -> Result<String, Failure> {
        self.expect(b'"')?;
        let mut output = String::new();
        while let Some(byte) = self.take() {
            match byte {
                b'"' => return Ok(output),
                b'\\' => {
                    let escaped = self
                        .take()
                        .ok_or_else(|| self.error("truncated JSON escape"))?;
                    match escaped {
                        b'"' => output.push('"'),
                        b'\\' => output.push('\\'),
                        b'/' => output.push('/'),
                        b'b' => output.push('\u{0008}'),
                        b'f' => output.push('\u{000c}'),
                        b'n' => output.push('\n'),
                        b'r' => output.push('\r'),
                        b't' => output.push('\t'),
                        b'u' => output.push(self.unicode_escape()?),
                        _ => return Err(self.error("invalid JSON escape")),
                    }
                }
                0x00..=0x1f => return Err(self.error("control byte in JSON string")),
                0x20..=0x7f => output.push(char::from(byte)),
                _ => {
                    let width = utf8_width(byte)
                        .ok_or_else(|| self.error("invalid UTF-8 in JSON string"))?;
                    let start = self.offset - 1;
                    let end = start
                        .checked_add(width)
                        .filter(|end| *end <= self.bytes.len())
                        .ok_or_else(|| self.error("truncated UTF-8 in JSON string"))?;
                    let value = std::str::from_utf8(&self.bytes[start..end])
                        .map_err(|_| self.error("invalid UTF-8 in JSON string"))?;
                    output.push_str(value);
                    self.offset = end;
                }
            }
        }
        Err(self.error("unterminated JSON string"))
    }

    fn unicode_escape(&mut self) -> Result<char, Failure> {
        let mut value = 0_u32;
        for _ in 0..4 {
            let byte = self
                .take()
                .ok_or_else(|| self.error("truncated Unicode escape"))?;
            value = value
                .checked_mul(16)
                .and_then(|value| value.checked_add(hex_digit(byte)?))
                .ok_or_else(|| self.error("invalid Unicode escape"))?;
        }
        char::from_u32(value).ok_or_else(|| self.error("invalid Unicode scalar"))
    }

    fn number(&mut self) -> Result<(), Failure> {
        let start = self.offset;
        if self.consume(b'-') && self.peek().is_none() {
            return Err(self.error("truncated JSON number"));
        }
        if self.consume(b'0') {
            if matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.error("leading zero in JSON number"));
            }
        } else {
            self.digits()?;
        }
        if self.consume(b'.') {
            self.digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.offset += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.offset += 1;
            }
            self.digits()?;
        }
        if self.offset == start {
            return Err(self.error("invalid JSON number"));
        }
        Ok(())
    }

    fn digits(&mut self) -> Result<(), Failure> {
        let start = self.offset;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.offset += 1;
        }
        if self.offset == start {
            Err(self.error("expected JSON digits"))
        } else {
            Ok(())
        }
    }

    fn literal(&mut self, literal: &[u8]) -> Result<(), Failure> {
        if self.bytes.get(self.offset..self.offset + literal.len()) == Some(literal) {
            self.offset += literal.len();
            Ok(())
        } else {
            Err(self.error("invalid JSON literal"))
        }
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.offset += 1;
        }
    }

    fn expect(&mut self, expected: u8) -> Result<(), Failure> {
        if self.consume(expected) {
            Ok(())
        } else {
            Err(self.error("unexpected JSON token"))
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }

    fn take(&mut self) -> Option<u8> {
        let value = self.peek()?;
        self.offset += 1;
        Some(value)
    }

    fn error(&self, message: &str) -> Failure {
        Failure::task(format!(
            "invalid locked Cargo metadata JSON at byte {}: {message}",
            self.offset
        ))
    }
}

fn utf8_width(first: u8) -> Option<usize> {
    match first {
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
}

fn hex_digit(byte: u8) -> Option<u32> {
    match byte {
        b'0'..=b'9' => Some(u32::from(byte - b'0')),
        b'a'..=b'f' => Some(u32::from(byte - b'a' + 10)),
        b'A'..=b'F' => Some(u32::from(byte - b'A' + 10)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DeepLayoutBuild, JsonParser, LayoutPolicy, locate_package, open_stable_regular_file,
        validate_git_status, validate_metadata_manifest_path, validate_regular_path,
        verify_open_file_identity, verify_tracked_bytes,
    };
    use crate::sha256::bytes_digest;
    use std::path::Path;

    const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
    const REPOSITORY: &str = "https://example.invalid/deepwyrm";

    #[test]
    fn locked_metadata_requires_exact_git_revision_and_canonical_manifest() {
        let source = format!("git+{REPOSITORY}.git?rev={REVISION}#{REVISION}");
        let document = metadata(
            &source,
            "/cache/checkouts/deepwyrm/crates/deepwyrm-abi/Cargo.toml",
        );
        let package = locate_package(&document, REPOSITORY, REVISION)
            .expect("exact Git package source rejected");
        assert_eq!(
            package.manifest_path,
            Path::new("/cache/checkouts/deepwyrm/crates/deepwyrm-abi/Cargo.toml")
        );

        let stale = source.replace(REVISION, "89abcdef89abcdef89abcdef89abcdef89abcdef");
        assert!(
            locate_package(
                &metadata(&stale, "/cache/deepwyrm/crates/deepwyrm-abi/Cargo.toml"),
                REPOSITORY,
                REVISION
            )
            .is_err()
        );
        assert!(
            locate_package(
                &metadata(
                    "git+https://example.invalid/deepwyrm.git#branch",
                    "/cache/deepwyrm/crates/deepwyrm-abi/Cargo.toml"
                ),
                REPOSITORY,
                REVISION
            )
            .is_err()
        );
        assert!(locate_package(
            r#"{"packages":[{"name":"deepwyrm-abi","source":null,"manifest_path":"/cache/deepwyrm/crates/deepwyrm-abi/Cargo.toml"}]}"#,
            REPOSITORY,
            REVISION
        )
        .is_err());
    }

    #[test]
    fn metadata_and_json_reject_traversal_and_malformed_input() {
        assert!(
            validate_metadata_manifest_path(Path::new(
                "/cache/deepwyrm/crates/deepwyrm-abi/../deepwyrm-abi/Cargo.toml"
            ))
            .is_err()
        );
        assert!(
            validate_metadata_manifest_path(Path::new("crates/deepwyrm-abi/Cargo.toml")).is_err()
        );
        assert!(
            validate_metadata_manifest_path(Path::new("/cache/deepwyrm/abi/Cargo.toml")).is_err()
        );
        assert!(JsonParser::new(r#"{"packages":[}"#).parse().is_err());
        assert!(
            JsonParser::new(r#"{"packages":[],"packages":[]}"#)
                .parse()
                .is_err()
        );
    }

    #[test]
    fn layout_validation_is_strict_and_generation_is_path_neutral() {
        let valid = layout("0xffff800000200000");
        let policy = LayoutPolicy::parse(&valid).expect("locked layout fixture rejected");
        let generated = policy.render_rust();
        assert!(generated.contains("DEEPWYRM_LINK_BASE: u64 = 0xffff800000200000"));
        assert!(generated.contains("DEEPWYRM_ELF_WINDOW_START: u64 = DEEPWYRM_LINK_BASE"));
        assert!(generated.contains("DEEPWYRM_ELF_WINDOW_END_EXCLUSIVE: u64 = u64::MAX"));
        assert!(
            generated
                .contains("DEEPWYRM_EARLY_INTAKE_MAX_NORMALIZED_MEMORY_MAP_ENTRIES: u64 = 128")
        );
        assert!(!generated.contains("/synthetic/private/workspace"));

        assert!(LayoutPolicy::parse(&valid.replace("version = 1", "version = 2")).is_err());
        assert!(
            LayoutPolicy::parse(&valid.replace(
                "p_paddr_policy = \"ignored\"",
                "p_paddr_policy = \"trusted\""
            ))
            .is_err()
        );
        assert!(
            LayoutPolicy::parse(&valid.replace("[\"PT_LOAD\"]", "[\"PT_LOAD\", \"PT_DYNAMIC\"]"))
                .is_err()
        );
        assert!(LayoutPolicy::parse(&format!("{valid}\nunknown = true\n")).is_err());
        assert!(
            LayoutPolicy::parse(&valid.replace(
                "max_normalized_memory_map_entries = 128",
                "max_normalized_memory_map_entries = 129"
            ))
            .is_err()
        );
        assert!(LayoutPolicy::parse(&layout("0x0000000000200000")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn source_tree_validation_rejects_symlinks() {
        use std::fs;
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "wyrmroot-deep-layout-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("kernel/arch/x86_64")).expect("create isolated source tree");
        let outside = root.join("outside.toml");
        fs::write(&outside, layout("0xffff800000200000")).expect("write source fixture");
        let linked = root.join("kernel/arch/x86_64/layout.toml");
        symlink(&outside, &linked).expect("create source symlink");
        assert!(validate_regular_path(&root, &linked, "test layout").is_err());
        fs::remove_dir_all(root).expect("remove isolated source tree");
    }

    #[cfg(unix)]
    #[test]
    fn generated_policy_identity_rejects_content_and_symlink_swaps() {
        use std::fs;
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "wyrmroot-layout-policy-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create isolated generated directory");
        let path = root.join("policy.rs");
        fs::write(&path, b"trusted policy").expect("write generated fixture");
        let build = DeepLayoutBuild {
            policy_path: path.clone(),
            layout_sha256: bytes_digest(b"layout"),
            policy_sha256: bytes_digest(b"trusted policy"),
        };
        build.verify_unchanged().expect("trusted policy rejected");
        fs::write(&path, b"changed policy").expect("replace policy contents");
        assert!(build.verify_unchanged().is_err());
        fs::remove_file(&path).expect("remove changed policy");
        let target = root.join("target.rs");
        fs::write(&target, b"trusted policy").expect("write symlink target");
        symlink(&target, &path).expect("swap policy for symlink");
        assert!(build.verify_unchanged().is_err());
        fs::remove_dir_all(root).expect("remove isolated generated directory");
    }

    #[test]
    fn exact_layout_bytes_are_bound_to_the_pinned_git_blob() {
        use std::fs;
        use std::process::Command;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "wyrmroot-layout-git-blob-test-{}-{nonce}",
            std::process::id()
        ));
        let layout_path = root.join(super::LAYOUT_PATH);
        fs::create_dir_all(layout_path.parent().expect("layout parent"))
            .expect("create layout fixture tree");
        fs::write(&layout_path, b"trusted layout bytes\n").expect("write layout fixture");
        for arguments in [
            vec!["init", "-q"],
            vec!["add", super::LAYOUT_PATH],
            vec![
                "-c",
                "user.name=Wyrmroot test",
                "-c",
                "user.email=wyrmroot-test@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "-m",
                "fixture",
            ],
        ] {
            assert!(
                Command::new("git")
                    .arg("-C")
                    .arg(&root)
                    .args(arguments)
                    .status()
                    .expect("run fixture Git command")
                    .success()
            );
        }
        verify_tracked_bytes(&root, super::LAYOUT_PATH, b"trusted layout bytes\n")
            .expect("exact committed layout bytes rejected");
        assert!(
            verify_tracked_bytes(&root, super::LAYOUT_PATH, b"swapped layout bytes\n").is_err()
        );
        fs::remove_dir_all(root).expect("remove isolated Git fixture");
    }

    #[test]
    fn layout_read_detects_a_path_swap_after_open() {
        use std::fs;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "wyrmroot-layout-path-swap-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create isolated layout directory");
        let path = root.join("layout.toml");
        fs::write(&path, b"trusted").expect("write trusted layout");
        let open = open_stable_regular_file(&path, "test layout").expect("open trusted layout");
        fs::rename(&path, root.join("original.toml")).expect("move open layout");
        fs::write(&path, b"replacement").expect("install replacement layout");
        assert!(verify_open_file_identity(&open, &path, "test layout").is_err());
        fs::remove_dir_all(root).expect("remove isolated layout directory");
    }

    #[test]
    fn cargo_checkout_marker_is_the_only_allowed_untracked_entry() {
        use std::fs;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "wyrmroot-cargo-marker-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create isolated checkout root");
        fs::write(root.join(".cargo-ok"), []).expect("write empty Cargo marker");
        validate_git_status(&root, "?? .cargo-ok\n")
            .expect("canonical Cargo checkout marker rejected");
        assert!(validate_git_status(&root, "?? layout.toml\n").is_err());
        fs::write(root.join(".cargo-ok"), b"contaminated").expect("replace marker content");
        assert!(validate_git_status(&root, "?? .cargo-ok\n").is_err());
        fs::remove_dir_all(root).expect("remove isolated checkout root");
    }

    fn metadata(source: &str, manifest: &str) -> String {
        format!(
            r#"{{"packages":[{{"name":"deepwyrm-abi","source":"{source}","manifest_path":"{manifest}"}}],"workspace_root":"/synthetic/private/workspace"}}"#
        )
    }

    fn layout(link_base: &str) -> String {
        format!(
            r#"schema = "deepwyrm-x86_64-layout"
version = 1
entry_contract = "DW_BOOT_X86_64_ENTRY_V1"
elf_type = "ET_EXEC"
entry_symbol = "_dw_kernel_entry"
link_base = "{link_base}"
base_page_size = 4096
red_zone = false
kernel_boot_stack_size = 65536
kernel_boot_stack_alignment = 4096
loader_transition_stack_size = 16384
loader_transition_stack_alignment = 4096
p_paddr_policy = "ignored"
allowed_program_header_types = ["PT_LOAD"]

[load_policy]
upper_canonical = true
non_overlapping = true
writable_xor_executable = true
entry_in_executable_segment = true

[entry_state]
transfer = "jmp"
returns = false
boot_info_register = "RDI"
boot_info_address = "identity-mapped-physical"
boot_info_alignment = 8
defined_incoming_gprs = ["RDI"]
loader_stack_owner = "loader"
loader_stack_rsp = "one-past-end"
loader_stack_rsp_mod_16 = 0
loader_stack_lifetime = "until-kernel-page-table-replacement"
immediate_kernel_stack_switch = true
kernel_stack_owner = "kernel"
kernel_stack_rsp_mod_16_before_call = 0
rust_entry_rsp_mod_16 = 8
rust_entry_abi = "sysv64"
interrupts_enabled = false
direction_flag_set = false
cr0_write_protect = true
execute_disable = true
paging_mode = "x86_64-4-level"
initial_processor = "BSP"
descriptor_state = "valid-CS-SS-others-unspecified"
tls_state = "FS-GS-unspecified"
fp_simd_state = "unavailable-until-kernel-initialization"
uefi_services_available = false
firmware_exit = "ExitBootServices-complete"

[handoff_mappings]
kernel_load_segments = "mapped-at-p_vaddr"
physical_allocation = "arbitrary-suitable-firmware-pages"
boot_info = "identity-mapped"
referenced_ranges = "identity-mapped"
lifetime = "until-kernel-page-table-replacement"
mutable = false
page_zero_mapped = false
framebuffer_pixels_identity_mapped = false

[early_intake]
max_normalized_memory_map_entries = 128
max_module_entries = 16
acpi_scope = "rsdp-only"
acpi_guid_preference = "ACPI_20_TABLE_GUID-then-ACPI_TABLE_GUID"
acpi_duplicate_selected_guid = "reject"
acpi_preferred_invalid = "reject-no-downgrade"
acpi_rsdp_signature = "RSD PTR "
acpi_rsdp_length_rule = "revision-lt-2:20;revision-ge-2:declared-36..4096"
acpi_rsdp_checksum = "v1-first-20-and-v2-full-record"
acpi_rsdp_mapping = "validated-record-intersecting-base-pages-only"
acpi_rsdp_max_intersecting_pages = 2
acpi_mapping_overlap = "coalesce"
acpi_table_traversal = "deferred-dw0-c"
acpi_memory_types_identity_mapped = false
"#
        )
    }
}
