use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use crate::cli::validate_filter;
use crate::deep_layout::DeepLayoutBuild;
use crate::error::Failure;
use crate::metadata::{BuildManifest, LoaderProfile};
use crate::provenance::{LoaderProvenance, write_loader_provenance};
use crate::sha256::{bytes_digest, file_digest};
use crate::toolchain_artifact::AcceptedToolchain;

const UEFI_TARGET_DIRECTORY: &str = "target/wyr0-b";
const UEFI_PROFILE_DIRECTORY: &str = "debug";
const TOOLCHAIN_REQUEST: &str = "toolchain/requests/RUST-WYR0B-UEFI-001.toml";
const MAX_LOADER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DEBUG_SYMBOL_BYTES: u64 = 512 * 1024 * 1024;
const DEEP_LAYOUT_POLICY_ENV: &str = "WYRMROOT_DEEP_LAYOUT_POLICY_RS";

pub(crate) struct LoaderToolchain {
    accepted: AcceptedToolchain,
    validation_report: String,
}

pub(crate) fn repository_root() -> Result<PathBuf, Failure> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .ok_or_else(|| Failure::task("could not resolve the Wyrmroot repository root"))
}

pub(crate) fn run_host_tool_probe(repository: &Path) -> Result<(), Failure> {
    let status = Command::new("sh")
        .arg("toolchain/verify-host-tools.sh")
        .arg("--json")
        .current_dir(repository)
        .stdin(Stdio::null())
        .status()
        .map_err(|error| Failure::task(format!("could not run host toolchain probe: {error}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(Failure::task(format!(
            "host toolchain probe failed with {}",
            child_status(status.code())
        )))
    }
}

pub(crate) fn run_workspace_build(repository: &Path) -> Result<(), Failure> {
    run_cargo(
        repository,
        &["build", "--workspace", "--all-targets", "--locked"],
    )
}

pub(crate) fn run_loader_build(
    repository: &Path,
    manifest: &BuildManifest,
    profile: &LoaderProfile,
    toolchain: &LoaderToolchain,
    layout: &DeepLayoutBuild,
) -> Result<(), Failure> {
    run_cargo(
        repository,
        &["test", "--locked", "--package", &profile.cargo_package],
    )?;
    let target_directory = repository.join(UEFI_TARGET_DIRECTORY);
    run_uefi_cargo(
        repository,
        toolchain,
        profile,
        &target_directory,
        &layout.policy_path,
        "check",
    )?;
    run_uefi_cargo(
        repository,
        toolchain,
        profile,
        &target_directory,
        &layout.policy_path,
        "build",
    )?;

    let output_directory = target_directory
        .join(&profile.rust_target)
        .join(UEFI_PROFILE_DIRECTORY);
    let loader = output_directory.join(&profile.artifact_name);
    let debug_symbols = output_directory.join(format!("{}.pdb", profile.cargo_binary));
    validate_regular_artifact(&loader, "UEFI loader", MAX_LOADER_BYTES)?;
    validate_regular_artifact(
        &debug_symbols,
        "UEFI loader debug symbols",
        MAX_DEBUG_SYMBOL_BYTES,
    )?;

    let artifact_report = run_verified_report(
        repository,
        &profile.artifact_inspection,
        [loader.as_os_str(), debug_symbols.as_os_str()],
        "UEFI artifact inspection",
    )?;
    let loader_hash = digest(&loader)?;
    let debug_hash = digest(&debug_symbols)?;
    let rustc_hash = digest(&toolchain.accepted.rustc)?;
    let versions_hash = digest(&repository.join("toolchain/versions.toml"))?;
    let profiles_hash = digest(&repository.join("toolchain/profiles.toml"))?;
    let toolchain_report_hash = bytes_digest(toolchain.validation_report.as_bytes());
    let artifact_report_hash = bytes_digest(artifact_report.as_bytes());
    let (repository_revision, repository_dirty) = repository_identity(repository)?;
    let loader_relative = repository_relative_path(repository, &loader, "UEFI loader")?;
    let debug_relative =
        repository_relative_path(repository, &debug_symbols, "UEFI loader debug symbols")?;

    let record = LoaderProvenance {
        repository_revision: &repository_revision,
        repository_dirty,
        deepwyrm_revision: manifest.deepwyrm_revision()?,
        rust_revision: manifest.rust_revision()?,
        rust_toolchain_name: manifest.rust_toolchain_name()?,
        rustc_sha256: &rustc_hash,
        cargo_sha256: &toolchain.accepted.cargo_sha256,
        rust_lld_sha256: &toolchain.accepted.rust_lld_sha256,
        uefi_core_sha256: &toolchain.accepted.uefi_core_sha256,
        uefi_builtins_sha256: &toolchain.accepted.uefi_builtins_sha256,
        toolchain_manifest_sha256: &toolchain.accepted.manifest_sha256,
        target: &profile.rust_target,
        package: &profile.cargo_package,
        binary: &profile.cargo_binary,
        artifact_path: &loader_relative,
        artifact_sha256: &loader_hash,
        debug_path: &debug_relative,
        debug_sha256: &debug_hash,
        versions_sha256: &versions_hash,
        profiles_sha256: &profiles_hash,
        deep_layout_sha256: &layout.layout_sha256,
        generated_layout_policy_sha256: &layout.policy_sha256,
        toolchain_report_sha256: &toolchain_report_hash,
        artifact_report_sha256: &artifact_report_hash,
    };
    let provenance = write_loader_provenance(&target_directory, &record)?;
    println!("xtask: validated UEFI loader: {}", loader.display());
    println!("xtask: recorded provenance: {}", provenance.display());
    Ok(())
}

fn repository_relative_path(
    repository: &Path,
    path: &Path,
    label: &str,
) -> Result<String, Failure> {
    let relative = path.strip_prefix(repository).map_err(|_| {
        Failure::task(format!(
            "{label} path is outside the Wyrmroot repository: {}",
            path.display()
        ))
    })?;
    relative
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| Failure::task(format!("{label} path is not valid UTF-8")))
}

pub(crate) fn prepare_loader_toolchain(
    repository: &Path,
    profile: &LoaderProfile,
    manifest: &BuildManifest,
) -> Result<LoaderToolchain, Failure> {
    reject_ambient_rust_overrides()?;
    let configured = configured_rustc(repository)?;
    let accepted = crate::toolchain_artifact::prepare(
        repository,
        &configured,
        manifest.rust_toolchain_name()?,
        manifest.rust_revision()?,
    )?;
    accepted.verify_unchanged()?;
    let validation_report = run_verified_report(
        repository,
        &profile.toolchain_inspection,
        [OsStr::new("--rustc"), accepted.rustc.as_os_str()],
        "UEFI toolchain validation",
    )?;
    accepted.verify_unchanged()?;
    Ok(LoaderToolchain {
        accepted,
        validation_report,
    })
}

fn configured_rustc(repository: &Path) -> Result<PathBuf, Failure> {
    let Some(configured) = env::var_os("WYRMROOT_RUSTC") else {
        let request_path = repository.join(TOOLCHAIN_REQUEST);
        let request = fs::read_to_string(&request_path).map_err(|error| {
            Failure::task(format!(
                "accepted WYR0-B rustc is unavailable and toolchain request {} could not be read: {error}",
                request_path.display()
            ))
        })?;
        return Err(blocked_toolchain_failure(&request));
    };
    let path = PathBuf::from(configured);
    if !path.is_absolute() {
        return Err(Failure::task(
            "WYRMROOT_RUSTC must be an absolute path to the accepted compiler",
        ));
    }
    Ok(path)
}

fn blocked_toolchain_failure(request: &str) -> Failure {
    let status = scalar_assignment(request, "status").unwrap_or("missing-status");
    Failure::task(format!(
        "accepted WYR0-B rustc is unavailable: {TOOLCHAIN_REQUEST} status is '{status}'; set WYRMROOT_RUSTC only to the accepted compiler artifact from that coordinator request"
    ))
}

fn scalar_assignment<'a>(contents: &'a str, key: &str) -> Option<&'a str> {
    contents.lines().find_map(|line| {
        let (actual_key, value) = line.split_once('=')?;
        if actual_key.trim() != key {
            return None;
        }
        value.trim().strip_prefix('"')?.strip_suffix('"')
    })
}

fn reject_ambient_rust_overrides() -> Result<(), Failure> {
    for variable in [
        "RUSTC",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_TARGET",
        "CARGO_TARGET_DIR",
        DEEP_LAYOUT_POLICY_ENV,
    ] {
        if env::var_os(variable).is_some() {
            return Err(Failure::task(format!(
                "UEFI loader build refuses ambient {variable}; centralized WYR0-B tooling owns compiler, target, flags, and output paths"
            )));
        }
    }
    if let Some((variable, _)) = env::vars_os().find(|(key, _)| {
        key.to_str()
            .is_some_and(|key| key.starts_with("CARGO_TARGET_"))
    }) {
        return Err(Failure::task(format!(
            "UEFI loader build refuses ambient {}; centralized WYR0-B tooling owns target-specific linker and rustflags configuration",
            variable.to_string_lossy()
        )));
    }
    Ok(())
}

fn run_verified_report<I, S>(
    repository: &Path,
    script: &str,
    arguments: I,
    label: &str,
) -> Result<String, Failure>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new("sh")
        .arg(script)
        .args(arguments)
        .current_dir(repository)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| Failure::task(format!("could not run {label}: {error}")))?;
    let report = utf8_stdout(&output, label)?;
    if !output.status.success() || !report.contains("\"verified\": true") {
        return Err(Failure::task(format!(
            "{label} failed with {}: {}{}",
            child_status(output.status.code()),
            report.trim(),
            stderr_suffix(&output)
        )));
    }
    Ok(report)
}

fn run_uefi_cargo(
    repository: &Path,
    toolchain: &LoaderToolchain,
    profile: &LoaderProfile,
    target_directory: &Path,
    layout_policy: &Path,
    operation: &str,
) -> Result<(), Failure> {
    toolchain.accepted.verify_unchanged()?;
    let sysroot = toolchain
        .accepted
        .sysroot
        .to_str()
        .ok_or_else(|| Failure::task("accepted toolchain sysroot path is not valid UTF-8"))?;
    let rust_lld = toolchain
        .accepted
        .rust_lld
        .to_str()
        .ok_or_else(|| Failure::task("accepted rust-lld path is not valid UTF-8"))?;
    let encoded_rustflags = format!("--sysroot\u{1f}{sysroot}\u{1f}-C\u{1f}linker={rust_lld}");
    let status = Command::new(&toolchain.accepted.cargo)
        .arg(operation)
        .arg("--locked")
        .arg("--package")
        .arg(&profile.cargo_package)
        .arg("--bin")
        .arg(&profile.cargo_binary)
        .arg("--features")
        .arg(&profile.cargo_features)
        .arg("--target")
        .arg(&profile.rust_target)
        .arg("--target-dir")
        .arg(target_directory)
        .env("RUSTC", &toolchain.accepted.rustc)
        .env("CARGO_ENCODED_RUSTFLAGS", encoded_rustflags)
        .env(
            "CARGO_TARGET_X86_64_UNKNOWN_UEFI_LINKER",
            &toolchain.accepted.rust_lld,
        )
        .env(DEEP_LAYOUT_POLICY_ENV, layout_policy)
        .current_dir(repository)
        .stdin(Stdio::null())
        .status()
        .map_err(|error| Failure::task(format!("could not run Cargo {operation}: {error}")))?;
    toolchain.accepted.verify_unchanged()?;
    if status.success() {
        Ok(())
    } else {
        Err(Failure::task(format!(
            "UEFI Cargo {operation} failed with {}",
            child_status(status.code())
        )))
    }
}

fn validate_regular_artifact(path: &Path, label: &str, maximum: u64) -> Result<(), Failure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Failure::task(format!("missing {label} {}: {error}", path.display())))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Failure::task(format!(
            "{label} must be a regular non-symlink file: {}",
            path.display()
        )));
    }
    if metadata.len() == 0 || metadata.len() > maximum {
        return Err(Failure::task(format!(
            "{label} size {} is outside the accepted range 1..={maximum}: {}",
            metadata.len(),
            path.display()
        )));
    }
    Ok(())
}

fn digest(path: &Path) -> Result<String, Failure> {
    file_digest(path)
        .map_err(|error| Failure::task(format!("could not hash {}: {error}", path.display())))
}

fn repository_identity(repository: &Path) -> Result<(String, bool), Failure> {
    let revision_output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repository)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| Failure::task(format!("could not inspect Wyrmroot revision: {error}")))?;
    let revision = utf8_stdout(&revision_output, "Wyrmroot revision inspection")?
        .trim()
        .to_owned();
    if !revision_output.status.success()
        || revision.len() != 40
        || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(Failure::task(
            "Wyrmroot revision inspection did not return a full Git commit",
        ));
    }
    let status_output = Command::new("git")
        .args(["status", "--porcelain=v1", "--untracked-files=all"])
        .current_dir(repository)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| Failure::task(format!("could not inspect Wyrmroot status: {error}")))?;
    if !status_output.status.success() {
        return Err(Failure::task(format!(
            "Wyrmroot status inspection failed with {}",
            child_status(status_output.status.code())
        )));
    }
    Ok((revision, !status_output.stdout.is_empty()))
}

fn utf8_stdout(output: &Output, label: &str) -> Result<String, Failure> {
    String::from_utf8(output.stdout.clone())
        .map_err(|_| Failure::task(format!("{label} produced non-UTF-8 output")))
}

fn stderr_suffix(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.trim().is_empty() {
        String::new()
    } else {
        format!("; stderr: {}", stderr.trim())
    }
}

pub(crate) fn run_host_tests(repository: &Path, filter: Option<&str>) -> Result<(), Failure> {
    let mut arguments = vec!["test", "--locked"];
    let owned_filter;

    match filter.and_then(component_package) {
        Some(package) => arguments.extend(["--package", package]),
        None => {
            arguments.extend(["--workspace", "--all-targets"]);
            if let Some(filter) = filter {
                owned_filter = explicit_test_filter(filter)?;
                arguments.extend(["--", owned_filter.as_str()]);
            }
        }
    }
    run_cargo(repository, &arguments)
}

fn component_package(filter: &str) -> Option<&'static str> {
    match filter {
        "bootfs" | "wyrmroot-bootfs" | "package:wyrmroot-bootfs" => Some("wyrmroot-bootfs"),
        "protocol"
        | "bootstrap-proto"
        | "wyrmroot-bootstrap-proto"
        | "package:wyrmroot-bootstrap-proto" => Some("wyrmroot-bootstrap-proto"),
        "elf" | "loader" | "wyrmroot-loader" | "package:wyrmroot-loader" => Some("wyrmroot-loader"),
        "runtime" | "wyrmroot-runtime" | "package:wyrmroot-runtime" => Some("wyrmroot-runtime"),
        "bootstrap" | "wyrmroot-bootstrap" | "package:wyrmroot-bootstrap" => {
            Some("wyrmroot-bootstrap")
        }
        "efi" | "uefi" | "efi-loader" | "wyrmroot-efi-loader" | "package:wyrmroot-efi-loader" => {
            Some("wyrmroot-efi-loader")
        }
        "init0" | "wyrmroot-init0" | "package:wyrmroot-init0" => Some("wyrmroot-init0"),
        "hello" | "wyrmroot-hello" | "package:wyrmroot-hello" => Some("wyrmroot-hello"),
        "xtask" | "package:xtask" => Some("xtask"),
        _ => None,
    }
}

fn explicit_test_filter(filter: &str) -> Result<String, Failure> {
    if let Some(package) = filter.strip_prefix("package:") {
        return Err(Failure::usage(format!(
            "unknown host-test package '{package}'"
        )));
    }
    let filter = filter.strip_prefix("test:").unwrap_or(filter);
    validate_filter(filter)?;
    Ok(filter.to_owned())
}

fn run_cargo(repository: &Path, arguments: &[&str]) -> Result<(), Failure> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .args(arguments)
        .current_dir(repository)
        .stdin(Stdio::null())
        .status()
        .map_err(|error| Failure::task(format!("could not run Cargo: {error}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(Failure::task(format!(
            "Cargo task failed with {}",
            child_status(status.code())
        )))
    }
}

fn child_status(code: Option<i32>) -> String {
    code.map_or_else(
        || "termination by signal".to_owned(),
        |code| format!("exit code {code}"),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        blocked_toolchain_failure, component_package, explicit_test_filter,
        validate_regular_artifact,
    };
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn component_filters_select_one_workspace_package() {
        assert_eq!(component_package("bootfs"), Some("wyrmroot-bootfs"));
        assert_eq!(
            component_package("protocol"),
            Some("wyrmroot-bootstrap-proto")
        );
        assert_eq!(component_package("elf"), Some("wyrmroot-loader"));
        assert_eq!(component_package("runtime"), Some("wyrmroot-runtime"));
        assert_eq!(component_package("hello"), Some("wyrmroot-hello"));
        assert_eq!(component_package("xtask"), Some("xtask"));
        assert_eq!(component_package("malformed"), None);
        assert_eq!(explicit_test_filter("test:malformed").unwrap(), "malformed");
        assert!(explicit_test_filter("package:unknown").is_err());
    }

    #[test]
    fn blocked_toolchain_request_has_stable_diagnostic() {
        let failure = blocked_toolchain_failure(
            "request_id = \"RUST-WYR0B-UEFI-001\"\nstatus = \"blocked-pending-coordinator-assignment\"\n",
        );
        assert_eq!(
            failure.message,
            "accepted WYR0-B rustc is unavailable: toolchain/requests/RUST-WYR0B-UEFI-001.toml status is 'blocked-pending-coordinator-assignment'; set WYRMROOT_RUSTC only to the accepted compiler artifact from that coordinator request"
        );
    }

    #[cfg(unix)]
    #[test]
    fn artifact_validation_rejects_symlinks_and_invalid_sizes() {
        use std::os::unix::fs::symlink;

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "wyrmroot-xtask-artifact-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create isolated test directory");

        let regular = root.join("loader.efi");
        fs::write(&regular, [0x4d, 0x5a]).expect("write regular test artifact");
        validate_regular_artifact(&regular, "test artifact", 2)
            .expect("valid regular artifact rejected");

        let empty = root.join("empty.efi");
        fs::write(&empty, []).expect("write empty test artifact");
        assert!(validate_regular_artifact(&empty, "test artifact", 2).is_err());

        assert!(validate_regular_artifact(&regular, "test artifact", 1).is_err());

        let link = root.join("linked.efi");
        symlink(&regular, &link).expect("create test artifact symlink");
        let failure = validate_regular_artifact(&link, "test artifact", 2)
            .expect_err("artifact validator followed or accepted a symlink");
        assert!(failure.message.contains("regular non-symlink file"));

        fs::remove_dir_all(&root).expect("remove isolated test directory");
    }
}
