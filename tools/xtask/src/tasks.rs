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
const UEFI_DEBUG_TARGET_DIRECTORY: &str = "target/wyr0-b-symbols";
const TOOLCHAIN_REQUEST: &str = "toolchain/requests/RUST-WYR0-I-B-SYSROOTS-007.toml";
const MAX_LOADER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DEBUG_SYMBOL_BYTES: u64 = 512 * 1024 * 1024;
const DEEP_LAYOUT_POLICY_ENV: &str = "WYRMROOT_DEEP_LAYOUT_POLICY_RS";
const BOOTFS_PACKAGE: &str = "wyrmroot-bootfs";
const BOOTFS_BUILDER_FEATURE: &str = "builder";
const BOOTFS_BUILD_ARGUMENTS: &[&str] = &[
    "build",
    "--locked",
    "--package",
    BOOTFS_PACKAGE,
    "--all-targets",
    "--features",
    BOOTFS_BUILDER_FEATURE,
];
const BOOTFS_TEST_ARGUMENTS: &[&str] = &[
    "test",
    "--locked",
    "--package",
    BOOTFS_PACKAGE,
    "--features",
    BOOTFS_BUILDER_FEATURE,
];
const DW1C_INIT0_TEST_ARGUMENTS: &[&str] = &[
    "test",
    "--locked",
    "--package",
    "wyrmroot-init0",
    "--features",
    "dw1c-preemption-integration",
    "--lib",
    "dw1c_protocol_tests",
];

pub(crate) struct LoaderToolchain {
    accepted: AcceptedToolchain,
    validation_report: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoaderLinkMode {
    Production,
    RetainedDebug,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UefiCargoOperation {
    Check,
    Build,
}

impl UefiCargoOperation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Build => "build",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UefiCargoProfile {
    Development,
    Release,
}

impl UefiCargoProfile {
    const fn directory(self) -> &'static str {
        match self {
            Self::Development => "debug",
            Self::Release => "release",
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Release => "release",
        }
    }
}

pub(crate) struct IsolatedUefiBuild<'a> {
    pub(crate) cargo_home: &'a Path,
    pub(crate) production_target: &'a Path,
    pub(crate) retained_debug_target: &'a Path,
    pub(crate) cargo_profile: UefiCargoProfile,
}

struct UefiCargoInvocation<'a> {
    cargo_home: &'a Path,
    target_directory: &'a Path,
    cargo_profile: UefiCargoProfile,
    link_mode: LoaderLinkMode,
    operation: UefiCargoOperation,
}

pub(crate) struct DeterministicUefiArtifacts {
    pub(crate) loader: PathBuf,
    pub(crate) debug_loader: PathBuf,
    pub(crate) debug_symbols: PathBuf,
    pub(crate) effective_config: String,
    pub(crate) effective_config_sha256: String,
    pub(crate) inspection_report: String,
    pub(crate) inspection_report_sha256: String,
    _target_authority: Option<UefiTargetAuthority>,
}

struct UefiTargetAuthority {
    _production: crate::secure_fs::InheritableDirectory,
    _retained_debug: crate::secure_fs::InheritableDirectory,
}

struct PreparedUefiTargetRoots {
    production: PathBuf,
    retained_debug: PathBuf,
    authority: Option<UefiTargetAuthority>,
}

impl LoaderToolchain {
    pub(crate) const fn accepted(&self) -> &AcceptedToolchain {
        &self.accepted
    }

    pub(crate) fn validation_report_sha256(&self) -> String {
        bytes_digest(self.validation_report.as_bytes())
    }
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

pub(crate) fn run_bootfs_build(repository: &Path) -> Result<(), Failure> {
    run_cargo(repository, BOOTFS_BUILD_ARGUMENTS)
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
    let debug_target_directory = repository.join(UEFI_DEBUG_TARGET_DIRECTORY);
    let cargo_home = project_cargo_home(repository, manifest)?;
    let artifacts = build_deterministic_uefi_pair(
        repository,
        toolchain,
        profile,
        layout,
        &IsolatedUefiBuild {
            cargo_home: &cargo_home,
            production_target: &target_directory,
            retained_debug_target: &debug_target_directory,
            cargo_profile: UefiCargoProfile::Development,
        },
    )?;
    let loader = &artifacts.loader;
    let debug_loader = &artifacts.debug_loader;
    let debug_symbols = &artifacts.debug_symbols;
    let loader_hash = digest(loader)?;
    let debug_loader_hash = digest(debug_loader)?;
    let debug_hash = digest(debug_symbols)?;
    let rustc_hash = digest(&toolchain.accepted.rustc)?;
    let versions_hash = digest(&repository.join("toolchain/versions.toml"))?;
    let profiles_hash = digest(&repository.join("toolchain/profiles.toml"))?;
    let toolchain_report_hash = toolchain.validation_report_sha256();
    let artifact_report_hash = artifacts.inspection_report_sha256;
    let (repository_revision, repository_dirty) = repository_identity(repository)?;
    let loader_relative = repository_relative_path(repository, loader, "UEFI loader")?;
    let debug_loader_relative =
        repository_relative_path(repository, debug_loader, "retained debug UEFI loader")?;
    let debug_relative =
        repository_relative_path(repository, debug_symbols, "UEFI loader debug symbols")?;

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
        uefi_alloc_sha256: &toolchain.accepted.uefi_alloc_sha256,
        uefi_builtins_sha256: &toolchain.accepted.uefi_builtins_sha256,
        rustc_driver_sha256: &toolchain.accepted.rustc_driver_sha256,
        llvm_sha256: &toolchain.accepted.llvm_sha256,
        toolchain_tree_sha256: &toolchain.accepted.toolchain_tree_sha256,
        toolchain_manifest_sha256: &toolchain.accepted.manifest_sha256,
        target: &profile.rust_target,
        package: &profile.cargo_package,
        binary: &profile.cargo_binary,
        artifact_path: &loader_relative,
        artifact_sha256: &loader_hash,
        debug_image_path: &debug_loader_relative,
        debug_image_sha256: &debug_loader_hash,
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
    let configured = configured_rustc(repository, manifest)?;
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

fn configured_rustc(repository: &Path, manifest: &BuildManifest) -> Result<PathBuf, Failure> {
    if env::var_os("WYRMROOT_RUSTC").is_some() {
        return Err(Failure::task(
            "WYRMROOT_RUSTC is toolchain-owned; do not supply it",
        ));
    }
    let artifact_root = Path::new(manifest.accepted_artifact_root()?);
    if artifact_root.is_absolute()
        || artifact_root
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(Failure::task(
            "accepted Rust artifact root must be a canonical project-relative path",
        ));
    }
    let project = repository
        .parent()
        .ok_or_else(|| Failure::task("Wyrmroot repository has no OS-Project parent"))?;
    let rustc = project
        .join(artifact_root)
        .join("toolchains")
        .join(manifest.rust_toolchain_name()?)
        .join("bin/rustc");
    let canonical = fs::canonicalize(&rustc).map_err(|error| {
        let request_path = repository.join(TOOLCHAIN_REQUEST);
        let request = fs::read_to_string(&request_path).unwrap_or_default();
        Failure::task(format!(
            "{}; accepted Rust compiler {} is unavailable: {error}",
            blocked_toolchain_failure(&request).message,
            rustc.display()
        ))
    })?;
    if canonical != rustc {
        return Err(Failure::task(
            "accepted Rust compiler path is not canonical",
        ));
    }
    Ok(canonical)
}

pub(crate) fn project_cargo_home(
    repository: &Path,
    manifest: &BuildManifest,
) -> Result<PathBuf, Failure> {
    let relative = Path::new(manifest.project_cargo_home()?);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(Failure::task(
            "toolchain Cargo home must be a canonical project-relative path",
        ));
    }
    let project = repository
        .parent()
        .ok_or_else(|| Failure::task("Wyrmroot repository has no OS-Project parent"))?;
    let project = canonical_build_directory(project, "OS-Project root")?;
    let path = project.join(relative);
    let cargo_home = canonical_build_directory(&path, "project Cargo home")?;
    if !cargo_home.starts_with(project.join(".tmp")) {
        return Err(Failure::task(
            "toolchain Cargo home must remain beneath OS-Project/.tmp",
        ));
    }
    Ok(cargo_home)
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
        .env_remove("LD_AUDIT")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD")
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

pub(crate) fn build_deterministic_uefi_pair(
    repository: &Path,
    toolchain: &LoaderToolchain,
    profile: &LoaderProfile,
    layout: &DeepLayoutBuild,
    build: &IsolatedUefiBuild<'_>,
) -> Result<DeterministicUefiArtifacts, Failure> {
    build_deterministic_uefi_pair_with_authority(
        repository, toolchain, profile, layout, build, None,
    )
}

pub(crate) fn build_deterministic_uefi_pair_in_scratch(
    repository: &Path,
    toolchain: &LoaderToolchain,
    profile: &LoaderProfile,
    layout: &DeepLayoutBuild,
    build: &IsolatedUefiBuild<'_>,
    scratch: &crate::secure_fs::InheritableDirectory,
) -> Result<DeterministicUefiArtifacts, Failure> {
    build_deterministic_uefi_pair_with_authority(
        repository,
        toolchain,
        profile,
        layout,
        build,
        Some(scratch),
    )
}

fn build_deterministic_uefi_pair_with_authority(
    repository: &Path,
    toolchain: &LoaderToolchain,
    profile: &LoaderProfile,
    layout: &DeepLayoutBuild,
    build: &IsolatedUefiBuild<'_>,
    scratch: Option<&crate::secure_fs::InheritableDirectory>,
) -> Result<DeterministicUefiArtifacts, Failure> {
    let cargo_home = canonical_build_directory(build.cargo_home, "Cargo home")?;
    let target_roots = prepare_uefi_target_roots(build, scratch)?;
    let production_target = &target_roots.production;
    let retained_debug_target = &target_roots.retained_debug;
    run_uefi_cargo(
        repository,
        toolchain,
        profile,
        layout,
        &UefiCargoInvocation {
            cargo_home: &cargo_home,
            target_directory: production_target,
            cargo_profile: build.cargo_profile,
            link_mode: LoaderLinkMode::Production,
            operation: UefiCargoOperation::Check,
        },
    )?;
    run_uefi_cargo(
        repository,
        toolchain,
        profile,
        layout,
        &UefiCargoInvocation {
            cargo_home: &cargo_home,
            target_directory: retained_debug_target,
            cargo_profile: build.cargo_profile,
            link_mode: LoaderLinkMode::RetainedDebug,
            operation: UefiCargoOperation::Build,
        },
    )?;
    run_uefi_cargo(
        repository,
        toolchain,
        profile,
        layout,
        &UefiCargoInvocation {
            cargo_home: &cargo_home,
            target_directory: production_target,
            cargo_profile: build.cargo_profile,
            link_mode: LoaderLinkMode::Production,
            operation: UefiCargoOperation::Build,
        },
    )?;

    let loader = production_target
        .join(&profile.rust_target)
        .join(build.cargo_profile.directory())
        .join(&profile.artifact_name);
    let debug_output = retained_debug_target
        .join(&profile.rust_target)
        .join(build.cargo_profile.directory());
    let debug_loader = debug_output.join(&profile.artifact_name);
    let debug_symbols = debug_output.join(format!("{}.pdb", profile.cargo_binary));
    validate_regular_artifact(&loader, "UEFI loader", MAX_LOADER_BYTES)?;
    validate_regular_artifact(
        &debug_loader,
        "retained debug UEFI loader",
        MAX_LOADER_BYTES,
    )?;
    validate_regular_artifact(
        &debug_symbols,
        "UEFI loader debug symbols",
        MAX_DEBUG_SYMBOL_BYTES,
    )?;
    let inspection_report = run_verified_report(
        repository,
        &profile.artifact_inspection,
        [
            loader.as_os_str(),
            debug_loader.as_os_str(),
            debug_symbols.as_os_str(),
        ],
        "UEFI artifact inspection",
    )?;
    let effective_config = normalized_uefi_config(profile, build.cargo_profile);
    Ok(DeterministicUefiArtifacts {
        loader,
        debug_loader,
        debug_symbols,
        effective_config_sha256: bytes_digest(effective_config.as_bytes()),
        effective_config,
        inspection_report_sha256: bytes_digest(inspection_report.as_bytes()),
        inspection_report,
        _target_authority: target_roots.authority,
    })
}

fn prepare_uefi_target_roots(
    build: &IsolatedUefiBuild<'_>,
    scratch: Option<&crate::secure_fs::InheritableDirectory>,
) -> Result<PreparedUefiTargetRoots, Failure> {
    if let Some(scratch) = scratch {
        let production = scratch
            .create_inheritable_child(build.production_target, "production UEFI target root")?;
        let retained_debug = scratch.create_inheritable_child(
            build.retained_debug_target,
            "retained-debug UEFI target root",
        )?;
        return Ok(PreparedUefiTargetRoots {
            production: production.path().to_path_buf(),
            retained_debug: retained_debug.path().to_path_buf(),
            authority: Some(UefiTargetAuthority {
                _production: production,
                _retained_debug: retained_debug,
            }),
        });
    }
    fs::create_dir_all(build.production_target).map_err(|error| {
        Failure::task(format!(
            "could not create production UEFI target root: {error}"
        ))
    })?;
    fs::create_dir_all(build.retained_debug_target).map_err(|error| {
        Failure::task(format!(
            "could not create retained-debug UEFI target root: {error}"
        ))
    })?;
    Ok(PreparedUefiTargetRoots {
        production: canonical_build_directory(
            build.production_target,
            "production UEFI target root",
        )?,
        retained_debug: canonical_build_directory(
            build.retained_debug_target,
            "retained-debug UEFI target root",
        )?,
        authority: None,
    })
}

fn normalized_uefi_config(profile: &LoaderProfile, cargo_profile: UefiCargoProfile) -> String {
    format!(
        concat!(
            "schema_version=1\n",
            "target={}\npackage={}\nbinary={}\nfeatures={}\nprofile={}\n",
            "repository_remap=/source/wyrmroot\n",
            "cargo_home_remap=/cargo-home\n",
            "cargo_target_remap=/cargo-target\n",
            "linker=accepted-rust-lld\n",
            "production_link_args=/Brepro,/debug:none\n",
            "retained_debug_link_args=/Brepro,/pdbaltpath:loader.pdb\n",
            "source_date_epoch=0\ncargo_incremental=0\n"
        ),
        profile.rust_target,
        profile.cargo_package,
        profile.cargo_binary,
        profile.cargo_features,
        cargo_profile.name(),
    )
}

fn run_uefi_cargo(
    repository: &Path,
    toolchain: &LoaderToolchain,
    profile: &LoaderProfile,
    layout: &DeepLayoutBuild,
    invocation: &UefiCargoInvocation<'_>,
) -> Result<(), Failure> {
    toolchain.accepted.verify_unchanged()?;
    layout.verify_unchanged()?;
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
    let encoded_rustflags = deterministic_uefi_rustflags(
        repository,
        invocation.cargo_home,
        invocation.target_directory,
        sysroot,
        rust_lld,
        invocation.link_mode,
    )?;
    let operation = invocation.operation.as_str();
    let mut command = Command::new(&toolchain.accepted.cargo);
    command.arg(operation).arg("--offline");
    if invocation.cargo_profile == UefiCargoProfile::Release {
        command.arg("--release");
    }
    let status = command
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
        .arg(invocation.target_directory)
        .env("CARGO_HOME", invocation.cargo_home)
        .env("RUSTC", &toolchain.accepted.rustc)
        .env("CARGO_ENCODED_RUSTFLAGS", encoded_rustflags)
        .env("SOURCE_DATE_EPOCH", "0")
        .env("CARGO_INCREMENTAL", "0")
        .env(
            "CARGO_TARGET_X86_64_UNKNOWN_UEFI_LINKER",
            &toolchain.accepted.rust_lld,
        )
        .env(DEEP_LAYOUT_POLICY_ENV, &layout.policy_path)
        .env_remove("LD_AUDIT")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD")
        .current_dir(repository)
        .stdin(Stdio::null())
        .status()
        .map_err(|error| Failure::task(format!("could not run Cargo {operation}: {error}")))?;
    layout.verify_unchanged()?;
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

fn deterministic_uefi_rustflags(
    repository: &Path,
    cargo_home: &Path,
    target_directory: &Path,
    sysroot: &str,
    rust_lld: &str,
    link_mode: LoaderLinkMode,
) -> Result<String, Failure> {
    encoded_uefi_rustflags(
        repository,
        cargo_home,
        target_directory,
        sysroot,
        rust_lld,
        link_mode,
    )
}

fn encoded_uefi_rustflags(
    repository: &Path,
    cargo_home: &Path,
    target_directory: &Path,
    sysroot: &str,
    rust_lld: &str,
    link_mode: LoaderLinkMode,
) -> Result<String, Failure> {
    let repository = canonical_build_directory(repository, "Wyrmroot repository")?;
    let cargo_home = canonical_build_directory(cargo_home, "Cargo home")?;
    let target_directory = canonical_build_directory(target_directory, "Cargo target root")?;
    let repository = repository
        .to_str()
        .ok_or_else(|| Failure::task("Wyrmroot repository path is not valid UTF-8"))?;
    let cargo_home = cargo_home
        .to_str()
        .ok_or_else(|| Failure::task("Cargo home path is not valid UTF-8"))?;
    let target_directory = target_directory
        .to_str()
        .ok_or_else(|| Failure::task("Cargo target root is not valid UTF-8"))?;

    for (value, label) in [
        (repository, "Wyrmroot repository"),
        (cargo_home, "Cargo home"),
        (target_directory, "Cargo target root"),
        (sysroot, "accepted sysroot"),
        (rust_lld, "accepted rust-lld"),
    ] {
        if value.contains('\u{1f}') {
            return Err(Failure::task(format!(
                "{label} path contains Cargo's encoded-rustflags separator"
            )));
        }
    }

    let mut flags = vec![
        "--sysroot".to_owned(),
        sysroot.to_owned(),
        "-C".to_owned(),
        format!("linker={rust_lld}"),
        format!("--remap-path-prefix={repository}=/source/wyrmroot"),
        format!("--remap-path-prefix={cargo_home}=/cargo-home"),
        format!("--remap-path-prefix={target_directory}=/cargo-target"),
        "-C".to_owned(),
        "link-arg=/Brepro".to_owned(),
    ];
    match link_mode {
        LoaderLinkMode::Production => {
            flags.push("-C".to_owned());
            flags.push("link-arg=/debug:none".to_owned());
        }
        LoaderLinkMode::RetainedDebug => {
            flags.push("-C".to_owned());
            flags.push("link-arg=/pdbaltpath:loader.pdb".to_owned());
        }
    }
    Ok(flags.join("\u{1f}"))
}

fn canonical_build_directory(path: &Path, label: &str) -> Result<PathBuf, Failure> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| Failure::task(format!("could not resolve {label}: {error}")))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Failure::task(format!("could not inspect {label}: {error}")))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || canonical != path {
        return Err(Failure::task(format!(
            "{label} must be an existing canonical non-symlink directory: {}",
            path.display()
        )));
    }
    Ok(canonical)
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
    for arguments in host_test_commands(filter)? {
        let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
        run_cargo(repository, &arguments)?;
    }
    Ok(())
}

fn host_test_commands(filter: Option<&str>) -> Result<Vec<Vec<String>>, Failure> {
    if matches!(filter, Some("dw1c" | "dw1c-init0")) {
        return Ok(vec![
            DW1C_INIT0_TEST_ARGUMENTS
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect(),
        ]);
    }
    let mut commands = vec![host_test_arguments(filter)?];
    if filter.is_none() {
        commands.push(
            BOOTFS_TEST_ARGUMENTS
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect(),
        );
    }
    Ok(commands)
}

fn host_test_arguments(filter: Option<&str>) -> Result<Vec<String>, Failure> {
    let mut arguments = vec!["test".to_owned(), "--locked".to_owned()];
    match filter.and_then(component_package) {
        Some(package) => {
            if package == BOOTFS_PACKAGE {
                return Ok(BOOTFS_TEST_ARGUMENTS
                    .iter()
                    .map(|argument| (*argument).to_owned())
                    .collect());
            }
            arguments.extend(["--package".to_owned(), package.to_owned()]);
        }
        None => {
            arguments.extend(["--workspace".to_owned(), "--all-targets".to_owned()]);
            if let Some(filter) = filter {
                arguments.extend(["--".to_owned(), explicit_test_filter(filter)?]);
            }
        }
    }
    Ok(arguments)
}

fn component_package(filter: &str) -> Option<&'static str> {
    match filter {
        "bootfs" | "wyrmroot-bootfs" | "package:wyrmroot-bootfs" => Some(BOOTFS_PACKAGE),
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
        BOOTFS_BUILD_ARGUMENTS, BOOTFS_PACKAGE, BOOTFS_TEST_ARGUMENTS, DW1C_INIT0_TEST_ARGUMENTS,
        IsolatedUefiBuild, LoaderLinkMode, UefiCargoProfile, blocked_toolchain_failure,
        canonical_build_directory, component_package, encoded_uefi_rustflags, explicit_test_filter,
        host_test_arguments, host_test_commands, prepare_uefi_target_roots,
        validate_regular_artifact,
    };
    use crate::error::Failure;
    use std::fs;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn component_filters_select_one_workspace_package() {
        assert_eq!(component_package("bootfs"), Some(BOOTFS_PACKAGE));
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
        assert_eq!(
            host_test_arguments(Some("bootfs")).unwrap(),
            BOOTFS_TEST_ARGUMENTS
        );
        assert_eq!(
            host_test_arguments(Some("test:traversal")).unwrap(),
            [
                "test",
                "--locked",
                "--workspace",
                "--all-targets",
                "--",
                "traversal"
            ]
        );
    }

    #[test]
    fn bootfs_build_is_locked_and_package_scoped() {
        assert_eq!(
            BOOTFS_BUILD_ARGUMENTS,
            [
                "build",
                "--locked",
                "--package",
                "wyrmroot-bootfs",
                "--all-targets",
                "--features",
                "builder",
            ]
        );
    }

    #[test]
    fn unfiltered_host_tests_add_the_builder_suite_without_global_features() {
        let commands = host_test_commands(None).unwrap();
        assert_eq!(
            commands,
            [
                vec!["test", "--locked", "--workspace", "--all-targets"],
                BOOTFS_TEST_ARGUMENTS.to_vec(),
            ]
        );

        assert_eq!(
            host_test_commands(Some("bootfs")).unwrap(),
            [BOOTFS_TEST_ARGUMENTS.to_vec()]
        );
        assert_eq!(
            host_test_commands(Some("dw1c")).unwrap(),
            [DW1C_INIT0_TEST_ARGUMENTS.to_vec()]
        );
    }

    #[test]
    fn blocked_toolchain_request_has_stable_diagnostic() {
        let failure = blocked_toolchain_failure(
            "request_id = \"RUST-WYR0B-UEFI-001\"\nstatus = \"blocked-pending-coordinator-assignment\"\n",
        );
        assert_eq!(
            failure.message,
            "accepted WYR0-B rustc is unavailable: toolchain/requests/RUST-WYR0-I-B-SYSROOTS-007.toml status is 'blocked-pending-coordinator-assignment'; set WYRMROOT_RUSTC only to the accepted compiler artifact from that coordinator request"
        );
    }

    #[test]
    fn uefi_flags_remap_build_specific_paths() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "wyrmroot-xtask-remap-test-{}-{nonce}",
            std::process::id()
        ));
        let repository = root.join("checkout");
        let cargo_home = root.join("cargo-home");
        let target_directory = root.join("cargo-target");
        fs::create_dir_all(&repository).expect("create test repository");
        fs::create_dir_all(&cargo_home).expect("create test Cargo home");
        fs::create_dir_all(&target_directory).expect("create test Cargo target root");

        let production_flags = encoded_uefi_rustflags(
            &repository,
            &cargo_home,
            &target_directory,
            "/accepted/sysroot",
            "/accepted/rust-lld",
            LoaderLinkMode::Production,
        )
        .expect("encode deterministic UEFI flags");
        let production_flags: Vec<_> = production_flags
            .split('\u{1f}')
            .map(str::to_owned)
            .collect();
        assert_eq!(
            production_flags,
            vec![
                "--sysroot".to_owned(),
                "/accepted/sysroot".to_owned(),
                "-C".to_owned(),
                "linker=/accepted/rust-lld".to_owned(),
                format!(
                    "--remap-path-prefix={}=/source/wyrmroot",
                    repository.display()
                ),
                format!("--remap-path-prefix={}=/cargo-home", cargo_home.display()),
                format!(
                    "--remap-path-prefix={}=/cargo-target",
                    target_directory.display()
                ),
                "-C".to_owned(),
                "link-arg=/Brepro".to_owned(),
                "-C".to_owned(),
                "link-arg=/debug:none".to_owned(),
            ]
        );

        let debug_flags = encoded_uefi_rustflags(
            &repository,
            &cargo_home,
            &target_directory,
            "/accepted/sysroot",
            "/accepted/rust-lld",
            LoaderLinkMode::RetainedDebug,
        )
        .expect("encode retained-debug UEFI flags");
        assert!(debug_flags.contains("link-arg=/pdbaltpath:loader.pdb"));
        assert!(!debug_flags.contains("link-arg=/debug:none"));

        fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[test]
    fn scoped_uefi_targets_accept_retained_procfd_and_reach_child_process() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "wyrmroot-xtask-scoped-uefi-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create isolated test directory");
        let parent =
            crate::secure_fs::Directory::open_exact(&root, "test root").expect("open test root");
        let scratch = parent
            .create_scratch("scratch", "test scratch")
            .expect("create test scratch");
        let result = scratch.with_inheritable_anchor("test scratch", |authority| {
            let production = authority.path().join("uefi-production");
            let retained = authority.path().join("uefi-retained");
            assert!(
                canonical_build_directory(&production, "ordinary target").is_err(),
                "general canonical validator unexpectedly admitted procfd target"
            );
            let build = IsolatedUefiBuild {
                cargo_home: &root,
                production_target: &production,
                retained_debug_target: &retained,
                cargo_profile: UefiCargoProfile::Release,
            };
            let targets = prepare_uefi_target_roots(&build, Some(authority))?;
            let production = &targets.production;
            let retained = &targets.retained_debug;
            let status = Command::new("sh")
                .args([
                    "-c",
                    "printf production > \"$1/child\" && printf retained > \"$2/child\"",
                    "sh",
                ])
                .arg(production)
                .arg(retained)
                .status()
                .map_err(|error| Failure::task(format!("could not spawn target test: {error}")))?;
            if !status.success() {
                return Err(Failure::task("scoped target test child failed"));
            }
            if fs::read(production.join("child")).ok().as_deref() != Some(b"production")
                || fs::read(retained.join("child")).ok().as_deref() != Some(b"retained")
            {
                return Err(Failure::task("scoped target child output drifted"));
            }
            Ok(())
        });
        scratch.finish(result).expect("retire test scratch");
        fs::remove_dir_all(root).expect("remove isolated test directory");
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
