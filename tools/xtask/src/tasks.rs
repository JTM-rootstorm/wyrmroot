use std::collections::{BTreeMap, BTreeSet};
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
use crate::secure_fs::{Directory, SealedFile};
use crate::sha256::{bytes_digest, file_digest};
use crate::toolchain_artifact::AcceptedToolchain;

const UEFI_TARGET_DIRECTORY: &str = "target/wyr0-b";
const UEFI_DEBUG_TARGET_DIRECTORY: &str = "target/wyr0-b-symbols";
const TOOLCHAIN_REQUEST: &str = "toolchain/requests/RUST-WYR0-I-B-SYSROOTS-007.toml";
const MAX_LOADER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DEBUG_SYMBOL_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const INSPECTION_PATH: &str = "/usr/lib/llvm/22/bin:/usr/bin:/bin";
pub(crate) const INSPECTION_SHELL: &str = "/bin/sh";
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
const DW1D6_BOOTSTRAP_TEST_ARGUMENTS: &[&str] = &[
    "test",
    "--locked",
    "--package",
    "wyrmroot-bootstrap",
    "--features",
    "dw1d6-synthetic",
    "--lib",
];
const DW1D6_SOURCE_CONTRACT_TEST_ARGUMENTS: &[&str] = &[
    "test",
    "--locked",
    "--package",
    "wyrmroot-bootstrap",
    "--test",
    "source_contract",
];
const DW1D6_ACTOR_TEST_ARGUMENTS: &[&str] = &[
    "test",
    "--locked",
    "--package",
    "wyrmroot-dw1d6-device-test",
    "--tests",
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
    target_directory: UefiTargetDirectory<'a>,
    cargo_profile: UefiCargoProfile,
    link_mode: LoaderLinkMode,
    operation: UefiCargoOperation,
}

pub(crate) struct DeterministicUefiArtifacts {
    pub(crate) loader: PathBuf,
    pub(crate) loader_bytes: Vec<u8>,
    pub(crate) debug_loader: PathBuf,
    pub(crate) debug_symbols: PathBuf,
    pub(crate) effective_config: String,
    pub(crate) effective_config_sha256: String,
    pub(crate) inspection_report: String,
    pub(crate) inspection_report_sha256: String,
    _target_authority: Option<UefiTargetAuthority>,
}

struct UefiTargetAuthority {
    production: crate::secure_fs::InheritableDirectory,
    retained_debug: crate::secure_fs::InheritableDirectory,
}

struct PreparedUefiTargetRoots {
    production: PathBuf,
    retained_debug: PathBuf,
    authority: Option<UefiTargetAuthority>,
}

#[derive(Clone, Copy)]
enum UefiTargetDirectory<'a> {
    Canonical(&'a Path),
    Retained(&'a crate::secure_fs::InheritableDirectory),
}

impl UefiTargetDirectory<'_> {
    fn verified_path(self, label: &str) -> Result<PathBuf, Failure> {
        match self {
            Self::Canonical(path) => canonical_build_directory(path, label),
            Self::Retained(directory) => {
                directory.verify_unchanged(label)?;
                Ok(directory.path().to_path_buf())
            }
        }
    }
}

impl PreparedUefiTargetRoots {
    fn production_target(&self) -> UefiTargetDirectory<'_> {
        self.authority.as_ref().map_or(
            UefiTargetDirectory::Canonical(&self.production),
            |authority| UefiTargetDirectory::Retained(&authority.production),
        )
    }

    fn retained_debug_target(&self) -> UefiTargetDirectory<'_> {
        self.authority.as_ref().map_or(
            UefiTargetDirectory::Canonical(&self.retained_debug),
            |authority| UefiTargetDirectory::Retained(&authority.retained_debug),
        )
    }

    fn read_production(
        &self,
        relative: &Path,
        maximum: u64,
        label: &str,
    ) -> Result<Vec<u8>, Failure> {
        match &self.authority {
            Some(authority) => authority.production.read_producer(relative, maximum, label),
            None => Directory::open_exact(&self.production, "production UEFI target root")?
                .read_producer(relative, maximum, label),
        }
    }

    fn read_retained_debug(
        &self,
        relative: &Path,
        maximum: u64,
        label: &str,
    ) -> Result<Vec<u8>, Failure> {
        match &self.authority {
            Some(authority) => authority
                .retained_debug
                .read_producer(relative, maximum, label),
            None => Directory::open_exact(&self.retained_debug, "retained-debug UEFI target root")?
                .read_producer(relative, maximum, label),
        }
    }

    fn with_inheritance_disabled<T>(
        &self,
        operation: impl FnOnce() -> Result<T, Failure>,
    ) -> Result<T, Failure> {
        match &self.authority {
            Some(authority) => authority.production.with_inheritance_disabled(
                "production UEFI target root",
                || {
                    authority
                        .retained_debug
                        .with_inheritance_disabled("retained-debug UEFI target root", operation)
                },
            ),
            None => operation(),
        }
    }
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
    let project = canonical_project_root(repository)?;
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
    let project = canonical_project_root(repository)?;
    let path = project.join(relative);
    let cargo_home = canonical_build_directory(&path, "project Cargo home")?;
    if !cargo_home.starts_with(project.join(".tmp")) {
        return Err(Failure::task(
            "toolchain Cargo home must remain beneath OS-Project/.tmp",
        ));
    }
    Ok(cargo_home)
}

pub(crate) fn canonical_project_root(repository: &Path) -> Result<PathBuf, Failure> {
    let repository = fs::canonicalize(repository).map_err(|error| {
        Failure::task(format!(
            "could not resolve Wyrmroot repository root: {error}"
        ))
    })?;
    let parent = repository
        .parent()
        .ok_or_else(|| Failure::task("Wyrmroot repository has no parent"))?;
    let managed_lane = parent.file_name() == Some(OsStr::new("wyrmroot"))
        && parent.parent().and_then(Path::file_name) == Some(OsStr::new(".worktrees"));
    if !managed_lane {
        return canonical_build_directory(parent, "OS-Project root");
    }

    let project = repository
        .ancestors()
        .nth(3)
        .ok_or_else(|| Failure::task("managed Wyrmroot lane has no OS-Project root"))?;
    let project = canonical_build_directory(project, "OS-Project root")?;
    let canonical_git = project.join("wyrmroot/.git");
    let metadata = fs::symlink_metadata(&canonical_git).map_err(|error| {
        Failure::task(format!(
            "managed Wyrmroot lane has no canonical Git directory: {error}"
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Failure::task(
            "managed Wyrmroot lane canonical Git path is not a regular directory",
        ));
    }
    let output = Command::new("git")
        .args([
            "-C",
            repository
                .to_str()
                .ok_or_else(|| Failure::task("Wyrmroot lane path is not UTF-8"))?,
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
        ])
        .output()
        .map_err(|error| Failure::task(format!("could not inspect lane Git identity: {error}")))?;
    if !output.status.success() {
        return Err(Failure::task(
            "managed Wyrmroot lane does not expose a common Git directory",
        ));
    }
    let common = String::from_utf8(output.stdout)
        .map_err(|_| Failure::task("managed Wyrmroot common Git path is not UTF-8"))?;
    let common = fs::canonicalize(common.trim()).map_err(|error| {
        Failure::task(format!(
            "could not resolve managed lane Git identity: {error}"
        ))
    })?;
    if common != canonical_git {
        return Err(Failure::task(
            "managed Wyrmroot lane is not registered to canonical Wyrmroot",
        ));
    }
    Ok(project)
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
    let output = Command::new(INSPECTION_SHELL)
        .arg(script)
        .args(arguments)
        .env_clear()
        .env("PATH", INSPECTION_PATH)
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
            target_directory: target_roots.production_target(),
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
            target_directory: target_roots.retained_debug_target(),
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
            target_directory: target_roots.production_target(),
            cargo_profile: build.cargo_profile,
            link_mode: LoaderLinkMode::Production,
            operation: UefiCargoOperation::Build,
        },
    )?;

    let loader_relative = PathBuf::from(&profile.rust_target)
        .join(build.cargo_profile.directory())
        .join(&profile.artifact_name);
    let debug_output_relative =
        PathBuf::from(&profile.rust_target).join(build.cargo_profile.directory());
    let debug_loader_relative = debug_output_relative.join(&profile.artifact_name);
    let debug_symbols_relative =
        debug_output_relative.join(format!("{}.pdb", profile.cargo_binary));
    let loader_bytes = target_roots.read_production(
        &loader_relative,
        MAX_LOADER_BYTES,
        "UEFI loader producer output",
    )?;
    let debug_loader_bytes = target_roots.read_retained_debug(
        &debug_loader_relative,
        MAX_LOADER_BYTES,
        "retained debug UEFI loader producer output",
    )?;
    let debug_symbols_bytes = target_roots.read_retained_debug(
        &debug_symbols_relative,
        MAX_DEBUG_SYMBOL_BYTES,
        "UEFI debug symbols producer output",
    )?;
    let inspect = || {
        target_roots.with_inheritance_disabled(|| {
            inspect_uefi_snapshots(
                repository,
                &profile.artifact_inspection,
                &loader_bytes,
                &debug_loader_bytes,
                &debug_symbols_bytes,
            )
        })
    };
    let inspection_report = match scratch {
        Some(scratch) => scratch.with_inheritance_disabled("UEFI build scratch root", inspect)?,
        None => inspect()?,
    };
    let loader = production_target.join(&loader_relative);
    let debug_loader = retained_debug_target.join(&debug_loader_relative);
    let debug_symbols = retained_debug_target.join(&debug_symbols_relative);
    let effective_config = normalized_uefi_config(profile, build.cargo_profile);
    Ok(DeterministicUefiArtifacts {
        loader,
        loader_bytes,
        debug_loader,
        debug_symbols,
        effective_config_sha256: bytes_digest(effective_config.as_bytes()),
        effective_config,
        inspection_report_sha256: bytes_digest(inspection_report.as_bytes()),
        inspection_report,
        _target_authority: target_roots.authority,
    })
}

fn inspect_uefi_snapshots(
    repository: &Path,
    script: &str,
    loader: &[u8],
    debug_loader: &[u8],
    debug_symbols: &[u8],
) -> Result<String, Failure> {
    let sealed_loader = SealedFile::from_bytes(loader, "UEFI loader inspection input")?;
    let sealed_debug_loader =
        SealedFile::from_bytes(debug_loader, "debug UEFI loader inspection input")?;
    let sealed_debug_symbols =
        SealedFile::from_bytes(debug_symbols, "UEFI debug-symbol inspection input")?;
    let report =
        sealed_loader.with_inheritable_path("UEFI loader inspection input", |loader_path| {
            sealed_debug_loader.with_inheritable_path(
                "debug UEFI loader inspection input",
                |debug_loader_path| {
                    sealed_debug_symbols.with_inheritable_path(
                        "UEFI debug-symbol inspection input",
                        |debug_symbols_path| {
                            run_verified_report(
                                repository,
                                script,
                                [
                                    loader_path.as_os_str(),
                                    debug_loader_path.as_os_str(),
                                    debug_symbols_path.as_os_str(),
                                ],
                                "UEFI artifact inspection",
                            )
                        },
                    )
                },
            )
        })?;
    let expected = render_uefi_inspection_report(loader, debug_loader, debug_symbols);
    if report != expected {
        return Err(Failure::task(
            "UEFI artifact inspection did not canonically bind the sealed inputs",
        ));
    }
    Ok(report)
}

fn render_uefi_inspection_report(
    loader: &[u8],
    debug_loader: &[u8],
    debug_symbols: &[u8],
) -> String {
    render_uefi_inspection_values(
        &bytes_digest(loader),
        loader.len(),
        &bytes_digest(debug_loader),
        debug_loader.len(),
        &bytes_digest(debug_symbols),
        debug_symbols.len(),
    )
}

fn render_uefi_inspection_values(
    loader_sha256: &str,
    loader_size: usize,
    debug_loader_sha256: &str,
    debug_loader_size: usize,
    debug_symbol_sha256: &str,
    debug_symbol_size: usize,
) -> String {
    format!(
        concat!(
            "{{\n",
            "  \"schema_version\": 2,\n",
            "  \"report_kind\": \"wyrmroot-wyr0-uefi-artifact-inspection\",\n",
            "  \"loader\": \"loader.efi\",\n",
            "  \"debug_loader\": \"loader.efi\",\n",
            "  \"debug_symbol_artifact\": \"loader.pdb\",\n",
            "  \"loader_sha256\": \"{}\",\n",
            "  \"loader_size\": {},\n",
            "  \"debug_loader_sha256\": \"{}\",\n",
            "  \"debug_loader_size\": {},\n",
            "  \"debug_symbol_sha256\": \"{}\",\n",
            "  \"debug_symbol_size\": {},\n",
            "  \"pe32_plus\": true,\n",
            "  \"amd64\": true,\n",
            "  \"efi_application\": true,\n",
            "  \"no_pe_imports\": true,\n",
            "  \"production_reproducible\": true,\n",
            "  \"production_codeview_absent\": true,\n",
            "  \"debug_pair_linked\": true,\n",
            "  \"pdb_has_symbols\": true,\n",
            "  \"verified\": true\n",
            "}}\n"
        ),
        loader_sha256,
        loader_size,
        debug_loader_sha256,
        debug_loader_size,
        debug_symbol_sha256,
        debug_symbol_size,
    )
}

pub(crate) fn validate_uefi_inspection_report(report: &[u8], loader: &[u8]) -> Result<(), Failure> {
    let report = std::str::from_utf8(report)
        .map_err(|_| Failure::task("UEFI inspection report is not UTF-8"))?;
    if report.contains('\r') || !report.ends_with('\n') {
        return Err(Failure::task(
            "UEFI inspection report is not canonical text",
        ));
    }
    let lines = report.lines().collect::<Vec<_>>();
    if lines.first() != Some(&"{") || lines.last() != Some(&"}") || lines.len() < 3 {
        return Err(Failure::task("UEFI inspection report framing is malformed"));
    }
    let field_lines = &lines[1..lines.len() - 1];
    let mut fields = BTreeMap::new();
    for (index, line) in field_lines.iter().enumerate() {
        let comma = index + 1 != field_lines.len();
        let line = if comma {
            line.strip_suffix(',')
                .ok_or_else(|| Failure::task("UEFI inspection report comma drifted"))?
        } else if line.ends_with(',') {
            return Err(Failure::task("UEFI inspection report has a trailing comma"));
        } else {
            line
        };
        let line = line
            .strip_prefix("  \"")
            .ok_or_else(|| Failure::task("UEFI inspection report indentation drifted"))?;
        let (key, value) = line
            .split_once("\": ")
            .ok_or_else(|| Failure::task("UEFI inspection report field is malformed"))?;
        if key.is_empty() || fields.insert(key, value).is_some() {
            return Err(Failure::task(
                "UEFI inspection report key is empty or duplicate",
            ));
        }
    }
    let expected_keys = [
        "schema_version",
        "report_kind",
        "loader",
        "debug_loader",
        "debug_symbol_artifact",
        "loader_sha256",
        "loader_size",
        "debug_loader_sha256",
        "debug_loader_size",
        "debug_symbol_sha256",
        "debug_symbol_size",
        "pe32_plus",
        "amd64",
        "efi_application",
        "no_pe_imports",
        "production_reproducible",
        "production_codeview_absent",
        "debug_pair_linked",
        "pdb_has_symbols",
        "verified",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if fields.keys().copied().collect::<BTreeSet<_>>() != expected_keys {
        return Err(Failure::task("UEFI inspection report key set drifted"));
    }
    for (key, expected) in [
        ("schema_version", "2"),
        ("report_kind", "\"wyrmroot-wyr0-uefi-artifact-inspection\""),
        ("loader", "\"loader.efi\""),
        ("debug_loader", "\"loader.efi\""),
        ("debug_symbol_artifact", "\"loader.pdb\""),
        ("pe32_plus", "true"),
        ("amd64", "true"),
        ("efi_application", "true"),
        ("no_pe_imports", "true"),
        ("production_reproducible", "true"),
        ("production_codeview_absent", "true"),
        ("debug_pair_linked", "true"),
        ("pdb_has_symbols", "true"),
        ("verified", "true"),
    ] {
        if fields.get(key).copied() != Some(expected) {
            return Err(Failure::task(format!(
                "UEFI inspection report {key} drifted"
            )));
        }
    }
    let digest = |key: &str| -> Result<&str, Failure> {
        let quoted = fields
            .get(key)
            .copied()
            .ok_or_else(|| Failure::task("UEFI inspection digest is missing"))?;
        let value = quoted
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .ok_or_else(|| Failure::task("UEFI inspection digest is not quoted"))?;
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Failure::task("UEFI inspection digest is malformed"));
        }
        Ok(value)
    };
    let size = |key: &str, maximum: usize| -> Result<usize, Failure> {
        let raw = fields
            .get(key)
            .copied()
            .ok_or_else(|| Failure::task("UEFI inspection size is missing"))?;
        let value = raw
            .parse::<usize>()
            .map_err(|_| Failure::task("UEFI inspection size is malformed"))?;
        if value == 0 || value > maximum || value.to_string() != raw {
            return Err(Failure::task("UEFI inspection size is outside its bound"));
        }
        Ok(value)
    };
    let loader_hash = digest("loader_sha256")?;
    let debug_loader_hash = digest("debug_loader_sha256")?;
    let debug_symbol_hash = digest("debug_symbol_sha256")?;
    let loader_size = size("loader_size", MAX_LOADER_BYTES as usize)?;
    let debug_loader_size = size("debug_loader_size", MAX_LOADER_BYTES as usize)?;
    let debug_symbol_size = size("debug_symbol_size", MAX_DEBUG_SYMBOL_BYTES as usize)?;
    if loader_hash != bytes_digest(loader) || loader_size != loader.len() {
        return Err(Failure::task(
            "UEFI inspection report does not bind the published loader bytes",
        ));
    }
    if report
        != render_uefi_inspection_values(
            loader_hash,
            loader_size,
            debug_loader_hash,
            debug_loader_size,
            debug_symbol_hash,
            debug_symbol_size,
        )
    {
        return Err(Failure::task("UEFI inspection report is not canonical"));
    }
    Ok(())
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
                production,
                retained_debug,
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
    let target_directory = invocation
        .target_directory
        .verified_path("Cargo target root")?;
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
        .arg(&target_directory)
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
        .status();
    invocation
        .target_directory
        .verified_path("Cargo target root")?;
    let status = status
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
    target_directory: UefiTargetDirectory<'_>,
    sysroot: &str,
    rust_lld: &str,
    link_mode: LoaderLinkMode,
) -> Result<String, Failure> {
    encoded_uefi_rustflags_for_target(
        repository,
        cargo_home,
        target_directory,
        sysroot,
        rust_lld,
        link_mode,
    )
}

#[cfg(test)]
fn encoded_uefi_rustflags(
    repository: &Path,
    cargo_home: &Path,
    target_directory: &Path,
    sysroot: &str,
    rust_lld: &str,
    link_mode: LoaderLinkMode,
) -> Result<String, Failure> {
    encoded_uefi_rustflags_for_target(
        repository,
        cargo_home,
        UefiTargetDirectory::Canonical(target_directory),
        sysroot,
        rust_lld,
        link_mode,
    )
}

fn encoded_uefi_rustflags_for_target(
    repository: &Path,
    cargo_home: &Path,
    target_directory: UefiTargetDirectory<'_>,
    sysroot: &str,
    rust_lld: &str,
    link_mode: LoaderLinkMode,
) -> Result<String, Failure> {
    let repository = canonical_build_directory(repository, "Wyrmroot repository")?;
    let cargo_home = canonical_build_directory(cargo_home, "Cargo home")?;
    let target_directory = target_directory.verified_path("Cargo target root")?;
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

#[cfg(test)]
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

/// A guest-target compile gate, run with the accepted native compiler.
///
/// Each is minutes of work in a fresh scratch target, which is why none of them
/// runs in the unfiltered host suite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeGate {
    C4,
    C5,
    C6,
    /// `wyr1e3-native` and its three sub-selections, which pass their name on.
    Wyr1e3,
    /// `wyr1e4-native` and `wyr1e5-native`, which pass their name on.
    Wyrmsh,
    Wyr1e6,
    Wyr1e7,
    Wyr1e8,
    Wyr1e8Actors,
    Wyr1f,
    E3b,
}

impl NativeGate {
    fn run(self, repository: &Path, filter: &str) -> Result<(), Failure> {
        match self {
            // WYR1-C4 is a guest-target compilation gate. The pinned host
            // compiler intentionally does not know the x86_64-unknown-wyrmroot
            // built-in target, so this must use the accepted immutable product
            // compiler.
            Self::C4 => crate::wyr1c::run_c4_native_checks(repository),
            Self::C5 => crate::wyr1c::run_c5_native_checks(repository),
            Self::C6 => crate::wyr1c::run_c6_native_checks(repository),
            Self::Wyr1e3 => crate::wyr1c::run_wyr1e3_native_checks(repository, filter),
            Self::Wyrmsh => crate::wyr1c::run_wyrmsh_native_checks(repository, filter),
            Self::Wyr1e6 => crate::wyr1c::run_wyr1e6_native_checks(repository),
            Self::Wyr1e7 => crate::wyr1c::run_wyr1e7_native_checks(repository),
            Self::Wyr1e8 => crate::wyr1c::run_wyr1e8_native_checks(repository),
            Self::Wyr1e8Actors => crate::wyr1c::run_wyr1e8_actor_native_checks(repository),
            Self::Wyr1f => crate::wyr1c::run_wyr1f_native_checks(repository),
            Self::E3b => crate::wyr1c::run_e3b_native_checks(repository),
        }
    }
}

/// What a named host filter runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Route {
    /// Host Cargo commands, from [`named_host_runs`]. Every one of these also
    /// runs in the unfiltered suite.
    Host,
    /// A guest-target compile gate. Every one of these runs in `native`, or is
    /// covered there by the gate [`NATIVE_COVERED_BY`] names.
    Native(NativeGate),
    /// `native`: every native gate.
    AllNative,
    /// `full`: the unfiltered suite, then every native gate.
    Full,
    /// The warn-level lint ratchet, which also runs in the unfiltered suite.
    LintRatchet,
}

/// Every named `xtask test host` filter, and what it runs.
///
/// Structural refactor S1.1. The dispatcher used to be a chain of `matches!`
/// arms spread over two functions, so the only list of gate names was the code
/// itself; a name was reachable exactly when someone typed it. This is now the
/// one place a named gate exists: `run_host_tests` looks every filter up here
/// first, and anything not listed is a component, `package:` or `test:` filter
/// over the workspace suite.
const NAMED_HOST_FILTERS: &[(&str, Route)] = &[
    ("native", Route::AllNative),
    ("full", Route::Full),
    ("lint-ratchet", Route::LintRatchet),
    ("selectors", Route::Host),
    ("wyr1e8-producer-fixture", Route::Host),
    ("wyr1d5-clippy", Route::Host),
    ("r1-clippy", Route::Host),
    ("r1-status", Route::Host),
    ("wyr1e3-model", Route::Host),
    ("wyr1e3-clippy", Route::Host),
    ("wyr1e3-controller-model", Route::Host),
    ("wyr1e3-controller-clippy", Route::Host),
    ("wyr1e4-model", Route::Host),
    ("wyr1e4-clippy", Route::Host),
    ("wyr1e5-model", Route::Host),
    ("wyr1e5-clippy", Route::Host),
    ("wyr1e6-model", Route::Host),
    ("wyr1e6-clippy", Route::Host),
    ("wyr1e6-controller-model", Route::Host),
    ("wyr1e6-controller-clippy", Route::Host),
    ("wyr1e7-model", Route::Host),
    ("wyr1e7-clippy", Route::Host),
    ("wyr1e8-model", Route::Host),
    ("wyr1e8-clippy", Route::Host),
    ("wyr1e8-product-model", Route::Host),
    ("wyr1e8-product-clippy", Route::Host),
    ("wyr1f-model", Route::Host),
    ("wyr1f-clippy", Route::Host),
    ("wyr1f-role-clippy", Route::Host),
    ("wyr1c6-model", Route::Host),
    ("wyr1c6-clippy", Route::Host),
    ("dw1c", Route::Host),
    ("dw1c-init0", Route::Host),
    ("dw1d6", Route::Host),
    ("dw1d6-synthetic", Route::Host),
    ("wyr1c4", Route::Native(NativeGate::C4)),
    ("wyr1c4-native", Route::Native(NativeGate::C4)),
    ("wyr1c5", Route::Native(NativeGate::C5)),
    ("wyr1c5-native", Route::Native(NativeGate::C5)),
    ("wyr1c6", Route::Native(NativeGate::C6)),
    ("wyr1c6-native", Route::Native(NativeGate::C6)),
    ("wyr1e3-native", Route::Native(NativeGate::Wyr1e3)),
    ("wyr1e3-consoled-native", Route::Native(NativeGate::Wyr1e3)),
    ("wyr1e3-registry-native", Route::Native(NativeGate::Wyr1e3)),
    (
        "wyr1e3-controller-native",
        Route::Native(NativeGate::Wyr1e3),
    ),
    ("wyr1e4-native", Route::Native(NativeGate::Wyrmsh)),
    ("wyr1e5-native", Route::Native(NativeGate::Wyrmsh)),
    ("wyr1e6-native", Route::Native(NativeGate::Wyr1e6)),
    ("wyr1e7-native", Route::Native(NativeGate::Wyr1e7)),
    ("wyr1e8-native", Route::Native(NativeGate::Wyr1e8)),
    (
        "wyr1e8-actors-native",
        Route::Native(NativeGate::Wyr1e8Actors),
    ),
    ("wyr1f-native", Route::Native(NativeGate::Wyr1f)),
    ("dw1e3b-native", Route::Native(NativeGate::E3b)),
];

/// Native filters `native` does not run itself, each with the one that covers it.
///
/// The `wyr1cN` names are aliases of their `-native` gate. The narrower E3
/// filters check subsets of `wyr1e3-native`'s specs
/// (`every_narrower_wyr1e3_native_selection_is_within_the_full_one`), and
/// `wyr1e5-native` checks the same `WYRMSH_NATIVE_CHECK_SPECS` as
/// `wyr1e4-native` under another label. Each native gate is minutes of work in
/// a fresh scratch target, so running a covered one again buys nothing.
///
/// `wyr1e8-actors-native` is not listed: its two specs are in `wyr1e8-native`
/// too, but that gate compiles them with the E8 evidence nonce set and this one
/// without, which is a different build.
const NATIVE_COVERED_BY: &[(&str, &str)] = &[
    ("wyr1c4", "wyr1c4-native"),
    ("wyr1c5", "wyr1c5-native"),
    ("wyr1c6", "wyr1c6-native"),
    ("wyr1e3-consoled-native", "wyr1e3-native"),
    ("wyr1e3-registry-native", "wyr1e3-native"),
    ("wyr1e3-controller-native", "wyr1e3-native"),
    ("wyr1e5-native", "wyr1e4-native"),
];

fn named_host_filter(filter: &str) -> Option<Route> {
    NAMED_HOST_FILTERS
        .iter()
        .find(|(name, _)| *name == filter)
        .map(|(_, route)| *route)
}

/// One Cargo invocation of a host gate.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CargoRun {
    arguments: Vec<String>,
    /// Whether the child needs [`SELECTOR_PLACEHOLDER_NONCE`] to compile.
    selector_nonce: bool,
}

impl CargoRun {
    fn plain(arguments: Vec<String>) -> Self {
        Self {
            arguments,
            selector_nonce: false,
        }
    }

    fn execute(&self, repository: &Path) -> Result<(), Failure> {
        let arguments = self
            .arguments
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        if self.selector_nonce {
            run_selector_cargo(repository, &arguments)
        } else {
            run_cargo(repository, &arguments)
        }
    }
}

/// The Cargo commands a named [`Route::Host`] filter runs, in order.
fn named_host_runs(filter: &str) -> Result<Vec<CargoRun>, Failure> {
    Ok(match filter {
        "selectors" => selector_library_commands()
            .into_iter()
            .map(|arguments| CargoRun {
                arguments,
                selector_nonce: true,
            })
            .collect(),
        "wyr1e8-producer-fixture" => vec![CargoRun::plain(wyr1e8_producer_fixture_command())],
        // Reset card E8D.4-32. Selector 32's `system-init` was compiled only by
        // the d5 product path, never by a host gate, so R7B-1 could replace its
        // episode deadline with a `super::wyr1e::` call -- a module gated on a
        // feature selector 32 does not select -- and leave the selector
        // unbuildable for a week without any gate noticing. Building the two
        // selector-32 libraries here is what makes that class of break loud.
        "wyr1d5-clippy" => selector32_library_commands()
            .into_iter()
            .map(CargoRun::plain)
            .collect(),
        // The ordinary clippy gates lint the default feature set, under which
        // r1_driver does not exist at all: it is compiled only by r1-status,
        // which runs rustc and not clippy. Without this entry the driver is the
        // largest unlinted module in the crate.
        "r1-clippy" => vec![CargoRun::plain(r1_clippy_command())],
        // Selector 34's failure statuses and its scenario driver only exist
        // under its own feature, and the launcher rightly refuses
        // caller-selected features, so the gate has to be named here. It runs
        // the whole library suite under that feature rather than one test
        // module: the driver's own tests are gated the same way, and naming
        // them individually is how a later one would be added and never run.
        "r1-status" => vec![CargoRun::plain(r1_status_command())],
        _ => host_test_commands(Some(filter))?
            .into_iter()
            .map(CargoRun::plain)
            .collect(),
    })
}

pub(crate) fn run_host_tests(repository: &Path, filter: Option<&str>) -> Result<(), Failure> {
    match filter.map(|name| (name, named_host_filter(name))) {
        Some((name, Some(Route::Native(gate)))) => gate.run(repository, name),
        Some((name, Some(Route::Host))) => {
            for run in named_host_runs(name)? {
                run.execute(repository)?;
            }
            Ok(())
        }
        Some((_, Some(Route::AllNative))) => run_every_step(repository, native_steps()),
        Some((_, Some(Route::LintRatchet))) => Step::LintRatchet.execute(repository),
        Some((_, Some(Route::Full))) => {
            let mut steps = default_steps()?;
            steps.extend(native_steps());
            run_every_step(repository, steps)
        }
        Some((_, None)) => {
            for arguments in host_test_commands(filter)? {
                CargoRun::plain(arguments).execute(repository)?;
            }
            Ok(())
        }
        None => run_every_step(repository, default_steps()?),
    }
}

/// One step of an aggregate host run.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Step {
    Cargo(CargoRun),
    Native(&'static str, NativeGate),
    LintRatchet,
}

impl Step {
    fn describe(&self) -> String {
        match self {
            Self::Cargo(run) => format!("cargo {}", run.arguments.join(" ")),
            Self::Native(name, _) => format!("native gate {name}"),
            Self::LintRatchet => format!(
                "lint ratchet against {}",
                crate::lint_ratchet::BASELINE_PATH
            ),
        }
    }

    fn execute(&self, repository: &Path) -> Result<(), Failure> {
        match self {
            Self::Cargo(run) => run.execute(repository),
            Self::Native(name, gate) => gate.run(repository, name),
            Self::LintRatchet => crate::lint_ratchet::run(repository, &lint_ratchet_shapes()?),
        }
    }
}

/// The unfiltered suite, derived from the two tables above.
///
/// Structural refactor S1.1. It used to be the workspace tests plus the
/// selector library checks; every clippy and feature-specific test gate was a
/// named filter that ran only when typed, and S0 found three of them red with
/// nobody the wiser. Now it is:
/// - a library check of every row of [`FEATURE_COMBINATIONS`] (`selectors`);
/// - the workspace suite and the bootfs builder suite, as before;
/// - every [`Route::Host`] filter's own commands, each distinct command once;
/// - the warn-level lint ratchet (S1.3) over every shape those gates lint.
///
/// So a gate that exists runs here, and only the native gates do not.
fn default_steps() -> Result<Vec<Step>, Failure> {
    let mut runs = named_host_runs("selectors")?;
    runs.extend(host_test_commands(None)?.into_iter().map(CargoRun::plain));
    for (name, route) in NAMED_HOST_FILTERS {
        if *route == Route::Host {
            for run in named_host_runs(name)? {
                if !runs.contains(&run) {
                    runs.push(run);
                }
            }
        }
    }
    let mut steps = runs.into_iter().map(Step::Cargo).collect::<Vec<_>>();
    steps.push(Step::LintRatchet);
    Ok(steps)
}

/// What the lint ratchet lints: the workspace in the default shape `xtask
/// clippy` lints, and every distinct clippy command a named host gate runs.
fn lint_ratchet_shapes() -> Result<Vec<Vec<String>>, Failure> {
    let mut shapes = vec![
        [
            "clippy",
            "--locked",
            "--offline",
            "--workspace",
            "--all-targets",
        ]
        .map(str::to_owned)
        .to_vec(),
    ];
    for (name, route) in NAMED_HOST_FILTERS {
        if *route == Route::Host {
            for run in named_host_runs(name)? {
                if run.arguments.first().map(String::as_str) == Some("clippy")
                    && !shapes.contains(&run.arguments)
                {
                    shapes.push(run.arguments);
                }
            }
        }
    }
    Ok(shapes)
}

/// Every native gate, each once: `xtask test host native`.
fn native_steps() -> Vec<Step> {
    NAMED_HOST_FILTERS
        .iter()
        .filter_map(|(name, route)| match route {
            Route::Native(gate)
                if !NATIVE_COVERED_BY.iter().any(|(covered, _)| covered == name) =>
            {
                Some(Step::Native(name, *gate))
            }
            _ => None,
        })
        .collect()
}

/// Runs every step even after one fails, then reports each failure.
///
/// An aggregate run exists to say everything that is wrong; stopping at the
/// first failure would hide the rest until the next run.
fn run_every_step(repository: &Path, steps: Vec<Step>) -> Result<(), Failure> {
    let total = steps.len();
    let mut failed = Vec::new();
    for (index, step) in steps.iter().enumerate() {
        let description = step.describe();
        eprintln!("xtask: [{}/{total}] {description}", index + 1);
        if let Err(failure) = step.execute(repository) {
            eprintln!("xtask: [{}/{total}] failed: {}", index + 1, failure.message);
            failed.push(format!(
                "[{}/{total}] {description}: {}",
                index + 1,
                failure.message
            ));
        }
    }
    if failed.is_empty() {
        eprintln!("xtask: all {total} host gate steps passed");
        return Ok(());
    }
    eprintln!("xtask: {} of {total} host gate steps failed:", failed.len());
    for line in &failed {
        eprintln!("xtask:   {line}");
    }
    Err(Failure::task(format!(
        "{} of {total} host gate steps failed",
        failed.len()
    )))
}

/// Every package/feature combination a product or a host gate builds, once.
///
/// Follow-up to reset card E8D.4. Two selectors broke on 2026-09-15 and neither
/// was noticed for a week, for one structural reason: a selector's libraries
/// are compiled only by the product path that mints its VM image, and every
/// feature-specific gate in this file is an opt-in named filter that an
/// unfiltered `xtask test host` never runs. R7B-1 left selector 32 calling a
/// module its feature does not enable. R7B-2 removed a `match` wildcard and
/// left selector 34 non-exhaustive. Both compiled clean under the default
/// feature set, which is all the default suite ever built -- and selector 34
/// even had two gates written for it, both red, both unrun.
///
/// Structural refactor S1.1 made this the one list. The unfiltered run checks
/// every row's library (`cargo check` answers "does not compile" cheapest), and
/// runs every named host gate besides, so the clippy and test commands those
/// gates own run too. Tests hold the list complete: every `--features` any
/// named host gate passes, and every native spec the `wyr1c`, `r1`, `wyr1b` and
/// `dw1c` product tables build, must appear here. The inline builders of the
/// older products (dw1b, dw1d6, dw1e3a, wyr1c2, wyr1c6) are listed by hand until
/// S2T gives every product one spec table.
///
/// Feature sets are spelled as their builder spells them, so a combination two
/// builders spell differently appears twice; Cargo resolves both to one build.
const FEATURE_COMBINATIONS: &[(&str, &str)] = &[
    // system-init: every selector and the product shapes.
    ("wyrmroot-system-init", "native-init"),
    ("wyrmroot-system-init", "native-init,wyr1-test-evidence"),
    ("wyrmroot-system-init", "native-init,wyr1b-test-evidence"),
    ("wyrmroot-system-init", "native-init,wyr1e-shell-controller"),
    ("wyrmroot-system-init", "wyr1-test-evidence"),
    ("wyrmroot-system-init", "wyr1b-test-evidence"),
    ("wyrmroot-system-init", "wyr1c4-production"),
    ("wyrmroot-system-init", "wyr1c5-production"),
    ("wyrmroot-system-init", "wyr1c6-production"),
    (
        "wyrmroot-system-init",
        "wyr1c6-production,wyr1c6-selector29",
    ),
    ("wyrmroot-system-init", "wyr1c6-test-evidence"),
    ("wyrmroot-system-init", "wyr1d-selector32"),
    ("wyrmroot-system-init", "wyr1e-shell-controller"),
    ("wyrmroot-system-init", "wyr1e-production"),
    ("wyrmroot-system-init", "wyr1e-production,wyr1f-closure"),
    ("wyrmroot-system-init", "wyr1e-selector33"),
    ("wyrmroot-system-init", "wyr1e8-selector33"),
    ("wyrmroot-system-init", "wyr1f-closure"),
    ("wyrmroot-system-init", "r1-selector34"),
    ("wyrmroot-system-init", "dw1e3-selector31"),
    // consoled.
    ("wyrmroot-consoled", "native-consoled,wyr1d-selector32"),
    ("wyrmroot-consoled", "native-consoled,wyr1e-wyrmsh"),
    (
        "wyrmroot-consoled",
        "native-consoled,wyr1e-wyrmsh,wyr1e8-recovery",
    ),
    ("wyrmroot-consoled", "wyr1e-wyrmsh"),
    // devmgr.
    ("wyrmroot-devmgr", "native-devmgr"),
    ("wyrmroot-devmgr", "wyr1c4-production"),
    ("wyrmroot-devmgr", "wyr1c5-production"),
    ("wyrmroot-devmgr", "wyr1c6-production,wyr1c6-selector29"),
    ("wyrmroot-devmgr", "wyr1d-production"),
    ("wyrmroot-devmgr", "wyr1d-selector32"),
    ("wyrmroot-devmgr", "wyr1e-production"),
    ("wyrmroot-devmgr", "wyr1e8-production"),
    ("wyrmroot-devmgr", "dw1e3-selector31"),
    // uart16550d.
    ("wyrmroot-uart16550d", "native-uart16550d"),
    ("wyrmroot-uart16550d", "wyr1d-selector32"),
    ("wyrmroot-uart16550d", "dw1e3-selector31"),
    // The other roles and payloads, in their product shapes.
    ("wyrmroot-registryd", "native-registryd"),
    ("wyrmroot-wyrmsh", "native-wyrmsh"),
    ("wyrmroot-console-echo", "native-console-echo"),
    ("wyrmroot-hello", "native-hello"),
    ("wyrmroot-hello", "native-job-hello"),
    ("wyrmroot-hello", "native-stream-hello"),
    ("wyrmroot-dw1b-preemption", "native-job-cpu-hog"),
    ("wyrmroot-dw1b-preemption", "native-payloads"),
    ("wyrmroot-dw1c-preemption", "native-payloads"),
    ("wyrmroot-dw1d6-device-test", "native-payloads"),
    ("wyrmroot-dw1e3-com2-test", "native-probe"),
    ("wyrmroot-r1-saturation", "native-payloads"),
    ("wyrmroot-wyr1b-gate", "native-gate"),
    ("wyrmroot-wyr1-bootstrap-stubs", "native-stubs"),
    ("wyrmroot-wyr1-retained-stubs", "native-retained"),
    ("wyrmroot-wyr1-retained-stubs", "wyr1c5-production"),
    (
        "wyrmroot-wyr1-retained-stubs",
        "wyr1c6-production,wyr1c6-selector29",
    ),
    ("wyrmroot-wyr1e-test-actors", "native-exit-nonzero"),
    ("wyrmroot-wyr1e-test-actors", "native-fault"),
    ("wyrmroot-wyr1e-test-actors", "native-recovery-trigger"),
    ("wyrmroot-wyr1e-test-actors", "native-stdout-pressure"),
    // init0 and the bootstrap, for the DW1 and WYR1 products.
    ("wyrmroot-init0", "dw1c-preemption-integration"),
    ("wyrmroot-init0", "native-init0,dw1b-preemption-integration"),
    ("wyrmroot-init0", "native-init0,dw1c-preemption-integration"),
    ("wyrmroot-bootstrap", "dw1d6-synthetic"),
    ("wyrmroot-bootstrap", "native-bootstrap"),
    (
        "wyrmroot-bootstrap",
        "native-bootstrap,wyr0-init0-integration",
    ),
    (
        "wyrmroot-bootstrap",
        "native-bootstrap,wyr0-init0-integration,dw1c-bootstrap-supervision",
    ),
    ("wyrmroot-bootstrap", "native-bootstrap,dw1d6-synthetic"),
    ("wyrmroot-bootstrap", "wyr1c4-production"),
    ("wyrmroot-bootstrap", "wyr1c5-production"),
    ("wyrmroot-bootstrap", "wyr1c6-production"),
    // Host-only builder shapes.
    ("wyrmroot-bootfs", "builder"),
    ("wyrmroot-rrc-manifest", "builder"),
];

/// Packages with no library target: only the native gates can compile them.
const BINARY_ONLY_PACKAGES: &[&str] = &["wyrmroot-wyr1-retained-stubs"];

/// Whether `FEATURE_COMBINATIONS` lists this package in this feature shape.
#[cfg(test)]
pub(crate) fn is_listed_combination(package: &str, features: &str) -> bool {
    FEATURE_COMBINATIONS
        .iter()
        .any(|(listed, shape)| *listed == package && *shape == features)
}

/// A placeholder for the evidence nonce selector 31's runtime stamps in at
/// compile time.
///
/// `wyrmroot-runtime`'s `dw1e3` module reads `DEEPWYRM_DW1E_EVIDENCE_NONCE`
/// through `env!`, so the selector does not compile without one and was
/// therefore reachable only from the product path that supplies the real
/// value. This gate compiles the library and never runs it, so any parseable
/// nonce answers the only question being asked -- does the code still build --
/// and no artifact is produced that could carry this value anywhere.
const SELECTOR_PLACEHOLDER_NONCE: &str = "0000000000000001";

fn selector_library_commands() -> Vec<Vec<String>> {
    FEATURE_COMBINATIONS
        .iter()
        .filter(|(package, _)| !BINARY_ONLY_PACKAGES.contains(package))
        .map(|&(package, features)| {
            [
                "check",
                "--locked",
                "--offline",
                "--package",
                package,
                "--no-default-features",
                "--features",
                features,
                "--lib",
            ]
            .map(str::to_owned)
            .into()
        })
        .collect()
}

/// The two libraries the selector-32 product builds and no other host gate does.
fn selector32_library_commands() -> Vec<Vec<String>> {
    [
        ("wyrmroot-system-init", "wyr1d-selector32"),
        ("wyrmroot-consoled", "native-consoled,wyr1d-selector32"),
    ]
    .into_iter()
    .map(|(package, features)| {
        [
            "clippy",
            "--locked",
            "--offline",
            "--package",
            package,
            "--no-default-features",
            "--features",
            features,
            "--lib",
            "--",
            "-D",
            "warnings",
        ]
        .map(str::to_owned)
        .into()
    })
    .collect()
}

fn r1_clippy_command() -> Vec<String> {
    [
        "clippy",
        "--locked",
        "--offline",
        "--package",
        "wyrmroot-system-init",
        "--features",
        "r1-selector34",
        "--lib",
        "--",
        "-D",
        "warnings",
    ]
    .map(str::to_owned)
    .into()
}

fn r1_status_command() -> Vec<String> {
    [
        "test",
        "--locked",
        "--offline",
        "--package",
        "wyrmroot-system-init",
        "--features",
        "r1-selector34",
        "--lib",
        "--",
        "--nocapture",
    ]
    .map(str::to_owned)
    .into()
}

fn wyr1e8_producer_fixture_command() -> Vec<String> {
    [
        "test",
        "--locked",
        "--offline",
        "--package",
        "wyrmroot-system-init",
        "--features",
        "wyr1e8-selector33",
        "--lib",
        "wyr1b_native::tests::e8_producer_fixture::actual_driver_and_registry_recovery_compose_through_s4_ready",
        "--",
        "--exact",
        "--nocapture",
    ]
    .map(str::to_owned)
    .into()
}

fn host_test_commands(filter: Option<&str>) -> Result<Vec<Vec<String>>, Failure> {
    if matches!(
        filter,
        Some("wyr1e8-product-model" | "wyr1e8-product-clippy")
    ) {
        let lint = filter.is_some_and(|value| value.ends_with("clippy"));
        return Ok([
            ("wyrmroot-wyr1e-test-actors", None, true),
            ("wyrmroot-bootfs", Some("builder"), true),
            ("xtask", None, false),
        ]
        .into_iter()
        .map(|(package, feature, library)| {
            let mut arguments = vec![
                if lint { "clippy" } else { "test" }.to_owned(),
                "--locked".to_owned(),
                "--offline".to_owned(),
                "--package".to_owned(),
                package.to_owned(),
            ];
            if let Some(feature) = feature {
                arguments.extend(["--features".to_owned(), feature.to_owned()]);
            }
            if library {
                arguments.push("--lib".to_owned());
            }
            if lint {
                arguments.extend(["--".to_owned(), "-D".to_owned(), "warnings".to_owned()]);
            }
            arguments
        })
        .collect());
    }
    if matches!(filter, Some("wyr1e7-model" | "wyr1e7-clippy")) {
        let lint = filter.is_some_and(|value| value.ends_with("clippy"));
        return Ok([
            ("wyrmroot-system-init", Some("wyr1e-selector33"), true),
            ("wyrmroot-dw1b-preemption", None, true),
            ("wyrmroot-wyr1e-test-actors", None, true),
            ("wyrmroot-bootfs", Some("builder"), true),
            ("xtask", None, false),
        ]
        .into_iter()
        .map(|(package, feature, library)| {
            let mut arguments = vec![
                if lint { "clippy" } else { "test" }.to_owned(),
                "--locked".to_owned(),
                "--offline".to_owned(),
                "--package".to_owned(),
                package.to_owned(),
            ];
            if let Some(feature) = feature {
                arguments.extend(["--features".to_owned(), feature.to_owned()]);
            }
            if library {
                arguments.push("--lib".to_owned());
            }
            if lint {
                arguments.extend(["--".to_owned(), "-D".to_owned(), "warnings".to_owned()]);
            }
            arguments
        })
        .collect());
    }
    // The DW1-F/WYR1-F instrumented artifact set. `wyr1f-closure` is the only
    // feature that compiles the declared post-console failure episode, so it
    // needs a gate of its own: every other row builds the production shape,
    // which is exactly the shape that must not contain it.
    // The one production role binary a host lint can reach, in the exact
    // feature shape it ships in.
    //
    // DW1-F/WYR1-F F2B. `wyr1f-clippy` lints `--lib`, and devmgr's role logic
    // is mostly not in the library: 3095 lines of `main.rs` against 1956 of
    // `lib.rs`. F2B.2's `--all-targets` workspace row does build that binary --
    // it is where two of F2B's findings came from -- but in the crate's
    // *default* feature shape, which is `default = []`, not the
    // `wyr1e8-production` shape that reaches a product.
    //
    // It is one row rather than seven because devmgr is the only role binary
    // whose `main.rs` is `#![cfg_attr(target_os = "wyrmroot", no_std)]`. The
    // other six are unconditionally `#![no_std]` with their own
    // `#[panic_handler]`, so no host build of them exists to lint -- they are
    // out of reach for the same reason as closure contract item 20, by a
    // different mechanism. `wyr1f-native` compiles them for the guest target
    // with `rustc`, which is type checking and no lint at all.
    if matches!(filter, Some("wyr1f-role-clippy")) {
        return Ok(vec![role_binary_lint_command(
            "wyrmroot-devmgr",
            "devmgr",
            "wyr1e8-production",
        )]);
    }
    if matches!(filter, Some("wyr1f-model" | "wyr1f-clippy")) {
        let lint = filter.is_some_and(|value| value.ends_with("clippy"));
        return Ok([
            ("wyrmroot-system-init", Some("wyr1f-closure"), true),
            ("wyrmroot-devmgr", Some("wyr1e8-production"), true),
            (
                // F3A.6k. The F gate builds consoled in the shape the F
                // product ships, and that shape no longer carries
                // `wyr1e8-recovery`.
                "wyrmroot-consoled",
                Some("native-consoled,wyr1e-wyrmsh"),
                true,
            ),
            ("wyrmroot-uart16550d", None, true),
            ("wyrmroot-bootfs", Some("builder"), true),
        ]
        .into_iter()
        .map(|(package, feature, library)| {
            let mut arguments = vec![
                if lint { "clippy" } else { "test" }.to_owned(),
                "--locked".to_owned(),
                "--offline".to_owned(),
                "--package".to_owned(),
                package.to_owned(),
            ];
            if let Some(feature) = feature {
                arguments.extend(["--features".to_owned(), feature.to_owned()]);
            }
            if library {
                arguments.push("--lib".to_owned());
            }
            if lint {
                arguments.extend(["--".to_owned(), "-D".to_owned(), "warnings".to_owned()]);
            }
            arguments
        })
        .collect());
    }
    if matches!(filter, Some("wyr1e8-model" | "wyr1e8-clippy")) {
        let lint = filter.is_some_and(|value| value.ends_with("clippy"));
        let mut commands: Vec<Vec<String>> = [
            ("wyrmroot-system-init", Some("wyr1e8-selector33"), true),
            ("wyrmroot-devmgr", Some("wyr1e8-production"), true),
            (
                "wyrmroot-consoled",
                Some("native-consoled,wyr1e-wyrmsh,wyr1e8-recovery"),
                true,
            ),
            ("wyrmroot-wyr1e-test-actors", None, true),
            ("wyrmroot-bootfs", Some("builder"), true),
            ("xtask", None, false),
        ]
        .into_iter()
        .map(|(package, feature, library)| {
            let mut arguments = vec![
                if lint { "clippy" } else { "test" }.to_owned(),
                "--locked".to_owned(),
                "--offline".to_owned(),
                "--package".to_owned(),
                package.to_owned(),
            ];
            if let Some(feature) = feature {
                arguments.extend(["--features".to_owned(), feature.to_owned()]);
            }
            if library {
                arguments.push("--lib".to_owned());
            }
            if lint && package == "wyrmroot-system-init" {
                arguments.extend(["--test".to_owned(), "wyr1e8_recovery_source".to_owned()]);
            }
            if lint {
                arguments.extend(["--".to_owned(), "-D".to_owned(), "warnings".to_owned()]);
            }
            arguments
        })
        .collect();
        // Running an integration target with native-init enabled also links
        // the freestanding binary on the host. Execute source assertions with
        // default features; Clippy additionally compiles the selected target.
        let mut source = [
            if lint { "clippy" } else { "test" },
            "--locked",
            "--offline",
            "--package",
            "wyrmroot-system-init",
            "--test",
            "wyr1e8_recovery_source",
        ]
        .map(str::to_owned)
        .to_vec();
        if lint {
            source.extend(["--".to_owned(), "-D".to_owned(), "warnings".to_owned()]);
        }
        commands.push(source);
        return Ok(commands);
    }
    if matches!(
        filter,
        Some("wyr1e6-controller-model" | "wyr1e6-controller-clippy")
    ) {
        let lint = filter.is_some_and(|value| value.ends_with("clippy"));
        return Ok([
            ("wyrmroot-system-init", "wyr1e-production"),
            ("wyrmroot-devmgr", "wyr1e-production"),
        ]
        .into_iter()
        .map(|(package, feature)| {
            let mut arguments = vec![
                if lint { "clippy" } else { "test" }.to_owned(),
                "--locked".to_owned(),
                "--offline".to_owned(),
                "--package".to_owned(),
                package.to_owned(),
                "--features".to_owned(),
                feature.to_owned(),
                "--lib".to_owned(),
            ];
            if lint {
                arguments.extend(["--".to_owned(), "-D".to_owned(), "warnings".to_owned()]);
            }
            arguments
        })
        .collect());
    }
    if matches!(
        filter,
        Some(
            "wyr1e4-model"
                | "wyr1e4-clippy"
                | "wyr1e5-model"
                | "wyr1e5-clippy"
                | "wyr1e6-model"
                | "wyr1e6-clippy"
        )
    ) {
        let lint = filter.is_some_and(|value| value.ends_with("clippy"));
        let packages: &[&str] = if filter.is_some_and(|value| value.starts_with("wyr1e6")) {
            &[
                "wyrmroot-wyrmsh",
                "wyrmroot-wyrmsh-core",
                "wyrmroot-rrc-manifest",
                "wyrmroot-bootfs",
                "xtask",
            ]
        } else {
            &["wyrmroot-wyrmsh", "wyrmroot-wyrmsh-core"]
        };
        return Ok(packages
            .iter()
            .copied()
            .map(|package| {
                let mut arguments = vec![
                    if lint { "clippy" } else { "test" }.to_owned(),
                    "--locked".to_owned(),
                    "--offline".to_owned(),
                    "--package".to_owned(),
                    package.to_owned(),
                ];
                if matches!(package, "wyrmroot-rrc-manifest" | "wyrmroot-bootfs") {
                    arguments.extend(["--features".to_owned(), "builder".to_owned()]);
                }
                if package != "xtask" {
                    arguments.push("--lib".to_owned());
                }
                arguments.push("--tests".to_owned());
                if lint {
                    arguments.extend(["--".to_owned(), "-D".to_owned(), "warnings".to_owned()]);
                }
                arguments
            })
            .collect());
    }
    if matches!(
        filter,
        Some(
            "wyr1e3-model"
                | "wyr1e3-clippy"
                | "wyr1e3-controller-model"
                | "wyr1e3-controller-clippy"
        )
    ) {
        let lint = filter.is_some_and(|value| value.ends_with("clippy"));
        let controller_only = filter.is_some_and(|value| value.contains("controller"));
        return Ok([
            ("wyrmroot-console-proto", None),
            ("wyrmroot-consoled", Some("wyr1e-wyrmsh")),
            ("wyrmroot-system-init", Some("wyr1e-shell-controller")),
            ("wyrmroot-registryd", None),
            ("wyrmroot-bootfs", Some("builder")),
        ]
        .into_iter()
        .filter(|(package, _)| {
            !controller_only || matches!(*package, "wyrmroot-system-init" | "wyrmroot-bootfs")
        })
        .map(|(package, features)| {
            let mut arguments = vec![
                if lint { "clippy" } else { "test" }.to_owned(),
                "--locked".to_owned(),
                "--offline".to_owned(),
                "--package".to_owned(),
                package.to_owned(),
                "--lib".to_owned(),
                "--tests".to_owned(),
            ];
            if let Some(features) = features {
                arguments.extend(["--features".to_owned(), features.to_owned()]);
            }
            if lint {
                arguments.extend(["--".to_owned(), "-D".to_owned(), "warnings".to_owned()]);
            }
            arguments
        })
        .collect());
    }
    if matches!(filter, Some("wyr1c6-clippy")) {
        let command = |package: &str, features: Option<&str>| {
            let mut arguments = vec![
                "clippy".to_owned(),
                "--locked".to_owned(),
                "--offline".to_owned(),
                "--package".to_owned(),
                package.to_owned(),
                "--lib".to_owned(),
            ];
            if let Some(features) = features {
                arguments.extend(["--features".to_owned(), features.to_owned()]);
            }
            arguments.extend(["--".to_owned(), "-D".to_owned(), "warnings".to_owned()]);
            arguments
        };
        return Ok(vec![
            command("wyrmroot-device-proto", None),
            command(
                "wyrmroot-devmgr",
                Some("wyr1c6-production,wyr1c6-selector29"),
            ),
            command(
                "wyrmroot-system-init",
                Some("wyr1c6-production,wyr1c6-selector29"),
            ),
        ]);
    }
    if matches!(filter, Some("wyr1c6-model")) {
        let command = |package: &str, features: Option<&str>| {
            let mut arguments = vec![
                "test".to_owned(),
                "--locked".to_owned(),
                "--offline".to_owned(),
                "--package".to_owned(),
                package.to_owned(),
                "--lib".to_owned(),
            ];
            if let Some(features) = features {
                arguments.extend(["--features".to_owned(), features.to_owned()]);
            }
            arguments
        };
        return Ok(vec![
            command("wyrmroot-device-proto", None),
            command(
                "wyrmroot-devmgr",
                Some("wyr1c6-production,wyr1c6-selector29"),
            ),
            command(
                "wyrmroot-system-init",
                Some("wyr1c6-production,wyr1c6-selector29"),
            ),
        ]);
    }
    if matches!(filter, Some("dw1c" | "dw1c-init0")) {
        return Ok(vec![
            DW1C_INIT0_TEST_ARGUMENTS
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect(),
        ]);
    }
    if matches!(filter, Some("dw1d6" | "dw1d6-synthetic")) {
        return Ok(vec![
            DW1D6_BOOTSTRAP_TEST_ARGUMENTS
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect(),
            DW1D6_SOURCE_CONTRACT_TEST_ARGUMENTS
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect(),
            DW1D6_ACTOR_TEST_ARGUMENTS
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
        // Reset card R7E. Section 9 asks for the driver, registry, shell and
        // console areas to be runnable as smaller independent tests, and each
        // of these had only the whole-workspace run or a product feature gate.
        // Naming them here costs nothing and makes one area's failure legible
        // without the rest of the suite around it.
        "registry" | "registryd" | "wyrmroot-registryd" | "package:wyrmroot-registryd" => {
            Some("wyrmroot-registryd")
        }
        "console" | "consoled" | "wyrmroot-consoled" | "package:wyrmroot-consoled" => {
            Some("wyrmroot-consoled")
        }
        "driver" | "uart16550d" | "wyrmroot-uart16550d" | "package:wyrmroot-uart16550d" => {
            Some("wyrmroot-uart16550d")
        }
        "devmgr" | "wyrmroot-devmgr" | "package:wyrmroot-devmgr" => Some("wyrmroot-devmgr"),
        "shell" | "wyrmsh" | "wyrmroot-wyrmsh" | "package:wyrmroot-wyrmsh" => {
            Some("wyrmroot-wyrmsh")
        }
        "shell-core" | "wyrmsh-core" | "wyrmroot-wyrmsh-core" | "package:wyrmroot-wyrmsh-core" => {
            Some("wyrmroot-wyrmsh-core")
        }
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

/// One warnings-denied Clippy row for a production role binary.
fn role_binary_lint_command(package: &str, binary: &str, features: &str) -> Vec<String> {
    [
        "clippy",
        "--locked",
        "--offline",
        "--package",
        package,
        "--bin",
        binary,
        "--features",
        features,
        "--",
        "-D",
        "warnings",
    ]
    .iter()
    .map(|argument| (*argument).to_owned())
    .collect()
}

/// `cargo fmt --all --check` on the accepted host rustfmt.
///
/// DW1-F/WYR1-F F2B. Closure contract item 9: Wyrmroot had no formatting gate
/// at all, so eleven files had drifted out of rustfmt shape without anything
/// saying so, three of them in a role the production product builds.
pub(crate) fn run_format_gate(repository: &Path) -> Result<(), Failure> {
    run_cargo(repository, &["fmt", "--all", "--", "--check"])
}

/// Warnings-denied Clippy over every workspace target in its default shape.
///
/// DW1-F/WYR1-F F2B. The per-card `*-clippy` host filters each select one
/// product's feature combination, which is what they are for; between them no
/// gate ever linted the default shape of the whole workspace. That is the row
/// that found a `#[test]` attribute duplicated onto the function above a WYR1-C6
/// test -- which had therefore not run since -- and two unreached evidence
/// recorders.
pub(crate) fn run_clippy_gate(repository: &Path) -> Result<(), Failure> {
    run_cargo(
        repository,
        &[
            "clippy",
            "--locked",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )
}

/// Workspace rustdoc with rustdoc warnings denied.
///
/// DW1-F/WYR1-F F2B, closure contract item 9's other half. `RUSTDOCFLAGS` is
/// set on the child rather than passed to `tools/pinned-cargo`, which rightly
/// refuses a caller-supplied one: the launcher owns the environment, and this
/// is the launcher's own xtask setting it for one invocation.
pub(crate) fn run_rustdoc_gate(repository: &Path) -> Result<(), Failure> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .args(["doc", "--locked", "--workspace", "--no-deps"])
        .env("RUSTDOCFLAGS", "-D warnings")
        .current_dir(repository)
        .stdin(Stdio::null())
        .status()
        .map_err(|error| Failure::task(format!("could not run Cargo: {error}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(Failure::task(format!(
            "rustdoc gate failed with {}",
            child_status(status.code())
        )))
    }
}

/// `run_cargo` plus the one compile-time variable a selector library needs.
///
/// Only selector 31 reads it, but setting it for the whole set keeps the table
/// a plain list of configurations rather than a list with an exception in it.
fn run_selector_cargo(repository: &Path, arguments: &[&str]) -> Result<(), Failure> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .args(arguments)
        .env("DEEPWYRM_DW1E_EVIDENCE_NONCE", SELECTOR_PLACEHOLDER_NONCE)
        .current_dir(repository)
        .stdin(Stdio::null())
        .status()
        .map_err(|error| Failure::task(format!("could not run Cargo: {error}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(Failure::task(format!(
            "selector library gate failed with {}",
            child_status(status.code())
        )))
    }
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
        BINARY_ONLY_PACKAGES, BOOTFS_BUILD_ARGUMENTS, BOOTFS_PACKAGE, BOOTFS_TEST_ARGUMENTS,
        CargoRun, DW1C_INIT0_TEST_ARGUMENTS, DW1D6_ACTOR_TEST_ARGUMENTS,
        DW1D6_BOOTSTRAP_TEST_ARGUMENTS, DW1D6_SOURCE_CONTRACT_TEST_ARGUMENTS, FEATURE_COMBINATIONS,
        INSPECTION_PATH, INSPECTION_SHELL, IsolatedUefiBuild, LoaderLinkMode, NAMED_HOST_FILTERS,
        NATIVE_COVERED_BY, Route, Step, UefiCargoProfile, blocked_toolchain_failure,
        canonical_build_directory, canonical_project_root, component_package, default_steps,
        encoded_uefi_rustflags, encoded_uefi_rustflags_for_target, explicit_test_filter,
        host_test_arguments, host_test_commands, is_listed_combination, lint_ratchet_shapes,
        named_host_filter, named_host_runs, native_steps, prepare_uefi_target_roots,
        r1_clippy_command, r1_status_command, render_uefi_inspection_report, run_verified_report,
        selector_library_commands, selector32_library_commands, validate_regular_artifact,
        validate_uefi_inspection_report, wyr1e8_producer_fixture_command,
    };
    use crate::error::Failure;
    use crate::sha256::bytes_digest;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn managed_lane_resolves_the_canonical_project_root() {
        let repository = super::repository_root().expect("resolve Wyrmroot repository");
        let project = canonical_project_root(&repository).expect("resolve OS-Project root");
        assert_eq!(
            project.file_name().and_then(|name| name.to_str()),
            Some("OS-Project")
        );
        assert!(project.join("wyrmroot/.git").is_dir());
    }

    #[test]
    fn wyrmsh_host_filters_select_shell_and_core_without_native_features() {
        for filter in [
            "wyr1e4-model",
            "wyr1e4-clippy",
            "wyr1e5-model",
            "wyr1e5-clippy",
        ] {
            let commands = host_test_commands(Some(filter)).unwrap();
            assert_eq!(commands.len(), 2);
            assert!(commands[0].iter().any(|arg| arg == "wyrmroot-wyrmsh"));
            assert!(commands[1].iter().any(|arg| arg == "wyrmroot-wyrmsh-core"));
            for command in &commands {
                assert_eq!(
                    command[0],
                    if filter.ends_with("clippy") {
                        "clippy"
                    } else {
                        "test"
                    }
                );
                assert!(command.iter().any(|arg| arg == "--locked"));
                assert!(command.iter().any(|arg| arg == "--offline"));
                assert!(!command.iter().any(|arg| arg == "--features"));
            }
        }
    }

    #[test]
    fn wyr1e6_host_filters_cover_product_codecs_and_producer() {
        for filter in ["wyr1e6-model", "wyr1e6-clippy"] {
            let commands = host_test_commands(Some(filter)).unwrap();
            assert_eq!(commands.len(), 5);
            for package in [
                "wyrmroot-wyrmsh",
                "wyrmroot-wyrmsh-core",
                "wyrmroot-rrc-manifest",
                "wyrmroot-bootfs",
                "xtask",
            ] {
                assert!(
                    commands
                        .iter()
                        .any(|command| command.iter().any(|arg| arg == package))
                );
            }
            for command in &commands {
                assert_eq!(
                    command[0],
                    if filter.ends_with("clippy") {
                        "clippy"
                    } else {
                        "test"
                    }
                );
                assert!(command.iter().any(|arg| arg == "--tests"));
                assert!(!command.iter().any(|arg| arg == "--all-targets"));
            }
            for package in ["wyrmroot-rrc-manifest", "wyrmroot-bootfs"] {
                let command = commands
                    .iter()
                    .find(|command| command.iter().any(|arg| arg == package))
                    .unwrap();
                assert!(
                    command
                        .windows(2)
                        .any(|args| args == ["--features", "builder"])
                );
            }
            let xtask = commands
                .iter()
                .find(|command| command.iter().any(|arg| arg == "xtask"))
                .unwrap();
            assert!(!xtask.iter().any(|arg| arg == "--lib"));
        }
    }

    #[test]
    fn wyr1e6_controller_filters_execute_selected_resident_features() {
        for filter in ["wyr1e6-controller-model", "wyr1e6-controller-clippy"] {
            let commands = host_test_commands(Some(filter)).unwrap();
            assert_eq!(commands.len(), 2);
            for (command, package) in commands
                .iter()
                .zip(["wyrmroot-system-init", "wyrmroot-devmgr"])
            {
                assert!(command.iter().any(|argument| argument == package));
                assert!(
                    command
                        .windows(2)
                        .any(|arguments| arguments == ["--features", "wyr1e-production"])
                );
                assert!(command.iter().any(|argument| argument == "--lib"));
                assert!(!command.iter().any(|argument| argument == "--tests"));
                assert!(!command.iter().any(|argument| argument == "--bin"));
            }
        }
    }

    #[test]
    fn wyr1e7_host_filters_cover_selected_observer_actors_and_product_builder() {
        for filter in ["wyr1e7-model", "wyr1e7-clippy"] {
            let commands = host_test_commands(Some(filter)).unwrap();
            assert_eq!(commands.len(), 5);
            for package in [
                "wyrmroot-system-init",
                "wyrmroot-dw1b-preemption",
                "wyrmroot-wyr1e-test-actors",
                "wyrmroot-bootfs",
                "xtask",
            ] {
                assert!(
                    commands
                        .iter()
                        .any(|command| command.iter().any(|argument| argument == package))
                );
            }
            for command in &commands[..4] {
                assert!(command.iter().any(|argument| argument == "--lib"));
                assert!(!command.iter().any(|argument| argument == "--tests"));
                assert!(!command.iter().any(|argument| argument == "--bin"));
                assert!(!command.iter().any(|argument| argument == "--all-targets"));
            }
            let init = &commands[0];
            assert!(
                init.windows(2)
                    .any(|arguments| arguments == ["--features", "wyr1e-selector33"])
            );
            let bootfs = &commands[3];
            assert!(
                bootfs
                    .windows(2)
                    .any(|arguments| arguments == ["--features", "builder"])
            );
            let xtask = &commands[4];
            assert!(!xtask.iter().any(|argument| argument == "--lib"));
            assert_eq!(
                commands[0][0],
                if filter.ends_with("clippy") {
                    "clippy"
                } else {
                    "test"
                }
            );
        }
    }

    #[test]
    fn wyr1e8_host_filters_cover_current_recovery_product_and_additive_builder() {
        for filter in ["wyr1e8-model", "wyr1e8-clippy"] {
            let commands = host_test_commands(Some(filter)).unwrap();
            assert_eq!(commands.len(), 7);
            for package in [
                "wyrmroot-system-init",
                "wyrmroot-devmgr",
                "wyrmroot-consoled",
                "wyrmroot-wyr1e-test-actors",
                "wyrmroot-bootfs",
                "xtask",
            ] {
                assert!(
                    commands
                        .iter()
                        .any(|command| command.iter().any(|argument| argument == package))
                );
            }
            assert!(
                commands[0]
                    .windows(2)
                    .any(|arguments| { arguments == ["--features", "wyr1e8-selector33"] })
            );
            assert!(commands[0].iter().any(|argument| argument == "--lib"));
            let source_target = commands[0]
                .windows(2)
                .position(|arguments| arguments == ["--test", "wyr1e8_recovery_source"]);
            assert_eq!(source_target.is_some(), filter.ends_with("clippy"));
            if let Some(lint_arguments) = commands[0].iter().position(|argument| argument == "--") {
                assert!(source_target.unwrap() < lint_arguments);
            }
            assert!(commands[1..6].iter().all(|command| {
                !command
                    .iter()
                    .any(|argument| argument == "wyr1e8_recovery_source")
            }));
            let mut expected_source = vec![
                if filter.ends_with("clippy") {
                    "clippy"
                } else {
                    "test"
                },
                "--locked",
                "--offline",
                "--package",
                "wyrmroot-system-init",
                "--test",
                "wyr1e8_recovery_source",
            ];
            if filter.ends_with("clippy") {
                expected_source.extend(["--", "-D", "warnings"]);
            }
            assert_eq!(commands[6], expected_source);
            assert!(
                commands[1]
                    .windows(2)
                    .any(|arguments| { arguments == ["--features", "wyr1e8-production"] })
            );
            assert!(commands[2].windows(2).any(|arguments| {
                arguments == ["--features", "native-consoled,wyr1e-wyrmsh,wyr1e8-recovery"]
            }));
        }
    }

    #[test]
    fn wyr1e8_producer_fixture_filter_is_exact_and_preserves_output() {
        assert_eq!(
            wyr1e8_producer_fixture_command(),
            [
                "test",
                "--locked",
                "--offline",
                "--package",
                "wyrmroot-system-init",
                "--features",
                "wyr1e8-selector33",
                "--lib",
                "wyr1b_native::tests::e8_producer_fixture::actual_driver_and_registry_recovery_compose_through_s4_ready",
                "--",
                "--exact",
                "--nocapture",
            ]
            .map(str::to_owned)
        );
    }

    #[test]
    fn wyr1e8_product_filters_cover_only_product_owned_host_code() {
        for filter in ["wyr1e8-product-model", "wyr1e8-product-clippy"] {
            let commands = host_test_commands(Some(filter)).unwrap();
            assert_eq!(commands.len(), 3);
            assert!(
                commands[0]
                    .iter()
                    .any(|arg| arg == "wyrmroot-wyr1e-test-actors")
            );
            assert!(commands[1].iter().any(|arg| arg == "wyrmroot-bootfs"));
            assert!(
                commands[1]
                    .windows(2)
                    .any(|args| args == ["--features", "builder"])
            );
            assert!(commands[2].iter().any(|arg| arg == "xtask"));
            assert_eq!(
                commands[0][0],
                if filter.ends_with("clippy") {
                    "clippy"
                } else {
                    "test"
                }
            );
        }
    }

    #[test]
    fn wyr1e3_host_filters_select_models_without_native_or_selector_features() {
        for filter in ["wyr1e3-model", "wyr1e3-clippy"] {
            let commands = host_test_commands(Some(filter)).unwrap();
            assert_eq!(commands.len(), 5);
            for command in &commands {
                assert!(command.iter().any(|arg| arg == "--lib"));
                assert!(command.iter().any(|arg| arg == "--tests"));
                assert!(
                    !command
                        .iter()
                        .any(|arg| arg == "--bin" || arg == "--all-targets")
                );
                assert!(
                    !command
                        .iter()
                        .any(|arg| arg.contains("native-") || arg.contains("selector32"))
                );
                assert!(command.iter().any(|arg| arg == "--locked"));
                assert!(command.iter().any(|arg| arg == "--offline"));
            }
            assert!(commands[1].iter().any(|arg| arg == "wyr1e-wyrmsh"));
            assert!(
                commands[2]
                    .iter()
                    .any(|arg| arg == "wyr1e-shell-controller")
            );
            assert_eq!(
                commands[0][0],
                if filter.ends_with("clippy") {
                    "clippy"
                } else {
                    "test"
                }
            );
        }
    }

    #[test]
    fn wyr1e3_controller_model_filter_excludes_the_parallel_console_lane() {
        for filter in ["wyr1e3-controller-model", "wyr1e3-controller-clippy"] {
            let commands = host_test_commands(Some(filter)).unwrap();
            assert_eq!(commands.len(), 2);
            assert!(commands[0].iter().any(|arg| arg == "wyrmroot-system-init"));
            assert!(
                commands[0]
                    .iter()
                    .any(|arg| arg == "wyr1e-shell-controller")
            );
            assert!(commands[1].iter().any(|arg| arg == "wyrmroot-bootfs"));
            assert!(commands[1].iter().any(|arg| arg == "builder"));
        }
    }

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
        assert_eq!(
            host_test_commands(Some("dw1d6")).unwrap(),
            [
                DW1D6_BOOTSTRAP_TEST_ARGUMENTS.to_vec(),
                DW1D6_SOURCE_CONTRACT_TEST_ARGUMENTS.to_vec(),
                DW1D6_ACTOR_TEST_ARGUMENTS.to_vec(),
            ]
        );
    }

    /// Every named gate is listed once, and every host-route name is one the
    /// command builders actually special-case: a listed name that fell through
    /// to the workspace `test:` substring filter would run nothing it names.
    #[test]
    fn every_named_host_filter_is_listed_once_and_routes_to_its_own_gate() {
        let mut seen = std::collections::BTreeSet::new();
        for (name, route) in NAMED_HOST_FILTERS {
            assert!(seen.insert(*name), "{name} is listed twice");
            assert_eq!(named_host_filter(name), Some(*route));
            if *route == Route::Host {
                let runs = named_host_runs(name).unwrap();
                assert!(!runs.is_empty(), "{name} runs nothing");
                assert!(
                    runs.iter().all(|run| !run
                        .arguments
                        .iter()
                        .any(|argument| argument == "--workspace")),
                    "{name} fell through to the workspace substring filter"
                );
            }
        }
        for unlisted in ["bootfs", "test:traversal", "traversal", "native-ish"] {
            assert_eq!(named_host_filter(unlisted), None);
        }
        let documented = crate::cli::USAGE
            .lines()
            .filter_map(|line| {
                line.trim()
                    .strip_prefix("tools/pinned-cargo xtask test host ")
            })
            .collect::<Vec<_>>();
        assert!(!documented.is_empty());
        for name in documented {
            assert!(
                named_host_filter(name).is_some(),
                "usage documents {name}, which is not a named host filter"
            );
        }
    }

    /// The four gates that used to be matched inside `run_host_tests` keep the
    /// exact commands they ran there.
    #[test]
    fn the_formerly_inline_gates_keep_their_exact_commands() {
        let runs = |name| named_host_runs(name).unwrap();
        assert_eq!(
            runs("wyr1e8-producer-fixture"),
            [CargoRun::plain(wyr1e8_producer_fixture_command())]
        );
        assert_eq!(runs("r1-clippy"), [CargoRun::plain(r1_clippy_command())]);
        assert_eq!(runs("r1-status"), [CargoRun::plain(r1_status_command())]);
        assert_eq!(
            runs("wyr1d5-clippy"),
            selector32_library_commands()
                .into_iter()
                .map(CargoRun::plain)
                .collect::<Vec<_>>()
        );
        let selectors = runs("selectors");
        assert_eq!(
            selectors.len(),
            FEATURE_COMBINATIONS.len()
                - FEATURE_COMBINATIONS
                    .iter()
                    .filter(|(package, _)| BINARY_ONLY_PACKAGES.contains(package))
                    .count()
        );
        assert!(selectors.iter().all(|run| run.selector_nonce));
        assert_eq!(
            selectors
                .into_iter()
                .map(|run| run.arguments)
                .collect::<Vec<_>>(),
            selector_library_commands()
        );
    }

    /// S1.1: a named host gate that exists runs in the unfiltered suite, so
    /// none of them waits for someone to type its name.
    #[test]
    fn the_unfiltered_suite_runs_every_named_host_gate() {
        let steps = default_steps().unwrap();
        let runs = steps
            .iter()
            .filter_map(|step| match step {
                Step::Cargo(run) => Some(run.clone()),
                Step::Native(name, _) => panic!("the unfiltered suite runs native gate {name}"),
                Step::LintRatchet => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(steps.last(), Some(&Step::LintRatchet));
        for (name, route) in NAMED_HOST_FILTERS {
            if *route == Route::Host {
                for run in named_host_runs(name).unwrap() {
                    assert!(runs.contains(&run), "{name} is missing {:?}", run.arguments);
                }
            }
        }
        for arguments in host_test_commands(None).unwrap() {
            assert!(runs.contains(&CargoRun::plain(arguments)));
        }
        for (index, run) in runs.iter().enumerate() {
            assert!(
                !runs[..index].contains(run),
                "{:?} runs twice",
                run.arguments
            );
        }
        // The cheapest question first: does every combination compile at all.
        let selectors = named_host_runs("selectors").unwrap();
        assert_eq!(runs[..selectors.len()], selectors);
    }

    /// S1.1: every feature set a named host gate passes is in the one table,
    /// so the table cannot fall behind the gates that read it.
    #[test]
    fn every_feature_set_a_host_gate_selects_is_a_listed_combination() {
        let mut checked = 0;
        for (name, route) in NAMED_HOST_FILTERS {
            if *route != Route::Host {
                continue;
            }
            for run in named_host_runs(name).unwrap() {
                let value = |flag: &str| {
                    run.arguments
                        .windows(2)
                        .find(|pair| pair[0] == flag)
                        .map(|pair| pair[1].as_str())
                };
                if let Some(features) = value("--features") {
                    let package = value("--package").expect("a feature gate names its package");
                    assert!(
                        is_listed_combination(package, features),
                        "{name} builds {package} with {features}, which FEATURE_COMBINATIONS omits"
                    );
                    checked += 1;
                }
            }
        }
        assert!(checked > FEATURE_COMBINATIONS.len());
    }

    /// S1.1: `native` runs every native gate once, and a gate it skips runs
    /// the same check function as the gate that covers it.
    #[test]
    fn native_runs_every_native_gate_or_the_one_covering_it() {
        let gates = native_steps()
            .into_iter()
            .map(|step| match step {
                Step::Native(name, gate) => (name, gate),
                Step::Cargo(run) => panic!("native runs a host command {:?}", run.arguments),
                Step::LintRatchet => panic!("native runs the lint ratchet"),
            })
            .collect::<Vec<_>>();
        for (index, (name, gate)) in gates.iter().enumerate() {
            assert!(
                !gates[..index].iter().any(|(_, earlier)| earlier == gate),
                "{name} repeats a gate native already runs"
            );
        }
        for (name, route) in NAMED_HOST_FILTERS {
            let Route::Native(gate) = route else {
                continue;
            };
            if gates.iter().any(|(run, _)| run == name) {
                continue;
            }
            let cover = NATIVE_COVERED_BY
                .iter()
                .find(|(covered, _)| covered == name)
                .map(|(_, cover)| *cover)
                .unwrap_or_else(|| panic!("native gate {name} is reachable only by its name"));
            assert_eq!(
                gates
                    .iter()
                    .find(|(run, _)| *run == cover)
                    .map(|(_, gate)| gate),
                Some(gate),
                "{name} is covered by {cover}, which native does not run as the same gate"
            );
        }
        assert_eq!(named_host_filter("native"), Some(Route::AllNative));
        assert_eq!(named_host_filter("full"), Some(Route::Full));
    }

    /// S1.3: the ratchet lints every shape a named clippy gate lints, plus the
    /// workspace's default shape, and each once.
    #[test]
    fn the_lint_ratchet_covers_every_clippy_shape_a_gate_lints() {
        let shapes = lint_ratchet_shapes().unwrap();
        assert_eq!(
            shapes[0],
            [
                "clippy",
                "--locked",
                "--offline",
                "--workspace",
                "--all-targets"
            ]
        );
        for (name, route) in NAMED_HOST_FILTERS {
            if *route == Route::Host {
                for run in named_host_runs(name).unwrap() {
                    if run.arguments[0] == "clippy" {
                        assert!(shapes.contains(&run.arguments), "{name}");
                    }
                }
            }
        }
        assert!(
            shapes
                .iter()
                .any(|shape| shape.contains(&"--bin".to_owned()))
        );
        for (index, shape) in shapes.iter().enumerate() {
            assert!(!shapes[..index].contains(shape));
        }
        assert_eq!(named_host_filter("lint-ratchet"), Some(Route::LintRatchet));
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
    fn uefi_inspection_report_binds_all_snapshot_hashes_and_sizes() {
        let first = render_uefi_inspection_report(b"loader", b"debug", b"symbols");
        validate_uefi_inspection_report(first.as_bytes(), b"loader")
            .expect("validate exact published loader binding");
        assert!(first.contains(&format!(
            "\"loader_sha256\": \"{}\"",
            bytes_digest(b"loader")
        )));
        assert!(first.contains("\"loader_size\": 6"));
        assert!(first.contains(&format!(
            "\"debug_loader_sha256\": \"{}\"",
            bytes_digest(b"debug")
        )));
        assert!(first.contains(&format!(
            "\"debug_symbol_sha256\": \"{}\"",
            bytes_digest(b"symbols")
        )));
        assert_ne!(
            first,
            render_uefi_inspection_report(b"loadeR", b"debug", b"symbols")
        );
        assert!(validate_uefi_inspection_report(first.as_bytes(), b"loadeR").is_err());

        let false_verified = first.replace("\"verified\": true", "\"verified\": false");
        assert!(validate_uefi_inspection_report(false_verified.as_bytes(), b"loader").is_err());
        let extra_key = first.replace(
            "  \"verified\": true\n",
            "  \"verified\": true,\n  \"extra\": true\n",
        );
        assert!(validate_uefi_inspection_report(extra_key.as_bytes(), b"loader").is_err());
        let malformed_debug_hash = first.replace(
            &bytes_digest(b"debug"),
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffG",
        );
        assert!(
            validate_uefi_inspection_report(malformed_debug_hash.as_bytes(), b"loader").is_err()
        );
    }

    #[test]
    fn verified_inspector_ignores_hostile_ambient_path() {
        const CHILD_ROOT: &str = "WYRMROOT_TEST_HERMETIC_INSPECTOR_ROOT";
        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            let repository = Path::new(&root).join("repository");
            let report = run_verified_report(
                &repository,
                "inspect.sh",
                std::iter::empty::<&str>(),
                "hermetic inspector test",
            )
            .expect("fixed inspector environment must pass");
            assert_eq!(report, "{\"verified\": true}\n");
            let native_report = crate::wyr1c::run_native_inspector_environment_probe(
                &repository,
                &repository.join("inspect.sh"),
            )
            .expect("fixed native inspector environment must pass");
            assert_eq!(native_report, "{\"verified\": true}\n");
            return;
        }

        assert_eq!(INSPECTION_SHELL, "/bin/sh");
        assert_eq!(INSPECTION_PATH, "/usr/lib/llvm/22/bin:/usr/bin:/bin");
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "wyrmroot-hermetic-inspector-{}-{nonce}",
            std::process::id()
        ));
        let hostile = root.join("hostile");
        let repository = root.join("repository");
        fs::create_dir_all(&hostile).expect("create hostile PATH");
        fs::create_dir(&repository).expect("create inspector repository");
        for tool in [
            "sh",
            "llvm-readobj",
            "llvm-pdbutil",
            "sha256sum",
            "wc",
            "awk",
            "grep",
            "sed",
            "tr",
        ] {
            let shim = hostile.join(tool);
            fs::write(&shim, "#!/bin/sh\nexit 99\n").expect("write hostile shim");
            fs::set_permissions(&shim, fs::Permissions::from_mode(0o755))
                .expect("make hostile shim executable");
        }
        fs::write(
            repository.join("inspect.sh"),
            concat!(
                "#!/bin/sh\nset -eu\n",
                "test \"$PATH\" = '/usr/lib/llvm/22/bin:/usr/bin:/bin'\n",
                "test \"$(command -v sh)\" = '/usr/bin/sh'\n",
                "test \"$(command -v llvm-readobj)\" = '/usr/lib/llvm/22/bin/llvm-readobj'\n",
                "test \"$(command -v llvm-pdbutil)\" = '/usr/lib/llvm/22/bin/llvm-pdbutil'\n",
                "test \"$(command -v sha256sum)\" = '/usr/bin/sha256sum'\n",
                "test \"$(command -v wc)\" = '/usr/bin/wc'\n",
                "test \"$(command -v awk)\" = '/usr/bin/awk'\n",
                "test \"$(command -v grep)\" = '/usr/bin/grep'\n",
                "test \"$(command -v sed)\" = '/usr/bin/sed'\n",
                "test \"$(command -v tr)\" = '/usr/bin/tr'\n",
                "printf '%s\\n' '{\"verified\": true}'\n",
            ),
        )
        .expect("write inspection script");

        let status = Command::new(std::env::current_exe().expect("locate test executable"))
            .args([
                "--exact",
                "tasks::tests::verified_inspector_ignores_hostile_ambient_path",
                "--nocapture",
            ])
            .env_clear()
            .env("PATH", &hostile)
            .env(CHILD_ROOT, &root)
            .status()
            .expect("spawn hostile-environment test child");
        assert!(status.success());
        fs::remove_dir_all(root).expect("remove hermetic inspector fixture");
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
            if encoded_uefi_rustflags(
                &root,
                &root,
                production,
                "/accepted/sysroot",
                "/accepted/rust-lld",
                LoaderLinkMode::Production,
            )
            .is_ok()
            {
                return Err(Failure::task(
                    "ordinary rustflags validator admitted a procfd target",
                ));
            }
            let flags = encoded_uefi_rustflags_for_target(
                &root,
                &root,
                targets.production_target(),
                "/accepted/sysroot",
                "/accepted/rust-lld",
                LoaderLinkMode::Production,
            )?;
            if !flags.contains(&format!(
                "--remap-path-prefix={}=/cargo-target",
                production.display()
            )) {
                return Err(Failure::task(
                    "scoped rustflags omitted the retained target root",
                ));
            }
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
