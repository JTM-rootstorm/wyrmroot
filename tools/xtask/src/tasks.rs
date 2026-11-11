use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use crate::deep_layout::DeepLayoutBuild;
use crate::error::Failure;
use crate::metadata::{BuildManifest, LoaderProfile};
use crate::secure_fs::{Directory, SealedFile};
use crate::sha256::bytes_digest;
use crate::toolchain_artifact::AcceptedToolchain;

const TOOLCHAIN_REQUEST: &str = "toolchain/requests/RUST-TC2-WYRMROOT-PSABI-008.toml";
const MAX_LOADER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DEBUG_SYMBOL_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const INSPECTION_PATH: &str = "/usr/lib/llvm/22/bin:/usr/bin:/bin";
pub(crate) const INSPECTION_SHELL: &str = "/bin/sh";
const DEEP_LAYOUT_POLICY_ENV: &str = "WYRMROOT_DEEP_LAYOUT_POLICY_RS";
pub(crate) struct LoaderToolchain {
    accepted: AcceptedToolchain,
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
    Release,
}

impl UefiCargoProfile {
    const fn directory(self) -> &'static str {
        match self {
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
    pub(crate) loader_bytes: Vec<u8>,
    _target_authority: Option<UefiTargetAuthority>,
}

impl DeterministicUefiArtifacts {}

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
}

pub(crate) fn repository_root() -> Result<PathBuf, Failure> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .ok_or_else(|| Failure::task("could not resolve the Wyrmroot repository root"))
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
    run_verified_report(
        repository,
        &profile.toolchain_inspection,
        [OsStr::new("--rustc"), accepted.rustc.as_os_str()],
        "UEFI toolchain validation",
    )?;
    accepted.verify_unchanged()?;
    Ok(LoaderToolchain { accepted })
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
    match scratch {
        Some(scratch) => scratch.with_inheritance_disabled("UEFI build scratch root", inspect)?,
        None => inspect()?,
    };
    Ok(DeterministicUefiArtifacts {
        loader_bytes,
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

fn child_status(code: Option<i32>) -> String {
    code.map_or_else(
        || "termination by signal".to_owned(),
        |code| format!("exit code {code}"),
    )
}
