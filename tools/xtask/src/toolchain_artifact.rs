use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Take};
use std::path::{Component as PathComponent, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

use crate::elf_runtime::{RuntimeMetadata, inspect};
use crate::error::Failure;
use crate::sha256::{bytes_digest, reader_digest};

const REQUEST_PATH: &str = "toolchain/requests/RUST-WYR0-I-B-SYSROOTS-007.toml";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const COORDINATOR_REQUEST: &str = "RUST-WYR0-I-B-SYSROOTS-007";
const CONSUMER_REQUEST: &str = "RUST-WYR0-I-B-SYSROOTS-007";
const RUST_SOURCE_TREE: &str = "aa3d5f9d1311772c99e385067d07641c01b8d203";
const RUSTC_DRIVER_NAME: &str = "librustc_driver-948919618f142f9a.so";
const LLVM_NAME: &str = "libLLVM.so.22.1-rust-1.97.1-stable";
const SYSTEM_INTERPRETER: &str = "/lib64/ld-linux-x86-64.so.2";
const GNU_TAR: &str = "/usr/bin/tar";
const MAX_TOOLCHAIN_ENTRIES: usize = 4096;
const MAX_TOOLCHAIN_REGULAR_BYTES: u64 = 8 * 1024 * 1024 * 1024;

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
    pub(crate) uefi_alloc_sha256: String,
    pub(crate) uefi_builtins_sha256: String,
    pub(crate) rustc_driver_sha256: String,
    pub(crate) llvm_sha256: String,
    pub(crate) toolchain_tree_sha256: String,
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
        "extend-immutable-existing-wyrmroot-rust-toolchain",
        "toolchain request",
    )?;
    let expected_manifest_sha = required_sha256(
        &request,
        "build.artifact_manifest_sha256",
        "toolchain request",
    )?;
    let expected_tree_sha =
        required_sha256(&request, "build.toolchain_tree_sha256", "toolchain request")?;
    let expected_root = required_string(
        &request,
        "build.accepted_artifact_root",
        "toolchain request",
    )?;

    let (root, canonical_rustc) = artifact_root_from_rustc(configured_rustc, expected_name)?;
    if root.to_str() != Some(expected_root.as_str()) {
        return Err(Failure::task(
            "configured WYRMROOT_RUSTC is outside the request-declared accepted artifact root",
        ));
    }
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
    let toolchain_tree_sha256 =
        required_sha256(&manifest, "toolchain_tree_sha256", "artifact manifest")?;
    if toolchain_tree_sha256 != expected_tree_sha {
        return Err(Failure::task(format!(
            "artifact manifest toolchain tree hash is {toolchain_tree_sha256}, expected {expected_tree_sha}"
        )));
    }

    let rustc = component(&root, &manifest, "artifacts.rustc", "rustc")?;
    if rustc.path != canonical_rustc {
        return Err(Failure::task(
            "configured WYRMROOT_RUSTC does not match manifest-declared rustc artifact",
        ));
    }
    let cargo = component(&root, &manifest, "artifacts.cargo", "cargo")?;
    let rust_lld = component(&root, &manifest, "artifacts.rust_lld", "rust-lld")?;
    let uefi_core = component(&root, &manifest, "artifacts.uefi_core", "UEFI core")?;
    let uefi_alloc = component(&root, &manifest, "artifacts.uefi_alloc", "UEFI alloc")?;
    let uefi_std = component(&root, &manifest, "artifacts.uefi_std", "UEFI std")?;
    let uefi_proc_macro = component(
        &root,
        &manifest,
        "artifacts.uefi_proc_macro",
        "UEFI proc_macro",
    )?;
    let uefi_builtins = component(
        &root,
        &manifest,
        "artifacts.uefi_compiler_builtins",
        "UEFI compiler-builtins",
    )?;
    let none_core = component(&root, &manifest, "artifacts.none_core", "none core")?;
    let none_alloc = component(&root, &manifest, "artifacts.none_alloc", "none alloc")?;
    let none_builtins = component(
        &root,
        &manifest,
        "artifacts.none_compiler_builtins",
        "none compiler-builtins",
    )?;
    let wyrmroot_core = component(&root, &manifest, "artifacts.wyrmroot_core", "Wyrmroot core")?;
    let wyrmroot_alloc = component(
        &root,
        &manifest,
        "artifacts.wyrmroot_alloc",
        "Wyrmroot alloc",
    )?;
    let wyrmroot_builtins = component(
        &root,
        &manifest,
        "artifacts.wyrmroot_compiler_builtins",
        "Wyrmroot compiler-builtins",
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
    verify_toolchain_tree(&sysroot, &toolchain_tree_sha256)?;
    let rustc_driver = component(&root, &manifest, "artifacts.rustc_driver", "rustc driver")?;
    let llvm = component(&root, &manifest, "artifacts.llvm", "toolchain LLVM")?;
    let host_core = component(&root, &manifest, "artifacts.host_core", "host core")?;
    let host_std = component(&root, &manifest, "artifacts.host_std", "host std")?;
    let host_proc_macro = component(
        &root,
        &manifest,
        "artifacts.host_proc_macro",
        "host proc_macro",
    )?;
    let host_builtins = component(
        &root,
        &manifest,
        "artifacts.host_compiler_builtins",
        "host compiler-builtins",
    )?;
    validate_runtime_dependencies(&sysroot, &rustc, &cargo, &rust_lld, &rustc_driver, &llvm)?;

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
        uefi_alloc.clone(),
        uefi_std,
        uefi_proc_macro,
        uefi_builtins.clone(),
        none_core.clone(),
        none_alloc.clone(),
        none_builtins.clone(),
        wyrmroot_core,
        wyrmroot_alloc,
        wyrmroot_builtins,
        rustc_driver.clone(),
        llvm.clone(),
        host_core,
        host_std,
        host_proc_macro,
        host_builtins,
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
        uefi_alloc_sha256: uefi_alloc.sha256.clone(),
        uefi_builtins_sha256: uefi_builtins.sha256.clone(),
        rustc_driver_sha256: rustc_driver.sha256.clone(),
        llvm_sha256: llvm.sha256.clone(),
        toolchain_tree_sha256,
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
    expect_integer(manifest, "bootstrap_stage", 1, "artifact manifest")?;
    expect_string(
        manifest,
        "host",
        "x86_64-unknown-linux-gnu",
        "artifact manifest",
    )?;
    expect_string(
        manifest,
        "source_tree",
        RUST_SOURCE_TREE,
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
        "x86_64-unknown-wyrmroot",
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
        "acceptance.target_specs",
        "acceptance.uefi_sysroot_presence",
        "acceptance.none_sysroot_presence",
        "acceptance.wyrmroot_sysroot_presence",
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
) -> Result<ArtifactComponent, Failure> {
    let path_key = format!("{section}.path");
    let hash_key = format!("{section}.sha256");
    let relative = required_string(manifest, &path_key, "artifact manifest")?;
    let declared_sha = required_sha256(manifest, &hash_key, "artifact manifest")?;
    let path = contained_path(root, &relative, label)?;
    let component = ArtifactComponent {
        label,
        path,
        sha256: declared_sha,
    };
    validate_component(root, &component)?;
    Ok(component)
}

fn verify_toolchain_tree(root: &Path, expected: &str) -> Result<(), Failure> {
    validate_toolchain_tree_entries(root)?;
    let version = Command::new(GNU_TAR)
        .arg("--version")
        .env_remove("TAR_OPTIONS")
        .env_remove("LD_AUDIT")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| Failure::task(format!("could not identify GNU tar: {error}")))?;
    if !version.status.success()
        || String::from_utf8_lossy(&version.stdout)
            .lines()
            .next()
            .is_none_or(|line| line != "tar (GNU tar) 1.35")
    {
        return Err(Failure::task(
            "accepted toolchain tree verification requires GNU tar 1.35",
        ));
    }
    let mut child = Command::new(GNU_TAR)
        .args([
            "--sort=name",
            "--mtime=@0",
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "-cf",
            "-",
            "-C",
        ])
        .arg(root)
        .arg(".")
        .env_remove("TAR_OPTIONS")
        .env_remove("LD_AUDIT")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD")
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| Failure::task(format!("could not archive accepted toolchain: {error}")))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| Failure::task("could not capture accepted toolchain archive"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| Failure::task("could not capture GNU tar diagnostics"))?;
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });
    let actual = reader_digest(&mut stdout).map_err(|error| {
        Failure::task(format!("could not hash accepted toolchain tree: {error}"))
    })?;
    let status = child
        .wait()
        .map_err(|error| Failure::task(format!("could not wait for GNU tar: {error}")))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| Failure::task("GNU tar diagnostic reader panicked"))?
        .map_err(|error| Failure::task(format!("could not read GNU tar diagnostics: {error}")))?;
    if !status.success() {
        return Err(Failure::task(format!(
            "GNU tar toolchain hashing failed with exit code {}{}",
            status.code().unwrap_or(-1),
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {}", String::from_utf8_lossy(&stderr).trim())
            }
        )));
    }
    if actual != expected {
        return Err(Failure::task(format!(
            "accepted toolchain tree hash is {actual}, expected {expected}"
        )));
    }
    Ok(())
}

fn validate_toolchain_tree_entries(root: &Path) -> Result<(), Failure> {
    let mut pending = vec![root.to_path_buf()];
    let mut entries = 0_usize;
    let mut regular_bytes = 0_u64;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|error| {
            Failure::task(format!(
                "could not inspect accepted toolchain directory {}: {error}",
                directory.display()
            ))
        })? {
            let entry = entry.map_err(|error| {
                Failure::task(format!(
                    "could not inspect accepted toolchain entry: {error}"
                ))
            })?;
            entries = entries
                .checked_add(1)
                .filter(|count| *count <= MAX_TOOLCHAIN_ENTRIES)
                .ok_or_else(|| Failure::task("accepted toolchain tree has too many entries"))?;
            let file_type = entry.file_type().map_err(|error| {
                Failure::task(format!(
                    "could not inspect accepted toolchain entry: {error}"
                ))
            })?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
                    Failure::task(format!(
                        "could not inspect accepted toolchain file: {error}"
                    ))
                })?;
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(Failure::task(
                        "accepted toolchain entry identity changed during traversal",
                    ));
                }
                let size = metadata.len();
                regular_bytes = regular_bytes
                    .checked_add(size)
                    .filter(|total| *total <= MAX_TOOLCHAIN_REGULAR_BYTES)
                    .ok_or_else(|| {
                        Failure::task("accepted toolchain regular-file bytes exceed the limit")
                    })?;
            } else if file_type.is_symlink() {
                return Err(Failure::task(format!(
                    "accepted toolchain contains symbolic link {}",
                    entry.path().display()
                )));
            } else {
                return Err(Failure::task(format!(
                    "accepted toolchain contains unsupported filesystem entry {}",
                    entry.path().display()
                )));
            }
        }
    }
    Ok(())
}

fn validate_runtime_dependencies(
    sysroot: &Path,
    rustc: &ArtifactComponent,
    cargo: &ArtifactComponent,
    rust_lld: &ArtifactComponent,
    rustc_driver: &ArtifactComponent,
    llvm: &ArtifactComponent,
) -> Result<(), Failure> {
    let rustc_runtime = inspect_component(rustc)?;
    expect_runtime(
        rustc.label,
        &rustc_runtime,
        Some(SYSTEM_INTERPRETER),
        "$ORIGIN/../lib",
        &[RUSTC_DRIVER_NAME, "libc.so.6"],
    )?;
    verify_local_resolution(
        sysroot,
        &rustc.path,
        &rustc_runtime,
        &[(RUSTC_DRIVER_NAME, &rustc_driver.path)],
    )?;

    let cargo_runtime = inspect_component(cargo)?;
    expect_runtime(
        cargo.label,
        &cargo_runtime,
        Some(SYSTEM_INTERPRETER),
        "$ORIGIN/../lib",
        &[
            "libdl.so.2",
            "libgcc_s.so.1",
            "librt.so.1",
            "libpthread.so.0",
            "libm.so.6",
            "libc.so.6",
            "ld-linux-x86-64.so.2",
        ],
    )?;
    verify_local_resolution(sysroot, &cargo.path, &cargo_runtime, &[])?;

    let lld_runtime = inspect_component(rust_lld)?;
    expect_runtime(
        rust_lld.label,
        &lld_runtime,
        Some(SYSTEM_INTERPRETER),
        "$ORIGIN/../../../:$ORIGIN/../lib",
        &[
            "libpthread.so.0",
            "libz.so.1",
            LLVM_NAME,
            "libm.so.6",
            "libgcc_s.so.1",
            "libc.so.6",
            "ld-linux-x86-64.so.2",
        ],
    )?;
    verify_local_resolution(
        sysroot,
        &rust_lld.path,
        &lld_runtime,
        &[(LLVM_NAME, &llvm.path)],
    )?;

    let driver_runtime = inspect_component(rustc_driver)?;
    expect_runtime(
        rustc_driver.label,
        &driver_runtime,
        None,
        "$ORIGIN/../lib",
        &[
            LLVM_NAME,
            "libstdc++.so.6",
            "libgcc_s.so.1",
            "libc.so.6",
            "ld-linux-x86-64.so.2",
        ],
    )?;
    verify_local_resolution(
        sysroot,
        &rustc_driver.path,
        &driver_runtime,
        &[(LLVM_NAME, &llvm.path)],
    )?;

    let llvm_runtime = inspect_component(llvm)?;
    expect_runtime(
        llvm.label,
        &llvm_runtime,
        None,
        "$ORIGIN/../lib",
        &[
            "librt.so.1",
            "libdl.so.2",
            "libpthread.so.0",
            "libm.so.6",
            "libz.so.1",
            "libgcc_s.so.1",
            "libc.so.6",
            "ld-linux-x86-64.so.2",
        ],
    )?;
    verify_local_resolution(sysroot, &llvm.path, &llvm_runtime, &[])
}

fn inspect_component(component: &ArtifactComponent) -> Result<RuntimeMetadata, Failure> {
    let mut file = open_stable_regular_file(&component.path, component.label)?;
    let runtime = inspect(&mut file, component.label)?;
    verify_open_file_identity(&file, &component.path, component.label)?;
    Ok(runtime)
}

fn expect_runtime(
    label: &str,
    actual: &RuntimeMetadata,
    interpreter: Option<&str>,
    runpath: &str,
    needed: &[&str],
) -> Result<(), Failure> {
    if actual.interpreter.as_deref() != interpreter
        || actual.runpath != runpath
        || !actual
            .needed
            .iter()
            .map(String::as_str)
            .eq(needed.iter().copied())
    {
        return Err(Failure::task(format!(
            "accepted {label} runtime dependency metadata does not match the pinned contract"
        )));
    }
    Ok(())
}

fn verify_local_resolution(
    sysroot: &Path,
    executable: &Path,
    runtime: &RuntimeMetadata,
    expected_local: &[(&str, &PathBuf)],
) -> Result<(), Failure> {
    let origin = executable
        .parent()
        .ok_or_else(|| Failure::task("accepted executable has no parent directory"))?;
    let directories = runtime
        .runpath
        .split(':')
        .map(|entry| expand_origin_path(sysroot, origin, entry))
        .collect::<Result<Vec<_>, _>>()?;
    for needed in &runtime.needed {
        let expected = expected_local
            .iter()
            .find_map(|(name, path)| (*name == needed).then_some(path.as_path()));
        let mut resolved = None;
        for directory in &directories {
            let candidate = directory.join(needed);
            match fs::symlink_metadata(&candidate) {
                Ok(_) => {
                    if resolved.replace(candidate).is_some() {
                        return Err(Failure::task(format!(
                            "accepted runtime dependency '{needed}' has multiple toolchain-local resolutions"
                        )));
                    }
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(Failure::task(format!(
                        "could not inspect runtime dependency '{needed}': {error}"
                    )));
                }
            }
        }
        match (expected, resolved) {
            (Some(expected), Some(actual)) if actual == expected => {}
            (Some(_), _) => {
                return Err(Failure::task(format!(
                    "accepted runtime dependency '{needed}' does not resolve to its pinned toolchain component"
                )));
            }
            (None, Some(actual)) => {
                return Err(Failure::task(format!(
                    "ambient system dependency '{needed}' is shadowed inside the toolchain at {}",
                    actual.display()
                )));
            }
            (None, None) => {}
        }
    }
    Ok(())
}

fn expand_origin_path(sysroot: &Path, origin: &Path, entry: &str) -> Result<PathBuf, Failure> {
    let suffix = entry
        .strip_prefix("$ORIGIN")
        .ok_or_else(|| Failure::task(format!("unsupported accepted RUNPATH entry '{entry}'")))?;
    if !suffix.is_empty() && !suffix.starts_with('/') {
        return Err(Failure::task(format!(
            "unsupported accepted RUNPATH entry '{entry}'"
        )));
    }
    let mut path = origin.to_path_buf();
    for component in Path::new(suffix.trim_start_matches('/')).components() {
        match component {
            PathComponent::Normal(component) => path.push(component),
            PathComponent::ParentDir => {
                if !path.pop() || !path.starts_with(sysroot) {
                    return Err(Failure::task(format!(
                        "accepted RUNPATH entry '{entry}' escapes the toolchain"
                    )));
                }
            }
            _ => {
                return Err(Failure::task(format!(
                    "unsupported accepted RUNPATH entry '{entry}'"
                )));
            }
        }
    }
    if !path.starts_with(sysroot) {
        return Err(Failure::task(format!(
            "accepted RUNPATH entry '{entry}' escapes the toolchain"
        )));
    }
    Ok(path)
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
    reject_symlink_components(root, &component.path, component.label)?;
    let mut file = open_stable_regular_file(&component.path, component.label)?;
    let actual = reader_digest(&mut file).map_err(|error| {
        Failure::task(format!(
            "could not hash accepted {}: {error}",
            component.label
        ))
    })?;
    verify_open_file_identity(&file, &component.path, component.label)?;
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
            "{label} is not a regular non-symlink file"
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
        ArtifactComponent, CONSUMER_REQUEST, COORDINATOR_REQUEST, contained_path,
        open_stable_regular_file, parse_manifest, prepare, validate_component,
        validate_manifest_identity, verify_local_resolution, verify_open_file_identity,
    };
    use crate::elf_runtime::RuntimeMetadata;
    use crate::sha256::bytes_digest;
    use std::fs;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    const NAME: &str = "wyrmroot-1.97.1-a92dc7f7";
    const COMMIT: &str = "a92dc7f7464ad6ddfece4402bd7b86dbfa86166d";

    #[test]
    #[ignore = "requires WYRMROOT_RUSTC pointing to the coordinator-accepted immutable artifact"]
    fn accepted_toolchain_positive_gate() {
        let rustc = std::env::var_os("WYRMROOT_RUSTC")
            .map(std::path::PathBuf::from)
            .expect("WYRMROOT_RUSTC is required for the ignored acceptance gate");
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("repository root");
        let accepted = prepare(repository, &rustc, NAME, COMMIT)
            .expect("coordinator-accepted immutable toolchain failed validation");
        accepted
            .verify_unchanged()
            .expect("accepted toolchain drifted after validation");
    }

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
            sha256: bytes_digest(b"trusted"),
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

    #[cfg(unix)]
    #[test]
    fn selected_component_resolution_never_crosses_an_ancestor_symlink() {
        use std::os::unix::fs::symlink;

        let root = temporary_root("ancestor-symlink");
        let outside = temporary_root("ancestor-symlink-outside");
        fs::create_dir(&root).expect("create synthetic artifact root");
        fs::create_dir(&outside).expect("create synthetic outside directory");
        fs::write(outside.join("cargo"), b"sentinel").expect("write outside component");
        symlink(&outside, root.join("bin")).expect("create ancestor symlink");
        assert!(contained_path(&root, "bin/cargo", "test cargo").is_err());
        fs::remove_dir_all(root).expect("remove synthetic artifact root");
        fs::remove_dir_all(outside).expect("remove synthetic outside directory");
    }

    #[test]
    fn manifest_read_detects_a_path_swap_after_open() {
        let root = temporary_root("manifest-path-swap");
        fs::create_dir(&root).expect("create synthetic artifact root");
        let path = root.join("manifest.toml");
        fs::write(&path, b"trusted").expect("write trusted manifest");
        let open = open_stable_regular_file(&path, "test manifest").expect("open trusted manifest");
        fs::rename(&path, root.join("original.toml")).expect("move open manifest");
        fs::write(&path, b"replacement").expect("install replacement manifest");
        assert!(verify_open_file_identity(&open, &path, "test manifest").is_err());
        fs::remove_dir_all(root).expect("remove synthetic artifact root");
    }

    #[test]
    fn runtime_resolution_rejects_toolchain_shadowing_of_system_libraries() {
        let root = temporary_root("runtime-shadow");
        fs::create_dir_all(root.join("bin")).expect("create synthetic executable directory");
        fs::create_dir(root.join("lib")).expect("create synthetic library directory");
        let executable = root.join("bin/rustc");
        fs::write(&executable, b"fixture").expect("write synthetic executable");
        let runtime = RuntimeMetadata {
            interpreter: Some(super::SYSTEM_INTERPRETER.to_owned()),
            runpath: "$ORIGIN/../lib".to_owned(),
            needed: vec!["libc.so.6".to_owned()],
        };
        verify_local_resolution(&root, &executable, &runtime, &[])
            .expect("unshadowed system dependency rejected");
        fs::write(root.join("lib/libc.so.6"), b"shadow").expect("write shadow system library");
        assert!(verify_local_resolution(&root, &executable, &runtime, &[]).is_err());
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
source_tree = "aa3d5f9d1311772c99e385067d07641c01b8d203"
source_dirty = false
source_modified = false
bootstrap_stage = 1
host = "x86_64-unknown-linux-gnu"
targets = [
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-wyrmroot",
    "x86_64-unknown-uefi",
    "x86_64-unknown-none",
]

[build]
status = "passed"
rust_source_changes = false

[acceptance]
rustc_identity = "passed"
target_specs = "passed"
uefi_sysroot_presence = "passed"
none_sysroot_presence = "passed"
wyrmroot_sysroot_presence = "passed"
"#
        )
    }
}
