use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Take, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::error::Failure;
use crate::sha256::bytes_digest;

const PACKAGE_NAME: &str = "deepwyrm-abi";
const PACKAGE_MANIFEST: &str = "crates/deepwyrm-abi/Cargo.toml";
const SYSCALL_PACKAGE_NAME: &str = "deepwyrm-syscall";
const SYSCALL_PACKAGE_MANIFEST: &str = "crates/deepwyrm-syscall/Cargo.toml";
const LAYOUT_PATH: &str = "kernel/arch/x86_64/layout.toml";
const GENERATED_POLICY_PATH: &str = "target/wyr0-b/generated/deepwyrm_layout_policy.rs";
const MAX_LAYOUT_BYTES: u64 = 1024 * 1024;
const MAX_METADATA_STDOUT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_METADATA_STDERR_BYTES: u64 = 1024 * 1024;
const METADATA_COMMAND_DEADLINE: Duration = Duration::from_secs(60);
const MAX_GIT_ROOT_STDOUT_BYTES: u64 = 4096;
const MAX_GIT_REVISION_STDOUT_BYTES: u64 = 64;
const MAX_GIT_STATUS_STDOUT_BYTES: u64 = 1024;
const MAX_GIT_PATH_STDOUT_BYTES: u64 = 256;
const MAX_GIT_STDERR_BYTES: u64 = 64 * 1024;
const MAX_GIT_ARCHIVE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_GIT_TREE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_GIT_BLOB_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TRACKED_SOURCE_BYTES: u64 = 128 * 1024 * 1024;
const GIT_COMMAND_DEADLINE: Duration = Duration::from_secs(10);
const GIT_ARCHIVE_DEADLINE: Duration = Duration::from_secs(30);
pub(crate) const FIXED_GIT: &str = "/usr/libexec/git-core/git";
const MAX_METADATA_JSON_DEPTH: usize = 32;
const MAX_METADATA_JSON_VALUES: usize = 262_144;
const MAX_METADATA_CONTAINER_ENTRIES: usize = 65_536;
const MAX_METADATA_STRING_BYTES: usize = 64 * 1024;

pub(crate) const LAYOUT_SCHEMA: &str = "deepwyrm-x86_64-layout";
pub(crate) const LAYOUT_VERSION: u64 = 2;
pub(crate) const TRANSITION_TABLE_CONTRACT: &str = "DW_BOOT_X86_64_PAGING_HANDOFF_V1";
pub(crate) const GENERATED_POLICY_CONTRACT: &str = "wyrmroot-deep-layout-policy-v2";
pub(crate) const GENERATED_POLICY_VALIDATION_SCOPE: &str =
    "exact-layout-schema-fields-and-semantic-constraints";
pub(crate) const GENERATED_ABI_ASSERTION_SCOPE: &str =
    "base-page-and-paging-handoff-numeric-constants";
const KERNEL_BOOT_STACK_BYTES: u64 = 4 * 1024 * 1024;

pub(crate) struct DeepLayoutBuild {
    pub(crate) policy_path: PathBuf,
    pub(crate) layout_sha256: String,
    pub(crate) policy_sha256: String,
    source_root: PathBuf,
    expected_revision: String,
}

pub(crate) struct CargoGitSourceIdentity {
    repository: PathBuf,
    source_root: PathBuf,
    cargo_home: PathBuf,
    expected_revision: String,
    tree: String,
    archive_sha256: String,
    git_sha256: String,
    cargo_config_sha256: String,
}

struct GitSourceState {
    tree: String,
    archive_sha256: String,
    git_sha256: String,
}

impl CargoGitSourceIdentity {
    pub(crate) fn tree(&self) -> &str {
        &self.tree
    }

    pub(crate) fn archive_sha256(&self) -> &str {
        &self.archive_sha256
    }

    pub(crate) fn git_sha256(&self) -> &str {
        &self.git_sha256
    }

    pub(crate) fn cargo_config_sha256(&self) -> &str {
        &self.cargo_config_sha256
    }

    pub(crate) fn verify_unchanged(&self) -> Result<(), Failure> {
        let current = verify_exact_cargo_git_source(
            &self.source_root,
            &self.cargo_home,
            &self.expected_revision,
        )?;
        let cargo_config_sha256 = verify_cargo_configuration(&self.repository, &self.cargo_home)?;
        if current.tree != self.tree
            || current.archive_sha256 != self.archive_sha256
            || current.git_sha256 != self.git_sha256
            || cargo_config_sha256 != self.cargo_config_sha256
        {
            return Err(Failure::task(
                "Cargo-selected Deepwyrm source identity changed",
            ));
        }
        Ok(())
    }
}

pub(crate) fn inspect_cargo_git_source(
    repository: &Path,
    cargo: &Path,
    rustc: &Path,
    cargo_home: &Path,
    temp_directory: &Path,
    expected_repository: &str,
    expected_revision: &str,
) -> Result<CargoGitSourceIdentity, Failure> {
    validate_regular_file(cargo, "accepted Cargo")?;
    validate_regular_file(rustc, "accepted rustc")?;
    validate_directory(cargo_home, "project Cargo home")?;
    validate_directory(temp_directory, "E6 dependency metadata temporary directory")?;
    for (path, label) in [
        (cargo, "accepted Cargo"),
        (rustc, "accepted rustc"),
        (cargo_home, "project Cargo home"),
        (temp_directory, "E6 dependency metadata temporary directory"),
    ] {
        if fs::canonicalize(path)
            .map_err(|error| Failure::task(format!("could not resolve {label}: {error}")))?
            != path
        {
            return Err(Failure::task(format!("{label} path is not canonical")));
        }
    }
    if !temp_directory.starts_with(repository) {
        return Err(Failure::task(
            "E6 dependency metadata temporary directory is outside the Wyrmroot source",
        ));
    }
    let cargo_config_sha256 = verify_cargo_configuration(repository, cargo_home)?;
    let cargo_bin = cargo
        .parent()
        .ok_or_else(|| Failure::task("accepted Cargo has no parent directory"))?;
    let fixed_path = env::join_paths([
        cargo_bin,
        Path::new("/usr/lib/llvm/22/bin"),
        Path::new("/usr/bin"),
        Path::new("/bin"),
    ])
    .map_err(|_| Failure::task("accepted Cargo path cannot be encoded for subprocess use"))?;
    let metadata = exact_cargo_metadata(
        repository,
        cargo,
        rustc,
        cargo_home,
        temp_directory,
        &fixed_path,
    )?;
    let package = locate_package(&metadata, expected_repository, expected_revision)?;
    let syscall_package = locate_named_package(
        &metadata,
        expected_repository,
        expected_revision,
        SYSCALL_PACKAGE_NAME,
        SYSCALL_PACKAGE_MANIFEST,
    )?;
    let source_root = package
        .manifest_path
        .ancestors()
        .nth(3)
        .ok_or_else(|| Failure::task("deepwyrm-abi manifest has no source root"))?
        .to_path_buf();
    validate_regular_path(
        &source_root,
        &package.manifest_path,
        "deepwyrm-abi manifest",
    )?;
    if source_root.join(PACKAGE_MANIFEST) != package.manifest_path {
        return Err(Failure::task(format!(
            "deepwyrm-abi manifest is not at canonical repository path {PACKAGE_MANIFEST}"
        )));
    }
    if source_root.join(SYSCALL_PACKAGE_MANIFEST) != syscall_package.manifest_path {
        return Err(Failure::task(format!(
            "deepwyrm-syscall manifest is not at canonical repository path {SYSCALL_PACKAGE_MANIFEST}"
        )));
    }
    let syscall_root = syscall_package
        .manifest_path
        .ancestors()
        .nth(3)
        .ok_or_else(|| Failure::task("deepwyrm-syscall manifest has no source root"))?;
    if syscall_root != source_root {
        return Err(Failure::task(
            "deepwyrm-abi and deepwyrm-syscall resolve from different source checkouts",
        ));
    }
    let state = verify_exact_cargo_git_source(&source_root, cargo_home, expected_revision)?;
    Ok(CargoGitSourceIdentity {
        repository: repository.to_path_buf(),
        source_root,
        cargo_home: cargo_home.to_path_buf(),
        expected_revision: expected_revision.to_owned(),
        tree: state.tree,
        archive_sha256: state.archive_sha256,
        git_sha256: state.git_sha256,
        cargo_config_sha256,
    })
}

impl DeepLayoutBuild {
    pub(crate) fn verify_unchanged(&self) -> Result<(), Failure> {
        verify_git_source_identity(&self.source_root, &self.expected_revision)?;
        let layout_path = self.source_root.join(LAYOUT_PATH);
        validate_regular_path(&self.source_root, &layout_path, "Deepwyrm x86_64 layout")?;
        let layout_bytes = read_bounded(&layout_path, MAX_LAYOUT_BYTES, "Deepwyrm x86_64 layout")?;
        verify_tracked_bytes(&self.source_root, LAYOUT_PATH, &layout_bytes)?;
        let actual_layout = bytes_digest(&layout_bytes);
        if actual_layout != self.layout_sha256 {
            return Err(Failure::task(format!(
                "Deepwyrm x86_64 layout hash changed: {actual_layout}, expected {}",
                self.layout_sha256
            )));
        }
        verify_git_source_identity(&self.source_root, &self.expected_revision)?;
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
    write_generated_policy(repository, &policy_path, &generated)?;
    verify_git_source_identity(&source_root, expected_revision)?;

    let build = DeepLayoutBuild {
        policy_path,
        layout_sha256,
        policy_sha256,
        source_root,
        expected_revision: expected_revision.to_owned(),
    };
    build.verify_unchanged()?;
    Ok(build)
}

fn cargo_metadata(repository: &Path) -> Result<String, Failure> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsStr::new("cargo").to_owned());
    let output = bounded_command_output(
        Command::new(cargo)
            .args(["metadata", "--locked", "--format-version", "1"])
            .current_dir(repository)
            .stdin(Stdio::null()),
        MAX_METADATA_STDOUT_BYTES,
        MAX_METADATA_STDERR_BYTES,
        METADATA_COMMAND_DEADLINE,
        "locked Cargo metadata",
    )?;
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| Failure::task("locked Cargo metadata produced non-UTF-8 stdout"))?;
    if output.status.success() {
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(Failure::task(format!(
            "locked Cargo metadata failed with exit code {}{}",
            output.status.code().unwrap_or(-1),
            if stderr.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", stderr.trim())
            }
        )))
    }
}

fn exact_cargo_metadata(
    repository: &Path,
    cargo: &Path,
    rustc: &Path,
    cargo_home: &Path,
    temp_directory: &Path,
    fixed_path: &OsStr,
) -> Result<String, Failure> {
    let output = bounded_command_output(
        Command::new(cargo)
            .args(["metadata", "--offline", "--locked", "--format-version", "1"])
            .current_dir(repository)
            .env_clear()
            .env("PATH", fixed_path)
            .env("CARGO_HOME", cargo_home)
            .env("CARGO_NET_OFFLINE", "true")
            .env("CARGO_INCREMENTAL", "0")
            .env("RUSTC", rustc)
            .env("SOURCE_DATE_EPOCH", "0")
            .env("TMPDIR", temp_directory)
            .stdin(Stdio::null()),
        MAX_METADATA_STDOUT_BYTES,
        MAX_METADATA_STDERR_BYTES,
        METADATA_COMMAND_DEADLINE,
        "exact locked Cargo metadata",
    )?;
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| Failure::task("exact locked Cargo metadata produced non-UTF-8 stdout"))?;
    if output.status.success() {
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(Failure::task(format!(
            "exact locked Cargo metadata failed with exit code {}{}",
            output.status.code().unwrap_or(-1),
            if stderr.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", stderr.trim())
            }
        )))
    }
}

#[derive(Debug)]
struct BoundedCommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Clone, Copy)]
enum PipeStream {
    Stdout,
    Stderr,
}

enum CommandWorkerResult {
    Stdout(Result<BoundedPipe, Failure>),
    Stderr(Result<BoundedPipe, Failure>),
    Stdin(Result<(), Failure>),
}

fn bounded_command_output(
    command: &mut Command,
    stdout_maximum: u64,
    stderr_maximum: u64,
    deadline: Duration,
    label: &str,
) -> Result<BoundedCommandOutput, Failure> {
    bounded_command_output_inner(
        command,
        None,
        stdout_maximum,
        stderr_maximum,
        deadline,
        label,
    )
}

fn bounded_command_output_with_stdin(
    command: &mut Command,
    stdin_bytes: &[u8],
    stdout_maximum: u64,
    stderr_maximum: u64,
    deadline: Duration,
    label: &str,
) -> Result<BoundedCommandOutput, Failure> {
    bounded_command_output_inner(
        command,
        Some(stdin_bytes.to_vec()),
        stdout_maximum,
        stderr_maximum,
        deadline,
        label,
    )
}

fn bounded_command_output_inner(
    command: &mut Command,
    stdin_bytes: Option<Vec<u8>>,
    stdout_maximum: u64,
    stderr_maximum: u64,
    deadline: Duration,
    label: &str,
) -> Result<BoundedCommandOutput, Failure> {
    command.stdin(if stdin_bytes.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| Failure::task(format!("could not run {label}: {error}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Failure::task(format!("could not capture {label} stdout")))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| Failure::task(format!("could not capture {label} stderr")))?;
    let (limit_sender, limit_receiver) = mpsc::channel();
    let (worker_sender, worker_receiver) = mpsc::channel();
    let stdout_sender = limit_sender.clone();
    let stdout_worker_sender = worker_sender.clone();
    thread::spawn(move || {
        let result = read_pipe_bounded(
            stdout,
            stdout_maximum,
            "command stdout",
            Some((stdout_sender, PipeStream::Stdout)),
        );
        let _ = stdout_worker_sender.send(CommandWorkerResult::Stdout(result));
    });
    let stderr_worker_sender = worker_sender.clone();
    thread::spawn(move || {
        let result = read_pipe_bounded(
            stderr,
            stderr_maximum,
            "command stderr",
            Some((limit_sender, PipeStream::Stderr)),
        );
        let _ = stderr_worker_sender.send(CommandWorkerResult::Stderr(result));
    });
    let mut stdin_result = if let Some(bytes) = stdin_bytes {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| Failure::task(format!("could not open {label} stdin")))?;
        let stdin_worker_sender = worker_sender.clone();
        thread::spawn(move || {
            let result = stdin
                .write_all(&bytes)
                .map_err(|error| Failure::task(format!("could not write command stdin: {error}")));
            let _ = stdin_worker_sender.send(CommandWorkerResult::Stdin(result));
        });
        None
    } else {
        Some(Ok(()))
    };
    drop(worker_sender);

    let started = Instant::now();
    let mut status = None;
    let mut stdout_result = None;
    let mut stderr_result = None;
    loop {
        match limit_receiver.try_recv() {
            Ok(stream) => {
                if status.is_none() {
                    terminate_direct_child(
                        &mut child,
                        label,
                        "after its output limit was exceeded",
                    )?;
                }
                // Do not join the reader threads on this failure path. A descendant may have
                // inherited the other pipe and kept it open; dropping the handles detaches the
                // already memory-bounded readers instead of reintroducing an unbounded wait.
                let stream = match stream {
                    PipeStream::Stdout => "stdout",
                    PipeStream::Stderr => "stderr",
                };
                return Err(Failure::task(format!(
                    "{label} {stream} exceeded its byte limit; the direct child was terminated and reaped when still running"
                )));
            }
            Err(mpsc::TryRecvError::Disconnected | mpsc::TryRecvError::Empty) => {}
        }

        while let Ok(result) = worker_receiver.try_recv() {
            match result {
                CommandWorkerResult::Stdout(result) => stdout_result = Some(result),
                CommandWorkerResult::Stderr(result) => stderr_result = Some(result),
                CommandWorkerResult::Stdin(result) => stdin_result = Some(result),
            }
        }
        if status.is_none() {
            status = child
                .try_wait()
                .map_err(|error| Failure::task(format!("could not poll {label}: {error}")))?;
        }
        if status.is_some()
            && stdout_result.is_some()
            && stderr_result.is_some()
            && stdin_result.is_some()
        {
            break;
        }
        if started.elapsed() >= deadline {
            if status.is_none() {
                terminate_direct_child(&mut child, label, "after its wall-clock deadline")?;
            }
            // Safe std APIs can terminate only the direct child. A same-user descendant may
            // inherit a pipe and outlive it, so never wait for detached pipe workers here.
            return Err(Failure::task(format!(
                "{label} exceeded its {} ms wall-clock deadline; the direct child was terminated and reaped when still running",
                deadline.as_millis()
            )));
        }
        thread::sleep(Duration::from_millis(1));
    }
    let status = status.ok_or_else(|| {
        Failure::task(format!("{label} completed without a captured exit status"))
    })?;
    let stdout = stdout_result
        .ok_or_else(|| Failure::task(format!("{label} completed without captured stdout")))??;
    let stderr = stderr_result
        .ok_or_else(|| Failure::task(format!("{label} completed without captured stderr")))??;
    stdin_result
        .ok_or_else(|| Failure::task(format!("{label} completed without closing stdin")))??;
    if stdout.exceeded {
        return Err(Failure::task(format!(
            "{label} stdout exceeds the {stdout_maximum}-byte limit"
        )));
    }
    if stderr.exceeded {
        return Err(Failure::task(format!(
            "{label} stderr exceeds the {stderr_maximum}-byte limit"
        )));
    }
    Ok(BoundedCommandOutput {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
    })
}

fn terminate_direct_child(child: &mut Child, label: &str, reason: &str) -> Result<(), Failure> {
    if let Err(kill_error) = child.kill()
        && child
            .try_wait()
            .map_err(|error| {
                Failure::task(format!(
                    "could not inspect {label} after termination failed: {error}"
                ))
            })?
            .is_none()
    {
        return Err(Failure::task(format!(
            "could not terminate {label} {reason}: {kill_error}"
        )));
    }
    child
        .wait()
        .map_err(|error| Failure::task(format!("could not reap {label} {reason}: {error}")))?;
    Ok(())
}

struct BoundedPipe {
    bytes: Vec<u8>,
    exceeded: bool,
}

fn read_pipe_bounded<R: Read>(
    mut reader: R,
    maximum: u64,
    label: &str,
    limit_signal: Option<(mpsc::Sender<PipeStream>, PipeStream)>,
) -> Result<BoundedPipe, Failure> {
    let mut bytes = Vec::new();
    (&mut reader)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| Failure::task(format!("could not read {label}: {error}")))?;
    let exceeded = bytes.len() as u64 > maximum;
    if exceeded {
        bytes.truncate(maximum as usize);
        if let Some((sender, stream)) = limit_signal {
            let _ = sender.send(stream);
        }
    }
    Ok(BoundedPipe { bytes, exceeded })
}

struct PackageSource {
    manifest_path: PathBuf,
}

fn locate_package(
    metadata: &str,
    expected_repository: &str,
    expected_revision: &str,
) -> Result<PackageSource, Failure> {
    locate_named_package(
        metadata,
        expected_repository,
        expected_revision,
        PACKAGE_NAME,
        PACKAGE_MANIFEST,
    )
}

fn locate_named_package(
    metadata: &str,
    expected_repository: &str,
    expected_revision: &str,
    package_name: &str,
    package_manifest: &str,
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
        if package.object_field("name")?.as_string("package name")? != package_name {
            continue;
        }
        if selected.is_some() {
            return Err(Failure::task(
                "locked Cargo metadata contains multiple {package_name} packages",
            ));
        }
        let source = package.object_field("source")?;
        let actual_source = source.as_string("Deepwyrm package source").map_err(|_| {
            Failure::task(
                format!("{package_name} must resolve from the exact pinned Git source, not a path or registry"),
            )
        })?;
        if actual_source != expected_source {
            return Err(Failure::task(format!(
                "{package_name} source is '{actual_source}', expected exact locked source '{expected_source}'"
            )));
        }
        let manifest = package
            .object_field("manifest_path")?
            .as_string("Deepwyrm package manifest path")?;
        let manifest_path = PathBuf::from(manifest);
        validate_named_metadata_manifest_path(&manifest_path, package_manifest)?;
        selected = Some(PackageSource { manifest_path });
    }
    selected.ok_or_else(|| {
        Failure::task(format!(
            "locked Cargo metadata does not contain the pinned {package_name} package"
        ))
    })
}

#[cfg(test)]
fn validate_metadata_manifest_path(path: &Path) -> Result<(), Failure> {
    validate_named_metadata_manifest_path(path, PACKAGE_MANIFEST)
}

fn validate_named_metadata_manifest_path(
    path: &Path,
    expected_manifest: &str,
) -> Result<(), Failure> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        || !path.ends_with(expected_manifest)
    {
        return Err(Failure::task(format!(
            "Deepwyrm metadata manifest path is not absolute, non-traversing, and suffixed by {expected_manifest}: {}",
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
    let root_output = git_output_bounded(
        manifest_directory,
        ["rev-parse", "--show-toplevel"],
        MAX_GIT_ROOT_STDOUT_BYTES,
        "Deepwyrm Git source root inspection",
    )?;
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
    let revision = git_output_bounded(
        root,
        ["rev-parse", "HEAD"],
        MAX_GIT_REVISION_STDOUT_BYTES,
        "Deepwyrm Git revision inspection",
    )?;
    if revision.trim() != expected_revision {
        return Err(Failure::task(format!(
            "deepwyrm-abi source checkout revision is '{}', expected '{}'",
            revision.trim(),
            expected_revision
        )));
    }
    let status = git_output_bounded(
        root,
        ["status", "--porcelain=v1", "--untracked-files=all"],
        MAX_GIT_STATUS_STDOUT_BYTES,
        "Deepwyrm Git status inspection",
    )?;
    validate_git_status(root, &status)
}

fn verify_exact_cargo_git_source(
    root: &Path,
    cargo_home: &Path,
    expected_revision: &str,
) -> Result<GitSourceState, Failure> {
    validate_directory(root, "Cargo-selected Deepwyrm source root")?;
    let canonical_root = fs::canonicalize(root).map_err(|error| {
        Failure::task(format!(
            "could not canonicalize Cargo-selected Deepwyrm source root: {error}"
        ))
    })?;
    if canonical_root != root {
        return Err(Failure::task(
            "Cargo-selected Deepwyrm source root is not canonical",
        ));
    }
    validate_cargo_owned_path(cargo_home, root, Path::new("git/checkouts"), "checkout")?;
    let fixed_git = Path::new(FIXED_GIT);
    validate_regular_file(fixed_git, "fixed Git")?;
    if fs::canonicalize(fixed_git)
        .map_err(|error| Failure::task(format!("could not resolve fixed Git: {error}")))?
        != fixed_git
    {
        return Err(Failure::task("fixed Git path is not canonical"));
    }
    let git_sha256 = crate::sha256::file_digest(fixed_git)
        .map_err(|error| Failure::task(format!("could not hash fixed Git: {error}")))?;
    let git_directory = resolve_checkout_git_directory(root, cargo_home)?;
    reject_path_presence(
        &git_directory.join("info/attributes"),
        "Cargo-selected Deepwyrm Git attribute overlay",
    )?;
    reject_local_git_includes(&git_directory, cargo_home)?;
    let revision = fixed_git_output_bounded(
        root,
        cargo_home,
        ["rev-parse", "HEAD"],
        MAX_GIT_REVISION_STDOUT_BYTES,
        "Cargo-selected Deepwyrm revision inspection",
    )?;
    if revision.trim() != expected_revision {
        return Err(Failure::task(format!(
            "Cargo-selected Deepwyrm revision is '{}', expected '{}'",
            revision.trim(),
            expected_revision
        )));
    }
    let status = fixed_git_output_bounded(
        root,
        cargo_home,
        ["status", "--porcelain=v1", "--untracked-files=all"],
        MAX_GIT_STATUS_STDOUT_BYTES,
        "Cargo-selected Deepwyrm status inspection",
    )?;
    validate_git_status(root, &status)?;
    let reported_git_directory = fixed_git_output_bounded(
        root,
        cargo_home,
        ["rev-parse", "--absolute-git-dir"],
        MAX_GIT_ROOT_STDOUT_BYTES,
        "Cargo-selected Deepwyrm Git directory inspection",
    )?;
    if Path::new(reported_git_directory.trim()) != git_directory {
        return Err(Failure::task(
            "Git reports a different directory than the validated checkout metadata",
        ));
    }
    let tree = fixed_git_output_bounded(
        root,
        cargo_home,
        ["rev-parse", "HEAD^{tree}"],
        MAX_GIT_REVISION_STDOUT_BYTES,
        "Cargo-selected Deepwyrm tree inspection",
    )?;
    let tree = tree.trim().to_owned();
    if tree.len() != 40
        || !tree
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(Failure::task(
            "Cargo-selected Deepwyrm tree identity is invalid",
        ));
    }
    verify_git_index_flags(root, cargo_home)?;
    verify_worktree_matches_head(root, cargo_home)?;
    let archive = bounded_command_output(
        hardened_fixed_git(root, cargo_home).args(["archive", "--format=tar", "HEAD"]),
        MAX_GIT_ARCHIVE_BYTES,
        MAX_GIT_STDERR_BYTES,
        GIT_ARCHIVE_DEADLINE,
        "Cargo-selected Deepwyrm source archive",
    )?;
    if !archive.status.success() {
        return Err(Failure::task(format!(
            "Cargo-selected Deepwyrm source archive failed with exit code {}",
            archive.status.code().unwrap_or(-1)
        )));
    }
    if !archive.stderr.is_empty() {
        return Err(Failure::task(
            "Cargo-selected Deepwyrm source archive produced stderr",
        ));
    }
    let archive_sha256 = bytes_digest(&archive.stdout);
    if crate::sha256::file_digest(fixed_git)
        .map_err(|error| Failure::task(format!("could not rehash fixed Git: {error}")))?
        != git_sha256
    {
        return Err(Failure::task(
            "fixed Git changed during source verification",
        ));
    }
    let identity = GitSourceState {
        tree,
        archive_sha256,
        git_sha256,
    };
    Ok(identity)
}

fn resolve_checkout_git_directory(root: &Path, cargo_home: &Path) -> Result<PathBuf, Failure> {
    let dot_git = root.join(".git");
    let metadata = fs::symlink_metadata(&dot_git).map_err(|error| {
        Failure::task(format!("could not inspect Cargo checkout .git: {error}"))
    })?;
    let root_owner = fs::symlink_metadata(root)
        .map_err(|error| Failure::task(format!("could not inspect Cargo checkout: {error}")))?
        .uid();
    if metadata.file_type().is_symlink() || metadata.uid() != root_owner {
        return Err(Failure::task(
            "Cargo checkout .git is not owned or is a symlink",
        ));
    }
    let git_directory = if metadata.is_dir() {
        validate_cargo_owned_path(root, &dot_git, Path::new(".git"), "Git directory")?;
        dot_git
    } else if metadata.is_file() {
        let contents = read_bounded(&dot_git, MAX_GIT_ROOT_STDOUT_BYTES, "Cargo checkout .git")?;
        let contents = std::str::from_utf8(&contents)
            .map_err(|_| Failure::task("Cargo checkout .git is not UTF-8"))?;
        let value = contents
            .strip_prefix("gitdir: ")
            .and_then(|value| value.strip_suffix('\n').or(Some(value)))
            .ok_or_else(|| Failure::task("Cargo checkout .git has invalid syntax"))?;
        if value.is_empty() || value.contains('\n') || value.contains('\r') {
            return Err(Failure::task("Cargo checkout .git has invalid syntax"));
        }
        let value = Path::new(value);
        if value
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        {
            return Err(Failure::task("Cargo checkout .git path contains traversal"));
        }
        let candidate = if value.is_absolute() {
            value.to_path_buf()
        } else {
            root.join(value)
        };
        let canonical = fs::canonicalize(&candidate).map_err(|error| {
            Failure::task(format!(
                "could not resolve Cargo checkout Git directory: {error}"
            ))
        })?;
        if canonical != candidate {
            return Err(Failure::task(
                "Cargo checkout Git directory path is not canonical",
            ));
        }
        validate_cargo_owned_path(cargo_home, &canonical, Path::new("git/db"), "Git database")?;
        canonical
    } else {
        return Err(Failure::task(
            "Cargo checkout .git is not a regular file or directory",
        ));
    };
    Ok(git_directory)
}

fn reject_local_git_includes(git_directory: &Path, temp_directory: &Path) -> Result<(), Failure> {
    let config = git_directory.join("config");
    validate_regular_path(
        git_directory,
        &config,
        "Cargo checkout local Git configuration",
    )?;
    let directory_owner = fs::symlink_metadata(git_directory)
        .map_err(|error| Failure::task(format!("could not inspect Git directory: {error}")))?
        .uid();
    let config_owner = fs::symlink_metadata(&config)
        .map_err(|error| Failure::task(format!("could not inspect local Git config: {error}")))?
        .uid();
    if config_owner != directory_owner {
        return Err(Failure::task(
            "Cargo checkout local Git configuration has an unexpected owner",
        ));
    }
    let output = bounded_command_output(
        hardened_fixed_git_without_repository(temp_directory)
            .args(["config", "--file"])
            .arg(&config)
            .args(["--no-includes", "--name-only", "--null", "--list"]),
        MAX_GIT_TREE_BYTES,
        MAX_GIT_STDERR_BYTES,
        GIT_COMMAND_DEADLINE,
        "Cargo checkout local Git configuration inspection",
    )?;
    if !output.status.success() {
        return Err(Failure::task(format!(
            "Cargo checkout local Git configuration inspection failed with exit code {}",
            output.status.code().unwrap_or(-1)
        )));
    }
    if !output.stderr.is_empty() {
        return Err(Failure::task(
            "Cargo checkout local Git configuration inspection produced stderr",
        ));
    }
    for name in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        let name = std::str::from_utf8(name)
            .map_err(|_| Failure::task("local Git configuration name is not UTF-8"))?
            .to_ascii_lowercase();
        if name == "include.path" || (name.starts_with("includeif.") && name.ends_with(".path")) {
            return Err(Failure::task(
                "Cargo checkout local Git configuration contains an external include",
            ));
        }
    }
    Ok(())
}

fn verify_cargo_configuration(repository: &Path, cargo_home: &Path) -> Result<String, Failure> {
    let repository_config = repository.join(".cargo/config.toml");
    validate_regular_path(
        repository,
        &repository_config,
        "Wyrmroot Cargo configuration",
    )?;
    reject_path_presence(
        &repository.join(".cargo/config"),
        "legacy repository Cargo config",
    )?;
    for candidate in [cargo_home.join("config"), cargo_home.join("config.toml")] {
        reject_path_presence(&candidate, "Cargo-home configuration")?;
    }
    let mut ancestor = repository.parent();
    while let Some(directory) = ancestor {
        for name in ["config", "config.toml"] {
            reject_path_presence(
                &directory.join(".cargo").join(name),
                "ancestor Cargo configuration",
            )?;
        }
        ancestor = directory.parent();
    }
    crate::sha256::file_digest(&repository_config).map_err(|error| {
        Failure::task(format!(
            "could not hash Wyrmroot Cargo configuration: {error}"
        ))
    })
}

fn reject_path_presence(path: &Path, label: &str) -> Result<(), Failure> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(Failure::task(format!(
            "E6 product rejects {label} at {}",
            path.display()
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Failure::task(format!(
            "could not inspect {label} at {}: {error}",
            path.display()
        ))),
    }
}

#[derive(Clone)]
struct TrackedSource {
    path: PathBuf,
    object: String,
    executable: bool,
}

fn verify_git_index_flags(root: &Path, cargo_home: &Path) -> Result<(), Failure> {
    let tree = read_head_tree(root, cargo_home)?;
    let output = fixed_git_bytes_bounded(
        root,
        cargo_home,
        ["ls-files", "-v", "-z", "--full-name"],
        MAX_GIT_TREE_BYTES,
        "Cargo-selected Deepwyrm index flag inspection",
    )?;
    let mut paths = BTreeSet::new();
    for record in output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        if !record.starts_with(b"H ") {
            return Err(Failure::task(
                "Cargo-selected Deepwyrm index contains assume-unchanged, skip-worktree, or non-canonical state",
            ));
        }
        let path = std::str::from_utf8(&record[2..])
            .map_err(|_| Failure::task("Cargo-selected Deepwyrm index path is not UTF-8"))?;
        let path = validate_relative_source_path(path)?;
        if !paths.insert(path) {
            return Err(Failure::task(
                "Cargo-selected Deepwyrm index repeats a tracked path",
            ));
        }
    }
    let expected = tree
        .into_iter()
        .map(|entry| entry.path)
        .collect::<BTreeSet<_>>();
    if paths != expected {
        return Err(Failure::task(
            "Cargo-selected Deepwyrm index path set differs from HEAD",
        ));
    }
    Ok(())
}

fn verify_worktree_matches_head(root: &Path, cargo_home: &Path) -> Result<(), Failure> {
    let tracked = read_head_tree(root, cargo_home)?;
    let tracked_paths = tracked
        .iter()
        .map(|entry| entry.path.clone())
        .collect::<BTreeSet<_>>();
    let mut tracked_directories = BTreeSet::new();
    for path in &tracked_paths {
        let mut parent = path.parent();
        while let Some(directory) = parent {
            if directory.as_os_str().is_empty() {
                break;
            }
            tracked_directories.insert(directory.to_path_buf());
            parent = directory.parent();
        }
    }
    verify_worktree_entries(root, root, &tracked_paths, &tracked_directories)?;
    let mut batch_input = Vec::with_capacity(tracked.len() * 41);
    for entry in &tracked {
        batch_input.extend_from_slice(entry.object.as_bytes());
        batch_input.push(b'\n');
    }
    let expected_blobs = fixed_git_bytes_with_stdin_bounded(
        root,
        cargo_home,
        ["cat-file", "--batch"],
        &batch_input,
        MAX_TRACKED_SOURCE_BYTES + MAX_GIT_TREE_BYTES,
        "Cargo-selected Deepwyrm object batch inspection",
    )?;
    let mut batch_offset = 0usize;
    let mut total = 0u64;
    for entry in tracked {
        let actual_path = root.join(&entry.path);
        let metadata = fs::symlink_metadata(&actual_path).map_err(|error| {
            Failure::task(format!(
                "could not inspect tracked Deepwyrm source {}: {error}",
                entry.path.display()
            ))
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(Failure::task(format!(
                "tracked Deepwyrm source is not a regular non-symlink file: {}",
                entry.path.display()
            )));
        }
        let executable = metadata.mode() & 0o111 != 0;
        if executable != entry.executable {
            return Err(Failure::task(format!(
                "tracked Deepwyrm source executable mode differs from HEAD: {}",
                entry.path.display()
            )));
        }
        total = total
            .checked_add(metadata.len())
            .ok_or_else(|| Failure::task("tracked Deepwyrm source size overflow"))?;
        if total > MAX_TRACKED_SOURCE_BYTES {
            return Err(Failure::task(
                "tracked Deepwyrm source exceeds its aggregate byte bound",
            ));
        }
        let actual = read_bounded(&actual_path, MAX_GIT_BLOB_BYTES, "tracked Deepwyrm source")?;
        let (expected, next_offset) = parse_batch_blob(&expected_blobs, batch_offset, &entry)?;
        batch_offset = next_offset;
        if actual != expected {
            return Err(Failure::task(format!(
                "tracked Deepwyrm worktree bytes differ from HEAD: {}",
                entry.path.display()
            )));
        }
    }
    if batch_offset != expected_blobs.len() {
        return Err(Failure::task(
            "Cargo-selected Deepwyrm object batch contains trailing bytes",
        ));
    }
    Ok(())
}

fn parse_batch_blob<'a>(
    output: &'a [u8],
    offset: usize,
    entry: &TrackedSource,
) -> Result<(&'a [u8], usize), Failure> {
    let header_end = output[offset..]
        .iter()
        .position(|byte| *byte == b'\n')
        .and_then(|relative| offset.checked_add(relative))
        .ok_or_else(|| Failure::task("truncated Deepwyrm cat-file batch header"))?;
    let header = std::str::from_utf8(&output[offset..header_end])
        .map_err(|_| Failure::task("Deepwyrm cat-file batch header is not UTF-8"))?;
    let mut fields = header.split(' ');
    let object = fields.next().unwrap_or_default();
    let kind = fields.next().unwrap_or_default();
    let size = fields
        .next()
        .ok_or_else(|| Failure::task("Deepwyrm cat-file batch header omits size"))?
        .parse::<usize>()
        .map_err(|_| Failure::task("Deepwyrm cat-file batch size is invalid"))?;
    if fields.next().is_some()
        || object != entry.object
        || kind != "blob"
        || size as u64 > MAX_GIT_BLOB_BYTES
    {
        return Err(Failure::task(
            "Deepwyrm cat-file batch header does not match HEAD",
        ));
    }
    let content_start = header_end
        .checked_add(1)
        .ok_or_else(|| Failure::task("Deepwyrm cat-file batch offset overflow"))?;
    let content_end = content_start
        .checked_add(size)
        .ok_or_else(|| Failure::task("Deepwyrm cat-file batch size overflow"))?;
    let next_offset = content_end
        .checked_add(1)
        .ok_or_else(|| Failure::task("Deepwyrm cat-file batch offset overflow"))?;
    if next_offset > output.len() || output[content_end] != b'\n' {
        return Err(Failure::task("truncated Deepwyrm cat-file batch object"));
    }
    Ok((&output[content_start..content_end], next_offset))
}

fn read_head_tree(root: &Path, cargo_home: &Path) -> Result<Vec<TrackedSource>, Failure> {
    let output = fixed_git_bytes_bounded(
        root,
        cargo_home,
        ["ls-tree", "-r", "-z", "--full-tree", "HEAD"],
        MAX_GIT_TREE_BYTES,
        "Cargo-selected Deepwyrm HEAD tree inspection",
    )?;
    let mut tracked = Vec::new();
    for record in output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| Failure::task("invalid Deepwyrm ls-tree record"))?;
        let header = std::str::from_utf8(&record[..tab])
            .map_err(|_| Failure::task("Deepwyrm ls-tree header is not UTF-8"))?;
        let mut fields = header.split(' ');
        let mode = fields.next().unwrap_or_default();
        let kind = fields.next().unwrap_or_default();
        let object = fields.next().unwrap_or_default();
        if fields.next().is_some()
            || !matches!(mode, "100644" | "100755")
            || kind != "blob"
            || object.len() != 40
            || !object.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(Failure::task(
                "Deepwyrm HEAD contains an unsupported tree entry",
            ));
        }
        let path = std::str::from_utf8(&record[tab + 1..])
            .map_err(|_| Failure::task("Deepwyrm tree path is not UTF-8"))?;
        tracked.push(TrackedSource {
            path: validate_relative_source_path(path)?,
            object: object.to_owned(),
            executable: mode == "100755",
        });
    }
    tracked.sort_by(|left, right| left.path.cmp(&right.path));
    if tracked.is_empty()
        || tracked
            .windows(2)
            .any(|entries| entries[0].path == entries[1].path)
    {
        return Err(Failure::task(
            "Deepwyrm HEAD tree is empty or contains duplicate paths",
        ));
    }
    Ok(tracked)
}

fn validate_relative_source_path(path: &str) -> Result<PathBuf, Failure> {
    let path = PathBuf::from(path);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || path.starts_with(".git")
        || path == Path::new(".cargo-ok")
    {
        return Err(Failure::task(
            "Deepwyrm source tree contains an invalid path",
        ));
    }
    Ok(path)
}

fn verify_worktree_entries(
    root: &Path,
    directory: &Path,
    tracked_paths: &BTreeSet<PathBuf>,
    tracked_directories: &BTreeSet<PathBuf>,
) -> Result<(), Failure> {
    let entries = fs::read_dir(directory).map_err(|error| {
        Failure::task(format!("could not enumerate Deepwyrm worktree: {error}"))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            Failure::task(format!(
                "could not inspect Deepwyrm worktree entry: {error}"
            ))
        })?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| Failure::task("Deepwyrm worktree entry escaped its root"))?;
        if relative == Path::new(".git") {
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                Failure::task(format!("could not inspect Deepwyrm .git: {error}"))
            })?;
            if metadata.file_type().is_symlink() || !(metadata.is_file() || metadata.is_dir()) {
                return Err(Failure::task(
                    "Deepwyrm .git is not a regular file or directory",
                ));
            }
            continue;
        }
        if relative == Path::new(".cargo-ok") {
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                Failure::task(format!("could not inspect Cargo checkout marker: {error}"))
            })?;
            if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != 0 {
                return Err(Failure::task(
                    "Cargo checkout .cargo-ok marker must be a regular non-symlink zero-byte file",
                ));
            }
            continue;
        }
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            Failure::task(format!(
                "could not inspect Deepwyrm worktree entry: {error}"
            ))
        })?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            if !tracked_directories.contains(relative) {
                return Err(Failure::task(format!(
                    "Deepwyrm worktree contains an untracked directory: {}",
                    relative.display()
                )));
            }
            verify_worktree_entries(root, &path, tracked_paths, tracked_directories)?;
        } else if !metadata.file_type().is_symlink()
            && metadata.is_file()
            && tracked_paths.contains(relative)
        {
            continue;
        } else {
            return Err(Failure::task(format!(
                "Deepwyrm worktree contains an untracked or unsupported entry: {}",
                relative.display()
            )));
        }
    }
    Ok(())
}

fn validate_cargo_owned_path(
    cargo_home: &Path,
    path: &Path,
    required_prefix: &Path,
    label: &str,
) -> Result<(), Failure> {
    let cargo_metadata = fs::symlink_metadata(cargo_home)
        .map_err(|error| Failure::task(format!("could not inspect project Cargo home: {error}")))?;
    let relative = path.strip_prefix(cargo_home).map_err(|_| {
        Failure::task(format!(
            "Cargo-selected Deepwyrm {label} is outside project Cargo home"
        ))
    })?;
    if !relative.starts_with(required_prefix) {
        return Err(Failure::task(format!(
            "Cargo-selected Deepwyrm {label} is outside {}",
            required_prefix.display()
        )));
    }
    let mut current = cargo_home.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(Failure::task(format!(
                "Cargo-selected Deepwyrm {label} path is not canonical"
            )));
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            Failure::task(format!(
                "could not inspect Cargo-selected Deepwyrm {label} path: {error}"
            ))
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != cargo_metadata.uid()
        {
            return Err(Failure::task(format!(
                "Cargo-selected Deepwyrm {label} path is not an owned non-symlink directory"
            )));
        }
    }
    Ok(())
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

fn git_output_bounded<I, S>(
    repository: &Path,
    arguments: I,
    stdout_maximum: u64,
    label: &str,
) -> Result<String, Failure>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = bounded_command_output(
        Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(arguments),
        stdout_maximum,
        MAX_GIT_STDERR_BYTES,
        GIT_COMMAND_DEADLINE,
        label,
    )?;
    output_stdout(output, label)
}

fn fixed_git_output_bounded<I, S>(
    repository: &Path,
    temp_directory: &Path,
    arguments: I,
    stdout_maximum: u64,
    label: &str,
) -> Result<String, Failure>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = bounded_command_output(
        hardened_fixed_git(repository, temp_directory).args(arguments),
        stdout_maximum,
        MAX_GIT_STDERR_BYTES,
        GIT_COMMAND_DEADLINE,
        label,
    )?;
    if output.status.success() && !output.stderr.is_empty() {
        return Err(Failure::task(format!("{label} produced stderr")));
    }
    output_stdout(output, label)
}

fn fixed_git_bytes_bounded<I, S>(
    repository: &Path,
    temp_directory: &Path,
    arguments: I,
    stdout_maximum: u64,
    label: &str,
) -> Result<Vec<u8>, Failure>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = bounded_command_output(
        hardened_fixed_git(repository, temp_directory).args(arguments),
        stdout_maximum,
        MAX_GIT_STDERR_BYTES,
        GIT_COMMAND_DEADLINE,
        label,
    )?;
    if !output.status.success() {
        return Err(Failure::task(format!(
            "{label} failed with exit code {}",
            output.status.code().unwrap_or(-1)
        )));
    }
    if !output.stderr.is_empty() {
        return Err(Failure::task(format!("{label} produced stderr")));
    }
    Ok(output.stdout)
}

fn fixed_git_bytes_with_stdin_bounded<I, S>(
    repository: &Path,
    temp_directory: &Path,
    arguments: I,
    stdin: &[u8],
    stdout_maximum: u64,
    label: &str,
) -> Result<Vec<u8>, Failure>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = bounded_command_output_with_stdin(
        hardened_fixed_git(repository, temp_directory).args(arguments),
        stdin,
        stdout_maximum,
        MAX_GIT_STDERR_BYTES,
        GIT_ARCHIVE_DEADLINE,
        label,
    )?;
    if !output.status.success() {
        return Err(Failure::task(format!(
            "{label} failed with exit code {}",
            output.status.code().unwrap_or(-1)
        )));
    }
    if !output.stderr.is_empty() {
        return Err(Failure::task(format!("{label} produced stderr")));
    }
    Ok(output.stdout)
}

fn hardened_fixed_git(repository: &Path, temp_directory: &Path) -> Command {
    let mut command = hardened_fixed_git_without_repository(temp_directory);
    command
        .arg("-C")
        .arg(repository)
        .args(["-c", "core.fsmonitor=false"])
        .args(["-c", "core.attributesFile=/dev/null"]);
    command
}

fn hardened_fixed_git_without_repository(temp_directory: &Path) -> Command {
    let mut command = Command::new(FIXED_GIT);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TMPDIR", temp_directory)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .stdin(Stdio::null());
    command
}

fn output_stdout(output: BoundedCommandOutput, label: &str) -> Result<String, Failure> {
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
    git_output_bounded(
        root,
        ["ls-files", "--error-unmatch", relative],
        MAX_GIT_PATH_STDOUT_BYTES,
        "Deepwyrm tracked layout path inspection",
    )?;
    let expected = git_output_bounded(
        root,
        ["rev-parse", &format!("HEAD:{relative}")],
        MAX_GIT_REVISION_STDOUT_BYTES,
        "Deepwyrm tracked layout revision inspection",
    )?;
    let actual = git_hash_bytes(root, bytes)?;
    if expected.trim() != actual.trim() {
        return Err(Failure::task(
            "Deepwyrm x86_64 layout content does not match the pinned Git revision",
        ));
    }
    Ok(())
}

fn git_hash_bytes(root: &Path, bytes: &[u8]) -> Result<String, Failure> {
    let output = bounded_command_output_with_stdin(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["hash-object", "--stdin"]),
        bytes,
        MAX_GIT_REVISION_STDOUT_BYTES,
        MAX_GIT_STDERR_BYTES,
        GIT_COMMAND_DEADLINE,
        "Deepwyrm layout byte hashing",
    )?;
    output_stdout(output, "Deepwyrm layout byte hashing")
}

fn write_generated_policy(repository: &Path, path: &Path, contents: &str) -> Result<(), Failure> {
    let directory = path
        .parent()
        .ok_or_else(|| Failure::task("generated layout policy has no parent directory"))?;
    let directory_identity = ensure_output_directory(
        repository,
        directory,
        "generated Deepwyrm layout policy directory",
    )?;
    validate_optional_regular_file(path, "generated Deepwyrm layout policy")?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| Failure::task(format!("system clock precedes Unix epoch: {error}")))?
        .as_nanos();
    let mut temporary = None;
    for attempt in 0_u8..16 {
        let candidate = directory.join(format!(
            ".deepwyrm_layout_policy.rs.tmp-{}-{nonce}-{attempt}",
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
                    "could not create exclusive generated policy temporary file: {error}"
                )));
            }
        }
    }
    let (temporary, mut file) = temporary.ok_or_else(|| {
        Failure::task("could not reserve a unique generated policy temporary file")
    })?;
    let result = (|| {
        file.write_all(contents.as_bytes()).map_err(|error| {
            Failure::task(format!(
                "could not write generated layout policy {}: {error}",
                temporary.display()
            ))
        })?;
        file.flush().map_err(|error| {
            Failure::task(format!(
                "could not flush generated layout policy {}: {error}",
                temporary.display()
            ))
        })?;
        verify_open_file_identity(&file, &temporary, "generated policy temporary file")?;
        verify_directory_identity(
            directory,
            &directory_identity,
            "generated Deepwyrm layout policy directory",
        )?;
        validate_optional_regular_file(path, "generated Deepwyrm layout policy")?;
        fs::rename(&temporary, path).map_err(|error| {
            Failure::task(format!(
                "could not install generated layout policy {}: {error}",
                path.display()
            ))
        })?;
        verify_directory_identity(
            directory,
            &directory_identity,
            "generated Deepwyrm layout policy directory",
        )?;
        let installed = read_bounded(path, MAX_LAYOUT_BYTES, "generated Deepwyrm layout policy")?;
        if installed != contents.as_bytes() {
            return Err(Failure::task(
                "installed generated Deepwyrm layout policy content changed",
            ));
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn ensure_output_directory(
    root: &Path,
    directory: &Path,
    label: &str,
) -> Result<fs::Metadata, Failure> {
    if !root.is_absolute() {
        return Err(Failure::task(format!("{label} root must be absolute")));
    }
    validate_directory(root, &format!("{label} root"))?;
    let canonical_root = fs::canonicalize(root)
        .map_err(|error| Failure::task(format!("could not canonicalize {label} root: {error}")))?;
    if canonical_root != root {
        return Err(Failure::task(format!(
            "{label} root is not canonical or contains a symlink"
        )));
    }
    let relative = directory
        .strip_prefix(root)
        .map_err(|_| Failure::task(format!("{label} is outside its trusted root")))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(Failure::task(format!(
                "{label} contains traversal or a non-normal component"
            )));
        };
        current.push(component);
        match fs::create_dir(&current) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(Failure::task(format!(
                    "could not create {label} {}: {error}",
                    current.display()
                )));
            }
        }
        validate_directory(&current, label)?;
    }
    fs::symlink_metadata(directory)
        .map_err(|error| Failure::task(format!("could not inspect {label}: {error}")))
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
            "{label} identity changed during generated output installation"
        )));
    }
    Ok(())
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
        expect_string(&mut values, "schema", LAYOUT_SCHEMA)?;
        expect_integer(&mut values, "version", LAYOUT_VERSION)?;
        expect_string(&mut values, "entry_contract", "DW_BOOT_X86_64_ENTRY_V1")?;
        expect_string(&mut values, "elf_type", "ET_EXEC")?;
        expect_string(&mut values, "entry_symbol", "_dw_kernel_entry")?;
        let link_base_text = take_string(&mut values, "link_base")?;
        let link_base = parse_hex_u64(&link_base_text, "link_base")?;
        let base_page_size = take_integer(&mut values, "base_page_size")?;
        if base_page_size != 4096 {
            return Err(Failure::task(
                "Deepwyrm base_page_size must remain the 4096-byte x86_64 base page",
            ));
        }
        expect_bool(&mut values, "red_zone", false)?;
        expect_integer(
            &mut values,
            "kernel_boot_stack_size",
            KERNEL_BOOT_STACK_BYTES,
        )?;
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
            ("handoff_mappings.referenced_ranges_mutable", false),
            ("handoff_mappings.page_zero_mapped", false),
            ("handoff_mappings.framebuffer_pixels_identity_mapped", false),
            ("transition_tables.pcide_enabled", false),
            ("transition_tables.pge_enabled", false),
        ] {
            expect_bool(&mut values, key, expected)?;
        }
        for (key, expected) in [
            ("transition_tables.identity_alias_mutable_by_deepwyrm", true),
            ("transition_tables.cr3_low_bits_zero", true),
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
            ("transition_tables.contract", TRANSITION_TABLE_CONTRACT),
            ("transition_tables.initial_leaf", "exactly-zero-non-present"),
            (
                "transition_tables.temporary_leaf_permissions",
                "supervisor-rw-nx-base-page",
            ),
            (
                "transition_tables.identity_alias_permissions",
                "supervisor-rw-nx-base-page",
            ),
            ("transition_tables.pat_entry_zero", "observed-write-back"),
            (
                "transition_tables.mtrr_policy",
                "alias-consistent-no-effective-write-back-claim",
            ),
            (
                "transition_tables.ownership_transfer",
                "loader-to-deepwyrm-after-exit-boot-services",
            ),
            ("transition_tables.lifetime", "until-deepwyrm-cr3-switch"),
            (
                "transition_tables.concurrency",
                "bsp-aps-off-if-clear-nonreentrant",
            ),
            (
                "transition_tables.physical_role_policy",
                "exclusive-table-frames-no-kernel-module-data-alias",
            ),
            (
                "transition_tables.new_root_table_access",
                "deepwyrm-owned-before-cr3-switch",
            ),
        ] {
            expect_string(&mut values, key, expected)?;
        }
        expect_integer(&mut values, "transition_tables.layout_version", 2)?;
        let temporary_page_count =
            take_integer(&mut values, "transition_tables.temporary_page_count")?;
        if temporary_page_count != 1 {
            return Err(Failure::task(
                "Deepwyrm transition-table temporary mapping must contain exactly one base page",
            ));
        }
        expect_integer(&mut values, "transition_tables.cache_selection_bits", 0)?;
        let temporary_address_text =
            take_string(&mut values, "transition_tables.temporary_virtual_address")?;
        let temporary_address = parse_hex_u64(
            &temporary_address_text,
            "transition_tables.temporary_virtual_address",
        )?;
        let declared_indices = [
            take_integer(&mut values, "transition_tables.pml4_index")?,
            take_integer(&mut values, "transition_tables.pdpt_index")?,
            take_integer(&mut values, "transition_tables.pd_index")?,
            take_integer(&mut values, "transition_tables.pt_index")?,
        ];
        let derived_indices = x86_64_page_table_indices(temporary_address);
        if declared_indices != derived_indices.map(u64::from) {
            return Err(Failure::task(
                "Deepwyrm transition-table indices do not match temporary_virtual_address",
            ));
        }
        let minimum_table_frames =
            take_integer(&mut values, "transition_tables.minimum_table_frame_count")?;
        let maximum_table_frames =
            take_integer(&mut values, "transition_tables.maximum_table_frame_count")?;
        if minimum_table_frames != declared_indices.len() as u64
            || maximum_table_frames < minimum_table_frames
            || maximum_table_frames > u64::from(u32::MAX)
        {
            return Err(Failure::task(
                "Deepwyrm transition-table frame bounds are inconsistent with four-level paging",
            ));
        }
        if !values.is_empty() {
            return Err(Failure::task(format!(
                "Deepwyrm layout contains unsupported or stale field '{}'",
                values.keys().next().expect("nonempty map")
            )));
        }
        if !is_upper_canonical_four_level(link_base) || link_base % base_page_size != 0 {
            return Err(Failure::task(
                "Deepwyrm link_base must be upper-canonical and base-page aligned",
            ));
        }
        let temporary_byte_len = temporary_page_count
            .checked_mul(base_page_size)
            .ok_or_else(|| Failure::task("Deepwyrm temporary mapping byte length overflows"))?;
        if !is_upper_canonical_four_level(temporary_address)
            || temporary_address % base_page_size != 0
            || temporary_address.checked_add(temporary_byte_len).is_none()
            || derived_indices[0] == x86_64_page_table_indices(link_base)[0]
        {
            return Err(Failure::task(
                "Deepwyrm temporary mapping must be one aligned upper-canonical page outside the kernel PT_LOAD PML4 slot",
            ));
        }

        let mut rendered_values = parse_layout_toml(contents)?;
        rendered_values.insert("link_base".to_owned(), TomlValue::Integer(link_base));
        rendered_values.insert(
            "transition_tables.temporary_virtual_address".to_owned(),
            TomlValue::Integer(temporary_address),
        );
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
                TomlValue::Integer(value)
                    if matches!(
                        key.as_str(),
                        "link_base" | "transition_tables.temporary_virtual_address"
                    ) =>
                {
                    output.push_str(&format!("pub const {identifier}: u64 = {value:#018x};\n"));
                }
                TomlValue::Integer(_)
                    if matches!(
                        key.as_str(),
                        "transition_tables.pml4_index"
                            | "transition_tables.pdpt_index"
                            | "transition_tables.pd_index"
                            | "transition_tables.pt_index"
                    ) =>
                {
                    let shift = match key.as_str() {
                        "transition_tables.pml4_index" => 39,
                        "transition_tables.pdpt_index" => 30,
                        "transition_tables.pd_index" => 21,
                        "transition_tables.pt_index" => 12,
                        _ => unreachable!("guarded transition-table index key"),
                    };
                    output.push_str(&format!(
                        "pub const {identifier}: u16 = ((DEEPWYRM_TRANSITION_TABLES_TEMPORARY_VIRTUAL_ADDRESS >> {shift}) & 0x1ff) as u16;\n"
                    ));
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
}\n\
\n\
// The accepted target build compiles these assertions against the actual pinned ABI crate.\n\
pub const fn deepwyrm_transition_table_policy_is_self_consistent() -> bool {\n\
    let temporary = DEEPWYRM_TRANSITION_TABLES_TEMPORARY_VIRTUAL_ADDRESS;\n\
    let link_base_pml4 = ((DEEPWYRM_LINK_BASE >> 39) & 0x1ff) as u16;\n\
    let upper_canonical = (temporary >> 48) == 0xffff && ((temporary >> 47) & 1) == 1;\n\
    upper_canonical\n\
        && temporary % DEEPWYRM_BASE_PAGE_SIZE == 0\n\
        && DEEPWYRM_TRANSITION_TABLES_TEMPORARY_PAGE_COUNT == 1\n\
        && DEEPWYRM_TRANSITION_TABLES_PML4_INDEX != link_base_pml4\n\
        && DEEPWYRM_TRANSITION_TABLES_MINIMUM_TABLE_FRAME_COUNT\n\
            <= DEEPWYRM_TRANSITION_TABLES_MAXIMUM_TABLE_FRAME_COUNT\n\
}\n\
\n\
const _: () = assert!(deepwyrm_transition_table_policy_is_self_consistent());\n\
const _: () = assert!(\n\
    DEEPWYRM_BASE_PAGE_SIZE == deepwyrm_abi::DW_BOOT_BASE_PAGE_SIZE as u64\n\
        && DEEPWYRM_TRANSITION_TABLES_LAYOUT_VERSION\n\
            == deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_LAYOUT_VERSION as u64\n\
        && DEEPWYRM_TRANSITION_TABLES_TEMPORARY_VIRTUAL_ADDRESS\n\
            == deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS\n\
        && DEEPWYRM_TRANSITION_TABLES_PML4_INDEX\n\
            == deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_PML4_INDEX\n\
        && DEEPWYRM_TRANSITION_TABLES_PDPT_INDEX\n\
            == deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_PDPT_INDEX\n\
        && DEEPWYRM_TRANSITION_TABLES_PD_INDEX\n\
            == deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_PD_INDEX\n\
        && DEEPWYRM_TRANSITION_TABLES_PT_INDEX\n\
            == deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_PT_INDEX\n\
        && DEEPWYRM_TRANSITION_TABLES_MINIMUM_TABLE_FRAME_COUNT\n\
            == deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_MIN_TABLE_FRAME_COUNT as u64\n\
        && DEEPWYRM_TRANSITION_TABLES_MAXIMUM_TABLE_FRAME_COUNT\n\
            == deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT as u64\n\
);\n",
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
                "load_policy"
                    | "entry_state"
                    | "handoff_mappings"
                    | "early_intake"
                    | "transition_tables"
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

fn take_integer(values: &mut BTreeMap<String, TomlValue>, key: &str) -> Result<u64, Failure> {
    match take_value(values, key)? {
        TomlValue::Integer(value) => Ok(value),
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

fn x86_64_page_table_indices(virtual_address: u64) -> [u16; 4] {
    [39, 30, 21, 12].map(|shift| ((virtual_address >> shift) & 0x1ff) as u16)
}

fn is_upper_canonical_four_level(address: u64) -> bool {
    (address >> 48) == 0xffff && ((address >> 47) & 1) == 1
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
    values: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            bytes: input.as_bytes(),
            offset: 0,
            values: 0,
        }
    }

    fn parse(mut self) -> Result<JsonValue, Failure> {
        if self.bytes.len() > MAX_METADATA_STDOUT_BYTES as usize {
            return Err(self.error("metadata document exceeds the admitted output limit"));
        }
        let value = self.value(0)?;
        self.whitespace();
        if self.offset != self.bytes.len() {
            return Err(self.error("trailing data"));
        }
        Ok(value)
    }

    fn value(&mut self, depth: usize) -> Result<JsonValue, Failure> {
        self.values = self
            .values
            .checked_add(1)
            .ok_or_else(|| self.error("metadata JSON value count overflows"))?;
        if self.values > MAX_METADATA_JSON_VALUES {
            return Err(self.error("metadata JSON contains too many values"));
        }
        self.whitespace();
        match self.peek() {
            Some(b'{') => {
                self.require_container_depth(depth)?;
                self.object(depth + 1)
            }
            Some(b'[') => {
                self.require_container_depth(depth)?;
                self.array(depth + 1)
            }
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

    fn object(&mut self, depth: usize) -> Result<JsonValue, Failure> {
        self.expect(b'{')?;
        let mut values = BTreeMap::new();
        self.whitespace();
        if self.consume(b'}') {
            return Ok(JsonValue::Object(values));
        }
        loop {
            if values.len() >= MAX_METADATA_CONTAINER_ENTRIES {
                return Err(self.error("metadata JSON object contains too many entries"));
            }
            self.whitespace();
            let key = self.string()?;
            self.whitespace();
            self.expect(b':')?;
            let value = self.value(depth)?;
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

    fn array(&mut self, depth: usize) -> Result<JsonValue, Failure> {
        self.expect(b'[')?;
        let mut values = Vec::new();
        self.whitespace();
        if self.consume(b']') {
            return Ok(JsonValue::Array(values));
        }
        loop {
            if values.len() >= MAX_METADATA_CONTAINER_ENTRIES {
                return Err(self.error("metadata JSON array contains too many entries"));
            }
            values.push(self.value(depth)?);
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
                        b'"' => self.push_string_character(&mut output, '"')?,
                        b'\\' => self.push_string_character(&mut output, '\\')?,
                        b'/' => self.push_string_character(&mut output, '/')?,
                        b'b' => self.push_string_character(&mut output, '\u{0008}')?,
                        b'f' => self.push_string_character(&mut output, '\u{000c}')?,
                        b'n' => self.push_string_character(&mut output, '\n')?,
                        b'r' => self.push_string_character(&mut output, '\r')?,
                        b't' => self.push_string_character(&mut output, '\t')?,
                        b'u' => {
                            let character = self.unicode_escape()?;
                            self.push_string_character(&mut output, character)?;
                        }
                        _ => return Err(self.error("invalid JSON escape")),
                    }
                }
                0x00..=0x1f => return Err(self.error("control byte in JSON string")),
                0x20..=0x7f => self.push_string_character(&mut output, char::from(byte))?,
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
                    self.push_string_text(&mut output, value)?;
                    self.offset = end;
                }
            }
        }
        Err(self.error("unterminated JSON string"))
    }

    fn push_string_character(&self, output: &mut String, character: char) -> Result<(), Failure> {
        let additional = character.len_utf8();
        if output
            .len()
            .checked_add(additional)
            .is_none_or(|length| length > MAX_METADATA_STRING_BYTES)
        {
            return Err(self.error("metadata JSON string exceeds the decoded length limit"));
        }
        output.push(character);
        Ok(())
    }

    fn push_string_text(&self, output: &mut String, value: &str) -> Result<(), Failure> {
        if output
            .len()
            .checked_add(value.len())
            .is_none_or(|length| length > MAX_METADATA_STRING_BYTES)
        {
            return Err(self.error("metadata JSON string exceeds the decoded length limit"));
        }
        output.push_str(value);
        Ok(())
    }

    fn require_container_depth(&self, depth: usize) -> Result<(), Failure> {
        if depth >= MAX_METADATA_JSON_DEPTH {
            Err(self.error("metadata JSON nesting exceeds the depth limit"))
        } else {
            Ok(())
        }
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
        DeepLayoutBuild, JsonParser, KERNEL_BOOT_STACK_BYTES, LayoutPolicy,
        MAX_METADATA_CONTAINER_ENTRIES, MAX_METADATA_JSON_DEPTH, MAX_METADATA_STRING_BYTES,
        bounded_command_output, locate_package, open_stable_regular_file, read_pipe_bounded,
        validate_git_status, validate_metadata_manifest_path, validate_regular_path,
        verify_cargo_configuration, verify_exact_cargo_git_source, verify_open_file_identity,
        verify_tracked_bytes, write_generated_policy, x86_64_page_table_indices,
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
    fn metadata_json_enforces_depth_cardinality_string_and_pipe_limits() {
        let deeply_nested = format!(
            "{}0{}",
            "[".repeat(MAX_METADATA_JSON_DEPTH + 1),
            "]".repeat(MAX_METADATA_JSON_DEPTH + 1)
        );
        assert!(JsonParser::new(&deeply_nested).parse().is_err());

        let oversized_string = format!("\"{}\"", "a".repeat(MAX_METADATA_STRING_BYTES + 1));
        assert!(JsonParser::new(&oversized_string).parse().is_err());

        let excessive_array = format!(
            "[{}]",
            std::iter::repeat_n("0", MAX_METADATA_CONTAINER_ENTRIES + 1)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(JsonParser::new(&excessive_array).parse().is_err());

        let maximum_container = format!(
            "[{}]",
            std::iter::repeat_n("0", MAX_METADATA_CONTAINER_ENTRIES)
                .collect::<Vec<_>>()
                .join(",")
        );
        let excessive_values = format!(
            "[{maximum_container},{maximum_container},{maximum_container},{maximum_container}]"
        );
        assert!(JsonParser::new(&excessive_values).parse().is_err());

        let bounded = read_pipe_bounded(std::io::Cursor::new(b"12345"), 4, "test pipe", None)
            .expect("bounded pipe read failed");
        assert!(bounded.exceeded);
        assert_eq!(bounded.bytes, b"1234");
    }

    #[cfg(unix)]
    #[test]
    fn bounded_command_terminates_an_over_limit_producer() {
        use std::process::Command;
        use std::time::{Duration, Instant};

        let started = Instant::now();
        let failure = bounded_command_output(
            Command::new("sh").args(["-c", "while :; do printf 0123456789abcdef; done"]),
            64,
            64,
            Duration::from_secs(5),
            "over-limit fixture",
        )
        .expect_err("unbounded producer unexpectedly succeeded");
        assert!(failure.message.contains("child was terminated"));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_command_times_out_a_silent_process() {
        use std::process::Command;
        use std::time::{Duration, Instant};

        let started = Instant::now();
        let failure = bounded_command_output(
            Command::new("sh").args(["-c", "exec sleep 30"]),
            64,
            64,
            Duration::from_millis(50),
            "silent fixture",
        )
        .expect_err("silent producer unexpectedly succeeded");
        assert!(failure.message.contains("wall-clock deadline"));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[test]
    fn git_status_capture_rejects_hostile_cardinality() {
        use std::fs;
        use std::process::Command;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "wyrmroot-git-status-bound-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create isolated Git fixture");
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(["init", "-q"])
                .status()
                .expect("initialize Git fixture")
                .success()
        );
        for index in 0..32 {
            fs::write(
                root.join(format!("hostile-untracked-entry-{index:04}.txt")),
                b"x",
            )
            .expect("write hostile status fixture");
        }
        let failure = super::git_output_bounded(
            &root,
            ["status", "--porcelain=v1", "--untracked-files=all"],
            64,
            "hostile Git status fixture",
        )
        .expect_err("oversized Git status unexpectedly succeeded");
        assert!(failure.message.contains("limit"));
        fs::remove_dir_all(&root).expect("remove isolated Git fixture");
    }

    #[test]
    fn layout_validation_is_strict_and_generation_is_path_neutral() {
        let valid = layout("0xffff800000200000");
        let policy = LayoutPolicy::parse(&valid).expect("locked layout fixture rejected");
        let generated = policy.render_rust();
        assert!(generated.contains("DEEPWYRM_LINK_BASE: u64 = 0xffff800000200000"));
        assert!(generated.contains("DEEPWYRM_KERNEL_BOOT_STACK_SIZE: u64 = 4194304"));
        assert!(generated.contains("DEEPWYRM_ELF_WINDOW_START: u64 = DEEPWYRM_LINK_BASE"));
        assert!(generated.contains("DEEPWYRM_ELF_WINDOW_END_EXCLUSIVE: u64 = u64::MAX"));
        assert!(
            generated
                .contains("DEEPWYRM_EARLY_INTAKE_MAX_NORMALIZED_MEMORY_MAP_ENTRIES: u64 = 128")
        );
        assert!(generated.contains(
            "DEEPWYRM_TRANSITION_TABLES_TEMPORARY_VIRTUAL_ADDRESS: u64 = 0xffffff0000000000"
        ));
        assert!(
            generated.contains("DEEPWYRM_TRANSITION_TABLES_MAXIMUM_TABLE_FRAME_COUNT: u64 = 256")
        );
        assert!(generated.contains(
            "DEEPWYRM_TRANSITION_TABLES_PML4_INDEX: u16 = ((DEEPWYRM_TRANSITION_TABLES_TEMPORARY_VIRTUAL_ADDRESS >> 39) & 0x1ff) as u16"
        ));
        assert!(generated.contains("deepwyrm_transition_table_policy_is_self_consistent"));
        assert!(
            generated
                .contains("deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS")
        );
        assert!(
            generated.contains("deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT")
        );
        assert!(!generated.contains("/synthetic/private/workspace"));

        let alternate = layout_with_transition("0xffff800000200000", "0xfffffe8000000000", 384);
        let alternate_generated = LayoutPolicy::parse(&alternate)
            .expect("semantically valid alternate manifest values rejected")
            .render_rust();
        assert!(alternate_generated.contains(
            "DEEPWYRM_TRANSITION_TABLES_TEMPORARY_VIRTUAL_ADDRESS: u64 = 0xfffffe8000000000"
        ));
        assert!(
            alternate_generated
                .contains("DEEPWYRM_TRANSITION_TABLES_MAXIMUM_TABLE_FRAME_COUNT: u64 = 384")
        );

        assert!(LayoutPolicy::parse(&valid.replace("version = 2", "version = 1")).is_err());
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
        assert!(
            LayoutPolicy::parse(&valid.replace("pml4_index = 510", "pml4_index = 509")).is_err()
        );
        assert!(
            LayoutPolicy::parse(&valid.replace(
                "maximum_table_frame_count = 256",
                "maximum_table_frame_count = 3"
            ))
            .is_err()
        );
        assert!(
            LayoutPolicy::parse(
                &valid.replace("temporary_page_count = 1", "temporary_page_count = 0")
            )
            .is_err()
        );
        assert!(
            LayoutPolicy::parse(&valid.replace(
                "minimum_table_frame_count = 4",
                "minimum_table_frame_count = 5"
            ))
            .is_err()
        );
        assert!(
            LayoutPolicy::parse(&valid.replace(
                "maximum_table_frame_count = 256",
                "maximum_table_frame_count = 4294967296"
            ))
            .is_err()
        );
        assert!(
            LayoutPolicy::parse(&valid.replace(
                "contract = \"DW_BOOT_X86_64_PAGING_HANDOFF_V1\"",
                "contract = \"loader-private\""
            ))
            .is_err()
        );
        assert!(
            LayoutPolicy::parse(&valid.replace("layout_version = 2", "layout_version = \"2\""))
                .is_err()
        );
        assert!(
            LayoutPolicy::parse(
                &valid.replace("referenced_ranges_mutable = false", "mutable = false")
            )
            .is_err()
        );
        assert!(
            LayoutPolicy::parse(&layout_with_transition(
                "0xffff800000200000",
                "0xffff800000300000",
                256,
            ))
            .is_err()
        );
        assert!(
            LayoutPolicy::parse(&layout_with_transition(
                "0xffff800000200000",
                "0xffffff0000000001",
                256,
            ))
            .is_err()
        );
        assert!(
            LayoutPolicy::parse(&layout_with_transition(
                "0xffff800000200000",
                "0xfffffffffffff000",
                256,
            ))
            .is_err()
        );
    }

    #[test]
    fn kernel_boot_stack_contract_requires_four_mib() {
        let valid = layout("0xffff800000200000");
        LayoutPolicy::parse(&valid).expect("4 MiB kernel boot stack rejected");

        for (bytes, label) in [(1_048_576, "stale 1 MiB"), (8_388_608, "unbound 8 MiB")] {
            let candidate = valid.replace(
                "kernel_boot_stack_size = 4194304",
                &format!("kernel_boot_stack_size = {bytes}"),
            );
            assert_ne!(
                candidate, valid,
                "stack-size fixture substitution did not apply"
            );
            let failure = match LayoutPolicy::parse(&candidate) {
                Ok(_) => panic!("{label} kernel boot stack unexpectedly accepted"),
                Err(failure) => failure,
            };
            assert!(failure.message.contains(&format!(
                "kernel_boot_stack_size' is {bytes}, expected {KERNEL_BOOT_STACK_BYTES}"
            )));
        }
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
        let source_root = std::env::temp_dir().join(format!(
            "wyrmroot-layout-source-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create isolated generated directory");
        let layout_path = source_root.join(super::LAYOUT_PATH);
        fs::create_dir_all(layout_path.parent().expect("layout parent"))
            .expect("create source layout directory");
        fs::write(&layout_path, b"trusted layout").expect("write trusted source layout");
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
                std::process::Command::new("git")
                    .arg("-C")
                    .arg(&source_root)
                    .args(arguments)
                    .status()
                    .expect("run source fixture Git command")
                    .success()
            );
        }
        let expected_revision = super::git_output_bounded(
            &source_root,
            ["rev-parse", "HEAD"],
            super::MAX_GIT_REVISION_STDOUT_BYTES,
            "source fixture revision",
        )
        .expect("read source fixture revision")
        .trim()
        .to_owned();
        let path = root.join("policy.rs");
        fs::write(&path, b"trusted policy").expect("write generated fixture");
        let build = DeepLayoutBuild {
            policy_path: path.clone(),
            layout_sha256: bytes_digest(b"trusted layout"),
            policy_sha256: bytes_digest(b"trusted policy"),
            source_root: source_root.clone(),
            expected_revision: expected_revision.clone(),
        };
        build.verify_unchanged().expect("trusted policy rejected");
        fs::write(&path, b"changed policy").expect("replace policy contents");
        assert!(build.verify_unchanged().is_err());
        fs::write(&path, b"trusted policy").expect("restore trusted policy");
        build.verify_unchanged().expect("restored policy rejected");
        fs::remove_file(&path).expect("remove trusted policy");
        let target = root.join("target.rs");
        fs::write(&target, b"trusted policy").expect("write symlink target");
        symlink(&target, &path).expect("swap policy for symlink");
        assert!(build.verify_unchanged().is_err());
        fs::remove_file(&path).expect("remove policy symlink");
        fs::write(&path, b"trusted policy").expect("restore policy after symlink");
        build
            .verify_unchanged()
            .expect("policy restored after symlink rejected");

        fs::write(&layout_path, b"changed layout").expect("change source layout");
        assert!(build.verify_unchanged().is_err());
        fs::write(&layout_path, b"trusted layout").expect("restore source layout");
        build
            .verify_unchanged()
            .expect("restored source layout rejected");

        assert!(
            std::process::Command::new("git")
                .arg("-C")
                .arg(&source_root)
                .args([
                    "-c",
                    "user.name=Wyrmroot test",
                    "-c",
                    "user.email=wyrmroot-test@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-q",
                    "--allow-empty",
                    "-m",
                    "move head",
                ])
                .status()
                .expect("move source fixture HEAD")
                .success()
        );
        assert!(build.verify_unchanged().is_err());

        fs::remove_dir_all(root).expect("remove isolated generated directory");
        fs::remove_dir_all(source_root).expect("remove isolated source repository");
    }

    #[cfg(unix)]
    #[test]
    fn generated_policy_writer_rejects_symlink_ancestry_and_destination() {
        use std::fs;
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "wyrmroot-generated-write-test-{}-{nonce}",
            std::process::id()
        ));
        let outside = std::env::temp_dir().join(format!(
            "wyrmroot-generated-outside-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create generated root");
        fs::create_dir(&outside).expect("create outside root");
        symlink(&outside, root.join("target")).expect("create generated ancestry symlink");
        let path = root.join(super::GENERATED_POLICY_PATH);
        assert!(write_generated_policy(&root, &path, "trusted").is_err());

        fs::remove_file(root.join("target")).expect("remove ancestry symlink");
        fs::create_dir_all(path.parent().expect("generated parent"))
            .expect("create generated parent");
        let outside_file = outside.join("outside.rs");
        fs::write(&outside_file, b"outside").expect("write outside file");
        symlink(&outside_file, &path).expect("create destination symlink");
        assert!(write_generated_policy(&root, &path, "trusted").is_err());
        assert_eq!(
            fs::read(&outside_file).expect("read outside file"),
            b"outside"
        );
        fs::remove_file(&path).expect("remove destination symlink");
        write_generated_policy(&root, &path, "trusted").expect("write generated policy");
        assert_eq!(fs::read(&path).expect("read generated policy"), b"trusted");
        assert!(
            fs::read_dir(path.parent().expect("generated parent"))
                .expect("read generated directory")
                .all(|entry| {
                    !entry
                        .expect("read generated entry")
                        .file_name()
                        .to_string_lossy()
                        .contains(".tmp-")
                })
        );

        fs::remove_dir_all(&root).expect("remove generated root");
        fs::remove_dir_all(&outside).expect("remove outside root");
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

    #[test]
    fn exact_cargo_source_identity_binds_checkout_tree_and_database_location() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("xtask manifest has a repository root");
        let temporary_root = repository.join(".tmp");
        fs::create_dir_all(&temporary_root).expect("create repository temporary root");
        let cargo_home = temporary_root.join(format!(
            "wyrmroot-cargo-source-test-{}-{nonce}",
            std::process::id()
        ));
        let checkout = cargo_home.join("git/checkouts/deepwyrm-fixture/revision");
        let database = cargo_home.join("git/db/deepwyrm-fixture");
        fs::create_dir_all(&checkout).expect("create checkout fixture");
        fs::create_dir_all(database.parent().expect("database parent"))
            .expect("create database parent");
        assert!(
            Command::new(super::FIXED_GIT)
                .args(["init", "-q", "--separate-git-dir"])
                .arg(&database)
                .arg(&checkout)
                .env("TMPDIR", &cargo_home)
                .status()
                .expect("initialize separate Git fixture")
                .success()
        );
        let manifest = checkout.join(super::PACKAGE_MANIFEST);
        fs::create_dir_all(manifest.parent().expect("manifest parent"))
            .expect("create package fixture");
        fs::write(
            &manifest,
            b"[package]\nname = \"deepwyrm-abi\"\nversion = \"0.0.0\"\n",
        )
        .expect("write package fixture");
        fs::write(checkout.join(".gitignore"), b"ignored-extra\n").expect("write ignore fixture");
        for arguments in [
            vec!["add", "--all"],
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
                Command::new(super::FIXED_GIT)
                    .arg("-C")
                    .arg(&checkout)
                    .args(arguments)
                    .env("TMPDIR", &cargo_home)
                    .status()
                    .expect("commit source fixture")
                    .success()
            );
        }
        fs::write(checkout.join(".cargo-ok"), []).expect("write Cargo marker");
        let revision = Command::new(super::FIXED_GIT)
            .arg("-C")
            .arg(&checkout)
            .args(["rev-parse", "HEAD"])
            .env("TMPDIR", &cargo_home)
            .output()
            .expect("read fixture revision");
        let revision = std::str::from_utf8(&revision.stdout)
            .expect("fixture revision UTF-8")
            .trim();
        let identity = verify_exact_cargo_git_source(&checkout, &cargo_home, revision)
            .expect("exact Cargo source fixture rejected");
        assert_eq!(identity.tree.len(), 40);
        assert_eq!(identity.archive_sha256.len(), 64);
        assert_eq!(identity.git_sha256.len(), 64);
        verify_exact_cargo_git_source(&checkout, &cargo_home, revision)
            .expect("stable identity changed");

        assert!(
            Command::new(super::FIXED_GIT)
                .arg("-C")
                .arg(&checkout)
                .args([
                    "update-index",
                    "--assume-unchanged",
                    super::PACKAGE_MANIFEST
                ])
                .env("TMPDIR", &cargo_home)
                .status()
                .expect("set assume-unchanged")
                .success()
        );
        fs::write(&manifest, b"modified\n").expect("modify tracked source");
        assert!(verify_exact_cargo_git_source(&checkout, &cargo_home, revision).is_err());
        assert!(
            Command::new(super::FIXED_GIT)
                .arg("-C")
                .arg(&checkout)
                .args([
                    "update-index",
                    "--no-assume-unchanged",
                    super::PACKAGE_MANIFEST
                ])
                .env("TMPDIR", &cargo_home)
                .status()
                .expect("clear assume-unchanged")
                .success()
        );
        fs::write(
            &manifest,
            b"[package]\nname = \"deepwyrm-abi\"\nversion = \"0.0.0\"\n",
        )
        .expect("restore tracked source");
        assert!(
            Command::new(super::FIXED_GIT)
                .arg("-C")
                .arg(&checkout)
                .args(["update-index", "--skip-worktree", super::PACKAGE_MANIFEST])
                .env("TMPDIR", &cargo_home)
                .status()
                .expect("set skip-worktree")
                .success()
        );
        fs::write(&manifest, b"skip-worktree modification\n").expect("modify skip-worktree source");
        assert!(verify_exact_cargo_git_source(&checkout, &cargo_home, revision).is_err());
        assert!(
            Command::new(super::FIXED_GIT)
                .arg("-C")
                .arg(&checkout)
                .args([
                    "update-index",
                    "--no-skip-worktree",
                    super::PACKAGE_MANIFEST
                ])
                .env("TMPDIR", &cargo_home)
                .status()
                .expect("clear skip-worktree")
                .success()
        );
        fs::write(
            &manifest,
            b"[package]\nname = \"deepwyrm-abi\"\nversion = \"0.0.0\"\n",
        )
        .expect("restore skip-worktree source");
        fs::write(checkout.join("ignored-extra"), b"ignored\n").expect("write ignored source");
        assert!(verify_exact_cargo_git_source(&checkout, &cargo_home, revision).is_err());
        fs::remove_file(checkout.join("ignored-extra")).expect("remove ignored source");
        fs::write(checkout.join("rogue"), b"untracked\n").expect("write rogue source");
        assert!(verify_exact_cargo_git_source(&checkout, &cargo_home, revision).is_err());
        fs::remove_file(checkout.join("rogue")).expect("remove rogue source");

        let fsmonitor = cargo_home.join("hostile-fsmonitor.sh");
        fs::write(&fsmonitor, b"#!/bin/sh\nprintf invoked > \"$0.invoked\"\n")
            .expect("write hostile fsmonitor");
        fs::set_permissions(&fsmonitor, fs::Permissions::from_mode(0o700))
            .expect("make hostile fsmonitor executable");
        let attributes = cargo_home.join("hostile-attributes");
        fs::write(&attributes, b"* export-ignore\n").expect("write hostile attributes");
        for (key, value) in [
            ("core.fsmonitor", fsmonitor.as_os_str()),
            ("core.attributesFile", attributes.as_os_str()),
        ] {
            assert!(
                Command::new(super::FIXED_GIT)
                    .arg("-C")
                    .arg(&checkout)
                    .args(["config", key])
                    .arg(value)
                    .env("TMPDIR", &cargo_home)
                    .status()
                    .expect("set hostile local Git configuration")
                    .success()
            );
        }
        let hardened = verify_exact_cargo_git_source(&checkout, &cargo_home, revision)
            .expect("hardened Git inspection consumed hostile local configuration");
        assert_eq!(hardened.archive_sha256, identity.archive_sha256);
        assert!(!fsmonitor.with_extension("sh.invoked").exists());

        let included = cargo_home.join("included-config");
        fs::write(&included, b"[core]\nfsmonitor = true\n")
            .expect("write included Git configuration");
        for key in ["include.path", "includeIf.onbranch:master.path"] {
            assert!(
                Command::new(super::FIXED_GIT)
                    .arg("-C")
                    .arg(&checkout)
                    .args(["config", "--add", key])
                    .arg(&included)
                    .env("TMPDIR", &cargo_home)
                    .status()
                    .expect("set local Git include")
                    .success()
            );
            assert!(verify_exact_cargo_git_source(&checkout, &cargo_home, revision).is_err());
            assert!(
                Command::new(super::FIXED_GIT)
                    .arg("-C")
                    .arg(&checkout)
                    .args(["config", "--unset-all", key])
                    .env("TMPDIR", &cargo_home)
                    .status()
                    .expect("clear local Git include")
                    .success()
            );
        }

        fs::write(database.join("info/attributes"), b"* export-ignore\n")
            .expect("write Git-directory attribute overlay");
        assert!(verify_exact_cargo_git_source(&checkout, &cargo_home, revision).is_err());
        fs::remove_dir_all(cargo_home).expect("remove isolated Cargo source fixture");
    }

    #[test]
    fn exact_cargo_source_identity_accepts_owned_checkout_local_git_directory() {
        use std::fs;
        use std::process::Command;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("xtask manifest has a repository root");
        let cargo_home = repository.join(".tmp").join(format!(
            "wyrmroot-local-git-source-test-{}-{nonce}",
            std::process::id()
        ));
        let checkout = cargo_home.join("git/checkouts/deepwyrm-fixture/revision");
        fs::create_dir_all(&checkout).expect("create checkout fixture");
        assert!(
            Command::new(super::FIXED_GIT)
                .args(["init", "-q"])
                .arg(&checkout)
                .env("TMPDIR", &cargo_home)
                .status()
                .expect("initialize local Git fixture")
                .success()
        );
        let manifest = checkout.join(super::PACKAGE_MANIFEST);
        fs::create_dir_all(manifest.parent().expect("manifest parent"))
            .expect("create package fixture");
        fs::write(&manifest, b"[package]\nname = \"deepwyrm-abi\"\n")
            .expect("write package fixture");
        assert!(
            Command::new(super::FIXED_GIT)
                .arg("-C")
                .arg(&checkout)
                .args(["add", "--all"])
                .env("TMPDIR", &cargo_home)
                .status()
                .expect("add local Git fixture")
                .success()
        );
        assert!(
            Command::new(super::FIXED_GIT)
                .arg("-C")
                .arg(&checkout)
                .args([
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
                ])
                .env("TMPDIR", &cargo_home)
                .status()
                .expect("commit local Git fixture")
                .success()
        );
        let revision = Command::new(super::FIXED_GIT)
            .arg("-C")
            .arg(&checkout)
            .args(["rev-parse", "HEAD"])
            .env("TMPDIR", &cargo_home)
            .output()
            .expect("read fixture revision");
        let revision = std::str::from_utf8(&revision.stdout)
            .expect("fixture revision UTF-8")
            .trim();
        verify_exact_cargo_git_source(&checkout, &cargo_home, revision)
            .expect("owned checkout-local Git directory rejected");
        fs::remove_dir_all(cargo_home).expect("remove local Git fixture");
    }

    #[test]
    fn e6_cargo_home_wrapper_configuration_is_rejected_before_execution() {
        use std::fs;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("xtask manifest has a repository root");
        let cargo_home = repository.join(".tmp").join(format!(
            "wyrmroot-cargo-config-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&cargo_home).expect("create Cargo-home fixture");
        let hash = verify_cargo_configuration(repository, &cargo_home)
            .expect("tracked repository Cargo configuration rejected");
        assert_eq!(hash.len(), 64);
        fs::write(
            cargo_home.join("config.toml"),
            b"[build]\nrustc-wrapper = \"/tmp/untrusted-wrapper\"\n",
        )
        .expect("write hostile Cargo wrapper configuration");
        assert!(verify_cargo_configuration(repository, &cargo_home).is_err());
        fs::remove_dir_all(cargo_home).expect("remove Cargo configuration fixture");
    }

    fn metadata(source: &str, manifest: &str) -> String {
        format!(
            r#"{{"packages":[{{"name":"deepwyrm-abi","source":"{source}","manifest_path":"{manifest}"}}],"workspace_root":"/synthetic/private/workspace"}}"#
        )
    }

    fn layout(link_base: &str) -> String {
        layout_with_transition(link_base, "0xffffff0000000000", 256)
    }

    fn layout_with_transition(
        link_base: &str,
        temporary_virtual_address: &str,
        maximum_table_frame_count: u64,
    ) -> String {
        let temporary = u64::from_str_radix(
            temporary_virtual_address
                .strip_prefix("0x")
                .expect("fixture temporary address must be hexadecimal"),
            16,
        )
        .expect("fixture temporary address must fit u64");
        let [pml4_index, pdpt_index, pd_index, pt_index] = x86_64_page_table_indices(temporary);
        format!(
            r#"schema = "deepwyrm-x86_64-layout"
version = 2
entry_contract = "DW_BOOT_X86_64_ENTRY_V1"
elf_type = "ET_EXEC"
entry_symbol = "_dw_kernel_entry"
link_base = "{link_base}"
base_page_size = 4096
red_zone = false
kernel_boot_stack_size = 4194304
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
referenced_ranges_mutable = false
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

[transition_tables]
contract = "DW_BOOT_X86_64_PAGING_HANDOFF_V1"
layout_version = 2
temporary_virtual_address = "{temporary_virtual_address}"
temporary_page_count = 1
pml4_index = {pml4_index}
pdpt_index = {pdpt_index}
pd_index = {pd_index}
pt_index = {pt_index}
minimum_table_frame_count = 4
maximum_table_frame_count = {maximum_table_frame_count}
initial_leaf = "exactly-zero-non-present"
temporary_leaf_permissions = "supervisor-rw-nx-base-page"
identity_alias_permissions = "supervisor-rw-nx-base-page"
identity_alias_mutable_by_deepwyrm = true
cache_selection_bits = 0
pat_entry_zero = "observed-write-back"
mtrr_policy = "alias-consistent-no-effective-write-back-claim"
pcide_enabled = false
pge_enabled = false
cr3_low_bits_zero = true
ownership_transfer = "loader-to-deepwyrm-after-exit-boot-services"
lifetime = "until-deepwyrm-cr3-switch"
concurrency = "bsp-aps-off-if-clear-nonreentrant"
physical_role_policy = "exclusive-table-frames-no-kernel-module-data-alias"
new_root_table_access = "deepwyrm-owned-before-cr3-switch"
"#
        )
    }
}
