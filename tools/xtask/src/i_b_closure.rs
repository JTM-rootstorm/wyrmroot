//! Fail-closed artifact audit supporting WYR0-I-B review.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use wyrmroot_bootfs::archive::Archive;

use crate::error::Failure;
use crate::h_request::{self, ExpectedOutcome, HRequest};
use crate::metadata::BuildManifest;
use crate::sha256;

const DEEPWYRM_ABI_REVISION: &str = "cfc69bd8a49819ce1cda1a132cf56e55c93f92e4";
const RUST_REVISION: &str = "a92dc7f7464ad6ddfece4402bd7b86dbfa86166d";
const RUST_TOOLCHAIN_NAME: &str = "wyrmroot-1.97.1-a92dc7f7";
const MAX_SOURCE_FILES: usize = 4096;
const MAX_SOURCE_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_SOURCE_TOTAL_BYTES: u64 = 32 * 1024 * 1024;
const MAX_NATIVE_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ESP_BYTES: u64 = crate::g3_image::IMAGE_BYTES;
const ELF_HEADER_BYTES: usize = 64;
const ELF_PROGRAM_HEADER_BYTES: usize = 56;
const MAX_ELF_PROGRAM_HEADERS: usize = 128;
const MAX_INSPECTOR_STDOUT_BYTES: u64 = 64 * 1024;
const MAX_INSPECTOR_STDERR_BYTES: u64 = 64 * 1024;
const INSPECTOR_DEADLINE: Duration = Duration::from_secs(120);

#[derive(Clone, Debug, Eq, PartialEq)]
struct ArtifactDigest {
    label: &'static str,
    digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceAudit {
    files: usize,
    bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeInspection {
    entry: u64,
    load_segments: usize,
    executable_segments: usize,
}

#[derive(Debug)]
struct BoundedCommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
enum PipeStream {
    Stdout,
    Stderr,
}

enum ReaderResult {
    Stdout(Result<BoundedPipe, Failure>),
    Stderr(Result<BoundedPipe, Failure>),
}

struct BoundedPipe {
    bytes: Vec<u8>,
    exceeded: bool,
}

pub(crate) fn audit(first_request: &str, second_request: &str) -> Result<String, Failure> {
    let repository = crate::tasks::repository_root()?;
    let manifest = BuildManifest::load(&repository)?;
    manifest.validate_host_build_readiness(&repository)?;
    require_exact_manifest_pins(&manifest)?;

    let first = h_request::load(Path::new(first_request))?;
    let second = h_request::load(Path::new(second_request))?;
    validate_request_pair(&first, &second, &manifest)?;

    // Reuse the canonical request/image inspector so this audit covers the exact bytes the
    // existing QEMU path would consume, including request-bound provenance and ESP contents.
    let first_inspection = crate::h_integration::inspect(first_request)?;
    let second_inspection = crate::h_integration::inspect(second_request)?;
    let first_candidate = json_sha256_field(&first_inspection, "candidate_sha256")?;
    let second_candidate = json_sha256_field(&second_inspection, "candidate_sha256")?;
    let first_provenance = sha256::file_digest(&first.provenance)
        .map_err(|error| Failure::task(format!("could not hash first I-B provenance: {error}")))?;
    let second_provenance = sha256::file_digest(&second.provenance)
        .map_err(|error| Failure::task(format!("could not hash second I-B provenance: {error}")))?;

    let first_native = inspect_request_native_artifacts(&repository, &first)?;
    let second_native = inspect_request_native_artifacts(&repository, &second)?;
    if first_native != second_native {
        return Err(Failure::task(
            "WYR0-I-B candidate native artifacts have different ELF structure",
        ));
    }

    let artifacts = compare_candidate_artifacts(&first, &second)?;
    let bootfs_executables = inspect_bootfs_executables(&first)?;
    if bootfs_executables != inspect_bootfs_executables(&second)? {
        return Err(Failure::task(
            "WYR0-I-B candidate bootfs archives expose different executable sets",
        ));
    }

    let source_audit = audit_abi_sources(&repository)?;
    let bootfs_sha256 = artifact_digest(&artifacts, "bootfs")?;
    let esp_sha256 = artifact_digest(&artifacts, "esp")?;
    if crate::h_integration::inspect(first_request)? != first_inspection
        || crate::h_integration::inspect(second_request)? != second_inspection
    {
        return Err(Failure::task(
            "WYR0-I-B candidate changed between initial inspection and report publication",
        ));
    }

    Ok(format!(
        concat!(
            "{{\"schema_version\":1,\"phase\":\"WYR0-I-B-artifact-audit\",",
            "\"status\":\"ARTIFACT_AUDIT_PASS\",\"proves_independent_clean_builds\":false,",
            "\"clean_build_process_evidence\":\"REQUIRED_SEPARATELY\",",
            "\"pins\":{{\"deepwyrm_revision\":\"{}\",\"deepwyrm_abi_revision\":\"{}\",",
            "\"wyrmroot_revision\":\"{}\",",
            "\"rust_revision\":\"{}\",\"rust_toolchain_name\":\"{}\"}},",
            "\"requests\":{{\"distinct_candidate_roots\":true,",
            "\"first_request_sha256\":\"{}\",\"second_request_sha256\":\"{}\",",
            "\"first_candidate_sha256\":\"{}\",\"second_candidate_sha256\":\"{}\",",
            "\"canonical_image_inspection_reused\":true}},",
            "\"artifact_equality\":{{\"all_comparable_artifact_bytes_identical\":true,",
            "\"bootfs\":{{\"identical_bytes\":true,\"sha256\":\"{}\"}},",
            "\"esp\":{{\"identical_bytes\":true,\"sha256\":\"{}\"}},",
            "\"consumed_sha256\":{}}},",
            "\"request_bound_provenance\":{{\"validated_independently\":true,",
            "\"first_sha256\":\"{}\",\"second_sha256\":\"{}\"}},",
            "\"native_artifacts\":{{\"canonical_inspector\":\"toolchain/inspect-native-artifact.sh\",",
            "\"required\":[\"bootstrap\",\"init0\",\"hello\"],",
            "\"bootfs_executables\":{},\"static_elf\":true,\"no_pt_interp\":true,",
            "\"no_pt_dynamic\":true,\"no_writable_executable_segment\":true}},",
            "\"abi_pin_audit\":{{\"manifest_lock_consistent\":true,",
            "\"generated_consumer_present\":true,\"bounded_source_audit\":true,",
            "\"source_files\":{},\"source_bytes\":{},",
            "\"heuristic_findings\":0,",
            "\"manual_structural_audit\":\"REQUIRED_SEPARATELY\"}}}}\n"
        ),
        first.deepwyrm_revision,
        DEEPWYRM_ABI_REVISION,
        first.wyrmroot_revision,
        RUST_REVISION,
        RUST_TOOLCHAIN_NAME,
        first.request_sha256,
        second.request_sha256,
        first_candidate,
        second_candidate,
        bootfs_sha256,
        esp_sha256,
        artifact_hash_json(&artifacts),
        first_provenance,
        second_provenance,
        json_string_array(&bootfs_executables),
        source_audit.files,
        source_audit.bytes,
    ))
}

fn require_exact_manifest_pins(manifest: &BuildManifest) -> Result<(), Failure> {
    for (actual, expected, label) in [
        (
            manifest.deepwyrm_revision()?,
            DEEPWYRM_ABI_REVISION,
            "Deepwyrm ABI revision",
        ),
        (manifest.rust_revision()?, RUST_REVISION, "Rust revision"),
        (
            manifest.rust_toolchain_name()?,
            RUST_TOOLCHAIN_NAME,
            "Rust toolchain name",
        ),
    ] {
        if actual != expected {
            return Err(Failure::task(format!(
                "WYR0-I-B {label} is '{actual}', expected '{expected}'"
            )));
        }
    }
    Ok(())
}

fn validate_request_pair(
    first: &HRequest,
    second: &HRequest,
    manifest: &BuildManifest,
) -> Result<(), Failure> {
    let first_root = request_root(first)?;
    let second_root = request_root(second)?;
    if first_root == second_root {
        return Err(Failure::task(
            "WYR0-I-B requests must use two distinct canonical output roots",
        ));
    }
    validate_request_source_pins(
        &first.deepwyrm_revision,
        &first.rust_revision,
        &second.deepwyrm_revision,
        &second.rust_revision,
        manifest.deepwyrm_revision()?,
        manifest.rust_revision()?,
    )?;
    for request in [first, second] {
        if request.expected_outcome != ExpectedOutcome::Pass || request.expected_detail != 0 {
            return Err(Failure::task(
                "WYR0-I-B artifact audit requires a successful production candidate request",
            ));
        }
    }
    if first.wyrmroot_revision != second.wyrmroot_revision
        || first.schema_version != second.schema_version
        || first.selector != second.selector
        || first.test_id != second.test_id
        || first.expected_outcome != second.expected_outcome
        || first.expected_detail != second.expected_detail
        || first.timeout_seconds != second.timeout_seconds
        || first.evidence != second.evidence
    {
        return Err(Failure::task(
            "WYR0-I-B requests do not describe the same exact source tuple and logical test",
        ));
    }

    for (left, right, label) in distinct_output_pairs(first, second) {
        reject_alias(left, right, label)?;
    }
    Ok(())
}

fn validate_request_source_pins(
    first_deepwyrm: &str,
    first_rust: &str,
    second_deepwyrm: &str,
    second_rust: &str,
    manifest_deepwyrm_abi: &str,
    manifest_rust: &str,
) -> Result<(), Failure> {
    if manifest_deepwyrm_abi != DEEPWYRM_ABI_REVISION
        || manifest_rust != RUST_REVISION
        || first_deepwyrm != second_deepwyrm
        || first_rust != second_rust
        || first_rust != RUST_REVISION
        || first_rust != manifest_rust
    {
        return Err(Failure::task(
            "WYR0-I-B requests disagree on their exact product source tuple or accepted toolchain pins",
        ));
    }
    Ok(())
}

fn request_root(request: &HRequest) -> Result<PathBuf, Failure> {
    let root = request
        .path
        .parent()
        .ok_or_else(|| Failure::task("WYR0-I-B request has no output root"))?;
    fs::canonicalize(root)
        .map_err(|error| Failure::task(format!("could not resolve I-B output root: {error}")))
}

fn artifact_pairs<'a>(
    first: &'a HRequest,
    second: &'a HRequest,
) -> [(&'a Path, &'a Path, &'static str); 10] {
    [
        (&first.loader, &second.loader, "loader"),
        (&first.kernel, &second.kernel, "kernel"),
        (&first.symbols, &second.symbols, "symbols"),
        (&first.bootstrap, &second.bootstrap, "bootstrap"),
        (&first.init0, &second.init0, "init0"),
        (&first.hello, &second.hello, "hello"),
        (&first.bootfs, &second.bootfs, "bootfs"),
        (&first.esp, &second.esp, "esp"),
        (&first.ovmf_code, &second.ovmf_code, "ovmf_code"),
        (
            &first.ovmf_vars_template,
            &second.ovmf_vars_template,
            "ovmf_vars_template",
        ),
    ]
}

fn distinct_output_pairs<'a>(
    first: &'a HRequest,
    second: &'a HRequest,
) -> [(&'a Path, &'a Path, &'static str); 9] {
    [
        (&first.loader, &second.loader, "loader"),
        (&first.kernel, &second.kernel, "kernel"),
        (&first.symbols, &second.symbols, "symbols"),
        (&first.bootstrap, &second.bootstrap, "bootstrap"),
        (&first.init0, &second.init0, "init0"),
        (&first.hello, &second.hello, "hello"),
        (&first.bootfs, &second.bootfs, "bootfs"),
        (&first.esp, &second.esp, "esp"),
        (&first.provenance, &second.provenance, "provenance"),
    ]
}

fn reject_alias(first: &Path, second: &Path, label: &str) -> Result<(), Failure> {
    let first = fs::metadata(first)
        .map_err(|error| Failure::task(format!("could not stat first I-B {label}: {error}")))?;
    let second = fs::metadata(second)
        .map_err(|error| Failure::task(format!("could not stat second I-B {label}: {error}")))?;
    if first.dev() == second.dev() && first.ino() == second.ino() {
        return Err(Failure::task(format!(
            "WYR0-I-B {label} candidates alias one file instead of using distinct output files"
        )));
    }
    Ok(())
}

fn compare_candidate_artifacts(
    first: &HRequest,
    second: &HRequest,
) -> Result<Vec<ArtifactDigest>, Failure> {
    let mut artifacts = Vec::new();
    for (left, right, label) in artifact_pairs(first, second) {
        let max_bytes = match label {
            "esp" => MAX_ESP_BYTES,
            _ => MAX_NATIVE_ARTIFACT_BYTES,
        };
        require_identical_files(left, right, label, max_bytes)?;
        artifacts.push(ArtifactDigest {
            label,
            digest: sha256::file_digest(left).map_err(|error| {
                Failure::task(format!("could not hash WYR0-I-B {label}: {error}"))
            })?,
        });
    }
    Ok(artifacts)
}

fn require_identical_files(
    first: &Path,
    second: &Path,
    label: &str,
    max_bytes: u64,
) -> Result<(), Failure> {
    let mut first = File::open(first)
        .map_err(|error| Failure::task(format!("could not open first I-B {label}: {error}")))?;
    let mut second = File::open(second)
        .map_err(|error| Failure::task(format!("could not open second I-B {label}: {error}")))?;
    let first_len = first
        .metadata()
        .map_err(|error| Failure::task(format!("could not stat first I-B {label}: {error}")))?
        .len();
    let second_len = second
        .metadata()
        .map_err(|error| Failure::task(format!("could not stat second I-B {label}: {error}")))?
        .len();
    if first_len == 0 || first_len > max_bytes || first_len != second_len {
        return Err(Failure::task(format!(
            "WYR0-I-B {label} outputs differ in byte length or exceed the artifact-audit bound"
        )));
    }
    let mut first_buffer = [0_u8; 64 * 1024];
    let mut second_buffer = [0_u8; 64 * 1024];
    loop {
        let first_count = first
            .read(&mut first_buffer)
            .map_err(|error| Failure::task(format!("could not read first I-B {label}: {error}")))?;
        let second_count = second.read(&mut second_buffer).map_err(|error| {
            Failure::task(format!("could not read second I-B {label}: {error}"))
        })?;
        if first_count != second_count
            || first_buffer[..first_count] != second_buffer[..second_count]
        {
            return Err(Failure::task(format!(
                "WYR0-I-B {label} outputs are not byte-for-byte identical"
            )));
        }
        if first_count == 0 {
            return Ok(());
        }
    }
}

fn artifact_digest<'a>(artifacts: &'a [ArtifactDigest], label: &str) -> Result<&'a str, Failure> {
    artifacts
        .iter()
        .find(|artifact| artifact.label == label)
        .map(|artifact| artifact.digest.as_str())
        .ok_or_else(|| Failure::task(format!("WYR0-I-B omitted {label} digest")))
}

fn artifact_hash_json(artifacts: &[ArtifactDigest]) -> String {
    format!(
        "{{{}}}",
        artifacts
            .iter()
            .map(|artifact| format!("\"{}\":\"{}\"", artifact.label, artifact.digest))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn inspect_request_native_artifacts(
    repository: &Path,
    request: &HRequest,
) -> Result<Vec<NativeInspection>, Failure> {
    let mut inspected = Vec::new();
    for (path, label) in [
        (&request.bootstrap, "bootstrap"),
        (&request.init0, "init0"),
        (&request.hello, "hello"),
    ] {
        let bytes = read_bounded(path, label, MAX_NATIVE_ARTIFACT_BYTES)?;
        inspected.push(inspect_static_native_elf(&bytes, label)?);
        let digest = sha256::bytes_digest(&bytes);
        run_canonical_native_inspector(repository, path, label, &digest)?;
    }
    Ok(inspected)
}

fn run_canonical_native_inspector(
    repository: &Path,
    artifact: &Path,
    label: &str,
    expected_digest: &str,
) -> Result<(), Failure> {
    let script = repository.join("toolchain/inspect-native-artifact.sh");
    let metadata = fs::symlink_metadata(&script).map_err(|error| {
        Failure::task(format!(
            "could not inspect canonical native artifact inspector: {error}"
        ))
    })?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > 64 * 1024 {
        return Err(Failure::task(
            "canonical native artifact inspector must be a bounded nonempty regular file",
        ));
    }

    let mut command = Command::new("sh");
    command.arg(&script).arg(artifact).current_dir(repository);
    let output = bounded_command_output(
        &mut command,
        MAX_INSPECTOR_STDOUT_BYTES,
        MAX_INSPECTOR_STDERR_BYTES,
        INSPECTOR_DEADLINE,
        &format!("canonical {label} native artifact inspection"),
    )?;
    if !output.status.success() {
        return Err(Failure::task(format!(
            "canonical {label} native artifact inspector rejected the candidate ({}): {}",
            child_status(output.status),
            bounded_diagnostic(&output.stderr, &output.stdout)
        )));
    }
    if !output.stderr.is_empty() {
        return Err(Failure::task(format!(
            "canonical {label} native artifact inspector wrote unexpected diagnostics: {}",
            bounded_diagnostic(&output.stderr, &[])
        )));
    }
    let report = std::str::from_utf8(&output.stdout).map_err(|_| {
        Failure::task(format!(
            "canonical {label} native artifact inspector report is not UTF-8"
        ))
    })?;
    let trimmed = report.strip_suffix('\n').ok_or_else(|| {
        Failure::task(format!(
            "canonical {label} native artifact inspector report lacks its final newline"
        ))
    })?;
    if trimmed.is_empty()
        || trimmed.contains(['\n', '\r'])
        || !trimmed.starts_with('{')
        || !trimmed.ends_with('}')
        || !trimmed.contains("\"report_kind\":\"wyrmroot-wyr0-native-artifact-inspection\"")
        || !trimmed.contains("\"verified\":true")
        || json_sha256_field(trimmed, "sha256")? != expected_digest
    {
        return Err(Failure::task(format!(
            "canonical {label} native artifact inspector returned an invalid or stale report"
        )));
    }
    Ok(())
}

fn bounded_command_output(
    command: &mut Command,
    stdout_maximum: u64,
    stderr_maximum: u64,
    deadline: Duration,
    label: &str,
) -> Result<BoundedCommandOutput, Failure> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| Failure::task(format!("could not start {label}: {error}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Failure::task(format!("could not capture {label} stdout")))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| Failure::task(format!("could not capture {label} stderr")))?;
    let (reader_sender, reader_receiver) = mpsc::channel();
    let (limit_sender, limit_receiver) = mpsc::channel();
    let stdout_sender = reader_sender.clone();
    let stdout_limit = limit_sender.clone();
    thread::spawn(move || {
        let result = read_pipe_bounded(
            stdout,
            stdout_maximum,
            Some((stdout_limit, PipeStream::Stdout)),
        );
        let _ = stdout_sender.send(ReaderResult::Stdout(result));
    });
    thread::spawn(move || {
        let result = read_pipe_bounded(
            stderr,
            stderr_maximum,
            Some((limit_sender, PipeStream::Stderr)),
        );
        let _ = reader_sender.send(ReaderResult::Stderr(result));
    });

    let started = Instant::now();
    let mut status = None;
    let mut stdout = None;
    let mut stderr = None;
    loop {
        if let Ok(stream) = limit_receiver.try_recv() {
            terminate_direct_child(&mut child, label)?;
            return Err(Failure::task(format!(
                "{label} {} exceeded its byte limit",
                match stream {
                    PipeStream::Stdout => "stdout",
                    PipeStream::Stderr => "stderr",
                }
            )));
        }
        while let Ok(result) = reader_receiver.try_recv() {
            match result {
                ReaderResult::Stdout(result) => stdout = Some(result),
                ReaderResult::Stderr(result) => stderr = Some(result),
            }
        }
        if status.is_none() {
            status = child
                .try_wait()
                .map_err(|error| Failure::task(format!("could not poll {label}: {error}")))?;
        }
        if status.is_some() && stdout.is_some() && stderr.is_some() {
            break;
        }
        if started.elapsed() >= deadline {
            terminate_direct_child(&mut child, label)?;
            return Err(Failure::task(format!(
                "{label} exceeded its {} ms wall-clock deadline",
                deadline.as_millis()
            )));
        }
        thread::sleep(Duration::from_millis(1));
    }

    let stdout =
        stdout.ok_or_else(|| Failure::task(format!("{label} omitted captured stdout")))??;
    let stderr =
        stderr.ok_or_else(|| Failure::task(format!("{label} omitted captured stderr")))??;
    if stdout.exceeded || stderr.exceeded {
        return Err(Failure::task(format!(
            "{label} exceeded its captured output limit"
        )));
    }
    Ok(BoundedCommandOutput {
        status: status.ok_or_else(|| Failure::task(format!("{label} omitted exit status")))?,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
    })
}

fn read_pipe_bounded<R: Read>(
    mut reader: R,
    maximum: u64,
    limit_signal: Option<(mpsc::Sender<PipeStream>, PipeStream)>,
) -> Result<BoundedPipe, Failure> {
    let mut bytes = Vec::new();
    (&mut reader)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| Failure::task(format!("could not capture inspector output: {error}")))?;
    let exceeded = bytes.len() as u64 > maximum;
    if exceeded {
        bytes.truncate(maximum as usize);
        if let Some((sender, stream)) = limit_signal {
            let _ = sender.send(stream);
        }
    }
    Ok(BoundedPipe { bytes, exceeded })
}

fn terminate_direct_child(child: &mut Child, label: &str) -> Result<(), Failure> {
    if child
        .try_wait()
        .map_err(|error| Failure::task(format!("could not inspect {label}: {error}")))?
        .is_none()
        && let Err(kill_error) = child.kill()
        && child
            .try_wait()
            .map_err(|error| Failure::task(format!("could not re-inspect {label}: {error}")))?
            .is_none()
    {
        return Err(Failure::task(format!(
            "could not terminate {label}: {kill_error}"
        )));
    }
    child
        .wait()
        .map_err(|error| Failure::task(format!("could not reap {label}: {error}")))?;
    Ok(())
}

fn child_status(status: ExitStatus) -> String {
    status.code().map_or_else(
        || "terminated by signal".to_owned(),
        |code| format!("exit {code}"),
    )
}

fn bounded_diagnostic(primary: &[u8], fallback: &[u8]) -> String {
    let bytes = if primary.is_empty() {
        fallback
    } else {
        primary
    };
    if bytes.is_empty() {
        return "no diagnostics".to_owned();
    }
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|character| {
            if character == '\n' || character == '\r' || character == '\t' {
                ' '
            } else if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect::<String>()
        .trim()
        .to_owned()
}

fn inspect_bootfs_executables(request: &HRequest) -> Result<Vec<String>, Failure> {
    let bytes = read_bounded(&request.bootfs, "bootfs", MAX_NATIVE_ARTIFACT_BYTES)?;
    let archive = Archive::new(&bytes)
        .map_err(|error| Failure::task(format!("could not parse I-B bootfs: {error:?}")))?;
    let mut names = Vec::new();
    for entry in archive.entries().filter(|entry| entry.is_executable()) {
        let name = entry
            .name_utf8()
            .map_err(|_| Failure::task("I-B bootfs executable path is not UTF-8"))?;
        inspect_static_native_elf(entry.data(), name)?;
        names.push(name.to_owned());
    }
    if !names.iter().any(|name| name == "system/init0")
        || !names.iter().any(|name| name == "bin/hello")
    {
        return Err(Failure::task(
            "WYR0-I-B bootfs does not contain executable init0 and hello payloads",
        ));
    }
    Ok(names)
}

fn inspect_static_native_elf(bytes: &[u8], label: &str) -> Result<NativeInspection, Failure> {
    if bytes.len() < ELF_HEADER_BYTES
        || &bytes[..4] != b"\x7fELF"
        || bytes[4] != 2
        || bytes[5] != 1
        || bytes[6] != 1
        || u16_at(bytes, 16)? != 2
        || u16_at(bytes, 18)? != 62
        || u32_at(bytes, 20)? != 1
        || usize::from(u16_at(bytes, 52)?) != ELF_HEADER_BYTES
    {
        return Err(Failure::task(format!(
            "WYR0-I-B {label} is not an ELF64 little-endian x86_64 static executable"
        )));
    }
    let entry = u64_at(bytes, 24)?;
    let program_offset = u64_at(bytes, 32)?;
    let entry_size = usize::from(u16_at(bytes, 54)?);
    let entry_count = usize::from(u16_at(bytes, 56)?);
    if entry == 0
        || entry_size < ELF_PROGRAM_HEADER_BYTES
        || !(1..=MAX_ELF_PROGRAM_HEADERS).contains(&entry_count)
    {
        return Err(Failure::task(format!(
            "WYR0-I-B {label} has invalid entry/program-header metadata"
        )));
    }

    let mut loads = 0;
    let mut executable = 0;
    let mut entry_covered = false;
    let mut mapped_pages = Vec::new();
    for index in 0..entry_count {
        let offset = program_offset
            .checked_add(
                u64::try_from(index)
                    .expect("bounded program header index")
                    .checked_mul(u64::try_from(entry_size).expect("program header size fits u64"))
                    .ok_or_else(|| Failure::task(format!("{label} program headers overflow")))?,
            )
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| Failure::task(format!("{label} program headers overflow")))?;
        let header_end = offset
            .checked_add(ELF_PROGRAM_HEADER_BYTES)
            .ok_or_else(|| Failure::task(format!("{label} program-header slice overflows")))?;
        let header = bytes
            .get(offset..header_end)
            .ok_or_else(|| Failure::task(format!("{label} program headers are truncated")))?;
        let kind = u32_at(header, 0)?;
        let flags = u32_at(header, 4)?;
        let file_offset = u64_at(header, 8)?;
        let virtual_address = u64_at(header, 16)?;
        let file_size = u64_at(header, 32)?;
        let memory_size = u64_at(header, 40)?;
        let alignment = u64_at(header, 48)?;
        let file_end = file_offset
            .checked_add(file_size)
            .filter(|end| *end <= bytes.len() as u64)
            .ok_or_else(|| Failure::task(format!("{label} segment exceeds its artifact")))?;
        let _ = file_end;
        if file_size > memory_size || (alignment != 0 && !alignment.is_power_of_two()) {
            return Err(Failure::task(format!(
                "WYR0-I-B {label} has invalid segment geometry"
            )));
        }
        if alignment > 1 && file_offset % alignment != virtual_address % alignment {
            return Err(Failure::task(format!(
                "WYR0-I-B {label} has incongruent segment alignment"
            )));
        }
        if kind == 2 || kind == 3 {
            return Err(Failure::task(format!(
                "WYR0-I-B {label} contains forbidden PT_DYNAMIC or PT_INTERP"
            )));
        }
        if !matches!(kind, 1 | 6 | 0x6474_e551) {
            return Err(Failure::task(format!(
                "WYR0-I-B {label} contains a program-header type outside the native subset"
            )));
        }
        if kind == 0x6474_e551 && (flags & 1 != 0 || flags > 6) {
            return Err(Failure::task(format!(
                "WYR0-I-B {label} requests an executable or invalid native stack"
            )));
        }
        if kind == 1 {
            if memory_size == 0 || !matches!(flags, 4..=6) {
                return Err(Failure::task(format!(
                    "WYR0-I-B {label} has an empty or invalid-permission PT_LOAD"
                )));
            }
            let memory_end = virtual_address
                .checked_add(memory_size)
                .ok_or_else(|| Failure::task(format!("{label} virtual load range overflows")))?;
            let page_start = virtual_address & !0xfff;
            let page_end = memory_end
                .checked_add(0xfff)
                .map(|value| value & !0xfff)
                .ok_or_else(|| Failure::task(format!("{label} virtual page range overflows")))?;
            if page_start < 0x1000 || page_end > 0x8000_0000_0000 {
                return Err(Failure::task(format!(
                    "WYR0-I-B {label} PT_LOAD leaves the admitted native user range"
                )));
            }
            if mapped_pages
                .iter()
                .any(|(start, end)| page_start < *end && *start < page_end)
            {
                return Err(Failure::task(format!(
                    "WYR0-I-B {label} PT_LOAD mappings overlap or create an executable alias"
                )));
            }
            mapped_pages.push((page_start, page_end));
            loads += 1;
            if flags & 1 != 0 {
                executable += 1;
                if flags & 2 != 0 {
                    return Err(Failure::task(format!(
                        "WYR0-I-B {label} contains a writable executable PT_LOAD"
                    )));
                }
                entry_covered |= entry >= virtual_address && entry < memory_end;
            }
        }
    }
    if loads == 0 || executable == 0 || !entry_covered {
        return Err(Failure::task(format!(
            "WYR0-I-B {label} lacks a valid executable load containing its entry"
        )));
    }
    Ok(NativeInspection {
        entry,
        load_segments: loads,
        executable_segments: executable,
    })
}

fn read_bounded(path: &Path, label: &str, max_bytes: u64) -> Result<Vec<u8>, Failure> {
    let mut file = File::open(path)
        .map_err(|error| Failure::task(format!("could not open I-B {label}: {error}")))?;
    let length = file
        .metadata()
        .map_err(|error| Failure::task(format!("could not stat I-B {label}: {error}")))?
        .len();
    if length == 0 || length > max_bytes {
        return Err(Failure::task(format!(
            "WYR0-I-B {label} is empty or exceeds its audit bound"
        )));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(
            usize::try_from(length).map_err(|_| {
                Failure::task(format!("WYR0-I-B {label} size is not representable"))
            })?,
        )
        .map_err(|_| Failure::task(format!("could not reserve I-B {label} buffer")))?;
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.read_to_end(&mut bytes))
        .map_err(|error| Failure::task(format!("could not read I-B {label}: {error}")))?;
    if bytes.len() as u64 != length {
        return Err(Failure::task(format!(
            "WYR0-I-B {label} changed length while being read"
        )));
    }
    Ok(bytes)
}

fn audit_abi_sources(repository: &Path) -> Result<SourceAudit, Failure> {
    let mut paths = Vec::new();
    for root in [
        "bootstrap",
        "crates",
        "loader",
        "userspace",
        "tools/xtask/src",
    ] {
        collect_sources(&repository.join(root), &mut paths)?;
    }
    paths.sort();
    if paths.len() > MAX_SOURCE_FILES {
        return Err(Failure::task(
            "WYR0-I-B ABI source audit exceeded its file-count bound",
        ));
    }
    let mut total = 0_u64;
    for path in &paths {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            Failure::task(format!(
                "could not stat ABI audit source {}: {error}",
                path.display()
            ))
        })?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_SOURCE_FILE_BYTES {
            return Err(Failure::task(format!(
                "ABI audit source {} is not a bounded regular file",
                path.display()
            )));
        }
        total = total
            .checked_add(metadata.len())
            .filter(|total| *total <= MAX_SOURCE_TOTAL_BYTES)
            .ok_or_else(|| Failure::task("WYR0-I-B ABI source audit exceeded its byte bound"))?;
        let source = fs::read_to_string(path).map_err(|error| {
            Failure::task(format!(
                "could not read ABI audit source {}: {error}",
                path.display()
            ))
        })?;
        if let Some(reason) = forbidden_abi_copy(&source) {
            let relative = path.strip_prefix(repository).unwrap_or(path);
            return Err(Failure::task(format!(
                "WYR0-I-B found a possible hand-copied Deepwyrm ABI definition in {}: {reason}",
                relative.display()
            )));
        }
    }
    Ok(SourceAudit {
        files: paths.len(),
        bytes: total,
    })
}

fn collect_sources(root: &Path, output: &mut Vec<PathBuf>) -> Result<(), Failure> {
    let mut entries = fs::read_dir(root)
        .map_err(|error| Failure::task(format!("could not enumerate {}: {error}", root.display())))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| Failure::task(format!("could not enumerate source tree: {error}")))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let kind = entry.file_type().map_err(|error| {
            Failure::task(format!(
                "could not inspect {}: {error}",
                entry.path().display()
            ))
        })?;
        if kind.is_symlink() {
            return Err(Failure::task(format!(
                "WYR0-I-B ABI source audit rejects symlink {}",
                entry.path().display()
            )));
        }
        if kind.is_dir() {
            collect_sources(&entry.path(), output)?;
        } else if kind.is_file() && is_source_file(&entry.path()) {
            output.push(entry.path());
        }
    }
    Ok(())
}

fn is_source_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("rs" | "c" | "h" | "cc" | "cpp" | "hpp" | "S")
    )
}

fn forbidden_abi_copy(source: &str) -> Option<String> {
    let sanitized = strip_comments_and_literals(source);
    for (index, line) in sanitized.lines().enumerate() {
        let tokens = source_tokens(line);
        for (position, token) in tokens.iter().enumerate() {
            if token.starts_with("DW_") {
                let remainder = &tokens[position + 1..];
                let declaration = (tokens
                    .first()
                    .is_some_and(|value| matches!(value.as_str(), "const" | "static"))
                    && (position == 1
                        || (position == 2 && tokens.get(1).map(String::as_str) == Some("mut"))))
                    || (remainder.first().map(String::as_str) == Some("=")
                        && remainder.get(1).is_some_and(|value| {
                            numeric_token(value)
                                || (value == "-"
                                    && remainder.get(2).is_some_and(|value| numeric_token(value)))
                        }));
                if declaration {
                    return Some(format!("local DW_ definition at line {}", index + 1));
                }
            }
            if matches!(token.as_str(), "struct" | "enum" | "union" | "type")
                && tokens.get(position + 1).is_some_and(|name| {
                    name.starts_with("Dw")
                        && name.as_bytes().get(2).is_some_and(u8::is_ascii_uppercase)
                })
            {
                return Some(format!(
                    "local Deepwyrm-shaped type declaration at line {}",
                    index + 1
                ));
            }
            if token == "dw_syscall6"
                && tokens.get(position + 1).map(String::as_str) == Some("(")
                && tokens
                    .get(position + 2)
                    .is_some_and(|value| numeric_token(value))
            {
                return Some(format!("raw numeric syscall ID at line {}", index + 1));
            }
        }
        if tokens.first().map(String::as_str) == Some("#")
            && tokens.get(1).map(String::as_str) == Some("define")
            && tokens.get(2).is_some_and(|name| name.starts_with("DW_"))
        {
            return Some(format!("local DW_ macro at line {}", index + 1));
        }
    }
    None
}

fn strip_comments_and_literals(source: &str) -> String {
    #[derive(Clone, Copy)]
    enum State {
        Code,
        LineComment,
        BlockComment(usize),
        String(bool),
        Character(bool),
        RawString(usize),
    }
    let bytes = source.as_bytes();
    let mut output = String::with_capacity(source.len());
    let mut state = State::Code;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        match state {
            State::Code if byte == b'/' && next == Some(b'/') => {
                output.push_str("  ");
                state = State::LineComment;
                index += 2;
            }
            State::Code if byte == b'/' && next == Some(b'*') => {
                output.push_str("  ");
                state = State::BlockComment(1);
                index += 2;
            }
            State::Code if raw_string_start(bytes, index).is_some() => {
                let (consumed, hashes) =
                    raw_string_start(bytes, index).expect("raw string start matched in guard");
                output.extend(std::iter::repeat_n(' ', consumed));
                state = State::RawString(hashes);
                index += consumed;
            }
            State::Code if byte == b'"' => {
                output.push(' ');
                state = State::String(false);
                index += 1;
            }
            State::Code if byte == b'\'' && character_literal_start(bytes, index) => {
                output.push(' ');
                state = State::Character(false);
                index += 1;
            }
            State::Code => {
                output.push(char::from(byte));
                index += 1;
            }
            State::LineComment if byte == b'\n' => {
                output.push('\n');
                state = State::Code;
                index += 1;
            }
            State::LineComment => {
                output.push(' ');
                index += 1;
            }
            State::BlockComment(depth) if byte == b'/' && next == Some(b'*') => {
                output.push_str("  ");
                state = State::BlockComment(depth + 1);
                index += 2;
            }
            State::BlockComment(depth) if byte == b'*' && next == Some(b'/') => {
                output.push_str("  ");
                state = if depth == 1 {
                    State::Code
                } else {
                    State::BlockComment(depth - 1)
                };
                index += 2;
            }
            State::BlockComment(depth) => {
                output.push(if byte == b'\n' { '\n' } else { ' ' });
                state = State::BlockComment(depth);
                index += 1;
            }
            State::String(escaped) | State::Character(escaped) => {
                output.push(if byte == b'\n' { '\n' } else { ' ' });
                let string = matches!(state, State::String(_));
                if escaped {
                    state = if string {
                        State::String(false)
                    } else {
                        State::Character(false)
                    };
                } else if byte == b'\\' {
                    state = if string {
                        State::String(true)
                    } else {
                        State::Character(true)
                    };
                } else if (string && byte == b'"') || (!string && byte == b'\'') {
                    state = State::Code;
                }
                index += 1;
            }
            State::RawString(hashes)
                if byte == b'"'
                    && index
                        .checked_add(1 + hashes)
                        .and_then(|end| bytes.get(index + 1..end))
                        .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#')) =>
            {
                output.extend(std::iter::repeat_n(' ', 1 + hashes));
                state = State::Code;
                index += 1 + hashes;
            }
            State::RawString(hashes) => {
                output.push(if byte == b'\n' { '\n' } else { ' ' });
                state = State::RawString(hashes);
                index += 1;
            }
        }
    }
    output
}

fn raw_string_start(bytes: &[u8], index: usize) -> Option<(usize, usize)> {
    if bytes.get(index) != Some(&b'r') {
        return None;
    }
    let mut cursor = index + 1;
    while bytes.get(cursor) == Some(&b'#') {
        cursor += 1;
    }
    (bytes.get(cursor) == Some(&b'"')).then_some((cursor - index + 1, cursor - index - 1))
}

fn character_literal_start(bytes: &[u8], index: usize) -> bool {
    matches!(
        (
            bytes.get(index + 1),
            bytes.get(index + 2),
            bytes.get(index + 3)
        ),
        (Some(b'\\'), Some(_), Some(b'\'')) | (Some(_), Some(b'\''), _)
    )
}

fn source_tokens(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for character in line.chars() {
        if character.is_ascii_alphanumeric() || character == '_' {
            current.push(character);
        } else {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            if matches!(character, '=' | '(' | '#' | '-') {
                tokens.push(character.to_string());
            }
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn numeric_token(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_digit())
}

fn json_sha256_field(report: &str, field: &str) -> Result<String, Failure> {
    let marker = format!("\"{field}\":\"");
    let start = report
        .find(&marker)
        .map(|index| index + marker.len())
        .ok_or_else(|| Failure::task(format!("I-B image inspection omitted {field}")))?;
    let digest = report
        .get(start..start + 64)
        .filter(|value| {
            value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| Failure::task(format!("I-B image inspection has invalid {field}")))?;
    if report.as_bytes().get(start + 64) != Some(&b'"') {
        return Err(Failure::task(format!(
            "I-B image inspection has invalid {field}"
        )));
    }
    Ok(digest.to_owned())
}

fn json_string_array(values: &[String]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| format!("\"{}\"", json_escape(value)))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn json_escape(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                output.push_str(&format!("\\u{:04x}", u32::from(character)));
            }
            character => output.push(character),
        }
    }
    output
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, Failure> {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or_else(|| Failure::task("WYR0-I-B ELF u16 field is truncated"))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, Failure> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| Failure::task("WYR0-I-B ELF u32 field is truncated"))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, Failure> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| Failure::task("WYR0-I-B ELF u64 field is truncated"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_audit_separates_product_revision_from_the_pinned_abi_revision() {
        let later_product = "2a9a42b33b9a4d0c7587ee7e4b51314b351e0b74";
        assert!(
            validate_request_source_pins(
                later_product,
                RUST_REVISION,
                later_product,
                RUST_REVISION,
                DEEPWYRM_ABI_REVISION,
                RUST_REVISION,
            )
            .is_ok()
        );
        assert!(
            validate_request_source_pins(
                later_product,
                RUST_REVISION,
                "6b25d12e69f5bd6f5e1e9a983310c60a36af22fa",
                RUST_REVISION,
                DEEPWYRM_ABI_REVISION,
                RUST_REVISION,
            )
            .is_err()
        );
    }

    #[test]
    fn static_native_elf_inspection_rejects_dynamic_interp_and_wx() {
        let valid = elf_fixture(1, 5);
        let inspected = inspect_static_native_elf(&valid, "fixture").expect("valid static ELF");
        assert_eq!(inspected.load_segments, 1);
        assert_eq!(inspected.executable_segments, 1);

        assert!(inspect_static_native_elf(&elf_fixture(3, 4), "interp").is_err());
        assert!(inspect_static_native_elf(&elf_fixture(2, 4), "dynamic").is_err());
        assert!(inspect_static_native_elf(&elf_fixture(1, 7), "wx").is_err());

        let mut phdr_overflow = valid.clone();
        put_u64(&mut phdr_overflow, 32, u64::MAX);
        assert!(inspect_static_native_elf(&phdr_overflow, "phdr-overflow").is_err());

        let mut virtual_overflow = valid.clone();
        put_u64(&mut virtual_overflow, 80, u64::MAX - 0x7f);
        put_u64(&mut virtual_overflow, 104, 0x100);
        assert!(inspect_static_native_elf(&virtual_overflow, "virtual-overflow").is_err());

        let mut alias = valid.clone();
        put_u16(&mut alias, 56, 2);
        program_header(&mut alias, 120, 1, 4, 0, 0x400080, 64, 64, 1);
        assert!(inspect_static_native_elf(&alias, "executable-alias").is_err());
    }

    #[test]
    fn source_audit_rejects_numeric_abi_copies_and_raw_syscalls() {
        assert!(forbidden_abi_copy("const DW_STATUS_FAKE: u32 = 0x10;").is_some());
        assert!(forbidden_abi_copy("const DW_STATUS_FAKE: u32 = 1 << 4;").is_some());
        assert!(forbidden_abi_copy("#define DW_RIGHT_FAKE 4").is_some());
        assert!(forbidden_abi_copy("unsafe { dw_syscall6(17, 0, 0, 0, 0, 0, 0) }").is_some());
        assert!(forbidden_abi_copy("#[repr(C)] struct DwFakeWire { value: u64 }").is_some());
        assert!(
            forbidden_abi_copy(
                "// const DW_STATUS_FAKE: u32 = 1;\nuse deepwyrm_abi::DW_STATUS_OK;\nlet text = \"DW_RIGHT_FAKE = 4\";"
            )
            .is_none()
        );
        assert!(
            forbidden_abi_copy(
                "fn borrow<'a>(value: &'a u32) -> &'a u32 { value }\nconst DW_FAKE: u32 = 7;"
            )
            .is_some()
        );
        assert!(
            forbidden_abi_copy(
                "let text = r###\"const DW_FAKE: u32 = 7; dw_syscall6(9)\"###;\nuse deepwyrm_abi::DW_STATUS_OK;"
            )
            .is_none()
        );
    }

    #[test]
    fn bounded_source_audit_accepts_the_current_generated_abi_consumers() {
        let repository = crate::tasks::repository_root().expect("repository root");
        let audit = audit_abi_sources(&repository).expect("current source audit");
        assert!(audit.files > 0);
        assert!(audit.bytes > 0);
    }

    #[test]
    fn bounded_file_comparison_requires_exact_bytes() {
        let root = temporary_root("compare");
        fs::create_dir(&root).expect("create temporary root");
        let first = root.join("first");
        let second = root.join("second");
        fs::write(&first, b"same").expect("write first");
        fs::write(&second, b"same").expect("write second");
        require_identical_files(&first, &second, "fixture", 16).expect("identical files");
        assert!(reject_alias(&first, &first, "fixture").is_err());
        reject_alias(&first, &second, "fixture").expect("independent files");
        fs::write(&second, b"different").expect("change second");
        assert!(require_identical_files(&first, &second, "fixture", 16).is_err());
        fs::remove_dir_all(root).expect("remove temporary root");
    }

    #[test]
    fn canonical_inspector_is_invoked_and_failure_diagnostics_are_preserved() {
        let root = temporary_root("canonical-inspector");
        fs::create_dir_all(root.join("toolchain")).expect("create toolchain directory");
        let artifact = root.join("native.elf");
        fs::write(&artifact, b"artifact-bytes").expect("write artifact");
        let digest = sha256::bytes_digest(b"artifact-bytes");
        let script = root.join("toolchain/inspect-native-artifact.sh");
        fs::write(
            &script,
            format!(
                concat!(
                    "#!/bin/sh\nset -eu\n",
                    "test \"$#\" -eq 1\ntest \"$1\" = '{}'\n",
                    "printf '%s\\n' '{{\"schema_version\":1,",
                    "\"report_kind\":\"wyrmroot-wyr0-native-artifact-inspection\",",
                    "\"verified\":true,\"sha256\":\"{}\"}}'\n"
                ),
                artifact.display(),
                digest,
            ),
        )
        .expect("write success inspector");
        run_canonical_native_inspector(&root, &artifact, "fixture", &digest)
            .expect("canonical inspector success");

        fs::write(
            &script,
            "#!/bin/sh\nprintf '%s\\n' 'sentinel canonical failure' >&2\nexit 9\n",
        )
        .expect("write failure inspector");
        let failure = run_canonical_native_inspector(&root, &artifact, "fixture", &digest)
            .expect_err("canonical inspector failure accepted");
        assert!(failure.message.contains("sentinel canonical failure"));
        assert!(failure.message.contains("exit 9"));
        fs::remove_dir_all(root).expect("remove temporary root");
    }

    #[test]
    fn local_deepwyrm_transport_is_exact_and_process_scoped() {
        const SOURCE: &str = include_str!("../../../toolchain/cargo-with-local-deepwyrm.sh");
        for expected in [
            "revision=cfc69bd8a49819ce1cda1a132cf56e55c93f92e4",
            "abi_tree=1c6a74f130e386eee95b3780c75950beefd0037d",
            "abi_crate_tree=3c4b82b4253d7d21d0f578d8d5b966304472cd8f",
            "syscall_crate_tree=a64290953ccc0548e908be88586969ac0b70b589",
            "GIT_CONFIG_GLOBAL=/dev/null",
            "GIT_CONFIG_COUNT=1",
            "CARGO_NET_GIT_FETCH_WITH_CLI=true",
        ] {
            assert!(SOURCE.contains(expected), "transport omitted {expected}");
        }
        assert!(SOURCE.contains("exec env"));
        assert!(!SOURCE.contains("git config --global"));
    }

    #[test]
    fn report_field_parser_is_strict() {
        let digest = "a".repeat(64);
        let report = format!("{{\"candidate_sha256\":\"{digest}\"}}");
        assert_eq!(
            json_sha256_field(&report, "candidate_sha256").unwrap(),
            digest
        );
        assert!(json_sha256_field("{\"candidate_sha256\":\"bad\"}", "candidate_sha256").is_err());
    }

    fn elf_fixture(kind: u32, flags: u32) -> Vec<u8> {
        let mut bytes = vec![0_u8; 256];
        let byte_len = bytes.len() as u64;
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        put_u16(&mut bytes, 16, 2);
        put_u16(&mut bytes, 18, 62);
        put_u32(&mut bytes, 20, 1);
        put_u64(&mut bytes, 24, 0x400080);
        put_u64(&mut bytes, 32, 64);
        put_u16(&mut bytes, 52, 64);
        put_u16(&mut bytes, 54, 56);
        put_u16(&mut bytes, 56, 1);
        program_header(
            &mut bytes, 64, kind, flags, 0, 0x400000, byte_len, byte_len, 0x1000,
        );
        bytes
    }

    #[allow(clippy::too_many_arguments)]
    fn program_header(
        bytes: &mut [u8],
        offset: usize,
        kind: u32,
        flags: u32,
        file_offset: u64,
        virtual_address: u64,
        file_size: u64,
        memory_size: u64,
        alignment: u64,
    ) {
        put_u32(bytes, offset, kind);
        put_u32(bytes, offset + 4, flags);
        put_u64(bytes, offset + 8, file_offset);
        put_u64(bytes, offset + 16, virtual_address);
        put_u64(bytes, offset + 32, file_size);
        put_u64(bytes, offset + 40, memory_size);
        put_u64(bytes, offset + 48, alignment);
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn temporary_root(label: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "wyrmroot-xtask-i-b-{label}-{}-{nonce}",
            std::process::id()
        ))
    }
}
