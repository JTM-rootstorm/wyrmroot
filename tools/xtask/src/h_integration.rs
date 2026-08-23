//! WYR0-H exact-artifact image, q35/OVMF, GDB, and integration tooling.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use wyrmroot_bootfs::builder::{Builder, FileMode};

use crate::cli::{G3ImageArguments, HProfile};
use crate::error::Failure;
use crate::h_request::{self, ExpectedOutcome, HRequest};
use crate::sha256;

const MAX_GUEST_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FIRMWARE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SERIAL_BYTES: u64 = 16 * 1024 * 1024;
const COMPLETION_RECORD_BYTES: usize = 38;
const DEFAULT_MEMORY_MIB: u32 = 1024;
const SMP_MEMORY_MIB: u32 = 2048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionKind {
    Run,
    Integration,
    Gdb,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuestOutcome {
    Pass,
    Fail,
    Panic,
}

impl GuestOutcome {
    const fn name(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Panic => "panic",
        }
    }

    const fn matches(self, expected: ExpectedOutcome) -> bool {
        matches!(
            (self, expected),
            (Self::Pass, ExpectedOutcome::Pass)
                | (Self::Fail, ExpectedOutcome::Fail)
                | (Self::Panic, ExpectedOutcome::Panic)
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GuestRecord {
    outcome: GuestOutcome,
    test_id: u32,
    detail: u32,
    line: usize,
}

#[derive(Debug, Eq, PartialEq)]
struct CandidateArtifacts {
    loader: PathBuf,
    kernel: PathBuf,
    symbols: PathBuf,
    bootstrap: PathBuf,
    init0: PathBuf,
    hello: PathBuf,
    ovmf_code: PathBuf,
    ovmf_vars_template: PathBuf,
}

#[derive(Debug)]
struct CandidateDigests {
    request: String,
    loader: String,
    kernel: String,
    symbols: String,
    bootstrap: String,
    init0: String,
    hello: String,
    bootfs: String,
    esp: String,
    ovmf_code: String,
    ovmf_vars_template: String,
    candidate: String,
}

impl HProfile {
    const fn vcpus(self) -> u32 {
        match self {
            Self::Default => 1,
            Self::Smp => 4,
        }
    }

    const fn memory_mib(self) -> u32 {
        match self {
            Self::Default => DEFAULT_MEMORY_MIB,
            Self::Smp => SMP_MEMORY_MIB,
        }
    }
}

pub(crate) fn build(request_path: &str) -> Result<String, Failure> {
    let request = h_request::load(Path::new(request_path))?;
    verify_source_revisions(&request)?;
    let artifacts = verify_candidate_inputs(&request)?;
    require_absent(&request, &request.bootfs, "bootfs output")?;
    require_absent(&request, &request.esp, "ESP output")?;
    require_absent(&request, &request.provenance, "provenance output")?;

    let bootfs = build_bootfs_bytes(&artifacts)?;
    write_new(&request, &request.bootfs, &bootfs, "bootfs")?;
    let image_arguments = image_arguments(&request, &artifacts);
    let result = (|| {
        crate::g3_image::build_in_root(&image_arguments, request.path.parent())?;
        write_provenance(&request, &artifacts)?;
        inspect_loaded(&request, &artifacts)
    })();
    if result.is_err() {
        remove_created(&request.provenance);
        remove_created(&request.esp);
        remove_created(&request.bootfs);
    }
    result
}

pub(crate) fn inspect(request_path: &str) -> Result<String, Failure> {
    let request = h_request::load(Path::new(request_path))?;
    verify_source_revisions(&request)?;
    let artifacts = verify_candidate_inputs(&request)?;
    inspect_loaded(&request, &artifacts)
}

pub(crate) fn run(profile: HProfile, request_path: &str) -> Result<String, Failure> {
    let request = h_request::load(Path::new(request_path))?;
    verify_source_revisions(&request)?;
    let artifacts = verify_candidate_inputs(&request)?;
    inspect_loaded(&request, &artifacts)?;
    execute(profile, &request, &artifacts, ExecutionKind::Run)
}

pub(crate) fn gdb(profile: HProfile, request_path: &str) -> Result<String, Failure> {
    let request = h_request::load(Path::new(request_path))?;
    verify_source_revisions(&request)?;
    let artifacts = verify_candidate_inputs(&request)?;
    inspect_loaded(&request, &artifacts)?;
    execute(profile, &request, &artifacts, ExecutionKind::Gdb)
}

pub(crate) fn integration(
    profile: Option<HProfile>,
    request_path: &str,
) -> Result<String, Failure> {
    let request = h_request::load(Path::new(request_path))?;
    verify_source_revisions(&request)?;
    let artifacts = verify_candidate_inputs(&request)?;
    if outputs_all_absent(&request)? {
        let bootfs = build_bootfs_bytes(&artifacts)?;
        write_new(&request, &request.bootfs, &bootfs, "bootfs")?;
        let image_arguments = image_arguments(&request, &artifacts);
        let result = (|| {
            crate::g3_image::build_in_root(&image_arguments, request.path.parent())?;
            write_provenance(&request, &artifacts)
        })();
        if let Err(error) = result {
            remove_created(&request.provenance);
            remove_created(&request.esp);
            remove_created(&request.bootfs);
            return Err(error);
        }
    }
    let inspection = inspect_loaded(&request, &artifacts)?;
    match profile {
        Some(profile) => execute(profile, &request, &artifacts, ExecutionKind::Integration),
        None => {
            let default = execute(
                HProfile::Default,
                &request,
                &artifacts,
                ExecutionKind::Integration,
            );
            let smp = execute(
                HProfile::Smp,
                &request,
                &artifacts,
                ExecutionKind::Integration,
            );
            join_profile_results(&inspection, default, smp)
        }
    }
}

fn join_profile_results(
    inspection: &str,
    default: Result<String, Failure>,
    smp: Result<String, Failure>,
) -> Result<String, Failure> {
    match (default, smp) {
        (Ok(default), Ok(smp)) => Ok(format!(
            concat!(
                "{{\"schema_version\":2,\"phase\":\"WYR0-H\",",
                "\"status\":\"PASS\",\"same_media\":true,",
                "\"inspection\":{},\"default\":{},\"smp\":{}}}\n"
            ),
            inspection.trim(),
            default.trim(),
            smp.trim()
        )),
        (Err(default), Ok(_)) => Err(Failure::task(format!(
            "paired WYR0-H integration failed: default: {}",
            default.message
        ))),
        (Ok(_), Err(smp)) => Err(Failure::task(format!(
            "paired WYR0-H integration failed: smp: {}",
            smp.message
        ))),
        (Err(default), Err(smp)) => Err(Failure::task(format!(
            "paired WYR0-H integration failed: default: {}; smp: {}",
            default.message, smp.message
        ))),
    }
}

fn inspect_loaded(request: &HRequest, artifacts: &CandidateArtifacts) -> Result<String, Failure> {
    let expected_bootfs = build_bootfs_bytes(artifacts)?;
    let actual_bootfs = read_regular(&request.bootfs, "bootfs", MAX_GUEST_ARTIFACT_BYTES)?;
    if actual_bootfs != expected_bootfs {
        return Err(Failure::task(
            "WYR0-H bootfs does not contain the exact current init0 and hello bytes",
        ));
    }
    let image_report = crate::g3_image::inspect(&image_arguments(request, artifacts))?;
    let expected_provenance = provenance_contents(request, artifacts)?;
    let actual_provenance = fs::read(&request.provenance)
        .map_err(|error| Failure::task(format!("could not read WYR0-H provenance: {error}")))?;
    if actual_provenance != expected_provenance.as_bytes() {
        return Err(Failure::task(
            "WYR0-H provenance is absent, stale, or disagrees with the exact candidate",
        ));
    }
    let digests = candidate_digests(request, artifacts)?;
    let provenance = sha256::bytes_digest(&actual_provenance);
    Ok(format!(
        concat!(
            "{{\"schema_version\":2,\"phase\":\"WYR0-H\",",
            "\"status\":\"PASS\",{}",
            "\"expected_outcome\":\"{}\",\"expected_detail\":{},",
            "\"default\":{{\"vcpu\":{},\"memory_mib\":{}}},",
            "\"smp\":{{\"vcpu\":{},\"memory_mib\":{}}},",
            "\"no_host_share\":true,\"esp_inspection\":{}}}\n"
        ),
        manifest_json_fields(&digests, &provenance),
        request.expected_outcome.name(),
        request.expected_detail,
        HProfile::Default.vcpus(),
        HProfile::Default.memory_mib(),
        HProfile::Smp.vcpus(),
        HProfile::Smp.memory_mib(),
        image_report.trim(),
    ))
}

fn verify_candidate_inputs(request: &HRequest) -> Result<CandidateArtifacts, Failure> {
    let artifacts = CandidateArtifacts {
        loader: h_request::canonical_regular(
            &request.loader,
            "loader.efi",
            MAX_GUEST_ARTIFACT_BYTES,
        )?,
        kernel: h_request::canonical_regular(
            &request.kernel,
            "deepwyrm.elf",
            MAX_GUEST_ARTIFACT_BYTES,
        )?,
        symbols: h_request::canonical_regular(
            &request.symbols,
            "Deepwyrm symbols",
            MAX_GUEST_ARTIFACT_BYTES,
        )?,
        bootstrap: h_request::canonical_regular(
            &request.bootstrap,
            "bootstrap.elf",
            MAX_GUEST_ARTIFACT_BYTES,
        )?,
        init0: h_request::canonical_regular(
            &request.init0,
            "system/init0",
            MAX_GUEST_ARTIFACT_BYTES,
        )?,
        hello: h_request::canonical_regular(&request.hello, "bin/hello", MAX_GUEST_ARTIFACT_BYTES)?,
        ovmf_code: h_request::canonical_regular(
            &request.ovmf_code,
            "OVMF code",
            MAX_FIRMWARE_BYTES,
        )?,
        ovmf_vars_template: h_request::canonical_regular(
            &request.ovmf_vars_template,
            "OVMF vars template",
            MAX_FIRMWARE_BYTES,
        )?,
    };
    for (path, label) in [
        (&artifacts.loader, "loader.efi"),
        (&artifacts.kernel, "deepwyrm.elf"),
        (&artifacts.symbols, "Deepwyrm symbols"),
        (&artifacts.bootstrap, "bootstrap.elf"),
        (&artifacts.init0, "init0"),
        (&artifacts.hello, "hello"),
        (&artifacts.ovmf_code, "OVMF code"),
        (&artifacts.ovmf_vars_template, "OVMF vars template"),
    ] {
        let display = path.to_string_lossy();
        if display.contains([',', '\n', '\r']) {
            return Err(Failure::task(format!(
                "WYR0-H {label} path contains a delimiter unsupported by QEMU media arguments"
            )));
        }
    }
    if digest(&artifacts.kernel, "deepwyrm.elf")? != digest(&artifacts.symbols, "Deepwyrm symbols")?
    {
        return Err(Failure::task(
            "WYR0-H GDB symbols do not exactly match the booted kernel SHA-256",
        ));
    }
    Ok(artifacts)
}

fn build_bootfs_bytes(artifacts: &CandidateArtifacts) -> Result<Vec<u8>, Failure> {
    let init0 = read_regular(&artifacts.init0, "init0", MAX_GUEST_ARTIFACT_BYTES)?;
    let hello = read_regular(&artifacts.hello, "hello", MAX_GUEST_ARTIFACT_BYTES)?;
    let mut builder = Builder::new();
    builder
        .add(b"system/init0", &init0, FileMode::Executable)
        .map_err(|error| Failure::task(format!("could not add init0 to bootfs: {error:?}")))?;
    builder
        .add(b"bin/hello", &hello, FileMode::Executable)
        .map_err(|error| Failure::task(format!("could not add hello to bootfs: {error:?}")))?;
    builder
        .build()
        .map_err(|error| Failure::task(format!("could not build WYR0-H bootfs: {error:?}")))
}

fn image_arguments(request: &HRequest, artifacts: &CandidateArtifacts) -> G3ImageArguments {
    G3ImageArguments {
        image: request.esp.display().to_string(),
        loader: artifacts.loader.display().to_string(),
        kernel: artifacts.kernel.display().to_string(),
        bootstrap: artifacts.bootstrap.display().to_string(),
        bootfs: request.bootfs.display().to_string(),
    }
}

fn write_provenance(request: &HRequest, artifacts: &CandidateArtifacts) -> Result<(), Failure> {
    let contents = provenance_contents(request, artifacts)?;
    write_new(
        request,
        &request.provenance,
        contents.as_bytes(),
        "provenance",
    )
}

fn provenance_contents(
    request: &HRequest,
    artifacts: &CandidateArtifacts,
) -> Result<String, Failure> {
    let digests = candidate_digests(request, artifacts)?;
    Ok(format!(
        concat!(
            "schema_version = 2\n",
            "phase = \"WYR0-H\"\n",
            "deepwyrm_revision = \"{}\"\n",
            "wyrmroot_revision = \"{}\"\n",
            "rust_revision = \"{}\"\n",
            "request_sha256 = \"{}\"\n",
            "candidate_sha256 = \"{}\"\n",
            "loader_sha256 = \"{}\"\n",
            "kernel_sha256 = \"{}\"\n",
            "symbols_sha256 = \"{}\"\n",
            "bootstrap_sha256 = \"{}\"\n",
            "init0_sha256 = \"{}\"\n",
            "hello_sha256 = \"{}\"\n",
            "bootfs_sha256 = \"{}\"\n",
            "esp_sha256 = \"{}\"\n",
            "ovmf_code_sha256 = \"{}\"\n",
            "ovmf_vars_template_sha256 = \"{}\"\n",
            "expected_outcome = \"{}\"\n",
            "expected_detail = {}\n",
            "default_vcpu = {}\n",
            "default_memory_mib = {}\n",
            "smp_vcpu = {}\n",
            "smp_memory_mib = {}\n",
            "machine = \"q35\"\n",
            "firmware = \"OVMF\"\n",
            "no_host_share = true\n",
            "same_boot_media = true\n"
        ),
        request.deepwyrm_revision,
        request.wyrmroot_revision,
        request.rust_revision,
        digests.request,
        digests.candidate,
        digests.loader,
        digests.kernel,
        digests.symbols,
        digests.bootstrap,
        digests.init0,
        digests.hello,
        digests.bootfs,
        digests.esp,
        digests.ovmf_code,
        digests.ovmf_vars_template,
        request.expected_outcome.name(),
        request.expected_detail,
        HProfile::Default.vcpus(),
        HProfile::Default.memory_mib(),
        HProfile::Smp.vcpus(),
        HProfile::Smp.memory_mib(),
    ))
}

fn candidate_digests(
    request: &HRequest,
    artifacts: &CandidateArtifacts,
) -> Result<CandidateDigests, Failure> {
    let request_digest = digest(&request.path, "WYR0-H request")?;
    let loader = digest(&artifacts.loader, "loader.efi")?;
    let kernel = digest(&artifacts.kernel, "deepwyrm.elf")?;
    let symbols = digest(&artifacts.symbols, "Deepwyrm symbols")?;
    let bootstrap = digest(&artifacts.bootstrap, "bootstrap.elf")?;
    let init0 = digest(&artifacts.init0, "init0")?;
    let hello = digest(&artifacts.hello, "hello")?;
    let bootfs = digest(&request.bootfs, "bootfs")?;
    let esp = digest(&request.esp, "ESP")?;
    let ovmf_code = digest(&artifacts.ovmf_code, "OVMF code")?;
    let ovmf_vars_template = digest(&artifacts.ovmf_vars_template, "OVMF vars template")?;
    let candidate = sha256::bytes_digest(
        format!(
            concat!(
                "wyr0-h-candidate-v1\nrequest={}\n",
                "deepwyrm={}\nwyrmroot={}\nrust={}\nselector={}\ntest_id={}\n",
                "expected_outcome={}\nexpected_detail={}\n",
                "loader={}\nkernel={}\nsymbols={}\n",
                "bootstrap={}\ninit0={}\nhello={}\n",
                "bootfs={}\nesp={}\novmf_code={}\n",
                "ovmf_vars_template={}\n"
            ),
            request_digest,
            request.deepwyrm_revision,
            request.wyrmroot_revision,
            request.rust_revision,
            request.selector,
            request.test_id,
            request.expected_outcome.name(),
            request.expected_detail,
            loader,
            kernel,
            symbols,
            bootstrap,
            init0,
            hello,
            bootfs,
            esp,
            ovmf_code,
            ovmf_vars_template,
        )
        .as_bytes(),
    );
    Ok(CandidateDigests {
        request: request_digest,
        loader,
        kernel,
        symbols,
        bootstrap,
        init0,
        hello,
        bootfs,
        esp,
        ovmf_code,
        ovmf_vars_template,
        candidate,
    })
}

fn manifest_json_fields(digests: &CandidateDigests, provenance: &str) -> String {
    format!(
        concat!(
            "\"candidate_sha256\":\"{}\",\"provenance_sha256\":\"{}\",",
            "\"request_sha256\":\"{}\",\"loader_sha256\":\"{}\",",
            "\"kernel_sha256\":\"{}\",\"symbols_sha256\":\"{}\",",
            "\"bootstrap_sha256\":\"{}\",\"init0_sha256\":\"{}\",",
            "\"hello_sha256\":\"{}\",\"bootfs_sha256\":\"{}\",",
            "\"esp_sha256\":\"{}\",\"ovmf_code_sha256\":\"{}\",",
            "\"ovmf_vars_template_sha256\":\"{}\","
        ),
        digests.candidate,
        provenance,
        digests.request,
        digests.loader,
        digests.kernel,
        digests.symbols,
        digests.bootstrap,
        digests.init0,
        digests.hello,
        digests.bootfs,
        digests.esp,
        digests.ovmf_code,
        digests.ovmf_vars_template,
    )
}

fn result_manifest_json(
    request: &HRequest,
    artifacts: &CandidateArtifacts,
) -> Result<String, Failure> {
    let digests = candidate_digests(request, artifacts)?;
    let provenance = digest(&request.provenance, "provenance")?;
    Ok(manifest_json_fields(&digests, &provenance))
}

/// A terminal PASS is evidence about the media actually launched, not merely
/// the media inspected before QEMU started. Re-admit the request and candidate
/// at the publication boundary and require the manifest to be byte-identical.
fn revalidate_before_pass(
    request: &HRequest,
    artifacts: &CandidateArtifacts,
    pre_execution_manifest: &str,
) -> Result<(), Failure> {
    let reloaded = h_request::load(&request.path)?;
    if &reloaded != request {
        return Err(Failure::task(
            "WYR0-H request changed after inspection; refusing PASS evidence",
        ));
    }
    h_request::validate_outputs(&reloaded)?;
    let current = verify_candidate_inputs(&reloaded)?;
    if &current != artifacts {
        return Err(Failure::task(
            "WYR0-H candidate paths changed after inspection; refusing PASS evidence",
        ));
    }
    inspect_loaded(&reloaded, &current)?;
    if result_manifest_json(&reloaded, &current)? != pre_execution_manifest {
        return Err(Failure::task(
            "WYR0-H candidate digest changed after inspection; refusing PASS evidence",
        ));
    }
    Ok(())
}

fn execute(
    profile: HProfile,
    request: &HRequest,
    artifacts: &CandidateArtifacts,
    kind: ExecutionKind,
) -> Result<String, Failure> {
    let run = prepare_run_directory(profile, request, artifacts)?;
    let pre_execution_manifest = result_manifest_json(request, artifacts)?;
    let args = qemu_arguments(profile, request, artifacts, kind, &run);
    let spawned = Command::new("qemu-system-x86_64")
        .args(&args)
        .current_dir(
            request
                .path
                .parent()
                .ok_or_else(|| Failure::task("WYR0-H request has no parent"))?,
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(open_new(
            request,
            &run.stderr_log,
            "QEMU stderr",
        )?))
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            if kind == ExecutionKind::Integration {
                write_integration_host_failure(
                    profile,
                    request,
                    artifacts,
                    &run,
                    HostFailure {
                        status: None,
                        reason: "qemu_spawn_failed",
                        timeout_seconds: None,
                        cleanup: CleanupDisposition::not_started(),
                    },
                )?;
            }
            return Err(Failure::task(format!(
                "could not launch canonical WYR0-H QEMU: {error}"
            )));
        }
    };

    if kind == ExecutionKind::Gdb {
        let status = Command::new("gdb")
            .args(gdb_arguments(artifacts))
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status();
        let status = match status {
            Ok(status) => status,
            Err(error) => {
                let _ = stop_child(&mut child);
                return Err(Failure::task(format!(
                    "could not launch WYR0-H GDB: {error}"
                )));
            }
        };
        let _ = stop_child(&mut child);
        if !status.success() {
            return Err(Failure::task(format!(
                "WYR0-H GDB exited with {}",
                status_label(&status)
            )));
        }
        return Ok(format!(
            "{{\"schema_version\":2,\"phase\":\"WYR0-H\",\"mode\":\"gdb\",\"profile\":\"{}\",\"status\":\"DIAGNOSTIC\",\"acceptance\":false,\"symbols_sha256\":\"{}\"}}\n",
            profile.name(),
            digest(&artifacts.symbols, "Deepwyrm symbols")?
        ));
    }

    let status = match wait_bounded(&mut child, request.timeout_seconds) {
        Ok(WaitOutcome::Exited(status)) => status,
        Ok(WaitOutcome::TimedOut(cleanup)) if kind == ExecutionKind::Integration => {
            write_integration_host_failure(
                profile,
                request,
                artifacts,
                &run,
                HostFailure {
                    status: None,
                    reason: "qemu_timeout",
                    timeout_seconds: Some(request.timeout_seconds),
                    cleanup,
                },
            )?;
            return Err(Failure::task(format!(
                "WYR0-H QEMU timed out after {} seconds",
                request.timeout_seconds
            )));
        }
        Ok(WaitOutcome::TimedOut(_)) => {
            return Err(Failure::task(format!(
                "WYR0-H QEMU timed out after {} seconds",
                request.timeout_seconds
            )));
        }
        Err(error) if kind == ExecutionKind::Integration => {
            write_integration_host_failure(
                profile,
                request,
                artifacts,
                &run,
                HostFailure {
                    status: None,
                    reason: "qemu_wait_failed",
                    timeout_seconds: None,
                    cleanup: error.cleanup,
                },
            )?;
            return Err(error.failure);
        }
        Err(error) => return Err(error.failure),
    };
    if kind == ExecutionKind::Run {
        if !status.success() {
            return Err(Failure::task(format!(
                "WYR0-H run exited with {}",
                status_label(&status)
            )));
        }
        return Ok(format!(
            "{{\"schema_version\":2,\"phase\":\"WYR0-H\",\"mode\":\"run\",\"profile\":\"{}\",\"status\":\"DIAGNOSTIC\",\"acceptance\":false,\"qemu_exit_status\":0}}\n",
            profile.name()
        ));
    }

    let serial = match read_regular(&run.serial_log, "integration serial log", MAX_SERIAL_BYTES) {
        Ok(serial) => serial,
        Err(error) => {
            write_integration_host_failure(
                profile,
                request,
                artifacts,
                &run,
                HostFailure {
                    status: Some(&status),
                    reason: "serial_log_unreadable",
                    timeout_seconds: None,
                    cleanup: CleanupDisposition::exited(),
                },
            )?;
            return Err(error);
        }
    };
    let record = match parse_terminal_record(&serial, request.test_id) {
        Ok(record) => record,
        Err(error) => {
            write_integration_host_failure(
                profile,
                request,
                artifacts,
                &run,
                HostFailure {
                    status: Some(&status),
                    reason: "terminal_record_invalid",
                    timeout_seconds: None,
                    cleanup: CleanupDisposition::exited(),
                },
            )?;
            return Err(error);
        }
    };
    let expected_exit = match record.outcome {
        GuestOutcome::Pass => 33,
        GuestOutcome::Fail => 35,
        GuestOutcome::Panic => 37,
    };
    if status.code() != Some(expected_exit) {
        write_integration_host_failure(
            profile,
            request,
            artifacts,
            &run,
            HostFailure {
                status: Some(&status),
                reason: "terminal_exit_mismatch",
                timeout_seconds: None,
                cleanup: CleanupDisposition::exited(),
            },
        )?;
        return Err(Failure::task(format!(
            "WYR0-H serial outcome and QEMU debug-exit status disagree (expected {expected_exit}, observed {})",
            status
                .code()
                .map_or_else(|| "signal".to_owned(), |code| code.to_string())
        )));
    }
    let expectation_matched = record.outcome.matches(request.expected_outcome)
        && record.detail == request.expected_detail;
    let status_name = if expectation_matched { "PASS" } else { "FAIL" };
    if status_name == "PASS" {
        revalidate_before_pass(request, artifacts, &pre_execution_manifest)?;
    }
    let manifest = result_manifest_json(request, artifacts)?;
    let result = format!(
        concat!(
            "{{\"schema_version\":2,\"phase\":\"WYR0-H\",",
            "\"mode\":\"integration\",\"profile\":\"{}\",",
            "\"status\":\"{}\",\"vcpu\":{},\"memory_mib\":{},",
            "\"test_id\":{},\"expected_outcome\":\"{}\",\"expected_detail\":{},",
            "\"actual_outcome\":\"{}\",\"detail\":{},\"serial_line\":{},",
            "\"qemu_exit_status\":{},{}",
            "\"deepwyrm_revision\":\"{}\",\"wyrmroot_revision\":\"{}\",",
            "\"rust_revision\":\"{}\",\"no_host_share\":true}}\n"
        ),
        profile.name(),
        status_name,
        profile.vcpus(),
        profile.memory_mib(),
        record.test_id,
        request.expected_outcome.name(),
        request.expected_detail,
        record.outcome.name(),
        record.detail,
        record.line,
        expected_exit,
        manifest,
        request.deepwyrm_revision,
        request.wyrmroot_revision,
        request.rust_revision,
    );
    write_new(
        request,
        &run.result_json,
        result.as_bytes(),
        "integration result",
    )?;
    if status_name != "PASS" {
        return Err(Failure::task(format!(
            "WYR0-H {} profile expected {} {:08X}, observed {} {:08X}",
            profile.name(),
            request.expected_outcome.name(),
            request.expected_detail,
            record.outcome.name(),
            record.detail
        )));
    }
    Ok(result)
}

struct HostFailure<'a> {
    status: Option<&'a ExitStatus>,
    reason: &'a str,
    timeout_seconds: Option<u64>,
    cleanup: CleanupDisposition,
}

fn write_integration_host_failure(
    profile: HProfile,
    request: &HRequest,
    artifacts: &CandidateArtifacts,
    run: &RunPaths,
    failure: HostFailure<'_>,
) -> Result<(), Failure> {
    let exit_status = failure
        .status
        .and_then(ExitStatus::code)
        .map_or_else(|| "null".to_owned(), |code| code.to_string());
    let manifest = result_manifest_json(request, artifacts)?;
    let timeout = failure.timeout_seconds.map_or_else(
        || "\"qemu_timeout\":false,".to_owned(),
        |seconds| format!("\"qemu_timeout\":true,\"timeout_seconds\":{seconds},",),
    );
    let result = format!(
        concat!(
            "{{\"schema_version\":2,\"phase\":\"WYR0-H\",",
            "\"mode\":\"integration\",\"profile\":\"{}\",",
            "\"status\":\"ERROR\",\"reason\":\"{}\",",
            "\"vcpu\":{},\"memory_mib\":{},",
            "\"expected_test_id\":{},\"qemu_exit_status\":{},",
            "\"expected_outcome\":\"{}\",\"expected_detail\":{},{}",
            "\"cleanup_disposition\":\"{}\",\"cleanup_killed\":{},\"cleanup_reaped\":{},",
            "\"killed\":{},\"reaped\":{},",
            "{}\"deepwyrm_revision\":\"{}\",\"wyrmroot_revision\":\"{}\",",
            "\"rust_revision\":\"{}\",\"no_host_share\":true}}\n"
        ),
        profile.name(),
        failure.reason,
        profile.vcpus(),
        profile.memory_mib(),
        request.test_id,
        exit_status,
        request.expected_outcome.name(),
        request.expected_detail,
        timeout,
        failure.cleanup.name,
        failure.cleanup.killed,
        failure.cleanup.reaped,
        failure.cleanup.killed,
        failure.cleanup.reaped,
        manifest,
        request.deepwyrm_revision,
        request.wyrmroot_revision,
        request.rust_revision,
    );
    write_new(
        request,
        &run.result_json,
        result.as_bytes(),
        "integration host-failure result",
    )
}

struct RunPaths {
    vars: PathBuf,
    serial_log: PathBuf,
    result_json: PathBuf,
    stderr_log: PathBuf,
}

fn prepare_run_directory(
    profile: HProfile,
    request: &HRequest,
    artifacts: &CandidateArtifacts,
) -> Result<RunPaths, Failure> {
    h_request::validate_outputs(request)?;
    if !request.run_directory.exists() {
        let parent = request
            .run_directory
            .parent()
            .ok_or_else(|| Failure::task("run directory has no parent"))?;
        fs::canonicalize(parent)
            .map_err(|error| Failure::task(format!("could not resolve run parent: {error}")))?;
        fs::create_dir(&request.run_directory)
            .map_err(|error| Failure::task(format!("could not create run directory: {error}")))?;
        h_request::validate_outputs(request)?;
    }
    let directory = request.run_directory.join(profile.name());
    fs::create_dir(&directory).map_err(|error| {
        Failure::task(format!(
            "could not create fresh {} run directory: {error}",
            profile.name()
        ))
    })?;
    let vars = directory.join("OVMF_VARS.fd");
    let serial_log = directory.join("serial.log");
    let result_json = directory.join("result.json");
    let stderr_log = directory.join("qemu.stderr.log");
    let vars_bytes = read_regular(
        &artifacts.ovmf_vars_template,
        "OVMF vars template",
        MAX_FIRMWARE_BYTES,
    )?;
    write_new(request, &vars, &vars_bytes, "request-local OVMF vars")?;
    Ok(RunPaths {
        vars,
        serial_log,
        result_json,
        stderr_log,
    })
}

fn qemu_arguments(
    profile: HProfile,
    request: &HRequest,
    artifacts: &CandidateArtifacts,
    kind: ExecutionKind,
    run: &RunPaths,
) -> Vec<String> {
    let mut args = vec![
        "-machine".into(),
        "q35".into(),
        "-m".into(),
        format!("{}M", profile.memory_mib()),
        "-smp".into(),
        profile.vcpus().to_string(),
        "-nodefaults".into(),
        "-display".into(),
        "none".into(),
        "-monitor".into(),
        "none".into(),
        "-no-reboot".into(),
        "-drive".into(),
        format!(
            "if=pflash,format=raw,readonly=on,file={}",
            artifacts.ovmf_code.display()
        ),
        "-drive".into(),
        format!("if=pflash,format=raw,file={}", run.vars.display()),
        "-drive".into(),
        format!(
            "if=virtio,format=raw,readonly=on,file={}",
            request.esp.display()
        ),
        "-serial".into(),
        format!("file:{}", run.serial_log.display()),
    ];
    if kind == ExecutionKind::Integration {
        args.extend([
            "-fw_cfg".into(),
            format!(
                "name=opt/org.deepwyrm.test.selector,string={}",
                request.selector
            ),
            "-device".into(),
            "isa-debug-exit,iobase=0xf4,iosize=0x04".into(),
        ]);
    }
    if kind == ExecutionKind::Gdb {
        args.extend(["-S".into(), "-gdb".into(), "tcp:127.0.0.1:1234".into()]);
    }
    args
}

fn gdb_arguments(artifacts: &CandidateArtifacts) -> Vec<String> {
    vec![
        "-ex".into(),
        "set architecture i386:x86-64".into(),
        "-ex".into(),
        format!("file {}", artifacts.symbols.display()),
        "-ex".into(),
        "target remote 127.0.0.1:1234".into(),
    ]
}

fn parse_terminal_record(bytes: &[u8], expected_test_id: u32) -> Result<GuestRecord, Failure> {
    let mut terminal = None;
    for (index, line) in bytes.split_inclusive(|byte| *byte == b'\n').enumerate() {
        if !line.starts_with(b"DWTEST1|") {
            continue;
        }
        if line.len() != COMPLETION_RECORD_BYTES
            || line[7] != b'|'
            || line[10] != b'|'
            || line[19] != b'|'
            || line[28] != b'|'
            || line[37] != b'\n'
        {
            return Err(Failure::task(format!(
                "serial line {} contains a malformed DWTEST1 record",
                index + 1
            )));
        }
        let outcome = match &line[8..10] {
            b"01" => GuestOutcome::Pass,
            b"02" => GuestOutcome::Fail,
            b"03" => GuestOutcome::Panic,
            _ => {
                return Err(Failure::task(format!(
                    "serial line {} has an invalid DWTEST1 outcome",
                    index + 1
                )));
            }
        };
        let test_id = parse_hex(&line[11..19]).ok_or_else(|| {
            Failure::task(format!(
                "serial line {} has an invalid DWTEST1 test id",
                index + 1
            ))
        })?;
        let detail = parse_hex(&line[20..28]).ok_or_else(|| {
            Failure::task(format!(
                "serial line {} has an invalid DWTEST1 detail",
                index + 1
            ))
        })?;
        let checksum = parse_hex(&line[29..37]).ok_or_else(|| {
            Failure::task(format!(
                "serial line {} has an invalid DWTEST1 checksum",
                index + 1
            ))
        })?;
        if checksum != fnv1a32(&line[..29]) {
            return Err(Failure::task(format!(
                "serial line {} has a mismatched DWTEST1 checksum",
                index + 1
            )));
        }
        if test_id != expected_test_id {
            return Err(Failure::task(format!(
                "serial line {} test id {test_id:08X} does not match request {expected_test_id:08X}",
                index + 1
            )));
        }
        if terminal.is_some() {
            return Err(Failure::task(
                "serial log contains duplicate DWTEST1 terminal records",
            ));
        }
        terminal = Some(GuestRecord {
            outcome,
            test_id,
            detail,
            line: index + 1,
        });
    }
    terminal.ok_or_else(|| Failure::task("serial log contains no DWTEST1 terminal record"))
}

fn parse_hex(bytes: &[u8]) -> Option<u32> {
    if bytes.len() != 8
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(byte))
    {
        return None;
    }
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|value| u32::from_str_radix(value, 16).ok())
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c_9dc5, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

const CLEANUP_REAP_ATTEMPTS: u32 = 40;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CleanupDisposition {
    name: &'static str,
    killed: bool,
    reaped: bool,
}

impl CleanupDisposition {
    const fn not_started() -> Self {
        Self {
            name: "not_started",
            killed: false,
            reaped: false,
        }
    }

    const fn exited() -> Self {
        Self {
            name: "exited",
            killed: false,
            reaped: true,
        }
    }
}

enum WaitOutcome {
    Exited(ExitStatus),
    TimedOut(CleanupDisposition),
}

struct WaitFailure {
    failure: Failure,
    cleanup: CleanupDisposition,
}

fn wait_bounded(child: &mut Child, timeout_seconds: u64) -> Result<WaitOutcome, WaitFailure> {
    let deadline = Instant::now() + Duration::from_secs(timeout_seconds);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(WaitOutcome::Exited(status)),
            Ok(None) => {}
            Err(error) => {
                return Err(WaitFailure {
                    failure: Failure::task(format!("could not poll WYR0-H QEMU: {error}")),
                    cleanup: stop_child(child),
                });
            }
        }
        if Instant::now() >= deadline {
            return Ok(WaitOutcome::TimedOut(stop_child(child)));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn stop_child(child: &mut Child) -> CleanupDisposition {
    match child.try_wait() {
        Ok(Some(_)) => CleanupDisposition::exited(),
        Ok(None) => {
            let killed = child.kill().is_ok();
            reap_child_bounded(child, killed)
        }
        Err(_) => {
            let killed = child.kill().is_ok();
            let mut cleanup = reap_child_bounded(child, killed);
            if cleanup.name == "kill_failed_reap_unconfirmed" {
                cleanup.name = "initial_poll_failed_kill_failed_reap_unconfirmed";
            } else if cleanup.name == "kill_sent_reap_unconfirmed" {
                cleanup.name = "initial_poll_failed_kill_sent_reap_unconfirmed";
            }
            cleanup
        }
    }
}

fn reap_child_bounded(child: &mut Child, killed: bool) -> CleanupDisposition {
    for _ in 0..CLEANUP_REAP_ATTEMPTS {
        match child.try_wait() {
            Ok(Some(_)) => {
                return cleanup_after_kill(killed, true);
            }
            Ok(None) => thread::sleep(Duration::from_millis(25)),
            Err(_) => {
                return cleanup_after_kill_failure(killed, "reap_poll_failed");
            }
        }
    }
    cleanup_after_kill_failure(killed, "reap_unconfirmed")
}

fn cleanup_after_kill(killed: bool, reaped: bool) -> CleanupDisposition {
    CleanupDisposition {
        name: match (killed, reaped) {
            (true, true) => "killed_and_reaped",
            (false, true) => "exited_before_kill_reaped",
            (true, false) => "kill_sent_reap_unconfirmed",
            (false, false) => "kill_failed_reap_unconfirmed",
        },
        killed,
        reaped,
    }
}

fn cleanup_after_kill_failure(killed: bool, suffix: &str) -> CleanupDisposition {
    let name = match (killed, suffix) {
        (true, "reap_poll_failed") => "kill_sent_reap_poll_failed",
        (false, "reap_poll_failed") => "kill_failed_reap_poll_failed",
        (true, _) => "kill_sent_reap_unconfirmed",
        (false, _) => "kill_failed_reap_unconfirmed",
    };
    CleanupDisposition {
        name,
        killed,
        reaped: false,
    }
}

fn verify_source_revisions(request: &HRequest) -> Result<(), Failure> {
    let repository = crate::tasks::repository_root()?;
    let workspace = repository
        .parent()
        .ok_or_else(|| Failure::task("Wyrmroot repository has no workspace parent"))?;
    for (path, expected, label) in [
        (&repository, request.wyrmroot_revision.as_str(), "Wyrmroot"),
        (
            &workspace.join("deepwyrm"),
            request.deepwyrm_revision.as_str(),
            "Deepwyrm",
        ),
        (
            &workspace.join("rust"),
            request.rust_revision.as_str(),
            "Rust",
        ),
    ] {
        let revision = git_output(path, &["rev-parse", "HEAD"], label)?;
        if revision.trim() != expected {
            return Err(Failure::task(format!(
                "WYR0-H request {label} revision does not match the current checkout"
            )));
        }
        let dirty = git_output(
            path,
            &["status", "--porcelain", "--untracked-files=no"],
            label,
        )?;
        if !dirty.trim().is_empty() {
            return Err(Failure::task(format!(
                "WYR0-H requires a clean tracked {label} checkout for exact revision provenance"
            )));
        }
    }
    Ok(())
}

fn git_output(repository: &Path, arguments: &[&str], label: &str) -> Result<String, Failure> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| Failure::task(format!("could not inspect {label} Git state: {error}")))?;
    if !output.status.success() {
        return Err(Failure::task(format!(
            "could not inspect {label} Git state ({})",
            status_label(&output.status)
        )));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| Failure::task(format!("{label} Git output was not UTF-8")))
}

fn outputs_all_absent(request: &HRequest) -> Result<bool, Failure> {
    let states = [
        fs::symlink_metadata(&request.bootfs).is_ok(),
        fs::symlink_metadata(&request.esp).is_ok(),
        fs::symlink_metadata(&request.provenance).is_ok(),
    ];
    if states.iter().all(|state| !state) {
        Ok(true)
    } else if states.iter().all(|state| *state) {
        Ok(false)
    } else {
        Err(Failure::task(
            "WYR0-H candidate outputs are partial; use a fresh request output set",
        ))
    }
}

fn read_regular(path: &Path, label: &str, max_bytes: u64) -> Result<Vec<u8>, Failure> {
    let path = h_request::canonical_regular(path, label, max_bytes)?;
    fs::read(path).map_err(|error| Failure::task(format!("could not read {label}: {error}")))
}

fn write_new(request: &HRequest, path: &Path, bytes: &[u8], label: &str) -> Result<(), Failure> {
    h_request::validate_output_parent(request, path, label)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::canonicalize(parent)
        .map_err(|error| Failure::task(format!("could not resolve {label} parent: {error}")))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| Failure::task(format!("could not create {label}: {error}")))?;
    if let Err(error) = output.write_all(bytes).and_then(|()| output.sync_all()) {
        drop(output);
        remove_created(path);
        return Err(Failure::task(format!("could not write {label}: {error}")));
    }
    Ok(())
}

fn open_new(request: &HRequest, path: &Path, label: &str) -> Result<fs::File, Failure> {
    h_request::validate_output_parent(request, path, label)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::canonicalize(parent)
        .map_err(|error| Failure::task(format!("could not resolve {label} parent: {error}")))?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| Failure::task(format!("could not create {label}: {error}")))
}

fn require_absent(request: &HRequest, path: &Path, label: &str) -> Result<(), Failure> {
    h_request::validate_output_parent(request, path, label)?;
    if fs::symlink_metadata(path).is_ok() {
        Err(Failure::task(format!("WYR0-H {label} already exists")))
    } else {
        Ok(())
    }
}

fn digest(path: &Path, label: &str) -> Result<String, Failure> {
    sha256::file_digest(path)
        .map_err(|error| Failure::task(format!("could not hash {label}: {error}")))
}

fn remove_created(path: &Path) {
    if fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
    {
        let _ = fs::remove_file(path);
    }
}

fn status_label(status: &ExitStatus) -> String {
    status.code().map_or_else(
        || "signal termination".to_owned(),
        |code| format!("status {code}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terminal(status: &str, test_id: u32, detail: u32) -> Vec<u8> {
        let mut record = format!("DWTEST1|{status}|{test_id:08X}|{detail:08X}|").into_bytes();
        record.extend_from_slice(format!("{:08X}\n", fnv1a32(&record)).as_bytes());
        record
    }

    #[test]
    fn locked_profiles_share_media_contract_but_not_cpu_count() {
        assert_eq!(HProfile::Default.vcpus(), 1);
        assert_eq!(HProfile::Smp.vcpus(), 4);
        assert_eq!(HProfile::Default.memory_mib(), 1024);
        assert_eq!(HProfile::Smp.memory_mib(), 2048);
    }

    #[test]
    fn terminal_parser_is_checksum_and_identity_strict() {
        let mut log = b"loader diagnostic\n".to_vec();
        log.extend_from_slice(&terminal("01", 18, 0));
        assert_eq!(
            parse_terminal_record(&log, 18).unwrap(),
            GuestRecord {
                outcome: GuestOutcome::Pass,
                test_id: 18,
                detail: 0,
                line: 2,
            }
        );
        assert!(parse_terminal_record(&log, 19).is_err());
        let mut corrupt = log.clone();
        *corrupt.last_mut().unwrap() = b'0';
        assert!(parse_terminal_record(&corrupt, 18).is_err());
        log.extend_from_slice(&terminal("01", 18, 0));
        assert!(parse_terminal_record(&log, 18).is_err());
    }

    #[test]
    fn expected_guest_outcome_requires_the_exact_kind_and_detail() {
        assert!(GuestOutcome::Fail.matches(ExpectedOutcome::Fail));
        assert!(!GuestOutcome::Fail.matches(ExpectedOutcome::Pass));
        assert!(!GuestOutcome::Panic.matches(ExpectedOutcome::Fail));
        let record = GuestRecord {
            outcome: GuestOutcome::Fail,
            test_id: 18,
            detail: 0xB000_0200,
            line: 1,
        };
        assert!(record.outcome.matches(ExpectedOutcome::Fail));
        assert_ne!(record.detail, 0);
    }

    #[test]
    fn cleanup_disposition_never_claims_an_unconfirmed_kill_or_reap() {
        assert_eq!(
            cleanup_after_kill(false, true),
            CleanupDisposition {
                name: "exited_before_kill_reaped",
                killed: false,
                reaped: true,
            }
        );
        assert_eq!(
            cleanup_after_kill_failure(false, "reap_unconfirmed"),
            CleanupDisposition {
                name: "kill_failed_reap_unconfirmed",
                killed: false,
                reaped: false,
            }
        );
        assert_eq!(
            cleanup_after_kill(true, false),
            CleanupDisposition {
                name: "kill_sent_reap_unconfirmed",
                killed: true,
                reaped: false,
            }
        );
    }

    #[test]
    fn qemu_and_gdb_plans_are_centralized_and_share_exact_symbols() {
        let root = PathBuf::from("/candidate");
        let request = HRequest {
            path: root.join("request.toml"),
            deepwyrm_revision: "1".repeat(40),
            wyrmroot_revision: "2".repeat(40),
            rust_revision: "3".repeat(40),
            selector: "primordial-bootstrap".into(),
            test_id: 18,
            expected_outcome: ExpectedOutcome::Pass,
            expected_detail: 0,
            timeout_seconds: 180,
            loader: root.join("loader.efi"),
            kernel: root.join("deepwyrm.elf"),
            symbols: root.join("deepwyrm.symbols"),
            bootstrap: root.join("bootstrap.elf"),
            init0: root.join("init0.elf"),
            hello: root.join("hello.elf"),
            bootfs: root.join("bootfs.img"),
            esp: root.join("esp.img"),
            provenance: root.join("provenance.toml"),
            ovmf_code: root.join("OVMF_CODE.fd"),
            ovmf_vars_template: root.join("OVMF_VARS.fd"),
            run_directory: root.join("runs"),
        };
        let artifacts = CandidateArtifacts {
            loader: request.loader.clone(),
            kernel: request.kernel.clone(),
            symbols: request.symbols.clone(),
            bootstrap: request.bootstrap.clone(),
            init0: request.init0.clone(),
            hello: request.hello.clone(),
            ovmf_code: request.ovmf_code.clone(),
            ovmf_vars_template: request.ovmf_vars_template.clone(),
        };
        let run = RunPaths {
            vars: request.run_directory.join("smp/OVMF_VARS.fd"),
            serial_log: request.run_directory.join("smp/serial.log"),
            result_json: request.run_directory.join("smp/result.json"),
            stderr_log: request.run_directory.join("smp/qemu.stderr.log"),
        };
        let args = qemu_arguments(
            HProfile::Smp,
            &request,
            &artifacts,
            ExecutionKind::Integration,
            &run,
        );
        let joined = args.join(" ");
        assert!(joined.contains("-machine q35"));
        assert!(joined.contains("-m 2048M"));
        assert!(joined.contains("-smp 4"));
        assert!(joined.contains("readonly=on,file=/candidate/esp.img"));
        assert!(joined.contains("isa-debug-exit"));
        for forbidden in ["virtfs", "virtiofs", "9p", "-net", "user,id="] {
            assert!(!joined.contains(forbidden));
        }
        assert!(
            gdb_arguments(&artifacts)
                .join(" ")
                .contains("file /candidate/deepwyrm.symbols")
        );
    }

    #[test]
    fn paired_join_requires_both_profiles_and_preserves_both_failures() {
        let inspection = "{\"status\":\"PASS\"}\n";
        let default = "{\"profile\":\"default\",\"status\":\"PASS\"}\n";
        let smp = "{\"profile\":\"smp\",\"status\":\"PASS\"}\n";
        let joined = join_profile_results(inspection, Ok(default.into()), Ok(smp.into()))
            .expect("paired successful profiles rejected");
        assert!(joined.contains("\"same_media\":true"));
        assert!(joined.contains("\"default\":{\"profile\":\"default\""));
        assert!(joined.contains("\"smp\":{\"profile\":\"smp\""));

        let failure = join_profile_results(
            inspection,
            Err(Failure::task("default failed")),
            Err(Failure::task("smp failed")),
        )
        .expect_err("paired failures were accepted");
        assert!(failure.message.contains("default: default failed"));
        assert!(failure.message.contains("smp: smp failed"));
    }

    #[test]
    fn host_failure_result_is_structured_without_a_guest_record() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!(
                "xtask-h-host-failure-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system clock before epoch")
                    .as_nanos()
            ));
        fs::create_dir(&root).expect("create test root");
        for name in [
            "loader.efi",
            "deepwyrm.elf",
            "deepwyrm.symbols",
            "bootstrap.elf",
            "init0.elf",
            "hello.elf",
            "bootfs.img",
            "esp.img",
            "provenance.toml",
            "OVMF_CODE.fd",
            "OVMF_VARS.fd",
        ] {
            fs::write(root.join(name), b"artifact").expect("write test artifact");
        }
        let esp = root.join("esp.img");
        let request = HRequest {
            path: root.join("request.toml"),
            deepwyrm_revision: "1".repeat(40),
            wyrmroot_revision: "2".repeat(40),
            rust_revision: "3".repeat(40),
            selector: "primordial-bootstrap".into(),
            test_id: 18,
            expected_outcome: ExpectedOutcome::Pass,
            expected_detail: 0,
            timeout_seconds: 180,
            loader: root.join("loader.efi"),
            kernel: root.join("deepwyrm.elf"),
            symbols: root.join("deepwyrm.symbols"),
            bootstrap: root.join("bootstrap.elf"),
            init0: root.join("init0.elf"),
            hello: root.join("hello.elf"),
            bootfs: root.join("bootfs.img"),
            esp,
            provenance: root.join("provenance.toml"),
            ovmf_code: root.join("OVMF_CODE.fd"),
            ovmf_vars_template: root.join("OVMF_VARS.fd"),
            run_directory: root.join("runs"),
        };
        let run = RunPaths {
            vars: root.join("OVMF_VARS.fd"),
            serial_log: root.join("serial.log"),
            result_json: root.join("result.json"),
            stderr_log: root.join("stderr.log"),
        };
        fs::write(&request.path, b"request").expect("write request");
        let artifacts = CandidateArtifacts {
            loader: request.loader.clone(),
            kernel: request.kernel.clone(),
            symbols: request.symbols.clone(),
            bootstrap: request.bootstrap.clone(),
            init0: request.init0.clone(),
            hello: request.hello.clone(),
            ovmf_code: request.ovmf_code.clone(),
            ovmf_vars_template: request.ovmf_vars_template.clone(),
        };
        write_integration_host_failure(
            HProfile::Smp,
            &request,
            &artifacts,
            &run,
            HostFailure {
                status: None,
                reason: "terminal_record_invalid",
                timeout_seconds: Some(7),
                cleanup: CleanupDisposition {
                    name: "killed_and_reaped",
                    killed: true,
                    reaped: true,
                },
            },
        )
        .expect("write host failure result");
        let result = fs::read_to_string(&run.result_json).expect("read host failure result");
        assert!(result.contains("\"profile\":\"smp\""));
        assert!(result.contains("\"status\":\"ERROR\""));
        assert!(result.contains("\"reason\":\"terminal_record_invalid\""));
        assert!(result.contains("\"qemu_exit_status\":null"));
        assert!(result.contains("\"candidate_sha256\":"));
        assert!(result.contains("\"ovmf_code_sha256\":"));
        assert!(result.contains("\"qemu_timeout\":true"));
        assert!(result.contains("\"timeout_seconds\":7"));
        assert!(result.contains("\"cleanup_killed\":true"));
        assert!(result.contains("\"cleanup_reaped\":true"));
        assert!(result.contains("\"killed\":true"));
        assert!(result.contains("\"reaped\":true"));

        for (name, reason) in [
            ("spawn-result.json", "qemu_spawn_failed"),
            ("serial-result.json", "serial_log_unreadable"),
        ] {
            let error_run = RunPaths {
                vars: root.join("unused-vars.fd"),
                serial_log: root.join("unused-serial.log"),
                result_json: root.join(name),
                stderr_log: root.join("unused-stderr.log"),
            };
            write_integration_host_failure(
                HProfile::Smp,
                &request,
                &artifacts,
                &error_run,
                HostFailure {
                    status: None,
                    reason,
                    timeout_seconds: None,
                    cleanup: CleanupDisposition::not_started(),
                },
            )
            .expect("write distinct host failure result");
            let result = fs::read_to_string(&error_run.result_json).expect("read host failure");
            assert!(result.contains(&format!("\"reason\":\"{reason}\"")));
            assert!(result.contains("\"status\":\"ERROR\""));
        }
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn candidate_symbols_must_match_the_booted_kernel() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!(
                "xtask-h-symbol-mismatch-test-{}",
                std::process::id()
            ));
        fs::create_dir(&root).expect("create test root");
        for name in [
            "loader.efi",
            "deepwyrm.elf",
            "bootstrap.elf",
            "init0.elf",
            "hello.elf",
            "OVMF_CODE.fd",
            "OVMF_VARS.fd",
        ] {
            fs::write(root.join(name), b"artifact").expect("write test artifact");
        }
        fs::write(root.join("deepwyrm.symbols"), b"different").expect("write symbols");
        let request = HRequest {
            path: root.join("request.toml"),
            deepwyrm_revision: "1".repeat(40),
            wyrmroot_revision: "2".repeat(40),
            rust_revision: "3".repeat(40),
            selector: "primordial-bootstrap".into(),
            test_id: 18,
            expected_outcome: ExpectedOutcome::Pass,
            expected_detail: 0,
            timeout_seconds: 180,
            loader: root.join("loader.efi"),
            kernel: root.join("deepwyrm.elf"),
            symbols: root.join("deepwyrm.symbols"),
            bootstrap: root.join("bootstrap.elf"),
            init0: root.join("init0.elf"),
            hello: root.join("hello.elf"),
            bootfs: root.join("bootfs.img"),
            esp: root.join("esp.img"),
            provenance: root.join("provenance.toml"),
            ovmf_code: root.join("OVMF_CODE.fd"),
            ovmf_vars_template: root.join("OVMF_VARS.fd"),
            run_directory: root.join("runs"),
        };
        let error = verify_candidate_inputs(&request).expect_err("mismatched symbols accepted");
        assert!(error.message.contains("do not exactly match"));
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn candidate_digest_is_stable_then_changes_with_a_consumed_artifact() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!(
                "xtask-h-digest-stability-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system clock before epoch")
                    .as_nanos()
            ));
        fs::create_dir(&root).expect("create test root");
        for name in [
            "request.toml",
            "loader.efi",
            "deepwyrm.elf",
            "deepwyrm.symbols",
            "bootstrap.elf",
            "init0.elf",
            "hello.elf",
            "bootfs.img",
            "esp.img",
            "OVMF_CODE.fd",
            "OVMF_VARS.fd",
        ] {
            fs::write(root.join(name), b"artifact").expect("write test artifact");
        }
        let request = HRequest {
            path: root.join("request.toml"),
            deepwyrm_revision: "1".repeat(40),
            wyrmroot_revision: "2".repeat(40),
            rust_revision: "3".repeat(40),
            selector: "primordial-bootstrap".into(),
            test_id: 18,
            expected_outcome: ExpectedOutcome::Pass,
            expected_detail: 0,
            timeout_seconds: 180,
            loader: root.join("loader.efi"),
            kernel: root.join("deepwyrm.elf"),
            symbols: root.join("deepwyrm.symbols"),
            bootstrap: root.join("bootstrap.elf"),
            init0: root.join("init0.elf"),
            hello: root.join("hello.elf"),
            bootfs: root.join("bootfs.img"),
            esp: root.join("esp.img"),
            provenance: root.join("provenance.toml"),
            ovmf_code: root.join("OVMF_CODE.fd"),
            ovmf_vars_template: root.join("OVMF_VARS.fd"),
            run_directory: root.join("runs"),
        };
        let artifacts = CandidateArtifacts {
            loader: request.loader.clone(),
            kernel: request.kernel.clone(),
            symbols: request.symbols.clone(),
            bootstrap: request.bootstrap.clone(),
            init0: request.init0.clone(),
            hello: request.hello.clone(),
            ovmf_code: request.ovmf_code.clone(),
            ovmf_vars_template: request.ovmf_vars_template.clone(),
        };
        let first = candidate_digests(&request, &artifacts).expect("first digest");
        let second = candidate_digests(&request, &artifacts).expect("second digest");
        assert_eq!(first.candidate, second.candidate);
        fs::write(&request.hello, b"changed").expect("mutate hello");
        let changed = candidate_digests(&request, &artifacts).expect("changed digest");
        assert_ne!(first.candidate, changed.candidate);
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn pass_revalidation_rejects_a_request_mutated_after_inspection() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!(
                "xtask-h-revalidation-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system clock before epoch")
                    .as_nanos()
            ));
        fs::create_dir(&root).expect("create test root");
        for name in [
            "loader.efi",
            "deepwyrm.elf",
            "bootstrap.elf",
            "init0.elf",
            "hello.elf",
            "OVMF_CODE.fd",
            "OVMF_VARS.fd",
        ] {
            fs::write(root.join(name), b"artifact").expect("write test artifact");
        }
        let revision = "1".repeat(40);
        let request_text = format!(
            concat!(
                "schema_version = 2\n",
                "deepwyrm_revision = \"{}\"\nwyrmroot_revision = \"{}\"\n",
                "rust_revision = \"{}\"\nselector = \"primordial-bootstrap\"\n",
                "test_id = 18\nexpected_outcome = \"pass\"\nexpected_detail = 0\n",
                "timeout_seconds = 180\nloader = \"loader.efi\"\nkernel = \"deepwyrm.elf\"\n",
                "symbols = \"deepwyrm.elf\"\nbootstrap = \"bootstrap.elf\"\n",
                "init0 = \"init0.elf\"\nhello = \"hello.elf\"\nbootfs = \"bootfs.img\"\n",
                "esp = \"esp.img\"\nprovenance = \"provenance.toml\"\n",
                "ovmf_code = \"OVMF_CODE.fd\"\novmf_vars_template = \"OVMF_VARS.fd\"\n",
                "run_directory = \"runs\"\n"
            ),
            revision, revision, revision
        );
        let path = root.join("request.toml");
        fs::write(&path, &request_text).expect("write request");
        let request = h_request::load(&path).expect("load request");
        let artifacts = verify_candidate_inputs(&request).expect("verify artifacts");
        fs::write(
            &path,
            request_text.replace("expected_detail = 0", "expected_detail = 1"),
        )
        .expect("mutate request");
        let error = revalidate_before_pass(&request, &artifacts, "unused")
            .expect_err("mutated request accepted for PASS");
        assert!(error.message.contains("request changed after inspection"));
        fs::remove_dir_all(root).expect("remove test root");
    }
}
