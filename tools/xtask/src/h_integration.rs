//! WYR0-H exact-artifact image, q35/OVMF, GDB, and integration tooling.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use wyrmroot_bootfs::builder::{Builder, FileMode};

use crate::cli::{G3ImageArguments, HProfile};
use crate::error::Failure;
use crate::h_request::{
    self, EvidenceRequest, ExpectedOutcome, HRequest, I1_EVIDENCE_PROTOCOL, I2_SCHEDULE_VERSION,
    StressRequest,
};
use crate::secure_fs;
use crate::sha256;

const MAX_GUEST_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FIRMWARE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SERIAL_BYTES: u64 = 16 * 1024 * 1024;
const COMPLETION_RECORD_BYTES: usize = 38;
const EVIDENCE_RECORD_BYTES: usize = 85;
const STRESS_RECORD_BYTES: usize = 140;
const MAX_EVIDENCE_RECORDS: usize = 64;
const I2_CPU_MASK: u32 = 0x0000_000F;
const I2_FAMILY_MASK: u32 = 0x0000_01FF;
const SPLITMIX64_GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;
const PROOF_CPU_ONLINE: u32 = 1 << 0;
const PROOF_CPL3_SYSCALL: u32 = 1 << 1;
const PROOF_BLOCKED_DESCENDANT: u32 = 1 << 2;
const PROOF_RUNNING_INVARIANT: u32 = 1 << 3;
const PROOF_REMOTE_WAKE: u32 = 1 << 4;
const PROOF_CHILD_CLEANUP: u32 = 1 << 5;
const PROOF_TLB_ACK: u32 = 1 << 6;
const PROOF_RENDEZVOUS_RECLAIM: u32 = 1 << 7;
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum EvidenceKind {
    CpuOnline,
    Cpl3Syscall,
    ParentBlocked,
    DescendantRunning,
    RunningInvariant,
    WakeSent,
    WakeObserved,
    ChildExit,
    ChildCleanup,
    TlbPublish,
    TlbAck,
    RendezvousAck,
    ReclaimAllowed,
}

impl EvidenceKind {
    fn parse(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::CpuOnline),
            0x02 => Some(Self::Cpl3Syscall),
            0x03 => Some(Self::ParentBlocked),
            0x04 => Some(Self::DescendantRunning),
            0x05 => Some(Self::RunningInvariant),
            0x06 => Some(Self::WakeSent),
            0x07 => Some(Self::WakeObserved),
            0x08 => Some(Self::ChildExit),
            0x09 => Some(Self::ChildCleanup),
            0x0A => Some(Self::TlbPublish),
            0x0B => Some(Self::TlbAck),
            0x0C => Some(Self::RendezvousAck),
            0x0D => Some(Self::ReclaimAllowed),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EvidenceEvent {
    sequence: u32,
    kind: EvidenceKind,
    cpu: u32,
    token: u32,
    arg0: u32,
    arg1: u32,
    line: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ValidatedEvidence {
    count: u32,
    observed_mask: u32,
    first_sequence: u32,
    last_sequence: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GuestTranscript {
    terminal: GuestRecord,
    evidence: Option<ValidatedEvidence>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StressRun {
    index: u32,
    base_seed: u64,
    seed: u64,
    operations: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StressRecord {
    outcome: GuestOutcome,
    test_id: u32,
    run_index: u32,
    base_seed: u64,
    seed: u64,
    configured_operations: u32,
    completed_operations: u32,
    cpu_mask: u32,
    family_mask: u32,
    detail: u32,
    failing_operation: u32,
    stage: u32,
    line: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StressTranscript {
    stress: StressRecord,
    terminal: GuestRecord,
}

struct StressSummaryDisposition<'a> {
    status: &'a str,
    failing_index: Option<u32>,
    reason: Option<&'a str>,
    candidate_revalidated: bool,
}

#[derive(Debug, Eq, PartialEq)]
struct AdmittedArtifact {
    source: PathBuf,
    bytes: Vec<u8>,
}

impl AdmittedArtifact {
    fn digest(&self) -> String {
        sha256::bytes_digest(&self.bytes)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct CandidateArtifacts {
    loader: AdmittedArtifact,
    kernel: AdmittedArtifact,
    symbols: AdmittedArtifact,
    bootstrap: AdmittedArtifact,
    init0: AdmittedArtifact,
    hello: AdmittedArtifact,
    ovmf_code: AdmittedArtifact,
    ovmf_vars_template: AdmittedArtifact,
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
        remove_created(&request, &request.provenance);
        remove_created(&request, &request.esp);
        remove_created(&request, &request.bootfs);
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
    validate_execution_profile(&request, Some(profile))?;
    if request.stress.is_some() {
        return Err(Failure::task(
            "WYR0-H schema_version = 4 is accepted only by test integration wyr0 smp",
        ));
    }
    verify_source_revisions(&request)?;
    let artifacts = verify_candidate_inputs(&request)?;
    inspect_loaded(&request, &artifacts)?;
    execute(profile, &request, &artifacts, ExecutionKind::Run)
}

pub(crate) fn gdb(profile: HProfile, request_path: &str) -> Result<String, Failure> {
    let request = h_request::load(Path::new(request_path))?;
    validate_execution_profile(&request, Some(profile))?;
    if request.stress.is_some() {
        return Err(Failure::task(
            "WYR0-H schema_version = 4 is accepted only by test integration wyr0 smp",
        ));
    }
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
    validate_execution_profile(&request, profile)?;
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
            remove_created(&request, &request.provenance);
            remove_created(&request, &request.esp);
            remove_created(&request, &request.bootfs);
            return Err(error);
        }
    }
    let inspection = inspect_loaded(&request, &artifacts)?;
    match profile {
        Some(_) if request.stress.is_some() => execute_stress(&request, &artifacts),
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

fn validate_execution_profile(
    request: &HRequest,
    profile: Option<HProfile>,
) -> Result<(), Failure> {
    if matches!(request.schema_version, 3 | 4) && profile != Some(HProfile::Smp) {
        return Err(Failure::task(
            "WYR0-H schema_version = 3 or 4 execution requires an explicit smp profile",
        ));
    }
    Ok(())
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
        loader: admit_artifact(&request.loader, "loader.efi", MAX_GUEST_ARTIFACT_BYTES)?,
        kernel: admit_artifact(&request.kernel, "deepwyrm.elf", MAX_GUEST_ARTIFACT_BYTES)?,
        symbols: admit_artifact(
            &request.symbols,
            "Deepwyrm symbols",
            MAX_GUEST_ARTIFACT_BYTES,
        )?,
        bootstrap: admit_artifact(
            &request.bootstrap,
            "bootstrap.elf",
            MAX_GUEST_ARTIFACT_BYTES,
        )?,
        init0: admit_artifact(&request.init0, "system/init0", MAX_GUEST_ARTIFACT_BYTES)?,
        hello: admit_artifact(&request.hello, "bin/hello", MAX_GUEST_ARTIFACT_BYTES)?,
        ovmf_code: admit_artifact(&request.ovmf_code, "OVMF code", MAX_FIRMWARE_BYTES)?,
        ovmf_vars_template: admit_artifact(
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
        let display = path.source.to_string_lossy();
        if display.contains([',', '\n', '\r']) {
            return Err(Failure::task(format!(
                "WYR0-H {label} path contains a delimiter unsupported by QEMU media arguments"
            )));
        }
    }
    if artifacts.kernel.bytes != artifacts.symbols.bytes {
        return Err(Failure::task(
            "WYR0-H GDB symbols do not exactly match the booted kernel SHA-256",
        ));
    }
    Ok(artifacts)
}

fn admit_artifact(path: &Path, label: &str, max_bytes: u64) -> Result<AdmittedArtifact, Failure> {
    Ok(AdmittedArtifact {
        source: path.to_path_buf(),
        bytes: secure_fs::read_path(path, label, max_bytes, false)?,
    })
}

fn build_bootfs_bytes(artifacts: &CandidateArtifacts) -> Result<Vec<u8>, Failure> {
    let mut builder = Builder::new();
    builder
        .add(
            b"system/init0",
            &artifacts.init0.bytes,
            FileMode::Executable,
        )
        .map_err(|error| Failure::task(format!("could not add init0 to bootfs: {error:?}")))?;
    builder
        .add(b"bin/hello", &artifacts.hello.bytes, FileMode::Executable)
        .map_err(|error| Failure::task(format!("could not add hello to bootfs: {error:?}")))?;
    builder
        .build()
        .map_err(|error| Failure::task(format!("could not build WYR0-H bootfs: {error:?}")))
}

fn image_arguments(request: &HRequest, artifacts: &CandidateArtifacts) -> G3ImageArguments {
    G3ImageArguments {
        image: request.esp.display().to_string(),
        loader: artifacts.loader.source.display().to_string(),
        kernel: artifacts.kernel.source.display().to_string(),
        bootstrap: artifacts.bootstrap.source.display().to_string(),
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
    let request_digest = sha256::bytes_digest(&request.request_bytes);
    let loader = artifacts.loader.digest();
    let kernel = artifacts.kernel.digest();
    let symbols = artifacts.symbols.digest();
    let bootstrap = artifacts.bootstrap.digest();
    let init0 = artifacts.init0.digest();
    let hello = artifacts.hello.digest();
    let bootfs = sha256::bytes_digest(&request.root.read(
        &request.bootfs,
        "bootfs",
        MAX_GUEST_ARTIFACT_BYTES,
        false,
    )?);
    let esp = sha256::bytes_digest(&request.root.read(
        &request.esp,
        "ESP",
        MAX_GUEST_ARTIFACT_BYTES,
        false,
    )?);
    let ovmf_code = artifacts.ovmf_code.digest();
    let ovmf_vars_template = artifacts.ovmf_vars_template.digest();
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
    let args = qemu_arguments(profile, request, artifacts, kind, &run, None);
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
            .args(gdb_arguments(&run))
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
            artifacts.symbols.digest()
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
    let transcript = match parse_transcript(&serial, request) {
        Ok(transcript) => transcript,
        Err(error) => {
            write_integration_host_failure(
                profile,
                request,
                artifacts,
                &run,
                HostFailure {
                    status: Some(&status),
                    reason: if request.evidence.is_some() {
                        "transcript_invalid"
                    } else {
                        "terminal_record_invalid"
                    },
                    timeout_seconds: None,
                    cleanup: CleanupDisposition::exited(),
                },
            )?;
            return Err(error);
        }
    };
    let record = transcript.terminal;
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
    let expectation_matched = guest_expectation_matches(request, record);
    let status_name = if expectation_matched { "PASS" } else { "FAIL" };
    if status_name == "PASS" {
        revalidate_before_pass(request, artifacts, &pre_execution_manifest)?;
    }
    let evidence_fields = if status_name == "PASS" {
        evidence_result_fields(request, transcript.evidence)?
    } else {
        String::new()
    };
    let manifest = result_manifest_json(request, artifacts)?;
    let serial_sha256 = digest(&run.serial_log, "serial log")?;
    let stderr_sha256 = digest_allow_empty(&run.stderr_log, "QEMU stderr")?;
    let vars_sha256 = digest(&run.vars, "OVMF vars")?;
    let result = format!(
        concat!(
            "{{\"schema_version\":{},\"phase\":\"WYR0-H\",",
            "\"mode\":\"integration\",\"profile\":\"{}\",\"selector\":\"{}\",",
            "\"status\":\"{}\",\"vcpu\":{},\"memory_mib\":{},",
            "\"test_id\":{},\"expected_outcome\":\"{}\",\"expected_detail\":{},",
            "\"actual_outcome\":\"{}\",\"detail\":{},\"serial_line\":{},",
            "\"qemu_exit_status\":{},{}{}",
            "\"serial_sha256\":\"{}\",\"qemu_stderr_sha256\":\"{}\",",
            "\"ovmf_vars_sha256\":\"{}\",",
            "\"deepwyrm_revision\":\"{}\",\"wyrmroot_revision\":\"{}\",",
            "\"rust_revision\":\"{}\",\"no_host_share\":true}}\n"
        ),
        request.schema_version,
        profile.name(),
        request.selector,
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
        evidence_fields,
        manifest,
        serial_sha256,
        stderr_sha256,
        vars_sha256,
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

fn execute_stress(request: &HRequest, artifacts: &CandidateArtifacts) -> Result<String, Failure> {
    let stress = request
        .stress
        .as_ref()
        .ok_or_else(|| Failure::task("I2 execution lacks a schema-v4 stress request"))?;
    let i2_directory = prepare_stress_directory(request, stress)?;
    let pre_execution_manifest = result_manifest_json(request, artifacts)?;
    let mut results = Vec::new();
    let mut failure = None;
    for index in 0..stress.run_count {
        let run = StressRun {
            index,
            base_seed: stress.base_seed,
            seed: splitmix64_seed(stress.base_seed, index),
            operations: stress.operations_per_run,
        };
        let paths = match prepare_stress_run_directory(request, artifacts, &i2_directory, run) {
            Ok(paths) => paths,
            Err(error) => {
                let result_path = i2_directory
                    .join(format!("run-{index:06}"))
                    .join("result.json");
                let evidence = write_stress_preparation_failure(
                    request,
                    run,
                    &result_path,
                    &error.message,
                    &pre_execution_manifest,
                );
                if let Ok(result) = evidence {
                    results.push((run, sha256::bytes_digest(result.as_bytes()), "ERROR"));
                }
                failure = Some((index, error, "ERROR"));
                break;
            }
        };
        let outcome = execute_stress_run(request, artifacts, run, &paths, &pre_execution_manifest);
        let result_bytes = request.root.read(
            &paths.result_json,
            "I2 run result",
            MAX_EVIDENCE_RESULT_BYTES,
            false,
        )?;
        let result_digest = sha256::bytes_digest(&result_bytes);
        let run_status = if outcome.is_ok() {
            "PASS"
        } else if result_bytes
            .windows(b"\"status\":\"FAIL\"".len())
            .any(|window| window == b"\"status\":\"FAIL\"")
        {
            "FAIL"
        } else {
            "ERROR"
        };
        results.push((run, result_digest, run_status));
        if let Err(error) = outcome {
            failure = Some((index, error, run_status));
            break;
        }
    }

    let revalidation = revalidate_before_pass(request, artifacts, &pre_execution_manifest);
    let (status, failing_index, reason) = match (&failure, &revalidation) {
        (None, Ok(())) if results.len() == stress.run_count as usize => ("PASS", None, None),
        (Some((index, error, run_status)), Ok(())) => {
            (*run_status, Some(*index), Some(error.message.as_str()))
        }
        (_, Err(error)) => (
            "ERROR",
            failure.as_ref().map(|item| item.0),
            Some(error.message.as_str()),
        ),
        _ => (
            "ERROR",
            None,
            Some("I2 runner did not complete every requested run"),
        ),
    };
    let summary = stress_summary_json(
        request,
        stress,
        StressSummaryDisposition {
            status,
            failing_index,
            reason,
            candidate_revalidated: revalidation.is_ok(),
        },
        &pre_execution_manifest,
        &results,
    )?;
    let summary_path = i2_directory.join("summary.json");
    write_new(request, &summary_path, summary.as_bytes(), "I2 summary")?;
    if status != "PASS" {
        let detail = failure
            .map(|(_, error, _)| error.message)
            .or_else(|| revalidation.err().map(|error| error.message))
            .unwrap_or_else(|| "I2 did not complete every requested run".to_owned());
        return Err(Failure::task(format!(
            "WYR0-H I2 stress failed; durable summary {}: {detail}",
            summary_path.display()
        )));
    }
    Ok(summary)
}

const MAX_EVIDENCE_RESULT_BYTES: u64 = 1024 * 1024;

fn write_stress_preparation_failure(
    request: &HRequest,
    run: StressRun,
    result_path: &Path,
    detail: &str,
    candidate_manifest: &str,
) -> Result<String, Failure> {
    if let Some(directory) = result_path.parent()
        && !directory.exists()
    {
        request
            .root
            .create_dir(directory, "I2 failed-run evidence directory")?;
    }
    let result = format!(
        concat!(
            "{{\"schema_version\":4,\"phase\":\"WYR0-H-I2\",\"status\":\"ERROR\",",
            "\"reason\":\"run_preparation_failed\",\"error_detail\":\"{}\",",
            "\"profile\":\"smp\",\"selector\":\"{}\",\"test_id\":{},\"run_index\":{},",
            "\"stress_schedule_version\":\"{}\",\"stress_base_seed\":\"{:016X}\",",
            "\"stress_seed\":\"{:016X}\",\"configured_operations\":{},",
            "\"serial_sha256\":null,\"qemu_stderr_sha256\":null,\"ovmf_vars_sha256\":null,",
            "\"cleanup_disposition\":\"not_started\",\"cleanup_killed\":false,",
            "\"cleanup_reaped\":false,{}\"deepwyrm_revision\":\"{}\",",
            "\"wyrmroot_revision\":\"{}\",\"rust_revision\":\"{}\",",
            "\"candidate_revalidated\":false,\"no_host_share\":true}}\n"
        ),
        json_escape(detail),
        request.selector,
        request.test_id,
        run.index,
        I2_SCHEDULE_VERSION,
        run.base_seed,
        run.seed,
        run.operations,
        candidate_manifest,
        request.deepwyrm_revision,
        request.wyrmroot_revision,
        request.rust_revision,
    );
    write_new(
        request,
        result_path,
        result.as_bytes(),
        "I2 preparation-failure result",
    )?;
    Ok(result)
}

fn prepare_stress_directory(
    request: &HRequest,
    stress: &StressRequest,
) -> Result<PathBuf, Failure> {
    h_request::validate_outputs(request)?;
    require_absent(request, &stress.v0_manifest, "V0 manifest output")?;
    if !request.run_directory.exists() {
        request
            .root
            .create_dir(&request.run_directory, "run directory")?;
    }
    h_request::validate_outputs(request)?;
    let directory = request.run_directory.join("i2");
    request.root.create_dir(&directory, "fresh I2 directory")?;
    Ok(directory)
}

fn prepare_stress_run_directory(
    request: &HRequest,
    artifacts: &CandidateArtifacts,
    i2_directory: &Path,
    run: StressRun,
) -> Result<RunPaths, Failure> {
    let directory = i2_directory.join(format!("run-{:06}", run.index));
    h_request::validate_output_parent(request, &directory, "I2 run directory")?;
    request.root.create_dir(
        &directory,
        &format!("fresh I2 run {:06} directory", run.index),
    )?;
    let paths = RunPaths {
        vars: directory.join("OVMF_VARS.fd"),
        serial_log: directory.join("serial.log"),
        result_json: directory.join("result.json"),
        stderr_log: directory.join("qemu.stderr.log"),
        qemu_ovmf_code: String::new(),
        qemu_vars: String::new(),
        qemu_esp: String::new(),
        qemu_serial: String::new(),
        gdb_symbols: String::new(),
        _inherited_files: Vec::new(),
    };
    write_new(
        request,
        &paths.vars,
        &artifacts.ovmf_vars_template.bytes,
        "I2 request-local OVMF vars",
    )?;
    bind_run_inputs(request, artifacts, &directory, paths)
}

fn execute_stress_run(
    request: &HRequest,
    artifacts: &CandidateArtifacts,
    stress: StressRun,
    paths: &RunPaths,
    pre_execution_manifest: &str,
) -> Result<String, Failure> {
    let args = qemu_arguments(
        HProfile::Smp,
        request,
        artifacts,
        ExecutionKind::Integration,
        paths,
        Some(stress),
    );
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
            &paths.stderr_log,
            "I2 QEMU stderr",
        )?))
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            write_stress_host_failure(
                request,
                stress,
                paths,
                "qemu_spawn_failed",
                None,
                pre_execution_manifest,
            )?;
            return Err(Failure::task(format!(
                "could not launch canonical WYR0-H I2 QEMU: {error}"
            )));
        }
    };
    let exit = match wait_bounded(&mut child, request.timeout_seconds) {
        Ok(WaitOutcome::Exited(status)) => status,
        Ok(WaitOutcome::TimedOut(cleanup)) => {
            write_stress_host_failure(
                request,
                stress,
                paths,
                "qemu_timeout",
                Some(cleanup),
                pre_execution_manifest,
            )?;
            return Err(Failure::task(format!(
                "WYR0-H I2 QEMU timed out after {} seconds",
                request.timeout_seconds
            )));
        }
        Err(error) => {
            write_stress_host_failure(
                request,
                stress,
                paths,
                "qemu_wait_failed",
                Some(error.cleanup),
                pre_execution_manifest,
            )?;
            return Err(error.failure);
        }
    };
    let serial = match read_regular(&paths.serial_log, "I2 serial log", MAX_SERIAL_BYTES) {
        Ok(serial) => serial,
        Err(error) => {
            write_stress_host_failure(
                request,
                stress,
                paths,
                "serial_log_unreadable",
                Some(CleanupDisposition::exited()),
                pre_execution_manifest,
            )?;
            return Err(error);
        }
    };
    let transcript = match parse_stress_transcript(&serial, request.test_id, stress) {
        Ok(transcript) => transcript,
        Err(error) => {
            write_stress_host_failure(
                request,
                stress,
                paths,
                "transcript_invalid",
                Some(CleanupDisposition::exited()),
                pre_execution_manifest,
            )?;
            return Err(error);
        }
    };
    let expected_exit = match transcript.terminal.outcome {
        GuestOutcome::Pass => 33,
        GuestOutcome::Fail => 35,
        GuestOutcome::Panic => 37,
    };
    if exit.code() != Some(expected_exit) {
        write_stress_host_failure(
            request,
            stress,
            paths,
            "terminal_exit_mismatch",
            Some(CleanupDisposition::exited()),
            pre_execution_manifest,
        )?;
        return Err(Failure::task(
            "I2 terminal outcome and QEMU debug-exit status disagree",
        ));
    }
    let accepted = transcript.stress.outcome == GuestOutcome::Pass
        && transcript.stress.detail == 0
        && transcript.terminal.outcome == GuestOutcome::Pass
        && transcript.terminal.detail == 0;
    if accepted
        && let Err(error) = revalidate_before_pass(request, artifacts, pre_execution_manifest)
    {
        write_stress_host_failure(
            request,
            stress,
            paths,
            "candidate_revalidation_failed",
            Some(CleanupDisposition::exited()),
            pre_execution_manifest,
        )?;
        return Err(error);
    }
    let status = if accepted { "PASS" } else { "FAIL" };
    let result = stress_result_json(
        request,
        stress,
        paths,
        transcript,
        status,
        expected_exit,
        pre_execution_manifest,
    )?;
    write_new(
        request,
        &paths.result_json,
        result.as_bytes(),
        "I2 run result",
    )?;
    if !accepted {
        return Err(Failure::task(format!(
            "I2 run {} reported {} detail {:08X} at operation {:08X} stage {:08X}",
            stress.index,
            transcript.stress.outcome.name(),
            transcript.stress.detail,
            transcript.stress.failing_operation,
            transcript.stress.stage
        )));
    }
    Ok(result)
}

fn stress_result_json(
    request: &HRequest,
    run: StressRun,
    paths: &RunPaths,
    transcript: StressTranscript,
    status: &str,
    exit_status: i32,
    candidate_manifest: &str,
) -> Result<String, Failure> {
    let serial = digest(&paths.serial_log, "I2 serial log")?;
    let stderr = digest_allow_empty(&paths.stderr_log, "I2 QEMU stderr")?;
    let vars = digest(&paths.vars, "I2 OVMF vars")?;
    Ok(format!(
        concat!(
            "{{\"schema_version\":4,\"phase\":\"WYR0-H-I2\",\"status\":\"{}\",",
            "\"profile\":\"smp\",\"selector\":\"{}\",\"test_id\":{},\"run_index\":{},",
            "\"stress_schedule_version\":\"{}\",\"stress_base_seed\":\"{:016X}\",",
            "\"stress_seed\":\"{:016X}\",\"configured_operations\":{},",
            "\"completed_operations\":{},\"cpu_mask\":{},\"family_mask\":{},",
            "\"actual_outcome\":\"{}\",\"detail\":{},\"failing_operation\":{},",
            "\"stage\":{},\"stress_serial_line\":{},\"terminal_serial_line\":{},",
            "\"qemu_exit_status\":{},\"serial_sha256\":\"{}\",",
            "\"qemu_stderr_sha256\":\"{}\",\"ovmf_vars_sha256\":\"{}\",{}",
            "\"deepwyrm_revision\":\"{}\",\"wyrmroot_revision\":\"{}\",",
            "\"rust_revision\":\"{}\",\"candidate_revalidated\":{},",
            "\"no_host_share\":true}}\n"
        ),
        status,
        request.selector,
        transcript.stress.test_id,
        run.index,
        I2_SCHEDULE_VERSION,
        run.base_seed,
        run.seed,
        transcript.stress.configured_operations,
        transcript.stress.completed_operations,
        transcript.stress.cpu_mask,
        transcript.stress.family_mask,
        transcript.stress.outcome.name(),
        transcript.stress.detail,
        transcript.stress.failing_operation,
        transcript.stress.stage,
        transcript.stress.line,
        transcript.terminal.line,
        exit_status,
        serial,
        stderr,
        vars,
        candidate_manifest,
        request.deepwyrm_revision,
        request.wyrmroot_revision,
        request.rust_revision,
        status == "PASS",
    ))
}

fn write_stress_host_failure(
    request: &HRequest,
    run: StressRun,
    paths: &RunPaths,
    reason: &str,
    cleanup: Option<CleanupDisposition>,
    candidate_manifest: &str,
) -> Result<(), Failure> {
    let vars = digest(&paths.vars, "I2 OVMF vars")?;
    let serial = optional_digest_json_allow_empty(&paths.serial_log, "I2 serial log")?;
    let stderr = optional_digest_json_allow_empty(&paths.stderr_log, "I2 QEMU stderr")?;
    let cleanup = cleanup.unwrap_or_else(CleanupDisposition::not_started);
    let result = format!(
        concat!(
            "{{\"schema_version\":4,\"phase\":\"WYR0-H-I2\",\"status\":\"ERROR\",",
            "\"reason\":\"{}\",\"profile\":\"smp\",\"selector\":\"{}\",\"test_id\":{},\"run_index\":{},",
            "\"stress_schedule_version\":\"{}\",\"stress_base_seed\":\"{:016X}\",",
            "\"stress_seed\":\"{:016X}\",\"configured_operations\":{},",
            "\"serial_sha256\":{},\"qemu_stderr_sha256\":{},\"ovmf_vars_sha256\":\"{}\",",
            "\"cleanup_disposition\":\"{}\",\"cleanup_killed\":{},\"cleanup_reaped\":{},{}",
            "\"deepwyrm_revision\":\"{}\",\"wyrmroot_revision\":\"{}\",",
            "\"rust_revision\":\"{}\",\"candidate_revalidated\":false,",
            "\"no_host_share\":true}}\n"
        ),
        reason,
        request.selector,
        request.test_id,
        run.index,
        I2_SCHEDULE_VERSION,
        run.base_seed,
        run.seed,
        run.operations,
        serial,
        stderr,
        vars,
        cleanup.name,
        cleanup.killed,
        cleanup.reaped,
        candidate_manifest,
        request.deepwyrm_revision,
        request.wyrmroot_revision,
        request.rust_revision,
    );
    write_new(
        request,
        &paths.result_json,
        result.as_bytes(),
        "I2 host-failure result",
    )
}

fn stress_summary_json(
    request: &HRequest,
    stress: &StressRequest,
    disposition: StressSummaryDisposition<'_>,
    candidate_manifest: &str,
    results: &[(StressRun, String, &'static str)],
) -> Result<String, Failure> {
    let mut ordered = String::from("[");
    for (position, (run, digest, status)) in results.iter().enumerate() {
        if position != 0 {
            ordered.push(',');
        }
        ordered.push_str(&format!(
            "{{\"run_index\":{},\"seed\":\"{:016X}\",\"result_sha256\":\"{}\",\"status\":\"{}\"}}",
            run.index, run.seed, digest, status
        ));
    }
    ordered.push(']');
    let failing = disposition
        .failing_index
        .map_or_else(|| "null".to_owned(), |index| index.to_string());
    let reason = disposition.reason.map_or_else(
        || "null".to_owned(),
        |reason| format!("\"{}\"", json_escape(reason)),
    );
    Ok(format!(
        concat!(
            "{{\"schema_version\":4,\"phase\":\"WYR0-H-I2\",\"kind\":\"stress-summary\",",
            "\"status\":\"{}\",\"selector\":\"{}\",\"test_id\":{},",
            "\"stress_schedule_version\":\"{}\",\"stress_base_seed\":\"{:016X}\",",
            "\"requested_runs\":{},\"completed_runs\":{},\"failing_run_index\":{},",
            "\"operations_per_run\":{},\"reason\":{},\"ordered_results\":{},{}",
            "\"deepwyrm_revision\":\"{}\",\"wyrmroot_revision\":\"{}\",",
            "\"rust_revision\":\"{}\",\"candidate_revalidated\":{}}}\n"
        ),
        disposition.status,
        request.selector,
        request.test_id,
        stress.schedule_version,
        stress.base_seed,
        stress.run_count,
        results
            .iter()
            .filter(|(_, _, status)| *status == "PASS")
            .count(),
        failing,
        stress.operations_per_run,
        reason,
        ordered,
        candidate_manifest,
        request.deepwyrm_revision,
        request.wyrmroot_revision,
        request.rust_revision,
        disposition.candidate_revalidated,
    ))
}

fn digest_allow_empty(path: &Path, label: &str) -> Result<String, Failure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Failure::task(format!("could not inspect {label}: {error}")))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_SERIAL_BYTES {
        return Err(Failure::task(format!(
            "{label} must be a bounded regular file"
        )));
    }
    digest(path, label)
}

fn optional_digest_json_allow_empty(path: &Path, label: &str) -> Result<String, Failure> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(format!("\"{}\"", digest_allow_empty(path, label)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok("null".to_owned()),
        Err(error) => Err(Failure::task(format!("could not inspect {label}: {error}"))),
    }
}

fn json_escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\n' => "\\n".chars().collect::<Vec<_>>(),
            '\r' => "\\r".chars().collect::<Vec<_>>(),
            '\t' => "\\t".chars().collect::<Vec<_>>(),
            character if character.is_control() => '?'.to_string().chars().collect(),
            character => vec![character],
        })
        .collect()
}

fn guest_expectation_matches(request: &HRequest, record: GuestRecord) -> bool {
    if request.schema_version == 3 {
        return request.expected_outcome == ExpectedOutcome::Pass
            && request.expected_detail == 0
            && record.outcome == GuestOutcome::Pass
            && record.detail == 0;
    }
    record.outcome.matches(request.expected_outcome) && record.detail == request.expected_detail
}

fn evidence_result_fields(
    request: &HRequest,
    evidence: Option<ValidatedEvidence>,
) -> Result<String, Failure> {
    evidence.map_or_else(
        || Ok(String::new()),
        |evidence| {
            let request_evidence = request.evidence.ok_or_else(|| {
                Failure::task("validated evidence is not bound to an evidence request")
            })?;
            Ok(format!(
                concat!(
                    "\"evidence_protocol\":\"{}\",\"evidence_nonce\":\"{:016X}\",",
                    "\"required_evidence_mask\":{},\"observed_evidence_mask\":{},",
                    "\"evidence_event_count\":{},\"first_evidence_sequence\":{},",
                    "\"last_evidence_sequence\":{},"
                ),
                I1_EVIDENCE_PROTOCOL,
                request_evidence.nonce,
                request_evidence.required_mask,
                evidence.observed_mask,
                evidence.count,
                evidence.first_sequence,
                evidence.last_sequence,
            ))
        },
    )
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
            "{{\"schema_version\":{},\"phase\":\"WYR0-H\",",
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
        request.schema_version,
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
    qemu_ovmf_code: String,
    qemu_vars: String,
    qemu_esp: String,
    qemu_serial: String,
    gdb_symbols: String,
    _inherited_files: Vec<fs::File>,
}

fn prepare_run_directory(
    profile: HProfile,
    request: &HRequest,
    artifacts: &CandidateArtifacts,
) -> Result<RunPaths, Failure> {
    h_request::validate_outputs(request)?;
    if !request.run_directory.exists() {
        request
            .root
            .create_dir(&request.run_directory, "run directory")?;
    }
    let directory = request.run_directory.join(profile.name());
    request.root.create_dir(
        &directory,
        &format!("fresh {} run directory", profile.name()),
    )?;
    let vars = directory.join("OVMF_VARS.fd");
    let serial_log = directory.join("serial.log");
    let result_json = directory.join("result.json");
    let stderr_log = directory.join("qemu.stderr.log");
    write_new(
        request,
        &vars,
        &artifacts.ovmf_vars_template.bytes,
        "request-local OVMF vars",
    )?;
    bind_run_inputs(
        request,
        artifacts,
        &directory,
        RunPaths {
            vars,
            serial_log,
            result_json,
            stderr_log,
            qemu_ovmf_code: String::new(),
            qemu_vars: String::new(),
            qemu_esp: String::new(),
            qemu_serial: String::new(),
            gdb_symbols: String::new(),
            _inherited_files: Vec::new(),
        },
    )
}

fn bind_run_inputs(
    request: &HRequest,
    artifacts: &CandidateArtifacts,
    directory: &Path,
    mut paths: RunPaths,
) -> Result<RunPaths, Failure> {
    let snapshots = directory.join("input-snapshots");
    request
        .root
        .create_dir(&snapshots, "run-local input snapshot directory")?;
    let code = snapshots.join("OVMF_CODE.fd");
    let esp = snapshots.join("esp.img");
    let symbols = snapshots.join("deepwyrm.symbols");
    let esp_bytes = request.root.read(
        &request.esp,
        "admitted ESP",
        MAX_GUEST_ARTIFACT_BYTES,
        false,
    )?;
    write_new(
        request,
        &code,
        &artifacts.ovmf_code.bytes,
        "OVMF code snapshot",
    )?;
    write_new(request, &esp, &esp_bytes, "ESP snapshot")?;
    write_new(
        request,
        &symbols,
        &artifacts.symbols.bytes,
        "symbols snapshot",
    )?;
    let code_file = request
        .root
        .open_inherited_read(&code, "OVMF code snapshot")?;
    let esp_file = request.root.open_inherited_read(&esp, "ESP snapshot")?;
    let symbols_file = request
        .root
        .open_inherited_read(&symbols, "symbols snapshot")?;
    let vars_file = request
        .root
        .open_inherited_read_write(&paths.vars, "OVMF vars snapshot")?;
    let serial_file = request.root.open_new(&paths.serial_log, "serial log")?;
    drop(serial_file);
    let serial_file = request
        .root
        .open_inherited_read_write(&paths.serial_log, "serial log")?;
    paths.qemu_ovmf_code = secure_fs::inherited_path(&code_file);
    paths.qemu_esp = secure_fs::inherited_path(&esp_file);
    paths.gdb_symbols = secure_fs::inherited_path(&symbols_file);
    paths.qemu_vars = secure_fs::inherited_path(&vars_file);
    paths.qemu_serial = secure_fs::inherited_path(&serial_file);
    paths._inherited_files = vec![code_file, esp_file, symbols_file, vars_file, serial_file];
    Ok(paths)
}

fn qemu_arguments(
    profile: HProfile,
    request: &HRequest,
    _artifacts: &CandidateArtifacts,
    kind: ExecutionKind,
    run: &RunPaths,
    stress: Option<StressRun>,
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
            run.qemu_ovmf_code
        ),
        "-drive".into(),
        format!("if=pflash,format=raw,file={}", run.qemu_vars),
        "-drive".into(),
        format!("if=virtio,format=raw,readonly=on,file={}", run.qemu_esp),
        "-serial".into(),
        format!("file:{}", run.qemu_serial),
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
        if let Some(stress) = stress {
            for (name, value) in [
                ("run-index", stress.index.to_string()),
                ("base-seed", format!("{:016X}", stress.base_seed)),
                ("seed", format!("{:016X}", stress.seed)),
                ("operations", stress.operations.to_string()),
            ] {
                args.extend([
                    "-fw_cfg".into(),
                    format!("name=opt/org.deepwyrm.test.stress.{name},string={value}"),
                ]);
            }
        }
    }
    if kind == ExecutionKind::Gdb {
        args.extend(["-S".into(), "-gdb".into(), "tcp:127.0.0.1:1234".into()]);
    }
    args
}

fn gdb_arguments(run: &RunPaths) -> Vec<String> {
    vec![
        "-ex".into(),
        "set architecture i386:x86-64".into(),
        "-ex".into(),
        format!("file {}", run.gdb_symbols),
        "-ex".into(),
        "target remote 127.0.0.1:1234".into(),
    ]
}

fn parse_transcript(bytes: &[u8], request: &HRequest) -> Result<GuestTranscript, Failure> {
    match request.evidence {
        Some(evidence) => parse_evidence_transcript(bytes, request.test_id, evidence),
        None => Ok(GuestTranscript {
            terminal: parse_terminal_record(bytes, request.test_id)?,
            evidence: None,
        }),
    }
}

fn parse_terminal_record(bytes: &[u8], expected_test_id: u32) -> Result<GuestRecord, Failure> {
    let mut terminal = None;
    for (index, line) in bytes.split_inclusive(|byte| *byte == b'\n').enumerate() {
        if !line.starts_with(b"DWTEST1|") {
            continue;
        }
        let record = parse_terminal_line(line, index + 1, expected_test_id)?;
        if terminal.is_some() {
            return Err(Failure::task(
                "serial log contains duplicate DWTEST1 terminal records",
            ));
        }
        terminal = Some(record);
    }
    terminal.ok_or_else(|| Failure::task("serial log contains no DWTEST1 terminal record"))
}

fn splitmix64_seed(base_seed: u64, run_index: u32) -> u64 {
    let mut value =
        base_seed.wrapping_add(SPLITMIX64_GAMMA.wrapping_mul(u64::from(run_index).wrapping_add(1)));
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    let mixed = value ^ (value >> 31);
    if mixed == 0 { SPLITMIX64_GAMMA } else { mixed }
}

fn parse_stress_transcript(
    bytes: &[u8],
    expected_test_id: u32,
    run: StressRun,
) -> Result<StressTranscript, Failure> {
    let mut stress = None;
    let mut terminal = None;
    for (index, line) in bytes.split_inclusive(|byte| *byte == b'\n').enumerate() {
        let line_number = index + 1;
        if resembles_protocol_magic(line, b"DWSTRESS1") {
            if terminal.is_some() {
                return Err(Failure::task(format!(
                    "serial line {line_number} contains DWSTRESS1 after the terminal record"
                )));
            }
            let record = parse_stress_line(line, line_number, expected_test_id, run)?;
            if stress.replace(record).is_some() {
                return Err(Failure::task(
                    "serial log contains duplicate DWSTRESS1 records",
                ));
            }
            continue;
        }
        if resembles_protocol_magic(line, b"DWTEST1") {
            let record = parse_terminal_line(line, line_number, expected_test_id)?;
            if terminal.replace(record).is_some() {
                return Err(Failure::task(
                    "serial log contains duplicate DWTEST1 terminal records",
                ));
            }
        }
    }
    let stress =
        stress.ok_or_else(|| Failure::task("I2 serial log contains no DWSTRESS1 record"))?;
    let terminal = terminal
        .ok_or_else(|| Failure::task("I2 serial log contains no DWTEST1 terminal record"))?;
    if stress.line >= terminal.line {
        return Err(Failure::task(
            "I2 DWSTRESS1 record must precede the DWTEST1 terminal record",
        ));
    }
    if stress.outcome != terminal.outcome || stress.detail != terminal.detail {
        return Err(Failure::task(
            "I2 DWSTRESS1 and DWTEST1 outcomes or details disagree",
        ));
    }
    Ok(StressTranscript { stress, terminal })
}

fn parse_stress_line(
    line: &[u8],
    line_number: usize,
    expected_test_id: u32,
    expected_run: StressRun,
) -> Result<StressRecord, Failure> {
    const DELIMITERS: &[usize] = &[9, 12, 21, 30, 47, 64, 73, 82, 91, 100, 103, 112, 121, 130];
    if line.len() != STRESS_RECORD_BYTES
        || &line[..9] != b"DWSTRESS1"
        || DELIMITERS.iter().any(|index| line[*index] != b'|')
        || line[139] != b'\n'
    {
        return Err(Failure::task(format!(
            "serial line {line_number} contains a malformed DWSTRESS1 record"
        )));
    }
    if &line[10..12] != b"01" {
        return Err(Failure::task(format!(
            "serial line {line_number} has an unsupported DWSTRESS1 version"
        )));
    }
    let test_id = stress_hex_u32(&line[13..21], line_number, "test id")?;
    let run_index = stress_hex_u32(&line[22..30], line_number, "run index")?;
    let base_seed = stress_hex_u64(&line[31..47], line_number, "base seed")?;
    let seed = stress_hex_u64(&line[48..64], line_number, "seed")?;
    let configured_operations =
        stress_hex_u32(&line[65..73], line_number, "configured operations")?;
    let completed_operations = stress_hex_u32(&line[74..82], line_number, "completed operations")?;
    let cpu_mask = stress_hex_u32(&line[83..91], line_number, "CPU mask")?;
    let family_mask = stress_hex_u32(&line[92..100], line_number, "family mask")?;
    let outcome = match &line[101..103] {
        b"01" => GuestOutcome::Pass,
        b"02" => GuestOutcome::Fail,
        b"03" => GuestOutcome::Panic,
        _ => {
            return Err(Failure::task(format!(
                "serial line {line_number} has an invalid DWSTRESS1 outcome"
            )));
        }
    };
    let detail = stress_hex_u32(&line[104..112], line_number, "detail")?;
    let failing_operation = stress_hex_u32(&line[113..121], line_number, "failing operation")?;
    let stage = stress_hex_u32(&line[122..130], line_number, "stage")?;
    let checksum = stress_hex_u32(&line[131..139], line_number, "checksum")?;
    if checksum != fnv1a32(&line[..131]) {
        return Err(Failure::task(format!(
            "serial line {line_number} has a mismatched DWSTRESS1 checksum"
        )));
    }
    if test_id != expected_test_id
        || run_index != expected_run.index
        || base_seed != expected_run.base_seed
        || seed != expected_run.seed
        || configured_operations != expected_run.operations
    {
        return Err(Failure::task(format!(
            "serial line {line_number} DWSTRESS1 identity or configuration does not match the request"
        )));
    }
    if completed_operations > configured_operations
        || cpu_mask & !I2_CPU_MASK != 0
        || family_mask & !I2_FAMILY_MASK != 0
    {
        return Err(Failure::task(format!(
            "serial line {line_number} DWSTRESS1 reports invalid progress or masks"
        )));
    }
    if outcome == GuestOutcome::Pass
        && (completed_operations != configured_operations
            || cpu_mask != I2_CPU_MASK
            || family_mask != I2_FAMILY_MASK
            || detail != 0
            || failing_operation != u32::MAX
            || stage != 0)
    {
        return Err(Failure::task(format!(
            "serial line {line_number} DWSTRESS1 PASS lacks the complete I2 proof"
        )));
    }
    Ok(StressRecord {
        outcome,
        test_id,
        run_index,
        base_seed,
        seed,
        configured_operations,
        completed_operations,
        cpu_mask,
        family_mask,
        detail,
        failing_operation,
        stage,
        line: line_number,
    })
}

fn stress_hex_u32(bytes: &[u8], line_number: usize, field: &str) -> Result<u32, Failure> {
    parse_hex(bytes).ok_or_else(|| {
        Failure::task(format!(
            "serial line {line_number} has an invalid DWSTRESS1 {field}"
        ))
    })
}

fn stress_hex_u64(bytes: &[u8], line_number: usize, field: &str) -> Result<u64, Failure> {
    parse_hex_u64(bytes).ok_or_else(|| {
        Failure::task(format!(
            "serial line {line_number} has an invalid DWSTRESS1 {field}"
        ))
    })
}

fn parse_evidence_transcript(
    bytes: &[u8],
    expected_test_id: u32,
    request: EvidenceRequest,
) -> Result<GuestTranscript, Failure> {
    let mut terminal = None;
    let mut events = Vec::new();
    for (index, line) in bytes.split_inclusive(|byte| *byte == b'\n').enumerate() {
        let line_number = index + 1;
        if resembles_protocol_magic(line, b"DWEVID1") {
            if terminal.is_some() {
                return Err(Failure::task(format!(
                    "serial line {line_number} contains DWEVID1 evidence after the terminal record"
                )));
            }
            if events.len() == MAX_EVIDENCE_RECORDS {
                return Err(Failure::task(format!(
                    "serial line {line_number} exceeds the {MAX_EVIDENCE_RECORDS}-record DWEVID1 limit"
                )));
            }
            let event = parse_evidence_line(line, line_number, request.nonce)?;
            if event.sequence != events.len() as u32 {
                return Err(Failure::task(format!(
                    "serial line {line_number} has non-contiguous DWEVID1 sequence {:08X}; expected {:08X}",
                    event.sequence,
                    events.len()
                )));
            }
            events.push(event);
            continue;
        }
        if resembles_protocol_magic(line, b"DWTEST1") {
            let record = parse_terminal_line(line, line_number, expected_test_id)?;
            if terminal.replace(record).is_some() {
                return Err(Failure::task(
                    "serial log contains duplicate DWTEST1 terminal records",
                ));
            }
        }
    }
    let terminal =
        terminal.ok_or_else(|| Failure::task("serial log contains no DWTEST1 terminal record"))?;
    if events.is_empty() {
        return Err(Failure::task(
            "I1 serial log contains no DWEVID1 evidence records",
        ));
    }
    let evidence = validate_evidence(&events, request.required_mask)?;
    Ok(GuestTranscript {
        terminal,
        evidence: Some(evidence),
    })
}

fn resembles_protocol_magic(line: &[u8], magic: &[u8]) -> bool {
    line.get(..magic.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(magic))
}

fn parse_terminal_line(
    line: &[u8],
    line_number: usize,
    expected_test_id: u32,
) -> Result<GuestRecord, Failure> {
    if line.len() != COMPLETION_RECORD_BYTES
        || &line[..7] != b"DWTEST1"
        || line[7] != b'|'
        || line[10] != b'|'
        || line[19] != b'|'
        || line[28] != b'|'
        || line[37] != b'\n'
    {
        return Err(Failure::task(format!(
            "serial line {line_number} contains a malformed DWTEST1 record"
        )));
    }
    let outcome = match &line[8..10] {
        b"01" => GuestOutcome::Pass,
        b"02" => GuestOutcome::Fail,
        b"03" => GuestOutcome::Panic,
        _ => {
            return Err(Failure::task(format!(
                "serial line {line_number} has an invalid DWTEST1 outcome"
            )));
        }
    };
    let test_id = parse_hex(&line[11..19]).ok_or_else(|| {
        Failure::task(format!(
            "serial line {line_number} has an invalid DWTEST1 test id"
        ))
    })?;
    let detail = parse_hex(&line[20..28]).ok_or_else(|| {
        Failure::task(format!(
            "serial line {line_number} has an invalid DWTEST1 detail"
        ))
    })?;
    let checksum = parse_hex(&line[29..37]).ok_or_else(|| {
        Failure::task(format!(
            "serial line {line_number} has an invalid DWTEST1 checksum"
        ))
    })?;
    if checksum != fnv1a32(&line[..29]) {
        return Err(Failure::task(format!(
            "serial line {line_number} has a mismatched DWTEST1 checksum"
        )));
    }
    if test_id != expected_test_id {
        return Err(Failure::task(format!(
            "serial line {line_number} test id {test_id:08X} does not match request {expected_test_id:08X}"
        )));
    }
    Ok(GuestRecord {
        outcome,
        test_id,
        detail,
        line: line_number,
    })
}

fn parse_evidence_line(
    line: &[u8],
    line_number: usize,
    expected_nonce: u64,
) -> Result<EvidenceEvent, Failure> {
    if line.len() != EVIDENCE_RECORD_BYTES
        || &line[..7] != b"DWEVID1"
        || line[7] != b'|'
        || line[10] != b'|'
        || line[27] != b'|'
        || line[36] != b'|'
        || line[39] != b'|'
        || line[48] != b'|'
        || line[57] != b'|'
        || line[66] != b'|'
        || line[75] != b'|'
        || line[84] != b'\n'
    {
        return Err(Failure::task(format!(
            "serial line {line_number} contains a malformed DWEVID1 record"
        )));
    }
    if &line[8..10] != b"01" {
        return Err(Failure::task(format!(
            "serial line {line_number} has an unsupported DWEVID1 version"
        )));
    }
    let nonce = parse_hex_u64(&line[11..27]).ok_or_else(|| {
        Failure::task(format!(
            "serial line {line_number} has an invalid DWEVID1 nonce"
        ))
    })?;
    if nonce != expected_nonce {
        return Err(Failure::task(format!(
            "serial line {line_number} DWEVID1 nonce does not match the request"
        )));
    }
    let sequence = evidence_hex_u32(&line[28..36], line_number, "sequence")?;
    let kind_value = parse_hex_u8(&line[37..39]).ok_or_else(|| {
        Failure::task(format!(
            "serial line {line_number} has an invalid DWEVID1 kind"
        ))
    })?;
    let kind = EvidenceKind::parse(kind_value).ok_or_else(|| {
        Failure::task(format!(
            "serial line {line_number} has unknown DWEVID1 kind {kind_value:02X}"
        ))
    })?;
    let cpu = evidence_hex_u32(&line[40..48], line_number, "CPU")?;
    if cpu > 3 {
        return Err(Failure::task(format!(
            "serial line {line_number} DWEVID1 CPU {cpu} is outside 0..3"
        )));
    }
    let token = evidence_hex_u32(&line[49..57], line_number, "token")?;
    let arg0 = evidence_hex_u32(&line[58..66], line_number, "arg0")?;
    let arg1 = evidence_hex_u32(&line[67..75], line_number, "arg1")?;
    let checksum = evidence_hex_u32(&line[76..84], line_number, "checksum")?;
    if checksum != fnv1a32(&line[..76]) {
        return Err(Failure::task(format!(
            "serial line {line_number} has a mismatched DWEVID1 checksum"
        )));
    }
    Ok(EvidenceEvent {
        sequence,
        kind,
        cpu,
        token,
        arg0,
        arg1,
        line: line_number,
    })
}

fn evidence_hex_u32(bytes: &[u8], line_number: usize, field: &str) -> Result<u32, Failure> {
    parse_hex(bytes).ok_or_else(|| {
        Failure::task(format!(
            "serial line {line_number} has an invalid DWEVID1 {field}"
        ))
    })
}

fn parse_hex_u8(bytes: &[u8]) -> Option<u8> {
    if bytes.len() != 2 || !bytes.iter().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(byte))
    {
        return None;
    }
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|value| u8::from_str_radix(value, 16).ok())
}

fn parse_hex_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.len() != 16
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(byte))
    {
        return None;
    }
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|value| u64::from_str_radix(value, 16).ok())
}

fn exactly_one(events: &[EvidenceEvent], label: &str) -> Result<EvidenceEvent, Failure> {
    if events.len() != 1 {
        return Err(Failure::task(format!(
            "I1 evidence requires exactly one {label} event; observed {}",
            events.len()
        )));
    }
    Ok(events[0])
}

fn validate_evidence(
    events: &[EvidenceEvent],
    required_evidence_mask: u32,
) -> Result<ValidatedEvidence, Failure> {
    let mut observed_mask = 0_u32;
    let mut cpu_online = Vec::new();
    let mut cpl3_syscall = Vec::new();
    let mut parent_blocked = Vec::new();
    let mut descendant_running = Vec::new();
    let mut running_invariant = Vec::new();
    let mut wake_sent = Vec::new();
    let mut wake_observed = Vec::new();
    let mut child_exit = Vec::new();
    let mut child_cleanup = Vec::new();
    let mut tlb_publish = Vec::new();
    let mut tlb_ack = Vec::new();
    let mut rendezvous_ack = Vec::new();
    let mut reclaim_allowed = Vec::new();
    let mut unique_events = BTreeSet::new();

    for event in events.iter().copied() {
        if !unique_events.insert((event.kind, event.cpu, event.token, event.arg0, event.arg1)) {
            return Err(Failure::task(format!(
                "serial line {} duplicates an earlier DWEVID1 event",
                event.line
            )));
        }
        match event.kind {
            EvidenceKind::CpuOnline => cpu_online.push(event),
            EvidenceKind::Cpl3Syscall => cpl3_syscall.push(event),
            EvidenceKind::ParentBlocked => parent_blocked.push(event),
            EvidenceKind::DescendantRunning => descendant_running.push(event),
            EvidenceKind::RunningInvariant => running_invariant.push(event),
            EvidenceKind::WakeSent => wake_sent.push(event),
            EvidenceKind::WakeObserved => wake_observed.push(event),
            EvidenceKind::ChildExit => child_exit.push(event),
            EvidenceKind::ChildCleanup => child_cleanup.push(event),
            EvidenceKind::TlbPublish => tlb_publish.push(event),
            EvidenceKind::TlbAck => tlb_ack.push(event),
            EvidenceKind::RendezvousAck => rendezvous_ack.push(event),
            EvidenceKind::ReclaimAllowed => reclaim_allowed.push(event),
        }
    }

    if cpu_online.len() != 4 {
        return Err(Failure::task(format!(
            "I1 evidence requires CPU_ONLINE exactly once for CPUs 0..3; observed {} records",
            cpu_online.len()
        )));
    }
    let mut online_cpus = BTreeSet::new();
    let mut apic_ids = BTreeSet::new();
    let mut slots = BTreeSet::new();
    for event in &cpu_online {
        if !online_cpus.insert(event.cpu) {
            return Err(Failure::task("I1 evidence repeats a CPU_ONLINE CPU"));
        }
        if !apic_ids.insert(event.arg0) {
            return Err(Failure::task("I1 evidence repeats a CPU_ONLINE APIC ID"));
        }
        if event.arg1 != event.cpu || !slots.insert(event.arg1) {
            return Err(Failure::task(
                "I1 CPU_ONLINE slots must be distinct and match their CPU IDs",
            ));
        }
    }
    if online_cpus != BTreeSet::from([0, 1, 2, 3]) {
        return Err(Failure::task(
            "I1 evidence does not contain CPU_ONLINE for every CPU 0..3",
        ));
    }
    let last_online_sequence = cpu_online
        .iter()
        .map(|event| event.sequence)
        .max()
        .ok_or_else(|| Failure::task("I1 evidence contains no CPU_ONLINE record"))?;
    if events.iter().any(|event| {
        event.kind != EvidenceKind::CpuOnline && event.sequence <= last_online_sequence
    }) {
        return Err(Failure::task(
            "I1 CPU_ONLINE records must precede every participation and activity event",
        ));
    }
    observed_mask |= PROOF_CPU_ONLINE;

    let cpl3_cpus = cpl3_syscall
        .iter()
        .map(|event| event.cpu)
        .collect::<BTreeSet<_>>();
    if cpl3_cpus.len() < 2 {
        return Err(Failure::task(
            "I1 evidence requires CPL3_SYSCALL on at least two distinct CPUs",
        ));
    }
    let cpl3_tokens = cpl3_syscall
        .iter()
        .map(|event| event.token)
        .collect::<BTreeSet<_>>();
    if cpl3_tokens.contains(&0) || cpl3_tokens.len() < 2 {
        return Err(Failure::task(
            "I1 evidence requires CPL3_SYSCALL with two distinct nonzero execution tokens",
        ));
    }
    observed_mask |= PROOF_CPL3_SYSCALL;

    let blocked = exactly_one(&parent_blocked, "PARENT_BLOCKED")?;
    let descendant = exactly_one(&descendant_running, "DESCENDANT_RUNNING")?;
    if blocked.token == 0
        || descendant.token != blocked.token
        || descendant.sequence <= blocked.sequence
        || descendant.cpu == blocked.cpu
    {
        return Err(Failure::task(
            "I1 parent/descendant evidence has an invalid token, order, or CPU join",
        ));
    }
    observed_mask |= PROOF_BLOCKED_DESCENDANT;

    let invariant = exactly_one(&running_invariant, "RUNNING_INVARIANT")?;
    if invariant.token != 0 || invariant.cpu != 0 || invariant.arg0 != 0 {
        return Err(Failure::task(
            "I1 RUNNING_INVARIANT must report zero token, CPU, and violation count",
        ));
    }
    if events.last().map(|event| event.sequence) != Some(invariant.sequence) {
        return Err(Failure::task(
            "I1 RUNNING_INVARIANT must be the final evidence event after all scheduler and lifecycle activity",
        ));
    }
    observed_mask |= PROOF_RUNNING_INVARIANT;

    let sent = exactly_one(&wake_sent, "WAKE_SENT")?;
    let observed = exactly_one(&wake_observed, "WAKE_OBSERVED")?;
    if sent.token == 0
        || observed.token != sent.token
        || observed.sequence <= sent.sequence
        || observed.cpu == sent.cpu
        || sent.arg0 != observed.cpu
        || observed.arg0 != sent.cpu
    {
        return Err(Failure::task(
            "I1 wake evidence has an invalid token, order, CPU, target, or source join",
        ));
    }
    observed_mask |= PROOF_REMOTE_WAKE;

    let exited = exactly_one(&child_exit, "CHILD_EXIT")?;
    let cleanup = exactly_one(&child_cleanup, "CHILD_CLEANUP")?;
    if exited.token == 0
        || cleanup.token != exited.token
        || cleanup.sequence <= exited.sequence
        || cleanup.cpu == exited.cpu
    {
        return Err(Failure::task(
            "I1 child exit/cleanup evidence has an invalid token, order, or CPU join",
        ));
    }
    observed_mask |= PROOF_CHILD_CLEANUP;

    let publish = exactly_one(&tlb_publish, "TLB_PUBLISH")?;
    let reclaim = exactly_one(&reclaim_allowed, "RECLAIM_ALLOWED")?;
    let required_cpu_mask = publish.arg0;
    if publish.token == 0 || required_cpu_mask != 0x0F {
        return Err(Failure::task(
            "I1 TLB_PUBLISH requires a nonzero generation and exact CPU mask 0000000F",
        ));
    }
    if reclaim.token != publish.token || reclaim.sequence <= publish.sequence {
        return Err(Failure::task(
            "I1 RECLAIM_ALLOWED has an invalid generation or order",
        ));
    }
    let tlb_ack_mask = validate_ack_set(&tlb_ack, publish, reclaim, required_cpu_mask, "TLB_ACK")?;
    let rendezvous_ack_mask = validate_ack_set(
        &rendezvous_ack,
        publish,
        reclaim,
        required_cpu_mask,
        "RENDEZVOUS_ACK",
    )?;
    if reclaim.arg0 != tlb_ack_mask || reclaim.arg1 != rendezvous_ack_mask {
        return Err(Failure::task(
            "I1 RECLAIM_ALLOWED masks do not exactly match the observed acknowledgement masks",
        ));
    }
    if reclaim.arg0 != 0x0F || reclaim.arg1 != 0x0F {
        return Err(Failure::task(
            "I1 RECLAIM_ALLOWED requires exact TLB and rendezvous masks 0000000F",
        ));
    }
    observed_mask |= PROOF_TLB_ACK;
    observed_mask |= PROOF_RENDEZVOUS_RECLAIM;

    if observed_mask != required_evidence_mask {
        return Err(Failure::task(format!(
            "I1 transcript proof mask {observed_mask:08X} does not exactly match request {required_evidence_mask:08X}"
        )));
    }
    Ok(ValidatedEvidence {
        count: events.len() as u32,
        observed_mask,
        first_sequence: events[0].sequence,
        last_sequence: events[events.len() - 1].sequence,
    })
}

fn validate_ack_set(
    acknowledgements: &[EvidenceEvent],
    publish: EvidenceEvent,
    reclaim: EvidenceEvent,
    required_cpu_mask: u32,
    label: &str,
) -> Result<u32, Failure> {
    let mut observed_mask = 0_u32;
    for event in acknowledgements {
        let cpu_bit = 1_u32 << event.cpu;
        if event.sequence <= publish.sequence
            || event.sequence >= reclaim.sequence
            || event.token != publish.token
            || event.arg0 != required_cpu_mask
            || required_cpu_mask & cpu_bit == 0
        {
            return Err(Failure::task(format!(
                "I1 {label} has an invalid order, generation, CPU, or required mask"
            )));
        }
        if observed_mask & cpu_bit != 0 {
            return Err(Failure::task(format!(
                "I1 {label} repeats an acknowledgement CPU"
            )));
        }
        observed_mask |= cpu_bit;
    }
    if observed_mask != required_cpu_mask {
        return Err(Failure::task(format!(
            "I1 {label} acknowledgements do not cover the required CPU mask"
        )));
    }
    Ok(observed_mask)
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

pub(crate) fn freeze_candidate_fields(request_path: &Path) -> Result<String, Failure> {
    let request = h_request::load(request_path)?;
    if request.schema_version != 4 || request.stress.is_none() {
        return Err(Failure::task(
            "V0 freeze candidate_request must be the admitted schema-v4 I2 request",
        ));
    }
    verify_source_revisions(&request)?;
    let artifacts = verify_candidate_inputs(&request)?;
    inspect_loaded(&request, &artifacts)?;
    let digests = candidate_digests(&request, &artifacts)?;
    let provenance = digest(&request.provenance, "provenance")?;
    Ok(format!(
        concat!(
            "candidate_request_sha256 = \"{}\"\n",
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
            "provenance_sha256 = \"{}\"\n"
        ),
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
        provenance,
    ))
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
    request.root.write_new(path, bytes, label)
}

fn open_new(request: &HRequest, path: &Path, label: &str) -> Result<fs::File, Failure> {
    request.root.open_new(path, label)
}

fn require_absent(request: &HRequest, path: &Path, label: &str) -> Result<(), Failure> {
    h_request::validate_output_parent(request, path, label)?;
    if request.root.exists(path, label)? {
        Err(Failure::task(format!("WYR0-H {label} already exists")))
    } else {
        Ok(())
    }
}

fn digest(path: &Path, label: &str) -> Result<String, Failure> {
    Ok(sha256::bytes_digest(&secure_fs::read_path(
        path,
        label,
        1024 * 1024 * 1024,
        true,
    )?))
}

fn remove_created(request: &HRequest, path: &Path) {
    let _ = request.root.remove_file(path, "partial output");
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
    use std::sync::Arc;

    const TEST_EVIDENCE_NONCE: u64 = h_request::I1_EVIDENCE_NONCE;

    fn test_root(path: &Path) -> secure_fs::Root {
        if path.is_dir() {
            secure_fs::Root::open(path, "test root").expect("open test root")
        } else {
            secure_fs::Root::placeholder(path)
        }
    }

    fn test_artifact(path: &Path) -> AdmittedArtifact {
        AdmittedArtifact {
            source: path.to_path_buf(),
            bytes: fs::read(path).unwrap_or_else(|_| b"artifact".to_vec()),
        }
    }

    #[derive(Clone, Copy)]
    struct EventSpec {
        kind: u8,
        cpu: u32,
        token: u32,
        arg0: u32,
        arg1: u32,
    }

    fn terminal(status: &str, test_id: u32, detail: u32) -> Vec<u8> {
        let mut record = format!("DWTEST1|{status}|{test_id:08X}|{detail:08X}|").into_bytes();
        record.extend_from_slice(format!("{:08X}\n", fnv1a32(&record)).as_bytes());
        record
    }

    fn evidence_line(nonce: u64, sequence: u32, event: EventSpec) -> Vec<u8> {
        let mut record = format!(
            "DWEVID1|01|{nonce:016X}|{sequence:08X}|{:02X}|{:08X}|{:08X}|{:08X}|{:08X}|",
            event.kind, event.cpu, event.token, event.arg0, event.arg1
        )
        .into_bytes();
        record.extend_from_slice(format!("{:08X}\n", fnv1a32(&record)).as_bytes());
        assert_eq!(record.len(), EVIDENCE_RECORD_BYTES);
        record
    }

    fn stress_line(run: StressRun, fields: (&str, u32, u32, u32, u32, u32, u32)) -> Vec<u8> {
        let (outcome, done, cpu_mask, family_mask, detail, failop, stage) = fields;
        let mut record = format!(
            "DWSTRESS1|01|{:08X}|{:08X}|{:016X}|{:016X}|{:08X}|{:08X}|{:08X}|{:08X}|{}|{:08X}|{:08X}|{:08X}|",
            h_request::I2_TEST_ID,
            run.index,
            run.base_seed,
            run.seed,
            run.operations,
            done,
            cpu_mask,
            family_mask,
            outcome,
            detail,
            failop,
            stage,
        )
        .into_bytes();
        record.extend_from_slice(format!("{:08X}\n", fnv1a32(&record)).as_bytes());
        assert_eq!(record.len(), STRESS_RECORD_BYTES);
        record
    }

    fn valid_stress_transcript(run: StressRun) -> Vec<u8> {
        let mut transcript = b"diagnostic before stress\n".to_vec();
        transcript.extend_from_slice(&stress_line(
            run,
            (
                "01",
                run.operations,
                I2_CPU_MASK,
                I2_FAMILY_MASK,
                0,
                u32::MAX,
                0,
            ),
        ));
        transcript.extend_from_slice(b"diagnostic before terminal\n");
        transcript.extend_from_slice(&terminal("01", h_request::I2_TEST_ID, 0));
        transcript
    }

    const fn event(kind: u8, cpu: u32, token: u32, arg0: u32, arg1: u32) -> EventSpec {
        EventSpec {
            kind,
            cpu,
            token,
            arg0,
            arg1,
        }
    }

    fn valid_evidence_specs() -> Vec<EventSpec> {
        vec![
            event(0x01, 0, 0, 0x10, 0),
            event(0x01, 1, 0, 0x11, 1),
            event(0x01, 2, 0, 0x12, 2),
            event(0x01, 3, 0, 0x13, 3),
            event(0x02, 0, 1, 0, 0),
            event(0x02, 2, 2, 0, 0),
            event(0x03, 0, 0x100, 0, 0),
            event(0x04, 1, 0x100, 0, 0),
            event(0x06, 1, 0x200, 3, 0),
            event(0x07, 3, 0x200, 1, 0),
            event(0x08, 2, 0x300, 0, 0),
            event(0x09, 0, 0x300, 0, 0),
            event(0x0A, 0, 0x400, 0x0F, 0),
            event(0x0B, 0, 0x400, 0x0F, 0),
            event(0x0B, 1, 0x400, 0x0F, 0),
            event(0x0B, 2, 0x400, 0x0F, 0),
            event(0x0B, 3, 0x400, 0x0F, 0),
            event(0x0C, 0, 0x400, 0x0F, 0),
            event(0x0C, 1, 0x400, 0x0F, 0),
            event(0x0C, 2, 0x400, 0x0F, 0),
            event(0x0C, 3, 0x400, 0x0F, 0),
            event(0x0D, 0, 0x400, 0x0F, 0x0F),
            event(0x05, 0, 0, 0, 0),
        ]
    }

    fn evidence_transcript(specs: &[EventSpec], nonce: u64) -> Vec<u8> {
        let mut transcript = b"firmware diagnostic\n".to_vec();
        for (sequence, event) in specs.iter().copied().enumerate() {
            transcript.extend_from_slice(&evidence_line(nonce, sequence as u32, event));
            if sequence == 8 {
                transcript.extend_from_slice(b"human diagnostic between evidence records\n");
            }
        }
        transcript.extend_from_slice(b"guest diagnostic before terminal\n");
        transcript.extend_from_slice(&terminal("01", 23, 0));
        transcript.extend_from_slice(b"host-visible diagnostic after terminal\n");
        transcript
    }

    fn mutate_evidence_line(
        transcript: &[u8],
        evidence_index: usize,
        mutate: impl FnOnce(&mut Vec<u8>),
    ) -> Vec<u8> {
        let mut lines = transcript
            .split_inclusive(|byte| *byte == b'\n')
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        let line = lines
            .iter_mut()
            .filter(|line| line.starts_with(b"DWEVID1"))
            .nth(evidence_index)
            .expect("evidence line exists");
        mutate(line);
        lines.concat()
    }

    fn i1_request() -> HRequest {
        let root = PathBuf::from("/candidate");
        HRequest {
            path: root.join("request.toml"),
            root: test_root(&root),
            request_bytes: Arc::new(b"request".to_vec()),
            schema_version: 3,
            deepwyrm_revision: "1".repeat(40),
            wyrmroot_revision: "2".repeat(40),
            rust_revision: "3".repeat(40),
            selector: "smp-runtime-acceptance".into(),
            test_id: 23,
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
            evidence: Some(EvidenceRequest {
                nonce: TEST_EVIDENCE_NONCE,
                required_mask: h_request::I1_REQUIRED_EVIDENCE_MASK,
            }),
            stress: None,
        }
    }

    fn i2_request() -> HRequest {
        let i1 = i1_request();
        HRequest {
            schema_version: 4,
            selector: h_request::I2_SELECTOR.into(),
            test_id: h_request::I2_TEST_ID,
            evidence: None,
            stress: Some(StressRequest {
                base_seed: TEST_EVIDENCE_NONCE,
                run_count: 4,
                operations_per_run: 256,
                schedule_version: I2_SCHEDULE_VERSION.into(),
                v0_manifest: PathBuf::from("/candidate/v0-manifest.toml"),
            }),
            ..i1
        }
    }

    #[test]
    fn locked_profiles_share_media_contract_but_not_cpu_count() {
        assert_eq!(HProfile::Default.vcpus(), 1);
        assert_eq!(HProfile::Smp.vcpus(), 4);
        assert_eq!(HProfile::Default.memory_mib(), 1024);
        assert_eq!(HProfile::Smp.memory_mib(), 2048);
    }

    #[test]
    fn splitmix64_schedule_matches_pinned_vectors() {
        assert_eq!(
            (0..4)
                .map(|index| splitmix64_seed(TEST_EVIDENCE_NONCE, index))
                .collect::<Vec<_>>(),
            vec![
                0x157A_3807_A48F_AA9D,
                0xD573_529B_34A1_D093,
                0x2F90_B72E_996D_CCBE,
                0xA2D4_1933_4C46_67EC,
            ]
        );
        assert_ne!(splitmix64_seed(1, 0), 0);
    }

    #[test]
    fn schema_four_execution_requires_explicit_smp() {
        let request = i2_request();
        assert!(validate_execution_profile(&request, Some(HProfile::Smp)).is_ok());
        assert!(validate_execution_profile(&request, Some(HProfile::Default)).is_err());
        assert!(validate_execution_profile(&request, None).is_err());
    }

    #[test]
    fn i2_transcript_is_exact_strict_and_semantically_complete() {
        let run = StressRun {
            index: 2,
            base_seed: TEST_EVIDENCE_NONCE,
            seed: splitmix64_seed(TEST_EVIDENCE_NONCE, 2),
            operations: 256,
        };
        let valid = valid_stress_transcript(run);
        let parsed = parse_stress_transcript(&valid, h_request::I2_TEST_ID, run)
            .expect("valid I2 transcript rejected");
        assert_eq!(parsed.stress.completed_operations, 256);
        assert_eq!(parsed.stress.cpu_mask, I2_CPU_MASK);
        assert_eq!(parsed.stress.family_mask, I2_FAMILY_MASK);

        let exact = stress_line(
            run,
            ("01", 256, I2_CPU_MASK, I2_FAMILY_MASK, 0, u32::MAX, 0),
        );
        for length in 0..STRESS_RECORD_BYTES {
            assert!(
                parse_stress_line(&exact[..length], 1, h_request::I2_TEST_ID, run).is_err(),
                "admitted DWSTRESS1 truncation at {length}"
            );
        }
        for delimiter in [9, 12, 21, 30, 47, 64, 73, 82, 91, 100, 103, 112, 121, 130] {
            let mut malformed = exact.clone();
            malformed[delimiter] = b':';
            assert!(parse_stress_line(&malformed, 1, h_request::I2_TEST_ID, run).is_err());
        }
        for mutation in [
            stress_line(
                StressRun { index: 1, ..run },
                ("01", 256, I2_CPU_MASK, I2_FAMILY_MASK, 0, u32::MAX, 0),
            ),
            stress_line(
                StressRun {
                    seed: run.seed ^ 1,
                    ..run
                },
                ("01", 256, I2_CPU_MASK, I2_FAMILY_MASK, 0, u32::MAX, 0),
            ),
            stress_line(
                run,
                ("01", 255, I2_CPU_MASK, I2_FAMILY_MASK, 0, u32::MAX, 0),
            ),
            stress_line(run, ("01", 256, 0x07, I2_FAMILY_MASK, 0, u32::MAX, 0)),
            stress_line(run, ("01", 256, I2_CPU_MASK, 0xFF, 0, u32::MAX, 0)),
            stress_line(
                run,
                ("01", 256, I2_CPU_MASK, I2_FAMILY_MASK, 1, u32::MAX, 0),
            ),
            stress_line(run, ("01", 256, I2_CPU_MASK, I2_FAMILY_MASK, 0, 0, 0)),
            stress_line(
                run,
                ("01", 256, I2_CPU_MASK, I2_FAMILY_MASK, 0, u32::MAX, 1),
            ),
        ] {
            assert!(parse_stress_line(&mutation, 1, h_request::I2_TEST_ID, run).is_err());
        }
        let mut lowercase = exact.clone();
        lowercase[49].make_ascii_lowercase();
        assert!(parse_stress_line(&lowercase, 1, h_request::I2_TEST_ID, run).is_err());
        let mut checksum = exact.clone();
        checksum[138] = if checksum[138] == b'0' { b'1' } else { b'0' };
        assert!(parse_stress_line(&checksum, 1, h_request::I2_TEST_ID, run).is_err());

        let replacements = [
            "DWSTRESX".to_owned(),
            "02".to_owned(),
            "00000017".to_owned(),
            format!("{:08X}", run.index ^ 1),
            format!("{:016X}", run.base_seed ^ 1),
            format!("{:016X}", run.seed ^ 1),
            "000000FF".to_owned(),
            "000000FF".to_owned(),
            "00000007".to_owned(),
            "000000FF".to_owned(),
            "00".to_owned(),
            "00000001".to_owned(),
            "00000000".to_owned(),
            "00000001".to_owned(),
            "00000000".to_owned(),
        ];
        for (field, replacement) in replacements.into_iter().enumerate() {
            let text = std::str::from_utf8(&exact).expect("stress record UTF-8");
            let mut fields = text
                .trim_end()
                .split('|')
                .map(str::to_owned)
                .collect::<Vec<_>>();
            assert_eq!(fields.len(), 15);
            fields[field] = replacement;
            let mutation = if field == 14 {
                format!("{}\n", fields.join("|")).into_bytes()
            } else {
                let prefix = format!("{}|", fields[..14].join("|"));
                format!("{prefix}{:08X}\n", fnv1a32(prefix.as_bytes())).into_bytes()
            };
            assert!(
                parse_stress_line(&mutation, 1, h_request::I2_TEST_ID, run).is_err(),
                "admitted recomputed DWSTRESS1 mutation in field {field}"
            );
        }
    }

    #[test]
    fn i2_near_magic_duplicates_and_order_fail_closed() {
        let run = StressRun {
            index: 0,
            base_seed: TEST_EVIDENCE_NONCE,
            seed: splitmix64_seed(TEST_EVIDENCE_NONCE, 0),
            operations: 32,
        };
        let valid = valid_stress_transcript(run);
        for prefix in [
            b"dwstress1".as_slice(),
            b"DwStReSs1".as_slice(),
            b"dwtest1".as_slice(),
        ] {
            let mut transcript = prefix.to_vec();
            transcript.extend_from_slice(b" malformed diagnostic\n");
            transcript.extend_from_slice(&valid);
            assert!(parse_stress_transcript(&transcript, h_request::I2_TEST_ID, run).is_err());
        }
        let mut duplicate_stress = valid.clone();
        duplicate_stress.splice(
            0..0,
            stress_line(run, ("01", 32, I2_CPU_MASK, I2_FAMILY_MASK, 0, u32::MAX, 0)),
        );
        assert!(parse_stress_transcript(&duplicate_stress, h_request::I2_TEST_ID, run).is_err());
        let mut duplicate_terminal = valid.clone();
        duplicate_terminal.extend_from_slice(&terminal("01", h_request::I2_TEST_ID, 0));
        assert!(parse_stress_transcript(&duplicate_terminal, h_request::I2_TEST_ID, run).is_err());
        let mut after_terminal = terminal("01", h_request::I2_TEST_ID, 0);
        after_terminal.extend_from_slice(&stress_line(
            run,
            ("01", 32, I2_CPU_MASK, I2_FAMILY_MASK, 0, u32::MAX, 0),
        ));
        assert!(parse_stress_transcript(&after_terminal, h_request::I2_TEST_ID, run).is_err());
        let mut mismatch = stress_line(run, ("02", 7, 0x03, 0x01, 0xDEAD, 6, 2));
        mismatch.extend_from_slice(&terminal("01", h_request::I2_TEST_ID, 0));
        assert!(parse_stress_transcript(&mismatch, h_request::I2_TEST_ID, run).is_err());
    }

    #[test]
    fn schema_three_execution_requires_an_explicit_smp_profile() {
        let request = i1_request();
        assert!(validate_execution_profile(&request, Some(HProfile::Smp)).is_ok());
        assert!(validate_execution_profile(&request, Some(HProfile::Default)).is_err());
        assert!(validate_execution_profile(&request, None).is_err());

        let schema_two = HRequest {
            schema_version: 2,
            selector: "primordial-bootstrap".into(),
            test_id: 18,
            evidence: None,
            stress: None,
            ..request
        };
        assert!(validate_execution_profile(&schema_two, Some(HProfile::Smp)).is_ok());
        assert!(validate_execution_profile(&schema_two, Some(HProfile::Default)).is_ok());
        assert!(validate_execution_profile(&schema_two, None).is_ok());
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
    fn i1_transcript_accepts_all_semantic_proofs_with_surrounding_diagnostics() {
        let request = i1_request();
        let transcript = evidence_transcript(&valid_evidence_specs(), TEST_EVIDENCE_NONCE);
        let parsed = parse_transcript(&transcript, &request).expect("valid I1 transcript rejected");
        assert_eq!(parsed.terminal.outcome, GuestOutcome::Pass);
        assert_eq!(parsed.terminal.test_id, 23);
        assert_eq!(
            parsed.evidence,
            Some(ValidatedEvidence {
                count: 23,
                observed_mask: 255,
                first_sequence: 0,
                last_sequence: 22,
            })
        );
        let fields = evidence_result_fields(&request, parsed.evidence)
            .expect("validated evidence fields rejected");
        assert_eq!(
            fields,
            concat!(
                "\"evidence_protocol\":\"dwevid1\",",
                "\"evidence_nonce\":\"0123456789ABCDEF\",",
                "\"required_evidence_mask\":255,\"observed_evidence_mask\":255,",
                "\"evidence_event_count\":23,\"first_evidence_sequence\":0,",
                "\"last_evidence_sequence\":22,"
            )
        );
    }

    #[test]
    fn i1_protocol_framing_is_exact_and_fail_closed() {
        let request = i1_request();
        let valid = evidence_transcript(&valid_evidence_specs(), TEST_EVIDENCE_NONCE);
        let exact_line = evidence_line(
            TEST_EVIDENCE_NONCE,
            0,
            event(0x0A, 3, 0xABCD_EF01, 0x0F, 0xCAFE_BABE),
        );
        assert!(parse_evidence_line(&exact_line, 1, TEST_EVIDENCE_NONCE).is_ok());
        for length in 0..EVIDENCE_RECORD_BYTES {
            assert!(
                parse_evidence_line(&exact_line[..length], 1, TEST_EVIDENCE_NONCE).is_err(),
                "admitted DWEVID1 truncation at {length} bytes"
            );
        }
        for delimiter in [7, 10, 27, 36, 39, 48, 57, 66, 75] {
            let mut malformed = exact_line.clone();
            malformed[delimiter] = b':';
            assert!(
                parse_evidence_line(&malformed, 1, TEST_EVIDENCE_NONCE).is_err(),
                "admitted malformed delimiter at byte {delimiter}"
            );
        }
        for &position in [26_usize, 38, 55, 56, 58, 82, 83].iter() {
            if exact_line[position].is_ascii_uppercase() {
                let mut lowercase = exact_line.clone();
                lowercase[position].make_ascii_lowercase();
                assert!(
                    parse_evidence_line(&lowercase, 1, TEST_EVIDENCE_NONCE).is_err(),
                    "admitted lowercase hexadecimal at byte {position}"
                );
            }
        }
        let mut cases = Vec::new();
        cases.push((
            "truncation",
            mutate_evidence_line(&valid, 0, |line| {
                line.pop();
            }),
        ));
        cases.push((
            "lowercase hex",
            mutate_evidence_line(&valid, 0, |line| line[26] = b'f'),
        ));
        cases.push((
            "delimiter",
            mutate_evidence_line(&valid, 0, |line| line[27] = b':'),
        ));
        cases.push((
            "checksum",
            mutate_evidence_line(&valid, 0, |line| line[83] ^= 1),
        ));
        cases.push((
            "nonce",
            evidence_transcript(&valid_evidence_specs(), TEST_EVIDENCE_NONCE + 1),
        ));
        cases.push((
            "sequence",
            mutate_evidence_line(&valid, 0, |line| {
                line[35] = b'1';
                let checksum = fnv1a32(&line[..76]);
                line[76..84].copy_from_slice(format!("{checksum:08X}").as_bytes());
            }),
        ));
        cases.push((
            "version",
            mutate_evidence_line(&valid, 0, |line| {
                line[8..10].copy_from_slice(b"02");
                let checksum = fnv1a32(&line[..76]);
                line[76..84].copy_from_slice(format!("{checksum:08X}").as_bytes());
            }),
        ));
        cases.push((
            "protocol case",
            mutate_evidence_line(&valid, 0, |line| line[0] = b'd'),
        ));
        let mut lowercase_extra = evidence_line(TEST_EVIDENCE_NONCE, 0, valid_evidence_specs()[0]);
        lowercase_extra[0] = b'd';
        lowercase_extra.extend_from_slice(&valid);
        cases.push(("lowercase protocol before valid evidence", lowercase_extra));
        let mut lowercase_terminal = terminal("01", 23, 0);
        lowercase_terminal[..7].make_ascii_lowercase();
        lowercase_terminal.extend_from_slice(&valid);
        cases.push((
            "lowercase terminal before valid transcript",
            lowercase_terminal,
        ));
        let mut terminal_magic_diagnostic = b"DWTEST1 diagnostic decoy\n".to_vec();
        terminal_magic_diagnostic.extend_from_slice(&valid);
        cases.push(("terminal magic diagnostic decoy", terminal_magic_diagnostic));
        let mut evidence_magic_diagnostic = b"dwevid1 diagnostic decoy\n".to_vec();
        evidence_magic_diagnostic.extend_from_slice(&valid);
        cases.push(("evidence magic diagnostic decoy", evidence_magic_diagnostic));
        cases.push((
            "unknown kind",
            mutate_evidence_line(&valid, 0, |line| {
                line[37..39].copy_from_slice(b"0E");
                let checksum = fnv1a32(&line[..76]);
                line[76..84].copy_from_slice(format!("{checksum:08X}").as_bytes());
            }),
        ));
        let mut duplicate_terminal = valid.clone();
        duplicate_terminal.extend_from_slice(&terminal("01", 23, 0));
        cases.push(("duplicate terminal", duplicate_terminal));
        let mut evidence_after_terminal =
            evidence_transcript(&valid_evidence_specs(), TEST_EVIDENCE_NONCE);
        evidence_after_terminal.extend_from_slice(&evidence_line(
            TEST_EVIDENCE_NONCE,
            23,
            valid_evidence_specs()[0],
        ));
        cases.push(("evidence after terminal", evidence_after_terminal));
        let too_many = vec![valid_evidence_specs()[0]; MAX_EVIDENCE_RECORDS + 1];
        cases.push((
            "record limit",
            evidence_transcript(&too_many, TEST_EVIDENCE_NONCE),
        ));

        for (label, transcript) in cases {
            assert!(
                parse_transcript(&transcript, &request).is_err(),
                "admitted hostile {label} transcript"
            );
        }
    }

    #[test]
    fn i1_semantic_joins_order_cpus_and_masks_are_strict() {
        let request = i1_request();
        let mut cases = Vec::new();

        let mut duplicate_cpu = valid_evidence_specs();
        duplicate_cpu[3].cpu = 2;
        cases.push(("duplicate online CPU", duplicate_cpu));

        let mut duplicate_apic = valid_evidence_specs();
        duplicate_apic[3].arg0 = duplicate_apic[2].arg0;
        cases.push(("duplicate APIC", duplicate_apic));

        let mut invalid_cpu = valid_evidence_specs();
        invalid_cpu[5].cpu = 4;
        cases.push(("out-of-range CPU", invalid_cpu));

        let mut wrong_slot = valid_evidence_specs();
        wrong_slot[3].arg1 = 2;
        cases.push(("wrong online slot", wrong_slot));

        let mut one_cpl3_cpu = valid_evidence_specs();
        one_cpl3_cpu[5].cpu = 0;
        cases.push(("one CPL3 CPU", one_cpl3_cpu));

        let mut duplicate_cpl3_token = valid_evidence_specs();
        duplicate_cpl3_token[5].token = duplicate_cpl3_token[4].token;
        cases.push(("duplicate CPL3 token", duplicate_cpl3_token));

        let mut zero_cpl3_token = valid_evidence_specs();
        zero_cpl3_token[4].token = 0;
        cases.push(("zero CPL3 token", zero_cpl3_token));

        let mut activity_before_online = valid_evidence_specs();
        activity_before_online.swap(3, 4);
        cases.push(("activity before CPU online", activity_before_online));

        let mut blocked_after_descendant = valid_evidence_specs();
        blocked_after_descendant.swap(6, 7);
        cases.push(("parent order", blocked_after_descendant));

        let mut zero_block_token = valid_evidence_specs();
        zero_block_token[6].token = 0;
        zero_block_token[7].token = 0;
        cases.push(("zero parent token", zero_block_token));

        let mut invariant_violation = valid_evidence_specs();
        invariant_violation[22].arg0 = 1;
        cases.push(("running violation", invariant_violation));

        let mut invariant_cpu = valid_evidence_specs();
        invariant_cpu[22].cpu = 1;
        cases.push(("running invariant CPU", invariant_cpu));

        let mut invariant_before_activity = valid_evidence_specs();
        invariant_before_activity.swap(21, 22);
        cases.push((
            "running invariant before reclaim",
            invariant_before_activity,
        ));

        let mut wake_target = valid_evidence_specs();
        wake_target[8].arg0 = 2;
        cases.push(("wake target", wake_target));

        let mut wake_token = valid_evidence_specs();
        wake_token[9].token = 0x201;
        cases.push(("wake token", wake_token));

        let mut same_cleanup_cpu = valid_evidence_specs();
        same_cleanup_cpu[11].cpu = 2;
        cases.push(("cleanup CPU", same_cleanup_cpu));

        let mut cleanup_token = valid_evidence_specs();
        cleanup_token[11].token = 0x301;
        cases.push(("cleanup token", cleanup_token));

        let mut missing_cleanup_proof = valid_evidence_specs();
        missing_cleanup_proof.remove(11);
        cases.push(("missing cleanup proof", missing_cleanup_proof));

        let mut zero_publish_mask = valid_evidence_specs();
        zero_publish_mask[12].arg0 = 0;
        cases.push(("zero publish mask", zero_publish_mask));

        let mut wide_publish_mask = valid_evidence_specs();
        wide_publish_mask[12].arg0 = 0x1F;
        cases.push(("wide publish mask", wide_publish_mask));

        let mut coherent_partial_mask = valid_evidence_specs();
        coherent_partial_mask.retain(|event| !matches!(event.kind, 0x0B | 0x0C) || event.cpu != 3);
        for event in &mut coherent_partial_mask {
            if matches!(event.kind, 0x0A..=0x0C) {
                event.arg0 = 0x07;
            }
            if event.kind == 0x0D {
                event.arg0 = 0x07;
                event.arg1 = 0x07;
            }
        }
        cases.push(("coherent partial CPU mask", coherent_partial_mask));

        let mut missing_tlb_ack = valid_evidence_specs();
        missing_tlb_ack.remove(16);
        cases.push(("missing TLB ack", missing_tlb_ack));

        let mut duplicate_rendezvous_cpu = valid_evidence_specs();
        duplicate_rendezvous_cpu[20].cpu = 2;
        cases.push(("duplicate rendezvous CPU", duplicate_rendezvous_cpu));

        let mut wrong_ack_token = valid_evidence_specs();
        wrong_ack_token[15].token = 0x401;
        cases.push(("wrong ack token", wrong_ack_token));

        let mut wrong_ack_mask = valid_evidence_specs();
        wrong_ack_mask[19].arg0 = 0x07;
        cases.push(("wrong ack mask", wrong_ack_mask));

        let mut early_reclaim = valid_evidence_specs();
        let reclaim = early_reclaim.remove(21);
        early_reclaim.insert(15, reclaim);
        cases.push(("early reclaim", early_reclaim));

        let mut wrong_reclaim_mask = valid_evidence_specs();
        wrong_reclaim_mask[21].arg1 = 0x07;
        cases.push(("wrong reclaim mask", wrong_reclaim_mask));

        let mut duplicate_event = valid_evidence_specs();
        duplicate_event.insert(5, duplicate_event[4]);
        cases.push(("duplicate event", duplicate_event));

        for (label, specs) in cases {
            let transcript = evidence_transcript(&specs, TEST_EVIDENCE_NONCE);
            assert!(
                parse_transcript(&transcript, &request).is_err(),
                "admitted hostile {label} semantics"
            );
        }
    }

    #[test]
    fn i1_requires_evidence_before_one_unchanged_terminal() {
        let request = i1_request();
        assert!(parse_transcript(&terminal("01", 23, 0), &request).is_err());
        let transcript = evidence_transcript(&valid_evidence_specs(), TEST_EVIDENCE_NONCE);
        assert!(parse_transcript(&transcript, &request).is_ok());
        assert!(
            parse_transcript(
                &transcript,
                &HRequest {
                    evidence: None,
                    schema_version: 2,
                    ..request
                }
            )
            .is_ok()
        );
        let mut schema_two_compatibility = b"dwtest1 diagnostic decoy\n".to_vec();
        schema_two_compatibility.extend_from_slice(b"dwevid1 diagnostic decoy\n");
        schema_two_compatibility.extend_from_slice(&terminal("01", 18, 0));
        assert!(
            parse_transcript(
                &schema_two_compatibility,
                &HRequest {
                    schema_version: 2,
                    selector: "primordial-bootstrap".into(),
                    test_id: 18,
                    evidence: None,
                    ..i1_request()
                }
            )
            .is_ok()
        );
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

        let i1 = i1_request();
        assert!(guest_expectation_matches(
            &i1,
            GuestRecord {
                outcome: GuestOutcome::Pass,
                test_id: 23,
                detail: 0,
                line: 1,
            }
        ));
        for outcome in [GuestOutcome::Fail, GuestOutcome::Panic] {
            let invalid_request = HRequest {
                expected_outcome: match outcome {
                    GuestOutcome::Fail => ExpectedOutcome::Fail,
                    GuestOutcome::Panic => ExpectedOutcome::Panic,
                    GuestOutcome::Pass => unreachable!(),
                },
                ..i1.clone()
            };
            assert!(!guest_expectation_matches(
                &invalid_request,
                GuestRecord {
                    outcome,
                    test_id: 23,
                    detail: 0,
                    line: 1,
                }
            ));
        }
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
            root: test_root(&root),
            request_bytes: Arc::new(b"request".to_vec()),
            schema_version: 2,
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
            evidence: None,
            stress: None,
        };
        let artifacts = CandidateArtifacts {
            loader: test_artifact(&request.loader),
            kernel: test_artifact(&request.kernel),
            symbols: test_artifact(&request.symbols),
            bootstrap: test_artifact(&request.bootstrap),
            init0: test_artifact(&request.init0),
            hello: test_artifact(&request.hello),
            ovmf_code: test_artifact(&request.ovmf_code),
            ovmf_vars_template: test_artifact(&request.ovmf_vars_template),
        };
        let run = RunPaths {
            vars: request.run_directory.join("smp/OVMF_VARS.fd"),
            serial_log: request.run_directory.join("smp/serial.log"),
            result_json: request.run_directory.join("smp/result.json"),
            stderr_log: request.run_directory.join("smp/qemu.stderr.log"),
            qemu_ovmf_code: request.ovmf_code.display().to_string(),
            qemu_vars: request
                .run_directory
                .join("smp/OVMF_VARS.fd")
                .display()
                .to_string(),
            qemu_esp: request.esp.display().to_string(),
            qemu_serial: request
                .run_directory
                .join("smp/serial.log")
                .display()
                .to_string(),
            gdb_symbols: request.symbols.display().to_string(),
            _inherited_files: Vec::new(),
        };
        let args = qemu_arguments(
            HProfile::Smp,
            &request,
            &artifacts,
            ExecutionKind::Integration,
            &run,
            None,
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
            gdb_arguments(&run)
                .join(" ")
                .contains("file /candidate/deepwyrm.symbols")
        );

        let stress = StressRun {
            index: 7,
            base_seed: TEST_EVIDENCE_NONCE,
            seed: splitmix64_seed(TEST_EVIDENCE_NONCE, 7),
            operations: 4096,
        };
        let stress_args = qemu_arguments(
            HProfile::Smp,
            &i2_request(),
            &artifacts,
            ExecutionKind::Integration,
            &run,
            Some(stress),
        )
        .join(" ");
        let seed_argument = format!(
            "name=opt/org.deepwyrm.test.stress.seed,string={:016X}",
            stress.seed
        );
        for expected in [
            "name=opt/org.deepwyrm.test.stress.run-index,string=7",
            "name=opt/org.deepwyrm.test.stress.base-seed,string=0123456789ABCDEF",
            seed_argument.as_str(),
            "name=opt/org.deepwyrm.test.stress.operations,string=4096",
        ] {
            assert!(stress_args.contains(expected));
        }
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
            root: test_root(&root),
            request_bytes: Arc::new(b"request".to_vec()),
            schema_version: 2,
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
            evidence: None,
            stress: None,
        };
        let run = RunPaths {
            vars: root.join("OVMF_VARS.fd"),
            serial_log: root.join("serial.log"),
            result_json: root.join("result.json"),
            stderr_log: root.join("stderr.log"),
            qemu_ovmf_code: String::new(),
            qemu_vars: String::new(),
            qemu_esp: String::new(),
            qemu_serial: String::new(),
            gdb_symbols: String::new(),
            _inherited_files: Vec::new(),
        };
        fs::write(&request.path, b"request").expect("write request");
        let artifacts = CandidateArtifacts {
            loader: test_artifact(&request.loader),
            kernel: test_artifact(&request.kernel),
            symbols: test_artifact(&request.symbols),
            bootstrap: test_artifact(&request.bootstrap),
            init0: test_artifact(&request.init0),
            hello: test_artifact(&request.hello),
            ovmf_code: test_artifact(&request.ovmf_code),
            ovmf_vars_template: test_artifact(&request.ovmf_vars_template),
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
                qemu_ovmf_code: String::new(),
                qemu_vars: String::new(),
                qemu_esp: String::new(),
                qemu_serial: String::new(),
                gdb_symbols: String::new(),
                _inherited_files: Vec::new(),
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

        let i1_failure_run = RunPaths {
            vars: root.join("unused-i1-vars.fd"),
            serial_log: root.join("unused-i1-serial.log"),
            result_json: root.join("i1-error-result.json"),
            stderr_log: root.join("unused-i1-stderr.log"),
            qemu_ovmf_code: String::new(),
            qemu_vars: String::new(),
            qemu_esp: String::new(),
            qemu_serial: String::new(),
            gdb_symbols: String::new(),
            _inherited_files: Vec::new(),
        };
        let i1_request = HRequest {
            schema_version: 3,
            selector: "smp-runtime-acceptance".into(),
            test_id: 23,
            evidence: Some(EvidenceRequest {
                nonce: TEST_EVIDENCE_NONCE,
                required_mask: h_request::I1_REQUIRED_EVIDENCE_MASK,
            }),
            ..request.clone()
        };
        write_integration_host_failure(
            HProfile::Smp,
            &i1_request,
            &artifacts,
            &i1_failure_run,
            HostFailure {
                status: None,
                reason: "transcript_invalid",
                timeout_seconds: None,
                cleanup: CleanupDisposition::exited(),
            },
        )
        .expect("write I1 host failure result");
        let i1_result =
            fs::read_to_string(&i1_failure_run.result_json).expect("read I1 failure result");
        assert!(i1_result.contains("\"schema_version\":3"));
        assert!(i1_result.contains("\"reason\":\"transcript_invalid\""));
        assert!(!i1_result.contains("evidence_protocol"));
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
            root: test_root(&root),
            request_bytes: Arc::new(b"request".to_vec()),
            schema_version: 2,
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
            evidence: None,
            stress: None,
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
            root: test_root(&root),
            request_bytes: Arc::new(b"artifact".to_vec()),
            schema_version: 2,
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
            evidence: None,
            stress: None,
        };
        let artifacts = CandidateArtifacts {
            loader: test_artifact(&request.loader),
            kernel: test_artifact(&request.kernel),
            symbols: test_artifact(&request.symbols),
            bootstrap: test_artifact(&request.bootstrap),
            init0: test_artifact(&request.init0),
            hello: test_artifact(&request.hello),
            ovmf_code: test_artifact(&request.ovmf_code),
            ovmf_vars_template: test_artifact(&request.ovmf_vars_template),
        };
        let first = candidate_digests(&request, &artifacts).expect("first digest");
        let second = candidate_digests(&request, &artifacts).expect("second digest");
        assert_eq!(first.candidate, second.candidate);
        fs::write(&request.hello, b"changed").expect("mutate hello");
        let still_admitted = candidate_digests(&request, &artifacts).expect("held digest");
        assert_eq!(first.candidate, still_admitted.candidate);
        let readmitted = verify_candidate_inputs(&request).expect("readmit changed candidate");
        let changed = candidate_digests(&request, &readmitted).expect("changed digest");
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
