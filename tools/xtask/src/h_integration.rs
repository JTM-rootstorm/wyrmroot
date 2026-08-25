//! WYR0-H exact-artifact image, q35/OVMF, GDB, and integration tooling.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use deepwyrm_abi::{DW_RIGHT_INSPECT, DW_RIGHT_MAP, DW_RIGHT_READ, DW_TERMINATION_AUTHORIZED};

use wyrmroot_bootfs::builder::{Builder, FileMode};

use crate::cli::{G3ImageArguments, HProfile};
use crate::error::Failure;
use crate::h_request::{
    self, CapabilityRequest, CheckedOutputRoot, EvidenceProtocol, EvidenceRequest, ExpectedOutcome,
    HRequest,
};
use crate::sha256;

const MAX_GUEST_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FIRMWARE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_WYR0_H_ESP_SNAPSHOT_BYTES: u64 = crate::g3_image::IMAGE_BYTES;
const MAX_SERIAL_BYTES: u64 = 16 * 1024 * 1024;
const COMPLETION_RECORD_BYTES: usize = 38;
const DWEVID1_RECORD_BYTES: usize = 85;
const WRCAP1_RECORD_BYTES: usize = 117;
const WYR0_I_CAPABILITY_EVENT_COUNT: u32 = 15;
const WYR0_I_MEMORY_RIGHTS: u64 = DW_RIGHT_READ.0 | DW_RIGHT_MAP.0 | DW_RIGHT_INSPECT.0;
const WYR0_I_AUTHORIZED_TERMINATION: u64 = DW_TERMINATION_AUTHORIZED.0 as u64;
const WYR0_I_CHANNEL_BACKPRESSURE_ATTEMPT_LIMIT: u64 = 32;
const MAX_EVIDENCE_RECORDS: usize = 64;
const MAX_SELECTOR_CONTENT_BYTES: u64 = 64 * 1024;
const WYR0_I_CONFIG_BOOTFS_PATH: &[u8] = b"test/wyr0-i/config.toml";
const WYR0_I_ASSET_BOOTFS_PATH: &[u8] = b"test/wyr0-i/asset.bin";
const WYR0_I_CANONICAL_ASSET: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../userspace/i-capability/assets/asset.bin"
));
const WYR0_I_RUST_TARGET: &str = "x86_64-unknown-wyrmroot";
const I2_SELECTOR: &str = "smp-runtime-stress";
const INIT0_PROFILE_ORDINARY: &[u8] = b"WYRMINIT0-PROFILE-V1:ordinary";
const INIT0_PROFILE_I2: &[u8] = b"WYRMINIT0-PROFILE-V1:i2-stress";
const INIT0_PROFILE_CAPABILITY: &[u8] = b"WYRMINIT0-PROFILE-V1:i-capability";
const WYR0_I_INHERITED_I0_I1_I2: &str = "Plans/WYR0_H_VALIDATION.md";
const WYR0_I_INHERITED_D0: &str = "../deepwyrm/security/DW0_H_SECURITY_REVIEW.md";
const BUILD_RECEIPT_FILE: &str = h_request::BUILD_RECEIPT_FILE;
const BUILD_RECEIPT_KIND: &str = "wyrmroot-wyr0-h-build-lineage";
const BUILD_RECEIPT_TOOLCHAIN_REQUEST: &str = "RUST-WYR0-I-B-SYSROOTS-007";
const BUILD_RECEIPT_LOADER_RECIPE: &str = "wyrmroot-xtask-build-loader-v1";
const BUILD_RECEIPT_KERNEL_RECIPE: &str = "deepwyrm-cargo-release-selector-v1";
const BUILD_RECEIPT_NATIVE_RECIPE: &str = "wyrmroot-cargo-release-selector-v1";
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
const O_NOFOLLOW: i32 = 0o400000;
const F_GETFD: i32 = 1;
const F_SETFD: i32 = 2;
const FD_CLOEXEC: i32 = 1;

unsafe extern "C" {
    fn fcntl(file_descriptor: i32, command: i32, ...) -> i32;
}

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

#[derive(Clone, Debug, Eq, PartialEq)]
struct CandidateArtifacts {
    build_receipt: PathBuf,
    loader: PathBuf,
    kernel: PathBuf,
    symbols: PathBuf,
    bootstrap: PathBuf,
    init0: PathBuf,
    hello: PathBuf,
    selector_config: Option<PathBuf>,
    selector_asset: Option<PathBuf>,
    ovmf_code: PathBuf,
    ovmf_vars_template: PathBuf,
}

#[derive(Debug)]
struct StableRunFile {
    path: PathBuf,
    file: fs::File,
    digest: String,
    immutable: bool,
}

impl StableRunFile {
    fn child_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }

    fn set_inheritable(&self, inheritable: bool) -> Result<(), Failure> {
        let descriptor = self.file.as_raw_fd();
        if inheritable {
            let mut file = self.file.try_clone().map_err(|error| {
                Failure::task(format!("could not clone run-local descriptor: {error}"))
            })?;
            file.seek(SeekFrom::Start(0)).map_err(|error| {
                Failure::task(format!("could not rewind run-local descriptor: {error}"))
            })?;
        }
        // SAFETY: fcntl is called with a live descriptor owned by this object and the documented
        // F_GETFD/F_SETFD integer commands. No pointer argument or borrowed memory crosses FFI.
        let flags = unsafe { fcntl(descriptor, F_GETFD) };
        if flags < 0 {
            return Err(Failure::task(format!(
                "could not inspect run-local descriptor flags: {}",
                std::io::Error::last_os_error()
            )));
        }
        let updated = if inheritable {
            flags & !FD_CLOEXEC
        } else {
            flags | FD_CLOEXEC
        };
        // SAFETY: the live descriptor and integer flag value satisfy the F_SETFD contract.
        if unsafe { fcntl(descriptor, F_SETFD, updated) } < 0 {
            return Err(Failure::task(format!(
                "could not update run-local descriptor flags: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn verify_unchanged(&self, label: &str) -> Result<(), Failure> {
        if !self.immutable {
            return Ok(());
        }
        let mut file = self.file.try_clone().map_err(|error| {
            Failure::task(format!("could not clone run-local {label}: {error}"))
        })?;
        file.seek(SeekFrom::Start(0)).map_err(|error| {
            Failure::task(format!("could not rewind run-local {label}: {error}"))
        })?;
        let digest = sha256::reader_digest(&mut file)
            .map_err(|error| Failure::task(format!("could not hash run-local {label}: {error}")))?;
        if digest != self.digest {
            return Err(Failure::task(format!(
                "run-local {label} changed after it was opened"
            )));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct CandidateDigests {
    request: String,
    build_receipt: String,
    loader: String,
    kernel: String,
    symbols: String,
    bootstrap: String,
    init0: String,
    hello: String,
    selector_config: Option<String>,
    selector_asset: Option<String>,
    bootfs: String,
    esp: String,
    ovmf_code: String,
    ovmf_vars_template: String,
    candidate: String,
}

#[derive(Debug)]
struct CertificateIdentity {
    deepwyrm_abi_tree: String,
    generated_schema_bound: bool,
    rust_target: String,
    rust_toolchain_name: String,
    llvm_build_version: String,
    rust_lld_sha256: String,
    llvm_sha256: String,
    versions_sha256: String,
    profiles_sha256: String,
    accepted_toolchain_request_sha256: String,
    accepted_toolchain_manifest_sha256: String,
    toolchain_tree_sha256: String,
    rustc_sha256: String,
    cargo_sha256: String,
}

const BUILD_RECEIPT_KEYS: &[&str] = &[
    "schema_version",
    "report_kind",
    "status",
    "source_checkout_clean_before",
    "source_checkout_clean_after",
    "deepwyrm_revision",
    "deepwyrm_tree",
    "wyrmroot_revision",
    "wyrmroot_tree",
    "rust_revision",
    "rust_tree",
    "accepted_toolchain_request",
    "accepted_toolchain_request_sha256",
    "accepted_toolchain_manifest_sha256",
    "toolchain_tree_sha256",
    "rustc_sha256",
    "cargo_sha256",
    "rust_lld_sha256",
    "llvm_sha256",
    "llvm_build_version",
    "versions_sha256",
    "profiles_sha256",
    "loader.target",
    "loader.profile",
    "loader.recipe",
    "kernel.target",
    "kernel.profile",
    "kernel.recipe",
    "native.target",
    "native.profile",
    "native.recipe",
    "selector",
    "test_id",
    "outputs.loader_sha256",
    "outputs.kernel_sha256",
    "outputs.symbols_sha256",
    "outputs.bootstrap_sha256",
    "outputs.init0_sha256",
    "outputs.hello_sha256",
    "outputs.ovmf_code_sha256",
    "outputs.ovmf_vars_template_sha256",
];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum CapabilityEvidenceKind {
    ContentDelivery,
    ProcessLifecycle,
    MemoryShare,
    ChannelLifecycle,
    WaitEventTimer,
    Cancellation,
    RestartReplacement,
    RestartExhausted,
    OverloadReplayRejected,
    CleanupBaseline,
}

impl CapabilityEvidenceKind {
    fn parse(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::ContentDelivery),
            0x02 => Some(Self::ProcessLifecycle),
            0x03 => Some(Self::MemoryShare),
            0x04 => Some(Self::ChannelLifecycle),
            0x05 => Some(Self::WaitEventTimer),
            0x06 => Some(Self::Cancellation),
            0x07 => Some(Self::RestartReplacement),
            0x08 => Some(Self::RestartExhausted),
            0x09 => Some(Self::OverloadReplayRejected),
            0x0A => Some(Self::CleanupBaseline),
            _ => None,
        }
    }

    const fn value(self) -> u8 {
        match self {
            Self::ContentDelivery => 0x01,
            Self::ProcessLifecycle => 0x02,
            Self::MemoryShare => 0x03,
            Self::ChannelLifecycle => 0x04,
            Self::WaitEventTimer => 0x05,
            Self::Cancellation => 0x06,
            Self::RestartReplacement => 0x07,
            Self::RestartExhausted => 0x08,
            Self::OverloadReplayRejected => 0x09,
            Self::CleanupBaseline => 0x0A,
        }
    }

    const fn bit(self) -> u32 {
        1_u32 << (self.value() - 1)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CapabilityEvidenceEvent {
    sequence: u32,
    kind: CapabilityEvidenceKind,
    peer: u32,
    generation: u32,
    token: u64,
    arg0: u64,
    arg1: u64,
    line: usize,
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
    let outputs = CheckedOutputRoot::open(&request)?;
    verify_source_revisions(&request)?;
    let artifacts = verify_candidate_inputs(&request)?;
    require_absent(&outputs, &request.bootfs, "bootfs output")?;
    require_absent(&outputs, &request.esp, "ESP output")?;
    require_absent(&outputs, &request.provenance, "provenance output")?;
    require_capability_outputs_absent(&outputs, &request)?;

    let bootfs = build_bootfs_bytes(&artifacts)?;
    write_new(&outputs, &request.bootfs, &bootfs, "bootfs")?;
    let esp_target = outputs.target(&request.esp, "ESP output")?;
    let mut image_arguments = image_arguments(&request, &artifacts);
    image_arguments.image = esp_target.path().display().to_string();
    let result = (|| {
        crate::g3_image::build_in_root(&image_arguments, Some(&outputs.directory_path()))?;
        write_provenance(&outputs, &request, &artifacts)?;
        inspect_loaded(&request, &artifacts)
    })();
    match result {
        Ok(result) => Ok(result),
        Err(error) => Err(with_rollback(
            error,
            rollback_created(
                &outputs,
                &[
                    (&request.provenance, "provenance"),
                    (&request.esp, "ESP"),
                    (&request.bootfs, "bootfs"),
                ],
            ),
        )),
    }
}

pub(crate) fn inspect(request_path: &str) -> Result<String, Failure> {
    let request = h_request::load(Path::new(request_path))?;
    verify_source_revisions(&request)?;
    let artifacts = verify_candidate_inputs(&request)?;
    inspect_loaded(&request, &artifacts)
}

pub(crate) fn run(profile: HProfile, request_path: &str) -> Result<String, Failure> {
    let request = h_request::load(Path::new(request_path))?;
    let outputs = CheckedOutputRoot::open(&request)?;
    validate_execution_profile(&request, Some(profile))?;
    verify_source_revisions(&request)?;
    let artifacts = verify_candidate_inputs(&request)?;
    inspect_loaded(&request, &artifacts)?;
    execute(profile, &request, &artifacts, &outputs, ExecutionKind::Run)
}

pub(crate) fn gdb(profile: HProfile, request_path: &str) -> Result<String, Failure> {
    let request = h_request::load(Path::new(request_path))?;
    let outputs = CheckedOutputRoot::open(&request)?;
    validate_execution_profile(&request, Some(profile))?;
    verify_source_revisions(&request)?;
    let artifacts = verify_candidate_inputs(&request)?;
    inspect_loaded(&request, &artifacts)?;
    execute(profile, &request, &artifacts, &outputs, ExecutionKind::Gdb)
}

pub(crate) fn integration(
    profile: Option<HProfile>,
    request_path: &str,
) -> Result<String, Failure> {
    let request = h_request::load(Path::new(request_path))?;
    let outputs = CheckedOutputRoot::open(&request)?;
    validate_execution_profile(&request, profile)?;
    verify_source_revisions(&request)?;
    let artifacts = verify_candidate_inputs(&request)?;
    if outputs_all_absent(&outputs, &request)? {
        let bootfs = build_bootfs_bytes(&artifacts)?;
        write_new(&outputs, &request.bootfs, &bootfs, "bootfs")?;
        let esp_target = outputs.target(&request.esp, "ESP output")?;
        let mut image_arguments = image_arguments(&request, &artifacts);
        image_arguments.image = esp_target.path().display().to_string();
        let result = (|| {
            crate::g3_image::build_in_root(&image_arguments, Some(&outputs.directory_path()))?;
            write_provenance(&outputs, &request, &artifacts)
        })();
        if let Err(error) = result {
            return Err(with_rollback(
                error,
                rollback_created(
                    &outputs,
                    &[
                        (&request.provenance, "provenance"),
                        (&request.esp, "ESP"),
                        (&request.bootfs, "bootfs"),
                    ],
                ),
            ));
        }
    }
    let inspection = inspect_loaded(&request, &artifacts)?;
    match profile {
        Some(profile) => execute(
            profile,
            &request,
            &artifacts,
            &outputs,
            ExecutionKind::Integration,
        ),
        None => {
            require_capability_outputs_absent(&outputs, &request)?;
            let default = execute(
                HProfile::Default,
                &request,
                &artifacts,
                &outputs,
                ExecutionKind::Integration,
            );
            let smp = execute(
                HProfile::Smp,
                &request,
                &artifacts,
                &outputs,
                ExecutionKind::Integration,
            );
            join_profile_results(&inspection, default, smp, &request, &artifacts, &outputs)
        }
    }
}

fn validate_execution_profile(
    request: &HRequest,
    profile: Option<HProfile>,
) -> Result<(), Failure> {
    if request.schema_version == 3 && profile != Some(HProfile::Smp) {
        return Err(Failure::task(
            "WYR0-H schema_version = 3 execution requires an explicit smp profile",
        ));
    }
    Ok(())
}

fn join_profile_results(
    inspection: &str,
    default: Result<String, Failure>,
    smp: Result<String, Failure>,
    request: &HRequest,
    artifacts: &CandidateArtifacts,
    outputs: &CheckedOutputRoot,
) -> Result<String, Failure> {
    let (joined, default, smp) =
        join_profile_result_json(inspection, default, smp, request.schema_version)?;
    if request.schema_version == 4 {
        let candidate = result_candidate_digest(&default)?;
        write_capability_certificate(request, artifacts, outputs, &default, &smp, candidate)?;
    }
    Ok(joined)
}

fn join_profile_result_json(
    inspection: &str,
    default: Result<String, Failure>,
    smp: Result<String, Failure>,
    schema_version: u32,
) -> Result<(String, String, String), Failure> {
    match (default, smp) {
        (Ok(default), Ok(smp)) => {
            let default_candidate = result_candidate_digest(&default)?;
            let smp_candidate = result_candidate_digest(&smp)?;
            if default_candidate != smp_candidate {
                return Err(Failure::task(
                    "paired WYR0-H integration profiles consumed different run-local candidates",
                ));
            }
            let joined = format!(
                concat!(
                    "{{\"schema_version\":{},\"phase\":\"WYR0-H\",",
                    "\"status\":\"PASS\",\"same_media\":true,",
                    "\"inspection\":{},\"default\":{},\"smp\":{}}}\n"
                ),
                schema_version,
                inspection.trim(),
                default.trim(),
                smp.trim()
            );
            Ok((joined, default, smp))
        }
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

fn result_candidate_digest(result: &str) -> Result<&str, Failure> {
    let marker = "\"candidate_sha256\":\"";
    let start = result
        .find(marker)
        .map(|index| index + marker.len())
        .ok_or_else(|| Failure::task("WYR0-H profile result omitted its candidate digest"))?;
    let digest = result
        .get(start..start + 64)
        .filter(|digest| {
            digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| Failure::task("WYR0-H profile result has an invalid candidate digest"))?;
    if result.as_bytes().get(start + 64) != Some(&b'"') {
        return Err(Failure::task(
            "WYR0-H profile result has an invalid candidate digest",
        ));
    }
    Ok(digest)
}

fn require_capability_outputs_absent(
    outputs: &CheckedOutputRoot,
    request: &HRequest,
) -> Result<(), Failure> {
    if let Some(capability) = &request.capability {
        require_absent(
            outputs,
            &capability.certificate,
            "WYR0-I certificate output",
        )?;
        require_absent(
            outputs,
            &capability.capability_summary,
            "WYR0-I capability summary output",
        )?;
    }
    Ok(())
}

fn write_capability_certificate(
    request: &HRequest,
    artifacts: &CandidateArtifacts,
    outputs: &CheckedOutputRoot,
    default: &str,
    smp: &str,
    paired_candidate: &str,
) -> Result<(), Failure> {
    let capability = request.capability.as_ref().ok_or_else(|| {
        Failure::task("schema-4 paired integration has no certificate output contract")
    })?;
    let evidence = request.evidence.ok_or_else(|| {
        Failure::task("schema-4 paired integration has no WRCAP1 request contract")
    })?;
    if evidence.protocol != EvidenceProtocol::Wrcap1 {
        return Err(Failure::task(
            "schema-4 paired integration is not bound to WRCAP1",
        ));
    }
    let observed_mask = validated_certificate_observed_mask(evidence, default, smp)?;

    let source = verify_source_revisions(request)?;
    let current = verify_candidate_inputs(request)?;
    if &current != artifacts {
        return Err(Failure::task(
            "WYR0-I candidate paths changed before certificate publication",
        ));
    }
    inspect_loaded(request, artifacts)?;
    require_capability_outputs_absent(outputs, request)?;
    let digests = candidate_digests(request, artifacts)?;
    if digests.candidate != paired_candidate {
        return Err(Failure::task(
            "WYR0-I paired result does not match the revalidated certificate candidate",
        ));
    }

    let identity = certificate_identity(request)?;
    let provenance_sha256 = digest(&request.provenance, "WYR0-H provenance")?;
    let default_sha256 = sha256::bytes_digest(default.as_bytes());
    let smp_sha256 = sha256::bytes_digest(smp.as_bytes());
    let config_sha256 = digests
        .selector_config
        .as_ref()
        .ok_or_else(|| Failure::task("WYR0-I candidate has no selector config digest"))?;
    let asset_sha256 = digests
        .selector_asset
        .as_ref()
        .ok_or_else(|| Failure::task("WYR0-I candidate has no selector asset digest"))?;

    let certificate = format!(
        concat!(
            "{{\"schema_version\":2,",
            "\"certificate_kind\":\"wyr0-i-native-userspace-capability\",",
            "\"status\":\"PASS\",\"acceptance\":true,",
            "\"selector\":\"native-userspace-capability\",\"test_id\":24,",
            "\"source\":{{\"deepwyrm_revision\":\"{}\",\"deepwyrm_clean\":{},",
            "\"wyrmroot_revision\":\"{}\",\"wyrmroot_clean\":{},",
            "\"rust_revision\":\"{}\",\"rust_clean\":{}}},",
            "\"abi\":{{\"deepwyrm_abi_tree\":\"{}\",\"generated_schema_bound\":{}}},",
            "\"toolchain\":{{\"rust_target\":\"{}\",\"rust_toolchain_name\":\"{}\",",
            "\"llvm_build_version\":\"{}\",\"rustc_sha256\":\"{}\",",
            "\"cargo_sha256\":\"{}\",\"rust_lld_sha256\":\"{}\",",
            "\"llvm_sha256\":\"{}\",",
            "\"toolchain_tree_sha256\":\"{}\",\"artifact_manifest_sha256\":\"{}\",",
            "\"versions_sha256\":\"{}\",\"profiles_sha256\":\"{}\",",
            "\"accepted_toolchain_request_sha256\":\"{}\"}},",
            "\"artifacts\":{{\"candidate_sha256\":\"{}\",\"request_sha256\":\"{}\",",
            "\"build_receipt_sha256\":\"{}\",",
            "\"provenance_sha256\":\"{}\",\"loader_sha256\":\"{}\",",
            "\"kernel_sha256\":\"{}\",\"symbols_sha256\":\"{}\",",
            "\"bootstrap_sha256\":\"{}\",\"init0_sha256\":\"{}\",",
            "\"payload_sha256\":\"{}\",\"selector_config_sha256\":\"{}\",",
            "\"selector_asset_sha256\":\"{}\",\"bootfs_sha256\":\"{}\",",
            "\"esp_sha256\":\"{}\",\"ovmf_code_sha256\":\"{}\",",
            "\"ovmf_vars_template_sha256\":\"{}\"}},",
            "\"profiles\":{{\"same_immutable_media\":true,",
            "\"default\":{{\"vcpu\":1,\"memory_mib\":1024,\"result_sha256\":\"{}\"}},",
            "\"smp\":{{\"vcpu\":4,\"memory_mib\":2048,\"result_sha256\":\"{}\"}}}},",
            "\"containment\":{{\"machine\":\"q35\",\"firmware\":\"OVMF\",",
            "\"no_host_share\":true,\"no_network\":true}},",
            "\"evidence\":{{\"protocol\":\"wrcap1\",\"version\":1,",
            "\"nonce\":\"{:016X}\",\"required_mask\":{},\"observed_mask\":{},",
            "\"event_count_per_profile\":{},\"result\":\"PASS\"}},",
            "\"accounting_enforcement\":{{",
            "\"kernel\":[\"bounded Channel envelope and native object invariants\"],",
            "\"wyrmroot\":[\"controller-owned admission, reservation, replay, and cleanup classes\"],",
            "\"future\":[\"generic hostile-peer TaskGroup resource quotas\"],",
            "\"generic_kernel_quota_containment\":false}},",
            "\"inherited_evidence\":{{\"i0_i1_i2\":\"{}\",\"d0\":\"{}\"}},",
            "\"wyr0_gw_claimed\":false}}\n"
        ),
        source.deepwyrm.revision,
        source.deepwyrm.clean,
        source.wyrmroot.revision,
        source.wyrmroot.clean,
        source.rust.revision,
        source.rust.clean,
        identity.deepwyrm_abi_tree,
        identity.generated_schema_bound,
        identity.rust_target,
        identity.rust_toolchain_name,
        identity.llvm_build_version,
        identity.rustc_sha256,
        identity.cargo_sha256,
        identity.rust_lld_sha256,
        identity.llvm_sha256,
        identity.toolchain_tree_sha256,
        identity.accepted_toolchain_manifest_sha256,
        identity.versions_sha256,
        identity.profiles_sha256,
        identity.accepted_toolchain_request_sha256,
        digests.candidate,
        digests.request,
        digests.build_receipt,
        provenance_sha256,
        digests.loader,
        digests.kernel,
        digests.symbols,
        digests.bootstrap,
        digests.init0,
        digests.hello,
        config_sha256,
        asset_sha256,
        digests.bootfs,
        digests.esp,
        digests.ovmf_code,
        digests.ovmf_vars_template,
        default_sha256,
        smp_sha256,
        evidence.nonce,
        evidence.required_mask,
        observed_mask,
        WYR0_I_CAPABILITY_EVENT_COUNT,
        WYR0_I_INHERITED_I0_I1_I2,
        WYR0_I_INHERITED_D0,
    );
    let certificate_sha256 = sha256::bytes_digest(certificate.as_bytes());
    let summary = format!(
        concat!(
            "# WYR0-I Native Userspace Capability Summary\n\n",
            "Status: **PASS** for `native-userspace-capability` test 24 on the same immutable candidate under default and SMP profiles.\n\n",
            "- Candidate SHA-256: `{}`\n",
            "- Certificate SHA-256: `{}`\n",
            "- WRCAP1 nonce: `{:016X}`\n",
            "- Required/observed capability mask: `0x{:08X}` / `0x{:08X}` on both profiles\n",
            "- Selector content: `{}` and `{}`\n",
            "- Inherited evidence: `{}` and `{}`\n",
            "- Boundary: Wyrmroot controller admission is proven; generic hostile-peer TaskGroup quotas and WYR0-GW remain unclaimed.\n"
        ),
        digests.candidate,
        certificate_sha256,
        evidence.nonce,
        evidence.required_mask,
        observed_mask,
        String::from_utf8_lossy(WYR0_I_CONFIG_BOOTFS_PATH),
        String::from_utf8_lossy(WYR0_I_ASSET_BOOTFS_PATH),
        WYR0_I_INHERITED_I0_I1_I2,
        WYR0_I_INHERITED_D0,
    );

    write_capability_outputs(
        outputs,
        capability,
        certificate.as_bytes(),
        summary.as_bytes(),
    )
}

fn validated_certificate_observed_mask(
    evidence: EvidenceRequest,
    default: &str,
    smp: &str,
) -> Result<u32, Failure> {
    let mut validated_observed_mask = None;
    for (result, profile) in [(default, "default"), (smp, "smp")] {
        if !result.contains(&format!("\"profile\":\"{profile}\",\"status\":\"PASS\"")) {
            return Err(Failure::task(format!(
                "WYR0-I {profile} result is not a validated PASS profile"
            )));
        }
        let observed_mask = result_number_field(result, "observed_evidence_mask")?;
        if result_number_field(result, "required_evidence_mask")? != evidence.required_mask
            || observed_mask != evidence.required_mask
            || result_number_field(result, "evidence_event_count")? != WYR0_I_CAPABILITY_EVENT_COUNT
        {
            return Err(Failure::task(format!(
                "WYR0-I {profile} result does not contain the exact fully validated capability evidence"
            )));
        }
        if validated_observed_mask
            .replace(observed_mask)
            .is_some_and(|prior| prior != observed_mask)
        {
            return Err(Failure::task(
                "WYR0-I paired results have different parser-validated observed masks",
            ));
        }
    }
    validated_observed_mask
        .ok_or_else(|| Failure::task("WYR0-I paired results have no validated observed mask"))
}

fn write_capability_outputs(
    outputs: &CheckedOutputRoot,
    capability: &CapabilityRequest,
    certificate: &[u8],
    summary: &[u8],
) -> Result<(), Failure> {
    // The summary is intentionally staged before the authoritative certificate.
    // The certificate bytes themselves are first written and synced under a
    // non-authoritative staging name, then published with one hard-link operation.
    // A surviving final certificate is therefore always a complete publication marker.
    write_new(
        outputs,
        &capability.capability_summary,
        summary,
        "WYR0-I capability summary",
    )?;
    let staged_certificate = h_request::staged_certificate_path(&capability.certificate)?;
    let staged_file = match write_new_retained(
        outputs,
        &staged_certificate,
        certificate,
        "staged WYR0-I capability certificate",
    ) {
        Ok(file) => file,
        Err(error) => {
            return Err(with_rollback(
                error,
                rollback_created(
                    outputs,
                    &[(&capability.capability_summary, "WYR0-I capability summary")],
                ),
            ));
        }
    };
    if let Err(error) = publish_staged_certificate(
        outputs,
        &staged_certificate,
        &capability.certificate,
        &staged_file,
    ) {
        return Err(with_rollback(
            error,
            rollback_created(
                outputs,
                &[
                    (&staged_certificate, "staged WYR0-I capability certificate"),
                    (&capability.capability_summary, "WYR0-I capability summary"),
                ],
            ),
        ));
    }
    if let Err(error) =
        outputs.remove_file(&staged_certificate, "staged WYR0-I capability certificate")
    {
        return Err(with_rollback(
            Failure::task(format!(
                "certificate publication staging cleanup failed: {}",
                error.message
            )),
            rollback_created(
                outputs,
                &[
                    (&capability.certificate, "WYR0-I capability certificate"),
                    (&capability.capability_summary, "WYR0-I capability summary"),
                    (&staged_certificate, "staged WYR0-I capability certificate"),
                ],
            ),
        ));
    }
    Ok(())
}

fn publish_staged_certificate(
    outputs: &CheckedOutputRoot,
    staged: &Path,
    certificate: &Path,
    staged_file: &fs::File,
) -> Result<(), Failure> {
    require_absent(outputs, certificate, "WYR0-I capability certificate")?;
    let expected = staged_file.metadata().map_err(|error| {
        Failure::task(format!(
            "could not stat staged WYR0-I capability certificate: {error}"
        ))
    })?;
    let staged = outputs.target(staged, "staged WYR0-I capability certificate")?;
    let certificate_target = outputs.target(certificate, "WYR0-I capability certificate")?;
    fs::hard_link(staged.path(), certificate_target.path()).map_err(|error| {
        Failure::task(format!(
            "could not atomically publish WYR0-I capability certificate: {error}"
        ))
    })?;
    let published = match outputs.open_regular_file(
        certificate,
        "published WYR0-I capability certificate",
        true,
        false,
    ) {
        Ok(file) => file,
        Err(error) => {
            return Err(with_rollback(
                error,
                outputs.remove_file(certificate, "WYR0-I capability certificate"),
            ));
        }
    };
    let observed = match published.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            return Err(with_rollback(
                Failure::task(format!(
                    "could not stat published WYR0-I capability certificate: {error}"
                )),
                outputs.remove_file(certificate, "WYR0-I capability certificate"),
            ));
        }
    };
    if expected.dev() != observed.dev() || expected.ino() != observed.ino() {
        return Err(with_rollback(
            Failure::task("staged WYR0-I capability certificate changed before atomic publication"),
            outputs.remove_file(certificate, "WYR0-I capability certificate"),
        ));
    }
    Ok(())
}

/// Derives every certificate identity claim from the checked-in binding and the
/// accepted immutable toolchain record.  In particular, the host's currently
/// installed LLVM programs are not evidence about the toolchain that produced
/// a WYR0-I candidate.
fn certificate_identity(request: &HRequest) -> Result<CertificateIdentity, Failure> {
    let repository = crate::tasks::repository_root()?;
    let deepwyrm = source_workspace_root(&repository)?.join("deepwyrm");
    let manifest = crate::metadata::BuildManifest::load(&repository)?;
    // This validates the canonical Cargo.toml/Cargo.lock dependency, its real
    // consumers, and the no-private-ABI policy before we attest that the
    // candidate ABI is equivalent to that generated binding.
    manifest.validate_host_build_readiness(&repository)?;
    if manifest.rust_revision()? != request.rust_revision {
        return Err(Failure::task(
            "accepted Wyrmroot toolchain manifest does not bind the request Rust revision",
        ));
    }

    let consumer_revision = manifest.deepwyrm_revision()?;
    let consumer_spec = format!("{consumer_revision}:abi");
    let candidate_spec = format!("{}:abi", request.deepwyrm_revision);
    let consumer_abi_tree = git_output(&deepwyrm, &["rev-parse", &consumer_spec], "Deepwyrm")?;
    let candidate_abi_tree = git_output(&deepwyrm, &["rev-parse", &candidate_spec], "Deepwyrm")?;
    let consumer_abi_tree = required_git_object(
        consumer_abi_tree.trim(),
        "Wyrmroot's generated Deepwyrm ABI binding",
    )?;
    let candidate_abi_tree = required_git_object(
        candidate_abi_tree.trim(),
        "certificate candidate Deepwyrm ABI tree",
    )?;
    if consumer_abi_tree != candidate_abi_tree {
        return Err(Failure::task(
            "certificate candidate ABI tree differs from Wyrmroot's generated ABI binding",
        ));
    }

    let versions_path = repository.join("toolchain/versions.toml");
    let versions = identity_toml(&versions_path, "toolchain versions")?;
    let rust_target =
        required_identity_value(&versions, "rust.native_target", "toolchain versions")?;
    if rust_target != WYR0_I_RUST_TARGET {
        return Err(Failure::task(format!(
            "accepted toolchain native target is '{rust_target}', expected '{WYR0_I_RUST_TARGET}'"
        )));
    }

    let accepted_request_path =
        repository.join("toolchain/requests/RUST-WYR0-I-B-SYSROOTS-007.toml");
    let accepted = identity_toml(
        &accepted_request_path,
        "accepted toolchain identity request",
    )?;
    if required_identity_value(&accepted, "status", "accepted toolchain identity request")?
        != "accepted-immutable-artifact"
    {
        return Err(Failure::task(
            "WYR0-I toolchain identity record is not an accepted immutable artifact",
        ));
    }
    if required_identity_value(
        &accepted,
        "rust.accepted_commit",
        "accepted toolchain identity request",
    )? != request.rust_revision
    {
        return Err(Failure::task(
            "accepted toolchain identity record does not bind the request Rust revision",
        ));
    }
    let rust_toolchain_name = required_identity_value(
        &accepted,
        "rust.requested_toolchain_name",
        "accepted toolchain identity request",
    )?;
    if rust_toolchain_name != manifest.rust_toolchain_name()? {
        return Err(Failure::task(
            "accepted toolchain identity record does not match toolchain/versions.toml",
        ));
    }
    let llvm_build_version = required_identity_value(
        &accepted,
        "build.llvm_version",
        "accepted toolchain identity request",
    )?;
    let rust_lld_sha256 = required_sha256_identity_value(
        &accepted,
        "artifacts.rust_lld_sha256",
        "accepted toolchain identity request",
    )?;
    let llvm_sha256 = required_sha256_identity_value(
        &accepted,
        "artifacts.llvm_sha256",
        "accepted toolchain identity request",
    )?;
    let accepted_toolchain_manifest_sha256 = required_sha256_identity_value(
        &accepted,
        "build.artifact_manifest_sha256",
        "accepted toolchain identity request",
    )?;
    let toolchain_tree_sha256 = required_sha256_identity_value(
        &accepted,
        "build.toolchain_tree_sha256",
        "accepted toolchain identity request",
    )?;
    let rustc_sha256 = required_sha256_identity_value(
        &accepted,
        "artifacts.rustc_sha256",
        "accepted toolchain identity request",
    )?;
    let cargo_sha256 = required_sha256_identity_value(
        &accepted,
        "artifacts.cargo_sha256",
        "accepted toolchain identity request",
    )?;

    Ok(CertificateIdentity {
        deepwyrm_abi_tree: candidate_abi_tree,
        generated_schema_bound: true,
        rust_target,
        rust_toolchain_name,
        llvm_build_version,
        rust_lld_sha256,
        llvm_sha256,
        versions_sha256: digest(&versions_path, "toolchain versions")?,
        profiles_sha256: digest(
            &repository.join("toolchain/profiles.toml"),
            "toolchain profiles",
        )?,
        accepted_toolchain_request_sha256: digest(
            &accepted_request_path,
            "accepted toolchain identity request",
        )?,
        accepted_toolchain_manifest_sha256,
        toolchain_tree_sha256,
        rustc_sha256,
        cargo_sha256,
    })
}

fn required_git_object(value: &str, label: &str) -> Result<String, Failure> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Failure::task(format!(
            "{label} is not a full lowercase Git object ID"
        )));
    }
    Ok(value.to_owned())
}

/// A deliberately narrow reader for the immutable records used by the
/// certificate.  It accepts only single-line quoted scalar values and rejects
/// a duplicate scalar key, so an ambiguous record cannot supply identity.
fn identity_toml(path: &Path, label: &str) -> Result<BTreeMap<String, String>, Failure> {
    let contents = fs::read_to_string(path)
        .map_err(|error| Failure::task(format!("could not read {label}: {error}")))?;
    let mut values = BTreeMap::new();
    let mut section = String::new();
    for (line_number, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') && !line.starts_with("[[") {
            section = line[1..line.len() - 1].to_owned();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || value.len() < 2
            || !value.starts_with('"')
            || !value.ends_with('"')
        {
            continue;
        }
        let value = &value[1..value.len() - 1];
        if value.contains('"') || value.contains('\\') {
            return Err(Failure::task(format!(
                "{label} line {} has an unsupported escaped identity value",
                line_number + 1
            )));
        }
        let full_key = if section.is_empty() {
            key.to_owned()
        } else {
            format!("{section}.{key}")
        };
        if values.insert(full_key.clone(), value.to_owned()).is_some() {
            return Err(Failure::task(format!(
                "{label} has a duplicate scalar identity key '{full_key}'"
            )));
        }
    }
    Ok(values)
}

fn build_receipt_values(path: &Path) -> Result<BTreeMap<String, String>, Failure> {
    let contents = read_regular(path, "WYR0-H build-lineage receipt", 64 * 1024)?;
    let contents = std::str::from_utf8(&contents)
        .map_err(|_| Failure::task("WYR0-H build-lineage receipt is not UTF-8"))?;
    let mut values = BTreeMap::new();
    let mut section = String::new();
    for (line_number, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') && !line.starts_with("[[") {
            let name = &line[1..line.len() - 1];
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                return Err(Failure::task(format!(
                    "WYR0-H build-lineage receipt line {} has an invalid section",
                    line_number + 1
                )));
            }
            section = name.to_owned();
            continue;
        }
        let (key, raw_value) = line.split_once('=').ok_or_else(|| {
            Failure::task(format!(
                "WYR0-H build-lineage receipt line {} is not one scalar assignment",
                line_number + 1
            ))
        })?;
        let key = key.trim();
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(Failure::task(format!(
                "WYR0-H build-lineage receipt line {} has an invalid key",
                line_number + 1
            )));
        }
        let raw_value = raw_value.trim();
        let value = if raw_value.starts_with('"') && raw_value.ends_with('"') {
            let value = &raw_value[1..raw_value.len() - 1];
            if value.contains(['"', '\\']) {
                return Err(Failure::task(format!(
                    "WYR0-H build-lineage receipt line {} uses an unsupported escaped value",
                    line_number + 1
                )));
            }
            value
        } else if matches!(raw_value, "true" | "false")
            || (!raw_value.is_empty() && raw_value.bytes().all(|byte| byte.is_ascii_digit()))
        {
            raw_value
        } else {
            return Err(Failure::task(format!(
                "WYR0-H build-lineage receipt line {} has an unsupported value",
                line_number + 1
            )));
        };
        let full_key = if section.is_empty() {
            key.to_owned()
        } else {
            format!("{section}.{key}")
        };
        if values.insert(full_key.clone(), value.to_owned()).is_some() {
            return Err(Failure::task(format!(
                "WYR0-H build-lineage receipt duplicates '{full_key}'"
            )));
        }
    }
    Ok(values)
}

fn receipt_value<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, Failure> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| Failure::task(format!("WYR0-H build-lineage receipt omitted '{key}'")))
}

fn expect_receipt_value(
    values: &BTreeMap<String, String>,
    key: &str,
    expected: &str,
) -> Result<(), Failure> {
    let actual = receipt_value(values, key)?;
    if actual == expected {
        Ok(())
    } else {
        Err(Failure::task(format!(
            "WYR0-H build-lineage receipt '{key}' is '{actual}', expected '{expected}'"
        )))
    }
}

fn build_receipt_path(request: &HRequest) -> Result<PathBuf, Failure> {
    request
        .path
        .parent()
        .map(|parent| parent.join(BUILD_RECEIPT_FILE))
        .ok_or_else(|| Failure::task("WYR0-H request has no build-lineage receipt parent"))
}

fn git_tree(repository: &Path, revision: &str, label: &str) -> Result<String, Failure> {
    let specification = format!("{revision}^{{tree}}");
    required_git_object(
        git_output(repository, &["rev-parse", &specification], label)?.trim(),
        label,
    )
}

fn verify_build_receipt(request: &HRequest, artifacts: &CandidateArtifacts) -> Result<(), Failure> {
    let values = build_receipt_values(&artifacts.build_receipt)?;
    let mut expected_keys = BUILD_RECEIPT_KEYS.iter().copied().collect::<BTreeSet<_>>();
    if request.capability.is_some() {
        expected_keys.extend([
            "outputs.selector_config_sha256",
            "outputs.selector_asset_sha256",
        ]);
    }
    let actual_keys = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual_keys != expected_keys {
        let missing = expected_keys
            .difference(&actual_keys)
            .copied()
            .collect::<Vec<_>>();
        let unknown = actual_keys
            .difference(&expected_keys)
            .copied()
            .collect::<Vec<_>>();
        return Err(Failure::task(format!(
            "WYR0-H build-lineage receipt key set drifted (missing: {}; unknown: {})",
            missing.join(", "),
            unknown.join(", ")
        )));
    }

    for (key, expected) in [
        ("schema_version", "1"),
        ("report_kind", BUILD_RECEIPT_KIND),
        ("status", "PASS"),
        ("source_checkout_clean_before", "true"),
        ("source_checkout_clean_after", "true"),
        ("deepwyrm_revision", request.deepwyrm_revision.as_str()),
        ("wyrmroot_revision", request.wyrmroot_revision.as_str()),
        ("rust_revision", request.rust_revision.as_str()),
        (
            "accepted_toolchain_request",
            BUILD_RECEIPT_TOOLCHAIN_REQUEST,
        ),
        ("loader.target", "x86_64-unknown-uefi"),
        ("loader.profile", "production"),
        ("loader.recipe", BUILD_RECEIPT_LOADER_RECIPE),
        ("kernel.target", "x86_64-unknown-none"),
        ("kernel.profile", "release"),
        ("kernel.recipe", BUILD_RECEIPT_KERNEL_RECIPE),
        ("native.target", WYR0_I_RUST_TARGET),
        ("native.profile", "release"),
        ("native.recipe", BUILD_RECEIPT_NATIVE_RECIPE),
        ("selector", request.selector.as_str()),
    ] {
        expect_receipt_value(&values, key, expected)?;
    }
    expect_receipt_value(&values, "test_id", &request.test_id.to_string())?;

    let repository = crate::tasks::repository_root()?;
    let workspace = source_workspace_root(&repository)?;
    for (key, tree) in [
        (
            "deepwyrm_tree",
            git_tree(
                &workspace.join("deepwyrm"),
                &request.deepwyrm_revision,
                "Deepwyrm tree",
            )?,
        ),
        (
            "wyrmroot_tree",
            git_tree(&repository, &request.wyrmroot_revision, "Wyrmroot tree")?,
        ),
        (
            "rust_tree",
            git_tree(&workspace.join("rust"), &request.rust_revision, "Rust tree")?,
        ),
    ] {
        expect_receipt_value(&values, key, &tree)?;
    }

    let identity = certificate_identity(request)?;
    for (key, expected) in [
        (
            "accepted_toolchain_request_sha256",
            identity.accepted_toolchain_request_sha256.as_str(),
        ),
        (
            "accepted_toolchain_manifest_sha256",
            identity.accepted_toolchain_manifest_sha256.as_str(),
        ),
        (
            "toolchain_tree_sha256",
            identity.toolchain_tree_sha256.as_str(),
        ),
        ("rustc_sha256", identity.rustc_sha256.as_str()),
        ("cargo_sha256", identity.cargo_sha256.as_str()),
        ("rust_lld_sha256", identity.rust_lld_sha256.as_str()),
        ("llvm_sha256", identity.llvm_sha256.as_str()),
        ("llvm_build_version", identity.llvm_build_version.as_str()),
        ("versions_sha256", identity.versions_sha256.as_str()),
        ("profiles_sha256", identity.profiles_sha256.as_str()),
    ] {
        expect_receipt_value(&values, key, expected)?;
    }

    let mut outputs = vec![
        ("outputs.loader_sha256", &artifacts.loader, "loader.efi"),
        ("outputs.kernel_sha256", &artifacts.kernel, "deepwyrm.elf"),
        (
            "outputs.symbols_sha256",
            &artifacts.symbols,
            "Deepwyrm symbols",
        ),
        (
            "outputs.bootstrap_sha256",
            &artifacts.bootstrap,
            "bootstrap.elf",
        ),
        ("outputs.init0_sha256", &artifacts.init0, "init0"),
        ("outputs.hello_sha256", &artifacts.hello, "hello"),
        (
            "outputs.ovmf_code_sha256",
            &artifacts.ovmf_code,
            "OVMF code",
        ),
        (
            "outputs.ovmf_vars_template_sha256",
            &artifacts.ovmf_vars_template,
            "OVMF vars template",
        ),
    ];
    if let (Some(config), Some(asset)) = (&artifacts.selector_config, &artifacts.selector_asset) {
        outputs.extend([
            (
                "outputs.selector_config_sha256",
                config,
                "WYR0-I selector config",
            ),
            (
                "outputs.selector_asset_sha256",
                asset,
                "WYR0-I selector asset",
            ),
        ]);
    }
    for (key, path, label) in outputs {
        expect_receipt_value(&values, key, &digest(path, label)?)?;
    }
    Ok(())
}

fn required_identity_value(
    values: &BTreeMap<String, String>,
    key: &str,
    label: &str,
) -> Result<String, Failure> {
    values
        .get(key)
        .cloned()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Failure::task(format!("{label} omits required identity key '{key}'")))
}

fn required_sha256_identity_value(
    values: &BTreeMap<String, String>,
    key: &str,
    label: &str,
) -> Result<String, Failure> {
    let value = required_identity_value(values, key, label)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Failure::task(format!(
            "{label} key '{key}' is not a lowercase SHA-256 identity"
        )));
    }
    Ok(value)
}

fn result_number_field(result: &str, field: &str) -> Result<u32, Failure> {
    let marker = format!("\"{field}\":");
    let start = result
        .find(&marker)
        .map(|index| index + marker.len())
        .ok_or_else(|| Failure::task(format!("WYR0-I result omitted '{field}'")))?;
    let end = result[start..]
        .find(|character: char| !character.is_ascii_digit())
        .map(|length| start + length)
        .ok_or_else(|| Failure::task(format!("WYR0-I result has an invalid '{field}'")))?;
    if end == start {
        return Err(Failure::task(format!(
            "WYR0-I result has an invalid '{field}'"
        )));
    }
    result[start..end]
        .parse()
        .map_err(|_| Failure::task(format!("WYR0-I result has an invalid '{field}'")))
}

fn inspect_loaded(request: &HRequest, artifacts: &CandidateArtifacts) -> Result<String, Failure> {
    let expected_bootfs = build_bootfs_bytes(artifacts)?;
    let actual_bootfs = read_regular(&request.bootfs, "bootfs", MAX_GUEST_ARTIFACT_BYTES)?;
    if actual_bootfs != expected_bootfs {
        return Err(Failure::task(
            "WYR0-H bootfs does not contain the exact current selector-bound content",
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
        build_receipt: build_receipt_path(request)?,
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
        selector_config: request
            .capability
            .as_ref()
            .map(|capability| {
                h_request::canonical_regular(
                    &capability.selector_config,
                    "WYR0-I selector config",
                    MAX_SELECTOR_CONTENT_BYTES,
                )
            })
            .transpose()?,
        selector_asset: request
            .capability
            .as_ref()
            .map(|capability| {
                h_request::canonical_regular(
                    &capability.selector_asset,
                    "WYR0-I selector asset",
                    MAX_SELECTOR_CONTENT_BYTES,
                )
            })
            .transpose()?,
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
    if let (Some(config), Some(asset), Some(evidence)) = (
        artifacts.selector_config.as_ref(),
        artifacts.selector_asset.as_ref(),
        request.evidence,
    ) {
        validate_selector_config(config, asset, evidence.nonce)?;
    }
    if digest(&artifacts.kernel, "deepwyrm.elf")? != digest(&artifacts.symbols, "Deepwyrm symbols")?
    {
        return Err(Failure::task(
            "WYR0-H GDB symbols do not exactly match the booted kernel SHA-256",
        ));
    }
    validate_init0_profile(request, &artifacts.init0)?;
    verify_build_receipt(request, &artifacts)?;
    Ok(artifacts)
}

fn validate_init0_profile(request: &HRequest, init0: &Path) -> Result<(), Failure> {
    let bytes = read_regular(init0, "init0", MAX_GUEST_ARTIFACT_BYTES)?;
    validate_init0_profile_bytes(&request.selector, &bytes)
}

fn validate_init0_profile_bytes(selector: &str, bytes: &[u8]) -> Result<(), Failure> {
    let expected = if selector == h_request::I_CAPABILITY_SELECTOR {
        INIT0_PROFILE_CAPABILITY
    } else if selector == I2_SELECTOR {
        INIT0_PROFILE_I2
    } else {
        INIT0_PROFILE_ORDINARY
    };
    for marker in [
        INIT0_PROFILE_ORDINARY,
        INIT0_PROFILE_I2,
        INIT0_PROFILE_CAPABILITY,
    ] {
        let count = bytes
            .windows(marker.len())
            .filter(|window| *window == marker)
            .count();
        let required = usize::from(marker == expected);
        if count != required {
            return Err(Failure::task(format!(
                "WYR0-H selector '{selector}' requires exactly one '{}' init0 profile marker and no competing profile marker",
                String::from_utf8_lossy(expected)
            )));
        }
    }
    Ok(())
}

fn build_bootfs_bytes(artifacts: &CandidateArtifacts) -> Result<Vec<u8>, Failure> {
    let init0 = read_regular(&artifacts.init0, "init0", MAX_GUEST_ARTIFACT_BYTES)?;
    let hello = read_regular(&artifacts.hello, "hello", MAX_GUEST_ARTIFACT_BYTES)?;
    let selector_content = match (&artifacts.selector_config, &artifacts.selector_asset) {
        (Some(config), Some(asset)) => Some((
            read_regular(config, "WYR0-I selector config", MAX_SELECTOR_CONTENT_BYTES)?,
            read_regular(asset, "WYR0-I selector asset", MAX_SELECTOR_CONTENT_BYTES)?,
        )),
        (None, None) => None,
        _ => {
            return Err(Failure::task(
                "WYR0-H selector config/asset identity is incomplete",
            ));
        }
    };
    let mut builder = Builder::new();
    builder
        .add(b"system/init0", &init0, FileMode::Executable)
        .map_err(|error| Failure::task(format!("could not add init0 to bootfs: {error:?}")))?;
    builder
        .add(b"bin/hello", &hello, FileMode::Executable)
        .map_err(|error| Failure::task(format!("could not add hello to bootfs: {error:?}")))?;
    if let Some((config, asset)) = &selector_content {
        builder
            .add(WYR0_I_CONFIG_BOOTFS_PATH, config, FileMode::ReadOnly)
            .map_err(|error| {
                Failure::task(format!("could not add WYR0-I config to bootfs: {error:?}"))
            })?;
        builder
            .add(WYR0_I_ASSET_BOOTFS_PATH, asset, FileMode::ReadOnly)
            .map_err(|error| {
                Failure::task(format!("could not add WYR0-I asset to bootfs: {error:?}"))
            })?;
    }
    builder
        .build()
        .map_err(|error| Failure::task(format!("could not build WYR0-H bootfs: {error:?}")))
}

fn validate_selector_config(config: &Path, asset: &Path, nonce: u64) -> Result<(), Failure> {
    let config_bytes = read_regular(config, "WYR0-I selector config", MAX_SELECTOR_CONTENT_BYTES)?;
    let asset_bytes = read_regular(asset, "WYR0-I selector asset", MAX_SELECTOR_CONTENT_BYTES)?;
    if asset_bytes != WYR0_I_CANONICAL_ASSET {
        return Err(Failure::task(
            "WYR0-I selector asset is not the exact canonical immutable payload",
        ));
    }
    let asset_sha256 = sha256::bytes_digest(&asset_bytes);
    let expected = canonical_selector_config(nonce, &asset_sha256);
    if config_bytes != expected.as_bytes() {
        return Err(Failure::task(
            "WYR0-I selector config is not the exact canonical request/asset-bound serialization",
        ));
    }
    Ok(())
}

fn canonical_selector_config(nonce: u64, asset_sha256: &str) -> String {
    format!(
        concat!(
            "schema_version = 1\n",
            "selector = \"native-userspace-capability\"\n",
            "test_id = 24\n",
            "evidence_protocol = \"wrcap1\"\n",
            "evidence_nonce = \"{:016X}\"\n",
            "asset_sha256 = \"{}\"\n"
        ),
        nonce, asset_sha256,
    )
}

fn capability_content_prefixes(request: &HRequest) -> Result<(u64, u64), Failure> {
    let capability = request.capability.as_ref().ok_or_else(|| {
        Failure::task("WYR0-I evidence request has no selector config/asset binding")
    })?;
    let config = digest(&capability.selector_config, "WYR0-I selector config")?;
    let asset = digest(&capability.selector_asset, "WYR0-I selector asset")?;
    Ok((sha256_prefix_u64(&config)?, sha256_prefix_u64(&asset)?))
}

fn sha256_prefix_u64(digest: &str) -> Result<u64, Failure> {
    let prefix = digest
        .get(..16)
        .ok_or_else(|| Failure::task("SHA-256 identity is too short for an evidence prefix"))?;
    u64::from_str_radix(prefix, 16)
        .map_err(|_| Failure::task("SHA-256 identity has an invalid evidence prefix"))
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

fn write_provenance(
    outputs: &CheckedOutputRoot,
    request: &HRequest,
    artifacts: &CandidateArtifacts,
) -> Result<(), Failure> {
    let contents = provenance_contents(request, artifacts)?;
    write_new(
        outputs,
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
    let capability_fields = match (&digests.selector_config, &digests.selector_asset) {
        (Some(config), Some(asset)) => format!(
            concat!(
                "selector_config_bootfs_path = \"test/wyr0-i/config.toml\"\n",
                "selector_config_sha256 = \"{}\"\n",
                "selector_asset_bootfs_path = \"test/wyr0-i/asset.bin\"\n",
                "selector_asset_sha256 = \"{}\"\n"
            ),
            config, asset
        ),
        (None, None) => String::new(),
        _ => {
            return Err(Failure::task(
                "WYR0-H selector config/asset identity is incomplete",
            ));
        }
    };
    Ok(format!(
        concat!(
            "schema_version = 3\n",
            "phase = \"WYR0-H\"\n",
            "deepwyrm_revision = \"{}\"\n",
            "wyrmroot_revision = \"{}\"\n",
            "rust_revision = \"{}\"\n",
            "request_sha256 = \"{}\"\n",
            "build_receipt_sha256 = \"{}\"\n",
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
            "{}",
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
        digests.build_receipt,
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
        capability_fields,
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
    let request_digest = request.request_sha256.clone();
    let build_receipt = digest(&artifacts.build_receipt, "WYR0-H build-lineage receipt")?;
    let loader = digest(&artifacts.loader, "loader.efi")?;
    let kernel = digest(&artifacts.kernel, "deepwyrm.elf")?;
    let symbols = digest(&artifacts.symbols, "Deepwyrm symbols")?;
    let bootstrap = digest(&artifacts.bootstrap, "bootstrap.elf")?;
    let init0 = digest(&artifacts.init0, "init0")?;
    let hello = digest(&artifacts.hello, "hello")?;
    let selector_config = artifacts
        .selector_config
        .as_ref()
        .map(|path| digest(path, "WYR0-I selector config"))
        .transpose()?;
    let selector_asset = artifacts
        .selector_asset
        .as_ref()
        .map(|path| digest(path, "WYR0-I selector asset"))
        .transpose()?;
    let bootfs = digest(&request.bootfs, "bootfs")?;
    let esp = digest(&request.esp, "ESP")?;
    let ovmf_code = digest(&artifacts.ovmf_code, "OVMF code")?;
    let ovmf_vars_template = digest(&artifacts.ovmf_vars_template, "OVMF vars template")?;
    let candidate = candidate_identity_digest(
        request,
        &request_digest,
        &build_receipt,
        &loader,
        &kernel,
        &symbols,
        &bootstrap,
        &init0,
        &hello,
        selector_config.as_deref(),
        selector_asset.as_deref(),
        &bootfs,
        &esp,
        &ovmf_code,
        &ovmf_vars_template,
    );
    Ok(CandidateDigests {
        request: request_digest,
        build_receipt,
        loader,
        kernel,
        symbols,
        bootstrap,
        init0,
        hello,
        selector_config,
        selector_asset,
        bootfs,
        esp,
        ovmf_code,
        ovmf_vars_template,
        candidate,
    })
}

#[allow(clippy::too_many_arguments)]
fn candidate_identity_digest(
    request: &HRequest,
    request_digest: &str,
    build_receipt: &str,
    loader: &str,
    kernel: &str,
    symbols: &str,
    bootstrap: &str,
    init0: &str,
    hello: &str,
    selector_config: Option<&str>,
    selector_asset: Option<&str>,
    bootfs: &str,
    esp: &str,
    ovmf_code: &str,
    ovmf_vars_template: &str,
) -> String {
    let selector_content = match (selector_config, selector_asset) {
        (Some(config), Some(asset)) => {
            format!("selector_config={config}\nselector_asset={asset}\n")
        }
        (None, None) => String::new(),
        _ => "selector_content=incomplete\n".to_owned(),
    };
    sha256::bytes_digest(
        format!(
            concat!(
                "wyr0-h-candidate-v2\nrequest={}\nbuild_receipt={}\n",
                "deepwyrm={}\nwyrmroot={}\nrust={}\nselector={}\ntest_id={}\n",
                "expected_outcome={}\nexpected_detail={}\n",
                "loader={}\nkernel={}\nsymbols={}\n",
                "bootstrap={}\ninit0={}\nhello={}\n",
                "{}",
                "bootfs={}\nesp={}\novmf_code={}\n",
                "ovmf_vars_template={}\n"
            ),
            request_digest,
            build_receipt,
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
            selector_content,
            bootfs,
            esp,
            ovmf_code,
            ovmf_vars_template,
        )
        .as_bytes(),
    )
}

fn run_candidate_digests(
    request: &HRequest,
    artifacts: &CandidateArtifacts,
    run: &RunPaths,
) -> Result<CandidateDigests, Failure> {
    let mut digests = candidate_digests(request, artifacts)?;
    digests.request.clone_from(&run.request.digest);
    digests.build_receipt.clone_from(&run.build_receipt.digest);
    digests.loader.clone_from(&run.loader.digest);
    digests.kernel.clone_from(&run.kernel.digest);
    digests.symbols.clone_from(&run.symbols.digest);
    digests.bootstrap.clone_from(&run.bootstrap.digest);
    digests.init0.clone_from(&run.init0.digest);
    digests.hello.clone_from(&run.hello.digest);
    if let (Some(digest), Some(snapshot)) = (&mut digests.selector_config, &run.selector_config) {
        digest.clone_from(&snapshot.digest);
    }
    if let (Some(digest), Some(snapshot)) = (&mut digests.selector_asset, &run.selector_asset) {
        digest.clone_from(&snapshot.digest);
    }
    digests.bootfs.clone_from(&run.bootfs.digest);
    digests.esp.clone_from(&run.esp.digest);
    digests.ovmf_code.clone_from(&run.ovmf_code.digest);
    digests.ovmf_vars_template.clone_from(&run.vars.digest);
    digests.candidate = candidate_identity_digest(
        request,
        &digests.request,
        &digests.build_receipt,
        &digests.loader,
        &digests.kernel,
        &digests.symbols,
        &digests.bootstrap,
        &digests.init0,
        &digests.hello,
        digests.selector_config.as_deref(),
        digests.selector_asset.as_deref(),
        &digests.bootfs,
        &digests.esp,
        &digests.ovmf_code,
        &digests.ovmf_vars_template,
    );
    Ok(digests)
}

fn manifest_json_fields(digests: &CandidateDigests, provenance: &str) -> String {
    let selector_content = match (&digests.selector_config, &digests.selector_asset) {
        (Some(config), Some(asset)) => format!(
            concat!(
                "\"selector_config_bootfs_path\":\"test/wyr0-i/config.toml\",",
                "\"selector_config_sha256\":\"{}\",",
                "\"selector_asset_bootfs_path\":\"test/wyr0-i/asset.bin\",",
                "\"selector_asset_sha256\":\"{}\","
            ),
            config, asset
        ),
        _ => String::new(),
    };
    format!(
        concat!(
            "\"candidate_sha256\":\"{}\",\"provenance_sha256\":\"{}\",",
            "\"request_sha256\":\"{}\",\"build_receipt_sha256\":\"{}\",",
            "\"loader_sha256\":\"{}\",",
            "\"kernel_sha256\":\"{}\",\"symbols_sha256\":\"{}\",",
            "\"bootstrap_sha256\":\"{}\",\"init0_sha256\":\"{}\",",
            "\"hello_sha256\":\"{}\",\"bootfs_sha256\":\"{}\",",
            "\"esp_sha256\":\"{}\",\"ovmf_code_sha256\":\"{}\",",
            "\"ovmf_vars_template_sha256\":\"{}\",",
            "{}"
        ),
        digests.candidate,
        provenance,
        digests.request,
        digests.build_receipt,
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
        selector_content,
    )
}

fn result_manifest_json(
    request: &HRequest,
    artifacts: &CandidateArtifacts,
    run: &RunPaths,
) -> Result<String, Failure> {
    let digests = run_candidate_digests(request, artifacts, run)?;
    let provenance = run.provenance.digest.clone();
    Ok(manifest_json_fields(&digests, &provenance))
}

/// A terminal PASS is evidence about the media actually launched, not merely
/// the media inspected before QEMU started. Re-admit the request and candidate
/// at the publication boundary and require the manifest to be byte-identical.
fn revalidate_before_pass(
    request: &HRequest,
    artifacts: &CandidateArtifacts,
    run: &RunPaths,
    pre_execution_manifest: &str,
) -> Result<(), Failure> {
    let reloaded = h_request::load(&request.path)?;
    if &reloaded != request {
        return Err(Failure::task(
            "WYR0-H request changed after inspection; refusing PASS evidence",
        ));
    }
    h_request::validate_outputs(&reloaded)?;
    verify_source_revisions(&reloaded)?;
    let current = verify_candidate_inputs(&reloaded)?;
    if &current != artifacts {
        return Err(Failure::task(
            "WYR0-H candidate paths changed after inspection; refusing PASS evidence",
        ));
    }
    inspect_loaded(&reloaded, &current)?;
    run.verify_immutable()?;
    if result_manifest_json(&reloaded, &current, run)? != pre_execution_manifest {
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
    outputs: &CheckedOutputRoot,
    kind: ExecutionKind,
) -> Result<String, Failure> {
    let run = prepare_run_directory(profile, request, artifacts, outputs)?;
    let pre_execution_manifest = result_manifest_json(request, artifacts, &run)?;
    let args = qemu_arguments(profile, request, artifacts, kind, &run);
    run.set_qemu_inheritable(true)?;
    let spawned = Command::new("qemu-system-x86_64")
        .args(&args)
        .current_dir(outputs.directory_path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(open_new(
            outputs,
            &run.stderr_log,
            "QEMU stderr",
        )?))
        .spawn();
    let restore_result = run.set_qemu_inheritable(false);
    let mut child = match spawned {
        Ok(mut child) => {
            if let Err(error) = restore_result {
                let _ = stop_child(&mut child);
                return Err(error);
            }
            child
        }
        Err(error) => {
            restore_result?;
            if kind == ExecutionKind::Integration {
                write_integration_host_failure(
                    profile,
                    request,
                    artifacts,
                    outputs,
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
        if let Err(error) = run.symbols.set_inheritable(true) {
            let _ = stop_child(&mut child);
            return Err(error);
        }
        let status = Command::new("gdb")
            .args(gdb_arguments(&run.symbols))
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status();
        if let Err(error) = run.symbols.set_inheritable(false) {
            let _ = stop_child(&mut child);
            return Err(error);
        }
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
            run.symbols.digest
        ));
    }

    let status = match wait_bounded(&mut child, request.timeout_seconds) {
        Ok(WaitOutcome::Exited(status)) => status,
        Ok(WaitOutcome::TimedOut(cleanup)) if kind == ExecutionKind::Integration => {
            write_integration_host_failure(
                profile,
                request,
                artifacts,
                outputs,
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
                outputs,
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

    let serial = match read_run_file(&run.serial_log, "integration serial log", MAX_SERIAL_BYTES) {
        Ok(serial) => serial,
        Err(error) => {
            write_integration_host_failure(
                profile,
                request,
                artifacts,
                outputs,
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
                outputs,
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
            outputs,
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
        revalidate_before_pass(request, artifacts, &run, &pre_execution_manifest)?;
    }
    let evidence_fields = if status_name == "PASS" {
        evidence_result_fields(request, transcript.evidence)?
    } else {
        String::new()
    };
    let manifest = result_manifest_json(request, artifacts, &run)?;
    let result = format!(
        concat!(
            "{{\"schema_version\":{},\"phase\":\"WYR0-H\",",
            "\"mode\":\"integration\",\"profile\":\"{}\",",
            "\"status\":\"{}\",\"vcpu\":{},\"memory_mib\":{},",
            "\"test_id\":{},\"expected_outcome\":\"{}\",\"expected_detail\":{},",
            "\"actual_outcome\":\"{}\",\"detail\":{},\"serial_line\":{},",
            "\"qemu_exit_status\":{},{}{}",
            "\"deepwyrm_revision\":\"{}\",\"wyrmroot_revision\":\"{}\",",
            "\"rust_revision\":\"{}\",\"no_host_share\":true}}\n"
        ),
        request.schema_version,
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
        evidence_fields,
        manifest,
        request.deepwyrm_revision,
        request.wyrmroot_revision,
        request.rust_revision,
    );
    write_new(
        outputs,
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
                request_evidence.protocol.name(),
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
    outputs: &CheckedOutputRoot,
    run: &RunPaths,
    failure: HostFailure<'_>,
) -> Result<(), Failure> {
    let exit_status = failure
        .status
        .and_then(ExitStatus::code)
        .map_or_else(|| "null".to_owned(), |code| code.to_string());
    let manifest = result_manifest_json(request, artifacts, run)?;
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
        outputs,
        &run.result_json,
        result.as_bytes(),
        "integration host-failure result",
    )
}

struct RunPaths {
    request: StableRunFile,
    build_receipt: StableRunFile,
    loader: StableRunFile,
    kernel: StableRunFile,
    symbols: StableRunFile,
    bootstrap: StableRunFile,
    init0: StableRunFile,
    hello: StableRunFile,
    selector_config: Option<StableRunFile>,
    selector_asset: Option<StableRunFile>,
    bootfs: StableRunFile,
    esp: StableRunFile,
    provenance: StableRunFile,
    ovmf_code: StableRunFile,
    vars: StableRunFile,
    serial_log: StableRunFile,
    result_json: PathBuf,
    stderr_log: PathBuf,
}

impl RunPaths {
    fn immutable_files(&self) -> Vec<(&StableRunFile, &'static str)> {
        let mut files = vec![
            (&self.request, "request"),
            (&self.build_receipt, "build-lineage receipt"),
            (&self.loader, "loader.efi"),
            (&self.kernel, "deepwyrm.elf"),
            (&self.symbols, "Deepwyrm symbols"),
            (&self.bootstrap, "bootstrap.elf"),
            (&self.init0, "init0"),
            (&self.hello, "hello"),
            (&self.bootfs, "bootfs"),
            (&self.esp, "ESP"),
            (&self.provenance, "provenance"),
            (&self.ovmf_code, "OVMF code"),
        ];
        if let Some(config) = &self.selector_config {
            files.push((config, "WYR0-I selector config"));
        }
        if let Some(asset) = &self.selector_asset {
            files.push((asset, "WYR0-I selector asset"));
        }
        files
    }

    fn verify_immutable(&self) -> Result<(), Failure> {
        for (file, label) in self.immutable_files() {
            file.verify_unchanged(label)?;
        }
        Ok(())
    }

    fn set_qemu_inheritable(&self, inheritable: bool) -> Result<(), Failure> {
        for file in [&self.ovmf_code, &self.vars, &self.esp, &self.serial_log] {
            file.set_inheritable(inheritable)?;
        }
        Ok(())
    }

    fn snapshot_request(&self, request: &HRequest) -> HRequest {
        let capability = request
            .capability
            .as_ref()
            .map(|capability| CapabilityRequest {
                selector_config: self.selector_config.as_ref().map_or_else(
                    || capability.selector_config.clone(),
                    |file| file.path.clone(),
                ),
                selector_asset: self.selector_asset.as_ref().map_or_else(
                    || capability.selector_asset.clone(),
                    |file| file.path.clone(),
                ),
                certificate: capability.certificate.clone(),
                capability_summary: capability.capability_summary.clone(),
            });
        HRequest {
            path: self.request.path.clone(),
            loader: self.loader.path.clone(),
            kernel: self.kernel.path.clone(),
            symbols: self.symbols.path.clone(),
            bootstrap: self.bootstrap.path.clone(),
            init0: self.init0.path.clone(),
            hello: self.hello.path.clone(),
            capability,
            bootfs: self.bootfs.path.clone(),
            esp: self.esp.path.clone(),
            provenance: self.provenance.path.clone(),
            ovmf_code: self.ovmf_code.path.clone(),
            ovmf_vars_template: self.vars.path.clone(),
            ..request.clone()
        }
    }

    fn snapshot_artifacts(&self) -> CandidateArtifacts {
        CandidateArtifacts {
            build_receipt: self.build_receipt.path.clone(),
            loader: self.loader.path.clone(),
            kernel: self.kernel.path.clone(),
            symbols: self.symbols.path.clone(),
            bootstrap: self.bootstrap.path.clone(),
            init0: self.init0.path.clone(),
            hello: self.hello.path.clone(),
            selector_config: self.selector_config.as_ref().map(|file| file.path.clone()),
            selector_asset: self.selector_asset.as_ref().map(|file| file.path.clone()),
            ovmf_code: self.ovmf_code.path.clone(),
            ovmf_vars_template: self.vars.path.clone(),
        }
    }
}

fn prepare_run_directory(
    profile: HProfile,
    request: &HRequest,
    artifacts: &CandidateArtifacts,
    outputs: &CheckedOutputRoot,
) -> Result<RunPaths, Failure> {
    h_request::validate_outputs(request)?;
    if !outputs.is_dir(&request.run_directory, "run directory")? {
        outputs.create_dir(&request.run_directory, "run directory")?;
    }
    let directory = request.run_directory.join(profile.name());
    outputs.create_dir(
        &directory,
        &format!("fresh {} run directory", profile.name()),
    )?;

    let request_bytes = read_regular(&request.path, "WYR0-H request", 64 * 1024)?;
    if sha256::bytes_digest(&request_bytes) != request.request_sha256 {
        return Err(Failure::task(
            "WYR0-H request changed before the run-local snapshot was created",
        ));
    }
    let build_receipt_bytes = read_regular(
        &artifacts.build_receipt,
        "WYR0-H build-lineage receipt",
        64 * 1024,
    )?;
    let loader_bytes = read_regular(&artifacts.loader, "loader.efi", MAX_GUEST_ARTIFACT_BYTES)?;
    let kernel_bytes = read_regular(&artifacts.kernel, "deepwyrm.elf", MAX_GUEST_ARTIFACT_BYTES)?;
    let symbols_bytes = read_regular(
        &artifacts.symbols,
        "Deepwyrm symbols",
        MAX_GUEST_ARTIFACT_BYTES,
    )?;
    let bootstrap_bytes = read_regular(
        &artifacts.bootstrap,
        "bootstrap.elf",
        MAX_GUEST_ARTIFACT_BYTES,
    )?;
    let init0_bytes = read_regular(&artifacts.init0, "init0", MAX_GUEST_ARTIFACT_BYTES)?;
    let hello_bytes = read_regular(&artifacts.hello, "hello", MAX_GUEST_ARTIFACT_BYTES)?;
    let selector_config_bytes = artifacts
        .selector_config
        .as_ref()
        .map(|path| read_regular(path, "WYR0-I selector config", MAX_SELECTOR_CONTENT_BYTES))
        .transpose()?;
    let selector_asset_bytes = artifacts
        .selector_asset
        .as_ref()
        .map(|path| read_regular(path, "WYR0-I selector asset", MAX_SELECTOR_CONTENT_BYTES))
        .transpose()?;
    let bootfs_bytes =
        read_output_regular(outputs, &request.bootfs, "bootfs", MAX_GUEST_ARTIFACT_BYTES)?;
    let esp_bytes =
        read_output_regular(outputs, &request.esp, "ESP", MAX_WYR0_H_ESP_SNAPSHOT_BYTES)?;
    let provenance_bytes = read_output_regular(
        outputs,
        &request.provenance,
        "provenance",
        MAX_GUEST_ARTIFACT_BYTES,
    )?;
    let ovmf_code_bytes = read_regular(&artifacts.ovmf_code, "OVMF code", MAX_FIRMWARE_BYTES)?;
    let result_json = directory.join("result.json");
    let stderr_log = directory.join("qemu.stderr.log");
    let vars_bytes = read_regular(
        &artifacts.ovmf_vars_template,
        "OVMF vars template",
        MAX_FIRMWARE_BYTES,
    )?;

    let run = RunPaths {
        request: create_run_file(
            outputs,
            &directory.join("request.toml"),
            &request_bytes,
            true,
        )?,
        build_receipt: create_run_file(
            outputs,
            &directory.join(BUILD_RECEIPT_FILE),
            &build_receipt_bytes,
            true,
        )?,
        loader: create_run_file(outputs, &directory.join("loader.efi"), &loader_bytes, true)?,
        kernel: create_run_file(
            outputs,
            &directory.join("deepwyrm.elf"),
            &kernel_bytes,
            true,
        )?,
        symbols: create_run_file(
            outputs,
            &directory.join("deepwyrm.symbols"),
            &symbols_bytes,
            true,
        )?,
        bootstrap: create_run_file(
            outputs,
            &directory.join("bootstrap.elf"),
            &bootstrap_bytes,
            true,
        )?,
        init0: create_run_file(outputs, &directory.join("init0.elf"), &init0_bytes, true)?,
        hello: create_run_file(outputs, &directory.join("hello.elf"), &hello_bytes, true)?,
        selector_config: selector_config_bytes
            .as_ref()
            .map(|bytes| {
                create_run_file(
                    outputs,
                    &directory.join("selector-config.toml"),
                    bytes,
                    true,
                )
            })
            .transpose()?,
        selector_asset: selector_asset_bytes
            .as_ref()
            .map(|bytes| {
                create_run_file(outputs, &directory.join("selector-asset.bin"), bytes, true)
            })
            .transpose()?,
        bootfs: create_run_file(outputs, &directory.join("bootfs.img"), &bootfs_bytes, true)?,
        esp: create_run_file(outputs, &directory.join("esp.img"), &esp_bytes, true)?,
        provenance: create_run_file(
            outputs,
            &directory.join("provenance.toml"),
            &provenance_bytes,
            true,
        )?,
        ovmf_code: create_run_file(
            outputs,
            &directory.join("OVMF_CODE.fd"),
            &ovmf_code_bytes,
            true,
        )?,
        vars: create_run_file(outputs, &directory.join("OVMF_VARS.fd"), &vars_bytes, false)?,
        serial_log: create_run_file(outputs, &directory.join("serial.log"), &[], false)?,
        result_json,
        stderr_log,
    };
    run.verify_immutable()?;
    let snapshot_request = run.snapshot_request(request);
    inspect_loaded(&snapshot_request, &run.snapshot_artifacts())?;
    Ok(run)
}

fn qemu_arguments(
    profile: HProfile,
    request: &HRequest,
    _artifacts: &CandidateArtifacts,
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
            run.ovmf_code.child_path().display()
        ),
        "-drive".into(),
        format!(
            "if=pflash,format=raw,file={}",
            run.vars.child_path().display()
        ),
        "-drive".into(),
        format!(
            "if=virtio,format=raw,readonly=on,file={}",
            run.esp.child_path().display()
        ),
        "-serial".into(),
        format!("file:{}", run.serial_log.child_path().display()),
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

fn gdb_arguments(symbols: &StableRunFile) -> Vec<String> {
    vec![
        "-ex".into(),
        "set architecture i386:x86-64".into(),
        "-ex".into(),
        format!("file {}", symbols.child_path().display()),
        "-ex".into(),
        "target remote 127.0.0.1:1234".into(),
    ]
}

fn parse_transcript(bytes: &[u8], request: &HRequest) -> Result<GuestTranscript, Failure> {
    match request.evidence {
        Some(evidence) => match evidence.protocol {
            EvidenceProtocol::Dwevid1 => parse_dwevid1_transcript(bytes, request.test_id, evidence),
            EvidenceProtocol::Wrcap1 => parse_wrcap1_transcript(bytes, request, evidence),
        },
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

fn parse_dwevid1_transcript(
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

fn parse_wrcap1_transcript(
    bytes: &[u8],
    request: &HRequest,
    evidence_request: EvidenceRequest,
) -> Result<GuestTranscript, Failure> {
    let mut terminal = None;
    let mut events = Vec::new();
    for (index, line) in bytes.split_inclusive(|byte| *byte == b'\n').enumerate() {
        let line_number = index + 1;
        if resembles_protocol_magic(line, b"WRCAP1") {
            if terminal.is_some() {
                return Err(Failure::task(format!(
                    "serial line {line_number} contains WRCAP1 evidence after the terminal record"
                )));
            }
            if events.len() == MAX_EVIDENCE_RECORDS {
                return Err(Failure::task(format!(
                    "serial line {line_number} exceeds the {MAX_EVIDENCE_RECORDS}-record WRCAP1 limit"
                )));
            }
            let event = parse_capability_evidence_line(line, line_number, evidence_request.nonce)?;
            if event.sequence != events.len() as u32 {
                return Err(Failure::task(format!(
                    "serial line {line_number} has non-contiguous WRCAP1 sequence {:08X}; expected {:08X}",
                    event.sequence,
                    events.len()
                )));
            }
            events.push(event);
            continue;
        }
        if resembles_protocol_magic(line, b"DWEVID1") {
            return Err(Failure::task(format!(
                "serial line {line_number} contains cross-protocol DWEVID1 input in a WRCAP1 transcript"
            )));
        }
        if resembles_protocol_magic(line, b"DWTEST1") {
            let record = parse_terminal_line(line, line_number, request.test_id)?;
            if terminal.replace(record).is_some() {
                return Err(Failure::task(
                    "serial log contains duplicate DWTEST1 terminal records",
                ));
            }
        }
    }
    let terminal =
        terminal.ok_or_else(|| Failure::task("serial log contains no DWTEST1 terminal record"))?;
    if terminal.outcome != GuestOutcome::Pass || terminal.detail != 0 {
        return Err(Failure::task(
            "WRCAP1 transcript requires one matching PASS/0 terminal for test 24",
        ));
    }
    if events.is_empty() {
        return Err(Failure::task(
            "WYR0-I serial log contains no WRCAP1 evidence records",
        ));
    }
    let evidence = validate_capability_evidence(&events, request, evidence_request.required_mask)?;
    Ok(GuestTranscript {
        terminal,
        evidence: Some(evidence),
    })
}

fn parse_capability_evidence_line(
    line: &[u8],
    line_number: usize,
    expected_nonce: u64,
) -> Result<CapabilityEvidenceEvent, Failure> {
    if line.len() != WRCAP1_RECORD_BYTES
        || &line[..6] != b"WRCAP1"
        || line[6] != b'|'
        || line[9] != b'|'
        || line[26] != b'|'
        || line[35] != b'|'
        || line[38] != b'|'
        || line[47] != b'|'
        || line[56] != b'|'
        || line[73] != b'|'
        || line[90] != b'|'
        || line[107] != b'|'
        || line[116] != b'\n'
    {
        return Err(Failure::task(format!(
            "serial line {line_number} contains a malformed WRCAP1 record"
        )));
    }
    if &line[7..9] != b"01" {
        return Err(Failure::task(format!(
            "serial line {line_number} has an unsupported WRCAP1 version"
        )));
    }
    let nonce = parse_hex_u64(&line[10..26]).ok_or_else(|| {
        Failure::task(format!(
            "serial line {line_number} has an invalid WRCAP1 nonce"
        ))
    })?;
    if nonce != expected_nonce {
        return Err(Failure::task(format!(
            "serial line {line_number} WRCAP1 nonce does not match the request"
        )));
    }
    let sequence = capability_hex_u32(&line[27..35], line_number, "sequence")?;
    let kind_value = parse_hex_u8(&line[36..38]).ok_or_else(|| {
        Failure::task(format!(
            "serial line {line_number} has an invalid WRCAP1 kind"
        ))
    })?;
    let kind = CapabilityEvidenceKind::parse(kind_value).ok_or_else(|| {
        Failure::task(format!(
            "serial line {line_number} has unknown WRCAP1 kind {kind_value:02X}"
        ))
    })?;
    let peer = capability_hex_u32(&line[39..47], line_number, "peer")?;
    let generation = capability_hex_u32(&line[48..56], line_number, "generation")?;
    let token = capability_hex_u64(&line[57..73], line_number, "token")?;
    let arg0 = capability_hex_u64(&line[74..90], line_number, "arg0")?;
    let arg1 = capability_hex_u64(&line[91..107], line_number, "arg1")?;
    let checksum = capability_hex_u32(&line[108..116], line_number, "checksum")?;
    if checksum != fnv1a32(&line[..108]) {
        return Err(Failure::task(format!(
            "serial line {line_number} has a mismatched WRCAP1 checksum"
        )));
    }
    Ok(CapabilityEvidenceEvent {
        sequence,
        kind,
        peer,
        generation,
        token,
        arg0,
        arg1,
        line: line_number,
    })
}

fn capability_hex_u32(bytes: &[u8], line_number: usize, field: &str) -> Result<u32, Failure> {
    parse_hex(bytes).ok_or_else(|| {
        Failure::task(format!(
            "serial line {line_number} has an invalid WRCAP1 {field}"
        ))
    })
}

fn capability_hex_u64(bytes: &[u8], line_number: usize, field: &str) -> Result<u64, Failure> {
    parse_hex_u64(bytes).ok_or_else(|| {
        Failure::task(format!(
            "serial line {line_number} has an invalid WRCAP1 {field}"
        ))
    })
}

fn validate_capability_evidence(
    events: &[CapabilityEvidenceEvent],
    request: &HRequest,
    required_evidence_mask: u32,
) -> Result<ValidatedEvidence, Failure> {
    if events.len() != WYR0_I_CAPABILITY_EVENT_COUNT as usize {
        return Err(Failure::task(format!(
            "WYR0-I evidence requires exactly {WYR0_I_CAPABILITY_EVENT_COUNT} canonical records; observed {}",
            events.len()
        )));
    }
    let expected_kinds = [
        CapabilityEvidenceKind::ContentDelivery,
        CapabilityEvidenceKind::ProcessLifecycle,
        CapabilityEvidenceKind::ProcessLifecycle,
        CapabilityEvidenceKind::MemoryShare,
        CapabilityEvidenceKind::ChannelLifecycle,
        CapabilityEvidenceKind::WaitEventTimer,
        CapabilityEvidenceKind::Cancellation,
        CapabilityEvidenceKind::RestartReplacement,
        CapabilityEvidenceKind::RestartReplacement,
        CapabilityEvidenceKind::RestartExhausted,
        CapabilityEvidenceKind::RestartExhausted,
        CapabilityEvidenceKind::RestartExhausted,
        CapabilityEvidenceKind::RestartExhausted,
        CapabilityEvidenceKind::OverloadReplayRejected,
        CapabilityEvidenceKind::CleanupBaseline,
    ];
    for (event, expected_kind) in events.iter().zip(expected_kinds) {
        if event.kind != expected_kind {
            return Err(Failure::task(format!(
                "serial line {} has WRCAP1 kind {:02X} out of canonical order; expected {:02X}",
                event.line,
                event.kind.value(),
                expected_kind.value(),
            )));
        }
    }

    let content = events[0];
    let (config_prefix, asset_prefix) = capability_content_prefixes(request)?;
    let content_token = config_prefix ^ asset_prefix;
    if content.peer != 0
        || content.generation != 0
        || content_token == 0
        || content.token != content_token
        || content.arg0 != config_prefix
        || content.arg1 != asset_prefix
    {
        return Err(Failure::task(
            "WYR0-I CONTENT_DELIVERY does not match the request-bound config/asset identity",
        ));
    }

    let normal_transaction = events[1].token;
    require_capability_event(events[1], 1, 1, 1, 0, "PROCESS_LIFECYCLE READY")?;
    require_capability_event(events[2], 1, 1, 2, 0, "PROCESS_LIFECYCLE EXIT")?;
    if events[2].token != normal_transaction {
        return Err(Failure::task(
            "WYR0-I PROCESS_LIFECYCLE READY and EXIT do not share NORMAL_TRANSACTION",
        ));
    }
    require_capability_event(events[3], 1, 1, 4096, WYR0_I_MEMORY_RIGHTS, "MEMORY_SHARE")?;
    let channel = events[4];
    if channel.peer != 1
        || channel.generation != 1
        || channel.token == 0
        || channel.arg0 != 0x0F
        || channel.arg1 == 0
        || channel.arg1 >= WYR0_I_CHANNEL_BACKPRESSURE_ATTEMPT_LIMIT
    {
        return Err(Failure::task(
            "WYR0-I CHANNEL_LIFECYCLE has an invalid peer, generation, token, proof bitmap, or measured queue-fill count",
        ));
    }
    require_capability_event(events[5], 1, 1, 0x0F, 0, "WAIT_EVENT_TIMER")?;
    require_capability_event(
        events[6],
        2,
        1,
        WYR0_I_AUTHORIZED_TERMINATION,
        0,
        "CANCELLATION",
    )?;

    require_capability_event(events[7], 3, 1, 1, 2, "RESTART_REPLACEMENT attempt 1")?;
    require_capability_event(events[8], 3, 2, 2, 1, "RESTART_REPLACEMENT attempt 2")?;
    if events[7].token.checked_add(1) != Some(events[8].token) {
        return Err(Failure::task(
            "WYR0-I RESTART_REPLACEMENT tokens are not contiguous RESTART_BASE + attempt",
        ));
    }

    for generation in 1_u32..=4 {
        let index = 8 + generation as usize;
        let next_generation = if generation == 4 {
            0
        } else {
            u64::from(generation + 1)
        };
        require_capability_event(
            events[index],
            4,
            generation,
            u64::from(generation),
            next_generation,
            "RESTART_EXHAUSTED",
        )?;
        if generation > 1 && events[index - 1].token.checked_add(1) != Some(events[index].token) {
            return Err(Failure::task(
                "WYR0-I RESTART_EXHAUSTED tokens are not contiguous EXHAUST_BASE + generation",
            ));
        }
    }

    require_capability_event(events[13], 1, 1, 0x0F, 2, "OVERLOAD_REPLAY_REJECTED")?;
    if events[13].token != normal_transaction {
        return Err(Failure::task(
            "WYR0-I OVERLOAD_REPLAY_REJECTED is not joined to NORMAL_TRANSACTION",
        ));
    }

    let cleanup = events[14];
    if cleanup.peer != 0
        || cleanup.generation != 0
        || cleanup.token != 0
        || cleanup.arg0 != 0
        || cleanup.arg1 != 0
    {
        return Err(Failure::task(
            "WYR0-I CLEANUP_BASELINE must be the final global zero-baseline record",
        ));
    }

    let mut tokens = BTreeSet::new();
    for (index, event) in events[..14].iter().enumerate() {
        if event.token == 0 {
            return Err(Failure::task(format!(
                "serial line {} has a zero WRCAP1 transaction/object token",
                event.line
            )));
        }
        if matches!(index, 2 | 13) {
            continue;
        }
        if !tokens.insert(event.token) {
            return Err(Failure::task(format!(
                "serial line {} reuses a WRCAP1 token outside the declared NORMAL_TRANSACTION join",
                event.line
            )));
        }
    }

    let observed_mask = events
        .iter()
        .fold(0_u32, |mask, event| mask | event.kind.bit());
    if observed_mask != required_evidence_mask {
        return Err(Failure::task(format!(
            "WYR0-I transcript proof mask {observed_mask:08X} does not exactly match request {required_evidence_mask:08X}"
        )));
    }
    Ok(ValidatedEvidence {
        count: events.len() as u32,
        observed_mask,
        first_sequence: events[0].sequence,
        last_sequence: events[events.len() - 1].sequence,
    })
}

fn require_capability_event(
    event: CapabilityEvidenceEvent,
    peer: u32,
    generation: u32,
    arg0: u64,
    arg1: u64,
    label: &str,
) -> Result<(), Failure> {
    if event.peer != peer
        || event.generation != generation
        || event.token == 0
        || event.arg0 != arg0
        || event.arg1 != arg1
    {
        return Err(Failure::task(format!(
            "WYR0-I {label} has an invalid peer, generation, token, or joined fact"
        )));
    }
    Ok(())
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
    if line.len() != DWEVID1_RECORD_BYTES
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
    if invariant.token != 0 || invariant.arg0 != 0 {
        return Err(Failure::task(
            "I1 RUNNING_INVARIANT must report zero token and violation count",
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
    let tlb_required_mask = publish.arg0;
    if publish.token == 0 || tlb_required_mask == 0 || tlb_required_mask & !0x0F != 0 {
        return Err(Failure::task(
            "I1 TLB_PUBLISH requires a nonzero generation and nonempty CPU mask within CPUs 0..3",
        ));
    }
    if reclaim.token != publish.token || reclaim.sequence <= publish.sequence {
        return Err(Failure::task(
            "I1 RECLAIM_ALLOWED has an invalid generation or order",
        ));
    }
    let rendezvous_required_mask = rendezvous_ack
        .first()
        .map(|event| event.arg0)
        .filter(|mask| *mask != 0 && *mask & !0x0F == 0)
        .ok_or_else(|| {
            Failure::task(
                "I1 RENDEZVOUS_ACK requires a nonempty operation-specific CPU mask within CPUs 0..3",
            )
        })?;
    let tlb_ack_mask = validate_ack_set(&tlb_ack, publish, reclaim, tlb_required_mask, "TLB_ACK")?;
    let rendezvous_ack_mask = validate_ack_set(
        &rendezvous_ack,
        publish,
        reclaim,
        rendezvous_required_mask,
        "RENDEZVOUS_ACK",
    )?;
    if reclaim.arg0 != tlb_ack_mask || reclaim.arg1 != rendezvous_ack_mask {
        return Err(Failure::task(
            "I1 RECLAIM_ALLOWED masks do not exactly match the observed acknowledgement masks",
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

#[derive(Debug, Eq, PartialEq)]
struct SourceState {
    revision: String,
    clean: bool,
}

#[derive(Debug, Eq, PartialEq)]
struct SourceQualification {
    deepwyrm: SourceState,
    wyrmroot: SourceState,
    rust: SourceState,
}

fn verify_source_revisions(request: &HRequest) -> Result<SourceQualification, Failure> {
    let repository = crate::tasks::repository_root()?;
    let workspace = source_workspace_root(&repository)?;
    let deepwyrm = workspace.join("deepwyrm");
    let rust = workspace.join("rust");
    Ok(SourceQualification {
        deepwyrm: qualify_source(&deepwyrm, &request.deepwyrm_revision, "Deepwyrm")?,
        wyrmroot: qualify_source(&repository, &request.wyrmroot_revision, "Wyrmroot")?,
        rust: qualify_source(&rust, &request.rust_revision, "Rust")?,
    })
}

fn qualify_source(repository: &Path, expected: &str, label: &str) -> Result<SourceState, Failure> {
    let revision = git_output(repository, &["rev-parse", "HEAD"], label)?;
    let revision = revision.trim().to_owned();
    if revision != expected {
        return Err(Failure::task(format!(
            "WYR0-H request {label} revision does not match the current checkout"
        )));
    }
    let dirty = git_output(
        repository,
        &["status", "--porcelain=v1", "--untracked-files=all"],
        label,
    )?;
    let clean = dirty.is_empty();
    if !clean {
        return Err(Failure::task(format!(
            "WYR0-H requires a clean {label} checkout, including untracked files, for exact revision provenance"
        )));
    }
    Ok(SourceState { revision, clean })
}

fn source_workspace_root(repository: &Path) -> Result<PathBuf, Failure> {
    repository
        .ancestors()
        .skip(1)
        .find(|ancestor| ancestor.join("deepwyrm").is_dir() && ancestor.join("rust").is_dir())
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            Failure::task(
                "could not locate the workspace containing sibling Deepwyrm and Rust repositories",
            )
        })
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

fn outputs_all_absent(outputs: &CheckedOutputRoot, request: &HRequest) -> Result<bool, Failure> {
    let states = [
        outputs.exists(&request.bootfs, "bootfs")?,
        outputs.exists(&request.esp, "ESP")?,
        outputs.exists(&request.provenance, "provenance")?,
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
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|error| Failure::task(format!("could not open {label}: {error}")))?;
    read_opened_regular(file, label, max_bytes)
}

fn read_output_regular(
    outputs: &CheckedOutputRoot,
    path: &Path,
    label: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, Failure> {
    let file = outputs.open_regular_file(path, label, true, false)?;
    read_opened_regular(file, label, max_bytes)
}

fn read_opened_regular(
    mut file: fs::File,
    label: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, Failure> {
    let metadata = file
        .metadata()
        .map_err(|error| Failure::task(format!("could not stat {label}: {error}")))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(Failure::task(format!(
            "{label} must be a nonempty regular file no larger than {max_bytes} bytes"
        )));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| Failure::task(format!("{label} does not fit host address space")))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .map_err(|error| Failure::task(format!("could not read {label}: {error}")))?;
    if u64::try_from(bytes.len()).ok() != Some(metadata.len()) {
        return Err(Failure::task(format!(
            "{label} changed length while its opened bytes were read"
        )));
    }
    Ok(bytes)
}

fn read_run_file(file: &StableRunFile, label: &str, max_bytes: u64) -> Result<Vec<u8>, Failure> {
    let mut opened = file
        .file
        .try_clone()
        .map_err(|error| Failure::task(format!("could not clone run-local {label}: {error}")))?;
    opened
        .seek(SeekFrom::Start(0))
        .map_err(|error| Failure::task(format!("could not rewind run-local {label}: {error}")))?;
    let metadata = opened
        .metadata()
        .map_err(|error| Failure::task(format!("could not stat run-local {label}: {error}")))?;
    if metadata.len() > max_bytes {
        return Err(Failure::task(format!(
            "run-local {label} exceeds its {max_bytes}-byte limit"
        )));
    }
    let mut bytes = Vec::new();
    opened
        .read_to_end(&mut bytes)
        .map_err(|error| Failure::task(format!("could not read run-local {label}: {error}")))?;
    Ok(bytes)
}

fn create_run_file(
    outputs: &CheckedOutputRoot,
    path: &Path,
    bytes: &[u8],
    immutable: bool,
) -> Result<StableRunFile, Failure> {
    let mut output = outputs.create_new_file(path, "run-local snapshot", true, true)?;
    output
        .write_all(bytes)
        .and_then(|()| output.sync_all())
        .map_err(|error| Failure::task(format!("could not write run-local snapshot: {error}")))?;
    output
        .seek(SeekFrom::Start(0))
        .map_err(|error| Failure::task(format!("could not rewind run-local snapshot: {error}")))?;
    let file = if immutable {
        let expected = output.metadata().map_err(|error| {
            Failure::task(format!("could not stat run-local snapshot: {error}"))
        })?;
        output
            .set_permissions(fs::Permissions::from_mode(0o400))
            .map_err(|error| {
                Failure::task(format!(
                    "could not make run-local snapshot read-only: {error}"
                ))
            })?;
        let reopened = outputs.open_regular_file(path, "run-local snapshot", true, false)?;
        let observed = reopened.metadata().map_err(|error| {
            Failure::task(format!(
                "could not stat reopened run-local snapshot: {error}"
            ))
        })?;
        if expected.dev() != observed.dev() || expected.ino() != observed.ino() {
            return Err(Failure::task(
                "run-local snapshot was replaced while it was made immutable",
            ));
        }
        reopened
    } else {
        output
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| {
                Failure::task(format!(
                    "could not restrict run-local file permissions: {error}"
                ))
            })?;
        output
    };
    Ok(StableRunFile {
        path: path.to_path_buf(),
        file,
        digest: sha256::bytes_digest(bytes),
        immutable,
    })
}

fn write_new(
    outputs: &CheckedOutputRoot,
    path: &Path,
    bytes: &[u8],
    label: &str,
) -> Result<(), Failure> {
    write_new_retained(outputs, path, bytes, label).map(drop)
}

fn write_new_retained(
    outputs: &CheckedOutputRoot,
    path: &Path,
    bytes: &[u8],
    label: &str,
) -> Result<fs::File, Failure> {
    let mut output = outputs.create_new_file(path, label, false, true)?;
    if let Err(error) = output.write_all(bytes).and_then(|()| output.sync_all()) {
        drop(output);
        return Err(with_rollback(
            Failure::task(format!("could not write {label}: {error}")),
            rollback_created(outputs, &[(path, label)]),
        ));
    }
    Ok(output)
}

fn open_new(outputs: &CheckedOutputRoot, path: &Path, label: &str) -> Result<fs::File, Failure> {
    outputs.create_new_file(path, label, false, true)
}

fn require_absent(outputs: &CheckedOutputRoot, path: &Path, label: &str) -> Result<(), Failure> {
    if outputs.exists(path, label)? {
        Err(Failure::task(format!("WYR0-H {label} already exists")))
    } else {
        Ok(())
    }
}

fn digest(path: &Path, label: &str) -> Result<String, Failure> {
    let path = h_request::canonical_regular(path, label, u64::MAX)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|error| Failure::task(format!("could not open {label}: {error}")))?;
    sha256::reader_digest(&mut file)
        .map_err(|error| Failure::task(format!("could not hash {label}: {error}")))
}

fn rollback_created(outputs: &CheckedOutputRoot, created: &[(&Path, &str)]) -> Result<(), Failure> {
    let mut failures = Vec::new();
    for (path, label) in created {
        if let Err(error) = outputs.remove_file(path, label) {
            failures.push(error.message);
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(Failure::task(format!(
            "could not complete output rollback: {}",
            failures.join("; ")
        )))
    }
}

fn with_rollback(mut primary: Failure, rollback: Result<(), Failure>) -> Failure {
    if let Err(rollback) = rollback {
        primary.message = format!(
            "{}; partial WYR0-H outputs may remain because rollback failed: {}",
            primary.message, rollback.message
        );
    }
    primary
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

    const TEST_EVIDENCE_NONCE: u64 = h_request::I1_EVIDENCE_NONCE;

    #[test]
    fn source_workspace_root_accepts_canonical_and_detached_review_layouts() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("xtask-source-workspace-{}", std::process::id()));
        let workspace = root.join("workspace");
        let canonical = workspace.join("wyrmroot");
        let detached = workspace.join(".worktrees/wyrmroot/review-wave3");
        fs::create_dir_all(&canonical).expect("create canonical repository fixture");
        fs::create_dir_all(&detached).expect("create detached repository fixture");
        fs::create_dir(workspace.join("deepwyrm")).expect("create Deepwyrm sibling fixture");
        fs::create_dir(workspace.join("rust")).expect("create Rust sibling fixture");

        assert_eq!(source_workspace_root(&canonical).unwrap(), workspace);
        assert_eq!(source_workspace_root(&detached).unwrap(), workspace);

        fs::remove_dir_all(root).expect("remove source-workspace fixture");
    }

    #[test]
    fn source_qualification_rejects_tracked_and_untracked_changes() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!(
                "xtask-source-qualification-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system clock before epoch")
                    .as_nanos()
            ));
        fs::create_dir_all(&root).expect("create source qualification fixture");
        run_git(&root, &["init", "-q"]);
        fs::write(root.join("tracked"), b"accepted\n").expect("write tracked fixture");
        run_git(&root, &["add", "tracked"]);
        run_git(
            &root,
            &[
                "-c",
                "commit.gpgsign=false",
                "-c",
                "user.name=Codex Test",
                "-c",
                "user.email=codex-test@example.invalid",
                "commit",
                "-q",
                "-m",
                "fixture",
            ],
        );
        let revision = git_output(&root, &["rev-parse", "HEAD"], "fixture")
            .expect("read fixture revision")
            .trim()
            .to_owned();

        assert_eq!(
            qualify_source(&root, &revision, "fixture").expect("qualify clean fixture"),
            SourceState {
                revision: revision.clone(),
                clean: true,
            }
        );

        fs::write(root.join("untracked"), b"not certified\n").expect("write untracked fixture");
        let error = qualify_source(&root, &revision, "fixture")
            .expect_err("qualified a checkout with an untracked file");
        assert!(error.message.contains("including untracked files"));
        fs::remove_file(root.join("untracked")).expect("remove untracked fixture");

        fs::write(root.join("tracked"), b"modified\n").expect("modify tracked fixture");
        assert!(qualify_source(&root, &revision, "fixture").is_err());

        fs::remove_dir_all(root).expect("remove source qualification fixture");
    }

    fn run_git(repository: &Path, arguments: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(arguments)
            .stdin(Stdio::null())
            .status()
            .expect("run fixture Git command");
        assert!(
            status.success(),
            "fixture Git command failed: {arguments:?}"
        );
    }

    fn test_stable_file(path: PathBuf, bytes: &[u8], immutable: bool) -> StableRunFile {
        fs::write(&path, bytes).expect("write test stable file");
        let file = OpenOptions::new()
            .read(true)
            .write(!immutable)
            .open(&path)
            .expect("open test stable file");
        StableRunFile {
            path,
            file,
            digest: sha256::bytes_digest(bytes),
            immutable,
        }
    }

    fn test_run_paths(root: &Path, name: &str) -> RunPaths {
        let directory = root.join(format!("run-snapshot-{name}"));
        fs::create_dir(&directory).expect("create test run snapshot");
        let stable =
            |file_name: &str| test_stable_file(directory.join(file_name), b"artifact", true);
        RunPaths {
            request: stable("request.toml"),
            build_receipt: stable(BUILD_RECEIPT_FILE),
            loader: stable("loader.efi"),
            kernel: stable("deepwyrm.elf"),
            symbols: stable("deepwyrm.symbols"),
            bootstrap: stable("bootstrap.elf"),
            init0: stable("init0.elf"),
            hello: stable("hello.elf"),
            selector_config: None,
            selector_asset: None,
            bootfs: stable("bootfs.img"),
            esp: stable("esp.img"),
            provenance: stable("provenance.toml"),
            ovmf_code: stable("OVMF_CODE.fd"),
            vars: test_stable_file(directory.join("OVMF_VARS.fd"), b"artifact", false),
            serial_log: test_stable_file(directory.join("serial.log"), b"", false),
            result_json: root.join(name),
            stderr_log: directory.join("qemu.stderr.log"),
        }
    }

    fn lineage_fixture(root: &Path) -> (HRequest, CandidateArtifacts) {
        fs::create_dir_all(root).expect("create lineage fixture");
        for name in [
            "loader.efi",
            "deepwyrm.elf",
            "bootstrap.elf",
            "init0.elf",
            "hello.elf",
            "OVMF_CODE.fd",
            "OVMF_VARS.fd",
        ] {
            fs::write(root.join(name), b"admitted artifact").expect("write lineage artifact");
        }
        fs::write(root.join("init0.elf"), INIT0_PROFILE_ORDINARY)
            .expect("write lineage init0 marker");
        let repository = crate::tasks::repository_root().expect("repository root");
        let workspace = source_workspace_root(&repository).expect("source workspace");
        let revision = |path: &Path, label: &str| {
            git_output(path, &["rev-parse", "HEAD"], label)
                .expect("read fixture revision")
                .trim()
                .to_owned()
        };
        let request = HRequest {
            path: root.join("request.toml"),
            request_sha256: sha256::bytes_digest(b"lineage request"),
            schema_version: 2,
            deepwyrm_revision: revision(&workspace.join("deepwyrm"), "Deepwyrm"),
            wyrmroot_revision: revision(&repository, "Wyrmroot"),
            rust_revision: revision(&workspace.join("rust"), "Rust"),
            selector: "primordial-bootstrap".into(),
            test_id: 18,
            expected_outcome: ExpectedOutcome::Pass,
            expected_detail: 0,
            timeout_seconds: 180,
            loader: root.join("loader.efi"),
            kernel: root.join("deepwyrm.elf"),
            symbols: root.join("deepwyrm.elf"),
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
            capability: None,
        };
        fs::write(&request.path, b"lineage request").expect("write lineage request");
        let artifacts = CandidateArtifacts {
            build_receipt: root.join(BUILD_RECEIPT_FILE),
            loader: request.loader.clone(),
            kernel: request.kernel.clone(),
            symbols: request.symbols.clone(),
            bootstrap: request.bootstrap.clone(),
            init0: request.init0.clone(),
            hello: request.hello.clone(),
            selector_config: None,
            selector_asset: None,
            ovmf_code: request.ovmf_code.clone(),
            ovmf_vars_template: request.ovmf_vars_template.clone(),
        };
        let identity = certificate_identity(&request).expect("certificate identity");
        let receipt = format!(
            concat!(
                "schema_version = 1\nreport_kind = \"{}\"\nstatus = \"PASS\"\n",
                "source_checkout_clean_before = true\nsource_checkout_clean_after = true\n",
                "deepwyrm_revision = \"{}\"\ndeepwyrm_tree = \"{}\"\n",
                "wyrmroot_revision = \"{}\"\nwyrmroot_tree = \"{}\"\n",
                "rust_revision = \"{}\"\nrust_tree = \"{}\"\n",
                "accepted_toolchain_request = \"{}\"\n",
                "accepted_toolchain_request_sha256 = \"{}\"\n",
                "accepted_toolchain_manifest_sha256 = \"{}\"\n",
                "toolchain_tree_sha256 = \"{}\"\nrustc_sha256 = \"{}\"\n",
                "cargo_sha256 = \"{}\"\nrust_lld_sha256 = \"{}\"\n",
                "llvm_sha256 = \"{}\"\nllvm_build_version = \"{}\"\n",
                "versions_sha256 = \"{}\"\nprofiles_sha256 = \"{}\"\n",
                "selector = \"{}\"\ntest_id = {}\n",
                "[loader]\ntarget = \"x86_64-unknown-uefi\"\nprofile = \"production\"\nrecipe = \"{}\"\n",
                "[kernel]\ntarget = \"x86_64-unknown-none\"\nprofile = \"release\"\nrecipe = \"{}\"\n",
                "[native]\ntarget = \"{}\"\nprofile = \"release\"\nrecipe = \"{}\"\n",
                "[outputs]\nloader_sha256 = \"{}\"\nkernel_sha256 = \"{}\"\n",
                "symbols_sha256 = \"{}\"\nbootstrap_sha256 = \"{}\"\n",
                "init0_sha256 = \"{}\"\nhello_sha256 = \"{}\"\n",
                "ovmf_code_sha256 = \"{}\"\novmf_vars_template_sha256 = \"{}\"\n"
            ),
            BUILD_RECEIPT_KIND,
            request.deepwyrm_revision,
            git_tree(
                &workspace.join("deepwyrm"),
                &request.deepwyrm_revision,
                "Deepwyrm tree"
            )
            .unwrap(),
            request.wyrmroot_revision,
            git_tree(&repository, &request.wyrmroot_revision, "Wyrmroot tree").unwrap(),
            request.rust_revision,
            git_tree(&workspace.join("rust"), &request.rust_revision, "Rust tree").unwrap(),
            BUILD_RECEIPT_TOOLCHAIN_REQUEST,
            identity.accepted_toolchain_request_sha256,
            identity.accepted_toolchain_manifest_sha256,
            identity.toolchain_tree_sha256,
            identity.rustc_sha256,
            identity.cargo_sha256,
            identity.rust_lld_sha256,
            identity.llvm_sha256,
            identity.llvm_build_version,
            identity.versions_sha256,
            identity.profiles_sha256,
            request.selector,
            request.test_id,
            BUILD_RECEIPT_LOADER_RECIPE,
            BUILD_RECEIPT_KERNEL_RECIPE,
            WYR0_I_RUST_TARGET,
            BUILD_RECEIPT_NATIVE_RECIPE,
            digest(&artifacts.loader, "loader").unwrap(),
            digest(&artifacts.kernel, "kernel").unwrap(),
            digest(&artifacts.symbols, "symbols").unwrap(),
            digest(&artifacts.bootstrap, "bootstrap").unwrap(),
            digest(&artifacts.init0, "init0").unwrap(),
            digest(&artifacts.hello, "hello").unwrap(),
            digest(&artifacts.ovmf_code, "OVMF code").unwrap(),
            digest(&artifacts.ovmf_vars_template, "OVMF vars").unwrap(),
        );
        fs::write(&artifacts.build_receipt, receipt).expect("write lineage receipt");
        (request, artifacts)
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
        assert_eq!(record.len(), DWEVID1_RECORD_BYTES);
        record
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
            event(0x0A, 2, 0x400, 0x05, 0),
            event(0x0B, 0, 0x400, 0x05, 0),
            event(0x0B, 2, 0x400, 0x05, 0),
            event(0x0C, 1, 0x400, 0x0A, 0),
            event(0x0C, 3, 0x400, 0x0A, 0),
            event(0x0D, 3, 0x400, 0x05, 0x0A),
            event(0x05, 2, 0, 0, 0),
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
            request_sha256: sha256::bytes_digest(b"request"),
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
                protocol: EvidenceProtocol::Dwevid1,
                nonce: TEST_EVIDENCE_NONCE,
                required_mask: h_request::I1_REQUIRED_EVIDENCE_MASK,
            }),
            capability: None,
        }
    }

    #[derive(Clone, Copy)]
    struct CapabilitySpec {
        kind: u8,
        peer: u32,
        generation: u32,
        token: u64,
        arg0: u64,
        arg1: u64,
    }

    fn capability_request(label: &str) -> (PathBuf, HRequest) {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!(
                "xtask-wyr0-i-{label}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system clock before epoch")
                    .as_nanos()
            ));
        fs::create_dir(&root).expect("create WYR0-I fixture");
        let asset = root.join("selector-asset.bin");
        fs::write(&asset, WYR0_I_CANONICAL_ASSET).expect("write selector asset");
        let asset_sha256 = digest(&asset, "test selector asset").expect("hash selector asset");
        let config = root.join("selector-config.toml");
        fs::write(
            &config,
            canonical_selector_config(0x89AB_CDEF_0123_4567, &asset_sha256),
        )
        .expect("write selector config");
        let request = HRequest {
            path: root.join("request.toml"),
            request_sha256: sha256::bytes_digest(b"request"),
            schema_version: 4,
            deepwyrm_revision: "1".repeat(40),
            wyrmroot_revision: "2".repeat(40),
            rust_revision: "3".repeat(40),
            selector: h_request::I_CAPABILITY_SELECTOR.into(),
            test_id: h_request::I_CAPABILITY_TEST_ID,
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
                protocol: EvidenceProtocol::Wrcap1,
                nonce: 0x89AB_CDEF_0123_4567,
                required_mask: h_request::I_CAPABILITY_REQUIRED_EVIDENCE_MASK,
            }),
            capability: Some(CapabilityRequest {
                selector_config: config,
                selector_asset: asset,
                certificate: root.join("certificate.json"),
                capability_summary: root.join("capability.md"),
            }),
        };
        (root, request)
    }

    fn capability_specs(request: &HRequest) -> Vec<CapabilitySpec> {
        let (config, asset) = capability_content_prefixes(request).expect("content prefixes");
        let content_token = config ^ asset;
        assert_ne!(content_token, 0);
        let normal_transaction = wyrmroot_i_capability::NORMAL_TRANSACTION;
        let restart_base = wyrmroot_i_capability::RESTART_TRANSACTION_BASE;
        let exhaust_base = wyrmroot_i_capability::EXHAUST_TRANSACTION_BASE;
        vec![
            CapabilitySpec {
                kind: 0x01,
                peer: 0,
                generation: 0,
                token: content_token,
                arg0: config,
                arg1: asset,
            },
            CapabilitySpec {
                kind: 0x02,
                peer: 1,
                generation: 1,
                token: normal_transaction,
                arg0: 1,
                arg1: 0,
            },
            CapabilitySpec {
                kind: 0x02,
                peer: 1,
                generation: 1,
                token: normal_transaction,
                arg0: 2,
                arg1: 0,
            },
            CapabilitySpec {
                kind: 0x03,
                peer: 1,
                generation: 1,
                token: wyrmroot_i_capability::MEMORY_TRANSACTION,
                arg0: 4096,
                arg1: WYR0_I_MEMORY_RIGHTS,
            },
            CapabilitySpec {
                kind: 0x04,
                peer: 1,
                generation: 1,
                token: wyrmroot_i_capability::CHANNEL_TOKEN,
                arg0: 0x0F,
                arg1: 2,
            },
            CapabilitySpec {
                kind: 0x05,
                peer: 1,
                generation: 1,
                token: wyrmroot_i_capability::WAIT_TOKEN,
                arg0: 0x0F,
                arg1: 0,
            },
            CapabilitySpec {
                kind: 0x06,
                peer: 2,
                generation: 1,
                token: wyrmroot_i_capability::CANCEL_TRANSACTION,
                arg0: WYR0_I_AUTHORIZED_TERMINATION,
                arg1: 0,
            },
            CapabilitySpec {
                kind: 0x07,
                peer: 3,
                generation: 1,
                token: restart_base + 1,
                arg0: 1,
                arg1: 2,
            },
            CapabilitySpec {
                kind: 0x07,
                peer: 3,
                generation: 2,
                token: restart_base + 2,
                arg0: 2,
                arg1: 1,
            },
            CapabilitySpec {
                kind: 0x08,
                peer: 4,
                generation: 1,
                token: exhaust_base + 1,
                arg0: 1,
                arg1: 2,
            },
            CapabilitySpec {
                kind: 0x08,
                peer: 4,
                generation: 2,
                token: exhaust_base + 2,
                arg0: 2,
                arg1: 3,
            },
            CapabilitySpec {
                kind: 0x08,
                peer: 4,
                generation: 3,
                token: exhaust_base + 3,
                arg0: 3,
                arg1: 4,
            },
            CapabilitySpec {
                kind: 0x08,
                peer: 4,
                generation: 4,
                token: exhaust_base + 4,
                arg0: 4,
                arg1: 0,
            },
            CapabilitySpec {
                kind: 0x09,
                peer: 1,
                generation: 1,
                token: normal_transaction,
                arg0: 0x0F,
                arg1: 2,
            },
            CapabilitySpec {
                kind: 0x0A,
                peer: 0,
                generation: 0,
                token: 0,
                arg0: 0,
                arg1: 0,
            },
        ]
    }

    fn capability_line(nonce: u64, sequence: u32, spec: CapabilitySpec) -> Vec<u8> {
        let mut record = format!(
            concat!(
                "WRCAP1|01|{:016X}|{:08X}|{:02X}|{:08X}|{:08X}|",
                "{:016X}|{:016X}|{:016X}|"
            ),
            nonce,
            sequence,
            spec.kind,
            spec.peer,
            spec.generation,
            spec.token,
            spec.arg0,
            spec.arg1,
        )
        .into_bytes();
        record.extend_from_slice(format!("{:08X}\n", fnv1a32(&record)).as_bytes());
        assert_eq!(record.len(), WRCAP1_RECORD_BYTES);
        record
    }

    fn capability_transcript(
        request: &HRequest,
        specs: &[CapabilitySpec],
        terminal_status: &str,
        terminal_detail: u32,
    ) -> Vec<u8> {
        let nonce = request.evidence.expect("evidence request").nonce;
        let mut transcript = b"trusted controller diagnostic\n".to_vec();
        for (sequence, spec) in specs.iter().copied().enumerate() {
            transcript.extend_from_slice(&capability_line(nonce, sequence as u32, spec));
        }
        transcript.extend_from_slice(&terminal(
            terminal_status,
            h_request::I_CAPABILITY_TEST_ID,
            terminal_detail,
        ));
        transcript
    }

    fn mutate_capability_record(
        transcript: &[u8],
        index: usize,
        mutate: impl FnOnce(&mut Vec<u8>),
        repair_checksum: bool,
    ) -> Vec<u8> {
        let mut lines = transcript
            .split_inclusive(|byte| *byte == b'\n')
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        let line = lines
            .iter_mut()
            .filter(|line| line.starts_with(b"WRCAP1"))
            .nth(index)
            .expect("capability record exists");
        mutate(line);
        if repair_checksum && line.len() == WRCAP1_RECORD_BYTES {
            let checksum = format!("{:08X}", fnv1a32(&line[..108]));
            line[108..116].copy_from_slice(checksum.as_bytes());
        }
        lines.concat()
    }

    #[test]
    fn locked_profiles_share_media_contract_but_not_cpu_count() {
        assert_eq!(HProfile::Default.vcpus(), 1);
        assert_eq!(HProfile::Smp.vcpus(), 4);
        assert_eq!(HProfile::Default.memory_mib(), 1024);
        assert_eq!(HProfile::Smp.memory_mib(), 2048);
    }

    #[test]
    fn candidate_init0_profile_must_match_the_selector() {
        assert!(
            validate_init0_profile_bytes("primordial-bootstrap", INIT0_PROFILE_ORDINARY).is_ok()
        );
        assert!(
            validate_init0_profile_bytes(h_request::I1_SELECTOR, INIT0_PROFILE_ORDINARY).is_ok()
        );
        assert!(validate_init0_profile_bytes(I2_SELECTOR, INIT0_PROFILE_I2).is_ok());
        assert!(
            validate_init0_profile_bytes(
                h_request::I_CAPABILITY_SELECTOR,
                INIT0_PROFILE_CAPABILITY,
            )
            .is_ok()
        );
        assert!(
            validate_init0_profile_bytes("primordial-bootstrap", INIT0_PROFILE_CAPABILITY)
                .unwrap_err()
                .message
                .contains("requires exactly one")
        );

        let mut competing = INIT0_PROFILE_ORDINARY.to_vec();
        competing.extend_from_slice(INIT0_PROFILE_CAPABILITY);
        assert!(validate_init0_profile_bytes("primordial-bootstrap", &competing).is_err());
    }

    #[test]
    fn schema_four_content_is_canonical_immutable_and_bootfs_bound() {
        let guest_asset = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../userspace/i-capability/assets/asset.bin"
        ));
        let guest_config = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../userspace/i-capability/assets/config.toml"
        ));
        assert_eq!(
            canonical_selector_config(0x0123_4567_89AB_CDEF, &sha256::bytes_digest(guest_asset)),
            guest_config,
            "host and guest canonical selector config serializations diverged"
        );

        let (root, request) = capability_request("content");
        let capability = request.capability.as_ref().expect("capability request");
        let nonce = request.evidence.expect("evidence request").nonce;
        validate_selector_config(
            &capability.selector_config,
            &capability.selector_asset,
            nonce,
        )
        .expect("canonical selector config rejected");

        for name in [
            "loader.efi",
            "deepwyrm.elf",
            "deepwyrm.symbols",
            "bootstrap.elf",
            "init0.elf",
            "hello.elf",
            "OVMF_CODE.fd",
            "OVMF_VARS.fd",
            BUILD_RECEIPT_FILE,
        ] {
            fs::write(root.join(name), b"artifact").expect("write candidate fixture");
        }
        fs::write(root.join("init0.elf"), INIT0_PROFILE_CAPABILITY)
            .expect("write capability init0 fixture");
        let artifacts = CandidateArtifacts {
            build_receipt: root.join(BUILD_RECEIPT_FILE),
            loader: request.loader.clone(),
            kernel: request.kernel.clone(),
            symbols: request.symbols.clone(),
            bootstrap: request.bootstrap.clone(),
            init0: request.init0.clone(),
            hello: request.hello.clone(),
            selector_config: Some(capability.selector_config.clone()),
            selector_asset: Some(capability.selector_asset.clone()),
            ovmf_code: request.ovmf_code.clone(),
            ovmf_vars_template: request.ovmf_vars_template.clone(),
        };
        let bootfs = build_bootfs_bytes(&artifacts).expect("build capability bootfs");
        let archive =
            wyrmroot_bootfs::archive::Archive::new(&bootfs).expect("parse capability bootfs");
        let config = archive
            .lookup(WYR0_I_CONFIG_BOOTFS_PATH)
            .expect("missing selector config");
        let asset = archive
            .lookup(WYR0_I_ASSET_BOOTFS_PATH)
            .expect("missing selector asset");
        assert!(!config.is_executable());
        assert!(!asset.is_executable());
        assert_eq!(
            config.data(),
            fs::read(&capability.selector_config).unwrap()
        );
        assert_eq!(asset.data(), fs::read(&capability.selector_asset).unwrap());

        let canonical = fs::read_to_string(&capability.selector_config).unwrap();
        for (label, changed) in [
            ("extra", format!("{canonical}unexpected = 1\n")),
            (
                "reordered",
                canonical.replacen("schema_version = 1\n", "", 1) + "schema_version = 1\n",
            ),
            (
                "nonce",
                canonical.replace("89ABCDEF01234567", "89ABCDEF01234568"),
            ),
            (
                "asset",
                canonical.replace(
                    &digest(&capability.selector_asset, "asset").unwrap(),
                    &"0".repeat(64),
                ),
            ),
        ] {
            fs::write(&capability.selector_config, changed).unwrap();
            assert!(
                validate_selector_config(
                    &capability.selector_config,
                    &capability.selector_asset,
                    nonce,
                )
                .is_err(),
                "accepted noncanonical {label} config"
            );
        }
        let alternate_asset = b"alternate-request-bound-asset\n";
        fs::write(&capability.selector_asset, alternate_asset).unwrap();
        fs::write(
            &capability.selector_config,
            canonical_selector_config(nonce, &sha256::bytes_digest(alternate_asset)),
        )
        .unwrap();
        assert!(
            validate_selector_config(
                &capability.selector_config,
                &capability.selector_asset,
                nonce,
            )
            .is_err(),
            "accepted a self-consistent but noncanonical selector asset"
        );
        fs::remove_dir_all(root).expect("remove content fixture");
    }

    #[test]
    fn wrcap1_accepts_only_the_complete_fifteen_record_join_and_matching_terminal() {
        let (root, request) = capability_request("valid-evidence");
        let specs = capability_specs(&request);
        let transcript = capability_transcript(&request, &specs, "01", 0);
        let parsed = parse_transcript(&transcript, &request).expect("valid WRCAP1 rejected");
        assert_eq!(parsed.terminal.outcome, GuestOutcome::Pass);
        let evidence = parsed
            .evidence
            .expect("missing validated capability evidence");
        assert_eq!(evidence.count, WYR0_I_CAPABILITY_EVENT_COUNT);
        assert_eq!(
            evidence.observed_mask,
            h_request::I_CAPABILITY_REQUIRED_EVIDENCE_MASK
        );
        assert_eq!(evidence.first_sequence, 0);
        assert_eq!(evidence.last_sequence, 14);
        let fields = evidence_result_fields(&request, parsed.evidence).unwrap();
        assert!(fields.contains("\"evidence_protocol\":\"wrcap1\""));
        assert!(fields.contains("\"observed_evidence_mask\":1023"));
        fs::remove_dir_all(root).expect("remove evidence fixture");
    }

    #[test]
    fn wrcap1_real_controller_encoder_is_accepted_by_the_host_join() {
        use wyrmroot_i_capability::{EvidenceEvent, EvidenceKind, EvidenceTranscript};

        let (root, request) = capability_request("real-controller-encoder");
        let nonce = request.evidence.expect("evidence request").nonce;
        let mut producer = EvidenceTranscript::new(nonce).expect("nonzero nonce");
        for spec in capability_specs(&request) {
            let kind = match spec.kind {
                0x01 => EvidenceKind::ContentDelivery,
                0x02 => EvidenceKind::ProcessLifecycle,
                0x03 => EvidenceKind::MemoryShare,
                0x04 => EvidenceKind::ChannelLifecycle,
                0x05 => EvidenceKind::WaitEventTimer,
                0x06 => EvidenceKind::Cancellation,
                0x07 => EvidenceKind::RestartReplacement,
                0x08 => EvidenceKind::RestartExhausted,
                0x09 => EvidenceKind::OverloadReplayRejected,
                0x0A => EvidenceKind::CleanupBaseline,
                _ => panic!("unknown capability kind"),
            };
            producer
                .push(EvidenceEvent {
                    kind,
                    peer: spec.peer,
                    generation: spec.generation,
                    token: spec.token,
                    arg0: spec.arg0,
                    arg1: spec.arg1,
                })
                .expect("controller event accepted");
        }

        let mut transcript = b"controller diagnostic\n".to_vec();
        for sequence in 0..producer.len() {
            transcript.extend_from_slice(
                &producer
                    .encoded(sequence)
                    .expect("complete controller transcript"),
            );
        }
        transcript.extend_from_slice(&terminal("01", h_request::I_CAPABILITY_TEST_ID, 0));

        let parsed = parse_transcript(&transcript, &request)
            .expect("host rejected the real controller encoder");
        assert_eq!(parsed.terminal.outcome, GuestOutcome::Pass);
        assert_eq!(
            parsed.evidence.expect("validated evidence").observed_mask,
            h_request::I_CAPABILITY_REQUIRED_EVIDENCE_MASK
        );
        fs::remove_dir_all(root).expect("remove producer fixture");
    }

    #[test]
    fn wrcap1_framing_nonce_sequence_checksum_and_terminal_are_fail_closed() {
        let (root, request) = capability_request("framing");
        let specs = capability_specs(&request);
        let valid = capability_transcript(&request, &specs, "01", 0);

        let first = capability_line(request.evidence.unwrap().nonce, 0, specs[0]);
        for length in 6..WRCAP1_RECORD_BYTES {
            let mut truncated = first[..length].to_vec();
            truncated.extend_from_slice(&terminal("01", 24, 0));
            assert!(
                parse_transcript(&truncated, &request).is_err(),
                "accepted WRCAP1 truncation at {length} bytes"
            );
        }

        let mut cases = Vec::new();
        cases.push(mutate_capability_record(
            &valid,
            0,
            |line| line[..6].make_ascii_lowercase(),
            false,
        ));
        cases.push(mutate_capability_record(
            &valid,
            0,
            |line| line[8] = b'2',
            true,
        ));
        cases.push(mutate_capability_record(
            &valid,
            0,
            |line| line[10] = if line[10] == b'8' { b'9' } else { b'8' },
            true,
        ));
        cases.push(mutate_capability_record(
            &valid,
            1,
            |line| line[34] = b'0',
            true,
        ));
        cases.push(mutate_capability_record(
            &valid,
            0,
            |line| line[36..38].copy_from_slice(b"0B"),
            true,
        ));
        cases.push(mutate_capability_record(
            &valid,
            0,
            |line| line[10] = b'a',
            true,
        ));
        cases.push(mutate_capability_record(
            &valid,
            0,
            |line| line[108] = if line[108] == b'0' { b'1' } else { b'0' },
            false,
        ));
        let mut after_terminal = valid.clone();
        after_terminal.extend_from_slice(&capability_line(
            request.evidence.unwrap().nonce,
            10,
            specs[0],
        ));
        cases.push(after_terminal);
        let mut duplicate_terminal = valid.clone();
        duplicate_terminal.extend_from_slice(&terminal("01", 24, 0));
        cases.push(duplicate_terminal);
        let mut cross_protocol = evidence_line(TEST_EVIDENCE_NONCE, 0, event(0x01, 0, 0, 0, 0));
        cross_protocol.extend_from_slice(&valid);
        cases.push(cross_protocol);
        let mut protocol_diagnostic = b"WRCAP1 diagnostic must not resemble evidence\n".to_vec();
        protocol_diagnostic.extend_from_slice(&valid);
        cases.push(protocol_diagnostic);
        let mut unrelated_lookalike = b"WRCAP10|unrelated output\n".to_vec();
        unrelated_lookalike.extend_from_slice(&valid);
        cases.push(unrelated_lookalike);
        cases.push(capability_transcript(&request, &specs, "02", 0x2401_0001));
        cases.push(capability_transcript(&request, &specs, "01", 1));
        cases.push(capability_transcript(&request, &specs[..14], "01", 0));

        let mut too_many = b"diagnostic\n".to_vec();
        for sequence in 0..=MAX_EVIDENCE_RECORDS {
            too_many.extend_from_slice(&capability_line(
                request.evidence.unwrap().nonce,
                sequence as u32,
                specs[0],
            ));
        }
        too_many.extend_from_slice(&terminal("01", 24, 0));
        cases.push(too_many);

        for (index, transcript) in cases.into_iter().enumerate() {
            assert!(
                parse_transcript(&transcript, &request).is_err(),
                "accepted hostile framing/terminal case {index}"
            );
        }
        fs::remove_dir_all(root).expect("remove framing fixture");
    }

    #[test]
    fn wrcap1_peer_generation_token_and_kind_facts_are_strict() {
        let (root, request) = capability_request("semantic-joins");
        let valid = capability_specs(&request);
        let mut cases = Vec::new();

        let mut mismatched_lifecycle_token = valid.clone();
        mismatched_lifecycle_token[2].token += 1;
        cases.push(mismatched_lifecycle_token);
        let mut unrelated_replay_token = valid.clone();
        unrelated_replay_token[13].token += 1;
        cases.push(unrelated_replay_token);
        let mut wrong_ready_stage = valid.clone();
        wrong_ready_stage[1].arg0 = 2;
        cases.push(wrong_ready_stage);
        let mut wrong_exit_stage = valid.clone();
        wrong_exit_stage[2].arg0 = 1;
        cases.push(wrong_exit_stage);
        let mut wrong_memory_rights = valid.clone();
        wrong_memory_rights[3].arg1 ^= DW_RIGHT_INSPECT.0;
        cases.push(wrong_memory_rights);
        let mut zero_queue_fill = valid.clone();
        zero_queue_fill[4].arg1 = 0;
        cases.push(zero_queue_fill);
        let mut unbounded_queue_fill = valid.clone();
        unbounded_queue_fill[4].arg1 = WYR0_I_CHANNEL_BACKPRESSURE_ATTEMPT_LIMIT;
        cases.push(unbounded_queue_fill);
        let mut wrong_cancellation_reason = valid.clone();
        wrong_cancellation_reason[6].arg0 = u64::from(deepwyrm_abi::DW_TERMINATION_NORMAL_EXIT.0);
        cases.push(wrong_cancellation_reason);

        let mut swapped_restart_generations = valid.clone();
        swapped_restart_generations.swap(7, 8);
        cases.push(swapped_restart_generations);
        let mut skipped_restart_generation = valid.clone();
        skipped_restart_generation[8].generation = 3;
        cases.push(skipped_restart_generation);
        let mut repeated_restart_generation = valid.clone();
        repeated_restart_generation[8].generation = 1;
        cases.push(repeated_restart_generation);
        let mut skipped_restart_token = valid.clone();
        skipped_restart_token[8].token += 1;
        cases.push(skipped_restart_token);

        let mut swapped_exhaust_generations = valid.clone();
        swapped_exhaust_generations.swap(9, 10);
        cases.push(swapped_exhaust_generations);
        let mut skipped_exhaust_generation = valid.clone();
        skipped_exhaust_generation[10].generation = 3;
        cases.push(skipped_exhaust_generation);
        let mut repeated_exhaust_generation = valid.clone();
        repeated_exhaust_generation[10].generation = 1;
        cases.push(repeated_exhaust_generation);
        let mut skipped_exhaust_token = valid.clone();
        skipped_exhaust_token[11].token += 1;
        cases.push(skipped_exhaust_token);

        for index in 1..14 {
            let mut wrong_peer = valid.clone();
            wrong_peer[index].peer = wrong_peer[index].peer.wrapping_add(1);
            cases.push(wrong_peer);
        }
        let mut zero_token = valid.clone();
        zero_token[3].token = 0;
        cases.push(zero_token);
        let mut reused_token = valid.clone();
        reused_token[4].token = reused_token[3].token;
        cases.push(reused_token);
        let mut wrong_cleanup = valid.clone();
        wrong_cleanup[14].arg1 = 1;
        cases.push(wrong_cleanup);
        let mut reordered = valid.clone();
        reordered.swap(2, 3);
        cases.push(reordered);
        let mut wrong_content = valid.clone();
        wrong_content[0].arg0 ^= 1;
        cases.push(wrong_content);

        for (index, specs) in cases.iter().enumerate() {
            let transcript = capability_transcript(&request, specs, "01", 0);
            assert!(
                parse_transcript(&transcript, &request).is_err(),
                "accepted invalid peer/generation/token/join case {index}"
            );
        }

        let mut fifth_exhaustion = valid.clone();
        fifth_exhaustion.insert(
            13,
            CapabilitySpec {
                kind: 0x08,
                peer: 4,
                generation: 5,
                token: valid[12].token + 1,
                arg0: 5,
                arg1: 0,
            },
        );
        assert!(
            parse_transcript(
                &capability_transcript(&request, &fifth_exhaustion, "01", 0),
                &request,
            )
            .is_err(),
            "accepted a fifth exhaustion generation"
        );

        let mut wrong_mask = request.clone();
        wrong_mask.evidence.as_mut().unwrap().required_mask = 0x01FF;
        assert!(
            parse_transcript(
                &capability_transcript(&request, &valid, "01", 0),
                &wrong_mask,
            )
            .is_err()
        );
        fs::remove_dir_all(root).expect("remove semantic fixture");
    }

    #[test]
    fn capability_summary_is_staged_before_certificate_and_rolls_back_on_certificate_failure() {
        let (root, request) = capability_request("certificate-rollback");
        let capability = request.capability.as_ref().expect("capability outputs");
        let outputs = CheckedOutputRoot::open(&request).expect("open output root");

        fs::write(&capability.certificate, b"existing certificate")
            .expect("write certificate collision");
        assert!(
            write_capability_outputs(&outputs, capability, b"new certificate", b"new summary")
                .is_err()
        );
        assert_eq!(
            fs::read(&capability.certificate).unwrap(),
            b"existing certificate"
        );
        // The summary was staged first and then removed when the authoritative
        // create-new certificate publication collided.
        assert!(!capability.capability_summary.exists());

        fs::remove_file(&capability.certificate).expect("remove certificate collision");
        fs::write(&capability.capability_summary, b"existing summary")
            .expect("write summary collision");
        assert!(
            write_capability_outputs(&outputs, capability, b"new certificate", b"new summary")
                .is_err()
        );
        assert!(!capability.certificate.exists());
        assert_eq!(
            fs::read(&capability.capability_summary).unwrap(),
            b"existing summary"
        );

        fs::remove_file(&capability.capability_summary).expect("remove summary collision");
        let staged_certificate =
            h_request::staged_certificate_path(&capability.certificate).unwrap();
        fs::write(&staged_certificate, b"stale staged certificate")
            .expect("write staged certificate collision");
        assert!(
            write_capability_outputs(&outputs, capability, b"new certificate", b"new summary")
                .is_err()
        );
        assert!(!capability.capability_summary.exists());
        assert!(!capability.certificate.exists());
        assert_eq!(
            fs::read(&staged_certificate).unwrap(),
            b"stale staged certificate"
        );
        fs::remove_file(&staged_certificate).expect("remove staged certificate collision");

        write_capability_outputs(&outputs, capability, b"new certificate", b"new summary")
            .expect("publish staged summary and certificate");
        assert_eq!(
            fs::read(&capability.capability_summary).unwrap(),
            b"new summary"
        );
        assert_eq!(
            fs::read(&capability.certificate).unwrap(),
            b"new certificate"
        );
        assert!(!staged_certificate.exists());

        fs::remove_dir_all(root).expect("remove rollback fixture");
    }

    #[test]
    fn certificate_uses_parser_validated_observed_mask_from_both_profiles() {
        let evidence = EvidenceRequest {
            protocol: EvidenceProtocol::Wrcap1,
            nonce: 1,
            required_mask: h_request::I_CAPABILITY_REQUIRED_EVIDENCE_MASK,
        };
        let result = |profile: &str, observed: u32| {
            format!(
                "{{\"profile\":\"{profile}\",\"status\":\"PASS\",\"required_evidence_mask\":1023,\"observed_evidence_mask\":{observed},\"evidence_event_count\":15}}"
            )
        };
        let default = result("default", 1023);
        let smp = result("smp", 1023);
        assert_eq!(
            validated_certificate_observed_mask(evidence, &default, &smp).unwrap(),
            1023
        );

        let incomplete = result("smp", 511);
        assert!(validated_certificate_observed_mask(evidence, &default, &incomplete).is_err());
    }

    #[test]
    fn build_receipt_rejects_other_artifact_or_toolchain_identity_before_media_build() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!(
                "xtask-build-lineage-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system clock before epoch")
                    .as_nanos()
            ));
        let (request, artifacts) = lineage_fixture(&root);
        verify_candidate_inputs(&request).expect("valid build receipt rejected");

        fs::write(&artifacts.hello, b"valid artifact bytes from another build")
            .expect("substitute native artifact");
        let artifact_error = verify_candidate_inputs(&request)
            .expect_err("accepted artifact substituted after receipt creation");
        assert!(artifact_error.message.contains("outputs.hello_sha256"));

        let (_, artifacts) = lineage_fixture(&root);
        let receipt = fs::read_to_string(&artifacts.build_receipt).expect("read receipt");
        let claimed = certificate_identity(&request)
            .expect("certificate identity")
            .rustc_sha256;
        fs::write(
            &artifacts.build_receipt,
            receipt.replace(&claimed, &"0".repeat(64)),
        )
        .expect("substitute toolchain identity");
        let toolchain_error =
            verify_candidate_inputs(&request).expect_err("accepted substituted toolchain identity");
        assert!(toolchain_error.message.contains("rustc_sha256"));

        fs::remove_dir_all(root).expect("remove lineage fixture");
    }

    #[test]
    fn build_receipt_template_matches_the_strict_base_schema() {
        let template = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../toolchain/templates/wyr0-h-build-receipt.toml");
        let values = build_receipt_values(&template).expect("parse build receipt template");
        assert_eq!(
            values.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            BUILD_RECEIPT_KEYS.iter().copied().collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn staged_certificate_path_swap_cannot_publish_different_bytes() {
        let (root, request) = capability_request("certificate-stage-swap");
        let capability = request.capability.as_ref().expect("capability outputs");
        let outputs = CheckedOutputRoot::open(&request).expect("open output root");
        let staged_certificate =
            h_request::staged_certificate_path(&capability.certificate).unwrap();
        let staged_file = write_new_retained(
            &outputs,
            &staged_certificate,
            b"retained certificate",
            "staged WYR0-I capability certificate",
        )
        .expect("write retained staged certificate");

        fs::remove_file(&staged_certificate).expect("unlink retained staging name");
        fs::write(&staged_certificate, b"replacement certificate")
            .expect("replace staged certificate path");

        let error = publish_staged_certificate(
            &outputs,
            &staged_certificate,
            &capability.certificate,
            &staged_file,
        )
        .expect_err("published bytes from a replaced staging path");
        assert!(error.message.contains("changed before atomic publication"));
        assert!(!capability.certificate.exists());
        assert_eq!(
            fs::read(&staged_certificate).unwrap(),
            b"replacement certificate"
        );

        drop(staged_file);
        fs::remove_dir_all(root).expect("remove stage-swap fixture");
    }

    #[test]
    fn rollback_failures_are_reported_instead_of_suppressed() {
        let (root, request) = capability_request("rollback-cleanup-failure");
        let outputs = CheckedOutputRoot::open(&request).expect("open output root");
        let stuck = root.join("stuck-output");
        fs::create_dir(&stuck).expect("create non-file rollback target");

        let error = with_rollback(
            Failure::task("publication failed"),
            rollback_created(&outputs, &[(&stuck, "stuck capability output")]),
        );
        assert!(error.message.contains("publication failed"));
        assert!(error.message.contains("rollback failed"));
        assert!(stuck.exists());

        fs::remove_dir_all(root).expect("remove rollback fixture");
    }

    #[test]
    fn identity_reader_rejects_duplicate_or_non_sha256_component_claims() {
        let (root, _) = capability_request("certificate-identity-reader");
        let path = root.join("identity.toml");
        fs::write(
            &path,
            "[artifacts]\nrust_lld_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
        )
        .expect("write identity fixture");
        let values = identity_toml(&path, "identity fixture").expect("parse identity fixture");
        assert_eq!(
            required_sha256_identity_value(
                &values,
                "artifacts.rust_lld_sha256",
                "identity fixture"
            )
            .unwrap(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );

        fs::write(&path, "[artifacts]\nrust_lld_sha256 = \"not-a-sha256\"\n")
            .expect("write invalid identity fixture");
        let values =
            identity_toml(&path, "identity fixture").expect("parse invalid identity fixture");
        assert!(
            required_sha256_identity_value(
                &values,
                "artifacts.rust_lld_sha256",
                "identity fixture"
            )
            .is_err()
        );

        fs::write(
            &path,
            "[artifacts]\nrust_lld_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\nrust_lld_sha256 = \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\n",
        )
        .expect("write duplicate identity fixture");
        assert!(identity_toml(&path, "identity fixture").is_err());
        fs::remove_dir_all(root).expect("remove identity fixture");
    }

    #[test]
    fn certificate_identity_uses_the_accepted_record_not_host_llvm_programs() {
        let (root, mut request) = capability_request("certificate-identity");
        let repository = crate::tasks::repository_root().expect("locate Wyrmroot repository");
        let deepwyrm = source_workspace_root(&repository)
            .expect("locate source workspace")
            .join("deepwyrm");
        request.deepwyrm_revision = git_output(&deepwyrm, &["rev-parse", "HEAD"], "Deepwyrm")
            .expect("read current Deepwyrm revision")
            .trim()
            .to_owned();
        request.rust_revision = "a92dc7f7464ad6ddfece4402bd7b86dbfa86166d".to_owned();

        let identity = certificate_identity(&request).expect("derive certificate identity");
        assert!(identity.generated_schema_bound);
        assert_eq!(identity.rust_target, WYR0_I_RUST_TARGET);
        assert_eq!(identity.llvm_build_version, "22.1.6");
        assert_eq!(identity.rust_lld_sha256.len(), 64);
        assert_eq!(identity.llvm_sha256.len(), 64);
        fs::remove_dir_all(root).expect("remove identity fixture");
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
                count: 19,
                observed_mask: 255,
                first_sequence: 0,
                last_sequence: 18,
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
                "\"evidence_event_count\":19,\"first_evidence_sequence\":0,",
                "\"last_evidence_sequence\":18,"
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
        for length in 0..DWEVID1_RECORD_BYTES {
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

        let invariant_index = valid_evidence_specs().len() - 1;
        let mut invariant_violation = valid_evidence_specs();
        invariant_violation[invariant_index].arg0 = 1;
        cases.push(("running violation", invariant_violation));

        let mut invariant_before_activity = valid_evidence_specs();
        let reclaim_index = invariant_before_activity.len() - 2;
        let invariant_index = invariant_before_activity.len() - 1;
        invariant_before_activity.swap(reclaim_index, invariant_index);
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

        let mut missing_tlb_ack = valid_evidence_specs();
        missing_tlb_ack.remove(14);
        cases.push(("missing TLB ack", missing_tlb_ack));

        let mut duplicate_rendezvous_cpu = valid_evidence_specs();
        duplicate_rendezvous_cpu[16].cpu = 1;
        cases.push(("duplicate rendezvous CPU", duplicate_rendezvous_cpu));

        let mut wrong_ack_token = valid_evidence_specs();
        wrong_ack_token[14].token = 0x401;
        cases.push(("wrong ack token", wrong_ack_token));

        let mut wrong_ack_mask = valid_evidence_specs();
        wrong_ack_mask[16].arg0 = 0x08;
        cases.push(("wrong ack mask", wrong_ack_mask));

        let mut early_reclaim = valid_evidence_specs();
        let reclaim = early_reclaim.remove(17);
        early_reclaim.insert(14, reclaim);
        cases.push(("early reclaim", early_reclaim));

        let mut wrong_reclaim_mask = valid_evidence_specs();
        wrong_reclaim_mask[17].arg1 = 0x02;
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
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("xtask-h-qemu-plan-test-{}", std::process::id()));
        fs::create_dir(&root).expect("create QEMU plan fixture");
        let request = HRequest {
            path: root.join("request.toml"),
            request_sha256: sha256::bytes_digest(b"request"),
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
            capability: None,
        };
        let artifacts = CandidateArtifacts {
            build_receipt: root.join(BUILD_RECEIPT_FILE),
            loader: request.loader.clone(),
            kernel: request.kernel.clone(),
            symbols: request.symbols.clone(),
            bootstrap: request.bootstrap.clone(),
            init0: request.init0.clone(),
            hello: request.hello.clone(),
            selector_config: None,
            selector_asset: None,
            ovmf_code: request.ovmf_code.clone(),
            ovmf_vars_template: request.ovmf_vars_template.clone(),
        };
        let run = test_run_paths(&root, "result.json");
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
        assert!(joined.contains("readonly=on,file=/proc/self/fd/"));
        assert!(joined.contains("isa-debug-exit"));
        for forbidden in ["virtfs", "virtiofs", "9p", "-net", "user,id="] {
            assert!(!joined.contains(forbidden));
        }
        assert!(
            gdb_arguments(&run.symbols)
                .join(" ")
                .contains("file /proc/self/fd/")
        );
        fs::remove_dir_all(root).expect("remove QEMU plan fixture");
    }

    #[test]
    fn run_snapshot_descriptor_survives_path_replacement_after_hashing() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!(
                "xtask-h-open-snapshot-race-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system clock before epoch")
                    .as_nanos()
            ));
        fs::create_dir(&root).expect("create snapshot race root");
        let request_path = root.join("request.toml");
        fs::write(&request_path, b"request").expect("write snapshot race request");
        let request = HRequest {
            path: request_path,
            ..i1_request()
        };
        let outputs = CheckedOutputRoot::open(&request).expect("open snapshot race root");
        let directory = root.join("run");
        outputs
            .create_dir(&directory, "snapshot race run")
            .expect("create snapshot race run");
        let path = directory.join("esp.img");
        let snapshot = create_run_file(&outputs, &path, b"trusted-media", true)
            .expect("create stable run snapshot");

        fs::rename(&path, directory.join("retained-esp.img"))
            .expect("rename snapshot path after hashing");
        fs::write(&path, b"attacker-media").expect("replace snapshot path");
        let mut opened = fs::File::open(snapshot.child_path())
            .expect("open the descriptor path that QEMU receives");
        let mut bytes = Vec::new();
        opened
            .read_to_end(&mut bytes)
            .expect("read inherited snapshot descriptor");

        assert_eq!(bytes, b"trusted-media");
        assert_eq!(snapshot.digest, sha256::bytes_digest(b"trusted-media"));
        snapshot
            .verify_unchanged("ESP")
            .expect("path replacement changed opened snapshot");
        assert_eq!(
            fs::read(&path).expect("read replacement"),
            b"attacker-media"
        );
        snapshot
            .set_inheritable(true)
            .expect("make snapshot descriptor inheritable");
        // SAFETY: snapshot owns this live descriptor and F_GETFD takes no third argument.
        let flags = unsafe { fcntl(snapshot.file.as_raw_fd(), F_GETFD) };
        assert_eq!(flags & FD_CLOEXEC, 0);
        snapshot
            .set_inheritable(false)
            .expect("restore close-on-exec");
        drop(snapshot);
        fs::remove_dir_all(root).expect("remove snapshot race fixture");
    }

    #[test]
    fn opened_esp_snapshot_size_policy_is_exact_and_bounded() {
        assert_eq!(MAX_WYR0_H_ESP_SNAPSHOT_BYTES, 134_217_728);
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!(
                "xtask-h-esp-size-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system clock before epoch")
                    .as_nanos()
            ));
        fs::create_dir(&root).expect("create ESP size fixture");

        let exact_path = root.join("exact.img");
        let exact = fs::File::create(&exact_path).expect("create exact-size ESP");
        exact
            .set_len(MAX_WYR0_H_ESP_SNAPSHOT_BYTES)
            .expect("size exact ESP");
        drop(exact);
        let bytes = read_opened_regular(
            fs::File::open(&exact_path).expect("open exact-size ESP"),
            "ESP",
            MAX_WYR0_H_ESP_SNAPSHOT_BYTES,
        )
        .expect("rejecting the canonical ESP size");
        assert_eq!(
            u64::try_from(bytes.len()).expect("ESP length fits u64"),
            MAX_WYR0_H_ESP_SNAPSHOT_BYTES
        );
        drop(bytes);

        let oversized_path = root.join("oversized.img");
        let oversized = fs::File::create(&oversized_path).expect("create oversized ESP");
        oversized
            .set_len(MAX_WYR0_H_ESP_SNAPSHOT_BYTES + 1)
            .expect("size oversized ESP");
        drop(oversized);
        assert!(
            read_opened_regular(
                fs::File::open(&oversized_path).expect("open oversized ESP"),
                "ESP",
                MAX_WYR0_H_ESP_SNAPSHOT_BYTES,
            )
            .is_err()
        );

        let empty_path = root.join("empty.img");
        fs::File::create(&empty_path).expect("create empty ESP");
        assert!(
            read_opened_regular(
                fs::File::open(&empty_path).expect("open empty ESP"),
                "ESP",
                MAX_WYR0_H_ESP_SNAPSHOT_BYTES,
            )
            .is_err()
        );
        assert!(
            read_opened_regular(
                fs::File::open(&root).expect("open nonregular ESP fixture"),
                "ESP",
                MAX_WYR0_H_ESP_SNAPSHOT_BYTES,
            )
            .is_err()
        );

        fs::remove_dir_all(root).expect("remove ESP size fixture");
    }

    #[test]
    fn paired_join_requires_both_profiles_and_preserves_both_failures() {
        let inspection = "{\"status\":\"PASS\"}\n";
        let candidate = "a".repeat(64);
        let default = format!(
            "{{\"profile\":\"default\",\"status\":\"PASS\",\"candidate_sha256\":\"{candidate}\"}}\n"
        );
        let smp = format!(
            "{{\"profile\":\"smp\",\"status\":\"PASS\",\"candidate_sha256\":\"{candidate}\"}}\n"
        );
        let (joined, _, _) =
            join_profile_result_json(inspection, Ok(default.clone()), Ok(smp.clone()), 2)
                .expect("paired successful profiles rejected");
        assert!(joined.contains("\"same_media\":true"));
        assert!(joined.contains("\"default\":{\"profile\":\"default\""));
        assert!(joined.contains("\"smp\":{\"profile\":\"smp\""));

        let mismatched = smp.replace(&candidate, &"b".repeat(64));
        let failure = join_profile_result_json(inspection, Ok(default), Ok(mismatched), 2)
            .expect_err("paired candidates with different exact bytes were accepted");
        assert!(failure.message.contains("different run-local candidates"));

        let failure = join_profile_result_json(
            inspection,
            Err(Failure::task("default failed")),
            Err(Failure::task("smp failed")),
            2,
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
            request_sha256: sha256::bytes_digest(b"request"),
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
            capability: None,
        };
        fs::write(&request.path, b"request").expect("write request");
        fs::write(root.join(BUILD_RECEIPT_FILE), b"receipt").expect("write receipt");
        let outputs = CheckedOutputRoot::open(&request).expect("open checked output root");
        let run = test_run_paths(&root, "result.json");
        let artifacts = CandidateArtifacts {
            build_receipt: root.join(BUILD_RECEIPT_FILE),
            loader: request.loader.clone(),
            kernel: request.kernel.clone(),
            symbols: request.symbols.clone(),
            bootstrap: request.bootstrap.clone(),
            init0: request.init0.clone(),
            hello: request.hello.clone(),
            selector_config: None,
            selector_asset: None,
            ovmf_code: request.ovmf_code.clone(),
            ovmf_vars_template: request.ovmf_vars_template.clone(),
        };
        write_integration_host_failure(
            HProfile::Smp,
            &request,
            &artifacts,
            &outputs,
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
        assert!(result.contains("\"build_receipt_sha256\":"));
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
            let error_run = test_run_paths(&root, name);
            write_integration_host_failure(
                HProfile::Smp,
                &request,
                &artifacts,
                &outputs,
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

        let i1_failure_run = test_run_paths(&root, "i1-error-result.json");
        let i1_request = HRequest {
            schema_version: 3,
            selector: "smp-runtime-acceptance".into(),
            test_id: 23,
            evidence: Some(EvidenceRequest {
                protocol: EvidenceProtocol::Dwevid1,
                nonce: TEST_EVIDENCE_NONCE,
                required_mask: h_request::I1_REQUIRED_EVIDENCE_MASK,
            }),
            ..request.clone()
        };
        write_integration_host_failure(
            HProfile::Smp,
            &i1_request,
            &artifacts,
            &outputs,
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
            BUILD_RECEIPT_FILE,
        ] {
            fs::write(root.join(name), b"artifact").expect("write test artifact");
        }
        fs::write(root.join("deepwyrm.symbols"), b"different").expect("write symbols");
        let request = HRequest {
            path: root.join("request.toml"),
            request_sha256: sha256::bytes_digest(b"artifact"),
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
            capability: None,
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
            BUILD_RECEIPT_FILE,
        ] {
            fs::write(root.join(name), b"artifact").expect("write test artifact");
        }
        let request = HRequest {
            path: root.join("request.toml"),
            request_sha256: sha256::bytes_digest(b"artifact"),
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
            capability: None,
        };
        let artifacts = CandidateArtifacts {
            build_receipt: root.join(BUILD_RECEIPT_FILE),
            loader: request.loader.clone(),
            kernel: request.kernel.clone(),
            symbols: request.symbols.clone(),
            bootstrap: request.bootstrap.clone(),
            init0: request.init0.clone(),
            hello: request.hello.clone(),
            selector_config: None,
            selector_asset: None,
            ovmf_code: request.ovmf_code.clone(),
            ovmf_vars_template: request.ovmf_vars_template.clone(),
        };
        let first = candidate_digests(&request, &artifacts).expect("first digest");
        let second = candidate_digests(&request, &artifacts).expect("second digest");
        assert_eq!(first.candidate, second.candidate);
        fs::write(&request.hello, b"changed").expect("mutate hello");
        let changed = candidate_digests(&request, &artifacts).expect("changed digest");
        assert_ne!(first.candidate, changed.candidate);
        fs::write(&request.hello, b"artifact").expect("restore hello");
        fs::write(&artifacts.build_receipt, b"different receipt").expect("substitute receipt");
        let changed_receipt =
            candidate_digests(&request, &artifacts).expect("receipt-bound digest");
        assert_ne!(first.candidate, changed_receipt.candidate);
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
        fs::write(root.join("init0.elf"), INIT0_PROFILE_ORDINARY)
            .expect("write ordinary init0 fixture");
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
        let artifacts = CandidateArtifacts {
            build_receipt: root.join(BUILD_RECEIPT_FILE),
            loader: request.loader.clone(),
            kernel: request.kernel.clone(),
            symbols: request.symbols.clone(),
            bootstrap: request.bootstrap.clone(),
            init0: request.init0.clone(),
            hello: request.hello.clone(),
            selector_config: None,
            selector_asset: None,
            ovmf_code: request.ovmf_code.clone(),
            ovmf_vars_template: request.ovmf_vars_template.clone(),
        };
        let run = test_run_paths(&root, "unused-result.json");
        fs::write(
            &path,
            request_text.replace("expected_detail = 0", "expected_detail = 1"),
        )
        .expect("mutate request");
        let error = revalidate_before_pass(&request, &artifacts, &run, "unused")
            .expect_err("mutated request accepted for PASS");
        assert!(error.message.contains("request changed after inspection"));
        fs::remove_dir_all(root).expect("remove test root");
    }
}
