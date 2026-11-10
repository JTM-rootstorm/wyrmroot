//! The generation-neutral native-artifact build and inspect engine.
//!
//! Structural refactor S2T (`DW1_WYR1_STRUCTURAL_REFACTOR_PLAN.md` §4 S2T
//! item 1). This is a move out of `wyr1c.rs`, behavior-preserving: every item
//! below is unchanged from its previous form in that file, and `wyr1c.rs`
//! re-exports all of them (`pub(crate) use crate::product_engine::*;`) so
//! every existing `wyr1c::` path -- `wyr1c::NativeSpec`, `wyr1c::build_native`,
//! `wyr1c::inspect_native_bytes`, and so on -- keeps compiling unchanged.
//!
//! What moved here is exactly the part of `wyr1c.rs` that does not vary by
//! generation: a native binary is built the same way and inspected the same
//! way whether the caller is preparing a C6, E3A, D5, E6, E7, E8 or F product.
//! The per-generation product-spec tables, snapshot builders, product
//! assemblers and product-specific validators stay in `wyr1c.rs` (structural
//! cause 4 in the plan's §1 -- "generation unnesting" is explicitly not this
//! phase's authorized scope, so those stay nested where they were).
//!
//! Checked behavior-preserving by: `cargo test -- --list` test-count parity
//! for the `xtask` binary before and after the move, and a byte-identical
//! `wyr1f prepare --scenario normal` artifact digest set before and after
//! (both recorded in the commit that performs this move).

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use crate::error::Failure;
use crate::secure_fs::{InheritableDirectory, SealedFile};
use crate::sha256;

/// The exact accepted Rust revision and toolchain name every frozen snapshot
/// and product is built and re-verified against, whichever generation it is.
pub(crate) const ACCEPTED_RUST_REVISION: &str = "a92dc7f7464ad6ddfece4402bd7b86dbfa86166d";
pub(crate) const ACCEPTED_TOOLCHAIN_NAME: &str = "wyrmroot-1.97.1-a92dc7f7";
/// The one native target every product's roles are built for.
pub(crate) const NATIVE_TARGET: &str = "x86_64-unknown-wyrmroot";
pub(crate) const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_BOOTFS_BYTES: usize = crate::g3_image::IMAGE_BYTES as usize;
pub(crate) const MAX_REPORT_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeSpec {
    pub(crate) label: &'static str,
    pub(crate) package: &'static str,
    pub(crate) binary: &'static str,
    pub(crate) features: &'static str,
    pub(crate) artifact: &'static str,
}

#[derive(Clone)]
pub(crate) struct NativeArtifact {
    pub(crate) spec: NativeSpec,
    pub(crate) bytes: Vec<u8>,
    pub(crate) sha256: String,
    pub(crate) inspection: String,
}

pub(crate) fn build_native(
    repository: &Path,
    cargo_home: &Path,
    toolchain: &crate::toolchain_artifact::AcceptedToolchain,
    build_directory: &InheritableDirectory,
    spec: NativeSpec,
    evidence_nonce: Option<&str>,
) -> Result<NativeArtifact, Failure> {
    build_native_with_flags(
        repository,
        cargo_home,
        toolchain,
        build_directory,
        spec,
        evidence_nonce,
        NativeBuildOptions::historical(),
    )
}

#[derive(Clone, Copy)]
pub(crate) struct NativeBuildOptions<'a> {
    pub(crate) extra_flags: &'a [&'a str],
    pub(crate) exact_environment: bool,
    pub(crate) evidence_variable: &'static str,
}

impl NativeBuildOptions<'_> {
    pub(crate) const fn historical() -> Self {
        Self {
            extra_flags: &[],
            exact_environment: false,
            evidence_variable: "DEEPWYRM_DW1E_EVIDENCE_NONCE",
        }
    }

    pub(crate) const fn exact(extra_flags: &'static [&'static str]) -> Self {
        Self {
            extra_flags,
            exact_environment: true,
            evidence_variable: "DEEPWYRM_DW1E_EVIDENCE_NONCE",
        }
    }

    pub(crate) const fn exact_wyr1e8() -> Self {
        Self::exact_with_evidence("WYRMROOT_WYR1E8_EVIDENCE_NONCE")
    }

    pub(crate) const fn exact_with_evidence(evidence_variable: &'static str) -> Self {
        Self::exact_with_evidence_and_flags(evidence_variable, &[])
    }

    /// The exact environment, a chosen evidence variable, and explicit
    /// rustflags.
    ///
    /// `exact_with_evidence` alone cannot express the production shell build:
    /// `system/wyrmsh` is built with `-Cjump-tables=no -Zemit-stack-sizes` in
    /// every accepted product, which `WYR1_E6_VALIDATION.md` records as the
    /// *production* shell setting rather than test instrumentation. A product
    /// that omits them ships a different shell binary and loses the stack-size
    /// sections the native stack proof reads.
    pub(crate) const fn exact_with_evidence_and_flags(
        evidence_variable: &'static str,
        extra_flags: &'static [&'static str],
    ) -> Self {
        Self {
            extra_flags,
            exact_environment: true,
            evidence_variable,
        }
    }
}

pub(crate) fn build_native_with_flags(
    repository: &Path,
    cargo_home: &Path,
    toolchain: &crate::toolchain_artifact::AcceptedToolchain,
    build_directory: &InheritableDirectory,
    spec: NativeSpec,
    evidence_nonce: Option<&str>,
    options: NativeBuildOptions<'_>,
) -> Result<NativeArtifact, Failure> {
    let target = build_directory.path().join(spec.label);
    fs::create_dir(&target)
        .map_err(|error| Failure::task(format!("could not create native target: {error}")))?;
    let exact_temp = target.join(".tmp");
    if options.exact_environment {
        fs::create_dir(&exact_temp).map_err(|error| {
            Failure::task(format!(
                "could not create E6 native temporary directory: {error}"
            ))
        })?;
        fs::set_permissions(&exact_temp, fs::Permissions::from_mode(0o700)).map_err(|error| {
            Failure::task(format!(
                "could not seal E6 native temporary directory: {error}"
            ))
        })?;
    }
    let mut flags = native_remap_flags(repository, cargo_home, &target)?;
    for flag in options.extra_flags {
        flags.push('\u{1f}');
        flags.push_str(flag);
    }
    let arguments = [
        "build",
        "--offline",
        "--locked",
        "--release",
        "--target",
        NATIVE_TARGET,
        "--package",
        spec.package,
        "--bin",
        spec.binary,
        "--no-default-features",
        "--features",
        spec.features,
    ];
    build_directory.verify_unchanged("WYR1-C1 build scratch")?;
    let mut command = Command::new(&toolchain.cargo);
    if options.exact_environment {
        let cargo_bin = toolchain
            .cargo
            .parent()
            .ok_or_else(|| Failure::task("accepted Cargo has no parent directory"))?;
        let path = env::join_paths([
            cargo_bin,
            Path::new("/usr/lib/llvm/22/bin"),
            Path::new("/usr/bin"),
            Path::new("/bin"),
        ])
        .map_err(|_| Failure::task("accepted Cargo path cannot be encoded for subprocess use"))?;
        command.env_clear().env("PATH", path).env("LC_ALL", "C");
        command.env("TMPDIR", &exact_temp);
    }
    command
        .args(arguments)
        .arg("--target-dir")
        .arg(&target)
        .env("RUSTC", &toolchain.rustc)
        .env("CARGO_HOME", cargo_home)
        .env("CARGO_ENCODED_RUSTFLAGS", flags)
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_NET_OFFLINE", "true")
        .env("SOURCE_DATE_EPOCH", "0")
        .env_remove("LD_AUDIT")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD")
        .current_dir(repository)
        .stdin(Stdio::null());
    if let Some(nonce) = evidence_nonce {
        command.env(options.evidence_variable, nonce);
    } else {
        command.env_remove(options.evidence_variable);
    }
    for variable in [
        "DEEPWYRM_DW1E_EVIDENCE_NONCE",
        "WYRMROOT_WYR1E7_EVIDENCE_NONCE",
        "WYRMROOT_WYR1E8_EVIDENCE_NONCE",
    ] {
        if variable != options.evidence_variable {
            command.env_remove(variable);
        }
    }
    let status = command.status();
    build_directory.verify_unchanged("WYR1-C1 build scratch")?;
    let status = status
        .map_err(|error| Failure::task(format!("could not build {}: {error}", spec.label)))?;
    if !status.success() {
        return Err(Failure::task(format!(
            "WYR1-C1 canonical {} build failed",
            spec.label
        )));
    }
    let artifact = PathBuf::from(spec.label)
        .join(NATIVE_TARGET)
        .join("release")
        .join(spec.artifact);
    let bytes = build_directory.read_producer(&artifact, MAX_ARTIFACT_BYTES as u64, spec.label)?;
    let sha256 = sha256::bytes_digest(&bytes);
    Ok(NativeArtifact {
        spec,
        bytes,
        sha256,
        inspection: String::new(),
    })
}

pub(crate) fn native_remap_flags(
    repository: &Path,
    cargo_home: &Path,
    target: &Path,
) -> Result<String, Failure> {
    let repository = fs::canonicalize(repository)
        .map_err(|error| Failure::task(format!("could not resolve source root: {error}")))?;
    let cargo_home = fs::canonicalize(cargo_home)
        .map_err(|error| Failure::task(format!("could not resolve Cargo home: {error}")))?;
    let target = fs::canonicalize(target)
        .map_err(|error| Failure::task(format!("could not resolve target root: {error}")))?;
    Ok([
        format!(
            "--remap-path-prefix={}=/source/wyrmroot",
            repository.display()
        ),
        format!("--remap-path-prefix={}=/cargo-home", cargo_home.display()),
        format!("--remap-path-prefix={}=/cargo-target", target.display()),
    ]
    .join("\u{1f}"))
}

pub(crate) fn native_command(spec: NativeSpec) -> String {
    format!(
        "cargo build --offline --locked --release --target {NATIVE_TARGET} --package {} --bin {} --no-default-features --features {}",
        spec.package, spec.binary, spec.features
    )
}

pub(crate) fn inspect_native(
    repository: &Path,
    bytes: &[u8],
    expected_sha256: &str,
    label: &str,
    build_directory: &InheritableDirectory,
) -> Result<String, Failure> {
    build_directory.with_inheritance_disabled("WYR1-C1 build scratch", || {
        inspect_native_bytes(repository, bytes, expected_sha256, label)
    })
}

pub(crate) fn inspect_native_bytes(
    repository: &Path,
    bytes: &[u8],
    expected_sha256: &str,
    label: &str,
) -> Result<String, Failure> {
    let sealed = SealedFile::from_bytes(bytes, &format!("WYR1-C {label}"))?;
    let output = sealed.with_inheritable_path(&format!("WYR1-C {label}"), |artifact| {
        run_native_inspector(
            repository,
            &repository.join("toolchain/inspect-native-artifact.sh"),
            artifact,
            label,
        )
    })?;
    if !output.status.success()
        || output.stdout.is_empty()
        || output.stdout.len() > MAX_REPORT_BYTES
        || output.stderr.len() > MAX_REPORT_BYTES
    {
        return Err(Failure::task(format!(
            "WYR1-C canonical inspection failed for {label}"
        )));
    }
    let report = String::from_utf8(output.stdout)
        .map_err(|_| Failure::task("WYR1-C native inspection report is not UTF-8"))?;
    validate_inspection(&report, label, expected_sha256, bytes.len())?;
    Ok(report)
}

fn run_native_inspector(
    repository: &Path,
    script: &Path,
    artifact: &Path,
    label: &str,
) -> Result<Output, Failure> {
    Command::new(crate::tasks::INSPECTION_SHELL)
        .arg(script)
        .arg(artifact)
        .current_dir(repository)
        .env_clear()
        .env("PATH", crate::tasks::INSPECTION_PATH)
        .env("WYRMROOT_INSPECTION_ARTIFACT_NAME", label)
        .env("WYRMROOT_SEALED_INSPECTION", "1")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| Failure::task(format!("could not inspect WYR1-C1 {label}: {error}")))
}

#[cfg(test)]
pub(crate) fn run_native_inspector_environment_probe(
    repository: &Path,
    script: &Path,
) -> Result<String, Failure> {
    let output = run_native_inspector(repository, script, Path::new("/dev/null"), "probe")?;
    if !output.status.success() {
        return Err(Failure::task(
            "WYR1-C1 native inspector environment probe failed",
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| Failure::task("WYR1-C1 native inspector environment probe is not UTF-8"))
}

pub(crate) fn validate_inspection(
    report: &str,
    label: &str,
    digest: &str,
    size: usize,
) -> Result<(), Failure> {
    if !report.ends_with('\n') || report.contains('\r') {
        return Err(Failure::task("WYR1-C1 inspection line endings drifted"));
    }
    let body = report
        .strip_suffix('\n')
        .and_then(|value| value.strip_prefix('{'))
        .and_then(|value| value.strip_suffix('}'))
        .ok_or_else(|| Failure::task("WYR1-C1 inspection JSON is malformed"))?;
    let mut fields = BTreeMap::new();
    for field in body.split(',') {
        let (key, value) = field
            .split_once(':')
            .ok_or_else(|| Failure::task("WYR1-C1 inspection field is malformed"))?;
        let key = key
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .ok_or_else(|| Failure::task("WYR1-C1 inspection key is malformed"))?;
        if fields.insert(key, value).is_some() {
            return Err(Failure::task("WYR1-C1 inspection key is duplicate"));
        }
    }
    let expected_keys = [
        "schema_version",
        "report_kind",
        "verified",
        "artifact",
        "sha256",
        "size",
        "osabi",
        "abi_version",
        "program_headers",
        "load_segments",
        "syscall_veneers",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let expected_artifact = format!("\"{label}\"");
    let expected_digest = format!("\"{digest}\"");
    let expected_size = size.to_string();
    if fields.keys().copied().collect::<BTreeSet<_>>() != expected_keys
        || fields.get("schema_version") != Some(&"1")
        || fields.get("report_kind") != Some(&"\"wyrmroot-wyr0-native-artifact-inspection\"")
        || fields.get("verified") != Some(&"true")
        || fields.get("artifact") != Some(&expected_artifact.as_str())
        || fields.get("sha256") != Some(&expected_digest.as_str())
        || fields.get("size") != Some(&expected_size.as_str())
        || fields.get("osabi") != Some(&"0")
        || fields.get("abi_version") != Some(&"0")
        || fields.get("syscall_veneers") != Some(&"1")
        || !["program_headers", "load_segments"].into_iter().all(|key| {
            fields
                .get(key)
                .is_some_and(|value| !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
        })
    {
        return Err(Failure::task(format!(
            "WYR1-C1 inspection did not exactly bind {label}"
        )));
    }
    Ok(())
}

pub(crate) fn validate_revision(revision: &str, label: &str) -> Result<(), Failure> {
    if revision.len() != 40
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Failure::task(format!(
            "{label} revision is not a commit ID"
        )));
    }
    Ok(())
}

pub(crate) fn validate_commit(
    repository: &Path,
    revision: &str,
    label: &str,
) -> Result<(), Failure> {
    validate_revision(revision, label)?;
    let commit = format!("{revision}^{{commit}}");
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["rev-parse", "--verify", &commit])
        .output()
        .map_err(|error| Failure::task(format!("could not inspect {label} commit: {error}")))?;
    if !output.status.success()
        || std::str::from_utf8(&output.stdout).ok().map(str::trim) != Some(revision)
    {
        return Err(Failure::task(format!(
            "declared {label} revision is not that exact commit"
        )));
    }
    Ok(())
}

pub(crate) fn git_file(repository: &Path, revision: &str, path: &str) -> Result<Vec<u8>, Failure> {
    let object = format!("{revision}:{path}");
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["show", &object])
        .output()
        .map_err(|error| Failure::task(format!("could not inspect historical {path}: {error}")))?;
    if !output.status.success() {
        return Err(Failure::task(format!(
            "declared WYR1-C1 revision lacks {path}"
        )));
    }
    Ok(output.stdout)
}
