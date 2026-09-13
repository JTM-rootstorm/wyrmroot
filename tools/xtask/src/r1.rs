//! Reset card R1's frozen product assembly.
//!
//! `cargo xtask r1 product` builds the card's payloads with the accepted
//! toolchain, composes its WRRM, WRDM, launch policy and both `WRR1` profile
//! configurations, and freezes two bootfs archives — one per profile handoff.
//! It produces no media, no domain XML and no VM request: the project's command
//! split puts those in a follow-on `prepare`, exactly as `wyr1c1 product` and
//! `wyr1c6 prepare` are separated, and this command mints nothing a VM run
//! could consume directly.
//!
//! Almost everything here is reuse. The accepted-toolchain build, artifact
//! inspection, freshness checks, ambient-environment rejection and revision
//! pinning are `wyr1c`'s, unchanged; the role graph is WYR1-C1's; the hog is the
//! existing `bin/cpu-hog` payload. What is R1's own is the policy, the two
//! configurations, and the cross-binds between them.

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsStr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use wyrmroot_bootfs::launch_policy::encode as encode_launch_policy;
use wyrmroot_bootfs::r1::{
    ACCEPTED_TOPOLOGIES, ProbeConfiguration, ProductR1, R1_GATE_BYTES, R1_POLICY_ENTRY_COUNT,
    build_r1, encode_gate, launch_policy_entries,
};
use wyrmroot_bootfs::wyr1::{Product, ProductC1, WYR1_C1_MARKER};
use wyrmroot_device_proto::manifest::{
    ContentIdentity, HEADER_BYTES as WRDM_HEADER_BYTES, RECORD_BYTES as WRDM_RECORD_BYTES,
    encode_com2_manifest,
};
use wyrmroot_rrc_manifest::StartupProfile;

use crate::error::Failure;
use crate::metadata::BuildManifest;
use crate::sha256;
use crate::wyr1c::{
    NativeArtifact, NativeBuildOptions, NativeSpec, build_native_with_flags,
    clean_repository_revision, inspect_native, reject_ambient_build_environment,
    validate_fresh_output, verify_repository_revision,
};

const PRODUCT_KIND: &str = "wyr1-r1-saturation";
const ACCEPTED_RUST_REVISION: &str = "a92dc7f7464ad6ddfece4402bd7b86dbfa86166d";
const ACCEPTED_TOOLCHAIN_NAME: &str = "wyrmroot-1.97.1-a92dc7f7";
const R1_EVIDENCE_VARIABLE: &str = "DEEPWYRM_R1_EVIDENCE_NONCE";
const MAX_BOOTFS_BYTES: usize = 32 * 1024 * 1024;
const MAX_RECEIPT_BYTES: usize = 64 * 1024;
/// Card R1's WYR1-A gate slot. The card has no A-era gate behaviour; the byte is
/// there because the archive's base shape requires the entry.
const GATE_CONFIG: &[u8] = b"\x00";

/// The nine payloads. The first six are C1's, unchanged, because R1's role graph
/// is C1's. The last three are what the card launches: its probe, the existing
/// no-yield hog, and the JobV2 smoke payload used as the progress child.
///
/// `hello` is deliberately `wyrmroot-job-hello` and not the stream variant: the
/// probe encodes every launch with `streams: false`, and the launch policy
/// admits both payloads zero-stream only.
const NATIVE_SPECS: [NativeSpec; 9] = [
    NativeSpec {
        label: "system-init",
        package: "wyrmroot-system-init",
        binary: "system-init",
        features: "r1-selector34",
        artifact: "system-init",
    },
    NativeSpec {
        label: "registryd",
        package: "wyrmroot-registryd",
        binary: "registryd",
        features: "native-registryd",
        artifact: "registryd",
    },
    // `wyr1c5-production`, not bare `native-devmgr`. The RRC graph assigns
    // devmgr the resident DeviceCoordinator profile, and this is the feature that
    // gives it the resource-domain init path and the registry publication the
    // geometry ledger accounts for in its three resident handles. Bare
    // `native-devmgr` selects the older non-resource coordinator and, as of this
    // revision, does not build at all: `wyrmroot-registry-proto` is attached to
    // the feature but used only from `wyr1c5-production` upward, so the crate's
    // own `unused_crate_dependencies = "deny"` rejects it. See the commit
    // message for the pre-existing breakage that exposes in `wyr1c1 product`.
    NativeSpec {
        label: "devmgr",
        package: "wyrmroot-devmgr",
        binary: "devmgr",
        features: "wyr1c5-production",
        artifact: "devmgr",
    },
    NativeSpec {
        label: "uart16550d",
        package: "wyrmroot-wyr1-retained-stubs",
        binary: "uart16550d",
        features: "native-retained",
        artifact: "uart16550d",
    },
    NativeSpec {
        label: "consoled",
        package: "wyrmroot-wyr1-retained-stubs",
        binary: "consoled",
        features: "native-retained",
        artifact: "consoled",
    },
    NativeSpec {
        label: "wyrmsh",
        package: "wyrmroot-wyr1-retained-stubs",
        binary: "wyrmsh",
        features: "native-retained",
        artifact: "wyrmsh",
    },
    NativeSpec {
        label: "r1-probe",
        package: "wyrmroot-r1-saturation",
        binary: "wyrmroot-r1-probe",
        features: "native-payloads",
        artifact: "wyrmroot-r1-probe",
    },
    NativeSpec {
        label: "cpu-hog",
        package: "wyrmroot-dw1b-preemption",
        binary: "wyrmroot-job-cpu-hog",
        features: "native-job-cpu-hog",
        artifact: "wyrmroot-job-cpu-hog",
    },
    NativeSpec {
        label: "hello",
        package: "wyrmroot-hello",
        binary: "wyrmroot-job-hello",
        features: "native-job-hello",
        artifact: "wyrmroot-job-hello",
    },
];

/// Payloads that must be compiled against the build nonce. The probe bakes it in
/// so its records cannot be refused by a collector compiled with another, and
/// init carries the evidence seam that submits them.
const NONCE_BOUND_LABELS: [&str; 2] = ["r1-probe", "system-init"];

/// The two profile handoffs, named as they appear in the product directory.
pub(crate) const PROFILES: [(&str, u16, u16); 2] = [("smp", 6, 4), ("control", 3, 1)];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct R1Snapshot {
    pub(crate) receipt: Vec<u8>,
    pub(crate) rrc_manifest: Vec<u8>,
    pub(crate) device_manifest: Vec<u8>,
    pub(crate) launch_policy: Vec<u8>,
    /// One archive per profile, keyed by profile name.
    pub(crate) bootfs: BTreeMap<String, Vec<u8>>,
    pub(crate) gates: BTreeMap<String, Vec<u8>>,
    pub(crate) artifacts: BTreeMap<String, Vec<u8>>,
    pub(crate) inspections: BTreeMap<String, Vec<u8>>,
}

struct AssembledR1 {
    generation: [u8; 32],
    rrc_manifest: Vec<u8>,
    device_manifest: Vec<u8>,
    launch_policy: Vec<u8>,
    bootfs: BTreeMap<String, Vec<u8>>,
    gates: BTreeMap<String, Vec<u8>>,
    probe_identity: [u8; 32],
}

pub(crate) fn product(output: &Path, nonce: &str) -> Result<String, Failure> {
    validate_nonce(nonce)?;
    reject_ambient_build_environment(env::vars_os())?;
    let repository = crate::tasks::repository_root()?;
    let project = crate::tasks::canonical_project_root(&repository)?;
    let output = validate_fresh_output(&repository, &project, output)?;
    let parent_path = output
        .parent()
        .ok_or_else(|| Failure::task("card R1 output has no parent"))?;
    let name = output
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| Failure::task("card R1 output name is not UTF-8"))?;
    let parent = crate::secure_fs::Directory::open_exact(parent_path, "card R1 output parent")?;
    let output_directory = parent.create_child(name, 0o700, "card R1 output")?;
    let snapshot = build_snapshot(&repository, &project, nonce)?;
    publish(&output_directory, &snapshot)?;
    let mut digests = String::new();
    for (profile, _, _) in PROFILES {
        use std::fmt::Write as _;
        let bytes = snapshot
            .bootfs
            .get(profile)
            .ok_or_else(|| Failure::task("card R1 snapshot lacks a profile archive"))?;
        write!(
            &mut digests,
            " bootfs_{profile}_sha256={}",
            sha256::bytes_digest(bytes)
        )
        .expect("writing to String cannot fail");
    }
    Ok(format!(
        "WYR1_R1_HOST_PRODUCT_PASS product_kind={PRODUCT_KIND} selector=dynamic-launch-saturation \
         evidence=not-produced media=not-produced request=not-produced \
         rust_revision={ACCEPTED_RUST_REVISION}{digests} receipt={}\n",
        output.join("product/build-receipt.toml").display(),
    ))
}

fn build_snapshot(repository: &Path, project: &Path, nonce: &str) -> Result<R1Snapshot, Failure> {
    let revision = clean_repository_revision(repository)?;
    let manifest = BuildManifest::load(repository)?;
    if manifest.rust_revision()? != ACCEPTED_RUST_REVISION
        || manifest.rust_toolchain_name()? != ACCEPTED_TOOLCHAIN_NAME
    {
        return Err(Failure::task(
            "card R1 product metadata does not name the accepted a92dc7f Rust toolchain",
        ));
    }
    let profile = manifest.validate_loader_build_readiness(repository)?;
    let toolchain = crate::tasks::prepare_loader_toolchain(repository, &profile, &manifest)?;
    let cargo_home = crate::tasks::project_cargo_home(repository, &manifest)?;
    if env::var_os("CARGO_HOME").as_deref() != Some(cargo_home.as_os_str()) {
        return Err(Failure::task(
            "card R1 product requires the pinned launcher's exact CARGO_HOME",
        ));
    }

    let project_directory = crate::secure_fs::Directory::open_exact(project, "OS-Project root")?;
    let tmp = match project_directory.open_child(".tmp", "project temporary root") {
        Ok(directory) => directory,
        Err(_) => project_directory.create_child(".tmp", 0o700, "project temporary root")?,
    };
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
        .as_nanos();
    let scratch_name = format!("r1-build-{}-{unique}", std::process::id());
    let scratch = tmp.create_scratch(&scratch_name, "card R1 build scratch")?;
    let build_result = (|| {
        let mut artifacts = Vec::with_capacity(NATIVE_SPECS.len());
        for spec in NATIVE_SPECS {
            toolchain.accepted().verify_unchanged()?;
            let bound = NONCE_BOUND_LABELS.contains(&spec.label);
            let artifact = scratch.with_inheritable_anchor("card R1 build scratch", |anchor| {
                let mut artifact = build_native_with_flags(
                    repository,
                    &cargo_home,
                    toolchain.accepted(),
                    anchor,
                    spec,
                    bound.then_some(nonce),
                    NativeBuildOptions::exact_with_evidence(R1_EVIDENCE_VARIABLE),
                )?;
                artifact.inspection = inspect_native(
                    repository,
                    &artifact.bytes,
                    &artifact.sha256,
                    spec.label,
                    anchor,
                )?;
                Ok(artifact)
            })?;
            artifacts.push(artifact);
        }
        Ok::<_, Failure>(artifacts)
    })();
    let artifacts = scratch.finish(build_result)?;
    toolchain.accepted().verify_unchanged()?;
    verify_repository_revision(repository, &revision)?;

    let assembled = assemble(&revision, &artifacts, nonce)?;
    let receipt = render_receipt(&revision, nonce, &assembled, &artifacts)?;
    if receipt.len() > MAX_RECEIPT_BYTES {
        return Err(Failure::task("card R1 receipt exceeds its fixed bound"));
    }
    Ok(R1Snapshot {
        receipt: receipt.into_bytes(),
        rrc_manifest: assembled.rrc_manifest,
        device_manifest: assembled.device_manifest,
        launch_policy: assembled.launch_policy,
        bootfs: assembled.bootfs,
        gates: assembled.gates,
        artifacts: artifacts
            .iter()
            .map(|artifact| (artifact.spec.label.to_owned(), artifact.bytes.clone()))
            .collect(),
        inspections: artifacts
            .iter()
            .map(|artifact| {
                (
                    artifact.spec.label.to_owned(),
                    artifact.inspection.clone().into_bytes(),
                )
            })
            .collect(),
    })
}

fn assemble(
    revision: &str,
    artifacts: &[NativeArtifact],
    nonce: &str,
) -> Result<AssembledR1, Failure> {
    let by_label = |label: &str| -> Result<&NativeArtifact, Failure> {
        artifacts
            .iter()
            .find(|artifact| artifact.spec.label == label)
            .ok_or_else(|| Failure::task(format!("card R1 product lacks its {label} artifact")))
    };
    if artifacts.len() != NATIVE_SPECS.len() {
        return Err(Failure::task(
            "card R1 product requires exactly its nine native artifacts",
        ));
    }
    let init = by_label("system-init")?;
    let registryd = by_label("registryd")?;
    let devmgr = by_label("devmgr")?;
    let uart = by_label("uart16550d")?;
    let consoled = by_label("consoled")?;
    let wyrmsh = by_label("wyrmsh")?;
    let probe = by_label("r1-probe")?;
    let cpu_hog = by_label("cpu-hog")?;
    let hello = by_label("hello")?;

    let role_hashes = [
        digest(&registryd.sha256)?,
        digest(&devmgr.sha256)?,
        digest(&uart.sha256)?,
        digest(&consoled.sha256)?,
        digest(&wyrmsh.sha256)?,
    ];
    let generation = generation(revision, artifacts, nonce);
    let rrc_manifest = crate::wyr1::fixed_builder_for_profiles(
        &generation,
        role_hashes,
        StartupProfile::BootstrapRegistry,
        StartupProfile::DeviceCoordinator,
    )?
    .build_structural()
    .map_err(|error| Failure::task(format!("card R1 WRRM build failed: {error:?}")))?;

    let mut wrdm = [0u8; WRDM_HEADER_BYTES + WRDM_RECORD_BYTES];
    let wrdm_size = encode_com2_manifest(ContentIdentity(role_hashes[2]), &mut wrdm)
        .map_err(|error| Failure::task(format!("card R1 WRDM build failed: {error:?}")))?;
    let device_manifest = wrdm[..wrdm_size].to_vec();

    let probe_identity = digest(&probe.sha256)?;
    let cpu_hog_identity = digest(&cpu_hog.sha256)?;
    let hello_identity = digest(&hello.sha256)?;
    let entries = launch_policy_entries(cpu_hog_identity, hello_identity);
    if entries.len() != R1_POLICY_ENTRY_COUNT {
        return Err(Failure::task("card R1 policy entry count changed"));
    }
    let mut policy_bytes = [0u8; 1024];
    let policy_size = encode_launch_policy(generation, &entries, &mut policy_bytes)
        .map_err(|error| Failure::task(format!("card R1 launch policy failed: {error:?}")))?;
    let launch_policy = policy_bytes[..policy_size].to_vec();

    let mut bootfs = BTreeMap::new();
    let mut gates = BTreeMap::new();
    for (name, hog_count, online_cpus) in PROFILES {
        if !ACCEPTED_TOPOLOGIES
            .iter()
            .any(|(hogs, cpus)| *hogs == hog_count && *cpus == online_cpus)
        {
            return Err(Failure::task(format!(
                "card R1 profile {name} is not one of the two accepted topologies"
            )));
        }
        let mut gate = [0u8; R1_GATE_BYTES];
        encode_gate(
            ProbeConfiguration {
                hog_count,
                online_cpus,
                probe_identity,
            },
            &mut gate,
        )
        .map_err(|error| Failure::task(format!("card R1 {name} gate failed: {error:?}")))?;
        let archive = build_r1(ProductR1 {
            c1: ProductC1 {
                base: Product {
                    init: &init.bytes,
                    registryd: &registryd.bytes,
                    devmgr: &devmgr.bytes,
                    uart16550d: &uart.bytes,
                    consoled: &consoled.bytes,
                    wyrmsh: &wyrmsh.bytes,
                    rrc_manifest: &rrc_manifest,
                    gate_config: GATE_CONFIG,
                },
                marker: WYR1_C1_MARKER,
                device_manifest: &device_manifest,
                expected_uart16550d_identity: role_hashes[2],
            },
            launch_policy: &launch_policy,
            gate_config: &gate,
            probe: &probe.bytes,
            cpu_hog: &cpu_hog.bytes,
            hello: &hello.bytes,
            expected_probe_identity: probe_identity,
            expected_cpu_hog_identity: cpu_hog_identity,
            expected_hello_identity: hello_identity,
        })
        .map_err(|error| Failure::task(format!("card R1 {name} bootfs build failed: {error:?}")))?;
        if archive.len() > MAX_BOOTFS_BYTES {
            return Err(Failure::task(format!(
                "card R1 {name} bootfs exceeds the image bound"
            )));
        }
        bootfs.insert(name.to_owned(), archive);
        gates.insert(name.to_owned(), gate.to_vec());
    }

    // The two handoffs must be one product with two configurations. If their
    // archives ever matched, the profiles would be indistinguishable and a
    // result could not be attributed to a topology at all.
    let distinct = bootfs.values().collect::<std::collections::BTreeSet<_>>();
    if distinct.len() != PROFILES.len() {
        return Err(Failure::task(
            "card R1 profile archives are not pairwise distinct",
        ));
    }

    Ok(AssembledR1 {
        generation,
        rrc_manifest,
        device_manifest,
        launch_policy,
        bootfs,
        gates,
        probe_identity,
    })
}

fn publish(output: &crate::secure_fs::Directory, snapshot: &R1Snapshot) -> Result<(), Failure> {
    let artifacts = output.create_child("artifacts", 0o700, "card R1 artifacts")?;
    let inspections = output.create_child("inspections", 0o700, "card R1 inspections")?;
    let product = output.create_child("product", 0o700, "card R1 product")?;
    for spec in NATIVE_SPECS {
        artifacts.write_new_retained(
            &format!("{}.elf", spec.label),
            snapshot
                .artifacts
                .get(spec.label)
                .ok_or_else(|| Failure::task("card R1 snapshot lacks an artifact"))?,
            0o400,
            "card R1 artifact",
        )?;
        inspections.write_new_retained(
            &format!("{}.json", spec.label),
            snapshot
                .inspections
                .get(spec.label)
                .ok_or_else(|| Failure::task("card R1 snapshot lacks an inspection"))?,
            0o400,
            "card R1 inspection",
        )?;
    }
    product.write_new_retained(
        "rrc-r1-v1.bin",
        &snapshot.rrc_manifest,
        0o400,
        "card R1 WRRM",
    )?;
    product.write_new_retained(
        "wrdm-r1-v1.bin",
        &snapshot.device_manifest,
        0o400,
        "card R1 WRDM",
    )?;
    product.write_new_retained(
        "launch-policy-v1.bin",
        &snapshot.launch_policy,
        0o400,
        "card R1 launch policy",
    )?;
    // One directory per profile handoff, each holding only what differs.
    for (name, _, _) in PROFILES {
        let directory = output.create_child(name, 0o700, "card R1 profile")?;
        directory.write_new_retained(
            "bootfs.img",
            snapshot
                .bootfs
                .get(name)
                .ok_or_else(|| Failure::task("card R1 snapshot lacks a profile archive"))?,
            0o400,
            "card R1 bootfs",
        )?;
        directory.write_new_retained(
            "r1-gate-v1.bin",
            snapshot
                .gates
                .get(name)
                .ok_or_else(|| Failure::task("card R1 snapshot lacks a profile gate"))?,
            0o400,
            "card R1 gate",
        )?;
    }
    product.write_new_retained(
        "build-receipt.toml",
        &snapshot.receipt,
        0o400,
        "card R1 receipt",
    )?;
    Ok(())
}

fn render_receipt(
    revision: &str,
    nonce: &str,
    assembled: &AssembledR1,
    artifacts: &[NativeArtifact],
) -> Result<String, Failure> {
    use std::fmt::Write as _;
    let mut receipt = String::new();
    writeln!(&mut receipt, "schema = \"wyrmroot-r1-build-receipt-v1\"")
        .map_err(|_| Failure::task("card R1 receipt write failed"))?;
    writeln!(&mut receipt, "product_kind = \"{PRODUCT_KIND}\"").ok();
    writeln!(&mut receipt, "selector = \"dynamic-launch-saturation\"").ok();
    writeln!(&mut receipt, "guest_test_id = 34").ok();
    writeln!(&mut receipt, "wyrmroot_revision = \"{revision}\"").ok();
    writeln!(&mut receipt, "rust_revision = \"{ACCEPTED_RUST_REVISION}\"").ok();
    writeln!(
        &mut receipt,
        "rust_toolchain = \"{ACCEPTED_TOOLCHAIN_NAME}\""
    )
    .ok();
    writeln!(&mut receipt, "evidence_nonce = \"{nonce}\"").ok();
    writeln!(
        &mut receipt,
        "boot_generation_sha256 = \"{}\"",
        hex(&assembled.generation)
    )
    .ok();
    writeln!(
        &mut receipt,
        "probe_identity_sha256 = \"{}\"",
        hex(&assembled.probe_identity)
    )
    .ok();
    writeln!(
        &mut receipt,
        "rrc_manifest_sha256 = \"{}\"",
        sha256::bytes_digest(&assembled.rrc_manifest)
    )
    .ok();
    writeln!(
        &mut receipt,
        "device_manifest_sha256 = \"{}\"",
        sha256::bytes_digest(&assembled.device_manifest)
    )
    .ok();
    writeln!(
        &mut receipt,
        "launch_policy_sha256 = \"{}\"",
        sha256::bytes_digest(&assembled.launch_policy)
    )
    .ok();
    writeln!(&mut receipt, "media = \"not-produced\"").ok();
    writeln!(&mut receipt, "request = \"not-produced\"").ok();
    for (name, hog_count, online_cpus) in PROFILES {
        let archive = assembled
            .bootfs
            .get(name)
            .ok_or_else(|| Failure::task("card R1 receipt lacks a profile archive"))?;
        let gate = assembled
            .gates
            .get(name)
            .ok_or_else(|| Failure::task("card R1 receipt lacks a profile gate"))?;
        writeln!(&mut receipt, "\n[profile.{name}]").ok();
        writeln!(&mut receipt, "hog_count = {hog_count}").ok();
        writeln!(&mut receipt, "online_cpus = {online_cpus}").ok();
        writeln!(
            &mut receipt,
            "bootfs_sha256 = \"{}\"",
            sha256::bytes_digest(archive)
        )
        .ok();
        writeln!(
            &mut receipt,
            "gate_sha256 = \"{}\"",
            sha256::bytes_digest(gate)
        )
        .ok();
    }
    for artifact in artifacts {
        writeln!(&mut receipt, "\n[artifact.{}]", artifact.spec.label).ok();
        writeln!(&mut receipt, "package = \"{}\"", artifact.spec.package).ok();
        writeln!(&mut receipt, "binary = \"{}\"", artifact.spec.binary).ok();
        writeln!(&mut receipt, "features = \"{}\"", artifact.spec.features).ok();
        writeln!(&mut receipt, "sha256 = \"{}\"", artifact.sha256).ok();
    }
    Ok(receipt)
}

fn generation(revision: &str, artifacts: &[NativeArtifact], nonce: &str) -> [u8; 32] {
    // Distinct domain separator and the nonce, so no card-R1 boot generation can
    // collide with C1's over the same artifacts, and the two runs of one product
    // under different nonces are different products.
    let mut material = Vec::from(b"wyrmroot-r1-host-product-v1\0".as_slice());
    material.extend_from_slice(revision.as_bytes());
    material.extend_from_slice(nonce.as_bytes());
    for artifact in artifacts {
        material.extend_from_slice(artifact.spec.label.as_bytes());
        material.extend_from_slice(artifact.sha256.as_bytes());
    }
    sha256::bytes_digest_array(&material)
}

fn digest(value: &str) -> Result<[u8; 32], Failure> {
    crate::wyr1::decode_digest(value)
}

fn hex(value: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in value {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

/// Exactly sixteen uppercase hex digits, nonzero. This is the same shape the
/// kernel's `build.rs` requires and the probe parses at compile time, checked
/// here so a malformed nonce fails before any build starts.
fn validate_nonce(nonce: &str) -> Result<(), Failure> {
    if nonce.len() != 16
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte.is_ascii_uppercase() && byte <= b'F')
    {
        return Err(Failure::usage(
            "card R1 requires --evidence-nonce as exactly sixteen uppercase hex digits",
        ));
    }
    if nonce.bytes().all(|byte| byte == b'0') {
        return Err(Failure::usage(
            "card R1 rejects the zero evidence nonce; the collector refuses every record under it",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
