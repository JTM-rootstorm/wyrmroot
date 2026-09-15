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
use std::fs;
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
/// Selector 34's measured bootfs page ceiling, validated by `pinned-cargo` and
/// compiled into Deepwyrm's primordial mapping journal.
const R1_BOOTFS_PAGES_VARIABLE: &str = "DEEPWYRM_R1_BOOTFS_MAX_PAGES";
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

// The domain seam below has no caller until `r1 prepare` lands; it is written
// and tested first because its contract is the GDB harness's, and a domain the
// harness refuses would waste an accepted request under the lease. The same
// pattern as `wyr1c::build_c6_snapshot`, which is a seam for `wyr1c6::prepare`.
/// The designated domain's fixed identity. Card R1 runs under the same domain as
/// every other card; the lease and the baseline XML are what make that safe.
#[allow(
    dead_code,
    reason = "domain seam consumed by the follow-on r1 prepare command"
)]
pub(crate) const DOMAIN_UUID: &str = "33005e22-d7c2-4b13-b1ac-b82eda95e584";
#[allow(
    dead_code,
    reason = "domain seam consumed by the follow-on r1 prepare command"
)]
pub(crate) const MACHINE: &str = "pc-q35-10.2";
#[allow(
    dead_code,
    reason = "domain seam consumed by the follow-on r1 prepare command"
)]
pub(crate) const SELECTOR: &str = "dynamic-launch-saturation";
#[allow(
    dead_code,
    reason = "domain seam consumed by the follow-on r1 prepare command"
)]
pub(crate) const TEST_ID: u32 = 34;
/// Two GiB, matching every other card's guest.
#[allow(
    dead_code,
    reason = "domain seam consumed by the follow-on r1 prepare command"
)]
const MEMORY_KIB: u32 = 2_097_152;

/// Renders one profile's libvirt domain for a **GDB-attached** run.
///
/// This is not C6's domain XML with a different vCPU count, and the differences
/// are the whole point. `tools/run-active-gdb-vm.sh` greps the file it is handed
/// and refuses it unless every one of these holds, so they are encoded here and
/// asserted in `tests`:
///
/// * `<name>OS-Project</name>` and the fixed UUID, so the harness can only ever
///   define the designated domain;
/// * `<qemu:arg value="-S"/>` and `tcp:127.0.0.1:<port>`, because the guest must
///   start stopped with the gdbstub listening — §5.2's three carrier facts are
///   unreadable any other way;
/// * the nvram source is `<output>/OVMF_VARS.fd`, the per-run copy the harness
///   makes itself. Prepare must **not** create that file: the harness refuses to
///   run if it already exists, so a pre-staged copy would fail every run;
/// * **no `fdgroup=` annotations.** C6's domain carries them on nvram and disk
///   because its runner owns those descriptors; the GDB harness rejects any file
///   containing one.
///
/// COM2 is `null` rather than a socket. §8.1 excludes COM2 conversation from this
/// card entirely, and the evidence transcript leaves over COM1.
#[allow(
    dead_code,
    reason = "domain seam consumed by the follow-on r1 prepare command"
)]
pub(crate) fn domain_xml(vcpus: u8, port: u16, code: &Path, esp: &Path, vars: &Path) -> String {
    format!(
        "<domain xmlns:qemu=\"http://libvirt.org/schemas/domain/qemu/1.0\" type=\"qemu\">\n  \
         <name>OS-Project</name>\n  <uuid>{DOMAIN_UUID}</uuid>\n  \
         <memory unit=\"KiB\">{MEMORY_KIB}</memory>\
         <currentMemory unit=\"KiB\">{MEMORY_KIB}</currentMemory>\
         <vcpu placement=\"static\">{vcpus}</vcpu>\n  \
         <sysinfo type=\"fwcfg\">\
         <entry name=\"opt/org.deepwyrm.test.selector\">{SELECTOR}</entry>\
         <entry name=\"opt/org.deepwyrm.test.test_id\">{TEST_ID}</entry></sysinfo>\n  \
         <os><type arch=\"x86_64\" machine=\"{MACHINE}\">hvm</type>\
         <loader readonly=\"yes\" secure=\"no\" type=\"pflash\" format=\"raw\">{}</loader>\
         <nvram type=\"file\" format=\"raw\"><source file=\"{}\"/></nvram>\
         <boot dev=\"hd\"/></os>\n  \
         <features><acpi/><apic/></features>\
         <clock offset=\"utc\"><timer name=\"rtc\" tickpolicy=\"catchup\"/>\
         <timer name=\"pit\" tickpolicy=\"delay\"/><timer name=\"hpet\" present=\"no\"/></clock>\
         <on_poweroff>destroy</on_poweroff><on_reboot>restart</on_reboot>\
         <on_crash>destroy</on_crash>\
         <pm><suspend-to-mem enabled=\"no\"/><suspend-to-disk enabled=\"no\"/></pm>\
         <devices><emulator>/usr/bin/qemu-system-x86_64</emulator>\
         <disk type=\"file\" device=\"disk\"><driver name=\"qemu\" type=\"raw\"/>\
         <source file=\"{}\"/><target dev=\"vda\" bus=\"virtio\"/><readonly/></disk>\
         <controller type=\"pci\" index=\"0\" model=\"pcie-root\"/>\
         <serial type=\"pty\"><target type=\"isa-serial\" port=\"0\"/></serial>\
         <serial type=\"null\"><target type=\"isa-serial\" port=\"1\"/></serial>\
         <console type=\"pty\"><target type=\"serial\" port=\"0\"/></console></devices>\n  \
         <qemu:commandline><qemu:arg value=\"-device\"/>\
         <qemu:arg value=\"isa-debug-exit,iobase=0xf4,iosize=0x04\"/>\
         <qemu:arg value=\"-S\"/><qemu:arg value=\"-gdb\"/>\
         <qemu:arg value=\"tcp:127.0.0.1:{port}\"/></qemu:commandline>\n</domain>\n",
        code.display(),
        vars.display(),
        esp.display(),
    )
}

/// Card R1's media inputs. Every byte here is either built from a pinned clean
/// revision or read from a digest-pinned path; nothing is copied from a
/// developer tree.
#[allow(
    dead_code,
    reason = "media seam consumed by the follow-on r1 prepare command"
)]
pub(crate) struct R1Media {
    pub(crate) loader: Vec<u8>,
    /// The selector-34 kernel. `deepwyrm.elf` and `deepwyrm.symbols.elf` are the
    /// same bytes: the release profile keeps full DWARF, which is what lets the
    /// GDB harness read §8.2's carrier facts at all.
    pub(crate) kernel: Vec<u8>,
    pub(crate) bootstrap: Vec<u8>,
    pub(crate) boot_device_table: Vec<u8>,
    pub(crate) ovmf_code: Vec<u8>,
    pub(crate) ovmf_vars: Vec<u8>,
}

/// The environment the selector-34 kernel must be built under.
///
/// Exactly two variables, and both matter. The selector chooses the guest test;
/// the nonce is baked into the kernel's evidence collector and must be the same
/// value the probe was compiled against, or the collector refuses every record
/// and a working run reports nothing.
#[allow(
    dead_code,
    reason = "media seam consumed by the follow-on r1 prepare command"
)]
/// The exact mapped page count selector 34's kernel must admit.
///
/// One kernel serves both profiles, so the ceiling is the larger archive's page
/// count. Deepwyrm sizes its primordial mapping journal from this value, so it
/// has to be measured from the archives that will actually be mapped rather
/// than guessed: an archive past the compiled ceiling does not fail admission,
/// it fails the bootstrap's bootfs mapping with an opaque NO_RESOURCES.
pub(crate) fn bootfs_page_ceiling(bootfs: &BTreeMap<String, Vec<u8>>) -> Result<usize, Failure> {
    const PAGE_BYTES: usize = 4096;
    const CEILING_PAGES: usize = 8192;

    let pages = bootfs
        .values()
        .map(|archive| archive.len().div_ceil(PAGE_BYTES))
        .max()
        .ok_or_else(|| Failure::task("card R1 has no profile archive to measure"))?;
    if pages == 0 || pages > CEILING_PAGES {
        return Err(Failure::task(format!(
            "card R1 bootfs page ceiling {pages} is outside Deepwyrm's 1..={CEILING_PAGES} bound"
        )));
    }
    Ok(pages)
}

pub(crate) fn kernel_environment(nonce: &str, bootfs_pages: usize) -> [(&'static str, String); 3] {
    [
        ("DEEPWYRM_GUEST_TEST_SELECTOR", SELECTOR.to_owned()),
        (R1_EVIDENCE_VARIABLE, nonce.to_owned()),
        (R1_BOOTFS_PAGES_VARIABLE, bootfs_pages.to_string()),
    ]
}

/// Builds the selector-34 Deepwyrm kernel from a pinned clean Deepwyrm checkout.
///
/// This mirrors `wyr1c6::build_selector29_kernel` rather than generalising it.
/// That function is part of an accepted producer path, and parameterising it
/// would put a card-R1 change inside selector 29's build; the duplication is
/// deliberate and bounded to the environment above.
#[allow(
    dead_code,
    reason = "media seam consumed by the follow-on r1 prepare command"
)]
pub(crate) fn build_kernel(
    deep_repository: &Path,
    nonce: &str,
    bootfs_pages: usize,
) -> Result<Vec<u8>, Failure> {
    use std::process::{Command, Stdio};

    let repository =
        crate::secure_fs::Directory::open_exact(deep_repository, "Deepwyrm source root")?;
    let temporary = match repository.open_child(".tmp", "Deepwyrm temporary root") {
        Ok(directory) => directory,
        Err(_) => repository.create_child(".tmp", 0o700, "Deepwyrm temporary root")?,
    };
    temporary.verify_owned_container_path("Deepwyrm temporary root")?;
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
        .as_nanos();
    let scratch = temporary.create_scratch(
        &format!("r1-kernel-{}-{unique}", std::process::id()),
        "card R1 Deepwyrm target",
    )?;
    let result = (|| {
        let mut command = Command::new(repository.path().join("tools/pinned-cargo"));
        command
            .arg("target")
            .args([
                "build",
                "--locked",
                "--offline",
                "--release",
                "--target",
                crate::wyr1c6::KERNEL_TARGET,
                "--package",
                "deepwyrm-kernel",
                "--bin",
                "deepwyrm-kernel",
                "--features",
                "test-support",
            ])
            .env("DEEPWYRM_PINNED_TARGET_DIR", scratch.path())
            .env_remove("CARGO_HOME")
            .env_remove("LD_AUDIT")
            .env_remove("LD_LIBRARY_PATH")
            .env_remove("LD_PRELOAD")
            .current_dir(repository.path())
            .stdin(Stdio::null());
        for (key, value) in kernel_environment(nonce, bootfs_pages) {
            command.env(key, value);
        }
        let status = command
            .status()
            .map_err(|error| Failure::task(format!("could not build card R1 kernel: {error}")))?;
        if !status.success() {
            return Err(Failure::task(
                "card R1 selector-34 Deepwyrm kernel build failed",
            ));
        }
        scratch.read_producer(
            &std::path::PathBuf::from(crate::wyr1c6::KERNEL_TARGET).join("release/deepwyrm-kernel"),
            crate::wyr1c6::MAX_ARTIFACT_BYTES,
            "selector-34 kernel",
        )
    })();
    scratch.finish(result)
}

/// The artifact files card R1 stages, in the order they are written.
///
/// `bootfs.img` is absent on purpose: it is per-profile and lives in each
/// profile's own directory, because the two handoffs differ precisely in the
/// `WRR1` configuration their archive carries.
#[allow(
    dead_code,
    reason = "media seam consumed by the follow-on r1 prepare command"
)]
pub(crate) const MEDIA_ARTIFACTS: [&str; 13] = [
    "loader.efi",
    "deepwyrm.elf",
    "deepwyrm.symbols.elf",
    "bootstrap.elf",
    "system-init.elf",
    "registryd.elf",
    "devmgr.elf",
    "uart16550d.elf",
    "consoled.elf",
    "wyrmsh.elf",
    "boot-device-table.bin",
    "OVMF_CODE.fd",
    "OVMF_VARS.fd",
];

/// Composes one profile's ESP from the shared media and that profile's archive.
///
/// The ESP is per-profile for the same reason the archive is: it embeds the
/// bootfs, so two profiles cannot share one image. §3's single `r1-esp.img` entry
/// therefore names two files, one under each profile directory, and the request
/// must record both digests.
#[allow(
    dead_code,
    reason = "media seam consumed by the follow-on r1 prepare command"
)]
pub(crate) fn compose_profile_esp(
    artifacts: &Path,
    profile_directory: &Path,
) -> Result<std::path::PathBuf, Failure> {
    let esp = profile_directory.join("r1-esp.img");
    let arguments = crate::cli::G3ImageArguments {
        image: esp.display().to_string(),
        loader: artifacts.join("loader.efi").display().to_string(),
        kernel: artifacts.join("deepwyrm.elf").display().to_string(),
        bootstrap: artifacts.join("bootstrap.elf").display().to_string(),
        bootfs: profile_directory.join("bootfs.img").display().to_string(),
    };
    crate::g3_image::build_d6(
        &arguments,
        &artifacts
            .join("boot-device-table.bin")
            .display()
            .to_string(),
    )?;
    crate::wyr1c6::seal_mode(&esp, 0o444, "card R1 ESP")?;
    Ok(esp)
}

/// Stages card R1's complete run inputs: shared media, both profile handoffs,
/// and a source receipt binding every digest to the revisions it came from.
///
/// Deliberately produces **no `request.toml`**. The root verifier
/// (`tools/verify-vm-request.py`) enumerates a schema per request kind, and
/// adding card R1's is a change to the script that decides whether a request may
/// reach the designated VM. That belongs in its own reviewed change, so this
/// command stops at the point where every digest such a request would need is
/// recorded in the receipt and nothing yet claims to be runnable.
///
/// Output is written directly into the validated fresh directory rather than
/// staged and moved. The directory must not already exist, so there is nothing to
/// clobber; a failure part-way leaves a partial tree the operator deletes, which
/// is the same recovery as a rejected staging.
pub(crate) fn prepare(
    output: &Path,
    card: RequestCard,
    deep_repository: &Path,
    deep_revision: &str,
    nonce: &str,
    gdb_port: u16,
) -> Result<String, Failure> {
    use crate::wyr1c6::{
        MAX_ARTIFACT_BYTES, canonical_deep_repository, canonical_new_output, clean_revision,
        matching_abi_tree, pinned_firmware, reject_selector_environment, validate_revision,
        verify_clean_revision, write_new,
    };

    reject_selector_environment()?;
    validate_nonce(nonce)?;
    validate_revision(deep_revision, "Deepwyrm revision")?;
    // The port is baked into both domains and passed to the harness separately.
    // Refusing the privileged range here keeps the generated domain runnable by
    // the unprivileged operator the harness assumes.
    if gdb_port < 1024 {
        return Err(Failure::usage(
            "card R1 requires --gdb-port above the privileged range",
        ));
    }

    let repository = crate::tasks::repository_root()?;
    let project = crate::tasks::canonical_project_root(&repository)?;
    let deep_repository = canonical_deep_repository(deep_repository, &project)?;
    let wyrmroot_revision = clean_revision(&repository, "Wyrmroot")?;
    verify_clean_revision(&deep_repository, "Deepwyrm", deep_revision)?;
    let manifest = BuildManifest::load(&repository)?;
    if manifest.rust_revision()? != ACCEPTED_RUST_REVISION
        || manifest.rust_toolchain_name()? != ACCEPTED_TOOLCHAIN_NAME
    {
        return Err(Failure::task(
            "card R1 prepare does not name the accepted a92dc7f Rust toolchain",
        ));
    }
    // The semantic join with Deepwyrm is the immutable `abi` tree, not the commit:
    // selector-34 code may sit at a newer clean revision than the generated ABI
    // pin without changing the ABI either side compiled against.
    let abi_revision = manifest.deepwyrm_revision()?.to_owned();
    let abi_tree = matching_abi_tree(&deep_repository, deep_revision, &abi_revision)?;
    let layout = crate::deep_layout::prepare_current_kernel_source(
        &repository,
        &deep_repository,
        deep_revision,
    )?;
    let output = canonical_new_output(output, &project, &repository, &deep_repository)?;

    let loader_profile = manifest.validate_loader_build_readiness(&repository)?;
    let toolchain =
        crate::tasks::prepare_loader_toolchain(&repository, &loader_profile, &manifest)?;
    let cargo_home = crate::tasks::project_cargo_home(&repository, &manifest)?;
    if env::var_os("CARGO_HOME").as_deref() != Some(cargo_home.as_os_str()) {
        return Err(Failure::task(
            "card R1 prepare requires the pinned launcher's exact CARGO_HOME",
        ));
    }
    toolchain.accepted().verify_unchanged()?;
    layout.verify_unchanged()?;

    fs::create_dir(&output)
        .map_err(|error| Failure::task(format!("could not create card R1 output: {error}")))?;
    let build = output.join(".build");
    fs::create_dir(&build).map_err(|error| {
        Failure::task(format!("could not create card R1 build directory: {error}"))
    })?;
    let uefi = crate::tasks::build_deterministic_uefi_pair(
        &repository,
        &toolchain,
        &loader_profile,
        &layout,
        &crate::tasks::IsolatedUefiBuild {
            cargo_home: &cargo_home,
            production_target: &build.join("uefi-production"),
            retained_debug_target: &build.join("uefi-retained-debug"),
            cargo_profile: crate::tasks::UefiCargoProfile::Release,
        },
    )?;
    let build_directory =
        crate::secure_fs::Directory::open_exact(&build, "card R1 build directory")?;
    let bootstrap =
        build_directory.with_inheritable_anchor("card R1 build directory", |anchor| {
            crate::wyr1c6::build_c6_bootstrap(&repository, &toolchain, &layout, &cargo_home, anchor)
        })?;
    // The snapshot is assembled before the kernel on purpose: the kernel's
    // mapping journal is sized from the archives' measured page count, so they
    // must exist first. Nothing in the snapshot consumes the kernel — the ESP
    // composition that needs both still runs after this.
    let snapshot = build_snapshot(&repository, &project, nonce)?;
    let bootfs_pages = bootfs_page_ceiling(&snapshot.bootfs)?;
    let kernel = build_kernel(&deep_repository, nonce, bootfs_pages)?;
    let media = R1Media {
        loader: uefi.loader_bytes,
        kernel,
        bootstrap,
        boot_device_table: crate::wyr1c6::boot_device_table(),
        ovmf_code: pinned_firmware(
            crate::wyr1c6::OVMF_CODE_PATH,
            crate::wyr1c6::OVMF_CODE_SHA256,
            "OVMF code",
        )?,
        ovmf_vars: pinned_firmware(
            crate::wyr1c6::OVMF_VARS_PATH,
            crate::wyr1c6::OVMF_VARS_SHA256,
            "OVMF vars",
        )?,
    };

    toolchain.accepted().verify_unchanged()?;
    layout.verify_unchanged()?;
    verify_repository_revision(&repository, &wyrmroot_revision)?;

    let artifacts = output.join("artifacts");
    fs::create_dir(&artifacts)
        .map_err(|error| Failure::task(format!("could not create card R1 artifacts: {error}")))?;
    let payload = |label: &str| -> Result<&Vec<u8>, Failure> {
        snapshot
            .artifacts
            .get(label)
            .ok_or_else(|| Failure::task(format!("card R1 snapshot omitted {label}")))
    };
    let mut digests: BTreeMap<String, String> = BTreeMap::new();
    for (name, bytes) in [
        ("loader.efi", &media.loader),
        ("deepwyrm.elf", &media.kernel),
        ("deepwyrm.symbols.elf", &media.kernel),
        ("bootstrap.elf", &media.bootstrap),
        ("system-init.elf", payload("system-init")?),
        ("registryd.elf", payload("registryd")?),
        ("devmgr.elf", payload("devmgr")?),
        ("uart16550d.elf", payload("uart16550d")?),
        ("consoled.elf", payload("consoled")?),
        ("wyrmsh.elf", payload("wyrmsh")?),
        ("r1-probe.elf", payload("r1-probe")?),
        ("cpu-hog.elf", payload("cpu-hog")?),
        ("hello.elf", payload("hello")?),
        ("boot-device-table.bin", &media.boot_device_table),
        ("OVMF_CODE.fd", &media.ovmf_code),
        ("OVMF_VARS.fd", &media.ovmf_vars),
        ("rrc-r1-v1.bin", &snapshot.rrc_manifest),
        ("wrdm-r1-v1.bin", &snapshot.device_manifest),
        ("launch-policy-v1.bin", &snapshot.launch_policy),
    ] {
        write_new(&artifacts.join(name), bytes, name)?;
        digests.insert(name.to_owned(), sha256::bytes_digest(bytes));
    }

    for (profile, _, _) in PROFILES {
        let directory = output.join(profile);
        fs::create_dir(&directory).map_err(|error| {
            Failure::task(format!(
                "could not create card R1 {profile} handoff: {error}"
            ))
        })?;
        let archive = snapshot
            .bootfs
            .get(profile)
            .ok_or_else(|| Failure::task("card R1 snapshot lacks a profile archive"))?;
        let gate = snapshot
            .gates
            .get(profile)
            .ok_or_else(|| Failure::task("card R1 snapshot lacks a profile gate"))?;
        write_new(&directory.join("bootfs.img"), archive, "profile bootfs")?;
        write_new(&directory.join("r1-gate-v1.bin"), gate, "profile gate")?;
        let esp = compose_profile_esp(&artifacts, &directory)?;
        let esp_bytes =
            crate::wyr1c6::read_regular_bounded(&esp, crate::g3_image::IMAGE_BYTES, "card R1 ESP")?;
        let vcpus = PROFILES
            .iter()
            .find(|(name, _, _)| *name == profile)
            .map(|(_, _, cpus)| u8::try_from(*cpus).unwrap_or(u8::MAX))
            .ok_or_else(|| Failure::task("card R1 profile width is unknown"))?;
        // The nvram path is the copy `run-active-gdb-vm.sh` makes for itself at
        // run time. Staging it here would make the harness refuse to start.
        let xml = domain_xml(
            vcpus,
            gdb_port,
            &artifacts.join("OVMF_CODE.fd"),
            &esp,
            &directory.join("OVMF_VARS.fd"),
        );
        write_new(
            &directory.join("domain.xml"),
            xml.as_bytes(),
            "profile domain",
        )?;
        if directory.join("OVMF_VARS.fd").exists() {
            return Err(Failure::task(
                "card R1 must not stage OVMF_VARS.fd; the GDB harness refuses to run when it exists",
            ));
        }
        digests.insert(
            format!("{profile}/bootfs.img"),
            sha256::bytes_digest(archive),
        );
        digests.insert(
            format!("{profile}/r1-gate-v1.bin"),
            sha256::bytes_digest(gate),
        );
        digests.insert(
            format!("{profile}/r1-esp.img"),
            sha256::bytes_digest(&esp_bytes),
        );
        digests.insert(
            format!("{profile}/domain.xml"),
            sha256::bytes_digest(xml.as_bytes()),
        );
    }

    write_new(
        &output.join("product/build-receipt.toml"),
        &snapshot.receipt,
        "card R1 product receipt",
    )
    .or_else(|_| {
        fs::create_dir(output.join("product")).map_err(|error| {
            Failure::task(format!(
                "could not create card R1 product directory: {error}"
            ))
        })?;
        write_new(
            &output.join("product/build-receipt.toml"),
            &snapshot.receipt,
            "card R1 product receipt",
        )
    })?;

    let request = render_request(
        &output,
        card,
        &wyrmroot_revision,
        deep_revision,
        &abi_revision,
        &abi_tree,
        nonce,
        gdb_port,
        bootfs_pages,
        &digests,
    )?;
    write_new(
        &output.join("request.toml"),
        request.as_bytes(),
        "card R1 request",
    )?;
    digests.insert(
        "request.toml".to_owned(),
        sha256::bytes_digest(request.as_bytes()),
    );

    let receipt = render_source_receipt(
        &wyrmroot_revision,
        deep_revision,
        &abi_revision,
        &abi_tree,
        nonce,
        gdb_port,
        bootfs_pages,
        &digests,
    )?;
    write_new(
        &output.join("source-receipt.toml"),
        receipt.as_bytes(),
        "card R1 source receipt",
    )?;
    fs::remove_dir_all(&build).map_err(|error| {
        Failure::task(format!("could not remove card R1 build directory: {error}"))
    })?;
    let _ = MAX_ARTIFACT_BYTES;
    toolchain.accepted().verify_unchanged()?;
    verify_repository_revision(&repository, &wyrmroot_revision)?;
    Ok(format!(
        "WYR1_R1_PREPARE_PASS product_kind={PRODUCT_KIND} selector={SELECTOR} test_id={TEST_ID} \
         request=request.toml physical_io=not-performed deepwyrm_revision={deep_revision} \
         wyrmroot_revision={wyrmroot_revision} gdb_port={gdb_port} \
         source_receipt={}\n",
        output.join("source-receipt.toml").display(),
    ))
}

#[allow(clippy::too_many_arguments)]
fn render_source_receipt(
    wyrmroot_revision: &str,
    deep_revision: &str,
    abi_revision: &str,
    abi_tree: &str,
    nonce: &str,
    gdb_port: u16,
    bootfs_pages: usize,
    digests: &BTreeMap<String, String>,
) -> Result<String, Failure> {
    use std::fmt::Write as _;
    let mut receipt = String::new();
    writeln!(&mut receipt, "schema = \"wyrmroot-r1-source-receipt-v1\"")
        .map_err(|_| Failure::task("card R1 receipt write failed"))?;
    for (key, value) in [
        ("product_kind", PRODUCT_KIND.to_owned()),
        ("selector", SELECTOR.to_owned()),
        ("test_id", TEST_ID.to_string()),
        ("wyrmroot_revision", wyrmroot_revision.to_owned()),
        ("deepwyrm_revision", deep_revision.to_owned()),
        ("generated_abi_revision", abi_revision.to_owned()),
        ("generated_abi_tree", abi_tree.to_owned()),
        ("rust_revision", ACCEPTED_RUST_REVISION.to_owned()),
        ("rust_toolchain", ACCEPTED_TOOLCHAIN_NAME.to_owned()),
        ("evidence_nonce", nonce.to_owned()),
        ("gdb_port", gdb_port.to_string()),
        ("machine", MACHINE.to_owned()),
        ("firmware", "uefi-ovmf-x64".to_owned()),
        ("memory_kib", MEMORY_KIB.to_string()),
        ("request", "request.toml".to_owned()),
        ("physical_io", "not-performed".to_owned()),
        ("baseline_domain_sha256", BASELINE_DOMAIN_SHA256.to_owned()),
        ("domain_uuid", DOMAIN_UUID.to_owned()),
        // The exact bound compiled into the kernel's primordial mapping
        // journal, so a later reader can check it against the archives below.
        ("bootfs_pages", bootfs_pages.to_string()),
        (
            "kernel_bootfs_env",
            format!("{R1_BOOTFS_PAGES_VARIABLE}={bootfs_pages}"),
        ),
    ] {
        writeln!(&mut receipt, "{key} = \"{value}\"").ok();
    }
    for (profile, hog_count, online_cpus) in PROFILES {
        writeln!(&mut receipt, "\n[profile.{profile}]").ok();
        writeln!(&mut receipt, "hog_count = {hog_count}").ok();
        writeln!(&mut receipt, "online_cpus = {online_cpus}").ok();
    }
    writeln!(&mut receipt, "\n[digest]").ok();
    for (name, digest) in digests {
        writeln!(&mut receipt, "\"{name}\" = \"{digest}\"").ok();
    }
    Ok(receipt)
}

/// The approved inactive baseline the GDB harness restores the domain to. Quoted
/// into the receipt so an operator can check it against `AGENTS.md` §10 without
/// reading the harness.
pub(crate) const BASELINE_DOMAIN_SHA256: &str =
    "a823095e2182f848be0c15fe1a88728fce9f126fbc55e7d9aab30d84a6c5d3c3";

/// Host timeout for one profile leg, in seconds.
///
/// This must **exceed the probe's own bounds**, and that is the whole point.
/// A27 failed because the host's 30 s bound expired before anything in the guest
/// reported, so the only evidence was "a spawn timed out". The probe now bounds
/// every wait itself — 3 s for an accept, 8 s for a terminal result — so the host
/// timeout exists only to stop a genuinely wedged guest, and must be larger than
/// any sequence the probe can legitimately take.
///
/// Worst case for the six-hog leg: per hog, a hog accept (3) plus a progress
/// accept (3) plus a progress result (8) is 14 s, and bounded cleanup is a
/// termination accept (8) plus a hog result (8), 16 s. Six hogs is 180 s, plus
/// firmware and boot. 300 s leaves margin without letting a wedged guest hold the
/// lease indefinitely.
pub(crate) const REQUEST_TIMEOUT_SECONDS: u32 = 300;

/// Seconds the probe itself can legitimately consume on the SMP leg, from its own
/// bounds. Kept beside the host timeout so the ordering between them is a test
/// rather than a comment.
pub(crate) const PROBE_WORST_CASE_SECONDS: u32 = 180;

/// Renders the request AGENTS.md §10 requires before a run.
///
/// §10 names eight things an acceptable request must carry: project and gate,
/// exact Deepwyrm and Wyrmroot revisions with dirty qualification, artifact and
/// media identity, the effective profile, selector, commands and expected
/// signals, timeout and logs, and destructive storage, configuration and cleanup
/// needs. Each has a section below, and the emitted file is what Mike accepts —
/// it is not consumed by `tools/verify-vm-request.py`, which serves the
/// `run-verified-vm-request.py` capture/recheck flow that a GDB-attached
/// diagnostic run does not use.
#[allow(clippy::too_many_arguments)]
/// Which reset card a prepared request is for.
///
/// The gate block is not decoration: it is what a reader checks a run against
/// before accepting it, so a request prepared for one card must not carry
/// another card's question. R1C wanted a classified failure and R4E does not,
/// and that difference belongs in the file rather than in whoever remembers it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequestCard {
    R1C,
    R4E,
}

impl RequestCard {
    pub(crate) fn parse(name: &str) -> Option<Self> {
        match name {
            "R1C" => Some(Self::R1C),
            "R4E" => Some(Self::R4E),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::R1C => "R1C",
            Self::R4E => "R4E",
        }
    }

    fn question(self) -> &'static str {
        match self {
            Self::R1C => {
                "reproduce the present failure family, or establish that A27 depends on additional E8 state"
            }
            Self::R4E => {
                "does every continuously runnable unpinned thread execute, and does the independent progress child stay responsive, while more hogs than CPUs are launched on exactly four vCPUs"
            }
        }
    }

    fn gate_notes(self) -> &'static [&'static str] {
        match self {
            Self::R1C => &[
                "# A failing run is a valid result if it identifies internal scheduler,",
                "# wait or teardown state. A run that stalls and captures no structured",
                "# state fails the card even though the VM behaved.",
            ],
            Self::R4E => &[
                "# A classified failure is a valid result and is not what this card",
                "# wants: it reports that R4's repair is incomplete, which is an answer.",
                "# R1C wanted such a failure; R4E does not. A run that stalls and",
                "# captures no structured state fails the card even though the VM",
                "# behaved, exactly as it did for R1C.",
                "#",
                "# This probe cannot discriminate R4B/R4C from their absence: it passed",
                "# four times before either existed, and it observes completion within a",
                "# latency bound rather than placement or share. Read a pass as evidence",
                "# that the live path is not regressed, not as vindication of the repair.",
                "# DW1_WYR1_RESET_R4E_VM_REQUEST.md section 4 states this at length.",
            ],
        }
    }

    fn gdb_notes(self) -> &'static [&'static str] {
        match self {
            Self::R1C => &[
                "# \u{a7}8.2's three carrier facts sit behind the monolithic runtime authority",
                "# on a boot-stack-pinned carrier, so reading a stopped guest over the",
                "# gdbstub is the only way to obtain them without entering the authority",
                "# under investigation.",
            ],
            Self::R4E => &[
                "# R1C required the gdbstub to read carrier facts from a stopped guest.",
                "# R4E expects passing runs and requires it for the opposite reason: if a",
                "# run does stall, the \u{a7}9 gate still demands internal scheduler, wait or",
                "# teardown state rather than \"a spawn timed out\", and the snapshot is the",
                "# only thing that supplies it. The hook reads nothing on a passing run.",
            ],
        }
    }
}

#[allow(clippy::too_many_arguments, reason = "ten parameters are distinct fields of one rendered request")]
fn render_request(
    output: &Path,
    card: RequestCard,
    wyrmroot_revision: &str,
    deep_revision: &str,
    abi_revision: &str,
    abi_tree: &str,
    nonce: &str,
    gdb_port: u16,
    bootfs_pages: usize,
    digests: &BTreeMap<String, String>,
) -> Result<String, Failure> {
    use std::fmt::Write as _;
    let mut request = String::new();
    let mut line = |text: String| {
        let _ = writeln!(&mut request, "{text}");
    };

    line("schema = \"wyrmroot-r1-vm-request-v1\"".into());
    line(format!("kind = \"{REQUEST_KIND}\""));
    line("# Accepted by Mike before a run, per AGENTS.md §10. This file is not".into());
    line("# consumed by tools/verify-vm-request.py: that tool serves the".into());
    line("# run-verified-vm-request.py capture/recheck flow, and a GDB-attached".into());
    line("# diagnostic run goes through tools/run-active-gdb-vm.sh instead.".into());
    line(String::new());

    line("[gate]".into());
    line("project = \"DW1/WYR1 runtime reset\"".into());
    line(format!("card = \"{}\"", card.name()));
    line("plan = \"DW1_WYR1_RUNTIME_RESET_IMPLEMENTATION_PLAN.md\"".into());
    line(format!("question = \"{}\"", card.question()));
    line("acceptance_identity = \"none-minted\"".into());
    line("advances_e8 = false".into());
    line("security_conclusion = \"none\"".into());
    for note in card.gate_notes() {
        line((*note).into());
    }
    line("failing_run_is_valid = true".into());
    line(String::new());

    line("[revisions]".into());
    line(format!("deepwyrm = \"{deep_revision}\""));
    line("deepwyrm_dirty = \"clean\"".into());
    line(format!("wyrmroot = \"{wyrmroot_revision}\""));
    line("wyrmroot_dirty = \"clean\"".into());
    line(format!("rust = \"{ACCEPTED_RUST_REVISION}\""));
    line(format!("rust_toolchain = \"{ACCEPTED_TOOLCHAIN_NAME}\""));
    line(format!("generated_abi_revision = \"{abi_revision}\""));
    line(format!("generated_abi_tree = \"{abi_tree}\""));
    line("# Both checkouts were verified clean at preparation and the revisions".into());
    line("# above were re-verified after every build step.".into());
    line(String::new());

    line("[domain]".into());
    line("connection = \"qemu:///system\"".into());
    line("name = \"OS-Project\"".into());
    line(format!("uuid = \"{DOMAIN_UUID}\""));
    line(format!(
        "baseline_xml_sha256 = \"{BASELINE_DOMAIN_SHA256}\""
    ));
    line("lease = \"/tmp/os-project-vm.lock\"".into());
    line(format!("machine = \"{MACHINE}\""));
    line("firmware = \"uefi-ovmf-x64\"".into());
    line(format!("memory_kib = {MEMORY_KIB}"));
    line(String::new());

    line("[storage]".into());
    line("# §10 requires destructive needs to be stated. This card has none.".into());
    line("destructive_needs = \"none\"".into());
    line("primary_qcow2_host_side_mutation = \"not-requested\"".into());
    line("overlays = \"none\"".into());
    line("snapshots = \"none\"".into());
    line("guest_io = \"none; the guest writes no storage\"".into());
    line("media = \"project-owned, read-only ESP per profile\"".into());
    line("nvram = \"per-profile copy created by the harness inside the product\"".into());
    line(
        "configuration_delta = \"domain XML redefined per profile; harness restores the baseline\""
            .into(),
    );
    line("cleanup = \"harness destroys the domain if running, redefines the baseline, and records the inactive digest\"".into());
    line(String::new());

    line("[run]".into());
    line(format!("selector = \"{SELECTOR}\""));
    line(format!("test_id = {TEST_ID}"));
    line(format!("evidence_nonce = \"{nonce}\""));
    line(
        "evidence_protocol = \"R1SP over the selector-private evidence syscall 0xffffff22\"".into(),
    );
    line("transcript = \"COM1 serial; no COM2 conversation\"".into());
    line(format!("gdb_port = {gdb_port}"));
    // Stated because it is otherwise invisible at acceptance: Deepwyrm sizes
    // its primordial mapping journal from this measured count, and an archive
    // past the compiled bound fails the bootstrap's mapping rather than any
    // admission check.
    line(format!("bootfs_pages = {bootfs_pages}"));
    line(format!(
        "kernel_bootfs_env = \"{R1_BOOTFS_PAGES_VARIABLE}={bootfs_pages}\""
    ));
    line("gdb_required = true".into());
    for note in card.gdb_notes() {
        line((*note).into());
    }
    line("hook_profile = \"diagnostic-only\"".into());
    line(format!("timeout_seconds = {REQUEST_TIMEOUT_SECONDS}"));
    line(format!(
        "probe_worst_case_seconds = {PROBE_WORST_CASE_SECONDS}"
    ));
    line("# The host bound exceeds the probe's own, so the probe reports a".into());
    line("# classification rather than the host timing out first, which is exactly".into());
    line("# what left A27 with no evidence.".into());
    line("logs = \"serial.log, active.gdb.log, and the snapshot log on a timeout re-attach, per profile directory\"".into());
    line("physical_io = \"not-performed\"".into());
    line(String::new());

    for (profile, hog_count, online_cpus) in PROFILES {
        let directory = output.join(profile);
        line(format!("[profile.{profile}]"));
        line(format!("vcpus = {online_cpus}"));
        line(format!("hog_count = {hog_count}"));
        line(format!("domain_xml = \"{profile}/domain.xml\""));
        line(format!("esp = \"{profile}/r1-esp.img\""));
        line(format!("bootfs = \"{profile}/bootfs.img\""));
        line(format!("gate = \"{profile}/r1-gate-v1.bin\""));
        line("# §4: if the domain cannot present exactly this width, reject the".into());
        line("# request rather than run at another. A27's diagnosis depends on it.".into());
        line(format!(
            "command = \"ACTIVE_GDB_EXTRA_HOOKS=tools/gdb/r1-liveness.gdb \
             tools/run-active-gdb-vm.sh {} {} {} {} {gdb_port} {REQUEST_TIMEOUT_SECONDS} \
             diagnostic-only\"",
            directory.join("domain.xml").display(),
            output.join("artifacts/deepwyrm.symbols.elf").display(),
            output.join("artifacts/OVMF_VARS.fd").display(),
            directory.display(),
        ));
        line(String::new());
    }

    line("[expected_signals]".into());
    line(
        "pass = \"one R1SP terminal record with outcome zero, after the full step sequence\""
            .into(),
    );
    line("classified_failure = \"an R1SP failure record naming one of the seven ProbeFailure ordinals, then the terminal record\"".into());
    line(
        "card_failure = \"no structured record at all; the run stalled and proved nothing\"".into(),
    );
    line("# The third outcome is the only one that fails card R1 rather than".into());
    line("# answering it.".into());
    line(String::new());

    line("[digest]".into());
    for (name, digest) in digests {
        line(format!("\"{name}\" = \"{digest}\""));
    }
    Ok(request)
}

pub(crate) const REQUEST_KIND: &str = "wyrmroot-r1-saturation-request";
