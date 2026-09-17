//! DW1-F/WYR1-F final normal product freeze and inspection (slice F1A.4).
//!
//! This is the *final production* producer. It differs from `wyr1e7`/`wyr1e8`,
//! which are its structural templates, in five deliberate ways:
//!
//! 1. **Nothing is inherited.** `wyr1e8::prepare` takes `--e6-product` and
//!    reuses the frozen E6 `registryd`/`wyrmsh`/`stack-report` bytes. This
//!    producer rebuilds all seven natives from the exact F pair, because
//!    `plans/specs/DW1F_WYR1F_F1A_NORMAL_PRODUCT_SPEC.md` §F1A.3 says an
//!    inherited artifact cannot be relabelled as rebuilt. There is therefore no
//!    `e6_*` request or receipt field at all.
//! 2. **The artifact set is the seven production roles plus two admitted
//!    payloads** — `hello` and, since F3A.2b, `cpu-hog`. No malformed-ELF
//!    fixture, no exit-nonzero/fault/recovery-trigger/stdout-pressure actor
//!    and no stack report: those are final-*acceptance* content under
//!    `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` §2 and are not in this product.
//!
//!    The hog is the one addition and it is not a selector fixture. The
//!    production supervisor's `LaunchSessionScope::ShellJobs` already admitted
//!    `bin/hello | bin/cpu-hog` with no feature gate at all, so the payload's
//!    absence — not its presence — was the anomaly; the plan's final normal
//!    proof requires showing that several no-yield jobs cannot starve the
//!    shell under SMP, and no F product could run that. It enters the bootfs
//!    and the WRJP and stays out of RRC-A, so the degraded product's "shell
//!    remains usable from retained RRC-A material" proof is untouched.
//! 3. **The kernel is the uninstrumented production kernel.**
//!    `build_normal_kernel` removes `DEEPWYRM_GUEST_TEST_SELECTOR` rather than
//!    setting it and passes no `--features test-support`, which is the shape of
//!    `PRODUCTION_KERNEL_ROW` in `deepwyrm/tools/xtask/src/lib.rs`. The final
//!    closure selector `dw1-wyr1-interactive-closure` / 35 is recorded in the
//!    request as *reserved*, not as selected; the product that selects it is
//!    F1B's.
//! 4. **There is no evidence nonce anywhere.** The normal gate configuration is
//!    `wyr1c::WYR1F_NORMAL_GATE_CONFIG` — `selector = "none"`, no scenario, no
//!    nonce, and deliberately unparseable by `gate::parse_gate_config`.
//!    `wyr1c::wyr1f_gate_config` builds the *instrumented* configuration and is
//!    not called from here.
//! 5. **No selector-33 capacity contract is bound.**
//!    `deep_layout::read_wyr1e8_capacity_contract` reads
//!    `kernel/src/arch/x86_64/mm/activation/wyr1e8_resource_geometry.rs`, whose
//!    own first line says it is "Selector-33 E8 scenario demand, separate from
//!    production resource policy". Binding it into a production receipt would
//!    assert a resource policy this product does not have, so the exact kernel
//!    source is bound through `deep_layout::prepare_current_kernel_source` and
//!    the recorded Deepwyrm revision/ABI tree instead.
//!
//! `prepare --scenario degraded` is refused: the degraded product needs the
//! instrumented init artifact, which is slice F1B's (see
//! `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` §11 item 13).
//!
//! This module does not stage libvirt domain XML or per-profile handoffs. The
//! only existing helper, `dw1e3a::selected_domain_xml`, hard-requires a
//! `(selector, test_id)` fw_cfg pair, and this product selects no guest test;
//! emitting one would declare a selector the product does not carry. Every
//! VM-facing obligation is therefore carried as a typed request field, and the
//! root verifier/runner F adapter — a different owner under
//! `plans/specs/DW1F_WYR1F_F1A_NORMAL_PRODUCT_SPEC.md` §3 — owns the handoff
//! grammar.

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    cli::G3ImageArguments, error::Failure, g3_image, secure_fs::Directory, sha256, tasks, wyr1c,
    wyr1c6,
};

// The kinds no longer name a scenario. F1B makes this producer build all
// three final products -- the production normal, and the instrumented normal
// and degraded siblings of the acceptance pair -- and one schema that carries
// the product as a field is what lets a reviewer compare two siblings field by
// field instead of reconciling two schemas.
const REQUEST_KIND: &str = "wyrmroot-wyr1-f-request";
const RECEIPT_KIND: &str = "wyrmroot-wyr1-f-freeze-receipt";
const SOURCE_KIND: &str = "wyrmroot-wyr1-f-source-build";
const RESULT_KIND: &str = "wyrmroot-wyr1-f-result";
const HANDOFF_KIND: &str = "wyrmroot-wyr1-f-vm-handoff";
const PAIR_KIND: &str = "wyrmroot-wyr1-f-vm-profile-pair";
/// The two profiles the plan's F3A row requires of every final product: one
/// vCPU and four. The fairness obligation is only meaningful at the second, and
/// the first is what shows a UP regression the second would mask.
const PROFILES: [(&str, u8); 2] = [("default", 1), ("smp", 4)];
const SOURCE_RECEIPT: &str = "f-source-build.toml";
const KERNEL_TARGET: &str = "x86_64-unknown-none";

/// The ESP basename, which names its product so two siblings cannot be
/// confused for one another on disk.
fn esp_name(product: wyr1c::Wyr1fProduct) -> String {
    format!("wyr1f-{}-esp.img", product.cli_value())
}

/// The six supervised roles and the two admitted payloads, in the frozen order
/// of `wyr1c::WYR1F_PRODUCT_NATIVE_SPECS`.
const NATIVE_LABELS: [&str; 8] = [
    "system-init",
    "registryd",
    "devmgr",
    "uart16550d",
    "consoled",
    "wyrmsh",
    "hello",
    "cpu-hog",
];

/// Every frozen file, with the request key that names its path.
///
/// `gate_config` is listed separately from `bootfs` even though the archive
/// contains it, because `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` §5.4 makes the
/// whole gate-config file the declared normal/degraded difference: binding its
/// hash directly is what lets a reviewer check that difference without
/// unpacking the archive.
pub(crate) const ARTIFACTS: &[(&str, &str)] = &[
    ("loader", "loader.efi"),
    ("kernel", "deepwyrm.elf"),
    ("symbols", "deepwyrm.symbols.elf"),
    ("bootstrap", "bootstrap.elf"),
    ("system_init", "system-init.elf"),
    ("registryd", "registryd.elf"),
    ("devmgr", "devmgr.elf"),
    ("uart16550d", "uart16550d.elf"),
    ("consoled", "consoled.elf"),
    ("wyrmsh", "wyrmsh.elf"),
    ("hello", "hello.elf"),
    ("cpu_hog", "cpu-hog.elf"),
    ("gate_config", "wyr1-a-gate-v1.bin"),
    ("rrc_manifest", "rrc-f-v1.bin"),
    ("device_manifest", "wrdm-f-v1.bin"),
    ("launch_policy", "launch-policy-f-v1.bin"),
    ("boot_device_table", "boot-device-table.bin"),
    ("bootfs", "bootfs.img"),
    ("stack_report", "wyrmsh-stack.json"),
    ("ovmf_code", "OVMF_CODE.fd"),
    ("ovmf_vars", "OVMF_VARS.fd"),
];

struct Produced {
    directory: PathBuf,
    deep_revision: String,
    abi_revision: String,
    abi_tree: String,
    wyrmroot_revision: String,
    rust_revision: String,
}

pub(crate) fn prepare(
    output: &Path,
    scenario: &str,
    deep_repository: &Path,
    deep_revision: &str,
    evidence_nonce: Option<&str>,
) -> Result<String, Failure> {
    // Scenario and nonce first, before any environment probe or filesystem
    // effect, so a malformed request cannot leave a half-made root behind.
    let product_kind = wyr1c::Wyr1fProduct::parse(scenario)?;
    let gate_config = product_kind.gate_config(evidence_nonce)?;
    wyr1c::reject_e6_ambient_build_environment(env::vars_os())?;
    reject_selector_environment()?;
    wyr1c6::validate_revision(deep_revision, "Deepwyrm revision")?;
    let repository = tasks::repository_root()?;
    let project = tasks::canonical_project_root(&repository)?;
    let deep_repository = wyr1c6::canonical_deep_repository(deep_repository, &project)?;
    let wyrmroot_revision = wyr1c6::clean_revision(&repository, "Wyrmroot")?;
    wyr1c6::verify_clean_revision(&deep_repository, "Deepwyrm", deep_revision)?;
    let manifest = crate::metadata::BuildManifest::load(&repository)?;
    let abi_revision = manifest.deepwyrm_revision()?.to_owned();
    let abi_tree = wyr1c6::matching_abi_tree(&deep_repository, deep_revision, &abi_revision)?;
    let layout = crate::deep_layout::prepare_current_kernel_source(
        &repository,
        &deep_repository,
        deep_revision,
    )?;
    let output = wyr1c::validate_fresh_output(&repository, &project, output)?;
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
        .as_nanos();
    let staging = repository
        .join(".tmp")
        .join(format!("wyr1f-producer-{}-{unique}", std::process::id()));
    fs::create_dir(&staging)
        .map_err(|error| Failure::task(format!("could not create WYR1-F staging: {error}")))?;
    let result = (|| {
        let produced = build_produced(
            &staging,
            &repository,
            &deep_repository,
            &wyrmroot_revision,
            deep_revision,
            &abi_revision,
            &abi_tree,
            &layout,
            product_kind,
            &gate_config,
        )?;
        freeze(&output, &produced, product_kind)
    })();
    if result.is_ok() {
        fs::remove_dir_all(&staging)
            .map_err(|error| Failure::task(format!("could not retire WYR1-F staging: {error}")))?;
    }
    result
}

pub(crate) fn inspect(product: &Path) -> Result<String, Failure> {
    let repository = tasks::repository_root()?;
    let project = tasks::canonical_project_root(&repository)?;
    let product = fs::canonicalize(product)
        .map_err(|error| Failure::task(format!("could not resolve WYR1-F product: {error}")))?;
    if !product.starts_with(&project) || product.starts_with(&repository) {
        return Err(Failure::task("WYR1-F product locality is invalid"));
    }
    let request_bytes =
        wyr1c6::read_regular_bounded(&product.join("request.toml"), 64 * 1024, "WYR1-F request")?;
    let request_text = std::str::from_utf8(&request_bytes)
        .map_err(|_| Failure::task("WYR1-F request is not UTF-8"))?;
    let request = parse(request_text)?;
    let product_kind = product_kind_of(&request)?;
    validate_request(&request)?;
    if render(&request, &request_keys(product_kind), ScalarSchema::Request)? != request_text {
        return Err(Failure::task("WYR1-F request is not canonical"));
    }
    let revision = wyr1c6::clean_revision(&repository, "Wyrmroot")?;
    if field(&request, "wyrmroot_revision")? != revision {
        return Err(Failure::task("WYR1-F source revision changed"));
    }
    validate_frozen_metadata(product_kind, &product, &request)?;

    // Byte-for-byte reconstruction from the frozen native ELFs.
    let mut artifacts = BTreeMap::new();
    for label in NATIVE_LABELS {
        let key = label.replace('-', "_");
        artifacts.insert(
            label.to_owned(),
            wyr1c6::read_regular_bounded(
                &product.join(field(&request, &key)?),
                wyr1c6::MAX_ARTIFACT_BYTES,
                label,
            )?,
        );
    }
    let gate_config = wyr1c6::read_regular_bounded(
        &product.join(field(&request, "gate_config")?),
        64 * 1024,
        "WYR1-F gate configuration",
    )?;
    let assembled =
        wyr1c::reassemble_wyr1f_snapshot(&revision, &artifacts, product_kind, &gate_config)?;
    for (key, actual) in [
        ("rrc_manifest", assembled.rrc_manifest.as_slice()),
        ("device_manifest", assembled.device_manifest.as_slice()),
        ("launch_policy", assembled.launch_policy.as_slice()),
        ("bootfs", assembled.bootfs.as_slice()),
    ] {
        let frozen = wyr1c6::read_regular_bounded(
            &product.join(field(&request, key)?),
            wyr1c6::MAX_ARTIFACT_BYTES,
            key,
        )?;
        if frozen != actual {
            return Err(Failure::task(format!("WYR1-F {key} reconstruction failed")));
        }
    }
    // Rebuilt from the declared product, not compared with one literal. The
    // production configuration is deliberately unparseable; an instrumented
    // one carries the frozen selector/test-id pair, its scenario and a nonzero
    // nonce. F1B.5 found this reading the production literal for every
    // product, which is also how the degraded product came to freeze it.
    let declared = product_kind
        .gate_config(wyr1c::wyr1f_kernel_evidence_nonce(product_kind, &gate_config)?.as_deref())?;
    if gate_config != declared {
        return Err(Failure::task(format!(
            "WYR1-F gate configuration is not the frozen {} configuration",
            product_kind.cli_value()
        )));
    }
    for (key, _) in ARTIFACTS {
        let bytes = wyr1c6::read_regular_bounded(
            &product.join(field(&request, key)?),
            artifact_maximum(key),
            key,
        )?;
        if sha256::bytes_digest(&bytes) != field(&request, &format!("{key}_sha256"))? {
            return Err(Failure::task(format!("WYR1-F {key} hash drifted")));
        }
    }
    let mut inspections = BTreeMap::new();
    for (label, bytes) in &artifacts {
        let digest = sha256::bytes_digest(bytes);
        inspections.insert(
            label.clone(),
            wyr1c::inspect_native_bytes(&repository, bytes, &digest, label)?.into_bytes(),
        );
    }
    // The shell's bounded stack depth is reproduced from the frozen ELF, not
    // read back from the frozen report. It is a production property of
    // `system/wyrmsh` — the shell is built with `-Zemit-stack-sizes` precisely
    // so it can be proved — so the final product binds it exactly as every
    // accepted product does.
    let frozen_stack_report = wyr1c6::read_regular_bounded(
        &product.join(field(&request, "stack_report")?),
        wyr1c6::MAX_ARTIFACT_BYTES,
        "WYR1-F stack report",
    )?;
    let shell = artifacts
        .get("wyrmsh")
        .ok_or_else(|| Failure::task("WYR1-F product lacks wyrmsh"))?;
    if wyr1c::wyrmsh_stack_report(&repository, shell)? != frozen_stack_report {
        return Err(Failure::task(
            "WYR1-F shell stack proof was not reproduced byte-for-byte",
        ));
    }
    validate_esp(&product, &request)?;

    let source = wyr1c6::read_regular_bounded(
        &product.join(field(&request, "source_receipt")?),
        64 * 1024,
        "WYR1-F source receipt",
    )?;
    let source_text = std::str::from_utf8(&source)
        .map_err(|_| Failure::task("WYR1-F source receipt is not UTF-8"))?;
    if sha256::bytes_digest(&source) != field(&request, "source_receipt_sha256")?
        || parse(source_text).is_err()
    {
        return Err(Failure::task("WYR1-F source receipt drifted"));
    }
    let manifest = crate::metadata::BuildManifest::load(&repository)?;
    if field(&request, "rust_revision")? != manifest.rust_revision()?
        || field(&request, "generated_abi_revision")? != manifest.deepwyrm_revision()?
    {
        return Err(Failure::task(
            "WYR1-F request does not match current source metadata",
        ));
    }
    let deep_repository = wyr1c6::canonical_deep_repository(&project.join("deepwyrm"), &project)?;
    let abi_tree = wyr1c6::matching_abi_tree(
        &deep_repository,
        field(&request, "deepwyrm_revision")?,
        field(&request, "generated_abi_revision")?,
    )?;
    if abi_tree != field(&request, "generated_abi_tree")? {
        return Err(Failure::task("WYR1-F generated ABI tree changed"));
    }
    let profile = manifest.validate_loader_build_readiness(&repository)?;
    let toolchain = tasks::prepare_loader_toolchain(&repository, &profile, &manifest)?;
    let expected_source = source_receipt(
        &manifest,
        toolchain.accepted(),
        field(&request, "deepwyrm_revision")?,
        field(&request, "generated_abi_revision")?,
        field(&request, "generated_abi_tree")?,
        &revision,
        &product.join("artifacts"),
        &assembled.generation,
        &inspections,
        product_kind,
    )?;
    if source_text != expected_source {
        return Err(Failure::task("WYR1-F source receipt is not canonical"));
    }
    Ok(format!(
        "WYR1_F_INSPECT_PASS product={} scenario={} selector={} wyrmroot_revision={revision} bootfs_sha256={}\n",
        field(&request, "product")?,
        field(&request, "scenario")?,
        field(&request, "selector")?,
        sha256::bytes_digest(&assembled.bootfs)
    ))
}

/// Refuses ambient selector/evidence state.
///
/// A production freeze that inherits `DEEPWYRM_GUEST_TEST_SELECTOR` from the
/// operator's shell would silently produce an instrumented kernel under a
/// request that says `selector = "none"`, which is exactly the undeclared drift
/// `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` §3.1 forbids.
fn reject_selector_environment() -> Result<(), Failure> {
    for key in [
        "DEEPWYRM_GUEST_TEST_SELECTOR",
        "DEEPWYRM_GUEST_TEST_ID",
        "DEEPWYRM_DW1E_EVIDENCE_NONCE",
        "DEEPWYRM_WYR1E7_EVIDENCE_NONCE",
        "DEEPWYRM_WYR1E8_EVIDENCE_NONCE",
        "DEEPWYRM_WYR1E8_EVIDENCE",
        "WYRMROOT_WYR1E7_EVIDENCE_NONCE",
        "WYRMROOT_WYR1E8_EVIDENCE_NONCE",
        "CARGO_TARGET_DIR",
    ] {
        if env::var_os(key).is_some() {
            return Err(Failure::task(format!(
                "WYR1-F prepare refuses ambient {key}"
            )));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_produced(
    staging: &Path,
    repository: &Path,
    deep_repository: &Path,
    wyrmroot_revision: &str,
    deep_revision: &str,
    abi_revision: &str,
    abi_tree: &str,
    layout: &crate::deep_layout::DeepLayoutBuild,
    product_kind: wyr1c::Wyr1fProduct,
    gate_config: &[u8],
) -> Result<Produced, Failure> {
    let manifest = crate::metadata::BuildManifest::load(repository)?;
    let profile = manifest.validate_loader_build_readiness(repository)?;
    let toolchain = tasks::prepare_loader_toolchain(repository, &profile, &manifest)?;
    let cargo_home = tasks::project_cargo_home(repository, &manifest)?;
    if env::var_os("CARGO_HOME").as_deref() != Some(cargo_home.as_os_str()) {
        return Err(Failure::task(
            "WYR1-F prepare requires the pinned launcher's exact CARGO_HOME",
        ));
    }
    let deep_source = wyr1c::inspect_e6_dependency_source(
        repository,
        &manifest,
        toolchain.accepted(),
        &cargo_home,
    )?;
    let build = staging.join("build");
    fs::create_dir(&build)
        .map_err(|e| Failure::task(format!("could not create WYR1-F build root: {e}")))?;
    let uefi = tasks::build_deterministic_uefi_pair(
        repository,
        &toolchain,
        &profile,
        layout,
        &tasks::IsolatedUefiBuild {
            cargo_home: &cargo_home,
            production_target: &build.join("uefi-production"),
            retained_debug_target: &build.join("uefi-retained-debug"),
            cargo_profile: tasks::UefiCargoProfile::Release,
        },
    )?;
    let build_directory = Directory::open_exact(&build, "WYR1-F build directory")?;
    let bootstrap =
        build_directory.with_inheritable_anchor("WYR1-F build directory", |anchor| {
            crate::dw1e3a::build_bootstrap(repository, &toolchain, layout, &cargo_home, anchor)
        })?;

    let natives = staging.join("natives");
    fs::create_dir(&natives)
        .map_err(|e| Failure::task(format!("could not create WYR1-F native root: {e}")))?;
    let native_directory = Directory::open_exact(&natives, "WYR1-F native directory")?;
    let mut artifact_bytes = BTreeMap::new();
    let mut inspections = BTreeMap::new();
    let mut stack_report = None;
    for label in NATIVE_LABELS {
        let spec = wyr1c::wyr1f_native_spec(label, product_kind)?;
        toolchain.accepted().verify_unchanged()?;
        deep_source.verify_unchanged()?;
        let artifact =
            native_directory.with_inheritable_anchor("WYR1-F native directory", |anchor| {
                wyr1c::build_native_with_flags(
                    repository,
                    &cargo_home,
                    toolchain.accepted(),
                    anchor,
                    spec,
                    // No nonce: the production build removes every evidence
                    // variable instead of setting one.
                    None,
                    // The shell carries the production rustflags every
                    // accepted product builds it with. They are a production
                    // setting, not instrumentation:
                    // `Plans/WYR1_E6_VALIDATION.md` calls
                    // `-Cjump-tables=no -Zemit-stack-sizes` "the production
                    // shell" setting, and dropping them would both change the
                    // shell binary and lose the stack-size sections the native
                    // stack proof reads.
                    wyr1c::NativeBuildOptions::exact_with_evidence_and_flags(
                        "WYRMROOT_WYR1E8_EVIDENCE_NONCE",
                        if label == "wyrmsh" {
                            &wyr1c::WYRMSH_PRODUCTION_FLAGS
                        } else {
                            &[]
                        },
                    ),
                )
            })?;
        let inspection =
            wyr1c::inspect_native_bytes(repository, &artifact.bytes, &artifact.sha256, label)?;
        if label == "wyrmsh" {
            stack_report = Some(wyr1c::wyrmsh_stack_report(repository, &artifact.bytes)?);
        }
        artifact_bytes.insert(label.to_owned(), artifact.bytes);
        inspections.insert(label.to_owned(), inspection.into_bytes());
    }
    let stack_report =
        stack_report.ok_or_else(|| Failure::task("WYR1-F build omitted the shell stack proof"))?;

    let product = wyr1c::reassemble_wyr1f_snapshot(
        wyrmroot_revision,
        &artifact_bytes,
        product_kind,
        gate_config,
    )?;
    // F3A.6y. The production kernel's bootfs page ceiling is measured from the
    // archive that will actually be mapped, rather than the Wave 4 literal
    // Deepwyrm held: a 203-page archive against a 17-page ceiling is what made
    // the F production product fail bootstrap with an opaque NO_RESOURCES.
    // Measured here because this is the point where the archive exists and the
    // kernel has not been built yet.
    let bootfs_pages = product.bootfs.len().div_ceil(4096);
    let kernel = build_kernel(deep_repository, product_kind, gate_config, bootfs_pages)?;
    let boot_device_table = wyr1c6::boot_device_table();
    let ovmf_code = wyr1c6::pinned_firmware(
        wyr1c6::OVMF_CODE_PATH,
        wyr1c6::OVMF_CODE_SHA256,
        "OVMF code",
    )?;
    let ovmf_vars = wyr1c6::pinned_firmware(
        wyr1c6::OVMF_VARS_PATH,
        wyr1c6::OVMF_VARS_SHA256,
        "OVMF vars",
    )?;
    let artifacts = staging.join("artifacts");
    fs::create_dir(&artifacts)
        .map_err(|e| Failure::task(format!("could not create WYR1-F artifacts: {e}")))?;
    let native = |label: &str| {
        artifact_bytes
            .get(label)
            .map(Vec::as_slice)
            .ok_or_else(|| Failure::task(format!("WYR1-F builder omitted {label}")))
    };
    for (name, bytes) in [
        ("loader.efi", uefi.loader_bytes.as_slice()),
        ("deepwyrm.elf", kernel.as_slice()),
        // The same bytes as `deepwyrm.elf`, deliberately: the release profile
        // keeps full DWARF, which is what makes a separate symbol artifact
        // unnecessary. Recorded at `r1.rs:753` and true of every product here.
        ("deepwyrm.symbols.elf", kernel.as_slice()),
        ("bootstrap.elf", bootstrap.as_slice()),
        ("system-init.elf", native("system-init")?),
        ("registryd.elf", native("registryd")?),
        ("devmgr.elf", native("devmgr")?),
        ("uart16550d.elf", native("uart16550d")?),
        ("consoled.elf", native("consoled")?),
        ("wyrmsh.elf", native("wyrmsh")?),
        ("hello.elf", native("hello")?),
        ("cpu-hog.elf", native("cpu-hog")?),
        ("wyr1-a-gate-v1.bin", gate_config),
        ("rrc-f-v1.bin", product.rrc_manifest.as_slice()),
        ("wrdm-f-v1.bin", product.device_manifest.as_slice()),
        ("launch-policy-f-v1.bin", product.launch_policy.as_slice()),
        ("boot-device-table.bin", boot_device_table.as_slice()),
        ("bootfs.img", product.bootfs.as_slice()),
        ("wyrmsh-stack.json", stack_report.as_slice()),
        ("OVMF_CODE.fd", ovmf_code.as_slice()),
        ("OVMF_VARS.fd", ovmf_vars.as_slice()),
    ] {
        wyr1c6::write_new(&artifacts.join(name), bytes, name)?;
    }
    let source = source_receipt(
        &manifest,
        toolchain.accepted(),
        deep_revision,
        abi_revision,
        abi_tree,
        wyrmroot_revision,
        &artifacts,
        &product.generation,
        &inspections,
        product_kind,
    )?;
    wyr1c6::write_new(
        &artifacts.join(SOURCE_RECEIPT),
        source.as_bytes(),
        "WYR1-F source receipt",
    )?;
    toolchain.accepted().verify_unchanged()?;
    deep_source.verify_unchanged()?;
    layout.verify_unchanged()?;
    wyr1c6::verify_clean_revision(repository, "Wyrmroot", wyrmroot_revision)?;
    wyr1c6::verify_clean_revision(deep_repository, "Deepwyrm", deep_revision)?;
    Ok(Produced {
        directory: artifacts,
        deep_revision: deep_revision.into(),
        abi_revision: abi_revision.into(),
        abi_tree: abi_tree.into(),
        wyrmroot_revision: wyrmroot_revision.into(),
        rust_revision: manifest.rust_revision()?.into(),
    })
}

/// Builds the uninstrumented production kernel.
///
/// Written here rather than reusing `wyr1e7::build_e8_kernel`, which cannot be
/// reused honestly: that helper sets `DEEPWYRM_GUEST_TEST_SELECTOR`,
/// `DEEPWYRM_WYR1E8_EVIDENCE` and a nonce, and passes `--features test-support`.
/// The production build removes the selector variable and passes no features,
/// which is the shape of `PRODUCTION_KERNEL_ROW`
/// (`deepwyrm/tools/xtask/src/lib.rs:535`).
fn build_kernel(
    repository: &Path,
    product_kind: wyr1c::Wyr1fProduct,
    gate_config: &[u8],
    bootfs_pages: usize,
) -> Result<Vec<u8>, Failure> {
    let nonce = wyr1c::wyr1f_kernel_evidence_nonce(product_kind, gate_config)?;
    let repository = Directory::open_exact(repository, "Deepwyrm source root")?;
    let temporary = match repository.open_child(".tmp", "Deepwyrm temporary root") {
        Ok(directory) => directory,
        Err(_) => repository.create_child(".tmp", 0o700, "Deepwyrm temporary root")?,
    };
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::task("system clock is before the Unix epoch"))?
        .as_nanos();
    let build = temporary.create_child(
        &format!("wyr1f-kernel-{}-{unique}", std::process::id()),
        0o700,
        "WYR1-F kernel target",
    )?;
    let target = build.create_child("target", 0o700, "WYR1-F Cargo target")?;
    let stdout = build.create_file("cargo.stdout.log", 0o600, "WYR1-F kernel stdout")?;
    let stderr = build.create_file("cargo.stderr.log", 0o600, "WYR1-F kernel stderr")?;
    let status = kernel_build_command(
        &repository.path().join("tools/pinned-cargo"),
        repository.path(),
        target.path(),
        nonce.as_deref(),
        bootfs_pages,
    )
    .stdout(Stdio::from(stdout))
    .stderr(Stdio::from(stderr))
    .status()
    .map_err(|error| Failure::task(format!("could not build WYR1-F kernel: {error}")))?;
    if !status.success() {
        return Err(Failure::task(format!(
            "WYR1-F production Deepwyrm kernel build failed; logs preserved in {}",
            build.path().display()
        )));
    }
    target.read_producer(
        &PathBuf::from(KERNEL_TARGET).join("release/deepwyrm-kernel"),
        wyr1c6::MAX_ARTIFACT_BYTES,
        "WYR1-F production kernel",
    )
}

fn kernel_build_command(
    pinned_cargo: &Path,
    repository: &Path,
    target: &Path,
    // The instrumentation is exactly "does this product have an evidence
    // nonce", and `wyr1c::wyr1f_kernel_evidence_nonce` is the one place that
    // decides it from the product kind. Taking the answer rather than the
    // product keeps a second, divergent decision from existing here.
    evidence_nonce: Option<&str>,
    // Measured page count of the archive this product will map. Only the
    // production kernel consults it: the instrumented siblings' selector
    // reaches a different `PRIMORDIAL_BOOTFS_MAX_PAGES` arm, so passing it to
    // them would be an inert variable in a build whose kernel contract §5.4
    // requires to be identical across the pair.
    bootfs_pages: usize,
) -> Command {
    let mut command = Command::new(pinned_cargo);
    command
        .arg("target")
        .args([
            "build",
            "--locked",
            "--offline",
            "--release",
            "--target",
            KERNEL_TARGET,
            "--package",
            "deepwyrm-kernel",
            "--bin",
            "deepwyrm-kernel",
        ])
        .env("DEEPWYRM_PINNED_TARGET_DIR", target)
        // Removed, never inherited. An instrumented product sets exactly the
        // two frozen selector variables below and nothing else; the production
        // product sets none, which is what makes its kernel contain no
        // guest-test selector string at all.
        .env_remove("DEEPWYRM_GUEST_TEST_SELECTOR")
        .env_remove("DEEPWYRM_GUEST_TEST_ID")
        .env_remove("DEEPWYRM_WYR1E8_EVIDENCE")
        .env_remove("DEEPWYRM_WYR1E8_EVIDENCE_NONCE")
        .env_remove("DEEPWYRM_WYR1E7_EVIDENCE_NONCE")
        .env_remove("DEEPWYRM_WYR1D_EVIDENCE_NONCE")
        .env_remove("DEEPWYRM_DW1E_EVIDENCE_NONCE")
        .env_remove("DEEPWYRM_DW1E_E3B_FULL")
        .env_remove("WYRMROOT_DW1E3_CHALLENGE_1_NONCE")
        .env_remove("WYRMROOT_DW1E3_CHALLENGE_2_NONCE")
        .env_remove("CARGO_HOME")
        .env_remove("LD_AUDIT")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD")
        .current_dir(repository)
        .stdin(Stdio::null());
    if evidence_nonce.is_none() {
        // Production: the measured ceiling, which is the whole point of the
        // change. Set explicitly rather than inherited, so an operator's
        // ambient value cannot decide what the production kernel admits.
        command.env("DEEPWYRM_BOOTFS_MAX_PAGES", bootfs_pages.to_string());
    } else {
        // Instrumented: removed, not set. Its selector reaches the 256-page
        // arm, so a value here would be inert -- and an inert variable that
        // differed between the two siblings would still be a difference in a
        // kernel §5.4 requires to be identical across the pair.
        command.env_remove("DEEPWYRM_BOOTFS_MAX_PAGES");
    }
    if let Some(nonce) = evidence_nonce {
        // The closure selector reuses `interactive-wyrmsh`'s WRE1 transport, so
        // the kernel build requires that transport's evidence nonce. It is the
        // *pair's* nonce, not a per-sibling one: contract §5.4 declares the
        // kernel identical across the matched siblings, and this variable
        // reaches the kernel ELF, so two different nonces would make the
        // kernels differ and fail inspection.
        // Only the selector name. `DEEPWYRM_GUEST_TEST_ID` is build-owned --
        // the pinned launcher refuses it outright -- and the id is derived
        // from the harness manifest, which is where 35 is registered.
        //
        // `--features test-support` is not optional either: the launcher
        // refuses a selector without it. It is therefore a declared
        // production-versus-instrumented difference, recorded by the request's
        // `kernel_cargo_features`, and not something this build chose.
        command
            .args(["--features", "test-support"])
            .env("DEEPWYRM_GUEST_TEST_SELECTOR", wyr1c::WYR1F_SELECTOR)
            .env("DEEPWYRM_WYR1E7_EVIDENCE_NONCE", nonce);
    }
    command
}

/// Identity, authority and limit fields that never vary for a given product.
///
/// Thirteen of them do vary by product, and those thirteen are the whole
/// declared production-versus-instrumented and normal-versus-degraded
/// difference as the request records it.
fn fixed_fields(product_kind: wyr1c::Wyr1fProduct) -> [(&'static str, &'static str); 40] {
    use wyr1c::Wyr1fProduct;
    let instrumented = product_kind.is_instrumented();
    [
        ("kind", REQUEST_KIND),
        ("schema_version", "1"),
        (
            "product",
            match product_kind {
                Wyr1fProduct::Normal => "wyr1-f-normal",
                Wyr1fProduct::InstrumentedNormal => "wyr1-f-normal-instrumented",
                Wyr1fProduct::Degraded => "wyr1-f-degraded",
            },
        ),
        (
            "profile",
            match product_kind {
                Wyr1fProduct::Normal => "wyr1f-normal",
                Wyr1fProduct::InstrumentedNormal => "wyr1f-normal-instrumented",
                Wyr1fProduct::Degraded => "wyr1f-degraded",
            },
        ),
        (
            "scenario",
            match product_kind {
                Wyr1fProduct::Normal | Wyr1fProduct::InstrumentedNormal => "normal",
                Wyr1fProduct::Degraded => "degraded_recovery",
            },
        ),
        (
            "selector",
            if instrumented {
                wyr1c::WYR1F_SELECTOR
            } else {
                "none"
            },
        ),
        (
            "guest_test",
            if instrumented {
                wyr1c::WYR1F_TEST_ID
            } else {
                "none"
            },
        ),
        ("closure_selector", wyr1c::WYR1F_SELECTOR),
        ("closure_test_id", wyr1c::WYR1F_TEST_ID),
        (
            "closure_selector_state",
            if instrumented {
                "implemented"
            } else {
                "reserved"
            },
        ),
        (
            "kernel_instrumentation",
            if instrumented {
                "dw1-wyr1-interactive-closure"
            } else {
                "none"
            },
        ),
        (
            "kernel_cargo_features",
            if instrumented { "test-support" } else { "none" },
        ),
        (
            "evidence",
            if instrumented {
                "produced"
            } else {
                "not-produced"
            },
        ),
        (
            "evidence_protocol",
            if instrumented { "wyr1evid1" } else { "none" },
        ),
        (
            "gate_config_selector",
            if instrumented {
                wyr1c::WYR1F_SELECTOR
            } else {
                "none"
            },
        ),
        (
            "gate_config_scenario",
            match product_kind.gate_scenario() {
                None => "none",
                Some(scenario) => scenario.as_config_value(),
            },
        ),
        // The nonce itself is not a fixed field: it is written from the gate
        // configuration the producer actually froze. This entry only records
        // whether one exists, so a reviewer comparing two siblings sees the
        // difference declared before reading the value.
        (
            "gate_config_nonce",
            if instrumented { "declared" } else { "none" },
        ),
        // Contract §5.4's declared difference (b), scenario-bound evidence
        // identity, as the request records it: the WYR1EVID1 discriminant the
        // instrumented init encodes into every record it emits.
        (
            "evidence_scenario_code",
            match product_kind.gate_scenario() {
                None => "none",
                Some(scenario) => scenario.evidence_code_text(),
            },
        ),
        (
            "acceptance_claim",
            match product_kind {
                Wyr1fProduct::Normal => "prepared-normal-product-only",
                Wyr1fProduct::InstrumentedNormal => "prepared-instrumented-normal-sibling-only",
                Wyr1fProduct::Degraded => "prepared-degraded-sibling-only",
            },
        ),
        // Contract §11 item 14, closed at F2A: the receipt bound no kernel
        // resource-geometry scalar, and F2A.1 found there was no production
        // resource policy for one to name -- the freestanding kernel fell
        // through to the bootstrap-era arm. These five say which ledger the
        // kernel inside this product was built against and what it selected.
        //
        // Deepwyrm owns the reconciliation. `production_resource_geometry.rs`
        // and `kernel/tests/x86_64_syscall_contract.rs` assert these same
        // numbers against the constants the kernel links, so a capacity change
        // there fails Deepwyrm's own suite before it can reach a product whose
        // receipt still claims the old figure.
        (
            "kernel_resource_geometry",
            if instrumented {
                "wyr1e-interactive"
            } else {
                "production"
            },
        ),
        // Sixteen in both, for different reasons: production selects its
        // ledger's `identities`, the instrumented arm its literal. They agree
        // today, and are recorded so that stays visible if one moves.
        ("kernel_identity_capacity", "16"),
        (
            "kernel_handle_capacity",
            if instrumented { "32" } else { "48" },
        ),
        ("kernel_registry_capacity", "160"),
        // The linked per-thread kernel-stack arena. `identities` becomes
        // `THREADS` and every Thread needs one of these carriers, so a product
        // whose identity capacity exceeds this number boots nothing at all --
        // silently, because the release build folds the unsatisfiable
        // continuation away. Bound here so the relation is legible in the
        // receipt rather than only in a const assert.
        ("kernel_thread_stack_count", "16"),
        ("com1_role", "trusted-serial-diagnostics"),
        ("com2_role", "native-shell-byte-stream"),
        ("com2_transport", "unix-socket-byte-stream"),
        ("com2_socket_mode", "connect"),
        ("com1_capture_bytes", "1048576"),
        ("com2_capture_bytes", "2097152"),
        ("overall_timeout_seconds", "600"),
        ("ordinary_timeout_seconds", "30"),
        ("transition_timeout_seconds", "60"),
        ("send_limit", "1024"),
        ("input_limit_bytes", "131072"),
        ("memory_mib", "2048"),
        ("machine", "pc-q35-10.2"),
        ("firmware", "OVMF"),
        ("default_vcpus", "1"),
        ("smp_vcpus", "4"),
    ]
}

/// The post-run obligations a consumer of this product must satisfy.
fn obligation_fields() -> [(&'static str, &'static str); 4] {
    [
        (
            "post_run_recheck",
            "run `xtask wyr1f inspect --product <dir>` against a preserved copy of the prepared product after every run",
        ),
        (
            "post_run_restoration",
            "restore the domain's prior inactive configuration and leave it off; mutable OVMF variables and serial transcripts are run artifacts and never rewritten into this product",
        ),
        (
            "consumed_product_rule",
            "a consumed product is never re-inspected as prepared; prepare a fresh output root instead",
        ),
        (
            "failed_product_rule",
            "preserve a failed product unchanged, fix the failing owner, and prepare a new root",
        ),
    ]
}

fn freeze(
    output: &Path,
    produced: &Produced,
    product_kind: wyr1c::Wyr1fProduct,
) -> Result<String, Failure> {
    let esp_name = esp_name(product_kind);
    fs::create_dir(output)
        .map_err(|e| Failure::task(format!("could not create WYR1-F output: {e}")))?;
    let frozen = output.join("artifacts");
    fs::create_dir(&frozen)
        .map_err(|e| Failure::task(format!("could not create artifacts: {e}")))?;
    let mut fields = BTreeMap::new();
    for (key, name) in ARTIFACTS {
        let bytes = wyr1c6::read_regular_bounded(
            &produced.directory.join(name),
            artifact_maximum(key),
            key,
        )?;
        wyr1c6::write_new(&frozen.join(name), &bytes, key)?;
        fields.insert((*key).into(), format!("artifacts/{name}"));
        fields.insert(format!("{key}_sha256"), sha256::bytes_digest(&bytes));
    }
    let source_bytes = wyr1c6::read_regular_bounded(
        &produced.directory.join(SOURCE_RECEIPT),
        64 * 1024,
        SOURCE_RECEIPT,
    )?;
    wyr1c6::write_new(&frozen.join(SOURCE_RECEIPT), &source_bytes, SOURCE_RECEIPT)?;
    fields.insert(
        "source_receipt".into(),
        format!("artifacts/{SOURCE_RECEIPT}"),
    );
    fields.insert(
        "source_receipt_sha256".into(),
        sha256::bytes_digest(&source_bytes),
    );
    build_esp(output, &fields, &esp_name)?;
    let esp = frozen.join(&esp_name);
    wyr1c6::seal_mode(&esp, 0o444, "WYR1-F ESP")?;
    fields.insert("esp".into(), format!("artifacts/{esp_name}"));
    fields.insert(
        "esp_sha256".into(),
        sha256::bytes_digest(&wyr1c6::read_regular_bounded(
            &esp,
            g3_image::IMAGE_BYTES,
            "ESP",
        )?),
    );
    for (k, v) in fixed_fields(product_kind)
        .into_iter()
        .chain(obligation_fields())
    {
        fields.insert(k.into(), v.into());
    }
    for (k, v) in [
        ("deepwyrm_revision", produced.deep_revision.as_str()),
        ("generated_abi_revision", produced.abi_revision.as_str()),
        ("generated_abi_tree", produced.abi_tree.as_str()),
        ("wyrmroot_revision", produced.wyrmroot_revision.as_str()),
        ("rust_revision", produced.rust_revision.as_str()),
        ("receipt", "freeze-receipt.toml"),
        ("result_schema", "result-schema.toml"),
    ] {
        fields.insert(k.into(), v.into());
    }
    validate_request(&fields)?;
    let request = render(&fields, &request_keys(product_kind), ScalarSchema::Request)?;
    wyr1c6::write_new(
        &output.join("request.toml"),
        request.as_bytes(),
        "WYR1-F request",
    )?;
    let request_hash = sha256::bytes_digest(request.as_bytes());
    wyr1c6::write_new(
        &output.join("result-schema.toml"),
        result_schema(product_kind)?.as_bytes(),
        "result schema",
    )?;
    // F3A.3. Every launching runner mode consumes a staged per-profile handoff;
    // before this the final products staged none, which is closure contract
    // item 15 and why the runner had only a preflight mode.
    for (profile, vcpus) in PROFILES {
        stage_profile(product_kind, output, profile, vcpus, &request_hash, &fields)?;
    }
    wyr1c6::write_new(
        &output.join("profile-pair.toml"),
        render_sorted(
            &pair_fields(product_kind, output, &request_hash, &fields)?,
            ScalarSchema::Pair,
        )?
        .as_bytes(),
        "profile pair",
    )?;
    let receipt = receipt_fields(&request_hash, &fields);
    wyr1c6::write_new(
        &output.join("freeze-receipt.toml"),
        render_sorted(&receipt, ScalarSchema::FreezeReceipt)?.as_bytes(),
        "freeze receipt",
    )?;
    let fixed = |key: &str| {
        fixed_fields(product_kind)
            .into_iter()
            .find(|(k, _)| *k == key)
            .map_or("?", |(_, v)| v)
    };
    Ok(format!(
        "WYR1_F_PREPARE_PASS product={} scenario={} selector={} request={} receipt={}\n",
        fixed("product"),
        fixed("scenario"),
        fixed("selector"),
        output.join("request.toml").display(),
        output.join("freeze-receipt.toml").display()
    ))
}

#[allow(clippy::too_many_arguments)]
fn source_receipt(
    manifest: &crate::metadata::BuildManifest,
    toolchain: &crate::toolchain_artifact::AcceptedToolchain,
    deep: &str,
    abi: &str,
    tree: &str,
    wyrmroot: &str,
    artifacts: &Path,
    generation: &[u8; 32],
    inspections: &BTreeMap<String, Vec<u8>>,
    product_kind: wyr1c::Wyr1fProduct,
) -> Result<String, Failure> {
    let mut f = BTreeMap::new();
    for (k, v) in fixed_fields(product_kind)
        .into_iter()
        .chain(obligation_fields())
    {
        if k != "kind" {
            f.insert(k.into(), v.into());
        }
    }
    for (k, v) in [
        ("kind", SOURCE_KIND),
        ("deepwyrm_revision", deep),
        ("generated_abi_revision", abi),
        ("generated_abi_tree", tree),
        ("wyrmroot_revision", wyrmroot),
        ("rust_revision", manifest.rust_revision()?),
        ("rust_toolchain_name", manifest.rust_toolchain_name()?),
    ] {
        f.insert(k.into(), v.into());
    }
    f.insert(
        "boot_generation".into(),
        generation.iter().map(|b| format!("{b:02x}")).collect(),
    );
    f.insert(
        "rustc_sha256".into(),
        sha256::file_digest(&toolchain.rustc)
            .map_err(|e| Failure::task(format!("rustc hash: {e}")))?,
    );
    for (k, v) in [
        ("cargo_sha256", toolchain.cargo_sha256.as_str()),
        ("rust_lld_sha256", toolchain.rust_lld_sha256.as_str()),
        (
            "toolchain_manifest_sha256",
            toolchain.manifest_sha256.as_str(),
        ),
        (
            "toolchain_tree_sha256",
            toolchain.toolchain_tree_sha256.as_str(),
        ),
        (
            "loader_command",
            "canonical deterministic release UEFI loader pair",
        ),
        (
            "kernel_command",
            "tools/pinned-cargo target build --locked --offline --release --target x86_64-unknown-none --package deepwyrm-kernel --bin deepwyrm-kernel [no --features; DEEPWYRM_GUEST_TEST_SELECTOR removed]",
        ),
        (
            "bootstrap_command",
            "canonical DW1-E3A native bootstrap build",
        ),
        ("bootstrap_features", "wyr1c5-production"),
        (
            "bootfs_command",
            "in-process wyrmroot-bootfs build_f exact 13-entry final archive",
        ),
        (
            "esp_command",
            "canonical g3_image build_d6 WYR1-F normal ESP with explicit boot device table",
        ),
        (
            "gate_config_command",
            "frozen wyr1c::WYR1F_NORMAL_GATE_CONFIG literal; no selector, no scenario, no nonce",
        ),
    ] {
        f.insert(k.into(), v.into());
    }
    for label in NATIVE_LABELS {
        let key = label.replace('-', "_");
        f.insert(
            format!("{key}_features"),
            wyr1c::wyr1f_native_features(label, product_kind)?.into(),
        );
        f.insert(
            format!("{key}_command"),
            wyr1c::wyr1f_native_command(label, product_kind)?,
        );
        f.insert(
            format!("{key}_inspection_sha256"),
            sha256::bytes_digest(
                inspections
                    .get(label)
                    .ok_or_else(|| Failure::task(format!("WYR1-F lacks {label} inspection")))?,
            ),
        );
    }
    for (k, n) in ARTIFACTS {
        f.insert(
            format!("{k}_sha256"),
            sha256::bytes_digest(&wyr1c6::read_regular_bounded(
                &artifacts.join(n),
                artifact_maximum(k),
                k,
            )?),
        );
    }
    render(
        &f,
        &source_receipt_keys(product_kind),
        ScalarSchema::SourceReceipt,
    )
}

fn source_receipt_keys(product_kind: wyr1c::Wyr1fProduct) -> Vec<String> {
    let mut keys = fixed_fields(product_kind)
        .iter()
        .chain(obligation_fields().iter())
        .map(|(key, _)| (*key).to_owned())
        .collect::<BTreeSet<_>>();
    keys.extend(
        [
            "deepwyrm_revision",
            "generated_abi_revision",
            "generated_abi_tree",
            "wyrmroot_revision",
            "rust_revision",
            "rust_toolchain_name",
            "boot_generation",
            "rustc_sha256",
            "cargo_sha256",
            "rust_lld_sha256",
            "toolchain_manifest_sha256",
            "toolchain_tree_sha256",
            "loader_command",
            "kernel_command",
            "bootstrap_command",
            "bootstrap_features",
            "bootfs_command",
            "esp_command",
            "gate_config_command",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    for label in NATIVE_LABELS {
        let key = label.replace('-', "_");
        keys.insert(format!("{key}_command"));
        keys.insert(format!("{key}_features"));
        keys.insert(format!("{key}_inspection_sha256"));
    }
    for (key, _) in ARTIFACTS {
        keys.insert(format!("{key}_sha256"));
    }
    keys.into_iter().collect()
}

fn build_esp(output: &Path, f: &BTreeMap<String, String>, esp_name: &str) -> Result<(), Failure> {
    let arguments = G3ImageArguments {
        image: output
            .join(format!("artifacts/{esp_name}"))
            .display()
            .to_string(),
        loader: output.join(field(f, "loader")?).display().to_string(),
        kernel: output.join(field(f, "kernel")?).display().to_string(),
        bootstrap: output.join(field(f, "bootstrap")?).display().to_string(),
        bootfs: output.join(field(f, "bootfs")?).display().to_string(),
    };
    g3_image::build_d6(
        &arguments,
        &output
            .join(field(f, "boot_device_table")?)
            .display()
            .to_string(),
    )
    .map(|_| ())
}

fn validate_esp(output: &Path, f: &BTreeMap<String, String>) -> Result<(), Failure> {
    let arguments = G3ImageArguments {
        image: output.join(field(f, "esp")?).display().to_string(),
        loader: output.join(field(f, "loader")?).display().to_string(),
        kernel: output.join(field(f, "kernel")?).display().to_string(),
        bootstrap: output.join(field(f, "bootstrap")?).display().to_string(),
        bootfs: output.join(field(f, "bootfs")?).display().to_string(),
    };
    g3_image::inspect_d6(
        &arguments,
        &output
            .join(field(f, "boot_device_table")?)
            .display()
            .to_string(),
    )
    .map(|_| ())
}

fn receipt_fields(hash: &str, r: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut f = BTreeMap::new();
    f.insert("kind".into(), RECEIPT_KIND.into());
    f.insert("request_sha256".into(), hash.into());
    for k in [
        "schema_version",
        "product",
        "profile",
        "scenario",
        "selector",
        "closure_selector",
        "closure_test_id",
        "closure_selector_state",
        "evidence",
        "source_receipt_sha256",
        "esp_sha256",
    ] {
        f.insert(k.into(), r[k].clone());
    }
    for (k, _) in ARTIFACTS {
        f.insert(format!("{k}_sha256"), r[&format!("{k}_sha256")].clone());
    }
    f
}

fn request_keys(product_kind: wyr1c::Wyr1fProduct) -> Vec<String> {
    let mut keys = Vec::new();
    for (key, _) in fixed_fields(product_kind) {
        keys.push(key.into());
    }
    keys.extend(obligation_fields().iter().map(|(k, _)| (*k).into()));
    for key in [
        "deepwyrm_revision",
        "generated_abi_revision",
        "generated_abi_tree",
        "wyrmroot_revision",
        "rust_revision",
        "esp",
        "esp_sha256",
        "receipt",
        "source_receipt",
        "source_receipt_sha256",
        "result_schema",
    ] {
        keys.push(key.into());
    }
    for (artifact, _) in ARTIFACTS {
        keys.push((*artifact).into());
        keys.push(format!("{artifact}_sha256"));
    }
    keys
}

/// Stages one profile's launch inputs beside the frozen product.
///
/// DW1-F/WYR1-F F3A.3. The shape follows `wyr1e8::stage_profile`, because the
/// runner already knows how to consume it: a profile directory holding the
/// mutable OVMF variables a run is allowed to change, the domain XML, and a
/// `handoff.toml` naming both. What differs is the domain itself -- see
/// [`profile_domain_xml`].
fn stage_profile(
    product_kind: wyr1c::Wyr1fProduct,
    output: &Path,
    profile: &str,
    vcpus: u8,
    request_hash: &str,
    request: &BTreeMap<String, String>,
) -> Result<(), Failure> {
    let directory = output.join(profile);
    fs::create_dir(&directory)
        .map_err(|error| Failure::task(format!("WYR1-F profile directory: {error}")))?;
    let vars = wyr1c6::read_regular_bounded(
        &output.join(field(request, "ovmf_vars")?),
        wyr1c6::MAX_FIRMWARE_BYTES,
        "OVMF vars",
    )?;
    // The one file a run may rewrite. Sealed read-only everywhere else in this
    // product; here it is the run's own copy, and the frozen template it was
    // taken from stays untouched under `artifacts/`.
    wyr1c6::write_new_mode(
        &directory.join("OVMF_VARS.mutable.fd"),
        &vars,
        0o600,
        "mutable OVMF vars",
    )?;
    let absolute = fs::canonicalize(output)
        .map_err(|error| Failure::task(format!("WYR1-F output resolve: {error}")))?;
    let xml = profile_domain_xml(
        product_kind,
        vcpus,
        &absolute.join(field(request, "ovmf_code")?),
        &absolute.join(field(request, "esp")?),
        &absolute.join(profile).join("OVMF_VARS.mutable.fd"),
        &absolute.join(profile).join("com2.sock"),
    );
    wyr1c6::write_new(&directory.join("domain.xml"), xml.as_bytes(), "domain XML")?;
    let handoff = handoff_fields(
        product_kind,
        profile,
        vcpus,
        request_hash,
        request,
        &xml,
        &vars,
    )?;
    wyr1c6::write_new(
        &directory.join("handoff.toml"),
        render_sorted(&handoff, ScalarSchema::Handoff)?.as_bytes(),
        "handoff",
    )
}

/// The domain XML for one profile of one product.
///
/// The production product gets the selectorless variant. Every other launching
/// card passes its selector to the guest through the fwcfg entries
/// `opt/org.deepwyrm.test.selector` and `…test_id`; `wyr1-f-normal` selects no
/// guest test, so a domain that named one would advertise something the product
/// does not contain. The two instrumented siblings do select one -- the same
/// one -- and get it.
fn profile_domain_xml(
    product_kind: wyr1c::Wyr1fProduct,
    vcpus: u8,
    code: &Path,
    esp: &Path,
    vars: &Path,
    com2: &Path,
) -> String {
    if product_kind.is_instrumented() {
        crate::dw1e3a::selected_domain_xml(
            vcpus,
            code,
            esp,
            vars,
            com2,
            (wyr1c::WYR1F_SELECTOR, wyr1c::WYR1F_TEST_ID),
        )
    } else {
        crate::dw1e3a::unselected_domain_xml(vcpus, code, esp, vars, com2)
    }
}

/// What one profile's handoff declares to the runner.
fn handoff_fields(
    product_kind: wyr1c::Wyr1fProduct,
    profile: &str,
    vcpus: u8,
    request_hash: &str,
    request: &BTreeMap<String, String>,
    xml: &str,
    vars: &[u8],
) -> Result<BTreeMap<String, String>, Failure> {
    let mut h = BTreeMap::new();
    h.insert("kind".into(), HANDOFF_KIND.into());
    h.insert("schema_version".into(), "1".into());
    // Product identity travels with the handoff, so a runner cannot be handed
    // the degraded profile and validate it as the normal one.
    for key in [
        "product",
        "profile",
        "scenario",
        "selector",
        "guest_test",
        "evidence",
        "evidence_protocol",
        "acceptance_claim",
        "com1_role",
        "com2_role",
        "com2_transport",
        "com2_socket_mode",
        "com1_capture_bytes",
        "com2_capture_bytes",
        "memory_mib",
        "machine",
        "firmware",
    ] {
        h.insert(key.into(), field(request, key)?.into());
    }
    // `profile` in the request is the product's name for itself. Here it is the
    // run profile, because that is the value the runner matches on, and the
    // product's own name moves to `product_profile` rather than being dropped:
    // a handoff has to say which product it launches as well as how.
    h.insert("profile".into(), profile.into());
    h.insert("product_profile".into(), field(request, "profile")?.into());
    h.insert("vcpus".into(), vcpus.to_string());
    h.insert(
        "timeout_seconds".into(),
        field(request, "overall_timeout_seconds")?.into(),
    );
    h.insert("request".into(), "request.toml".into());
    h.insert("request_sha256".into(), request_hash.into());
    h.insert("result_schema".into(), "result-schema.toml".into());
    h.insert("esp".into(), field(request, "esp")?.into());
    h.insert("esp_sha256".into(), field(request, "esp_sha256")?.into());
    h.insert("ovmf_code".into(), field(request, "ovmf_code")?.into());
    h.insert(
        "ovmf_code_sha256".into(),
        field(request, "ovmf_code_sha256")?.into(),
    );
    h.insert("com1_fd_group".into(), "com1".into());
    h.insert("com2_fd_group".into(), "com2".into());
    h.insert("esp_fd_group".into(), "esp".into());
    h.insert("vars_fd_group".into(), "vars".into());
    h.insert("com2_socket".into(), format!("{profile}/com2.sock"));
    // Where the run writes. Declared by the handoff rather than chosen by the
    // runner, so the verifier binds the same paths the producer reserved and a
    // run cannot quietly write its transcript somewhere unexamined. Every one
    // of these is in `PROFILE_RUNTIME_STATE_NAMES`, which is what makes their
    // presence the mark of a consumed profile.
    h.insert("com1_serial_log".into(), format!("{profile}/com1.log"));
    h.insert("com2_log".into(), format!("{profile}/com2.bin"));
    h.insert("result_path".into(), format!("{profile}/result.toml"));
    h.insert(
        "acceptance_receipt".into(),
        format!("{profile}/acceptance-receipt.toml"),
    );
    // Only a product that produces evidence reserves a place to put it. The
    // production product declares `none`, which is the same statement its
    // request and its result grammar make.
    h.insert(
        "evidence_log".into(),
        if product_kind.is_instrumented() {
            format!("{profile}/evidence.bin")
        } else {
            "none".into()
        },
    );
    h.insert("domain_xml".into(), format!("{profile}/domain.xml"));
    h.insert(
        "domain_xml_sha256".into(),
        sha256::bytes_digest(xml.as_bytes()),
    );
    // Whether this profile's domain names a guest test at all. A reviewer reads
    // one field rather than grepping the XML, and the production product's
    // `false` is the assertion that F3A.3 exists to make.
    h.insert(
        "domain_declares_selector".into(),
        if product_kind.is_instrumented() {
            "true"
        } else {
            "false"
        }
        .into(),
    );
    h.insert(
        "mutable_ovmf_vars".into(),
        format!("{profile}/OVMF_VARS.mutable.fd"),
    );
    h.insert(
        "mutable_ovmf_vars_initial_sha256".into(),
        sha256::bytes_digest(vars),
    );
    Ok(h)
}

/// The pair manifest naming both staged profiles.
fn pair_fields(
    product_kind: wyr1c::Wyr1fProduct,
    output: &Path,
    request_hash: &str,
    request: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, Failure> {
    let mut f = BTreeMap::new();
    f.insert("kind".into(), PAIR_KIND.into());
    f.insert("schema_version".into(), "1".into());
    for key in ["product", "scenario", "selector", "evidence"] {
        f.insert(key.into(), field(request, key)?.into());
    }
    f.insert("request".into(), "request.toml".into());
    f.insert("request_sha256".into(), request_hash.into());
    f.insert("result_schema".into(), "result-schema.toml".into());
    f.insert("profiles".into(), "default,smp".into());
    f.insert("memory_mib".into(), field(request, "memory_mib")?.into());
    f.insert(
        "timeout_seconds".into(),
        field(request, "overall_timeout_seconds")?.into(),
    );
    f.insert(
        "domain_declares_selector".into(),
        if product_kind.is_instrumented() {
            "true"
        } else {
            "false"
        }
        .into(),
    );
    for (profile, vcpus) in PROFILES {
        f.insert(
            format!("{profile}_handoff"),
            format!("{profile}/handoff.toml"),
        );
        f.insert(format!("{profile}_vcpus"), vcpus.to_string());
        let handoff = wyr1c6::read_regular_bounded(
            &output.join(profile).join("handoff.toml"),
            64 * 1024,
            "WYR1-F handoff",
        )?;
        f.insert(
            format!("{profile}_handoff_sha256"),
            sha256::bytes_digest(&handoff),
        );
    }
    Ok(f)
}

/// The live-run result grammar, per product.
///
/// DW1-F/WYR1-F F3A.2. This used to take no argument and hardcode the
/// production product's `product`, `scenario`, `selector` and `evidence`, so
/// all three prepared products carried the byte-identical file -- and `inspect`
/// re-renders it and refuses a product whose copy differs, which made the
/// production shape *required* of the other two. The degraded product was
/// obliged to declare `scenario = "normal"`, and the instrumented sibling, the
/// only product that produces evidence, was obliged to declare
/// `evidence = "not-produced"` and had nowhere to record any.
///
/// The four identity values are read out of [`fixed_fields`] rather than spelled
/// again here. A result that disagrees with its own request about which product
/// it is would otherwise be expressible, and that is precisely the mistake this
/// function used to institutionalise.
fn result_schema(product_kind: wyr1c::Wyr1fProduct) -> Result<String, Failure> {
    let keys = result_keys(product_kind);
    let fixed = fixed_fields(product_kind);
    let from_request = |name: &str| -> Result<String, Failure> {
        fixed
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| (*value).to_owned())
            .ok_or_else(|| Failure::task(format!("WYR1-F result schema cannot source `{name}`")))
    };
    let mut f = BTreeMap::new();
    for key in &keys {
        let key = key.as_str();
        let value = match key {
            "kind" => RESULT_KIND.into(),
            "schema_version" => "1".into(),
            "product" | "scenario" | "selector" | "evidence" | "evidence_protocol" => {
                from_request(key)?
            }
            "shutdown_byte_hex" => "04".into(),
            "acceptance" => "pass".into(),
            _ => format!("<runner:{key}>"),
        };
        f.insert(key.into(), value);
    }
    render(&f, &keys, ScalarSchema::ResultTemplate)
}

/// The live-run result grammar this product's runner must fill in.
///
/// DW1-F/WYR1-F F3A.2. The previous list had 28 keys, and four of the plan's
/// thirteen F3A proof obligations had a field to land in: `prompt_reached`,
/// `status_output_sha256`, `services_output_sha256` and the shell-exit pair.
/// Roles reaching READY in dependency order, COM1 and COM2 staying distinct,
/// the nonce `echo`, `tasks`, `run bin/hello`, CPU-hog fairness and every one
/// of the five DEGRADED obligations had nowhere to go, so a runner could report
/// `acceptance = "pass"` having proven a third of the card.
///
/// Every key here is fillable from what a run actually produces: the COM1 and
/// COM2 transcripts, and for an instrumented sibling the WRE1 evidence stream.
/// Nothing is listed that the runner would have to invent.
///
/// F3A.2b corrected two keys that failed exactly that test. `roles_ready_order`
/// and `roles_ready_count` were in every product's grammar, including the
/// production product, whose kernel writes COM1 only from
/// `emit_early_panic_record` and therefore emits no READY record at all; they
/// moved to the two instrumented products, and production gained `com1_empty`,
/// which is the assertion its silent COM1 can actually make. The three
/// `cpu_hog_*` keys stayed where they were, and the payload that fills them was
/// added to the product instead.
fn result_keys(product_kind: wyr1c::Wyr1fProduct) -> Vec<String> {
    let mut keys: Vec<&'static str> = vec![
        "kind",
        "schema_version",
        "product",
        "profile",
        "scenario",
        "selector",
        "evidence",
        "request_sha256",
        "effective_vcpus",
        "esp_sha256",
        "bootfs_sha256",
        "source_receipt_sha256",
        "com1_length",
        "com1_sha256",
        "com2_accepted_length",
        "com2_accepted_sha256",
        "com2_full_length",
        "com2_full_sha256",
        "shutdown_byte_hex",
        // COM1 is the trusted diagnostic serial line and COM2 the shell byte
        // stream. That they stay distinct is an obligation, not an assumption:
        // a console that leaked onto COM1 would still produce a prompt. On the
        // production product it carries more than that -- see below, where the
        // absence of a COM1 record is itself the assertion.
        "com1_com2_distinct",
        "prompt_reached",
        "nonce_echo_nonce",
        "nonce_echo_status",
        "services_output_sha256",
        "status_output_sha256",
        "tasks_output_sha256",
        "hello_stdout_sha256",
        "hello_exit_status",
        "prompt_after_hello",
        "shell_exit_status",
        "shell_restart_generation",
        "qemu_exit",
        "post_run_inspect_result",
        "domain_restored",
    ];
    match product_kind {
        // The normal scenario owes the fairness proof. It is meaningful only at
        // `smp`, but the key exists in both profiles' grammar so that a UP
        // result has to say what it observed rather than omit the question.
        wyr1c::Wyr1fProduct::Normal | wyr1c::Wyr1fProduct::InstrumentedNormal => {
            keys.extend([
                "cpu_hog_jobs",
                "shell_responses_under_hogs",
                "shell_progress_bounded",
            ]);
        }
        // Contract §5.4's declared episode. `degraded_transitions` must be one
        // -- entering DEGRADED twice is a different failure from never entering
        // it -- and `degraded_retry_attempts` is what makes "no infinite retry"
        // a number rather than an impression.
        wyr1c::Wyr1fProduct::Degraded => {
            keys.extend([
                "degraded_transitions",
                "degraded_retry_attempts",
                "shell_usable_in_degraded",
                "degraded_admin_nonce",
                "degraded_admin_status",
                "degraded_exit_restart_generation",
                "degraded_exit_restart_bounded",
            ]);
        }
    }
    if product_kind.is_instrumented() {
        keys.extend([
            // The bring-up proof, and it lives here rather than in the base
            // list because only an instrumented product can make it.
            // `deepwyrm`'s COM1 writers other than `emit_early_panic_record`
            // are all behind `feature = "test-support"`, which the production
            // kernel is deliberately not built with, so a clean production
            // boot emits no COM1 bytes at all and there is no READY record to
            // read. The instrumented sibling emits one WYR1EVID1 `Ready` per
            // role, which is what the sibling is for.
            //
            // `roles_ready_order` is the observed sequence as one
            // comma-separated list rather than five booleans: the obligation
            // is dependency *order*, and five independent flags cannot
            // express a wrong one.
            "roles_ready_order",
            "roles_ready_count",
            "evidence_protocol",
            "evidence_nonce",
            "expected_evidence_records",
            "evidence_records",
            "evidence_sha256",
        ]);
    } else {
        // The production product's COM1 is silent on a clean boot, so its
        // emptiness is the signal: any byte on that line is an early panic
        // record, which is the only thing the production kernel writes there.
        keys.push("com1_empty");
    }
    keys.push("acceptance");
    keys.into_iter().map(str::to_owned).collect()
}

/// Which product a request declares itself to be.
///
/// Read before anything else is checked, because every other fixed field is
/// conditioned on it. An unknown value is rejected here rather than silently
/// validated against the production shape.
fn product_kind_of(f: &BTreeMap<String, String>) -> Result<wyr1c::Wyr1fProduct, Failure> {
    match field(f, "product")? {
        "wyr1-f-normal" => Ok(wyr1c::Wyr1fProduct::Normal),
        "wyr1-f-normal-instrumented" => Ok(wyr1c::Wyr1fProduct::InstrumentedNormal),
        "wyr1-f-degraded" => Ok(wyr1c::Wyr1fProduct::Degraded),
        other => Err(Failure::task(format!(
            "WYR1-F request declares the unknown product `{other}`"
        ))),
    }
}

fn validate_request(f: &BTreeMap<String, String>) -> Result<(), Failure> {
    let product_kind = product_kind_of(f)?;
    for (k, v) in fixed_fields(product_kind)
        .into_iter()
        .chain(obligation_fields())
    {
        if field(f, k)? != v {
            return Err(Failure::task(format!("WYR1-F {k} drifted")));
        }
    }
    for (k, n) in ARTIFACTS {
        if field(f, k)? != format!("artifacts/{n}") {
            return Err(Failure::task(format!("WYR1-F {k} path drifted")));
        }
    }
    let esp = format!("artifacts/{}", esp_name(product_kind));
    for (k, v) in [
        ("receipt", "freeze-receipt.toml"),
        ("result_schema", "result-schema.toml"),
        ("source_receipt", "artifacts/f-source-build.toml"),
        // The ESP names its product, so a sibling's image cannot be presented
        // under this request.
        ("esp", esp.as_str()),
    ] {
        if field(f, k)? != v {
            return Err(Failure::task(format!("WYR1-F {k} path drifted")));
        }
    }
    for k in [
        "deepwyrm_revision",
        "generated_abi_revision",
        "generated_abi_tree",
        "wyrmroot_revision",
        "rust_revision",
    ] {
        wyr1c6::validate_revision(field(f, k)?, k)?;
    }
    for k in ["esp_sha256", "source_receipt_sha256"] {
        validate_lower_hex(field(f, k)?, 64, k)?;
    }
    for (k, _) in ARTIFACTS {
        let hash = format!("{k}_sha256");
        validate_lower_hex(field(f, &hash)?, 64, &hash)?;
    }
    Ok(())
}

/// Prepared-only inspection: the product must still be exactly what `prepare`
/// wrote, with no consumed/runtime state anywhere in it.
fn validate_frozen_metadata(
    product_kind: wyr1c::Wyr1fProduct,
    output: &Path,
    request: &BTreeMap<String, String>,
) -> Result<(), Failure> {
    reject_consumed_runtime_state(output)?;
    require_exact_directory(
        output,
        &[
            "artifacts",
            "default",
            "smp",
            "profile-pair.toml",
            "request.toml",
            "result-schema.toml",
            "freeze-receipt.toml",
        ],
        "WYR1-F output",
    )?;
    let esp = esp_name(product_kind);
    let mut artifact_names = ARTIFACTS.iter().map(|(_, name)| *name).collect::<Vec<_>>();
    artifact_names.extend([SOURCE_RECEIPT, esp.as_str()]);
    require_exact_directory(
        &output.join("artifacts"),
        &artifact_names,
        "WYR1-F artifacts",
    )?;
    require_mode(&output.join("request.toml"), 0o444, "WYR1-F request")?;
    for (key, _) in ARTIFACTS {
        require_mode(&output.join(field(request, key)?), 0o444, key)?;
    }
    for key in ["source_receipt", "esp", "result_schema", "receipt"] {
        require_mode(&output.join(field(request, key)?), 0o444, key)?;
    }
    let result_schema_bytes = wyr1c6::read_regular_bounded(
        &output.join(field(request, "result_schema")?),
        64 * 1024,
        "WYR1-F result schema",
    )?;
    if result_schema_bytes != result_schema(product_kind)?.as_bytes() {
        return Err(Failure::task("WYR1-F result schema drifted"));
    }
    // F3A.3's staged launch inputs, re-derived rather than trusted. The domain
    // XML is rebuilt from this product's own frozen paths and compared, so a
    // hand-edited domain -- one that added a selector to the production
    // product, say -- is refused here rather than at the point it boots.
    require_mode(
        &output.join("profile-pair.toml"),
        0o444,
        "WYR1-F profile pair",
    )?;
    let absolute = fs::canonicalize(output)
        .map_err(|error| Failure::task(format!("WYR1-F output resolve: {error}")))?;
    for (profile, vcpus) in PROFILES {
        let directory = output.join(profile);
        require_exact_directory(&directory, &PROFILE_ENTRIES, "WYR1-F profile")?;
        require_mode(&directory.join("domain.xml"), 0o444, "WYR1-F domain XML")?;
        require_mode(&directory.join("handoff.toml"), 0o444, "WYR1-F handoff")?;
        require_mode(
            &directory.join("OVMF_VARS.mutable.fd"),
            0o600,
            "WYR1-F mutable OVMF vars",
        )?;
        let expected = profile_domain_xml(
            product_kind,
            vcpus,
            &absolute.join(field(request, "ovmf_code")?),
            &absolute.join(field(request, "esp")?),
            &absolute.join(profile).join("OVMF_VARS.mutable.fd"),
            &absolute.join(profile).join("com2.sock"),
        );
        let observed = wyr1c6::read_regular_bounded(
            &directory.join("domain.xml"),
            64 * 1024,
            "WYR1-F domain XML",
        )?;
        if observed != expected.as_bytes() {
            return Err(Failure::task(format!(
                "WYR1-F {profile} domain XML is not this product's"
            )));
        }
        // The production product must not advertise a guest test it does not
        // contain, and the two siblings must advertise exactly the one they do.
        let names_selector = observed
            .windows(wyr1c::WYR1F_SELECTOR.len())
            .any(|window| window == wyr1c::WYR1F_SELECTOR.as_bytes());
        if names_selector != product_kind.is_instrumented() {
            return Err(Failure::task(format!(
                "WYR1-F {profile} domain XML selector declaration disagrees with the product"
            )));
        }
    }
    let request_hash = sha256::bytes_digest(&wyr1c6::read_regular_bounded(
        &output.join("request.toml"),
        64 * 1024,
        "WYR1-F request",
    )?);
    let receipt = receipt_fields(&request_hash, request);
    if wyr1c6::read_regular_bounded(
        &output.join(field(request, "receipt")?),
        64 * 1024,
        "WYR1-F freeze receipt",
    )? != render_sorted(&receipt, ScalarSchema::FreezeReceipt)?.as_bytes()
    {
        return Err(Failure::task("WYR1-F freeze receipt drifted"));
    }
    Ok(())
}

/// Names that only exist once a product has been *run*. Their presence means
/// this is consumed state, which is verified by the runner's own grammar and
/// never by prepared-product inspection.
/// What only a *run* leaves behind. Finding any of it means the directory is a
/// consumed product, and a consumed product is never re-inspected as prepared.
///
/// DW1-F/WYR1-F F3A.3 removed `default` and `smp` from this list. They used to
/// be here because the final products staged no launch inputs at all -- closure
/// contract item 15 -- so a profile directory could only have come from a run.
/// They are now prepared content, and what distinguishes prepared from consumed
/// moved *inside* them: see [`PROFILE_RUNTIME_STATE_NAMES`].
const RUNTIME_STATE_NAMES: [&str; 8] = [
    "com1.log",
    "com2.bin",
    "com2.sock",
    "evidence.bin",
    "result.toml",
    "acceptance-receipt.toml",
    "verification-manifest.json",
    "OVMF_VARS.mutable.fd",
];

/// The same, one level down. A staged profile holds exactly its domain XML, its
/// handoff and the mutable firmware variables a run is allowed to change; a run
/// adds the socket, the transcripts and its result beside them.
const PROFILE_RUNTIME_STATE_NAMES: [&str; 7] = [
    "com1.log",
    "com2.bin",
    "com2.sock",
    "evidence.bin",
    "result.toml",
    "acceptance-receipt.toml",
    "verification-manifest.json",
];

/// A staged profile directory's exact prepared entry set.
const PROFILE_ENTRIES: [&str; 3] = ["domain.xml", "handoff.toml", "OVMF_VARS.mutable.fd"];

fn reject_consumed_runtime_state(output: &Path) -> Result<(), Failure> {
    for name in RUNTIME_STATE_NAMES {
        if fs::symlink_metadata(output.join(name)).is_ok() {
            return Err(Failure::task(
                "WYR1-F output is consumed/runtime state; inspect a preserved prepared copy instead",
            ));
        }
    }
    for (profile, _) in PROFILES {
        let directory = output.join(profile);
        for name in PROFILE_RUNTIME_STATE_NAMES {
            if fs::symlink_metadata(directory.join(name)).is_ok() {
                return Err(Failure::task(format!(
                    "WYR1-F {profile} profile is consumed/runtime state; inspect a \
                     preserved prepared copy instead"
                )));
            }
        }
    }
    Ok(())
}

fn require_exact_directory(path: &Path, expected: &[&str], label: &str) -> Result<(), Failure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| Failure::task(format!("could not stat {label}: {e}")))?;
    if !metadata.file_type().is_dir() {
        return Err(Failure::task(format!("{label} is not a directory")));
    }
    let actual = fs::read_dir(path)
        .map_err(|e| Failure::task(format!("could not read {label}: {e}")))?
        .map(|entry| {
            entry
                .map_err(|e| Failure::task(format!("could not read {label}: {e}")))?
                .file_name()
                .into_string()
                .map_err(|_| Failure::task(format!("{label} contains a non-UTF-8 name")))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = expected.iter().map(|name| (*name).to_owned()).collect();
    if actual != expected {
        return Err(Failure::task(format!("{label} entry set drifted")));
    }
    Ok(())
}

fn require_mode(path: &Path, expected: u32, label: &str) -> Result<(), Failure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| Failure::task(format!("could not stat {label}: {e}")))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != expected
    {
        return Err(Failure::task(format!("{label} mode drifted")));
    }
    Ok(())
}

fn validate_lower_hex(value: &str, length: usize, label: &str) -> Result<(), Failure> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Failure::task(format!(
            "{label} is not lowercase hexadecimal"
        )));
    }
    Ok(())
}

fn field<'a>(f: &'a BTreeMap<String, String>, k: &str) -> Result<&'a str, Failure> {
    f.get(k)
        .map(String::as_str)
        .ok_or_else(|| Failure::task(format!("missing WYR1-F field {k}")))
}

fn artifact_maximum(k: &str) -> u64 {
    match k {
        "ovmf_code" | "ovmf_vars" => wyr1c6::MAX_FIRMWARE_BYTES,
        "esp" => g3_image::IMAGE_BYTES,
        _ => wyr1c6::MAX_ARTIFACT_BYTES,
    }
}

const SEMANTIC_INTEGER_KEYS: &[&str] = &[
    "closure_test_id",
    "com1_capture_bytes",
    "com2_capture_bytes",
    "overall_timeout_seconds",
    "ordinary_timeout_seconds",
    "transition_timeout_seconds",
    "send_limit",
    "input_limit_bytes",
    "memory_mib",
    "default_vcpus",
    "smp_vcpus",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScalarSchema {
    Request,
    SourceReceipt,
    FreezeReceipt,
    ResultTemplate,
    Handoff,
    Pair,
}

impl ScalarSchema {
    fn label(self) -> &'static str {
        match self {
            Self::Request => "WYR1-F request",
            Self::SourceReceipt => "WYR1-F source receipt",
            Self::FreezeReceipt => "WYR1-F freeze receipt",
            Self::ResultTemplate => "WYR1-F result schema",
            Self::Handoff => "WYR1-F handoff",
            Self::Pair => "WYR1-F profile pair",
        }
    }

    fn is_integer(self, key: &str) -> bool {
        match self {
            Self::Request | Self::SourceReceipt => {
                key == "schema_version" || SEMANTIC_INTEGER_KEYS.contains(&key)
            }
            Self::FreezeReceipt => matches!(key, "schema_version" | "closure_test_id"),
            Self::ResultTemplate => false,
            Self::Handoff => matches!(
                key,
                "schema_version"
                    | "closure_test_id"
                    | "vcpus"
                    | "memory_mib"
                    | "timeout_seconds"
                    | "com1_capture_bytes"
                    | "com2_capture_bytes"
            ),
            Self::Pair => matches!(
                key,
                "schema_version" | "default_vcpus" | "smp_vcpus" | "memory_mib" | "timeout_seconds"
            ),
        }
    }
}

fn render(
    f: &BTreeMap<String, String>,
    keys: &[String],
    schema: ScalarSchema,
) -> Result<String, Failure> {
    let label = schema.label();
    let expected = keys.iter().cloned().collect::<BTreeSet<_>>();
    if f.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return Err(Failure::task(format!("{label} fields drifted")));
    }
    let mut out = String::new();
    for k in keys {
        let v = field(f, k)?;
        if v.contains(['\n', '\r']) {
            return Err(Failure::task(format!("{label} unsafe value")));
        }
        if schema.is_integer(k) {
            if v.is_empty()
                || !v.bytes().all(|byte| byte.is_ascii_digit())
                || (v.len() > 1 && v.starts_with('0'))
            {
                return Err(Failure::task(format!(
                    "{label} {k} is not a canonical integer"
                )));
            }
            out.push_str(&format!("{k} = {v}\n"));
        } else {
            let escaped = v.replace('\\', "\\\\").replace('"', "\\\"");
            out.push_str(&format!("{k} = \"{escaped}\"\n"));
        }
    }
    Ok(out)
}

fn render_sorted(f: &BTreeMap<String, String>, schema: ScalarSchema) -> Result<String, Failure> {
    let keys = f.keys().cloned().collect::<Vec<_>>();
    render(f, &keys, schema)
}

fn parse(text: &str) -> Result<BTreeMap<String, String>, Failure> {
    if !text.ends_with('\n') || text.contains('\r') {
        return Err(Failure::task("noncanonical WYR1-F scalar file"));
    }
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let (k, v) = line
            .split_once(" = ")
            .ok_or_else(|| Failure::task("malformed WYR1-F scalar line"))?;
        if k.is_empty()
            || !k
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(Failure::task("invalid WYR1-F key"));
        }
        let value = if let Some(q) = v.strip_prefix('"').and_then(|x| x.strip_suffix('"')) {
            decode_scalar_string(q)?
        } else if v.bytes().all(|b| b.is_ascii_digit()) && !v.is_empty() {
            v.to_owned()
        } else {
            return Err(Failure::task("invalid WYR1-F value"));
        };
        if out.insert(k.into(), value).is_some() {
            return Err(Failure::task("duplicate WYR1-F key"));
        }
    }
    Ok(out)
}

fn decode_scalar_string(inner: &str) -> Result<String, Failure> {
    let mut value = String::new();
    let mut characters = inner.chars();
    while let Some(character) = characters.next() {
        match character {
            '\\' => match characters.next() {
                Some('\\') => value.push('\\'),
                Some('"') => value.push('"'),
                _ => return Err(Failure::task("unsupported WYR1-F scalar escape")),
            },
            '"' => return Err(Failure::task("unescaped WYR1-F scalar quote")),
            other => value.push(other),
        }
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    const DEEP: &str = "70e3c9a70e3c9a70e3c9a70e3c9a70e3c9a70e3c";
    const ABI: &str = "085b184c32ae1fa3d5ec322c86957dd5d036595c";
    const TREE: &str = "a9b067107ec38e2be44630f4dce428dab0f48de8";
    const WYRMROOT: &str = "07e070c07e070c07e070c07e070c07e070c07e07";
    const RUST: &str = "a92dc7f7464ad6ddfece4402bd7b86dbfa86166d";

    fn normalized_request() -> BTreeMap<String, String> {
        let mut request = fixed_fields(wyr1c::Wyr1fProduct::Normal)
            .into_iter()
            .chain(obligation_fields())
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect::<BTreeMap<_, _>>();
        for (key, value) in [
            ("deepwyrm_revision", DEEP),
            ("generated_abi_revision", ABI),
            ("generated_abi_tree", TREE),
            ("wyrmroot_revision", WYRMROOT),
            ("rust_revision", RUST),
            ("esp", "artifacts/wyr1f-normal-esp.img"),
            ("receipt", "freeze-receipt.toml"),
            ("source_receipt", "artifacts/f-source-build.toml"),
            ("result_schema", "result-schema.toml"),
        ] {
            request.insert(key.to_owned(), value.to_owned());
        }
        request.insert("esp_sha256".into(), "ab".repeat(32));
        request.insert("source_receipt_sha256".into(), "cd".repeat(32));
        for (key, name) in ARTIFACTS {
            request.insert((*key).to_owned(), format!("artifacts/{name}"));
            request.insert(format!("{key}_sha256"), "ef".repeat(32));
        }
        request
    }

    fn scratch(slug: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = tasks::repository_root()
            .unwrap()
            .join(".tmp/wyr1f-tests")
            .join(format!("{slug}-{}-{unique}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn the_final_product_is_the_production_roles_plus_its_two_admitted_payloads() {
        assert_eq!(
            NATIVE_LABELS,
            [
                "system-init",
                "registryd",
                "devmgr",
                "uart16550d",
                "consoled",
                "wyrmsh",
                "hello",
                "cpu-hog",
            ]
        );
        for label in NATIVE_LABELS {
            wyr1c::wyr1f_native_spec(label, wyr1c::Wyr1fProduct::Normal)
                .expect("every production role is in the final set");
        }
        // Acceptance content the E7/E8 products carry and this one must not.
        // The hog left this list at F3A.2b; the four selector fixtures did
        // not, and the reason is the one the module doc gives: the production
        // supervisor admits `bin/cpu-hog` and admits none of these.
        for label in [
            "exit-nonzero",
            "fault",
            "recovery-trigger",
            "stdout-pressure",
        ] {
            assert!(
                wyr1c::wyr1f_native_spec(label, wyr1c::Wyr1fProduct::Normal).is_err(),
                "{label} is not production"
            );
            assert!(!NATIVE_LABELS.contains(&label));
        }
        let keys = ARTIFACTS.iter().map(|(key, _)| *key).collect::<Vec<_>>();
        assert_eq!(ARTIFACTS.len(), 21);
        // `stack_report` is deliberately present: the shell's bounded stack
        // depth is a production property of `system/wyrmsh`, not selector-33
        // instrumentation, and every accepted product binds it.
        assert!(keys.contains(&"stack_report"));
        assert!(keys.contains(&"cpu_hog"));
        for absent in [
            "malformed_elf",
            "exit_nonzero",
            "fault",
            "recovery_trigger",
            "stdout_pressure",
        ] {
            assert!(!keys.contains(&absent), "{absent} is not a final artifact");
        }
        assert_eq!(
            keys.iter().cloned().collect::<BTreeSet<_>>().len(),
            keys.len()
        );
    }

    #[test]
    fn no_request_or_receipt_field_inherits_e6_or_carries_an_evidence_nonce() {
        let request = request_keys(wyr1c::Wyr1fProduct::Normal);
        let source = source_receipt_keys(wyr1c::Wyr1fProduct::Normal);
        for key in request.iter().chain(source.iter()) {
            assert!(!key.starts_with("e6_"), "{key} inherits an E6 artifact");
            assert!(
                !key.contains("nonce") || key == "gate_config_nonce",
                "{key}"
            );
            assert!(!key.contains("evidence_nonce"), "{key}");
        }
        assert!(!request.contains(&"test_id".to_owned()));
        assert!(!request.contains(&"evidence_nonce".to_owned()));
        // The instrumented gate configuration is F1B's and is not referenced.
        let module = include_str!("wyr1f.rs");
        let code = &module[..module.find("mod tests").unwrap()];
        assert!(!code.contains("wyr1f_gate_config("));
        assert!(code.contains("WYR1F_NORMAL_GATE_CONFIG"));
    }

    #[test]
    fn the_request_key_set_is_exact_and_renders_canonically() {
        let keys = request_keys(wyr1c::Wyr1fProduct::Normal);
        assert_eq!(
            keys.iter().cloned().collect::<BTreeSet<_>>().len(),
            keys.len()
        );
        let request = normalized_request();
        assert_eq!(request.len(), keys.len());
        validate_request(&request).unwrap();
        let text = render(&request, &keys, ScalarSchema::Request).unwrap();
        // Typed scalars: limits are integers, identities are strings.
        assert!(text.contains("closure_test_id = 35\n"));
        assert!(text.contains("com2_capture_bytes = 2097152\n"));
        assert!(text.contains("selector = \"none\"\n"));
        assert!(text.contains("scenario = \"normal\"\n"));
        assert!(text.contains("closure_selector_state = \"reserved\"\n"));
        // Round trip.
        let parsed = parse(&text).unwrap();
        assert_eq!(parsed, request);
        assert_eq!(render(&parsed, &keys, ScalarSchema::Request).unwrap(), text);
    }

    #[test]
    fn malformed_field_types_and_versions_are_rejected() {
        let keys = request_keys(wyr1c::Wyr1fProduct::Normal);
        for (key, bad) in [
            ("schema_version", "2"),
            ("selector", "interactive-wyrmsh"),
            ("scenario", "degraded_recovery"),
            ("closure_test_id", "34"),
            ("closure_selector_state", "implemented"),
            ("kernel_cargo_features", "test-support"),
            ("evidence", "wre1"),
            ("gate_config_nonce", "E800000000000001"),
            ("product", "wyr1-f-degraded"),
        ] {
            let mut request = normalized_request();
            request.insert(key.into(), bad.into());
            assert!(
                validate_request(&request).is_err(),
                "{key} = {bad} must be refused"
            );
        }
        // Mistyped scalars: an integer field rendered non-canonically.
        for (key, bad) in [
            ("schema_version", "01"),
            ("memory_mib", "2048 "),
            ("send_limit", "one-thousand"),
            ("closure_test_id", ""),
        ] {
            let mut request = normalized_request();
            request.insert(key.into(), bad.into());
            assert!(
                render(&request, &keys, ScalarSchema::Request).is_err(),
                "{key}"
            );
        }
        // Altered media identity.
        for (key, bad) in [
            ("esp_sha256", "AB".repeat(32)),
            ("bootfs_sha256", "ab".repeat(20)),
            ("kernel_sha256", "zz".repeat(32)),
            ("deepwyrm_revision", "ab".repeat(32)),
        ] {
            let mut request = normalized_request();
            request.insert(key.into(), bad);
            assert!(validate_request(&request).is_err(), "{key}");
        }
        // Undeclared authority: an artifact path outside the frozen tree.
        for key in ["kernel", "bootfs", "system_init", "gate_config"] {
            let mut request = normalized_request();
            request.insert(key.into(), "../elsewhere/evil.bin".into());
            assert!(validate_request(&request).is_err(), "{key}");
        }
    }

    #[test]
    fn a_mixed_product_request_is_refused_by_both_the_validator_and_the_renderer() {
        // An E8 selector-33 request fed to the F inspector.
        let mut e8 = normalized_request();
        e8.insert("kind".into(), "wyrmroot-wyr1-e8-selector33-request".into());
        assert!(validate_request(&e8).is_err());

        for kind in [
            "wyrmroot-wyr1-e7-selector33-request",
            "wyrmroot-wyr1-e8-selector33-request",
            "wyrmroot-wyr1-e6-product",
        ] {
            let mut request = normalized_request();
            request.insert("kind".into(), kind.into());
            assert!(validate_request(&request).is_err(), "{kind}");
        }
        // A foreign key set never renders as an F request, in either direction.
        let mut extra = normalized_request();
        extra.insert("evidence_nonce".into(), "E800000000000001".into());
        assert!(
            render(
                &extra,
                &request_keys(wyr1c::Wyr1fProduct::Normal),
                ScalarSchema::Request
            )
            .is_err()
        );
        assert!(
            validate_request(&extra).is_ok(),
            "extra keys are a render error, not a field error"
        );

        let mut missing = normalized_request();
        missing.remove("bootfs_sha256");
        assert!(
            render(
                &missing,
                &request_keys(wyr1c::Wyr1fProduct::Normal),
                ScalarSchema::Request
            )
            .is_err()
        );
        assert!(validate_request(&missing).is_err());
    }

    #[test]
    fn the_source_receipt_binds_only_frozen_production_features() {
        let keys = source_receipt_keys(wyr1c::Wyr1fProduct::Normal);
        assert_eq!(
            keys.iter().cloned().collect::<BTreeSet<_>>().len(),
            keys.len()
        );
        for label in NATIVE_LABELS {
            let key = label.replace('-', "_");
            assert!(keys.contains(&format!("{key}_features")));
            assert!(keys.contains(&format!("{key}_command")));
            assert!(keys.contains(&format!("{key}_inspection_sha256")));
            let features =
                wyr1c::wyr1f_native_features(label, wyr1c::Wyr1fProduct::Normal).unwrap();
            assert!(
                !features.contains("selector") && !features.contains("evidence"),
                "{label} carries {features}"
            );
            let command = wyr1c::wyr1f_native_command(label, wyr1c::Wyr1fProduct::Normal).unwrap();
            assert!(command.contains(&format!("--features {features}")));
            assert!(!command.contains("NONCE"), "{label}: {command}");
        }
        assert_eq!(
            wyr1c::wyr1f_native_features("system-init", wyr1c::Wyr1fProduct::Normal).unwrap(),
            "wyr1e-production"
        );
        assert_eq!(
            wyr1c::wyr1f_native_features("devmgr", wyr1c::Wyr1fProduct::Normal).unwrap(),
            "wyr1e8-production"
        );
        assert_eq!(
            wyr1c::wyr1f_native_features("consoled", wyr1c::Wyr1fProduct::Normal).unwrap(),
            "native-consoled,wyr1e-wyrmsh"
        );
    }

    /// DW1-F/WYR1-F F3A.2. The predecessor of this test asserted that the
    /// grammar was "evidence free" and nonce free for *every* product, which is
    /// how the production shape came to be required of the two siblings that
    /// are neither. What is actually true is per product, so this checks each
    /// one against its own request rather than all three against one shape.
    #[test]
    fn each_product_gets_the_result_grammar_its_own_request_implies() {
        use wyr1c::Wyr1fProduct;
        for product_kind in [
            Wyr1fProduct::Normal,
            Wyr1fProduct::InstrumentedNormal,
            Wyr1fProduct::Degraded,
        ] {
            let keys = result_keys(product_kind);
            assert_eq!(
                keys.iter().cloned().collect::<BTreeSet<_>>().len(),
                keys.len(),
                "{product_kind:?} repeats a key"
            );
            assert_eq!(keys.last().map(String::as_str), Some("acceptance"));
            let rendered = result_schema(product_kind).unwrap();
            assert!(rendered.contains("schema_version = \"1\"\n"));
            assert!(rendered.ends_with("acceptance = \"pass\"\n"));
            // Every identity value agrees with the request's, because it is
            // read from the same table rather than spelled twice.
            let fixed = fixed_fields(product_kind);
            for name in ["product", "scenario", "selector", "evidence"] {
                let expected = fixed
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| *value)
                    .unwrap();
                assert!(
                    rendered.contains(&format!("{name} = \"{expected}\"\n")),
                    "{product_kind:?} {name}: {rendered}"
                );
            }
            // The plan's thirteen F3A obligations, each with somewhere to
            // land. `roles_ready_order` is not here: it is asserted below,
            // against the two products whose kernel can actually emit it.
            for key in [
                "com1_com2_distinct",
                "prompt_reached",
                "nonce_echo_status",
                "services_output_sha256",
                "status_output_sha256",
                "tasks_output_sha256",
                "hello_stdout_sha256",
                "hello_exit_status",
                "shell_exit_status",
                "shell_restart_generation",
            ] {
                assert!(
                    keys.iter().any(|k| k == key),
                    "{product_kind:?} lacks {key}"
                );
            }
        }
    }

    /// The scenario-specific halves, and the one property that made the old
    /// grammar wrong: an evidence-producing product must have somewhere to
    /// record evidence, and a product that produces none must not.
    #[test]
    fn the_scenario_and_evidence_halves_are_where_they_belong() {
        use wyr1c::Wyr1fProduct;
        let normal = result_keys(Wyr1fProduct::Normal);
        let instrumented = result_keys(Wyr1fProduct::InstrumentedNormal);
        let degraded = result_keys(Wyr1fProduct::Degraded);

        for keys in [&normal, &instrumented] {
            assert!(keys.iter().any(|k| k == "cpu_hog_jobs"));
            assert!(!keys.iter().any(|k| k.starts_with("degraded_")));
        }
        for key in [
            "degraded_transitions",
            "degraded_retry_attempts",
            "shell_usable_in_degraded",
            "degraded_admin_status",
            "degraded_exit_restart_bounded",
        ] {
            assert!(degraded.iter().any(|k| k == key), "{key}");
        }
        assert!(!degraded.iter().any(|k| k == "cpu_hog_jobs"));

        // The bring-up proof follows the kernel that can witness it. The
        // production kernel writes COM1 only from `emit_early_panic_record`,
        // so a clean boot leaves that line empty and there is no READY record
        // to order; the assertion the production product makes instead is
        // that the line stayed empty.
        for keys in [&instrumented, &degraded] {
            assert!(keys.iter().any(|k| k == "roles_ready_order"));
            assert!(keys.iter().any(|k| k == "roles_ready_count"));
            assert!(!keys.iter().any(|k| k == "com1_empty"));
        }
        assert!(!normal.iter().any(|k| k == "roles_ready_order"));
        assert!(!normal.iter().any(|k| k == "roles_ready_count"));
        assert!(normal.iter().any(|k| k == "com1_empty"));

        // The production product produces no evidence and gets no field for
        // any; both instrumented siblings produce it and get five.
        assert!(!normal.iter().any(|k| k.starts_with("evidence_")));
        for keys in [&instrumented, &degraded] {
            for key in [
                "evidence_protocol",
                "evidence_nonce",
                "expected_evidence_records",
                "evidence_records",
                "evidence_sha256",
            ] {
                assert!(keys.iter().any(|k| k == key), "{key}");
            }
        }
        assert!(
            result_schema(Wyr1fProduct::Normal)
                .unwrap()
                .contains("evidence = \"not-produced\"\n")
        );
        assert!(
            result_schema(Wyr1fProduct::Degraded)
                .unwrap()
                .contains("evidence = \"produced\"\n")
        );
        assert!(
            result_schema(Wyr1fProduct::Degraded)
                .unwrap()
                .contains("scenario = \"degraded_recovery\"\n")
        );
    }

    /// The three grammars must differ. The defect F3A.2 corrects was that they
    /// did not: all three prepared products carried the byte-identical file,
    /// and `inspect` re-rendered the production shape and refused anything else.
    #[test]
    fn the_three_products_do_not_share_one_result_schema() {
        use wyr1c::Wyr1fProduct;
        let normal = result_schema(Wyr1fProduct::Normal).unwrap();
        let instrumented = result_schema(Wyr1fProduct::InstrumentedNormal).unwrap();
        let degraded = result_schema(Wyr1fProduct::Degraded).unwrap();
        assert_ne!(normal, instrumented);
        assert_ne!(normal, degraded);
        assert_ne!(instrumented, degraded);
    }

    #[test]
    fn the_freeze_receipt_carries_every_artifact_identity() {
        let request = normalized_request();
        let text = render(
            &request,
            &request_keys(wyr1c::Wyr1fProduct::Normal),
            ScalarSchema::Request,
        )
        .unwrap();
        let receipt = receipt_fields(&sha256::bytes_digest(text.as_bytes()), &request);
        for (key, _) in ARTIFACTS {
            assert!(receipt.contains_key(&format!("{key}_sha256")), "{key}");
        }
        assert_eq!(receipt["kind"], RECEIPT_KIND);
        assert_eq!(receipt["selector"], "none");
        assert!(!receipt.contains_key("evidence_nonce"));
        let rendered = render_sorted(&receipt, ScalarSchema::FreezeReceipt).unwrap();
        assert!(rendered.contains("closure_test_id = 35\n"));
        assert_eq!(parse(&rendered).unwrap(), receipt);
    }

    #[test]
    fn the_scalar_parser_rejects_ambiguity_and_noncanonical_values() {
        assert!(parse("kind = \"one\"\nkind = \"two\"\n").is_err());
        assert!(parse("kind=\"one\"\n").is_err());
        assert!(parse("kind = bare\n").is_err());
        assert!(parse("kind = \"one\"\r\n").is_err());
        assert!(parse("kind = \"one\"").is_err());
        assert!(parse("Kind = \"one\"\n").is_err());
        assert!(parse("kind = \n").is_err());
    }

    /// F1A refused `--scenario degraded` because the instrumented init
    /// artifact did not exist. F1B supplies it, so the refusal is gone and the
    /// nonce requirement takes its place: an instrumented product's episode
    /// identity is bound to its evidence nonce, and a production product has
    /// no scenario to bind one to.
    #[test]
    fn prepare_requires_a_nonce_for_an_instrumented_product_and_refuses_one_otherwise() {
        let root = scratch("nonce");
        let output = root.join("product");
        for scenario in ["degraded", "degraded_recovery", "normal-instrumented"] {
            let failure = prepare(
                &output,
                scenario,
                Path::new("/nonexistent-deepwyrm"),
                DEEP,
                None,
            )
            .expect_err("an instrumented product without a nonce is refused");
            assert!(
                failure.message.contains("requires --evidence-nonce"),
                "{scenario}: {}",
                failure.message
            );
            assert!(!output.exists(), "a refused prepare must create nothing");
        }
        let failure = prepare(
            &output,
            "normal",
            Path::new("/nonexistent-deepwyrm"),
            DEEP,
            Some("0123456789ABCDEF"),
        )
        .expect_err("the production product takes no nonce");
        assert!(
            failure.message.contains("takes no evidence nonce"),
            "{}",
            failure.message
        );
        assert!(!output.exists());
        // A nonce the real init parser would reject is refused before any
        // filesystem effect too.
        for bad in ["0123456789abcdef", "FF", "0000000000000000", ""] {
            let failure = prepare(
                &output,
                "degraded",
                Path::new("/nonexistent-deepwyrm"),
                DEEP,
                Some(bad),
            )
            .expect_err("a malformed nonce is refused");
            assert!(!failure.message.is_empty(), "{bad}");
            assert!(!output.exists(), "{bad}");
        }
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn prepare_refuses_an_unknown_scenario_before_any_effect() {
        let root = scratch("unknown-scenario");
        let output = root.join("product");
        for scenario in ["", "normal-recovery", "NORMAL", "interactive-wyrmsh", "35"] {
            let failure = prepare(
                &output,
                scenario,
                Path::new("/nonexistent-deepwyrm"),
                DEEP,
                None,
            )
            .expect_err("an unknown scenario is refused");
            assert!(
                failure.message.contains("unknown WYR1-F scenario"),
                "{scenario}: {}",
                failure.message
            );
            assert!(!output.exists());
        }
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn inspect_refuses_traversal_symlinks_and_owned_paths() {
        let repository = tasks::repository_root().unwrap();
        // Inside the Wyrmroot checkout: explicitly excluded locality.
        let owned = scratch("owned");
        assert!(inspect(&owned).is_err());
        fs::remove_dir_all(&owned).unwrap();
        // Outside the project boundary.
        assert!(inspect(Path::new("/usr/share")).is_err());
        assert!(inspect(Path::new("/nonexistent/wyr1f")).is_err());
        // A symlink that resolves back into the owned checkout.
        let root = scratch("symlink");
        let link = root.join("link");
        std::os::unix::fs::symlink(&repository, &link).unwrap();
        assert!(inspect(&link).is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn prepared_only_inspection_rejects_consumed_runtime_state() {
        let root = scratch("consumed");
        reject_consumed_runtime_state(&root).expect("a bare directory is not consumed state");
        for name in RUNTIME_STATE_NAMES {
            let path = root.join(name);
            fs::write(&path, b"x").unwrap();
            let failure =
                reject_consumed_runtime_state(&root).expect_err("runtime state must be refused");
            assert!(
                failure.message.contains("consumed/runtime state"),
                "{name}: {}",
                failure.message
            );
            fs::remove_file(&path).unwrap();
        }
        // F3A.3: a bare profile directory is now *prepared* content, not
        // evidence of a run. What makes it consumed is what a run leaves inside
        // it, so the same refusal has to hold one level down.
        for (profile, _) in PROFILES {
            let directory = root.join(profile);
            fs::create_dir(&directory).unwrap();
            reject_consumed_runtime_state(&root)
                .expect("a staged profile directory is not consumed state");
            for name in PROFILE_RUNTIME_STATE_NAMES {
                let path = directory.join(name);
                fs::write(&path, b"x").unwrap();
                let failure = reject_consumed_runtime_state(&root)
                    .expect_err("profile runtime state must be refused");
                assert!(
                    failure.message.contains("consumed/runtime state"),
                    "{profile}/{name}: {}",
                    failure.message
                );
                fs::remove_file(&path).unwrap();
            }
        }
        // The staged trio is what a prepared profile holds, and none of it
        // reads as a run.
        for (profile, _) in PROFILES {
            for name in PROFILE_ENTRIES {
                fs::write(root.join(profile).join(name), b"x").unwrap();
            }
        }
        reject_consumed_runtime_state(&root).expect("staged profile entries are not consumed");
        fs::remove_dir_all(&root).unwrap();
    }

    /// DW1-F/WYR1-F F3A.3. Every other launching card hands its selector to the
    /// guest through fwcfg entries. The production final product selects no
    /// guest test, so its domain must name none -- and passing empty strings to
    /// the selected generator would still emit the entry, which is why there is
    /// a second generator rather than an empty argument.
    #[test]
    fn only_an_instrumented_product_gets_a_domain_that_names_a_guest_test() {
        use std::path::Path;
        use wyr1c::Wyr1fProduct;
        let render = |product_kind, vcpus| {
            profile_domain_xml(
                product_kind,
                vcpus,
                Path::new("/p/OVMF_CODE.fd"),
                Path::new("/p/esp.img"),
                Path::new("/p/default/OVMF_VARS.mutable.fd"),
                Path::new("/p/default/com2.sock"),
            )
        };
        let production = render(Wyr1fProduct::Normal, 1);
        assert!(
            !production.contains("org.deepwyrm.test.selector"),
            "{production}"
        );
        assert!(!production.contains("<sysinfo"), "{production}");
        assert!(!production.contains(wyr1c::WYR1F_SELECTOR), "{production}");

        for product_kind in [Wyr1fProduct::InstrumentedNormal, Wyr1fProduct::Degraded] {
            let instrumented = render(product_kind, 4);
            assert!(instrumented.contains("org.deepwyrm.test.selector"));
            assert!(instrumented.contains(wyr1c::WYR1F_SELECTOR));
            assert!(instrumented.contains(wyr1c::WYR1F_TEST_ID));
        }

        // Both profiles differ only in the vCPU count, and the production and
        // instrumented domains differ only by the selection: everything a run
        // depends on -- machine, firmware, COM1 pty, COM2 unix socket,
        // isa-debug-exit -- is shared.
        assert!(production.contains("<vcpu placement=\"static\">1</vcpu>"));
        assert!(render(Wyr1fProduct::Normal, 4).contains("<vcpu placement=\"static\">4</vcpu>"));
        for xml in [&production, &render(Wyr1fProduct::InstrumentedNormal, 1)] {
            assert!(xml.contains("isa-debug-exit,iobase=0xf4,iosize=0x04"));
            assert!(xml.contains("<serial type=\"pty\">"));
            assert!(xml.contains("<source mode=\"connect\" path=\"/p/default/com2.sock\"/>"));
        }
    }

    #[test]
    fn frozen_metadata_requires_an_exact_entry_set_and_sealed_modes() {
        let root = scratch("entries");
        let product = root.join("product");
        fs::create_dir(&product).unwrap();
        for name in [
            "artifacts",
            "default",
            "smp",
            "profile-pair.toml",
            "request.toml",
            "result-schema.toml",
            "freeze-receipt.toml",
        ] {
            if matches!(name, "artifacts" | "default" | "smp") {
                fs::create_dir(product.join(name)).unwrap();
            } else {
                fs::write(product.join(name), b"x").unwrap();
            }
        }
        const PREPARED: [&str; 7] = [
            "artifacts",
            "default",
            "smp",
            "profile-pair.toml",
            "request.toml",
            "result-schema.toml",
            "freeze-receipt.toml",
        ];
        require_exact_directory(&product, &PREPARED, "WYR1-F output").unwrap();
        fs::write(product.join("extra.toml"), b"x").unwrap();
        assert!(require_exact_directory(&product, &PREPARED, "WYR1-F output").is_err());
        fs::remove_file(product.join("extra.toml")).unwrap();
        // Modes: 0644 is not a sealed product file, and a symlink is never one.
        assert!(require_mode(&product.join("request.toml"), 0o444, "request").is_err());
        fs::set_permissions(
            product.join("request.toml"),
            fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        require_mode(&product.join("request.toml"), 0o444, "request").unwrap();
        std::os::unix::fs::symlink(product.join("request.toml"), product.join("alias")).unwrap();
        assert!(require_mode(&product.join("alias"), 0o444, "alias").is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_kernel_command_declares_exactly_its_product_s_instrumentation() {
        const NONCE: &str = "0123456789ABCDEF";
        let arguments_and_env = |product_kind| {
            let command = kernel_build_command(
                Path::new("/deep/tools/pinned-cargo"),
                Path::new("/deep"),
                Path::new("/deep/.tmp/target"),
                wyr1c::wyr1f_kernel_evidence_nonce(
                    product_kind,
                    &product_kind
                        .gate_config(product_kind.gate_scenario().map(|_| NONCE))
                        .unwrap(),
                )
                .unwrap()
                .as_deref(),
                // The measured WYR1-F archive (828,200 bytes) that exposed the
                // 17-page ceiling.
                203,
            );
            let arguments = command
                .get_args()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            let removed = command
                .get_envs()
                .filter(|(_, value)| value.is_none())
                .map(|(key, _)| key.to_string_lossy().into_owned())
                .collect::<BTreeSet<_>>();
            let set = command
                .get_envs()
                .filter_map(|(key, value)| {
                    value.map(|value| {
                        (
                            key.to_string_lossy().into_owned(),
                            value.to_string_lossy().into_owned(),
                        )
                    })
                })
                .collect::<BTreeMap<_, _>>();
            (arguments, removed, set)
        };

        // No product passes cargo features, ever.
        for product_kind in [
            wyr1c::Wyr1fProduct::Normal,
            wyr1c::Wyr1fProduct::InstrumentedNormal,
            wyr1c::Wyr1fProduct::Degraded,
        ] {
            let (arguments, removed, _) = arguments_and_env(product_kind);
            let features = arguments.iter().any(|argument| argument == "--features");
            assert_eq!(features, product_kind.is_instrumented());
            assert_eq!(
                arguments.iter().any(|argument| argument == "test-support"),
                product_kind.is_instrumented()
            );
            assert!(arguments.contains(&"--locked".to_owned()));
            assert!(arguments.contains(&"--offline".to_owned()));
            assert!(arguments.contains(&KERNEL_TARGET.to_owned()));
            // Every evidence variable is removed for every product: an
            // instrumented kernel selects a guest test, it does not inherit an
            // evidence nonce from the operator's shell.
            assert!(removed.contains("DEEPWYRM_WYR1E8_EVIDENCE"));
            assert!(removed.contains("DEEPWYRM_WYR1E8_EVIDENCE_NONCE"));
            assert!(removed.contains("DEEPWYRM_DW1E_EVIDENCE_NONCE"));
        }

        // The production kernel sets nothing but its target directory, which is
        // what makes it carry no guest-test selector string at all.
        let (_, removed, set) = arguments_and_env(wyr1c::Wyr1fProduct::Normal);
        assert!(removed.contains("DEEPWYRM_GUEST_TEST_SELECTOR"));
        assert!(removed.contains("DEEPWYRM_GUEST_TEST_ID"));
        // F3A.6y adds the measured bootfs ceiling. It is not a selector and
        // does not instrument the kernel -- it decides how large an archive the
        // production kernel admits, which used to be a Wave 4 literal of 17
        // against a 203-page archive.
        assert_eq!(
            set.keys().cloned().collect::<Vec<_>>(),
            vec![
                "DEEPWYRM_BOOTFS_MAX_PAGES".to_owned(),
                "DEEPWYRM_PINNED_TARGET_DIR".to_owned(),
            ]
        );
        assert_eq!(
            set.get("DEEPWYRM_BOOTFS_MAX_PAGES").map(String::as_str),
            Some("203")
        );

        // Both instrumented siblings set exactly the frozen selector pair, and
        // the same pair: the kernel is not part of the declared normal/degraded
        // difference.
        let mut instrumented = Vec::new();
        for product_kind in [
            wyr1c::Wyr1fProduct::InstrumentedNormal,
            wyr1c::Wyr1fProduct::Degraded,
        ] {
            let (_, _, set) = arguments_and_env(product_kind);
            assert_eq!(
                set.get("DEEPWYRM_GUEST_TEST_SELECTOR").map(String::as_str),
                Some(wyr1c::WYR1F_SELECTOR)
            );
            // The id is never set: it is build-owned, derived from the
            // manifest entry the selector name selects.
            assert!(!set.contains_key("DEEPWYRM_GUEST_TEST_ID"));
            // The selector, its WRE1 evidence nonce, and the target
            // directory. Nothing else.
            assert_eq!(
                set.get("DEEPWYRM_WYR1E7_EVIDENCE_NONCE")
                    .map(String::as_str),
                Some(NONCE)
            );
            assert_eq!(set.len(), 3, "no fourth variable is set");
            // The measured ceiling is removed, not set: contract §5.4 makes
            // the instrumented kernel identical across the pair, so nothing
            // derived from a per-product archive may reach it.
            assert!(!set.contains_key("DEEPWYRM_BOOTFS_MAX_PAGES"));
            instrumented.push(set);
        }
        assert_eq!(instrumented[0], instrumented[1]);
    }
}
