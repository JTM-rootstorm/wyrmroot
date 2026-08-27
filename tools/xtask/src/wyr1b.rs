//! Selector-27 WYR1-B request, deterministic bootfs, receipt, and WRB1 evidence.

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
};

use crate::wyr1::fixed_builder_for_profile;
use crate::{error::Failure, sha256};
use wyrmroot_bootfs::{
    archive::Archive,
    launch_policy::{LaunchPolicy, LaunchPolicyEntry, encode as encode_policy},
    wyr1::{Product, ProductB, build_b},
};
use wyrmroot_rrc_manifest::{Activation, Manifest, RoleId, StartupProfile};

pub const SCHEMA: u32 = 6;
pub const SELECTOR: &str = "bootstrap-registry-launch";
pub const TEST_ID: u32 = 27;
pub const ACCEPTED_RUST_REVISION: &str = "a92dc7f7464ad6ddfece4402bd7b86dbfa86166d";
const REQUEST_KIND: &str = "wyrmroot-wyr1-b-acceptance-request";
const RECEIPT_KIND: &str = "wyrmroot-wyr1-b-build-lineage";
const SOURCE_RECEIPT_KIND: &str = "wyrmroot-wyr1-b-wyr-source-build";
const KERNEL_PROVENANCE_KIND: &str = "wyrmroot-wyr1-b-kernel-build";
const RUN_RECEIPT_KIND: &str = "wyrmroot-wyr1-b-run-receipt";
const ACCEPTED_TOOLCHAIN_NAME: &str = "wyrmroot-1.97.1-a92dc7f7";
const ACCEPTED_RUSTC_SHA256: &str =
    "65bd51e9ecb8e1185524471a8cbc4af1e6ac4e37e7d446c7a127bda0fa431c70";
const ACCEPTED_CARGO_SHA256: &str =
    "a73b2c25573d251489101c0d8f19ad3702eb9761166de5ed8437b472b6c038ce";
const ACCEPTED_RUST_LLD_SHA256: &str =
    "38a9f28404309892f9c9afe02fa4979a0d9e8bc866979cde09f5bb7ec17e5721";
const ACCEPTED_TOOLCHAIN_MANIFEST_SHA256: &str =
    "cc78368219552cce8fdaad38ab419040cab945fe175aa774d6dca51eece84fd2";
const ACCEPTED_TOOLCHAIN_TREE_SHA256: &str =
    "dce57d31def1f509ce537f96ae6b6dd320da11c9f321382cb93d142f558a32ca";
const OVMF_CODE_PATH: &str = "/usr/share/edk2/OvmfX64/OVMF_CODE.fd";
const OVMF_CODE_SHA256: &str = "f3ff7e73448ed2845ee15356f394882f5618eb5dab92c9a30ec6ee0e1468553a";
const OVMF_VARS_PATH: &str = "/usr/share/edk2/OvmfX64/OVMF_VARS.fd";
const OVMF_VARS_SHA256: &str = "6ed987af3a3c155be71665f510eae3e007eda9b8b94afd59d45e91c4a11565cc";
const NATIVE_TARGET: &str = "x86_64-unknown-wyrmroot";
const KERNEL_TARGET: &str = "x86_64-unknown-none";
const MAX_REQUEST: usize = 64 * 1024;
const MAX_EVIDENCE: usize = 16 * 1024 * 1024;
const KEYS: &[&str] = &[
    "kind",
    "schema_version",
    "selector",
    "test_id",
    "timeout_seconds",
    "deepwyrm_revision",
    "wyrmroot_revision",
    "rust_revision",
    "boot_generation",
    "loader",
    "loader_sha256",
    "kernel",
    "kernel_sha256",
    "symbols",
    "symbols_sha256",
    "bootstrap",
    "bootstrap_sha256",
    "init",
    "init_sha256",
    "registryd",
    "registryd_sha256",
    "devmgr",
    "devmgr_sha256",
    "uart16550d",
    "uart16550d_sha256",
    "consoled",
    "consoled_sha256",
    "wyrmsh",
    "wyrmsh_sha256",
    "hello",
    "hello_sha256",
    "publisher",
    "publisher_sha256",
    "client",
    "client_sha256",
    "source_receipt",
    "source_receipt_sha256",
    "kernel_provenance",
    "kernel_provenance_sha256",
    "ovmf_code",
    "ovmf_code_sha256",
    "ovmf_vars",
    "ovmf_vars_sha256",
    "rrc_manifest",
    "bootfs",
    "bootfs_pages",
    "esp",
    "receipt",
    "run_directory",
    "serial_log",
    "run_receipt",
    "evidence_nonce",
];
const BUILD_RECEIPT_KEYS: &[&str] = &[
    "kind",
    "schema_version",
    "selector",
    "test_id",
    "request_sha256",
    "deepwyrm_revision",
    "wyrmroot_revision",
    "rust_revision",
    "boot_generation",
    "bootfs_bytes",
    "bootfs_pages",
    "bootfs_sha256",
    "rrc_manifest_sha256",
    "launch_policy_sha256",
    "gate_sha256",
    "hello_sha256",
    "publisher_sha256",
    "client_sha256",
    "loader_sha256",
    "kernel_sha256",
    "symbols_sha256",
    "bootstrap_sha256",
    "source_receipt_sha256",
    "kernel_provenance_sha256",
    "ovmf_code_sha256",
    "ovmf_vars_sha256",
    "esp_sha256",
    "evidence_nonce",
    "timeout_seconds",
];
const KERNEL_PROVENANCE_KEYS: &[&str] = &[
    "kind",
    "schema_version",
    "selector",
    "test_id",
    "deepwyrm_revision",
    "rust_revision",
    "rustc_sha256",
    "cargo_sha256",
    "rust_lld_sha256",
    "toolchain_manifest_sha256",
    "toolchain_tree_sha256",
    "kernel_command",
    "kernel_sha256",
    "symbols_sha256",
    "DEEPWYRM_WYR1B_EVIDENCE_NONCE",
    "DEEPWYRM_WYR1B_BOOTFS_MAX_PAGES",
];
const RUN_RECEIPT_KEYS: &[&str] = &[
    "kind",
    "schema_version",
    "selector",
    "test_id",
    "request_sha256",
    "build_receipt_sha256",
    "esp_sha256",
    "bootfs_sha256",
    "serial_log_sha256",
    "ovmf_code_sha256",
    "ovmf_vars_sha256",
    "timeout_seconds",
    "qemu_exit_status",
    "timed_out",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    root: PathBuf,
    path: PathBuf,
    request_sha256: String,
    timeout_seconds: u64,
    deepwyrm_revision: String,
    wyrmroot_revision: String,
    rust_revision: String,
    boot_generation: [u8; 32],
    loader: PathBuf,
    loader_sha256: String,
    kernel: PathBuf,
    kernel_sha256: String,
    symbols: PathBuf,
    symbols_sha256: String,
    bootstrap: PathBuf,
    bootstrap_sha256: String,
    init: PathBuf,
    init_sha256: String,
    registryd: PathBuf,
    registryd_sha256: String,
    devmgr: PathBuf,
    devmgr_sha256: String,
    uart16550d: PathBuf,
    uart16550d_sha256: String,
    consoled: PathBuf,
    consoled_sha256: String,
    wyrmsh: PathBuf,
    wyrmsh_sha256: String,
    rrc_manifest: PathBuf,
    hello: PathBuf,
    hello_sha256: String,
    publisher: PathBuf,
    publisher_sha256: String,
    client: PathBuf,
    client_sha256: String,
    source_receipt: PathBuf,
    source_receipt_sha256: String,
    kernel_provenance: PathBuf,
    kernel_provenance_sha256: String,
    ovmf_code: PathBuf,
    ovmf_code_sha256: String,
    ovmf_vars: PathBuf,
    ovmf_vars_sha256: String,
    bootfs: PathBuf,
    bootfs_pages: usize,
    esp: PathBuf,
    receipt: PathBuf,
    run_directory: PathBuf,
    serial_log: PathBuf,
    run_receipt: PathBuf,
    evidence_nonce: u64,
}

struct FrozenArtifacts {
    loader: Vec<u8>,
    bootstrap: Vec<u8>,
    init27: Vec<u8>,
    registryd: Vec<u8>,
    devmgr: Vec<u8>,
    uart16550d: Vec<u8>,
    consoled: Vec<u8>,
    wyrmsh: Vec<u8>,
    hello: Vec<u8>,
    publisher: Vec<u8>,
    client: Vec<u8>,
    init25: Vec<u8>,
    registryd25: Vec<u8>,
    registryd25_fail: Vec<u8>,
    source_receipt: String,
}

struct NativeSpec<'a> {
    label: &'a str,
    package: &'a str,
    binary: &'a str,
    features: &'a str,
    artifact: &'a str,
}

pub fn freeze(output: &Path) -> Result<String, Failure> {
    reject_ambient_build_environment()?;
    let repository = crate::tasks::repository_root()?;
    let deepwyrm = deepwyrm_repository()?;
    let wyrmroot_revision = repository_revision(&repository, "Wyrmroot")?;
    let deepwyrm_revision = repository_revision(&deepwyrm, "Deepwyrm")?;
    if fs::symlink_metadata(output).is_ok() {
        return Err(Failure::task(
            "WYR1-B freeze refuses a pre-existing output path",
        ));
    }
    let parent = output
        .parent()
        .ok_or_else(|| Failure::task("WYR1-B freeze output has no parent"))?;
    let parent = fs::canonicalize(parent)
        .map_err(|error| Failure::task(format!("could not resolve freeze parent: {error}")))?;
    let name = output
        .file_name()
        .ok_or_else(|| Failure::task("WYR1-B freeze output has no final component"))?;
    let output = parent.join(name);
    if output.starts_with(&repository) || output.starts_with(&deepwyrm) {
        return Err(Failure::task(
            "WYR1-B freeze output must be outside both clean source repositories",
        ));
    }
    fs::create_dir(&output)
        .map_err(|error| Failure::task(format!("could not create WYR1-B freeze root: {error}")))?;
    let build_root = output.join("build");
    fs::create_dir(&build_root)
        .map_err(|error| Failure::task(format!("could not create WYR1-B build root: {error}")))?;
    let artifacts = build_frozen_artifacts(&build_root, &wyrmroot_revision)?;
    let nonce = 0xB001_B027_0000_0001;
    let generation_text = sha256::bytes_digest(
        format!(
            "WYR1-B|{deepwyrm_revision}|{wyrmroot_revision}|{ACCEPTED_RUST_REVISION}|{nonce:016X}"
        )
        .as_bytes(),
    );
    let generation = decode_digest(&generation_text)?;
    let bootfs = product_bytes(&artifacts, generation, nonce)?;
    let bootfs_pages = bootfs.len().div_ceil(4096);
    let kernel = build_kernel(
        &deepwyrm,
        &build_root,
        "selector27",
        SELECTOR,
        &[
            ("DEEPWYRM_WYR1B_EVIDENCE_NONCE", format!("{nonce:016X}")),
            ("DEEPWYRM_WYR1B_BOOTFS_MAX_PAGES", bootfs_pages.to_string()),
        ],
    )?;
    let kernel_sha256 = sha256::bytes_digest(&kernel);
    let kernel_provenance = format!(
        "kind = \"{KERNEL_PROVENANCE_KIND}\"\nschema_version = 1\nselector = \"{SELECTOR}\"\ntest_id = {TEST_ID}\ndeepwyrm_revision = \"{deepwyrm_revision}\"\nrust_revision = \"{ACCEPTED_RUST_REVISION}\"\nrustc_sha256 = \"{ACCEPTED_RUSTC_SHA256}\"\ncargo_sha256 = \"{ACCEPTED_CARGO_SHA256}\"\nrust_lld_sha256 = \"{ACCEPTED_RUST_LLD_SHA256}\"\ntoolchain_manifest_sha256 = \"{ACCEPTED_TOOLCHAIN_MANIFEST_SHA256}\"\ntoolchain_tree_sha256 = \"{ACCEPTED_TOOLCHAIN_TREE_SHA256}\"\nkernel_command = \"tools/pinned-cargo target build --locked --offline --release --target x86_64-unknown-none --package deepwyrm-kernel --bin deepwyrm-kernel --features test-support\"\nkernel_sha256 = \"{kernel_sha256}\"\nsymbols_sha256 = \"{kernel_sha256}\"\nDEEPWYRM_WYR1B_EVIDENCE_NONCE = \"{nonce:016X}\"\nDEEPWYRM_WYR1B_BOOTFS_MAX_PAGES = {bootfs_pages}\n"
    );
    let selector27 = output.join("selector27");
    let selector27_artifacts = selector27.join("artifacts");
    fs::create_dir_all(&selector27_artifacts).map_err(|error| {
        Failure::task(format!("could not create selector-27 artifacts: {error}"))
    })?;
    for (name, bytes) in [
        ("loader.efi", artifacts.loader.as_slice()),
        ("deepwyrm.elf", kernel.as_slice()),
        ("deepwyrm.symbols.elf", kernel.as_slice()),
        ("bootstrap.elf", artifacts.bootstrap.as_slice()),
        ("system-init.elf", artifacts.init27.as_slice()),
        ("registryd.elf", artifacts.registryd.as_slice()),
        ("devmgr.elf", artifacts.devmgr.as_slice()),
        ("uart16550d.elf", artifacts.uart16550d.as_slice()),
        ("consoled.elf", artifacts.consoled.as_slice()),
        ("wyrmsh.elf", artifacts.wyrmsh.as_slice()),
        ("hello.elf", artifacts.hello.as_slice()),
        ("wyr1-b-publisher.elf", artifacts.publisher.as_slice()),
        ("wyr1-b-client.elf", artifacts.client.as_slice()),
        ("wyr-source-build.toml", artifacts.source_receipt.as_bytes()),
        ("kernel-provenance.toml", kernel_provenance.as_bytes()),
    ] {
        write_new_file(&selector27_artifacts.join(name), bytes)?;
    }
    let ovmf_code = read_pinned_firmware(OVMF_CODE_PATH, OVMF_CODE_SHA256, "OVMF code")?;
    let ovmf_vars = read_pinned_firmware(OVMF_VARS_PATH, OVMF_VARS_SHA256, "OVMF vars")?;
    write_new_file(&selector27_artifacts.join("OVMF_CODE.fd"), &ovmf_code)?;
    write_new_file(&selector27_artifacts.join("OVMF_VARS.fd"), &ovmf_vars)?;
    let request_text = render_request(
        &deepwyrm_revision,
        &wyrmroot_revision,
        &generation_text,
        nonce,
        bootfs_pages,
        &artifacts,
        &kernel,
        kernel_provenance.as_bytes(),
        &ovmf_code,
        &ovmf_vars,
    );
    let request_path = selector27.join("request.toml");
    write_new_file(&request_path, request_text.as_bytes())?;
    let image_result = build(&request_path)?;
    let _ = inspect_recorded(&request_path)?;
    freeze_selector25_regressions(
        &output,
        &build_root,
        &deepwyrm,
        &deepwyrm_revision,
        &wyrmroot_revision,
        &artifacts,
        &ovmf_code,
        &ovmf_vars,
    )?;
    verify_repository_revision(&repository, "Wyrmroot", &wyrmroot_revision)?;
    verify_repository_revision(&deepwyrm, "Deepwyrm", &deepwyrm_revision)?;
    Ok(format!(
        "WYR1_B_FREEZE_PASS deepwyrm_revision={deepwyrm_revision} wyrmroot_revision={wyrmroot_revision} rust_revision={ACCEPTED_RUST_REVISION} bootfs_pages={bootfs_pages} request={} {image_result}",
        request_path.display(),
    ))
}

fn product_bytes(
    artifacts: &FrozenArtifacts,
    generation: [u8; 32],
    nonce: u64,
) -> Result<Vec<u8>, Failure> {
    let role_hashes = [
        sha256::bytes_digest_array(&artifacts.registryd),
        sha256::bytes_digest_array(&artifacts.devmgr),
        sha256::bytes_digest_array(&artifacts.uart16550d),
        sha256::bytes_digest_array(&artifacts.consoled),
        sha256::bytes_digest_array(&artifacts.wyrmsh),
    ];
    let manifest =
        fixed_builder_for_profile(&generation, role_hashes, StartupProfile::BootstrapRegistry)?
            .build_structural()
            .map_err(|error| Failure::task(format!("WYR1-B manifest build failed: {error:?}")))?;
    let mut policy_bytes = [0u8; 512];
    let policy_size = encode_policy(
        generation,
        &[LaunchPolicyEntry {
            path: "bin/hello",
            content_sha256: sha256::bytes_digest_array(&artifacts.hello),
            startup_abi: 2,
            profile_id: 1,
            allow_no_streams: true,
            allow_three_streams: true,
        }],
        &mut policy_bytes,
    )
    .map_err(|error| Failure::task(format!("WYR1-B launch policy failed: {error:?}")))?;
    let policy = policy_bytes[..policy_size].to_vec();
    let a_gate = format!(
        "schema = 1\nselector = \"permanent-supervisor-rrc\"\ntest_id = 25\nscenario = \"normal\"\nevidence_protocol = \"wyr1evid1\"\nnonce = \"{nonce:016X}\"\n"
    );
    let gate = format!(
        "schema = 6\nselector = \"{SELECTOR}\"\ntest_id = {TEST_ID}\nevidence_protocol = \"wrb1\"\nnonce = \"{nonce:016X}\"\n"
    )
    .into_bytes();
    let bootfs = build_b(ProductB {
        base: Product {
            init: &artifacts.init27,
            registryd: &artifacts.registryd,
            devmgr: &artifacts.devmgr,
            uart16550d: &artifacts.uart16550d,
            consoled: &artifacts.consoled,
            wyrmsh: &artifacts.wyrmsh,
            rrc_manifest: &manifest,
            gate_config: a_gate.as_bytes(),
        },
        launch_policy: &policy,
        gate_config: &gate,
        hello: &artifacts.hello,
        publisher: &artifacts.publisher,
        client: &artifacts.client,
    })
    .map_err(|error| Failure::task(format!("WYR1-B bootfs build failed: {error:?}")))?;
    Ok(bootfs)
}

fn reject_ambient_build_environment() -> Result<(), Failure> {
    for variable in [
        "RUSTC",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_TARGET",
        "CARGO_TARGET_DIR",
        "CARGO_HOME",
        "WYRMROOT_DEEP_LAYOUT_POLICY_RS",
        "DEEPWYRM_GUEST_TEST_SELECTOR",
        "DEEPWYRM_GUEST_TEST_ID",
        "DEEPWYRM_WYR1B_EVIDENCE_NONCE",
        "DEEPWYRM_WYR1B_BOOTFS_MAX_PAGES",
        "DEEPWYRM_WYR1_EVIDENCE_NONCE",
        "DEEPWYRM_WYR1_EVIDENCE_SCENARIO",
    ] {
        if env::var_os(variable).is_some() {
            return Err(Failure::task(format!(
                "WYR1-B canonical freeze refuses ambient {variable}"
            )));
        }
    }
    Ok(())
}

fn build_frozen_artifacts(build_root: &Path, revision: &str) -> Result<FrozenArtifacts, Failure> {
    let repository = crate::tasks::repository_root()?;
    let manifest = crate::metadata::BuildManifest::load(&repository)?;
    if manifest.rust_revision()? != ACCEPTED_RUST_REVISION
        || manifest.rust_toolchain_name()? != ACCEPTED_TOOLCHAIN_NAME
    {
        return Err(Failure::task(
            "WYR1-B source metadata does not name the accepted Rust toolchain",
        ));
    }
    let profile = manifest.validate_loader_build_readiness(&repository)?;
    let layout = crate::deep_layout::prepare(
        &repository,
        manifest.deepwyrm_repository()?,
        manifest.deepwyrm_revision()?,
    )?;
    let toolchain = crate::tasks::prepare_loader_toolchain(&repository, &profile, &manifest)?;
    let cargo_home = crate::tasks::project_cargo_home(&repository, &manifest)?;
    let uefi = crate::tasks::build_deterministic_uefi_pair(
        &repository,
        &toolchain,
        &profile,
        &layout,
        &crate::tasks::IsolatedUefiBuild {
            cargo_home: &cargo_home,
            production_target: &build_root.join("uefi-production"),
            retained_debug_target: &build_root.join("uefi-retained-debug"),
            cargo_profile: crate::tasks::UefiCargoProfile::Release,
        },
    )?;
    let loader = read_bounded(&uefi.loader, "loader", 64 * 1024 * 1024)?;
    let specs = [
        NativeSpec {
            label: "bootstrap",
            package: "wyrmroot-bootstrap",
            binary: "wyrmroot-bootstrap",
            features: "native-bootstrap",
            artifact: "wyrmroot-bootstrap",
        },
        NativeSpec {
            label: "init27",
            package: "wyrmroot-system-init",
            binary: "system-init",
            features: "native-init,wyr1b-test-evidence",
            artifact: "system-init",
        },
        NativeSpec {
            label: "registryd",
            package: "wyrmroot-registryd",
            binary: "registryd",
            features: "native-registryd",
            artifact: "registryd",
        },
        NativeSpec {
            label: "devmgr",
            package: "wyrmroot-wyr1-bootstrap-stubs",
            binary: "devmgr",
            features: "native-stubs",
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
            label: "hello",
            package: "wyrmroot-hello",
            binary: "wyrmroot-job-hello",
            features: "native-job-hello",
            artifact: "wyrmroot-job-hello",
        },
        NativeSpec {
            label: "publisher",
            package: "wyrmroot-wyr1b-gate",
            binary: "wyr1-b-publisher",
            features: "native-gate",
            artifact: "wyr1-b-publisher",
        },
        NativeSpec {
            label: "client",
            package: "wyrmroot-wyr1b-gate",
            binary: "wyr1-b-client",
            features: "native-gate",
            artifact: "wyr1-b-client",
        },
        NativeSpec {
            label: "init25",
            package: "wyrmroot-system-init",
            binary: "system-init",
            features: "native-init,wyr1-test-evidence",
            artifact: "system-init",
        },
        NativeSpec {
            label: "registryd25",
            package: "wyrmroot-wyr1-bootstrap-stubs",
            binary: "registryd",
            features: "native-stubs",
            artifact: "registryd",
        },
        NativeSpec {
            label: "registryd25-fail",
            package: "wyrmroot-wyr1-bootstrap-stubs",
            binary: "registryd-fail",
            features: "native-stubs",
            artifact: "registryd-fail",
        },
    ];
    let mut built = Vec::with_capacity(specs.len());
    let mut commands = Vec::with_capacity(specs.len());
    for spec in specs {
        toolchain.accepted().verify_unchanged()?;
        layout.verify_unchanged()?;
        let (bytes, command) = build_native(
            &repository,
            &cargo_home,
            toolchain.accepted(),
            build_root,
            &spec,
        )?;
        built.push(bytes);
        commands.push((spec.label, command));
    }
    let [
        bootstrap,
        init27,
        registryd,
        devmgr,
        uart16550d,
        consoled,
        wyrmsh,
        hello,
        publisher,
        client,
        init25,
        registryd25,
        registryd25_fail,
    ]: [Vec<u8>; 13] = built
        .try_into()
        .map_err(|_| Failure::task("WYR1-B source build produced wrong artifact count"))?;
    verify_repository_revision(&repository, "Wyrmroot", revision)?;
    let rustc_sha256 = sha256::file_digest(&toolchain.accepted().rustc)
        .map_err(|error| Failure::task(format!("could not hash accepted rustc: {error}")))?;
    let mut source_receipt = format!(
        "kind = \"{SOURCE_RECEIPT_KIND}\"\nschema_version = 1\nwyrmroot_revision = \"{revision}\"\nrust_revision = \"{ACCEPTED_RUST_REVISION}\"\nrustc_sha256 = \"{rustc_sha256}\"\ncargo_sha256 = \"{}\"\nrust_lld_sha256 = \"{}\"\ntoolchain_manifest_sha256 = \"{}\"\ntoolchain_tree_sha256 = \"{}\"\ncargo_lock_sha256 = \"{}\"\nloader_sha256 = \"{}\"\n",
        toolchain.accepted().cargo_sha256,
        toolchain.accepted().rust_lld_sha256,
        toolchain.accepted().manifest_sha256,
        toolchain.accepted().toolchain_tree_sha256,
        sha256::file_digest(&repository.join("Cargo.lock"))
            .map_err(|error| Failure::task(format!("could not hash Cargo.lock: {error}")))?,
        sha256::bytes_digest(&loader),
    );
    for ((label, command), bytes) in commands.iter().zip([
        &bootstrap,
        &init27,
        &registryd,
        &devmgr,
        &uart16550d,
        &consoled,
        &wyrmsh,
        &hello,
        &publisher,
        &client,
        &init25,
        &registryd25,
        &registryd25_fail,
    ]) {
        source_receipt.push_str(&format!(
            "{label}_command = \"{command}\"\n{label}_sha256 = \"{}\"\n",
            sha256::bytes_digest(bytes),
        ));
    }
    Ok(FrozenArtifacts {
        loader,
        bootstrap,
        init27,
        registryd,
        devmgr,
        uart16550d,
        consoled,
        wyrmsh,
        hello,
        publisher,
        client,
        init25,
        registryd25,
        registryd25_fail,
        source_receipt,
    })
}

fn build_native(
    repository: &Path,
    cargo_home: &Path,
    toolchain: &crate::toolchain_artifact::AcceptedToolchain,
    build_root: &Path,
    spec: &NativeSpec<'_>,
) -> Result<(Vec<u8>, String), Failure> {
    let target = build_root.join(spec.label);
    fs::create_dir(&target)
        .map_err(|error| Failure::task(format!("could not create native target: {error}")))?;
    let flags = native_remap_flags(repository, cargo_home, &target)?;
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
        "--features",
        spec.features,
    ];
    let status = Command::new(&toolchain.cargo)
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
        .stdin(Stdio::null())
        .status()
        .map_err(|error| Failure::task(format!("could not build {}: {error}", spec.label)))?;
    if !status.success() {
        return Err(Failure::task(format!(
            "WYR1-B canonical {} build failed",
            spec.label
        )));
    }
    let artifact = target
        .join(NATIVE_TARGET)
        .join("release")
        .join(spec.artifact);
    let bytes = read_bounded(&artifact, spec.label, 64 * 1024 * 1024)?;
    Ok((bytes, format!("cargo {}", arguments.join(" "))))
}

fn native_remap_flags(
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

fn build_kernel(
    repository: &Path,
    build_root: &Path,
    label: &str,
    selector: &str,
    environment: &[(&str, String)],
) -> Result<Vec<u8>, Failure> {
    let proposed = build_root.join(format!("deepwyrm-{label}"));
    let target = if proposed.starts_with("/tmp") {
        proposed
    } else {
        repository
            .join(".tmp/wyr1b-freeze")
            .join(std::process::id().to_string())
            .join(label)
    };
    fs::create_dir_all(&target)
        .map_err(|error| Failure::task(format!("could not create kernel target: {error}")))?;
    let mut command = Command::new(repository.join("tools/pinned-cargo"));
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
            "--features",
            "test-support",
        ])
        .env("DEEPWYRM_PINNED_TARGET_DIR", &target)
        .env("DEEPWYRM_GUEST_TEST_SELECTOR", selector)
        .env_remove("LD_AUDIT")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD")
        .current_dir(repository)
        .stdin(Stdio::null());
    for (key, value) in environment {
        command.env(key, value);
    }
    let status = command
        .status()
        .map_err(|error| Failure::task(format!("could not build {label} kernel: {error}")))?;
    if !status.success() {
        return Err(Failure::task(format!(
            "WYR1-B canonical {label} Deepwyrm build failed"
        )));
    }
    read_bounded(
        &target.join(KERNEL_TARGET).join("release/deepwyrm-kernel"),
        label,
        64 * 1024 * 1024,
    )
}

fn read_pinned_firmware(path: &str, expected: &str, label: &str) -> Result<Vec<u8>, Failure> {
    let bytes = fs::read(path)
        .map_err(|error| Failure::task(format!("could not read pinned {label}: {error}")))?;
    if sha256::bytes_digest(&bytes) != expected {
        return Err(Failure::task(format!("pinned {label} identity mismatch")));
    }
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
fn render_request(
    deepwyrm_revision: &str,
    wyrmroot_revision: &str,
    generation: &str,
    nonce: u64,
    bootfs_pages: usize,
    artifacts: &FrozenArtifacts,
    kernel: &[u8],
    kernel_provenance: &[u8],
    ovmf_code: &[u8],
    ovmf_vars: &[u8],
) -> String {
    let entries: [(&str, &str, &[u8]); 17] = [
        ("loader", "artifacts/loader.efi", &artifacts.loader),
        ("kernel", "artifacts/deepwyrm.elf", kernel),
        ("symbols", "artifacts/deepwyrm.symbols.elf", kernel),
        ("bootstrap", "artifacts/bootstrap.elf", &artifacts.bootstrap),
        ("init", "artifacts/system-init.elf", &artifacts.init27),
        ("registryd", "artifacts/registryd.elf", &artifacts.registryd),
        ("devmgr", "artifacts/devmgr.elf", &artifacts.devmgr),
        (
            "uart16550d",
            "artifacts/uart16550d.elf",
            &artifacts.uart16550d,
        ),
        ("consoled", "artifacts/consoled.elf", &artifacts.consoled),
        ("wyrmsh", "artifacts/wyrmsh.elf", &artifacts.wyrmsh),
        ("hello", "artifacts/hello.elf", &artifacts.hello),
        (
            "publisher",
            "artifacts/wyr1-b-publisher.elf",
            &artifacts.publisher,
        ),
        ("client", "artifacts/wyr1-b-client.elf", &artifacts.client),
        (
            "source_receipt",
            "artifacts/wyr-source-build.toml",
            artifacts.source_receipt.as_bytes(),
        ),
        (
            "kernel_provenance",
            "artifacts/kernel-provenance.toml",
            kernel_provenance,
        ),
        ("ovmf_code", "artifacts/OVMF_CODE.fd", ovmf_code),
        ("ovmf_vars", "artifacts/OVMF_VARS.fd", ovmf_vars),
    ];
    let mut text = format!(
        "kind = \"{REQUEST_KIND}\"\nschema_version = {SCHEMA}\nselector = \"{SELECTOR}\"\ntest_id = {TEST_ID}\ntimeout_seconds = 60\ndeepwyrm_revision = \"{deepwyrm_revision}\"\nwyrmroot_revision = \"{wyrmroot_revision}\"\nrust_revision = \"{ACCEPTED_RUST_REVISION}\"\nboot_generation = \"{generation}\"\n"
    );
    for (key, path, bytes) in entries {
        text.push_str(&format!(
            "{key} = \"{path}\"\n{key}_sha256 = \"{}\"\n",
            sha256::bytes_digest(bytes),
        ));
    }
    text.push_str(&format!(
        "rrc_manifest = \"product/rrc-a-v1.bin\"\nbootfs = \"product/bootfs.img\"\nbootfs_pages = {bootfs_pages}\nesp = \"product/esp.img\"\nreceipt = \"product/build-receipt.toml\"\nrun_directory = \"run\"\nserial_log = \"run/serial.log\"\nrun_receipt = \"run/run-receipt.toml\"\nevidence_nonce = \"{nonce:016X}\"\n"
    ));
    text
}

#[allow(clippy::too_many_arguments)]
fn freeze_selector25_regressions(
    output: &Path,
    build_root: &Path,
    deepwyrm: &Path,
    deepwyrm_revision: &str,
    wyrmroot_revision: &str,
    artifacts: &FrozenArtifacts,
    ovmf_code: &[u8],
    ovmf_vars: &[u8],
) -> Result<(), Failure> {
    for (scenario, registry, nonce) in [
        (
            "normal",
            artifacts.registryd25.as_slice(),
            0xA025_0000_0000_0001u64,
        ),
        (
            "degraded_recovery",
            artifacts.registryd25_fail.as_slice(),
            0xA025_0000_0000_0002u64,
        ),
    ] {
        let kernel = build_kernel(
            deepwyrm,
            build_root,
            &format!("selector25-{scenario}"),
            crate::wyr1::SELECTOR,
            &[
                ("DEEPWYRM_WYR1_EVIDENCE_NONCE", format!("{nonce:016X}")),
                ("DEEPWYRM_WYR1_EVIDENCE_SCENARIO", scenario.to_owned()),
            ],
        )?;
        let root = output.join("selector25").join(scenario);
        let input = root.join("artifacts");
        fs::create_dir_all(&input).map_err(|error| {
            Failure::task(format!("could not create selector-25 artifacts: {error}"))
        })?;
        let provenance = format!(
            "kind = \"wyrmroot-wyr1-a-regression-kernel-build\"\nschema_version = 1\nselector = \"{}\"\ntest_id = {}\nscenario = \"{scenario}\"\ndeepwyrm_revision = \"{deepwyrm_revision}\"\nwyrmroot_revision = \"{wyrmroot_revision}\"\nrust_revision = \"{ACCEPTED_RUST_REVISION}\"\nDEEPWYRM_WYR1_EVIDENCE_NONCE = \"{nonce:016X}\"\nDEEPWYRM_WYR1_EVIDENCE_SCENARIO = \"{scenario}\"\nkernel_sha256 = \"{}\"\n",
            crate::wyr1::SELECTOR,
            crate::wyr1::TEST_ID,
            sha256::bytes_digest(&kernel),
        );
        for (name, bytes) in [
            ("loader.efi", artifacts.loader.as_slice()),
            ("deepwyrm.elf", kernel.as_slice()),
            ("deepwyrm.symbols.elf", kernel.as_slice()),
            ("bootstrap.elf", artifacts.bootstrap.as_slice()),
            ("system-init.elf", artifacts.init25.as_slice()),
            ("registryd.elf", registry),
            ("devmgr.elf", artifacts.devmgr.as_slice()),
            ("uart16550d.elf", artifacts.uart16550d.as_slice()),
            ("consoled.elf", artifacts.consoled.as_slice()),
            ("wyrmsh.elf", artifacts.wyrmsh.as_slice()),
            ("provenance.toml", provenance.as_bytes()),
            ("OVMF_CODE.fd", ovmf_code),
            ("OVMF_VARS.fd", ovmf_vars),
        ] {
            write_new_file(&input.join(name), bytes)?;
        }
        let request_text = format!(
            "schema_version = \"5\"\ndeepwyrm_revision = \"{deepwyrm_revision}\"\nwyrmroot_revision = \"{wyrmroot_revision}\"\nrust_revision = \"{ACCEPTED_RUST_REVISION}\"\nselector = \"{}\"\ntest_id = \"{}\"\nscenario = \"{scenario}\"\ntimeout_seconds = \"120\"\nloader = \"artifacts/loader.efi\"\nkernel = \"artifacts/deepwyrm.elf\"\nsymbols = \"artifacts/deepwyrm.symbols.elf\"\nbootstrap = \"artifacts/bootstrap.elf\"\ninit = \"artifacts/system-init.elf\"\nregistryd = \"artifacts/registryd.elf\"\ndevmgr = \"artifacts/devmgr.elf\"\nuart16550d = \"artifacts/uart16550d.elf\"\nconsoled = \"artifacts/consoled.elf\"\nwyrmsh = \"artifacts/wyrmsh.elf\"\nrrc_manifest = \"product/rrc-a-v1.bin\"\nbootfs = \"product/bootfs.img\"\nesp = \"product/esp.img\"\nprovenance = \"artifacts/provenance.toml\"\novmf_code = \"artifacts/OVMF_CODE.fd\"\novmf_vars_template = \"artifacts/OVMF_VARS.fd\"\nrun_directory = \"run\"\nevidence_nonce = \"{nonce:016X}\"\nreceipt = \"product/build-receipt.toml\"\n",
            crate::wyr1::SELECTOR,
            crate::wyr1::TEST_ID,
        );
        let request_path = root.join("request.toml");
        write_new_file(&request_path, request_text.as_bytes())?;
        let request = crate::wyr1::load(&request_path)?;
        fs::create_dir(root.join("product")).map_err(|error| {
            Failure::task(format!(
                "could not create selector-25 product root: {error}"
            ))
        })?;
        let identities = crate::wyr1::build_bootfs(&request)?;
        let image = crate::cli::G3ImageArguments {
            image: request.esp.display().to_string(),
            loader: request.loader.display().to_string(),
            kernel: request.kernel.display().to_string(),
            bootstrap: request.bootstrap.display().to_string(),
            bootfs: request.bootfs.display().to_string(),
        };
        let _ = crate::g3_image::build(&image)?;
        crate::g3_image::inspect(&image)?;
        let esp_sha256 = sha256::file_digest(&request.esp)
            .map_err(|error| Failure::task(format!("could not hash selector-25 ESP: {error}")))?;
        let receipt = crate::wyr1::receipt_text(
            &request,
            &identities,
            &esp_sha256,
            crate::wyr1::Profile::Default,
        )?;
        crate::wyr1::write_receipt(&request, &receipt)?;
        let _ = crate::wyr1::verify_receipt(&request, crate::wyr1::Profile::Default)?;
    }
    Ok(())
}

pub fn load(path: &Path) -> Result<Request, Failure> {
    let bytes = fs::read(path)
        .map_err(|error| Failure::task(format!("could not read WYR1-B request: {error}")))?;
    if bytes.is_empty() || bytes.len() > MAX_REQUEST {
        return Err(Failure::task("WYR1-B request is empty or oversized"));
    }
    let values = parse_scalars(
        std::str::from_utf8(&bytes).map_err(|_| Failure::task("WYR1-B request is not UTF-8"))?,
    )?;
    let expected = KEYS.iter().copied().collect::<BTreeSet<_>>();
    let actual = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if expected != actual {
        return Err(Failure::task("WYR1-B request key set drifted"));
    }
    if required(&values, "kind")? != REQUEST_KIND
        || number::<u32>(&values, "schema_version")? != SCHEMA
        || required(&values, "selector")? != SELECTOR
        || number::<u32>(&values, "test_id")? != TEST_ID
    {
        return Err(Failure::task(
            "WYR1-B request must name schema 6 selector 27",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| Failure::task("WYR1-B request has no parent"))?;
    let parent = fs::canonicalize(parent).map_err(|error| {
        Failure::task(format!("could not resolve WYR1-B request root: {error}"))
    })?;
    let canonical_request = fs::canonicalize(path)
        .map_err(|error| Failure::task(format!("could not resolve WYR1-B request: {error}")))?;
    if canonical_request.parent() != Some(parent.as_path()) {
        return Err(Failure::task(
            "WYR1-B request must be a direct child of its canonical root",
        ));
    }
    let request = Request {
        root: parent.clone(),
        path: canonical_request,
        request_sha256: sha256::bytes_digest(&bytes),
        timeout_seconds: bounded_number(&values, "timeout_seconds", 1, 120)?,
        deepwyrm_revision: revision(&values, "deepwyrm_revision")?,
        wyrmroot_revision: revision(&values, "wyrmroot_revision")?,
        rust_revision: revision(&values, "rust_revision")?,
        boot_generation: decode_digest(required(&values, "boot_generation")?)?,
        loader: input(&parent, required(&values, "loader")?)?,
        loader_sha256: digest(&values, "loader_sha256")?,
        kernel: input(&parent, required(&values, "kernel")?)?,
        kernel_sha256: digest(&values, "kernel_sha256")?,
        symbols: input(&parent, required(&values, "symbols")?)?,
        symbols_sha256: digest(&values, "symbols_sha256")?,
        bootstrap: input(&parent, required(&values, "bootstrap")?)?,
        bootstrap_sha256: digest(&values, "bootstrap_sha256")?,
        init: input(&parent, required(&values, "init")?)?,
        init_sha256: digest(&values, "init_sha256")?,
        registryd: input(&parent, required(&values, "registryd")?)?,
        registryd_sha256: digest(&values, "registryd_sha256")?,
        devmgr: input(&parent, required(&values, "devmgr")?)?,
        devmgr_sha256: digest(&values, "devmgr_sha256")?,
        uart16550d: input(&parent, required(&values, "uart16550d")?)?,
        uart16550d_sha256: digest(&values, "uart16550d_sha256")?,
        consoled: input(&parent, required(&values, "consoled")?)?,
        consoled_sha256: digest(&values, "consoled_sha256")?,
        wyrmsh: input(&parent, required(&values, "wyrmsh")?)?,
        wyrmsh_sha256: digest(&values, "wyrmsh_sha256")?,
        rrc_manifest: output(&parent, required(&values, "rrc_manifest")?)?,
        hello: input(&parent, required(&values, "hello")?)?,
        hello_sha256: digest(&values, "hello_sha256")?,
        publisher: input(&parent, required(&values, "publisher")?)?,
        publisher_sha256: digest(&values, "publisher_sha256")?,
        client: input(&parent, required(&values, "client")?)?,
        client_sha256: digest(&values, "client_sha256")?,
        source_receipt: input(&parent, required(&values, "source_receipt")?)?,
        source_receipt_sha256: digest(&values, "source_receipt_sha256")?,
        kernel_provenance: input(&parent, required(&values, "kernel_provenance")?)?,
        kernel_provenance_sha256: digest(&values, "kernel_provenance_sha256")?,
        ovmf_code: input(&parent, required(&values, "ovmf_code")?)?,
        ovmf_code_sha256: digest(&values, "ovmf_code_sha256")?,
        ovmf_vars: input(&parent, required(&values, "ovmf_vars")?)?,
        ovmf_vars_sha256: digest(&values, "ovmf_vars_sha256")?,
        bootfs: output(&parent, required(&values, "bootfs")?)?,
        bootfs_pages: bounded_number(&values, "bootfs_pages", 1, 8192)?,
        esp: output(&parent, required(&values, "esp")?)?,
        receipt: output(&parent, required(&values, "receipt")?)?,
        run_directory: output(&parent, required(&values, "run_directory")?)?,
        serial_log: output(&parent, required(&values, "serial_log")?)?,
        run_receipt: output(&parent, required(&values, "run_receipt")?)?,
        evidence_nonce: nonce(required(&values, "evidence_nonce")?)?,
    };
    reject_aliases(&request)?;
    if request.rust_revision != ACCEPTED_RUST_REVISION {
        return Err(Failure::task(
            "WYR1-B request does not name the accepted Rust revision",
        ));
    }
    Ok(request)
}

pub fn build(path: &Path) -> Result<String, Failure> {
    let request = load(path)?;
    verify_acceptance_source(&request)?;
    refuse_product_outputs(&request)?;
    let loader = read_expected(&request.loader, "loader", &request.loader_sha256)?;
    let kernel = read_expected(&request.kernel, "kernel", &request.kernel_sha256)?;
    let symbols = read_expected(&request.symbols, "symbols", &request.symbols_sha256)?;
    let bootstrap = read_expected(&request.bootstrap, "bootstrap", &request.bootstrap_sha256)?;
    let init = read_expected(&request.init, "init", &request.init_sha256)?;
    let registryd = read_expected(&request.registryd, "registryd", &request.registryd_sha256)?;
    let devmgr = read_expected(&request.devmgr, "devmgr", &request.devmgr_sha256)?;
    let uart = read_expected(
        &request.uart16550d,
        "uart16550d",
        &request.uart16550d_sha256,
    )?;
    let console = read_expected(&request.consoled, "consoled", &request.consoled_sha256)?;
    let shell = read_expected(&request.wyrmsh, "wyrmsh", &request.wyrmsh_sha256)?;
    let hello = read_expected(&request.hello, "hello", &request.hello_sha256)?;
    let publisher = read_expected(&request.publisher, "publisher", &request.publisher_sha256)?;
    let client = read_expected(&request.client, "client", &request.client_sha256)?;
    let source_receipt = read_expected(
        &request.source_receipt,
        "source receipt",
        &request.source_receipt_sha256,
    )?;
    let kernel_provenance = read_expected(
        &request.kernel_provenance,
        "kernel provenance",
        &request.kernel_provenance_sha256,
    )?;
    let ovmf_code = read_expected(&request.ovmf_code, "OVMF code", &request.ovmf_code_sha256)?;
    let ovmf_vars = read_expected(&request.ovmf_vars, "OVMF vars", &request.ovmf_vars_sha256)?;
    verify_source_receipt(&request, &source_receipt)?;
    verify_kernel_provenance(&request, &kernel_provenance)?;
    let role_hashes = [
        sha256::bytes_digest_array(&registryd),
        sha256::bytes_digest_array(&devmgr),
        sha256::bytes_digest_array(&uart),
        sha256::bytes_digest_array(&console),
        sha256::bytes_digest_array(&shell),
    ];
    let manifest = fixed_builder_for_profile(
        &request.boot_generation,
        role_hashes,
        StartupProfile::BootstrapRegistry,
    )?
    .build_structural()
    .map_err(|error| Failure::task(format!("WYR1-B manifest build failed: {error:?}")))?;
    write_new_file(&request.rrc_manifest, &manifest)?;
    let policy_entry = LaunchPolicyEntry {
        path: "bin/hello",
        content_sha256: sha256::bytes_digest_array(&hello),
        startup_abi: 2,
        profile_id: 1,
        allow_no_streams: true,
        allow_three_streams: true,
    };
    let mut policy_bytes = [0u8; 512];
    let policy_size = encode_policy(request.boot_generation, &[policy_entry], &mut policy_bytes)
        .map_err(|error| Failure::task(format!("WYR1-B launch policy failed: {error:?}")))?;
    let policy = &policy_bytes[..policy_size];
    let a_gate = format!(
        "schema = 1\nselector = \"permanent-supervisor-rrc\"\ntest_id = 25\nscenario = \"normal\"\nevidence_protocol = \"wyr1evid1\"\nnonce = \"{:016X}\"\n",
        request.evidence_nonce
    );
    let b_gate = format!(
        "schema = 6\nselector = \"bootstrap-registry-launch\"\ntest_id = 27\nevidence_protocol = \"wrb1\"\nnonce = \"{:016X}\"\n",
        request.evidence_nonce
    );
    let expected = build_b(ProductB {
        base: Product {
            init: &init,
            registryd: &registryd,
            devmgr: &devmgr,
            uart16550d: &uart,
            consoled: &console,
            wyrmsh: &shell,
            rrc_manifest: &manifest,
            gate_config: a_gate.as_bytes(),
        },
        launch_policy: policy,
        gate_config: b_gate.as_bytes(),
        hello: &hello,
        publisher: &publisher,
        client: &client,
    })
    .map_err(|error| Failure::task(format!("WYR1-B bootfs build failed: {error:?}")))?;
    let pages = expected.len().div_ceil(4096);
    if pages != request.bootfs_pages {
        return Err(Failure::task(format!(
            "WYR1-B measured bootfs pages {pages} do not match request {}",
            request.bootfs_pages
        )));
    }
    write_new_file(&request.bootfs, &expected)?;
    let observed = fs::read(&request.bootfs)
        .map_err(|error| Failure::task(format!("could not reread WYR1-B bootfs: {error}")))?;
    verify_archive(
        &observed,
        &request.boot_generation,
        &hello,
        &publisher,
        &client,
        policy,
        b_gate.as_bytes(),
    )?;
    if expected != observed {
        return Err(Failure::task("WYR1-B independent bootfs reread mismatch"));
    }
    let image_args = crate::cli::G3ImageArguments {
        image: request.esp.display().to_string(),
        loader: request.loader.display().to_string(),
        kernel: request.kernel.display().to_string(),
        bootstrap: request.bootstrap.display().to_string(),
        bootfs: request.bootfs.display().to_string(),
    };
    let _ = crate::g3_image::build(&image_args)?;
    crate::g3_image::inspect(&image_args)?;
    let esp = read(&request.esp, "ESP")?;
    let receipt = receipt(ReceiptInput {
        request: &request,
        bootfs: &observed,
        manifest: &manifest,
        policy,
        gate: b_gate.as_bytes(),
        hello: &hello,
        publisher: &publisher,
        client: &client,
        platform: [
            &loader,
            &kernel,
            &symbols,
            &bootstrap,
            &source_receipt,
            &kernel_provenance,
            &ovmf_code,
            &ovmf_vars,
            &esp,
        ],
    });
    write_new_file(&request.receipt, receipt.as_bytes())?;
    Ok(format!(
        "WYR1_B_IMAGE_PASS selector={} test_id={} bootfs_pages={} bootfs_sha256={} esp_sha256={}\n",
        SELECTOR,
        TEST_ID,
        pages,
        sha256::bytes_digest(&observed),
        sha256::bytes_digest(&esp),
    ))
}

pub fn inspect(path: &Path) -> Result<String, Failure> {
    let request = load(path)?;
    verify_acceptance_source(&request)?;
    inspect_loaded(&request)
}

fn inspect_recorded(path: &Path) -> Result<String, Failure> {
    let request = load(path)?;
    inspect_loaded(&request)
}

fn inspect_loaded(request: &Request) -> Result<String, Failure> {
    let source_receipt = read_expected(
        &request.source_receipt,
        "source receipt",
        &request.source_receipt_sha256,
    )?;
    let provenance = read_expected(
        &request.kernel_provenance,
        "kernel provenance",
        &request.kernel_provenance_sha256,
    )?;
    verify_source_receipt(request, &source_receipt)?;
    verify_kernel_provenance(request, &provenance)?;
    let _ = read_expected(&request.ovmf_code, "OVMF code", &request.ovmf_code_sha256)?;
    let _ = read_expected(&request.ovmf_vars, "OVMF vars", &request.ovmf_vars_sha256)?;
    let bootfs = read_expected(
        &request.bootfs,
        "bootfs",
        &receipt_value(request, "bootfs_sha256")?,
    )?;
    if bootfs.len().div_ceil(4096) != request.bootfs_pages {
        return Err(Failure::task("WYR1-B inspected bootfs page count drifted"));
    }
    let archive = Archive::new(&bootfs)
        .map_err(|error| Failure::task(format!("WYR1-B archive invalid: {error:?}")))?;
    verify_manifest_profile(&archive, &request.boot_generation)?;
    for (path, source, expected, executable) in [
        ("system/init", &request.init, &request.init_sha256, true),
        (
            "system/registryd",
            &request.registryd,
            &request.registryd_sha256,
            true,
        ),
        (
            "system/devmgr",
            &request.devmgr,
            &request.devmgr_sha256,
            true,
        ),
        (
            "system/uart16550d",
            &request.uart16550d,
            &request.uart16550d_sha256,
            true,
        ),
        (
            "system/consoled",
            &request.consoled,
            &request.consoled_sha256,
            true,
        ),
        (
            "system/wyrmsh",
            &request.wyrmsh,
            &request.wyrmsh_sha256,
            true,
        ),
        ("bin/hello", &request.hello, &request.hello_sha256, true),
        (
            "test/wyr1-b/publisher",
            &request.publisher,
            &request.publisher_sha256,
            true,
        ),
        (
            "test/wyr1-b/client",
            &request.client,
            &request.client_sha256,
            true,
        ),
    ] {
        let expected_bytes = read_expected(source, path, expected)?;
        let entry = archive
            .lookup(path.as_bytes())
            .map_err(|error| Failure::task(format!("WYR1-B missing {path}: {error:?}")))?;
        if entry.data() != expected_bytes || entry.is_executable() != executable {
            return Err(Failure::task(format!(
                "WYR1-B artifact substitution at {path}"
            )));
        }
    }
    if archive.entries().count() != 13 {
        return Err(Failure::task(
            "WYR1-B archive must contain exactly 13 entries",
        ));
    }
    let policy = archive
        .lookup(b"system/bootstrap/launch-policy-v1")
        .map_err(|error| Failure::task(format!("WYR1-B policy missing: {error:?}")))?;
    LaunchPolicy::parse(policy.data())
        .map_err(|error| Failure::task(format!("WYR1-B policy invalid: {error:?}")))?;
    let args = crate::cli::G3ImageArguments {
        image: request.esp.display().to_string(),
        loader: request.loader.display().to_string(),
        kernel: request.kernel.display().to_string(),
        bootstrap: request.bootstrap.display().to_string(),
        bootfs: request.bootfs.display().to_string(),
    };
    crate::g3_image::inspect(&args)?;
    verify_build_receipt(request, &bootfs)?;
    Ok(format!(
        "WYR1_B_INSPECTION_PASS entries=13 bootfs_pages={} bootfs_sha256={} esp_sha256={}\n",
        request.bootfs_pages,
        sha256::bytes_digest(&bootfs),
        sha256::file_digest(&request.esp)
            .map_err(|error| Failure::task(format!("could not hash WYR1-B ESP: {error}")))?,
    ))
}

pub fn run(path: &Path) -> Result<String, Failure> {
    let _ = inspect(path)?;
    let request = load(path)?;
    if request.serial_log.parent() != Some(request.run_directory.as_path())
        || request.run_receipt.parent() != Some(request.run_directory.as_path())
    {
        return Err(Failure::task(
            "WYR1-B serial and run receipt must be direct run-directory children",
        ));
    }
    if fs::symlink_metadata(&request.run_directory).is_ok() {
        return Err(Failure::task("WYR1-B run directory is one-shot"));
    }
    fs::create_dir(&request.run_directory).map_err(|error| {
        Failure::task(format!("could not create WYR1-B run directory: {error}"))
    })?;
    let snapshot_request = request.run_directory.join("request.toml");
    let snapshot_esp = request.run_directory.join("booted-esp.img");
    let snapshot_code = request.run_directory.join("OVMF_CODE.fd");
    let snapshot_vars = request.run_directory.join("OVMF_VARS.fd");
    let snapshot_bootfs = request.run_directory.join("bootfs.img");
    let snapshot_receipt = request.run_directory.join("build-receipt.toml");
    let stderr_log = request.run_directory.join("qemu.stderr.log");
    let esp_sha256 = receipt_value(&request, "esp_sha256")?;
    let bootfs_sha256 = receipt_value(&request, "bootfs_sha256")?;
    for (source, destination, expected, label) in [
        (
            request.path.as_path(),
            snapshot_request.as_path(),
            Some(request.request_sha256.as_str()),
            "request",
        ),
        (
            request.esp.as_path(),
            snapshot_esp.as_path(),
            Some(esp_sha256.as_str()),
            "ESP",
        ),
        (
            request.ovmf_code.as_path(),
            snapshot_code.as_path(),
            Some(request.ovmf_code_sha256.as_str()),
            "OVMF code",
        ),
        (
            request.ovmf_vars.as_path(),
            snapshot_vars.as_path(),
            Some(request.ovmf_vars_sha256.as_str()),
            "OVMF vars",
        ),
        (
            request.bootfs.as_path(),
            snapshot_bootfs.as_path(),
            Some(bootfs_sha256.as_str()),
            "bootfs",
        ),
        (
            request.receipt.as_path(),
            snapshot_receipt.as_path(),
            None,
            "build receipt",
        ),
    ] {
        snapshot(source, destination, expected, label)?;
    }
    let outcome = crate::h_integration::run_canonical_one_cpu_selector(
        &crate::h_integration::CanonicalSelectorRun {
            ovmf_code: &snapshot_code,
            ovmf_vars: &snapshot_vars,
            esp: &snapshot_esp,
            serial_log: &request.serial_log,
            stderr_log: &stderr_log,
            selector: SELECTOR,
            timeout_seconds: request.timeout_seconds,
        },
    )?;
    let serial = read_bounded(&request.serial_log, "serial log", MAX_EVIDENCE)?;
    if sha256::file_digest(&snapshot_code)
        .map_err(|error| Failure::task(format!("could not rehash OVMF code: {error}")))?
        != request.ovmf_code_sha256
        || sha256::file_digest(&snapshot_esp)
            .map_err(|error| Failure::task(format!("could not rehash booted ESP: {error}")))?
            != receipt_value(&request, "esp_sha256")?
    {
        return Err(Failure::task(
            "WYR1-B read-only firmware code or ESP changed during run",
        ));
    }
    let _ = inspect_recorded(path)?;
    let receipt = format!(
        "kind = \"{RUN_RECEIPT_KIND}\"\nschema_version = 1\nselector = \"{SELECTOR}\"\ntest_id = {TEST_ID}\nrequest_sha256 = \"{}\"\nbuild_receipt_sha256 = \"{}\"\nesp_sha256 = \"{}\"\nbootfs_sha256 = \"{}\"\nserial_log_sha256 = \"{}\"\novmf_code_sha256 = \"{}\"\novmf_vars_sha256 = \"{}\"\ntimeout_seconds = {}\nqemu_exit_status = {}\ntimed_out = {}\n",
        request.request_sha256,
        sha256::file_digest(&request.receipt)
            .map_err(|error| Failure::task(format!("could not hash build receipt: {error}")))?,
        sha256::file_digest(&snapshot_esp)
            .map_err(|error| Failure::task(format!("could not hash booted ESP: {error}")))?,
        sha256::file_digest(&snapshot_bootfs)
            .map_err(|error| Failure::task(format!("could not hash run bootfs: {error}")))?,
        sha256::bytes_digest(&serial),
        request.ovmf_code_sha256,
        request.ovmf_vars_sha256,
        request.timeout_seconds,
        outcome.qemu_exit_status.unwrap_or(-1),
        outcome.timed_out,
    );
    write_new_file(&request.run_receipt, receipt.as_bytes())?;
    if outcome.timed_out {
        return Err(Failure::task(format!(
            "WYR1-B canonical QEMU timed out after {} seconds",
            request.timeout_seconds
        )));
    }
    if outcome.qemu_exit_status != Some(33) {
        return Err(Failure::task(format!(
            "WYR1-B canonical QEMU did not produce debug-exit status 33: {:?}",
            outcome.qemu_exit_status
        )));
    }
    parse_evidence(request.evidence_nonce, &verify_run_receipt(&request)?)
}

fn verify_run_receipt(request: &Request) -> Result<Vec<u8>, Failure> {
    let serial = read_bounded(&request.serial_log, "serial log", MAX_EVIDENCE)?;
    let values = parse_scalars(
        std::str::from_utf8(&read_bounded(
            &request.run_receipt,
            "run receipt",
            MAX_REQUEST,
        )?)
        .map_err(|_| Failure::task("WYR1-B run receipt is not UTF-8"))?,
    )?;
    exact_keys(&values, RUN_RECEIPT_KEYS, "WYR1-B run receipt")?;
    for (key, expected) in [
        ("kind", RUN_RECEIPT_KIND.to_owned()),
        ("schema_version", "1".to_owned()),
        ("selector", SELECTOR.to_owned()),
        ("test_id", TEST_ID.to_string()),
        ("request_sha256", request.request_sha256.clone()),
        (
            "build_receipt_sha256",
            sha256::file_digest(&request.receipt)
                .map_err(|error| Failure::task(format!("could not hash build receipt: {error}")))?,
        ),
        ("esp_sha256", receipt_value(request, "esp_sha256")?),
        ("bootfs_sha256", receipt_value(request, "bootfs_sha256")?),
        ("serial_log_sha256", sha256::bytes_digest(&serial)),
        ("ovmf_code_sha256", request.ovmf_code_sha256.clone()),
        ("ovmf_vars_sha256", request.ovmf_vars_sha256.clone()),
        ("timeout_seconds", request.timeout_seconds.to_string()),
        ("qemu_exit_status", "33".to_owned()),
        ("timed_out", "false".to_owned()),
    ] {
        if required(&values, key)? != expected {
            return Err(Failure::task(format!(
                "WYR1-B run receipt field {key} mismatch"
            )));
        }
    }
    Ok(serial)
}

fn snapshot(
    source: &Path,
    destination: &Path,
    expected: Option<&str>,
    label: &str,
) -> Result<(), Failure> {
    let maximum = usize::try_from(crate::g3_image::IMAGE_BYTES)
        .map_err(|_| Failure::task("WYR1-B image size exceeds host usize"))?;
    let bytes = read_bounded(source, label, maximum)?;
    if expected.is_some_and(|digest| digest != sha256::bytes_digest(&bytes)) {
        return Err(Failure::task(format!(
            "WYR1-B {label} changed before snapshot"
        )));
    }
    write_new_file(destination, &bytes)
}

pub fn evidence(path: &Path) -> Result<String, Failure> {
    let _ = inspect(path)?;
    let request = load(path)?;
    let bytes = verify_run_receipt(&request)?;
    parse_evidence(request.evidence_nonce, &bytes)
}

fn parse_evidence(evidence_nonce: u64, bytes: &[u8]) -> Result<String, Failure> {
    if bytes.is_empty() || bytes.len() > MAX_EVIDENCE {
        return Err(Failure::task("WYR1-B serial evidence length is invalid"));
    }
    let expected_events = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0xff];
    let mut records = Vec::new();
    let mut cursor = 0;
    while cursor + 4 <= bytes.len() {
        if &bytes[cursor..cursor + 4] == b"WRB1" {
            let end = cursor
                .checked_add(96)
                .ok_or_else(|| Failure::task("WRB1 record range overflow"))?;
            let record = bytes
                .get(cursor..end)
                .ok_or_else(|| Failure::task("truncated WRB1 record"))?;
            records.push((cursor, record));
            cursor = end;
        } else {
            cursor += 1;
        }
    }
    if records.len() != expected_events.len() {
        return Err(Failure::task("WRB1 evidence event count is invalid"));
    }
    for (sequence, ((_, record), expected)) in records.iter().zip(expected_events).enumerate() {
        verify_record(record, evidence_nonce, sequence as u32, expected)?;
    }
    let terminal = canonical_terminal(TEST_ID);
    let terminal_offsets = find_all(bytes, &terminal);
    if terminal_offsets.len() != 1 || terminal_offsets[0] < records.last().unwrap().0 + 96 {
        return Err(Failure::task(
            "WYR1-B requires one canonical selector-27 terminal after WRB1",
        ));
    }
    Ok(format!(
        "WYR1_B_EVIDENCE_PASS records={} test_id=27 detail=0 terminal=normal\n",
        expected_events.len()
    ))
}

fn verify_archive(
    bootfs: &[u8],
    boot_generation: &[u8; 32],
    hello: &[u8],
    publisher: &[u8],
    client: &[u8],
    policy: &[u8],
    gate: &[u8],
) -> Result<(), Failure> {
    let archive = Archive::new(bootfs)
        .map_err(|error| Failure::task(format!("WYR1-B archive invalid: {error:?}")))?;
    verify_manifest_profile(&archive, boot_generation)?;
    for (path, bytes, executable) in [
        ("bin/hello", hello, true),
        ("test/wyr1-b/publisher", publisher, true),
        ("test/wyr1-b/client", client, true),
        ("system/bootstrap/launch-policy-v1", policy, false),
        ("system/bootstrap/wyr1-b-gate-v1", gate, false),
    ] {
        let entry = archive
            .lookup(path.as_bytes())
            .map_err(|error| Failure::task(format!("WYR1-B missing {path}: {error:?}")))?;
        if entry.data() != bytes || entry.is_executable() != executable {
            return Err(Failure::task(format!("WYR1-B substitution at {path}")));
        }
    }
    if archive.entries().count() != 13 {
        return Err(Failure::task("WYR1-B archive contains undeclared entries"));
    }
    Ok(())
}

fn verify_manifest_profile(
    archive: &Archive<'_>,
    boot_generation: &[u8; 32],
) -> Result<(), Failure> {
    let entry = archive
        .lookup(wyrmroot_rrc_manifest::MANIFEST_PATH.as_bytes())
        .map_err(|error| Failure::task(format!("WYR1-B manifest missing: {error:?}")))?;
    let manifest = Manifest::parse_structural(entry.data(), boot_generation)
        .map_err(|error| Failure::task(format!("WYR1-B manifest invalid: {error:?}")))?;
    let registry = manifest
        .role(RoleId::Registryd)
        .ok_or_else(|| Failure::task("WYR1-B registry role missing"))?;
    let devmgr = manifest
        .role(RoleId::Devmgr)
        .ok_or_else(|| Failure::task("WYR1-B devmgr role missing"))?;
    if registry.activation() != Activation::Early
        || registry.startup_profile() != StartupProfile::BootstrapRegistry
        || devmgr.activation() != Activation::Early
        || devmgr.startup_profile() != StartupProfile::EarlyBootStub
    {
        return Err(Failure::task("WYR1-B retained-role profile drifted"));
    }
    Ok(())
}

struct ReceiptInput<'a> {
    request: &'a Request,
    bootfs: &'a [u8],
    manifest: &'a [u8],
    policy: &'a [u8],
    gate: &'a [u8],
    hello: &'a [u8],
    publisher: &'a [u8],
    client: &'a [u8],
    platform: [&'a [u8]; 9],
}

fn receipt(input: ReceiptInput<'_>) -> String {
    format!(
        "kind = \"{RECEIPT_KIND}\"\nschema_version = 6\nselector = \"{}\"\ntest_id = 27\nrequest_sha256 = \"{}\"\ndeepwyrm_revision = \"{}\"\nwyrmroot_revision = \"{}\"\nrust_revision = \"{}\"\nboot_generation = \"{}\"\nbootfs_bytes = {}\nbootfs_pages = {}\nbootfs_sha256 = \"{}\"\nrrc_manifest_sha256 = \"{}\"\nlaunch_policy_sha256 = \"{}\"\ngate_sha256 = \"{}\"\nhello_sha256 = \"{}\"\npublisher_sha256 = \"{}\"\nclient_sha256 = \"{}\"\nloader_sha256 = \"{}\"\nkernel_sha256 = \"{}\"\nsymbols_sha256 = \"{}\"\nbootstrap_sha256 = \"{}\"\nsource_receipt_sha256 = \"{}\"\nkernel_provenance_sha256 = \"{}\"\novmf_code_sha256 = \"{}\"\novmf_vars_sha256 = \"{}\"\nesp_sha256 = \"{}\"\nevidence_nonce = \"{:016X}\"\ntimeout_seconds = {}\n",
        SELECTOR,
        input.request.request_sha256,
        input.request.deepwyrm_revision,
        input.request.wyrmroot_revision,
        input.request.rust_revision,
        encode_digest(&input.request.boot_generation),
        input.bootfs.len(),
        input.bootfs.len().div_ceil(4096),
        sha256::bytes_digest(input.bootfs),
        sha256::bytes_digest(input.manifest),
        sha256::bytes_digest(input.policy),
        sha256::bytes_digest(input.gate),
        sha256::bytes_digest(input.hello),
        sha256::bytes_digest(input.publisher),
        sha256::bytes_digest(input.client),
        sha256::bytes_digest(input.platform[0]),
        sha256::bytes_digest(input.platform[1]),
        sha256::bytes_digest(input.platform[2]),
        sha256::bytes_digest(input.platform[3]),
        sha256::bytes_digest(input.platform[4]),
        sha256::bytes_digest(input.platform[5]),
        sha256::bytes_digest(input.platform[6]),
        sha256::bytes_digest(input.platform[7]),
        sha256::bytes_digest(input.platform[8]),
        input.request.evidence_nonce,
        input.request.timeout_seconds,
    )
}

fn verify_record(record: &[u8], nonce: u64, sequence: u32, event: u8) -> Result<(), Failure> {
    if &record[..4] != b"WRB1"
        || record[4] != b'|'
        || parse_hex(&record[5..7])? != 1
        || parse_hex(&record[8..24])? != nonce
        || parse_hex(&record[25..33])? != u64::from(sequence)
        || parse_hex(&record[34..36])? != u64::from(event)
    {
        return Err(Failure::task("WRB1 identity or sequence mismatch"));
    }
    for offset in [7usize, 24, 33, 36, 53, 70, 87] {
        if record[offset] != b'|' {
            return Err(Failure::task("WRB1 delimiter mismatch"));
        }
    }
    if parse_hex(&record[88..96])? != u64::from(fnv1a32(&record[..88])) {
        return Err(Failure::task("WRB1 checksum mismatch"));
    }
    let subject = parse_hex(&record[37..53])?;
    let generation = parse_hex(&record[54..70])?;
    let value = parse_hex(&record[71..87])?;
    if (event == 0xff) != (subject == 0 && generation == 0 && value == 0)
        || (event != 0xff && (subject == 0 || generation == 0))
    {
        return Err(Failure::task("WRB1 event identity mismatch"));
    }
    Ok(())
}

fn parse_scalars(text: &str) -> Result<BTreeMap<String, String>, Failure> {
    let mut values = BTreeMap::new();
    for (line_no, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (key, raw_value) = line
            .split_once('=')
            .ok_or_else(|| Failure::task(format!("WYR1-B line {} is malformed", line_no + 1)))?;
        let key = key.trim();
        let raw_value = raw_value.trim();
        let value = if let Some(value) = raw_value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
        {
            value
        } else {
            raw_value
        };
        if values.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(Failure::task("WYR1-B duplicate key"));
        }
    }
    Ok(values)
}
fn exact_keys(
    values: &BTreeMap<String, String>,
    expected: &[&str],
    label: &str,
) -> Result<(), Failure> {
    let actual = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(Failure::task(format!("{label} key set drifted")));
    }
    Ok(())
}
fn required<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, Failure> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| Failure::task(format!("missing WYR1-B {key}")))
}
fn number<T: std::str::FromStr>(
    values: &BTreeMap<String, String>,
    key: &str,
) -> Result<T, Failure> {
    required(values, key)?
        .parse()
        .map_err(|_| Failure::task(format!("invalid WYR1-B {key}")))
}
fn bounded_number<T>(
    values: &BTreeMap<String, String>,
    key: &str,
    minimum: T,
    maximum: T,
) -> Result<T, Failure>
where
    T: std::str::FromStr + Copy + Ord,
{
    let raw = required(values, key)?;
    let value = raw
        .parse::<T>()
        .map_err(|_| Failure::task(format!("invalid WYR1-B {key}")))?;
    if raw.len() > 1 && raw.starts_with('0') || value < minimum || value > maximum {
        return Err(Failure::task(format!("out-of-range WYR1-B {key}")));
    }
    Ok(value)
}
fn revision(values: &BTreeMap<String, String>, key: &str) -> Result<String, Failure> {
    let value = required(values, key)?;
    if value.len() != 40
        || value.bytes().all(|byte| byte == b'0')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Failure::task(format!("invalid WYR1-B {key}")));
    }
    Ok(value.to_owned())
}
fn digest(values: &BTreeMap<String, String>, key: &str) -> Result<String, Failure> {
    let value = required(values, key)?;
    if value.len() != 64
        || value.bytes().all(|byte| byte == b'0')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Failure::task(format!("invalid WYR1-B {key}")));
    }
    Ok(value.to_owned())
}
fn input(parent: &Path, value: &str) -> Result<PathBuf, Failure> {
    let path = output(parent, value)?;
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| Failure::task(format!("could not inspect WYR1-B input: {error}")))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.nlink() != 1 {
        return Err(Failure::task(
            "WYR1-B input must be a single-link regular file",
        ));
    }
    let resolved = fs::canonicalize(&path)
        .map_err(|error| Failure::task(format!("could not resolve WYR1-B input: {error}")))?;
    if !resolved.starts_with(parent) {
        return Err(Failure::task("WYR1-B input escapes the request root"));
    }
    Ok(resolved)
}
fn output(parent: &Path, value: &str) -> Result<PathBuf, Failure> {
    let path = Path::new(value);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(Failure::task("WYR1-B output must be request-relative"));
    }
    let joined = parent.join(path);
    let mut cursor = parent.to_path_buf();
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(Failure::task("WYR1-B path is not canonical relative"));
        };
        cursor.push(name);
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Failure::task("WYR1-B path contains symlink ancestry"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(Failure::task(format!(
                    "could not inspect WYR1-B path ancestry: {error}"
                )));
            }
        }
    }
    Ok(joined)
}
fn nonce(value: &str) -> Result<u64, Failure> {
    if value.len() != 16
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
    {
        return Err(Failure::task("invalid WYR1-B evidence nonce"));
    }
    let value = u64::from_str_radix(value, 16)
        .map_err(|_| Failure::task("invalid WYR1-B evidence nonce"))?;
    if value == 0 {
        return Err(Failure::task("zero WYR1-B evidence nonce"));
    }
    Ok(value)
}
fn read(path: &Path, label: &str) -> Result<Vec<u8>, Failure> {
    fs::read(path).map_err(|error| Failure::task(format!("could not read WYR1-B {label}: {error}")))
}
fn read_expected(path: &Path, label: &str, expected: &str) -> Result<Vec<u8>, Failure> {
    let bytes = read(path, label)?;
    if sha256::bytes_digest(&bytes) != expected {
        return Err(Failure::task(format!(
            "WYR1-B {label} does not match request-bound SHA-256"
        )));
    }
    Ok(bytes)
}
fn read_bounded(path: &Path, label: &str, maximum: usize) -> Result<Vec<u8>, Failure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Failure::task(format!("could not inspect WYR1-B {label}: {error}")))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > maximum as u64
    {
        return Err(Failure::task(format!(
            "WYR1-B {label} is not a bounded single-link regular file"
        )));
    }
    read(path, label)
}
fn decode_digest(value: &str) -> Result<[u8; 32], Failure> {
    if value.len() != 64 {
        return Err(Failure::task("invalid WYR1-B request digest"));
    }
    let mut out = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        out[index] = ((pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| Failure::task("invalid digest"))?
            << 4
            | (pair[1] as char)
                .to_digit(16)
                .ok_or_else(|| Failure::task("invalid digest"))?) as u8;
    }
    Ok(out)
}
fn parse_hex(bytes: &[u8]) -> Result<u64, Failure> {
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F'))
    {
        return Err(Failure::task("WRB1 hexadecimal field is invalid"));
    }
    u64::from_str_radix(
        std::str::from_utf8(bytes).map_err(|_| Failure::task("WRB1 is not ASCII"))?,
        16,
    )
    .map_err(|_| Failure::task("WRB1 hexadecimal field is invalid"))
}
fn encode_digest(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return Vec::new();
    }
    haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == needle).then_some(offset))
        .collect()
}
fn canonical_terminal(test_id: u32) -> Vec<u8> {
    let mut line = format!("DWTEST1|01|{test_id:08X}|00000000|").into_bytes();
    let checksum = fnv1a32(&line);
    line.extend_from_slice(format!("{checksum:08X}\n").as_bytes());
    line
}
fn reject_aliases(request: &Request) -> Result<(), Failure> {
    let paths = [
        &request.path,
        &request.loader,
        &request.kernel,
        &request.symbols,
        &request.bootstrap,
        &request.init,
        &request.registryd,
        &request.devmgr,
        &request.uart16550d,
        &request.consoled,
        &request.wyrmsh,
        &request.hello,
        &request.publisher,
        &request.client,
        &request.source_receipt,
        &request.kernel_provenance,
        &request.ovmf_code,
        &request.ovmf_vars,
        &request.rrc_manifest,
        &request.bootfs,
        &request.esp,
        &request.receipt,
        &request.run_directory,
        &request.serial_log,
        &request.run_receipt,
    ];
    let mut lexical = BTreeSet::new();
    let mut inodes = BTreeSet::new();
    for path in paths {
        if !lexical.insert(path) {
            return Err(Failure::task("WYR1-B request paths alias"));
        }
        if let Ok(metadata) = fs::symlink_metadata(path)
            && (metadata.file_type().is_symlink()
                || metadata.is_file() && metadata.nlink() != 1
                || metadata.is_file() && !inodes.insert((metadata.dev(), metadata.ino())))
        {
            return Err(Failure::task("WYR1-B request inode aliases"));
        }
    }
    for (index, left) in paths.iter().enumerate() {
        for right in paths.iter().skip(index + 1) {
            let allowed_run_child = (*left == &request.run_directory
                && (*right == &request.serial_log || *right == &request.run_receipt))
                || (*right == &request.run_directory
                    && (*left == &request.serial_log || *left == &request.run_receipt));
            if !allowed_run_child && (left.starts_with(right) || right.starts_with(left)) {
                return Err(Failure::task("WYR1-B request paths overlap"));
            }
        }
    }
    Ok(())
}

fn refuse_product_outputs(request: &Request) -> Result<(), Failure> {
    for path in [
        &request.rrc_manifest,
        &request.bootfs,
        &request.esp,
        &request.receipt,
    ] {
        if fs::symlink_metadata(path).is_ok() {
            return Err(Failure::task(
                "WYR1-B image refuses pre-existing product outputs",
            ));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                Failure::task(format!("could not create WYR1-B output: {error}"))
            })?;
        }
    }
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), Failure> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| Failure::task(format!("could not create WYR1-B product: {error}")))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| Failure::task(format!("could not write WYR1-B product: {error}")))
}

fn receipt_values(request: &Request) -> Result<BTreeMap<String, String>, Failure> {
    let bytes = read_bounded(&request.receipt, "build receipt", MAX_REQUEST)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Failure::task("WYR1-B build receipt is not UTF-8"))?;
    parse_scalars(text)
}

fn receipt_value(request: &Request, key: &str) -> Result<String, Failure> {
    Ok(required(&receipt_values(request)?, key)?.to_owned())
}

fn verify_build_receipt(request: &Request, bootfs: &[u8]) -> Result<(), Failure> {
    let values = receipt_values(request)?;
    exact_keys(&values, BUILD_RECEIPT_KEYS, "WYR1-B build receipt")?;
    let archive = Archive::new(bootfs)
        .map_err(|error| Failure::task(format!("WYR1-B archive invalid: {error:?}")))?;
    let manifest = archive
        .lookup(wyrmroot_rrc_manifest::MANIFEST_PATH.as_bytes())
        .map_err(|error| Failure::task(format!("WYR1-B manifest missing: {error:?}")))?;
    let policy = archive
        .lookup(b"system/bootstrap/launch-policy-v1")
        .map_err(|error| Failure::task(format!("WYR1-B policy missing: {error:?}")))?;
    let gate = archive
        .lookup(b"system/bootstrap/wyr1-b-gate-v1")
        .map_err(|error| Failure::task(format!("WYR1-B gate missing: {error:?}")))?;
    for (key, expected) in [
        ("kind", RECEIPT_KIND.to_owned()),
        ("schema_version", SCHEMA.to_string()),
        ("selector", SELECTOR.to_owned()),
        ("test_id", TEST_ID.to_string()),
        ("request_sha256", request.request_sha256.clone()),
        ("deepwyrm_revision", request.deepwyrm_revision.clone()),
        ("wyrmroot_revision", request.wyrmroot_revision.clone()),
        ("rust_revision", request.rust_revision.clone()),
        ("boot_generation", encode_digest(&request.boot_generation)),
        ("bootfs_bytes", bootfs.len().to_string()),
        ("bootfs_pages", request.bootfs_pages.to_string()),
        ("bootfs_sha256", sha256::bytes_digest(bootfs)),
        ("rrc_manifest_sha256", sha256::bytes_digest(manifest.data())),
        ("launch_policy_sha256", sha256::bytes_digest(policy.data())),
        ("gate_sha256", sha256::bytes_digest(gate.data())),
        ("hello_sha256", request.hello_sha256.clone()),
        ("publisher_sha256", request.publisher_sha256.clone()),
        ("client_sha256", request.client_sha256.clone()),
        ("loader_sha256", request.loader_sha256.clone()),
        ("kernel_sha256", request.kernel_sha256.clone()),
        ("symbols_sha256", request.symbols_sha256.clone()),
        ("bootstrap_sha256", request.bootstrap_sha256.clone()),
        (
            "source_receipt_sha256",
            request.source_receipt_sha256.clone(),
        ),
        (
            "kernel_provenance_sha256",
            request.kernel_provenance_sha256.clone(),
        ),
        ("ovmf_code_sha256", request.ovmf_code_sha256.clone()),
        ("ovmf_vars_sha256", request.ovmf_vars_sha256.clone()),
        (
            "esp_sha256",
            sha256::file_digest(&request.esp)
                .map_err(|error| Failure::task(format!("could not hash WYR1-B ESP: {error}")))?,
        ),
        ("evidence_nonce", format!("{:016X}", request.evidence_nonce)),
        ("timeout_seconds", request.timeout_seconds.to_string()),
    ] {
        if required(&values, key)? != expected {
            return Err(Failure::task(format!(
                "WYR1-B build receipt field {key} mismatch"
            )));
        }
    }
    Ok(())
}

fn verify_source_receipt(request: &Request, receipt: &[u8]) -> Result<(), Failure> {
    let text = std::str::from_utf8(receipt)
        .map_err(|_| Failure::task("WYR1-B source receipt is not UTF-8"))?;
    let values = parse_scalars(text)?;
    let mut expected_keys = [
        "kind",
        "schema_version",
        "wyrmroot_revision",
        "rust_revision",
        "rustc_sha256",
        "cargo_sha256",
        "rust_lld_sha256",
        "toolchain_manifest_sha256",
        "toolchain_tree_sha256",
        "cargo_lock_sha256",
        "loader_sha256",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    for label in [
        "bootstrap",
        "init27",
        "registryd",
        "devmgr",
        "uart16550d",
        "consoled",
        "wyrmsh",
        "hello",
        "publisher",
        "client",
        "init25",
        "registryd25",
        "registryd25-fail",
    ] {
        expected_keys.insert(format!("{label}_command"));
        expected_keys.insert(format!("{label}_sha256"));
    }
    if values.keys().cloned().collect::<BTreeSet<_>>() != expected_keys {
        return Err(Failure::task("WYR1-B source receipt key set drifted"));
    }
    for (key, expected) in [
        ("kind", SOURCE_RECEIPT_KIND.to_owned()),
        ("schema_version", "1".to_owned()),
        ("wyrmroot_revision", request.wyrmroot_revision.clone()),
        ("rust_revision", request.rust_revision.clone()),
        ("rustc_sha256", ACCEPTED_RUSTC_SHA256.to_owned()),
        ("cargo_sha256", ACCEPTED_CARGO_SHA256.to_owned()),
        ("rust_lld_sha256", ACCEPTED_RUST_LLD_SHA256.to_owned()),
        (
            "toolchain_manifest_sha256",
            ACCEPTED_TOOLCHAIN_MANIFEST_SHA256.to_owned(),
        ),
        (
            "toolchain_tree_sha256",
            ACCEPTED_TOOLCHAIN_TREE_SHA256.to_owned(),
        ),
        ("loader_sha256", request.loader_sha256.clone()),
        ("bootstrap_sha256", request.bootstrap_sha256.clone()),
        ("init27_sha256", request.init_sha256.clone()),
        ("registryd_sha256", request.registryd_sha256.clone()),
        ("devmgr_sha256", request.devmgr_sha256.clone()),
        ("uart16550d_sha256", request.uart16550d_sha256.clone()),
        ("consoled_sha256", request.consoled_sha256.clone()),
        ("wyrmsh_sha256", request.wyrmsh_sha256.clone()),
        ("hello_sha256", request.hello_sha256.clone()),
        ("publisher_sha256", request.publisher_sha256.clone()),
        ("client_sha256", request.client_sha256.clone()),
        (
            "bootstrap_command",
            "cargo build --offline --locked --release --target x86_64-unknown-wyrmroot --package wyrmroot-bootstrap --bin wyrmroot-bootstrap --features native-bootstrap".to_owned(),
        ),
        (
            "init27_command",
            "cargo build --offline --locked --release --target x86_64-unknown-wyrmroot --package wyrmroot-system-init --bin system-init --features native-init,wyr1b-test-evidence".to_owned(),
        ),
        (
            "registryd_command",
            "cargo build --offline --locked --release --target x86_64-unknown-wyrmroot --package wyrmroot-registryd --bin registryd --features native-registryd".to_owned(),
        ),
        (
            "hello_command",
            "cargo build --offline --locked --release --target x86_64-unknown-wyrmroot --package wyrmroot-hello --bin wyrmroot-job-hello --features native-job-hello".to_owned(),
        ),
        (
            "publisher_command",
            "cargo build --offline --locked --release --target x86_64-unknown-wyrmroot --package wyrmroot-wyr1b-gate --bin wyr1-b-publisher --features native-gate".to_owned(),
        ),
        (
            "client_command",
            "cargo build --offline --locked --release --target x86_64-unknown-wyrmroot --package wyrmroot-wyr1b-gate --bin wyr1-b-client --features native-gate".to_owned(),
        ),
        (
            "init25_command",
            "cargo build --offline --locked --release --target x86_64-unknown-wyrmroot --package wyrmroot-system-init --bin system-init --features native-init,wyr1-test-evidence".to_owned(),
        ),
    ] {
        if required(&values, key)? != expected {
            return Err(Failure::task(format!(
                "WYR1-B source receipt field {key} mismatch"
            )));
        }
    }
    let recorded_lock = required(&values, "cargo_lock_sha256")?;
    let current_lock = sha256::file_digest(&crate::tasks::repository_root()?.join("Cargo.lock"))
        .map_err(|error| Failure::task(format!("could not hash current Cargo.lock: {error}")))?;
    if recorded_lock != current_lock {
        return Err(Failure::task(
            "WYR1-B source receipt Cargo.lock does not match current source",
        ));
    }
    Ok(())
}

fn verify_kernel_provenance(request: &Request, provenance: &[u8]) -> Result<(), Failure> {
    let text = std::str::from_utf8(provenance)
        .map_err(|_| Failure::task("WYR1-B kernel provenance is not UTF-8"))?;
    let values = parse_scalars(text)?;
    exact_keys(&values, KERNEL_PROVENANCE_KEYS, "WYR1-B kernel provenance")?;
    for (key, expected) in [
        ("kind", KERNEL_PROVENANCE_KIND.to_owned()),
        ("schema_version", "1".to_owned()),
        ("selector", SELECTOR.to_owned()),
        ("test_id", TEST_ID.to_string()),
        ("deepwyrm_revision", request.deepwyrm_revision.clone()),
        ("rust_revision", request.rust_revision.clone()),
        ("rustc_sha256", ACCEPTED_RUSTC_SHA256.to_owned()),
        ("cargo_sha256", ACCEPTED_CARGO_SHA256.to_owned()),
        (
            "rust_lld_sha256",
            ACCEPTED_RUST_LLD_SHA256.to_owned(),
        ),
        (
            "toolchain_manifest_sha256",
            ACCEPTED_TOOLCHAIN_MANIFEST_SHA256.to_owned(),
        ),
        (
            "toolchain_tree_sha256",
            ACCEPTED_TOOLCHAIN_TREE_SHA256.to_owned(),
        ),
        (
            "kernel_command",
            "tools/pinned-cargo target build --locked --offline --release --target x86_64-unknown-none --package deepwyrm-kernel --bin deepwyrm-kernel --features test-support".to_owned(),
        ),
        ("kernel_sha256", request.kernel_sha256.clone()),
        ("symbols_sha256", request.symbols_sha256.clone()),
        (
            "DEEPWYRM_WYR1B_EVIDENCE_NONCE",
            format!("{:016X}", request.evidence_nonce),
        ),
        (
            "DEEPWYRM_WYR1B_BOOTFS_MAX_PAGES",
            request.bootfs_pages.to_string(),
        ),
    ] {
        if required(&values, key)? != expected {
            return Err(Failure::task(format!(
                "WYR1-B kernel provenance field {key} mismatch"
            )));
        }
    }
    Ok(())
}

fn verify_acceptance_source(request: &Request) -> Result<(), Failure> {
    verify_repository_revision(
        &crate::tasks::repository_root()?,
        "Wyrmroot",
        &request.wyrmroot_revision,
    )?;
    verify_repository_revision(
        &deepwyrm_repository()?,
        "Deepwyrm",
        &request.deepwyrm_revision,
    )
}

fn verify_repository_revision(
    repository: &Path,
    label: &str,
    expected: &str,
) -> Result<(), Failure> {
    let revision = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|error| Failure::task(format!("could not inspect {label} HEAD: {error}")))?;
    let status = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["status", "--porcelain=v1", "--untracked-files=all"])
        .output()
        .map_err(|error| Failure::task(format!("could not inspect {label} status: {error}")))?;
    let actual = std::str::from_utf8(&revision.stdout)
        .map_err(|_| Failure::task(format!("{label} HEAD is not UTF-8")))?
        .trim();
    if !revision.status.success()
        || !status.status.success()
        || !status.stdout.is_empty()
        || actual != expected
    {
        return Err(Failure::task(format!(
            "WYR1-B acceptance requires exact clean {label} revision"
        )));
    }
    Ok(())
}

fn repository_revision(repository: &Path, label: &str) -> Result<String, Failure> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|error| Failure::task(format!("could not inspect {label} HEAD: {error}")))?;
    let revision = std::str::from_utf8(&output.stdout)
        .map_err(|_| Failure::task(format!("{label} HEAD is not UTF-8")))?
        .trim()
        .to_owned();
    if !output.status.success() {
        return Err(Failure::task(format!("could not resolve {label} HEAD")));
    }
    verify_repository_revision(repository, label, &revision)?;
    Ok(revision)
}

fn deepwyrm_repository() -> Result<PathBuf, Failure> {
    let wyrmroot = crate::tasks::repository_root()?;
    let project = wyrmroot
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .and_then(Path::parent)
        .and_then(Path::parent)
        .filter(|path| path.ends_with("OS-Project"))
        .map(Path::to_path_buf)
        .or_else(|| {
            wyrmroot
                .ancestors()
                .find(|path| path.ends_with("OS-Project"))
                .map(Path::to_path_buf)
        })
        .ok_or_else(|| Failure::task("could not locate OS-Project root"))?;
    let deepwyrm = fs::canonicalize(project.join("deepwyrm"))
        .map_err(|error| Failure::task(format!("could not resolve Deepwyrm: {error}")))?;
    Ok(deepwyrm)
}
fn fnv1a32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c9dc5, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x01000193)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn record(nonce: u64, sequence: u32, event: u8) -> [u8; 96] {
        let mut record = [b'|'; 96];
        record[..4].copy_from_slice(b"WRB1");
        for (range, value) in [
            (5..7, 1),
            (8..24, nonce),
            (25..33, u64::from(sequence)),
            (34..36, u64::from(event)),
            (37..53, u64::from(event != 0xff)),
            (54..70, u64::from(event != 0xff)),
            (71..87, 0),
        ] {
            let width = range.len();
            let text = format!("{value:0width$X}");
            record[range].copy_from_slice(text.as_bytes());
        }
        let checksum = fnv1a32(&record[..88]);
        record[88..96].copy_from_slice(format!("{checksum:08X}").as_bytes());
        record
    }

    #[test]
    fn wrb1_rejects_wrong_event_order_and_checksum() {
        let mut record = record(1, 0, 1);
        assert_eq!(verify_record(&record, 1, 0, 1), Ok(()));
        record[95] ^= 1;
        assert!(verify_record(&record, 1, 0, 1).is_err());
    }

    #[test]
    fn evidence_requires_fourteen_ordered_records_then_selector27_terminal() {
        let nonce = 0xB001_B027_0000_0001;
        let events = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0xff];
        let mut serial = b"firmware diagnostic\n".to_vec();
        for (sequence, event) in events.into_iter().enumerate() {
            serial.extend_from_slice(&record(nonce, sequence as u32, event));
        }
        serial.extend_from_slice(&canonical_terminal(TEST_ID));
        assert!(parse_evidence(nonce, &serial).is_ok());
        let offset = b"firmware diagnostic\n".len() + 3 * 96 + 34;
        serial[offset..offset + 2].copy_from_slice(b"05");
        assert!(parse_evidence(nonce, &serial).is_err());
    }

    #[test]
    fn frozen_request_is_exact_selector27_and_request_bound() {
        let bytes = vec![0x42];
        let artifacts = FrozenArtifacts {
            loader: bytes.clone(),
            bootstrap: bytes.clone(),
            init27: bytes.clone(),
            registryd: bytes.clone(),
            devmgr: bytes.clone(),
            uart16550d: bytes.clone(),
            consoled: bytes.clone(),
            wyrmsh: bytes.clone(),
            hello: bytes.clone(),
            publisher: bytes.clone(),
            client: bytes.clone(),
            init25: bytes.clone(),
            registryd25: bytes.clone(),
            registryd25_fail: bytes.clone(),
            source_receipt: "receipt".to_owned(),
        };
        let text = render_request(
            "1111111111111111111111111111111111111111",
            "2222222222222222222222222222222222222222",
            &"33".repeat(32),
            1,
            41,
            &artifacts,
            &bytes,
            &bytes,
            &bytes,
            &bytes,
        );
        let values = parse_scalars(&text).unwrap();
        exact_keys(&values, KEYS, "request").unwrap();
        assert_eq!(required(&values, "test_id"), Ok("27"));
        assert_eq!(required(&values, "bootfs_pages"), Ok("41"));
        assert!(!text.contains("normal-preemption-up"));
        assert!(!text.contains("test_id = 26"));
    }

    #[test]
    fn frozen_request_loads_with_disjoint_product_and_nested_run_outputs() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "wyr1b-request-load-{}-{unique}",
            std::process::id()
        ));
        let input = root.join("artifacts");
        fs::create_dir_all(&input).unwrap();
        let bytes = vec![0x42];
        let artifacts = FrozenArtifacts {
            loader: bytes.clone(),
            bootstrap: bytes.clone(),
            init27: bytes.clone(),
            registryd: bytes.clone(),
            devmgr: bytes.clone(),
            uart16550d: bytes.clone(),
            consoled: bytes.clone(),
            wyrmsh: bytes.clone(),
            hello: bytes.clone(),
            publisher: bytes.clone(),
            client: bytes.clone(),
            init25: bytes.clone(),
            registryd25: bytes.clone(),
            registryd25_fail: bytes.clone(),
            source_receipt: "receipt".to_owned(),
        };
        for (name, contents) in [
            ("loader.efi", bytes.as_slice()),
            ("deepwyrm.elf", bytes.as_slice()),
            ("deepwyrm.symbols.elf", bytes.as_slice()),
            ("bootstrap.elf", bytes.as_slice()),
            ("system-init.elf", bytes.as_slice()),
            ("registryd.elf", bytes.as_slice()),
            ("devmgr.elf", bytes.as_slice()),
            ("uart16550d.elf", bytes.as_slice()),
            ("consoled.elf", bytes.as_slice()),
            ("wyrmsh.elf", bytes.as_slice()),
            ("hello.elf", bytes.as_slice()),
            ("wyr1-b-publisher.elf", bytes.as_slice()),
            ("wyr1-b-client.elf", bytes.as_slice()),
            ("wyr-source-build.toml", b"receipt"),
            ("kernel-provenance.toml", bytes.as_slice()),
            ("OVMF_CODE.fd", bytes.as_slice()),
            ("OVMF_VARS.fd", bytes.as_slice()),
        ] {
            fs::write(input.join(name), contents).unwrap();
        }
        let text = render_request(
            "1111111111111111111111111111111111111111",
            "2222222222222222222222222222222222222222",
            &"33".repeat(32),
            1,
            41,
            &artifacts,
            &bytes,
            &bytes,
            &bytes,
            &bytes,
        );
        let request = root.join("request.toml");
        fs::write(&request, text).unwrap();
        let loaded = load(&request).unwrap();
        assert_eq!(
            loaded.serial_log.parent(),
            Some(loaded.run_directory.as_path())
        );
        assert_eq!(
            loaded.run_receipt.parent(),
            Some(loaded.run_directory.as_path())
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn selector_27_builder_uses_bootstrap_registry_without_changing_devmgr() {
        let generation = [0x42; 32];
        let manifest = fixed_builder_for_profile(
            &generation,
            [[1; 32], [2; 32], [3; 32], [4; 32], [5; 32]],
            StartupProfile::BootstrapRegistry,
        )
        .unwrap()
        .build_structural()
        .unwrap();
        let parsed = Manifest::parse_structural(&manifest, &generation).unwrap();
        assert_eq!(
            parsed.role(RoleId::Registryd).unwrap().startup_profile(),
            StartupProfile::BootstrapRegistry
        );
        assert_eq!(
            parsed.role(RoleId::Devmgr).unwrap().startup_profile(),
            StartupProfile::EarlyBootStub
        );
    }
}
