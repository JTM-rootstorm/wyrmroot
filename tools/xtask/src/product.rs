//! `xtask product`: builds the current Wyrmroot product.
//!
//! One pipeline, no phase history: the eight native roles, the bootstrap, the
//! UEFI loader and the production Deepwyrm kernel are built, the bootfs and its
//! manifests are assembled, and the ESP image is written. The output directory
//! holds `artifacts/` with the ESP and the OVMF pair `dev-boot` boots.
//!
//! Builds come from the working trees of both repositories, not from a
//! committed revision, and reuse persistent Cargo targets under
//! `OS-Project/.tmp/product/` and `deepwyrm/.tmp/product-kernel/` so a rebuild
//! only recompiles what changed. Nothing here is milestone evidence.

use std::{
    collections::BTreeMap,
    env, fs,
    os::unix::fs::MetadataExt,
    path::Path,
    process::{Command, Stdio},
};

use crate::{
    cli::G3ImageArguments,
    error::Failure,
    g3_image,
    product_engine::{MAX_ARTIFACT_BYTES, MAX_BOOTFS_BYTES, NATIVE_TARGET, NativeSpec},
    sha256, tasks,
};
use deepwyrm_abi::{
    DW_BOOT_DEVICE_RESOURCE_FLAGS_SUPPORTED_MASK, DW_BOOT_DEVICE_RESOURCE_V1_SIZE,
    DW_BOOT_DEVICE_RESOURCE_V1_VERSION, DW_BOOT_DEVICE_TABLE_FLAGS_SUPPORTED_MASK,
    DW_BOOT_DEVICE_TABLE_RECORD_STRIDE, DW_BOOT_DEVICE_TABLE_V1_SIZE,
    DW_BOOT_DEVICE_TABLE_V1_VERSION, DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT,
    DwBootDeviceResourceV1, DwBootDeviceTableV1,
};
use wyrmroot_bootfs::{
    launch_policy::{
        JOB_V2_PROFILE_ID, LaunchPolicyEntry, WYRMSH_PATH, WYRMSH_PROFILE_ID, encode_wyrmsh,
    },
    product::{Product, build as build_bootfs},
};
use wyrmroot_device_proto::manifest::{
    ContentIdentity, HEADER_BYTES as WRDM_HEADER_BYTES, RECORD_BYTES as WRDM_RECORD_BYTES,
    encode_com2_manifest,
};
use wyrmroot_rrc_manifest::{
    Activation, DependencyKind, RoleId, StartupProfile,
    builder::{Builder, DependencySpec, RoleSpec},
};

const KERNEL_TARGET: &str = "x86_64-unknown-none";
pub(crate) const OVMF_CODE_PATH: &str = "/usr/share/edk2/OvmfX64/OVMF_CODE.fd";
pub(crate) const OVMF_VARS_PATH: &str = "/usr/share/edk2/OvmfX64/OVMF_VARS.fd";
pub(crate) const MAX_FIRMWARE_BYTES: u64 = 128 * 1024 * 1024;
pub(crate) const ESP_NAME: &str = "esp.img";

/// The shell's production rustflags: no jump tables, and the stack-size
/// sections the native stack check reads.
const WYRMSH_FLAGS: [&str; 2] = ["-Cjump-tables=no", "-Zemit-stack-sizes"];

/// The bootstrap configuration `system-init` reads at `wyr1-a-gate-v1`. The
/// bytes are what every production product has carried; the guest still
/// parses them, so they change only together with `system-init`.
const GATE_CONFIG: &[u8] =
    b"schema = 1\nproduct = \"wyr1-f-normal\"\nselector = \"none\"\nevidence = \"not-produced\"\n";

/// The product's native roles, in bootfs assembly order.
pub(crate) const NATIVES: [NativeSpec; 8] = [
    native(
        "system-init",
        "wyrmroot-system-init",
        "system-init",
        "native-init",
        "system-init",
    ),
    native(
        "registryd",
        "wyrmroot-registryd",
        "registryd",
        "native-registryd",
        "registryd",
    ),
    native(
        "devmgr",
        "wyrmroot-devmgr",
        "devmgr",
        "native-devmgr",
        "devmgr",
    ),
    native(
        "uart16550d",
        "wyrmroot-uart16550d",
        "uart16550d",
        "native-uart16550d",
        "uart16550d",
    ),
    native(
        "consoled",
        "wyrmroot-consoled",
        "consoled",
        "native-consoled",
        "consoled",
    ),
    native(
        "wyrmsh",
        "wyrmroot-wyrmsh",
        "wyrmsh",
        "native-wyrmsh",
        "wyrmsh",
    ),
    native(
        "hello",
        "wyrmroot-hello",
        "wyrmroot-stream-hello",
        "native-stream-hello",
        "wyrmroot-stream-hello",
    ),
    native(
        "cpu-hog",
        "wyrmroot-dw1b-preemption",
        "wyrmroot-job-cpu-hog",
        "native-job-cpu-hog",
        "wyrmroot-job-cpu-hog",
    ),
];

const BOOTSTRAP: NativeSpec = native(
    "bootstrap",
    "wyrmroot-bootstrap",
    "wyrmroot-bootstrap",
    "native-bootstrap",
    "wyrmroot-bootstrap",
);

const fn native(
    label: &'static str,
    package: &'static str,
    binary: &'static str,
    features: &'static str,
    artifact: &'static str,
) -> NativeSpec {
    NativeSpec {
        label,
        package,
        binary,
        features,
        artifact,
    }
}

/// Builds the product into `output`, which must not exist yet.
pub(crate) fn build(output: &Path, deep_repository: &Path) -> Result<(), Failure> {
    let repository = tasks::repository_root()?;
    let project = tasks::canonical_project_root(&repository)?;
    let deep_repository = fs::canonicalize(deep_repository)
        .map_err(|error| Failure::task(format!("could not resolve Deepwyrm checkout: {error}")))?;
    let deep_revision = git_head(&deep_repository)?;
    if output.exists() {
        return Err(Failure::task(format!(
            "product output {} already exists",
            output.display()
        )));
    }

    let manifest = crate::metadata::BuildManifest::load(&repository)?;
    let profile = manifest.validate_loader_build_readiness(&repository)?;
    let toolchain = tasks::prepare_loader_toolchain(&repository, &profile, &manifest)?;
    let cargo_home = tasks::project_cargo_home(&repository, &manifest)?;
    let layout = crate::deep_layout::prepare_current_kernel_source(
        &repository,
        &deep_repository,
        &deep_revision,
    )?;

    let targets = project.join(".tmp/product");
    let staging = targets.join(format!("staging-{}", std::process::id()));
    if staging.exists() {
        fs::remove_dir_all(&staging)
            .map_err(|error| Failure::task(format!("could not clear product staging: {error}")))?;
    }
    fs::create_dir_all(&staging)
        .map_err(|error| Failure::task(format!("could not create product staging: {error}")))?;
    let result = (|| {
        let uefi = tasks::build_deterministic_uefi_pair(
            &repository,
            &toolchain,
            &profile,
            &layout,
            &tasks::IsolatedUefiBuild {
                cargo_home: &cargo_home,
                production_target: &staging.join("uefi-production"),
                retained_debug_target: &staging.join("uefi-retained-debug"),
                cargo_profile: tasks::UefiCargoProfile::Release,
            },
        )?;

        let accepted = toolchain.accepted();
        let shared = targets.join("native");
        let shell = targets.join("native-wyrmsh");
        let bootstrap = build_native(&repository, &cargo_home, accepted, &shared, BOOTSTRAP, &[])?;
        let mut natives = BTreeMap::new();
        for spec in NATIVES {
            let (target, flags): (&Path, &[&str]) = if spec.label == "wyrmsh" {
                (&shell, &WYRMSH_FLAGS)
            } else {
                (&shared, &[])
            };
            let bytes = build_native(&repository, &cargo_home, accepted, target, spec, flags)?;
            natives.insert(spec.label, bytes);
        }

        let assembled = assemble(&natives)?;
        let kernel = build_kernel(&deep_repository, assembled.bootfs.len().div_ceil(4096))?;

        fs::create_dir(output)
            .map_err(|error| Failure::task(format!("could not create product output: {error}")))?;
        let artifacts = output.join("artifacts");
        fs::create_dir(&artifacts)
            .map_err(|error| Failure::task(format!("could not create artifacts: {error}")))?;
        let native_bytes = |label: &str| natives[label].as_slice();
        let ovmf_code =
            read_regular_bounded(Path::new(OVMF_CODE_PATH), MAX_FIRMWARE_BYTES, "OVMF code")?;
        let ovmf_vars =
            read_regular_bounded(Path::new(OVMF_VARS_PATH), MAX_FIRMWARE_BYTES, "OVMF vars")?;
        let device_table = boot_device_table();
        for (name, bytes) in [
            ("loader.efi", uefi.loader_bytes.as_slice()),
            ("deepwyrm.elf", kernel.as_slice()),
            ("bootstrap.elf", bootstrap.as_slice()),
            ("system-init.elf", native_bytes("system-init")),
            ("registryd.elf", native_bytes("registryd")),
            ("devmgr.elf", native_bytes("devmgr")),
            ("uart16550d.elf", native_bytes("uart16550d")),
            ("consoled.elf", native_bytes("consoled")),
            ("wyrmsh.elf", native_bytes("wyrmsh")),
            ("hello.elf", native_bytes("hello")),
            ("cpu-hog.elf", native_bytes("cpu-hog")),
            ("rrc-manifest.bin", assembled.rrc_manifest.as_slice()),
            ("device-manifest.bin", assembled.device_manifest.as_slice()),
            ("launch-policy.bin", assembled.launch_policy.as_slice()),
            ("boot-device-table.bin", device_table.as_slice()),
            ("bootfs.img", assembled.bootfs.as_slice()),
            ("OVMF_CODE.fd", ovmf_code.as_slice()),
            ("OVMF_VARS.fd", ovmf_vars.as_slice()),
        ] {
            write_new(&artifacts.join(name), bytes, name)?;
        }
        let path = |name: &str| artifacts.join(name).display().to_string();
        g3_image::build_d6(
            &G3ImageArguments {
                image: path(ESP_NAME),
                loader: path("loader.efi"),
                kernel: path("deepwyrm.elf"),
                bootstrap: path("bootstrap.elf"),
                bootfs: path("bootfs.img"),
            },
            &path("boot-device-table.bin"),
        )?;
        Ok(())
    })();
    let _ = fs::remove_dir_all(&staging);
    result
}

/// Builds one native binary with the accepted toolchain into a persistent
/// target directory and returns its bytes.
fn build_native(
    repository: &Path,
    cargo_home: &Path,
    toolchain: &crate::toolchain_artifact::AcceptedToolchain,
    target: &Path,
    spec: NativeSpec,
    extra_flags: &[&str],
) -> Result<Vec<u8>, Failure> {
    fs::create_dir_all(target)
        .map_err(|error| Failure::task(format!("could not create native target: {error}")))?;
    let mut flags = crate::product_engine::native_remap_flags(repository, cargo_home, target)?;
    for flag in extra_flags {
        flags.push('\u{1f}');
        flags.push_str(flag);
    }
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
    let status = Command::new(&toolchain.cargo)
        .env_clear()
        .env("PATH", path)
        .env("LC_ALL", "C")
        .args([
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
        ])
        .arg("--target-dir")
        .arg(target)
        .env("RUSTC", &toolchain.rustc)
        .env("CARGO_HOME", cargo_home)
        .env("CARGO_ENCODED_RUSTFLAGS", flags)
        .env("CARGO_NET_OFFLINE", "true")
        .env("SOURCE_DATE_EPOCH", "0")
        .current_dir(repository)
        .stdin(Stdio::null())
        .status()
        .map_err(|error| Failure::task(format!("could not build {}: {error}", spec.label)))?;
    if !status.success() {
        return Err(Failure::task(format!("{} build failed", spec.label)));
    }
    read_build_output(
        &target
            .join(NATIVE_TARGET)
            .join("release")
            .join(spec.artifact),
        MAX_ARTIFACT_BYTES as u64,
        spec.label,
    )
}

/// Builds the production Deepwyrm kernel: no selector, no test support, and
/// the measured bootfs page ceiling.
fn build_kernel(deep_repository: &Path, bootfs_pages: usize) -> Result<Vec<u8>, Failure> {
    let target = deep_repository.join(".tmp/product-kernel");
    fs::create_dir_all(&target)
        .map_err(|error| Failure::task(format!("could not create kernel target: {error}")))?;
    let status = Command::new(deep_repository.join("tools/pinned-cargo"))
        .args([
            "target",
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
        .env("DEEPWYRM_PINNED_TARGET_DIR", &target)
        .env("DEEPWYRM_BOOTFS_MAX_PAGES", bootfs_pages.to_string())
        .env_remove("DEEPWYRM_GUEST_TEST_SELECTOR")
        .env_remove("DEEPWYRM_GUEST_TEST_ID")
        .env_remove("CARGO_HOME")
        .env_remove("CARGO_TARGET_DIR")
        .current_dir(deep_repository)
        .stdin(Stdio::null())
        .status()
        .map_err(|error| Failure::task(format!("could not build the kernel: {error}")))?;
    if !status.success() {
        return Err(Failure::task("production Deepwyrm kernel build failed"));
    }
    read_build_output(
        &target.join(KERNEL_TARGET).join("release/deepwyrm-kernel"),
        MAX_ARTIFACT_BYTES as u64,
        "kernel",
    )
}

struct Assembled {
    rrc_manifest: Vec<u8>,
    device_manifest: Vec<u8>,
    launch_policy: Vec<u8>,
    bootfs: Vec<u8>,
}

/// Assembles the bootfs and the three manifests it carries.
fn assemble(natives: &BTreeMap<&str, Vec<u8>>) -> Result<Assembled, Failure> {
    let identity = |label: &str| sha256::bytes_digest_array(&natives[label]);
    let role_hashes = [
        identity("registryd"),
        identity("devmgr"),
        identity("uart16550d"),
        identity("consoled"),
        identity("wyrmsh"),
    ];
    let mut material = Vec::from(b"wyrmroot-product-v1\0".as_slice());
    for spec in NATIVES {
        material.extend_from_slice(spec.label.as_bytes());
        material.extend_from_slice(&identity(spec.label));
    }
    let generation = sha256::bytes_digest_array(&material);

    let rrc_manifest = rrc_builder(&generation, role_hashes)?
        .build_structural()
        .map_err(|error| Failure::task(format!("RRC manifest build failed: {error:?}")))?;

    let mut wrdm = [0u8; WRDM_HEADER_BYTES + WRDM_RECORD_BYTES];
    let wrdm_size = encode_com2_manifest(ContentIdentity(role_hashes[2]), &mut wrdm)
        .map_err(|error| Failure::task(format!("device manifest build failed: {error:?}")))?;
    let device_manifest = wrdm[..wrdm_size].to_vec();

    let hello = identity("hello");
    let cpu_hog = identity("cpu-hog");
    let mut policy = [0u8; 512];
    let policy_size = encode_wyrmsh(
        generation,
        &[
            // A background job gets no stream roles, so the hog is admitted
            // on zero streams only.
            LaunchPolicyEntry {
                path: "bin/cpu-hog",
                content_sha256: cpu_hog,
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: true,
                allow_three_streams: false,
            },
            LaunchPolicyEntry {
                path: "bin/hello",
                content_sha256: hello,
                startup_abi: 2,
                profile_id: JOB_V2_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
            LaunchPolicyEntry {
                path: WYRMSH_PATH,
                content_sha256: role_hashes[4],
                startup_abi: 2,
                profile_id: WYRMSH_PROFILE_ID,
                allow_no_streams: false,
                allow_three_streams: true,
            },
        ],
        &mut policy,
    )
    .map_err(|error| Failure::task(format!("launch policy build failed: {error:?}")))?;
    let launch_policy = policy[..policy_size].to_vec();

    let bootfs = build_bootfs(Product {
        init: &natives["system-init"],
        registryd: &natives["registryd"],
        devmgr: &natives["devmgr"],
        uart16550d: &natives["uart16550d"],
        consoled: &natives["consoled"],
        wyrmsh: &natives["wyrmsh"],
        hello: &natives["hello"],
        cpu_hog: &natives["cpu-hog"],
        rrc_manifest: &rrc_manifest,
        gate_config: GATE_CONFIG,
        device_manifest: &device_manifest,
        launch_policy: &launch_policy,
        uart16550d_identity: role_hashes[2],
        wyrmsh_identity: role_hashes[4],
        hello_identity: hello,
        cpu_hog_identity: cpu_hog,
    })
    .map_err(|error| Failure::task(format!("bootfs build failed: {error:?}")))?;
    if bootfs.len() > MAX_BOOTFS_BYTES {
        return Err(Failure::task("bootfs exceeds the image bound"));
    }
    Ok(Assembled {
        rrc_manifest,
        device_manifest,
        launch_policy,
        bootfs,
    })
}

/// The recovery-root closure: five roles, each ready-gated on the one before.
fn rrc_builder(
    generation: &[u8; 32],
    role_hashes: [[u8; 32]; 5],
) -> Result<Builder<'static>, Failure> {
    let mut builder = Builder::new(*generation);
    let roles = [
        (
            RoleId::Registryd,
            "system/registryd",
            "minimum bootfs discovery needed to reconstruct direct recovery-service connections without root",
            Activation::Early,
            StartupProfile::BootstrapRegistry,
        ),
        (
            RoleId::Devmgr,
            "system/devmgr",
            "binding/restart path for root-critical and console devices without root",
            Activation::Early,
            StartupProfile::DeviceCoordinator,
        ),
        (
            RoleId::Uart16550d,
            "system/uart16550d",
            "selected q35 recovery-console transport, launched only by devmgr after exact delegation",
            Activation::DeviceBound,
            StartupProfile::Retained,
        ),
        (
            RoleId::Consoled,
            "system/consoled",
            "bounded operator-control transport when root recovery degrades",
            Activation::ConsoleBound,
            StartupProfile::Retained,
        ),
        (
            RoleId::Wyrmsh,
            "system/wyrmsh",
            "minimum recovery/admin control path independent of persistent root",
            Activation::ConsoleBound,
            StartupProfile::Wyrmsh,
        ),
    ];
    for (index, (id, path, justification, activation, startup_profile)) in
        roles.into_iter().enumerate()
    {
        builder
            .add_role(RoleSpec {
                id,
                required: true,
                requires_ready: true,
                activation,
                startup_profile,
                path,
                justification,
                executable_identity: role_hashes[index],
            })
            .map_err(|error| Failure::task(format!("RRC role builder failed: {error:?}")))?;
    }
    for (owner, target) in [
        (RoleId::Devmgr, RoleId::Registryd),
        (RoleId::Uart16550d, RoleId::Devmgr),
        (RoleId::Consoled, RoleId::Uart16550d),
        (RoleId::Wyrmsh, RoleId::Consoled),
    ] {
        builder
            .add_dependency(DependencySpec {
                owner,
                kind: DependencyKind::RoleReady,
                target_role: Some(target),
                target_path: None,
            })
            .map_err(|error| Failure::task(format!("RRC dependency builder failed: {error:?}")))?;
    }
    Ok(builder)
}

/// The boot device table: one q35 COM2 resource (PIO 0x2f8, IRQ 3).
fn boot_device_table() -> Vec<u8> {
    let header = DW_BOOT_DEVICE_TABLE_V1_SIZE as usize;
    let stride = DW_BOOT_DEVICE_TABLE_RECORD_STRIDE as usize;
    let total = header + stride;
    let mut table = vec![0; total];
    let mut put =
        |offset: usize, value: &[u8]| table[offset..offset + value.len()].copy_from_slice(value);
    put(
        core::mem::offset_of!(DwBootDeviceTableV1, size),
        &DW_BOOT_DEVICE_TABLE_V1_SIZE.to_le_bytes(),
    );
    put(
        core::mem::offset_of!(DwBootDeviceTableV1, version),
        &DW_BOOT_DEVICE_TABLE_V1_VERSION.to_le_bytes(),
    );
    put(
        core::mem::offset_of!(DwBootDeviceTableV1, resource_count),
        &1u32.to_le_bytes(),
    );
    put(
        core::mem::offset_of!(DwBootDeviceTableV1, flags),
        &DW_BOOT_DEVICE_TABLE_FLAGS_SUPPORTED_MASK.to_le_bytes(),
    );
    put(
        core::mem::offset_of!(DwBootDeviceTableV1, record_stride),
        &DW_BOOT_DEVICE_TABLE_RECORD_STRIDE.to_le_bytes(),
    );
    put(
        core::mem::offset_of!(DwBootDeviceTableV1, total_byte_len),
        &(total as u64).to_le_bytes(),
    );
    let record = header;
    put(
        record + core::mem::offset_of!(DwBootDeviceResourceV1, size),
        &DW_BOOT_DEVICE_RESOURCE_V1_SIZE.to_le_bytes(),
    );
    put(
        record + core::mem::offset_of!(DwBootDeviceResourceV1, version),
        &DW_BOOT_DEVICE_RESOURCE_V1_VERSION.to_le_bytes(),
    );
    put(
        record + core::mem::offset_of!(DwBootDeviceResourceV1, kind),
        &DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT
            .0
            .to_le_bytes(),
    );
    put(
        record + core::mem::offset_of!(DwBootDeviceResourceV1, flags),
        &DW_BOOT_DEVICE_RESOURCE_FLAGS_SUPPORTED_MASK.to_le_bytes(),
    );
    put(
        record + core::mem::offset_of!(DwBootDeviceResourceV1, resource_id),
        &1u64.to_le_bytes(),
    );
    put(
        record + core::mem::offset_of!(DwBootDeviceResourceV1, device_correlation_id),
        &1u64.to_le_bytes(),
    );
    put(
        record + core::mem::offset_of!(DwBootDeviceResourceV1, pio_base),
        &0x02f8u16.to_le_bytes(),
    );
    put(
        record + core::mem::offset_of!(DwBootDeviceResourceV1, pio_length),
        &8u16.to_le_bytes(),
    );
    put(
        record + core::mem::offset_of!(DwBootDeviceResourceV1, interrupt_source),
        &3u32.to_le_bytes(),
    );
    table
}

fn git_head(repository: &Path) -> Result<String, Failure> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["rev-parse", "HEAD"])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| Failure::task(format!("could not run git: {error}")))?;
    if !output.status.success() {
        return Err(Failure::task(format!(
            "could not read HEAD of {}",
            repository.display()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Reads a regular, single-link, non-empty file of at most `maximum` bytes.
pub(crate) fn read_regular_bounded(
    path: &Path,
    maximum: u64,
    label: &str,
) -> Result<Vec<u8>, Failure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Failure::task(format!("could not stat {label}: {error}")))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(Failure::task(format!(
            "{label} is not a bounded regular file"
        )));
    }
    fs::read(path).map_err(|error| Failure::task(format!("could not read {label}: {error}")))
}

/// Reads a Cargo build output: a regular, non-empty file of at most `maximum`
/// bytes. Cargo hard-links release binaries, so the link count is not checked.
fn read_build_output(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>, Failure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Failure::task(format!("could not stat {label}: {error}")))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(Failure::task(format!(
            "{label} is not a bounded regular file"
        )));
    }
    fs::read(path).map_err(|error| Failure::task(format!("could not read {label}: {error}")))
}

fn write_new(path: &Path, bytes: &[u8], label: &str) -> Result<(), Failure> {
    use std::io::Write as _;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| Failure::task(format!("could not create {label}: {error}")))?;
    file.write_all(bytes)
        .map_err(|error| Failure::task(format!("could not write {label}: {error}")))
}
