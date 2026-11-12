//! `xtask product`: builds the current Wyrmroot product.
//!
//! One pipeline, no phase history: the eight native roles, the bootstrap, the
//! UEFI loader and the production Deepwyrm kernel are built, the bootfs and its
//! manifests are assembled, and the ESP image is written. The output directory
//! holds `artifacts/` with the ESP, the empty ext4 root disk and the OVMF pair
//! that `dev-boot` and the VM gate boot.
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
    DW_BOOT_DEVICE_RESOURCE_FLAGS_SUPPORTED_MASK, DW_BOOT_DEVICE_RESOURCE_V2_SIZE,
    DW_BOOT_DEVICE_RESOURCE_V2_VERSION, DW_BOOT_DEVICE_TABLE_FLAGS_SUPPORTED_MASK,
    DW_BOOT_DEVICE_TABLE_RECORD_STRIDE, DW_BOOT_DEVICE_TABLE_V2_SIZE,
    DW_BOOT_DEVICE_TABLE_V2_VERSION, DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION,
    DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT, DwBootDeviceResourceV2,
    DwBootDeviceTableV2,
};
use wyrmroot_bootfs::{
    launch_policy::{
        JOB_V2_PROFILE_ID, LaunchPolicyEntry, SERVICE_ROLE_PROFILE_ID, WYRMSH_PATH,
        WYRMSH_PROFILE_ID, encode as encode_policy,
    },
    paths::{BLOCKMGR_PATH, EXT4D_PATH, FAT32D_PATH, VFSD_PATH},
    product::{Product, ServiceArtifact, build as build_bootfs},
};
use wyrmroot_device_proto::manifest::{
    ContentIdentity, HEADER_BYTES as WRDM_HEADER_BYTES, RECORD_BYTES as WRDM_RECORD_BYTES,
    encode_product_manifest,
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
/// The empty persistent root (root `STORAGE_PLAN.md` W7): an ext4 volume
/// with a `boot` mount point. Runs boot a writable copy, never the artifact.
pub(crate) const ROOT_DISK_NAME: &str = "root.img";
const ROOT_DISK_BYTES: u64 = 64 << 20;

/// The shell's production rustflags: no jump tables, and the stack-size
/// sections the native stack check reads.
const WYRMSH_FLAGS: [&str; 2] = ["-Cjump-tables=no", "-Zemit-stack-sizes"];

/// `/EFI/WYRMROOT/README.TXT` on the ESP, which the running system reads
/// back through its own FAT32 (root `STORAGE_PLAN.md` W6).
pub(crate) const ESP_README: &[u8] = b"This is the Wyrmroot EFI System Partition.\n";

/// The product's native roles, in bootfs assembly order.
pub(crate) const NATIVES: [NativeSpec; 13] = [
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
        "virtio-blkd",
        "wyrmroot-virtio-blkd",
        "virtio-blkd",
        "native-virtio-blkd",
        "virtio-blkd",
    ),
    native(
        "blockmgr",
        "wyrmroot-blockmgr",
        "blockmgr",
        "native-blockmgr",
        "blockmgr",
    ),
    native(
        "fat32d",
        "wyrmroot-fat32d",
        "fat32d",
        "native-fat32d",
        "fat32d",
    ),
    native("ext4d", "wyrmroot-ext4d", "ext4d", "native-ext4d", "ext4d"),
    native("vfsd", "wyrmroot-vfsd", "vfsd", "native-vfsd", "vfsd"),
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
        "wyrmroot-cpu-hog",
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
/// The SDK's test files dev-boot runs from `/EFI/WYRMROOT`: each file in
/// `<sdk>/programs` and its 8.3 name on the ESP.
pub(crate) const SDK_FILES: [(&str, [u8; 11]); 4] = [
    ("hello.elf", *b"SDKHELLOELF"),
    ("zlib-example.elf", *b"ZEXAMPLEELF"),
    ("lua.elf", *b"LUA     ELF"),
    ("test.lua", *b"TEST    LUA"),
];
/// The largest SDK file the ESP takes; init reads at most 8 MiB.
const MAX_SDK_PROGRAM_BYTES: u64 = 8 << 20;

/// Builds the product into `output`. With `sdk`, a built Wyrmroot SDK
/// (`wyrmroot-sdk/out`), its [`SDK_FILES`] go on the ESP for dev-boot to
/// run.
pub(crate) fn build(
    output: &Path,
    deep_repository: &Path,
    sdk: Option<&Path>,
) -> Result<(), Failure> {
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
        let root_disk = root_disk()?;
        let mut sdk_files = Vec::new();
        if let Some(sdk) = sdk {
            for (name, short_name) in SDK_FILES {
                let bytes = read_regular_bounded(
                    &sdk.join("programs").join(name),
                    MAX_SDK_PROGRAM_BYTES,
                    "SDK test file",
                )?;
                sdk_files.push((format!("sdk-{name}"), short_name, bytes));
            }
        }
        for (name, bytes) in [
            ("loader.efi", uefi.loader_bytes.as_slice()),
            ("deepwyrm.elf", kernel.as_slice()),
            ("bootstrap.elf", bootstrap.as_slice()),
            ("system-init.elf", native_bytes("system-init")),
            ("registryd.elf", native_bytes("registryd")),
            ("devmgr.elf", native_bytes("devmgr")),
            ("uart16550d.elf", native_bytes("uart16550d")),
            ("virtio-blkd.elf", native_bytes("virtio-blkd")),
            ("blockmgr.elf", native_bytes("blockmgr")),
            ("fat32d.elf", native_bytes("fat32d")),
            ("ext4d.elf", native_bytes("ext4d")),
            ("vfsd.elf", native_bytes("vfsd")),
            ("consoled.elf", native_bytes("consoled")),
            ("wyrmsh.elf", native_bytes("wyrmsh")),
            ("hello.elf", native_bytes("hello")),
            ("cpu-hog.elf", native_bytes("cpu-hog")),
            ("rrc-manifest.bin", assembled.rrc_manifest.as_slice()),
            ("device-manifest.bin", assembled.device_manifest.as_slice()),
            ("launch-policy.bin", assembled.launch_policy.as_slice()),
            ("boot-device-table.bin", device_table.as_slice()),
            ("esp-readme.txt", ESP_README),
            ("bootfs.img", assembled.bootfs.as_slice()),
            (ROOT_DISK_NAME, root_disk.as_slice()),
            ("OVMF_CODE.fd", ovmf_code.as_slice()),
            ("OVMF_VARS.fd", ovmf_vars.as_slice()),
        ] {
            write_new(&artifacts.join(name), bytes, name)?;
        }
        for (artifact, _, bytes) in &sdk_files {
            write_new(&artifacts.join(artifact), bytes, artifact)?;
        }
        let path = |name: &str| artifacts.join(name).display().to_string();
        let (readme_path, hello_path) = (path("esp-readme.txt"), path("hello.elf"));
        let sdk_paths: Vec<([u8; 11], String)> = sdk_files
            .iter()
            .map(|(artifact, short_name, _)| (*short_name, path(artifact)))
            .collect();
        let mut extras = vec![
            g3_image::EspExtra {
                short_name: *b"README  TXT",
                path: &readme_path,
            },
            g3_image::EspExtra {
                short_name: *b"HELLO   ELF",
                path: &hello_path,
            },
        ];
        for (short_name, path) in &sdk_paths {
            extras.push(g3_image::EspExtra {
                short_name: *short_name,
                path,
            });
        }
        g3_image::build_d6(
            &G3ImageArguments {
                image: path(ESP_NAME),
                loader: path("loader.efi"),
                kernel: path("deepwyrm.elf"),
                bootstrap: path("bootstrap.elf"),
                bootfs: path("bootfs.img"),
            },
            &path("boot-device-table.bin"),
            &extras,
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

    // COM2, then the boot disk (root `STORAGE_PLAN.md` W2) and the data disk
    // (W7). The disk driver is not a recovery-root role, so WRDM alone names
    // its identity.
    let block_identity = identity("virtio-blkd");
    let mut wrdm = [0u8; WRDM_HEADER_BYTES + 3 * WRDM_RECORD_BYTES];
    let wrdm_size = encode_product_manifest(
        ContentIdentity(role_hashes[2]),
        ContentIdentity(block_identity),
        &mut wrdm,
    )
    .map_err(|error| Failure::task(format!("device manifest build failed: {error:?}")))?;
    let device_manifest = wrdm[..wrdm_size].to_vec();

    let hello = identity("hello");
    let cpu_hog = identity("cpu-hog");
    let services = ["blockmgr", "fat32d", "ext4d", "vfsd"].map(identity);
    let service = |path, content_sha256| LaunchPolicyEntry {
        path,
        content_sha256,
        startup_abi: 1,
        profile_id: SERVICE_ROLE_PROFILE_ID,
        allow_no_streams: true,
        allow_three_streams: false,
    };
    let mut policy = [0u8; 1024];
    let policy_size = encode_policy(
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
            // The storage service roles (root `STORAGE_PLAN.md` W6, W7), in
            // canonical path order.
            service(BLOCKMGR_PATH, services[0]),
            service(EXT4D_PATH, services[2]),
            service(FAT32D_PATH, services[1]),
            service(VFSD_PATH, services[3]),
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
        virtio_blkd: &natives["virtio-blkd"],
        consoled: &natives["consoled"],
        wyrmsh: &natives["wyrmsh"],
        hello: &natives["hello"],
        cpu_hog: &natives["cpu-hog"],
        rrc_manifest: &rrc_manifest,
        device_manifest: &device_manifest,
        launch_policy: &launch_policy,
        uart16550d_identity: role_hashes[2],
        virtio_blkd_identity: block_identity,
        wyrmsh_identity: role_hashes[4],
        hello_identity: hello,
        cpu_hog_identity: cpu_hog,
        services: [
            ServiceArtifact {
                bytes: &natives["blockmgr"],
                identity: services[0],
            },
            ServiceArtifact {
                bytes: &natives["fat32d"],
                identity: services[1],
            },
            ServiceArtifact {
                bytes: &natives["ext4d"],
                identity: services[2],
            },
            ServiceArtifact {
                bytes: &natives["vfsd"],
                identity: services[3],
            },
        ],
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

/// A modern (non-transitional) virtio block device, 1af4:1042.
use wyrmroot_device_proto::manifest::VIRTIO_BLOCK_PCI_IDS;
/// The q35 PCI addresses of the boot disk (bus 0, device 1, function 0) and
/// the data disk (device 2). `dev-boot` and the VM gate pin the disks to
/// these slots. The device table and WRDM's disk roles share these values.
pub(crate) use wyrmroot_device_proto::manifest::{BOOT_DISK_PCI_ADDRESS, DATA_DISK_PCI_ADDRESS};

/// One boot device-table record. Fields of the other kind stay zero.
#[derive(Clone, Copy)]
struct DeviceRecord {
    kind: deepwyrm_abi::DwDeviceResourceKind,
    resource_id: u64,
    pio_base: u16,
    pio_length: u16,
    interrupt_source: u32,
    pci_address: u32,
    pci_ids: u32,
}

/// The boot device table: q35 COM2 (PIO 0x2f8, IRQ 3), resource 1, the
/// boot disk's PCI function, resource 2 (root `STORAGE_PLAN.md` K1/W1), and
/// the data disk's, resource 3 (W7). A disk that is not attached is logged
/// absent by the kernel and simply cannot be claimed.
fn boot_device_table() -> Vec<u8> {
    let records = [
        DeviceRecord {
            kind: DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT,
            resource_id: 1,
            pio_base: 0x02f8,
            pio_length: 8,
            interrupt_source: 3,
            pci_address: 0,
            pci_ids: 0,
        },
        DeviceRecord {
            kind: DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION,
            resource_id: wyrmroot_device_proto::manifest::BOOT_DISK_RESOURCE_ID,
            pio_base: 0,
            pio_length: 0,
            interrupt_source: 0,
            pci_address: BOOT_DISK_PCI_ADDRESS,
            pci_ids: VIRTIO_BLOCK_PCI_IDS,
        },
        DeviceRecord {
            kind: DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION,
            resource_id: wyrmroot_device_proto::manifest::DATA_DISK_RESOURCE_ID,
            pio_base: 0,
            pio_length: 0,
            interrupt_source: 0,
            pci_address: DATA_DISK_PCI_ADDRESS,
            pci_ids: VIRTIO_BLOCK_PCI_IDS,
        },
    ];
    let header = DW_BOOT_DEVICE_TABLE_V2_SIZE as usize;
    let stride = DW_BOOT_DEVICE_TABLE_RECORD_STRIDE as usize;
    let total = header + stride * records.len();
    let mut table = vec![0; total];
    let mut put =
        |offset: usize, value: &[u8]| table[offset..offset + value.len()].copy_from_slice(value);
    put(
        core::mem::offset_of!(DwBootDeviceTableV2, size),
        &DW_BOOT_DEVICE_TABLE_V2_SIZE.to_le_bytes(),
    );
    put(
        core::mem::offset_of!(DwBootDeviceTableV2, version),
        &DW_BOOT_DEVICE_TABLE_V2_VERSION.to_le_bytes(),
    );
    put(
        core::mem::offset_of!(DwBootDeviceTableV2, resource_count),
        &(records.len() as u32).to_le_bytes(),
    );
    put(
        core::mem::offset_of!(DwBootDeviceTableV2, flags),
        &DW_BOOT_DEVICE_TABLE_FLAGS_SUPPORTED_MASK.to_le_bytes(),
    );
    put(
        core::mem::offset_of!(DwBootDeviceTableV2, record_stride),
        &DW_BOOT_DEVICE_TABLE_RECORD_STRIDE.to_le_bytes(),
    );
    put(
        core::mem::offset_of!(DwBootDeviceTableV2, total_byte_len),
        &(total as u64).to_le_bytes(),
    );
    for (index, item) in records.iter().enumerate() {
        let record = header + index * stride;
        let field = |name: usize| record + name;
        put(
            field(core::mem::offset_of!(DwBootDeviceResourceV2, size)),
            &DW_BOOT_DEVICE_RESOURCE_V2_SIZE.to_le_bytes(),
        );
        put(
            field(core::mem::offset_of!(DwBootDeviceResourceV2, version)),
            &DW_BOOT_DEVICE_RESOURCE_V2_VERSION.to_le_bytes(),
        );
        put(
            field(core::mem::offset_of!(DwBootDeviceResourceV2, kind)),
            &item.kind.0.to_le_bytes(),
        );
        put(
            field(core::mem::offset_of!(DwBootDeviceResourceV2, flags)),
            &DW_BOOT_DEVICE_RESOURCE_FLAGS_SUPPORTED_MASK.to_le_bytes(),
        );
        put(
            field(core::mem::offset_of!(DwBootDeviceResourceV2, resource_id)),
            &item.resource_id.to_le_bytes(),
        );
        put(
            field(core::mem::offset_of!(
                DwBootDeviceResourceV2,
                device_correlation_id
            )),
            &item.resource_id.to_le_bytes(),
        );
        put(
            field(core::mem::offset_of!(DwBootDeviceResourceV2, pio_base)),
            &item.pio_base.to_le_bytes(),
        );
        put(
            field(core::mem::offset_of!(DwBootDeviceResourceV2, pio_length)),
            &item.pio_length.to_le_bytes(),
        );
        put(
            field(core::mem::offset_of!(
                DwBootDeviceResourceV2,
                interrupt_source
            )),
            &item.interrupt_source.to_le_bytes(),
        );
        put(
            field(core::mem::offset_of!(DwBootDeviceResourceV2, pci_address)),
            &item.pci_address.to_le_bytes(),
        );
        put(
            field(core::mem::offset_of!(DwBootDeviceResourceV2, pci_ids)),
            &item.pci_ids.to_le_bytes(),
        );
    }
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
    read_bounded_no_follow(path, maximum, true, label)
}

/// Reads a Cargo build output: a regular, non-empty file of at most `maximum`
/// bytes. Cargo hard-links release binaries, so the link count is not checked.
fn read_build_output(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>, Failure> {
    read_bounded_no_follow(path, maximum, false, label)
}

/// Opens `path` once without following a final symlink and without blocking
/// on a FIFO, then checks and reads that same open file, so a path swapped
/// after the check cannot be read in its place (F4 WR-F4-L3).
fn read_bounded_no_follow(
    path: &Path,
    maximum: u64,
    single_link: bool,
    label: &str,
) -> Result<Vec<u8>, Failure> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(crate::secure_fs::O_NOFOLLOW | crate::secure_fs::O_NONBLOCK)
        .open(path)
        .map_err(|error| Failure::task(format!("could not open {label}: {error}")))?;
    let metadata = file
        .metadata()
        .map_err(|error| Failure::task(format!("could not stat {label}: {error}")))?;
    if !metadata.file_type().is_file()
        || (single_link && metadata.nlink() != 1)
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(Failure::task(format!(
            "{label} is not a bounded regular file"
        )));
    }
    let mut bytes = Vec::new();
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| Failure::task(format!("could not read {label}: {error}")))?;
    if bytes.len() as u64 != metadata.len() {
        return Err(Failure::task(format!("{label} changed while it was read")));
    }
    Ok(bytes)
}

/// A disk image held in memory, for formatting the root disk.
struct MemoryDisk(Vec<u8>);

impl MemoryDisk {
    fn range(
        &self,
        offset: u64,
        len: usize,
    ) -> Result<core::ops::Range<usize>, wyrmroot_ext4::DeviceError> {
        let fail = wyrmroot_ext4::DeviceError(1);
        let start = usize::try_from(offset).map_err(|_| fail)?;
        let end = start.checked_add(len).ok_or(fail)?;
        if end > self.0.len() {
            return Err(fail);
        }
        Ok(start..end)
    }
}

impl wyrmroot_ext4::Device for MemoryDisk {
    fn read(&mut self, offset: u64, out: &mut [u8]) -> Result<(), wyrmroot_ext4::DeviceError> {
        let range = self.range(offset, out.len())?;
        out.copy_from_slice(&self.0[range]);
        Ok(())
    }
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), wyrmroot_ext4::DeviceError> {
        let range = self.range(offset, data.len())?;
        self.0[range].copy_from_slice(data);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), wyrmroot_ext4::DeviceError> {
        Ok(())
    }
}

/// The empty root disk. Every field that could vary is fixed, so the image
/// is reproducible.
fn root_disk() -> Result<Vec<u8>, Failure> {
    use wyrmroot_ext4::{FormatParams, Kind, ROOT_INODE, Volume};
    let failed = |what: String| Failure::task(format!("could not make the root disk: {what}"));
    let mut disk = MemoryDisk(vec![0; ROOT_DISK_BYTES as usize]);
    let params = FormatParams {
        block_size: 4096,
        uuid: *b"wyrmroot-devroot",
        label: *b"wyrmroot-root\0\0\0",
        time: 1_700_000_000,
    };
    wyrmroot_ext4::format(&mut disk, ROOT_DISK_BYTES, &params)
        .map_err(|error| failed(format!("{error:?}")))?;
    let mut volume = Volume::mount(&mut disk, ROOT_DISK_BYTES, true)
        .map_err(|error| failed(format!("{error:?}")))?;
    volume
        .create(&mut disk, ROOT_INODE, b"boot", Kind::Directory)
        .and_then(|_| volume.sync(&mut disk))
        .map_err(|error| failed(format!("{error:?}")))?;
    Ok(disk.0)
}

#[cfg(test)]
mod root_disk_tests {
    use super::*;
    use wyrmroot_ext4::{ROOT_INODE, Volume};

    #[test]
    fn the_root_disk_is_reproducible_and_has_a_boot_mount_point() {
        let image = root_disk().unwrap();
        assert_eq!(image.len() as u64, ROOT_DISK_BYTES);
        assert_eq!(image, root_disk().unwrap());
        let mut disk = MemoryDisk(image);
        let volume = Volume::mount(&mut disk, ROOT_DISK_BYTES, false).unwrap();
        let boot = volume.lookup(&mut disk, ROOT_INODE, b"boot").unwrap();
        assert_eq!(boot.kind, wyrmroot_ext4::Kind::Directory);
    }
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

#[cfg(test)]
mod bounded_read_tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        // Inside the project's ignored `.tmp`, never the shared system temp.
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../.tmp/xtask-tests")
            .join(format!("bounded-read-{}-{name}", std::process::id()));
        fs::create_dir_all(dir.parent().unwrap()).unwrap();
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn reads_a_bounded_regular_file() {
        let dir = scratch("regular");
        let file = dir.join("out");
        fs::write(&file, b"abc").unwrap();
        assert_eq!(read_regular_bounded(&file, 3, "out").unwrap(), b"abc");
        assert!(read_regular_bounded(&file, 2, "out").is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    /// F4 WR-F4-L3: a symlink in place of the output is refused, not followed.
    #[test]
    fn refuses_a_symlinked_output() {
        let dir = scratch("symlink");
        let target = dir.join("target");
        fs::write(&target, b"abc").unwrap();
        let link = dir.join("out");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_regular_bounded(&link, 16, "out").is_err());
        assert!(read_build_output(&link, 16, "out").is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
