//! Selector-30 immutable product and root-verifier handoff producer.
//!
//! This module never operates the designated VM.  It only produces a fresh
//! immutable product and the smoke/coexist handoffs consumed by root tooling.

use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use deepwyrm_abi::{
    DW_BOOT_DEVICE_RESOURCE_FLAGS_SUPPORTED_MASK, DW_BOOT_DEVICE_RESOURCE_V1_SIZE,
    DW_BOOT_DEVICE_RESOURCE_V1_VERSION, DW_BOOT_DEVICE_TABLE_FLAGS_SUPPORTED_MASK,
    DW_BOOT_DEVICE_TABLE_MAX_RESOURCES, DW_BOOT_DEVICE_TABLE_RECORD_STRIDE,
    DW_BOOT_DEVICE_TABLE_V1_SIZE, DW_BOOT_DEVICE_TABLE_V1_VERSION,
    DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT, DwBootDeviceResourceV1,
    DwBootDeviceTableV1,
};
use wyrmroot_bootfs::archive::Archive;
use wyrmroot_bootfs::builder::{Builder, FileMode};

use crate::error::Failure;
use crate::metadata::BuildManifest;
use crate::sha256;

const SELECTOR: &str = "device-resource-interrupt-synthetic";
const TEST_ID: &str = "30";
const NATIVE_TARGET: &str = "x86_64-unknown-wyrmroot";
const KERNEL_TARGET: &str = "x86_64-unknown-none";
const MACHINE: &str = "pc-q35-10.2";
const DOMAIN_UUID: &str = "33005e22-d7c2-4b13-b1ac-b82eda95e584";
const ESP_FD_GROUP: &str = "dw-f13-esp-v1";
const VARS_FD_GROUP: &str = "dw-f13-ovmf-vars-v1";
const OVMF_CODE: &str = "/usr/share/edk2/OvmfX64/OVMF_CODE.fd";
const OVMF_CODE_SHA256: &str = "f3ff7e73448ed2845ee15356f394882f5618eb5dab92c9a30ec6ee0e1468553a";
const OVMF_VARS: &str = "/usr/share/edk2/OvmfX64/OVMF_VARS.fd";
const OVMF_VARS_SHA256: &str = "6ed987af3a3c155be71665f510eae3e007eda9b8b94afd59d45e91c4a11565cc";
const O_NOFOLLOW: i32 = 0x2_0000;
const INPUTS: [&str; 12] = [
    "loader",
    "kernel",
    "symbols",
    "bootstrap",
    "resource_owner",
    "trigger",
    "boot_device_table",
    "provenance",
    "bootfs",
    "esp",
    "ovmf_code",
    "ovmf_vars_template",
];

#[derive(Clone)]
struct Snapshot {
    path: PathBuf,
    sha256: String,
}

/// Build the D6 product from an explicitly selected clean Deepwyrm revision.
/// `output` is exclusively created and removed if any pre-run phase fails.
pub fn freeze(
    output: &Path,
    deep_repository: &Path,
    deep_revision: &str,
    evidence_nonce: &str,
    evidence_challenge: &str,
) -> Result<String, Failure> {
    if output.exists() {
        return Err(Failure::task("DW1-D6 freeze output already exists"));
    }
    validate_environment()?;
    validate_lower_hex(deep_revision, 40, "deep_revision")?;
    validate_upper_hex(evidence_nonce, 16, "evidence_nonce")?;
    validate_upper_hex(evidence_challenge, 16, "evidence_challenge")?;
    if evidence_nonce == "0000000000000000" || evidence_challenge == "0000000000000000" {
        return Err(Failure::task(
            "DW1-D6 evidence nonce and challenge must be nonzero",
        ));
    }

    let wyrmroot = crate::tasks::repository_root()?;
    let wyrmroot_revision = git(&wyrmroot, &["rev-parse", "HEAD"])?;
    clean(&wyrmroot, "Wyrmroot", &wyrmroot_revision)?;
    require_d6_loader_contract(&wyrmroot)?;
    let deep_repository = canonical_deep_repository(deep_repository)?;
    clean(&deep_repository, "Deepwyrm", deep_revision)?;

    let manifest = BuildManifest::load(&wyrmroot)?;
    let generated_abi_revision = manifest.deepwyrm_revision()?.to_owned();
    let deepwyrm_abi_tree =
        require_matching_abi_tree(&deep_repository, deep_revision, &generated_abi_revision)?;

    let parent = fs::canonicalize(
        output
            .parent()
            .ok_or_else(|| Failure::task("DW1-D6 output has no parent"))?,
    )
    .map_err(io)?;
    let output = parent.join(
        output
            .file_name()
            .ok_or_else(|| Failure::task("DW1-D6 output has no final component"))?,
    );
    let project = crate::tasks::canonical_project_root(&wyrmroot)?;
    validate_output_location(&output, &project, &wyrmroot, &deep_repository)?;
    fs::create_dir(&output).map_err(io)?;
    let result = build_product(
        &output,
        &wyrmroot,
        &wyrmroot_revision,
        &deep_repository,
        deep_revision,
        &generated_abi_revision,
        &deepwyrm_abi_tree,
        evidence_nonce,
        evidence_challenge,
    );
    if result.is_err() {
        fs::remove_dir_all(&output).map_err(io)?;
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn build_product(
    output: &Path,
    wyrmroot: &Path,
    wyrmroot_revision: &str,
    deep: &Path,
    deep_revision: &str,
    generated_abi_revision: &str,
    deepwyrm_abi_tree: &str,
    nonce: &str,
    challenge: &str,
) -> Result<String, Failure> {
    let manifest = BuildManifest::load(wyrmroot)?;
    if manifest.deepwyrm_revision()? != generated_abi_revision {
        return Err(Failure::task(
            "DW1-D6 generated ABI revision changed after preflight",
        ));
    }
    let rust_revision = manifest.rust_revision()?.to_owned();
    let loader_profile = manifest.validate_loader_build_readiness(wyrmroot)?;
    let layout = crate::deep_layout::prepare(
        wyrmroot,
        manifest.deepwyrm_repository()?,
        manifest.deepwyrm_revision()?,
    )?;
    let toolchain = crate::tasks::prepare_loader_toolchain(wyrmroot, &loader_profile, &manifest)?;
    let cargo_home = crate::tasks::project_cargo_home(wyrmroot, &manifest)?;
    let build = output.join("build");
    fs::create_dir(&build).map_err(io)?;
    let uefi = crate::tasks::build_deterministic_uefi_pair(
        wyrmroot,
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
    let loader = read_build(&uefi.loader, "loader")?;
    let bootstrap = native_build(
        wyrmroot,
        &toolchain,
        &layout,
        &cargo_home,
        &build,
        "bootstrap",
        "wyrmroot-bootstrap",
        "wyrmroot-bootstrap",
        "native-bootstrap,dw1d6-synthetic",
        nonce,
        challenge,
    )?;
    let owner = native_build(
        wyrmroot,
        &toolchain,
        &layout,
        &cargo_home,
        &build,
        "resource-owner",
        "wyrmroot-dw1d6-device-test",
        "wyrmroot-dw1d6-owner",
        "native-payloads",
        nonce,
        challenge,
    )?;
    let trigger = native_build(
        wyrmroot,
        &toolchain,
        &layout,
        &cargo_home,
        &build,
        "trigger",
        "wyrmroot-dw1d6-device-test",
        "wyrmroot-dw1d6-trigger",
        "native-payloads",
        nonce,
        challenge,
    )?;
    let replacement = native_build(
        wyrmroot,
        &toolchain,
        &layout,
        &cargo_home,
        &build,
        "replacement-owner",
        "wyrmroot-dw1d6-device-test",
        "wyrmroot-dw1d6-replacement-owner",
        "native-payloads",
        nonce,
        challenge,
    )?;
    let table = boot_device_table();
    let bootfs = bootfs(&owner, &trigger, &replacement)?;
    let kernel = kernel_build(deep, nonce, challenge)?;
    let symbols = kernel.clone();
    let code = pinned_firmware(OVMF_CODE, OVMF_CODE_SHA256, "OVMF code")?;
    let vars = pinned_firmware(OVMF_VARS, OVMF_VARS_SHA256, "OVMF vars")?;

    let product = build.join("product");
    fs::create_dir(&product).map_err(io)?;
    for (name, bytes) in [
        ("loader.efi", loader.as_slice()),
        ("deepwyrm.elf", kernel.as_slice()),
        ("deepwyrm.symbols", symbols.as_slice()),
        ("bootstrap.elf", bootstrap.as_slice()),
        ("resource-owner.elf", owner.as_slice()),
        ("trigger.elf", trigger.as_slice()),
        ("boot-device-table.bin", table.as_slice()),
        ("bootfs.img", bootfs.as_slice()),
        ("OVMF_CODE.fd", code.as_slice()),
        ("OVMF_VARS.fd", vars.as_slice()),
    ] {
        write_new(&product.join(name), bytes, 0o444)?;
    }
    let esp = product.join("esp.img");
    crate::g3_image::build_d6(
        &crate::cli::G3ImageArguments {
            image: path(&esp)?,
            loader: path(&product.join("loader.efi"))?,
            kernel: path(&product.join("deepwyrm.elf"))?,
            bootstrap: path(&product.join("bootstrap.elf"))?,
            bootfs: path(&product.join("bootfs.img"))?,
        },
        &path(&product.join("boot-device-table.bin"))?,
    )?;
    let provenance = render(&fields([
        ("schema_version", "1".into()),
        ("kind", "wyrmroot-dw1-d6-product-provenance".into()),
        ("selector", SELECTOR.into()),
        ("test_id", TEST_ID.into()),
        ("deepwyrm_revision", deep_revision.into()),
        ("generated_abi_revision", generated_abi_revision.into()),
        ("deepwyrm_abi_tree", deepwyrm_abi_tree.into()),
        ("wyrmroot_revision", wyrmroot_revision.into()),
        ("rust_revision", rust_revision.clone()),
        ("evidence_nonce", nonce.into()),
        ("evidence_challenge", challenge.into()),
        ("boot_device_table_sha256", sha256::bytes_digest(&table)),
        ("uefi_effective_config_sha256", uefi.effective_config_sha256),
        (
            "uefi_inspection_report_sha256",
            uefi.inspection_report_sha256,
        ),
        (
            "nonclaims",
            "no-ioapic-irq3-routing-no-uart-rx-tx-no-selector29-no-mmio-dma-iommu".into(),
        ),
    ]))?;
    write_new(
        &product.join("provenance.toml"),
        provenance.as_bytes(),
        0o444,
    )?;

    let immutable = output.join("immutable");
    fs::create_dir(&immutable).map_err(io)?;
    let files = [
        ("loader", "loader.efi"),
        ("kernel", "deepwyrm.elf"),
        ("symbols", "deepwyrm.symbols"),
        ("bootstrap", "bootstrap.elf"),
        ("resource_owner", "resource-owner.elf"),
        ("trigger", "trigger.elf"),
        ("boot_device_table", "boot-device-table.bin"),
        ("provenance", "provenance.toml"),
        ("bootfs", "bootfs.img"),
        ("esp", "esp.img"),
        ("ovmf_code", "OVMF_CODE.fd"),
        ("ovmf_vars_template", "OVMF_VARS.fd"),
    ];
    let mut inputs = BTreeMap::new();
    for (label, file) in files {
        inputs.insert(
            label,
            snapshot(&product.join(file), &immutable.join(format!("{label}.bin")))?,
        );
    }
    let receipt = write_new(
        &immutable.join("build-receipt.toml"),
        render_receipt(
            deep_revision,
            generated_abi_revision,
            deepwyrm_abi_tree,
            wyrmroot_revision,
            &rust_revision,
            nonce,
            &inputs,
        )?
        .as_bytes(),
        0o444,
    )?;
    let smoke_request = write_new(
        &immutable.join("request-smoke.toml"),
        render_request(
            "smoke",
            1,
            deep_revision,
            generated_abi_revision,
            deepwyrm_abi_tree,
            wyrmroot_revision,
            &rust_revision,
            nonce,
            &receipt,
            &inputs,
        )?
        .as_bytes(),
        0o444,
    )?;
    let coexist_request = write_new(
        &immutable.join("request-coexist.toml"),
        render_request(
            "coexist",
            4,
            deep_revision,
            generated_abi_revision,
            deepwyrm_abi_tree,
            wyrmroot_revision,
            &rust_revision,
            nonce,
            &receipt,
            &inputs,
        )?
        .as_bytes(),
        0o444,
    )?;
    let smoke = profile(
        output,
        "smoke",
        1,
        deep_revision,
        generated_abi_revision,
        deepwyrm_abi_tree,
        wyrmroot_revision,
        &rust_revision,
        nonce,
        &receipt,
        &smoke_request,
        &inputs,
    )?;
    let coexist = profile(
        output,
        "coexist",
        4,
        deep_revision,
        generated_abi_revision,
        deepwyrm_abi_tree,
        wyrmroot_revision,
        &rust_revision,
        nonce,
        &receipt,
        &coexist_request,
        &inputs,
    )?;
    let pair = write_new(
        &output.join("profile-pair.toml"),
        render_pair(
            deep_revision,
            generated_abi_revision,
            deepwyrm_abi_tree,
            wyrmroot_revision,
            &rust_revision,
            nonce,
            &smoke,
            &coexist,
        )?
        .as_bytes(),
        0o444,
    )?;
    clean(wyrmroot, "Wyrmroot", wyrmroot_revision)?;
    clean(deep, "Deepwyrm", deep_revision)?;
    Ok(format!(
        "DW1_D6_FREEZE_READY selector={SELECTOR} test_id={TEST_ID} profile_pair={} sha256={}\n",
        pair.path.display(),
        pair.sha256
    ))
}

#[allow(clippy::too_many_arguments)]
fn native_build(
    repository: &Path,
    toolchain: &crate::tasks::LoaderToolchain,
    layout: &crate::deep_layout::DeepLayoutBuild,
    cargo_home: &Path,
    build: &Path,
    label: &str,
    package: &str,
    binary: &str,
    features: &str,
    nonce: &str,
    challenge: &str,
) -> Result<Vec<u8>, Failure> {
    toolchain.accepted().verify_unchanged()?;
    layout.verify_unchanged()?;
    let target = build.join(label);
    fs::create_dir(&target).map_err(io)?;
    let flags = [
        "-C".into(),
        "link-arg=--build-id=none".into(),
        "--remap-path-prefix".into(),
        format!("{}=/workspace", repository.display()),
        "--remap-path-prefix".into(),
        format!("{}=/cargo-home", cargo_home.display()),
        "--remap-path-prefix".into(),
        format!("{}=/target", target.display()),
    ]
    .join("\u{1f}");
    let status = Command::new(&toolchain.accepted().cargo)
        .args([
            "build",
            "--offline",
            "--locked",
            "--release",
            "--target",
            NATIVE_TARGET,
        ])
        .args([
            "--package",
            package,
            "--bin",
            binary,
            "--features",
            features,
        ])
        .arg("--target-dir")
        .arg(&target)
        .env("RUSTC", &toolchain.accepted().rustc)
        .env("CARGO_HOME", cargo_home)
        .env("CARGO_ENCODED_RUSTFLAGS", flags)
        .env("DEEPWYRM_DW1D6_BUILD_NONCE", nonce)
        .env("DEEPWYRM_DW1D6_BUILD_CHALLENGE", challenge)
        .env_remove("CARGO_TARGET_DIR")
        .current_dir(repository)
        .stdin(Stdio::null())
        .status()
        .map_err(io)?;
    if !status.success() {
        return Err(Failure::task(format!(
            "DW1-D6 native build failed for {label}"
        )));
    }
    read_build(
        &target.join(NATIVE_TARGET).join("release").join(binary),
        label,
    )
}

fn kernel_build(repository: &Path, nonce: &str, challenge: &str) -> Result<Vec<u8>, Failure> {
    let target = repository
        .join(".tmp/dw1d6-freeze")
        .join(format!("{}-{nonce}", std::process::id()));
    if target.exists() {
        return Err(Failure::task("DW1-D6 kernel target already exists"));
    }
    fs::create_dir_all(target.parent().expect("target parent")).map_err(io)?;
    fs::create_dir(&target).map_err(io)?;
    let result = (|| {
        let status = Command::new(repository.join("tools/pinned-cargo"))
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
            .env("DEEPWYRM_GUEST_TEST_SELECTOR", SELECTOR)
            .env("DEEPWYRM_DW1D_EVIDENCE_NONCE", nonce)
            .env("DEEPWYRM_DW1D_EVIDENCE_CHALLENGE", challenge)
            .env_remove("CARGO_HOME")
            .env_remove("LD_AUDIT")
            .env_remove("LD_LIBRARY_PATH")
            .env_remove("LD_PRELOAD")
            .current_dir(repository)
            .stdin(Stdio::null())
            .status()
            .map_err(io)?;
        if !status.success() {
            return Err(Failure::task(
                "DW1-D6 canonical Deepwyrm kernel build failed",
            ));
        }
        read_build(
            &target.join(KERNEL_TARGET).join("release/deepwyrm-kernel"),
            "kernel",
        )
    })();
    fs::remove_dir_all(&target).map_err(io)?;
    result
}

fn boot_device_table() -> Vec<u8> {
    const RESOURCE_ID: u64 = 1;
    const DEVICE_CORRELATION_ID: u64 = 1;
    const PIO_BASE: u16 = 0x02f8;
    const PIO_LENGTH: u16 = 8;
    const INTERRUPT_SOURCE: u32 = 3;

    let header_len = usize::try_from(DW_BOOT_DEVICE_TABLE_V1_SIZE)
        .expect("generated table header size fits usize");
    let stride = usize::try_from(DW_BOOT_DEVICE_TABLE_RECORD_STRIDE)
        .expect("generated table stride fits usize");
    let record_size =
        usize::try_from(DW_BOOT_DEVICE_RESOURCE_V1_SIZE).expect("generated record size fits usize");
    assert_eq!(
        stride, record_size,
        "generated table stride must match record size"
    );
    let max_resources = DW_BOOT_DEVICE_TABLE_MAX_RESOURCES;
    assert!(max_resources >= 1);
    assert_ne!(stride, 0, "generated table stride must be nonzero");
    let total_len = header_len
        .checked_add(stride)
        .expect("generated boot-device table length fits usize");
    let resource_count = u32::try_from(
        total_len
            .checked_sub(header_len)
            .expect("generated table length includes its header")
            / stride,
    )
    .expect("generated boot-device table resource count fits u32");
    assert!(resource_count <= max_resources);
    let mut table = vec![0_u8; total_len];
    write_u32_le(
        &mut table,
        core::mem::offset_of!(DwBootDeviceTableV1, size),
        DW_BOOT_DEVICE_TABLE_V1_SIZE,
    );
    write_u32_le(
        &mut table,
        core::mem::offset_of!(DwBootDeviceTableV1, version),
        DW_BOOT_DEVICE_TABLE_V1_VERSION,
    );
    write_u32_le(
        &mut table,
        core::mem::offset_of!(DwBootDeviceTableV1, resource_count),
        resource_count,
    );
    write_u32_le(
        &mut table,
        core::mem::offset_of!(DwBootDeviceTableV1, flags),
        DW_BOOT_DEVICE_TABLE_FLAGS_SUPPORTED_MASK,
    );
    write_u32_le(
        &mut table,
        core::mem::offset_of!(DwBootDeviceTableV1, record_stride),
        DW_BOOT_DEVICE_TABLE_RECORD_STRIDE,
    );
    write_u32_le(
        &mut table,
        core::mem::offset_of!(DwBootDeviceTableV1, reserved0),
        u32::default(),
    );
    write_u64_le(
        &mut table,
        core::mem::offset_of!(DwBootDeviceTableV1, total_byte_len),
        u64::try_from(total_len).expect("generated boot-device table length fits u64"),
    );

    let record = header_len;
    write_u32_le(
        &mut table,
        record + core::mem::offset_of!(DwBootDeviceResourceV1, size),
        DW_BOOT_DEVICE_RESOURCE_V1_SIZE,
    );
    write_u32_le(
        &mut table,
        record + core::mem::offset_of!(DwBootDeviceResourceV1, version),
        DW_BOOT_DEVICE_RESOURCE_V1_VERSION,
    );
    write_u32_le(
        &mut table,
        record + core::mem::offset_of!(DwBootDeviceResourceV1, kind),
        DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT.0,
    );
    write_u32_le(
        &mut table,
        record + core::mem::offset_of!(DwBootDeviceResourceV1, flags),
        DW_BOOT_DEVICE_RESOURCE_FLAGS_SUPPORTED_MASK,
    );
    write_u64_le(
        &mut table,
        record + core::mem::offset_of!(DwBootDeviceResourceV1, resource_id),
        RESOURCE_ID,
    );
    write_u64_le(
        &mut table,
        record + core::mem::offset_of!(DwBootDeviceResourceV1, device_correlation_id),
        DEVICE_CORRELATION_ID,
    );
    write_u16_le(
        &mut table,
        record + core::mem::offset_of!(DwBootDeviceResourceV1, pio_base),
        PIO_BASE,
    );
    write_u16_le(
        &mut table,
        record + core::mem::offset_of!(DwBootDeviceResourceV1, pio_length),
        PIO_LENGTH,
    );
    write_u32_le(
        &mut table,
        record + core::mem::offset_of!(DwBootDeviceResourceV1, interrupt_source),
        INTERRUPT_SOURCE,
    );
    write_u64_le(
        &mut table,
        record + core::mem::offset_of!(DwBootDeviceResourceV1, reserved),
        u64::default(),
    );
    table
}

fn write_u16_le(bytes: &mut [u8], offset: usize, value: u16) {
    write_le(bytes, offset, &value.to_le_bytes());
}

fn write_u32_le(bytes: &mut [u8], offset: usize, value: u32) {
    write_le(bytes, offset, &value.to_le_bytes());
}

fn write_u64_le(bytes: &mut [u8], offset: usize, value: u64) {
    write_le(bytes, offset, &value.to_le_bytes());
}

fn write_le(bytes: &mut [u8], offset: usize, value: &[u8]) {
    let end = offset
        .checked_add(value.len())
        .expect("generated boot-device table field offset overflows");
    bytes[offset..end].copy_from_slice(value);
}

fn bootfs(owner: &[u8], trigger: &[u8], replacement: &[u8]) -> Result<Vec<u8>, Failure> {
    let mut builder = Builder::new();
    for (entry, bytes, mode) in [
        (b"test/dw1-d6/owner".as_slice(), owner, FileMode::Executable),
        (
            b"test/dw1-d6/trigger".as_slice(),
            trigger,
            FileMode::Executable,
        ),
        (
            b"test/dw1-d6/replacement-owner".as_slice(),
            replacement,
            FileMode::Executable,
        ),
    ] {
        builder
            .add(entry, bytes, mode)
            .map_err(|error| Failure::task(format!("DW1-D6 bootfs add failed: {error:?}")))?;
    }
    let bootfs = builder
        .build()
        .map_err(|error| Failure::task(format!("DW1-D6 bootfs build failed: {error:?}")))?;
    let archive = Archive::new(&bootfs)
        .map_err(|error| Failure::task(format!("DW1-D6 bootfs parse failed: {error:?}")))?;
    for entry in [
        b"test/dw1-d6/owner".as_slice(),
        b"test/dw1-d6/trigger".as_slice(),
        b"test/dw1-d6/replacement-owner".as_slice(),
    ] {
        if !archive
            .lookup(entry)
            .map_err(|_| Failure::task("DW1-D6 bootfs actor missing"))?
            .is_executable()
        {
            return Err(Failure::task("DW1-D6 bootfs actor is not executable"));
        }
    }
    Ok(bootfs)
}

#[allow(clippy::too_many_arguments)]
fn profile(
    output: &Path,
    profile: &str,
    vcpus: u32,
    deep: &str,
    generated_abi_revision: &str,
    deepwyrm_abi_tree: &str,
    wyrmroot: &str,
    rust: &str,
    nonce: &str,
    receipt: &Snapshot,
    request: &Snapshot,
    inputs: &BTreeMap<&str, Snapshot>,
) -> Result<Snapshot, Failure> {
    let directory = output.join(profile);
    fs::create_dir(&directory).map_err(io)?;
    let vars = snapshot_mode(
        &inputs["ovmf_vars_template"].path,
        &directory.join("OVMF_VARS.fd"),
        0o600,
    )?;
    let xml = write_new(
        &directory.join("domain.xml"),
        domain_xml(vcpus, inputs, &vars)?.as_bytes(),
        0o444,
    )?;
    let mut handoff = fields([
        ("schema_version", "1".into()),
        ("kind", "wyrmroot-dw1-d6-vm-handoff".into()),
        ("profile", profile.into()),
        ("vcpus", vcpus.to_string()),
        ("memory_mib", "2048".into()),
        ("machine", MACHINE.into()),
        ("firmware", "OVMF".into()),
        ("request_path", path(&request.path)?),
        ("request_sha256", request.sha256.clone()),
        ("build_receipt_path", path(&receipt.path)?),
        ("build_receipt_sha256", receipt.sha256.clone()),
        ("deepwyrm_revision", deep.into()),
        ("generated_abi_revision", generated_abi_revision.into()),
        ("deepwyrm_abi_tree", deepwyrm_abi_tree.into()),
        ("wyrmroot_revision", wyrmroot.into()),
        ("rust_revision", rust.into()),
        ("selector", SELECTOR.into()),
        ("test_id", TEST_ID.into()),
        ("timeout_seconds", "300".into()),
        ("evidence_nonce", nonce.into()),
        ("evidence_protocol", "DWD6E1".into()),
        ("kernel_result_protocol", "DWTEST1".into()),
        ("kernel_result_test_id", TEST_ID.into()),
        ("kernel_result_detail", "0".into()),
        ("com1", "kernel-diagnostics-structured-evidence-only".into()),
        ("com2", "q35-isa-serial-port-1-no-console".into()),
        ("network", "none".into()),
        ("host_shares", "none".into()),
        ("system_disk", "absent".into()),
        ("domain_xml_path", path(&xml.path)?),
        ("domain_xml_sha256", xml.sha256.clone()),
        ("ovmf_vars_path", path(&vars.path)?),
        ("ovmf_vars_initial_sha256", vars.sha256.clone()),
        ("serial_log_path", path(&directory.join("serial.log"))?),
        ("evidence_log_path", path(&directory.join("evidence.log"))?),
        ("result_json_path", path(&directory.join("result.json"))?),
        ("run_receipt_path", path(&directory.join("result.json"))?),
        ("run_receipt_sha256", "absent".into()),
    ]);
    for label in INPUTS {
        handoff.insert(format!("{label}_path"), path(&inputs[label].path)?);
        handoff.insert(format!("{label}_sha256"), inputs[label].sha256.clone());
    }
    write_new(
        &directory.join("handoff.toml"),
        render(&handoff)?.as_bytes(),
        0o444,
    )
}

fn render_receipt(
    deep: &str,
    generated_abi_revision: &str,
    deepwyrm_abi_tree: &str,
    wyrmroot: &str,
    rust: &str,
    nonce: &str,
    inputs: &BTreeMap<&str, Snapshot>,
) -> Result<String, Failure> {
    let mut values = fields([
        ("schema_version", "1".into()),
        ("kind", "wyrmroot-dw1-d6-build-lineage".into()),
        ("selector", SELECTOR.into()),
        ("test_id", TEST_ID.into()),
        ("deepwyrm_revision", deep.into()),
        ("generated_abi_revision", generated_abi_revision.into()),
        ("deepwyrm_abi_tree", deepwyrm_abi_tree.into()),
        ("wyrmroot_revision", wyrmroot.into()),
        ("rust_revision", rust.into()),
        ("evidence_nonce", nonce.into()),
    ]);
    for label in INPUTS {
        values.insert(format!("{label}_sha256"), inputs[label].sha256.clone());
    }
    render(&values)
}

#[allow(clippy::too_many_arguments)]
fn render_request(
    profile: &str,
    vcpus: u32,
    deep: &str,
    generated_abi_revision: &str,
    deepwyrm_abi_tree: &str,
    wyrmroot: &str,
    rust: &str,
    nonce: &str,
    receipt: &Snapshot,
    inputs: &BTreeMap<&str, Snapshot>,
) -> Result<String, Failure> {
    let mut values = fields([
        ("schema_version", "1".into()),
        ("selector", SELECTOR.into()),
        ("test_id", TEST_ID.into()),
        ("profile", profile.into()),
        ("vcpus", vcpus.to_string()),
        ("memory_mib", "2048".into()),
        ("timeout_seconds", "300".into()),
        ("deepwyrm_revision", deep.into()),
        ("generated_abi_revision", generated_abi_revision.into()),
        ("deepwyrm_abi_tree", deepwyrm_abi_tree.into()),
        ("wyrmroot_revision", wyrmroot.into()),
        ("rust_revision", rust.into()),
        ("evidence_nonce", nonce.into()),
        ("build_receipt", "build-receipt.toml".into()),
        ("build_receipt_sha256", receipt.sha256.clone()),
    ]);
    for label in INPUTS {
        values.insert(format!("{label}_path"), format!("{label}.bin"));
        values.insert(format!("{label}_sha256"), inputs[label].sha256.clone());
    }
    render(&values)
}

#[allow(clippy::too_many_arguments)]
fn render_pair(
    deep: &str,
    generated_abi_revision: &str,
    deepwyrm_abi_tree: &str,
    wyrmroot: &str,
    rust: &str,
    nonce: &str,
    smoke: &Snapshot,
    coexist: &Snapshot,
) -> Result<String, Failure> {
    render(&fields([
        ("schema_version", "1".into()),
        ("kind", "wyrmroot-dw1-d6-vm-profile-pair".into()),
        ("selector", SELECTOR.into()),
        ("test_id", TEST_ID.into()),
        ("memory_mib", "2048".into()),
        ("machine", MACHINE.into()),
        ("firmware", "OVMF".into()),
        ("timeout_seconds", "300".into()),
        ("deepwyrm_revision", deep.into()),
        ("generated_abi_revision", generated_abi_revision.into()),
        ("deepwyrm_abi_tree", deepwyrm_abi_tree.into()),
        ("wyrmroot_revision", wyrmroot.into()),
        ("rust_revision", rust.into()),
        ("evidence_nonce", nonce.into()),
        ("evidence_protocol", "DWD6E1".into()),
        ("kernel_result_protocol", "DWTEST1".into()),
        ("kernel_result_test_id", TEST_ID.into()),
        ("kernel_result_detail", "0".into()),
        ("com1", "kernel-diagnostics-structured-evidence-only".into()),
        ("com2", "q35-isa-serial-port-1-no-console".into()),
        ("network", "none".into()),
        ("host_shares", "none".into()),
        ("system_disk", "absent".into()),
        ("smoke_handoff_path", path(&smoke.path)?),
        ("smoke_handoff_sha256", smoke.sha256.clone()),
        ("coexist_handoff_path", path(&coexist.path)?),
        ("coexist_handoff_sha256", coexist.sha256.clone()),
    ]))
}

fn domain_xml(
    vcpus: u32,
    inputs: &BTreeMap<&str, Snapshot>,
    vars: &Snapshot,
) -> Result<String, Failure> {
    Ok(format!(
        "<domain xmlns:qemu=\"http://libvirt.org/schemas/domain/qemu/1.0\" type=\"qemu\">\n  <name>OS-Project</name>\n  <uuid>{DOMAIN_UUID}</uuid>\n  <memory unit=\"KiB\">2097152</memory>\n  <currentMemory unit=\"KiB\">2097152</currentMemory>\n  <vcpu placement=\"static\">{vcpus}</vcpu>\n  <sysinfo type=\"fwcfg\"><entry name=\"opt/org.deepwyrm.test.selector\">{SELECTOR}</entry><entry name=\"opt/org.deepwyrm.test.test_id\">{TEST_ID}</entry></sysinfo>\n  <os><type arch=\"x86_64\" machine=\"{MACHINE}\">hvm</type><loader readonly=\"yes\" secure=\"no\" type=\"pflash\" format=\"raw\">{}</loader><nvram type=\"file\" format=\"raw\"><source file=\"{}\" fdgroup=\"{VARS_FD_GROUP}\"/></nvram><boot dev=\"hd\"/></os>\n  <features><acpi/><apic/></features>\n  <clock offset=\"utc\"><timer name=\"rtc\" tickpolicy=\"catchup\"/><timer name=\"pit\" tickpolicy=\"delay\"/><timer name=\"hpet\" present=\"no\"/></clock>\n  <on_poweroff>destroy</on_poweroff><on_reboot>restart</on_reboot><on_crash>destroy</on_crash>\n  <pm><suspend-to-mem enabled=\"no\"/><suspend-to-disk enabled=\"no\"/></pm>\n  <devices><emulator>/usr/bin/qemu-system-x86_64</emulator><disk type=\"file\" device=\"disk\"><driver name=\"qemu\" type=\"raw\"/><source file=\"{}\" fdgroup=\"{ESP_FD_GROUP}\"/><target dev=\"vda\" bus=\"virtio\"/><readonly/></disk><controller type=\"pci\" index=\"0\" model=\"pcie-root\"/><serial type=\"pty\"><target type=\"isa-serial\" port=\"0\"/></serial><serial type=\"null\"><target type=\"isa-serial\" port=\"1\"/></serial><console type=\"pty\"><target type=\"serial\" port=\"0\"/></console></devices>\n  <qemu:commandline><qemu:arg value=\"-device\"/><qemu:arg value=\"isa-debug-exit,iobase=0xf4,iosize=0x04\"/></qemu:commandline>\n</domain>\n",
        xml(&inputs["ovmf_code"].path)?,
        xml(&vars.path)?,
        xml(&inputs["esp"].path)?
    ))
}

fn require_d6_loader_contract(repository: &Path) -> Result<(), Failure> {
    let modules = fs::read_to_string(repository.join("loader/src/modules.rs")).map_err(io)?;
    let adapter = fs::read_to_string(repository.join("loader/src/uefi_app.rs")).map_err(io)?;
    let artifacts = fs::read_to_string(repository.join("loader/src/artifacts.rs")).map_err(io)?;
    let image = fs::read_to_string(repository.join("tools/xtask/src/g3_image.rs")).map_err(io)?;
    if !modules.contains("DW_BOOT_MODULE_KIND_DEEPWYRM_BOOT_DEVICE_TABLE_V1")
        || !modules.contains("plan_modules_with_boot_device_table")
        || !adapter.contains("BOOT_DEVICE_TABLE_PATH")
        || !adapter.contains("plan_modules_with_boot_device_table")
        || !artifacts.contains("BDEVICE.BIN")
        || !image.contains("build_d6")
        || !image.contains("BOOT_DEVICE_TABLE_SHORT")
    {
        return Err(Failure::task(
            "DW1-D6 freeze requires the separately integrated EFI boot-device-table module handoff; this Wyrmroot revision still has the pre-D6 three-module loader",
        ));
    }
    Ok(())
}

fn require_matching_abi_tree(
    deep: &Path,
    kernel_revision: &str,
    generated_abi_revision: &str,
) -> Result<String, Failure> {
    validate_lower_hex(generated_abi_revision, 40, "generated_abi_revision")?;
    let kernel_spec = format!("{kernel_revision}:abi");
    let generated_spec = format!("{generated_abi_revision}:abi");
    let kernel_tree = git(deep, &["rev-parse", &kernel_spec])?;
    let generated_tree = git(deep, &["rev-parse", &generated_spec])?;
    validate_lower_hex(&kernel_tree, 40, "deepwyrm_abi_tree")?;
    validate_lower_hex(&generated_tree, 40, "generated_abi_tree")?;
    if kernel_tree != generated_tree {
        return Err(Failure::task(
            "DW1-D6 product Deep candidate does not match the Wyrmroot generated ABI tree",
        ));
    }
    Ok(kernel_tree)
}

fn validate_output_location(
    output: &Path,
    project: &Path,
    wyrmroot: &Path,
    deep: &Path,
) -> Result<(), Failure> {
    let canonical_wyrmroot = project.join("wyrmroot");
    if !output.starts_with(project)
        || output.starts_with(wyrmroot)
        || output.starts_with(&canonical_wyrmroot)
        || output.starts_with(deep)
    {
        return Err(Failure::task(
            "DW1-D6 output must be beneath OS-Project and outside both source repositories",
        ));
    }
    Ok(())
}

fn canonical_deep_repository(input: &Path) -> Result<PathBuf, Failure> {
    if !input.is_absolute()
        || input
            .components()
            .any(|item| !matches!(item, Component::RootDir | Component::Normal(_)))
    {
        return Err(Failure::task(
            "DW1-D6 Deepwyrm repository path is not canonical",
        ));
    }
    let canonical = fs::canonicalize(input).map_err(io)?;
    let root = crate::tasks::repository_root()?;
    let project = root
        .ancestors()
        .find(|item| item.ends_with("OS-Project"))
        .ok_or_else(|| Failure::task("DW1-D6 cannot locate OS-Project root"))?;
    if canonical != input || canonical != fs::canonicalize(project.join("deepwyrm")).map_err(io)? {
        return Err(Failure::task(
            "DW1-D6 Deepwyrm repository must be the canonical sibling",
        ));
    }
    Ok(canonical)
}
fn validate_environment() -> Result<(), Failure> {
    for key in [
        "RUSTUP_TOOLCHAIN",
        "RUSTC_BOOTSTRAP",
        "RUSTC",
        "RUSTFLAGS",
        "CARGO_TARGET_DIR",
        "DEEPWYRM_GUEST_TEST_SELECTOR",
        "DEEPWYRM_DW1D6_BUILD_NONCE",
        "DEEPWYRM_DW1D6_BUILD_CHALLENGE",
        "DEEPWYRM_DW1D_EVIDENCE_NONCE",
        "DEEPWYRM_DW1D_EVIDENCE_CHALLENGE",
        "DEEPWYRM_DW1D6_BOOT_DEVICE_TABLE",
    ] {
        if env::var_os(key).is_some() {
            return Err(Failure::task(format!(
                "DW1-D6 freeze refuses ambient {key}"
            )));
        }
    }
    Ok(())
}
fn validate_lower_hex(value: &str, length: usize, label: &str) -> Result<(), Failure> {
    if value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(Failure::task(format!(
            "DW1-D6 {label} is not lowercase {length}-hex"
        )))
    }
}
fn validate_upper_hex(value: &str, length: usize, label: &str) -> Result<(), Failure> {
    if value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase())
    {
        Ok(())
    } else {
        Err(Failure::task(format!(
            "DW1-D6 {label} is not uppercase {length}-hex"
        )))
    }
}
fn git(repository: &Path, arguments: &[&str]) -> Result<String, Failure> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .output()
        .map_err(io)?;
    if !output.status.success() {
        return Err(Failure::task("DW1-D6 Git query failed"));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().into())
        .map_err(|_| Failure::task("DW1-D6 Git output is not UTF-8"))
}
fn clean(repository: &Path, label: &str, revision: &str) -> Result<(), Failure> {
    if git(repository, &["rev-parse", "HEAD"])? != revision
        || !git(
            repository,
            &["status", "--porcelain=v1", "--untracked-files=all"],
        )?
        .is_empty()
    {
        Err(Failure::task(format!(
            "DW1-D6 {label} repository is not the requested clean revision"
        )))
    } else {
        Ok(())
    }
}
fn read_build(file: &Path, label: &str) -> Result<Vec<u8>, Failure> {
    let meta = fs::symlink_metadata(file).map_err(io)?;
    if meta.file_type().is_symlink()
        || !meta.is_file()
        || meta.len() == 0
        || meta.len() > 64 * 1024 * 1024
    {
        return Err(Failure::task(format!(
            "DW1-D6 {label} output is not bounded regular content"
        )));
    }
    fs::read(file).map_err(io)
}
fn pinned_firmware(file: &str, hash: &str, label: &str) -> Result<Vec<u8>, Failure> {
    let bytes = read_regular(Path::new(file), label)?;
    if sha256::bytes_digest(&bytes) != hash {
        Err(Failure::task(format!("DW1-D6 {label} hash changed")))
    } else {
        Ok(bytes)
    }
}
fn snapshot(source: &Path, target: &Path) -> Result<Snapshot, Failure> {
    snapshot_mode(source, target, 0o444)
}
fn snapshot_mode(source: &Path, target: &Path, mode: u32) -> Result<Snapshot, Failure> {
    write_new(target, &read_regular(source, "immutable input")?, mode)
}
fn read_regular(file: &Path, label: &str) -> Result<Vec<u8>, Failure> {
    let meta = fs::symlink_metadata(file).map_err(io)?;
    if meta.file_type().is_symlink()
        || !meta.is_file()
        || meta.nlink() != 1
        || meta.len() == 0
        || meta.len() > 512 * 1024 * 1024
    {
        return Err(Failure::task(format!(
            "DW1-D6 {label} is not bounded single-link regular content"
        )));
    }
    fs::read(file).map_err(io)
}
fn write_new(file: &Path, bytes: &[u8], mode: u32) -> Result<Snapshot, Failure> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(O_NOFOLLOW)
        .open(file)
        .map_err(io)?;
    output
        .write_all(bytes)
        .and_then(|_| output.sync_all())
        .map_err(io)?;
    fs::set_permissions(file, fs::Permissions::from_mode(mode)).map_err(io)?;
    Ok(Snapshot {
        path: file.into(),
        sha256: sha256::bytes_digest(bytes),
    })
}
fn path(file: &Path) -> Result<String, Failure> {
    file.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Failure::task("DW1-D6 path is not UTF-8"))
}
fn xml(file: &Path) -> Result<String, Failure> {
    let value = path(file)?;
    if value.contains(['&', '<', '>', '\"', '\'']) {
        Err(Failure::task("DW1-D6 XML path requires escaping"))
    } else {
        Ok(value)
    }
}
fn fields<const N: usize>(values: [(&str, String); N]) -> BTreeMap<String, String> {
    values
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect()
}
fn render(values: &BTreeMap<String, String>) -> Result<String, Failure> {
    let mut text = String::new();
    for (key, value) in values {
        if key.is_empty()
            || !key.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            })
            || value.contains(['\n', '\r', '\"', '\\'])
        {
            return Err(Failure::task("DW1-D6 field is not safe scalar TOML"));
        }
        text.push_str(&format!("{key} = \"{value}\"\n"));
    }
    Ok(text)
}
fn io(error: std::io::Error) -> Failure {
    Failure::task(format!("DW1-D6 I/O failure: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boot_table_is_exact_single_com2_irq3_descriptor() {
        let table = boot_device_table();
        let header_len = DW_BOOT_DEVICE_TABLE_V1_SIZE as usize;
        let stride = DW_BOOT_DEVICE_TABLE_RECORD_STRIDE as usize;
        let u16_width = core::mem::size_of::<u16>();
        let u32_width = core::mem::size_of::<u32>();
        let u64_width = core::mem::size_of::<u64>();
        let header = |field_offset, field_width| &table[field_offset..field_offset + field_width];
        let record = |field_offset, field_width| {
            let start = header_len + field_offset;
            &table[start..start + field_width]
        };
        assert_eq!(table.len(), header_len + stride);
        assert_eq!(core::mem::size_of::<DwBootDeviceTableV1>(), header_len);
        assert_eq!(core::mem::size_of::<DwBootDeviceResourceV1>(), stride);
        assert_eq!(
            header(core::mem::offset_of!(DwBootDeviceTableV1, size), u32_width),
            &DW_BOOT_DEVICE_TABLE_V1_SIZE.to_le_bytes()
        );
        assert_eq!(
            header(
                core::mem::offset_of!(DwBootDeviceTableV1, version),
                u32_width
            ),
            &DW_BOOT_DEVICE_TABLE_V1_VERSION.to_le_bytes()
        );
        assert_eq!(
            header(
                core::mem::offset_of!(DwBootDeviceTableV1, resource_count),
                u32_width
            ),
            &u32::try_from((table.len() - header_len) / stride)
                .unwrap()
                .to_le_bytes()
        );
        assert_eq!(
            header(core::mem::offset_of!(DwBootDeviceTableV1, flags), u32_width),
            &DW_BOOT_DEVICE_TABLE_FLAGS_SUPPORTED_MASK.to_le_bytes()
        );
        assert_eq!(
            header(
                core::mem::offset_of!(DwBootDeviceTableV1, record_stride),
                u32_width
            ),
            &DW_BOOT_DEVICE_TABLE_RECORD_STRIDE.to_le_bytes()
        );
        assert_eq!(
            header(
                core::mem::offset_of!(DwBootDeviceTableV1, total_byte_len),
                u64_width
            ),
            &u64::try_from(table.len()).unwrap().to_le_bytes()
        );
        assert_eq!(
            record(
                core::mem::offset_of!(DwBootDeviceResourceV1, size),
                u32_width
            ),
            &DW_BOOT_DEVICE_RESOURCE_V1_SIZE.to_le_bytes()
        );
        assert_eq!(
            record(
                core::mem::offset_of!(DwBootDeviceResourceV1, version),
                u32_width
            ),
            &DW_BOOT_DEVICE_RESOURCE_V1_VERSION.to_le_bytes()
        );
        assert_eq!(
            record(
                core::mem::offset_of!(DwBootDeviceResourceV1, kind),
                u32_width
            ),
            &DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT
                .0
                .to_le_bytes()
        );
        assert_eq!(
            record(
                core::mem::offset_of!(DwBootDeviceResourceV1, resource_id),
                u64_width
            ),
            &1_u64.to_le_bytes()
        );
        assert_eq!(
            record(
                core::mem::offset_of!(DwBootDeviceResourceV1, device_correlation_id),
                u64_width
            ),
            &1_u64.to_le_bytes()
        );
        assert_eq!(
            record(
                core::mem::offset_of!(DwBootDeviceResourceV1, pio_base),
                u16_width
            ),
            &0x02f8_u16.to_le_bytes()
        );
        assert_eq!(
            record(
                core::mem::offset_of!(DwBootDeviceResourceV1, pio_length),
                u16_width
            ),
            &8_u16.to_le_bytes()
        );
        assert_eq!(
            record(
                core::mem::offset_of!(DwBootDeviceResourceV1, interrupt_source),
                u32_width
            ),
            &3_u32.to_le_bytes()
        );
    }

    #[test]
    fn bootfs_excludes_the_loader_owned_boot_device_table() {
        let bootfs = bootfs(b"owner", b"trigger", b"replacement").unwrap();
        let archive = Archive::new(&bootfs).unwrap();
        assert!(archive.lookup(b"test/dw1-d6/boot-device-table").is_err());
    }

    #[test]
    fn ambient_environment_rejects_both_d6_evidence_name_sets() {
        let source = include_str!("dw1d6.rs");
        for variable in [
            "DEEPWYRM_DW1D6_BUILD_NONCE",
            "DEEPWYRM_DW1D6_BUILD_CHALLENGE",
            "DEEPWYRM_DW1D_EVIDENCE_NONCE",
            "DEEPWYRM_DW1D_EVIDENCE_CHALLENGE",
        ] {
            assert!(source.contains(variable));
        }
        assert!(!source.contains(".env(\"DEEPWYRM_DW1D6_BOOT_DEVICE_TABLE\""));
    }

    #[test]
    fn preflight_requires_the_real_efi_table_handoff_path() {
        let modules = include_str!("../../../loader/src/modules.rs");
        let adapter = include_str!("../../../loader/src/uefi_app.rs");
        let artifacts = include_str!("../../../loader/src/artifacts.rs");
        let image = include_str!("g3_image.rs");
        assert!(modules.contains("plan_modules_with_boot_device_table"));
        assert!(adapter.contains("BOOT_DEVICE_TABLE_PATH"));
        assert!(adapter.contains("plan_modules_with_boot_device_table"));
        assert!(artifacts.contains("BDEVICE.BIN"));
        assert!(image.contains("build_d6"));
        assert!(image.contains("BOOT_DEVICE_TABLE_SHORT"));
    }
    #[test]
    fn request_and_receipt_bind_every_verifier_label() {
        let inputs = INPUTS
            .into_iter()
            .map(|label| {
                (
                    label,
                    Snapshot {
                        path: PathBuf::from(format!("/tmp/{label}.bin")),
                        sha256: "a".repeat(64),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let receipt = Snapshot {
            path: PathBuf::from("/tmp/build-receipt.toml"),
            sha256: "b".repeat(64),
        };
        let request = render_request(
            "smoke",
            1,
            &"d".repeat(40),
            &"g".repeat(40),
            &"a".repeat(40),
            &"w".repeat(40),
            &"r".repeat(40),
            "D6D6000000000030",
            &receipt,
            &inputs,
        )
        .unwrap();
        for label in INPUTS {
            assert!(request.contains(&format!("{label}_path = \"{label}.bin\"")));
        }
        assert!(request.contains(&format!("generated_abi_revision = \"{}\"", "g".repeat(40))));
        assert!(request.contains(&format!("deepwyrm_abi_tree = \"{}\"", "a".repeat(40))));
    }
    #[test]
    fn output_location_is_project_bound_and_repository_external() {
        let project = Path::new("/project/OS-Project");
        let wyrmroot = project.join(".worktrees/wyrmroot/d6");
        let deep = project.join("deepwyrm");
        assert!(
            validate_output_location(
                &project.join("artifacts/dw1-d/d6"),
                project,
                &wyrmroot,
                &deep,
            )
            .is_ok()
        );
        for rejected in [
            PathBuf::from("/tmp/d6"),
            project.join("wyrmroot/artifacts/d6"),
            wyrmroot.join("artifacts/d6"),
            deep.join("artifacts/d6"),
        ] {
            assert!(
                validate_output_location(&rejected, project, &wyrmroot, &deep).is_err(),
                "accepted {}",
                rejected.display()
            );
        }
    }
    #[test]
    fn domain_keeps_com2_disconnected_and_excludes_nic_share_and_system_disk() {
        let input = Snapshot {
            path: PathBuf::from("/tmp/input"),
            sha256: "a".repeat(64),
        };
        let inputs = INPUTS
            .into_iter()
            .map(|label| (label, input.clone()))
            .collect::<BTreeMap<_, _>>();
        let text = domain_xml(4, &inputs, &input).unwrap();
        assert!(text.contains("<vcpu placement=\"static\">4</vcpu>"));
        assert!(
            text.contains(
                "<serial type=\"null\"><target type=\"isa-serial\" port=\"1\"/></serial>"
            )
        );
        assert!(!text.contains("interface"));
        assert!(!text.contains("filesystem"));
        assert!(!text.contains("system_disk"));
        assert!(text.contains("fdgroup=\"dw-f13-esp-v1\""));
        assert!(text.contains("fdgroup=\"dw-f13-ovmf-vars-v1\""));
    }
}
